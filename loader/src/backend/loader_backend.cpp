#include "loader_backend.h"

#include <thread>
#include <mutex>
#include <atomic>

#include "system/system.h"
#include "hook/hook.h"
#include "inject/inject.h"

namespace backend
{
	static std::atomic<inject_state> s_state = inject_state::idle;
	static std::mutex                s_status_mutex;
	static std::string               s_status_text = "Ready";
	static std::thread               s_worker;
	static bool                      s_initialized = false;

	static void set_status(const std::string& text)
	{
		std::lock_guard<std::mutex> lock(s_status_mutex);
		s_status_text = text;
	}

	void cleanup()
	{
		if (s_worker.joinable())
			s_worker.join();

		// cleanup injection hooks before exiting
		if (inject::mmaf_hook_va != 0 || inject::ksse_hook_va != 0)
			inject::uninject();

		sys::clean_up();
	}

	void inject_async(const std::string& dll_path, const std::string& process_name)
	{
		if (s_state == inject_state::running || s_state == inject_state::initializing)
			return;

		if (s_worker.joinable())
			s_worker.join();

		s_state = inject_state::running;
		set_status("Starting...");

		s_worker = std::thread([dll_path, process_name]()
		{
			// initialize hypervisor bridge on first injection
			if (!s_initialized)
			{
				set_status("Initializing hypervisor bridge...");

				if (sys::set_up() == 0)
				{
					set_status("Failed: hyperv-attachment not loaded");
					s_state = inject_state::failed;
					return;
				}

				s_initialized = true;
			}

			set_status("Injecting into " + process_name + "...");

			bool result = inject::inject_dll(dll_path, process_name);

			if (result)
			{
				set_status("Injection successful");
				s_state = inject_state::success;
			}
			else
			{
				set_status("Injection failed");
				s_state = inject_state::failed;
			}
		});
	}

	void uninject_all()
	{
		if (s_state == inject_state::running)
			return;

		inject::uninject();
		set_status("Uninjected — clean state");
		s_state = inject_state::idle;
	}

	inject_state get_state()
	{
		return s_state.load();
	}

	std::string get_status_text()
	{
		std::lock_guard<std::mutex> lock(s_status_mutex);
		return s_status_text;
	}

	bool is_busy()
	{
		return s_state == inject_state::running || s_state == inject_state::initializing;
	}
}
