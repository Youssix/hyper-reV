#include "loader_backend.h"
#include "../crypto/crypto.h"
#include "../auth/auth_client.h"
#include "../security/integrity.h"

#include <thread>
#include <mutex>
#include <atomic>
#include <Windows.h>

#include "system/system.h"
#include "hook/hook.h"
#include "inject/inject.h"

namespace backend
{
	static std::atomic<inject_state> s_state = inject_state::idle;
	static std::mutex                s_status_mutex;
	static std::string               s_status_text = "Ready";
	static std::thread               s_worker;
	static std::thread               s_watchdog;
	static std::atomic<bool>         s_watchdog_stop = false;
	static bool                      s_initialized = false;

	static void set_status(const std::string& text)
	{
		std::lock_guard<std::mutex> lock(s_status_mutex);
		s_status_text = text;
	}

	static void stop_watchdog()
	{
		s_watchdog_stop = true;
		if (s_watchdog.joinable())
			s_watchdog.join();
		s_watchdog_stop = false;
	}

	static void start_watchdog()
	{
		stop_watchdog();

		s_watchdog = std::thread([]()
		{
			while (!s_watchdog_stop)
			{
				const std::uint64_t pid = inject::target_pid;

				if (pid == 0)
					break; // no longer injected

				HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
				if (h == nullptr)
				{
					// process is gone — auto-uninject
					inject::uninject();
					set_status("Process exited — auto-uninjected");
					s_state = inject_state::idle;
					break;
				}

				// wait up to 500ms for process death, then loop
				DWORD wait = WaitForSingleObject(h, 500);
				CloseHandle(h);

				if (wait == WAIT_OBJECT_0)
				{
					// process died
					inject::uninject();
					set_status("Process exited — auto-uninjected");
					s_state = inject_state::idle;
					break;
				}

				// WAIT_TIMEOUT → still alive, loop
			}
		});
	}

	// shared init + inject logic
	static bool ensure_initialized()
	{
		if (s_initialized)
			return true;

		set_status("Initializing hypervisor bridge...");

		if (sys::set_up() == 0)
		{
			set_status("Failed: hyperv-attachment not loaded");
			s_state = inject_state::failed;
			return false;
		}

		s_initialized = true;
		return true;
	}

	void cleanup()
	{
		stop_watchdog();

		if (s_worker.joinable())
			s_worker.join();

		// cleanup injection hooks before exiting
		if (inject::ksse_hook_va != 0 || inject::target_pid != 0)
			inject::uninject();

		sys::clean_up();
	}

	void inject_async(const std::string& dll_path, const std::string& process_name)
	{
		if (s_state == inject_state::running || s_state == inject_state::initializing)
			return;

		stop_watchdog();

		if (s_worker.joinable())
			s_worker.join();

		s_state = inject_state::running;
		set_status("Starting...");

		s_worker = std::thread([dll_path, process_name]()
		{
			if (!ensure_initialized())
				return;

			set_status("Injecting into " + process_name + "...");

			bool result = inject::inject_dll(dll_path, process_name);

			if (result)
			{
				set_status("Injection successful");
				s_state = inject_state::success;
				start_watchdog();
			}
			else
			{
				set_status("Injection failed");
				s_state = inject_state::failed;
			}
		});
	}

	void inject_from_memory(std::vector<uint8_t> dll_data, const std::string& process_name)
	{
		if (s_state == inject_state::running || s_state == inject_state::initializing)
			return;

		stop_watchdog();

		if (s_worker.joinable())
			s_worker.join();

		s_state = inject_state::running;
		set_status("Starting...");

		s_worker = std::thread([data = std::move(dll_data), process_name]() mutable
		{
			if (!ensure_initialized())
			{
				crypto::secure_zero(data);
				return;
			}

			set_status("Injecting into " + process_name + "...");

			bool result = inject::inject_dll("", process_name, &data);

			// zero DLL buffer regardless of outcome
			crypto::secure_zero(data);

			if (result)
			{
				set_status("Injection successful");
				s_state = inject_state::success;
				start_watchdog();
			}
			else
			{
				set_status("Injection failed");
				s_state = inject_state::failed;
			}
		});
	}

	void download_and_inject(const std::string& token, const std::string& game_id,
		const std::string& process_name)
	{
		if (s_state == inject_state::running || s_state == inject_state::initializing)
			return;

		stop_watchdog();

		if (s_worker.joinable())
			s_worker.join();

		// pre-inject integrity gate
		integrity::inline_check();

		s_state = inject_state::running;
		set_status("Downloading...");

		s_worker = std::thread([token, game_id, process_name]()
		{
			auto dl = auth::download_dll(token, game_id);
			if (!dl.success)
			{
				set_status("Download failed: " + dl.error);
				s_state = inject_state::failed;
				return;
			}

			if (!ensure_initialized())
			{
				crypto::secure_zero(dl.dll_data);
				return;
			}

			set_status("Injecting into " + process_name + "...");

			bool result = inject::inject_dll("", process_name, &dl.dll_data);

			// zero DLL buffer regardless of outcome
			crypto::secure_zero(dl.dll_data);

			if (result)
			{
				set_status("Injection successful");
				s_state = inject_state::success;
				start_watchdog();
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

		stop_watchdog();
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
