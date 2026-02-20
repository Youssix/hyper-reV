#pragma once
#include <string>
#include <mutex>
#include <atomic>

namespace backend
{
	enum class inject_state
	{
		idle,
		initializing,
		running,
		success,
		failed
	};

	void cleanup();

	void inject_async(const std::string& dll_path, const std::string& process_name);
	void uninject_all();

	inject_state get_state();
	std::string  get_status_text();
	bool         is_busy();
}
