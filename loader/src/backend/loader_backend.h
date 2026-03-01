#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>

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
	void inject_from_memory(std::vector<uint8_t> dll_data, const std::string& process_name);
	void download_and_inject(const std::string& token, const std::string& game_id,
		const std::string& process_name);
	void uninject_all();

	inject_state get_state();
	std::string  get_status_text();
	bool         is_busy();
}
