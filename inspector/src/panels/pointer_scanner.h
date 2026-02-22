#pragma once
#include "panel.h"
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstdint>

class PointerScannerPanel : public IPanel
{
public:
	~PointerScannerPanel() override;
	void render() override;
	tab_id get_id() const override { return tab_id::pointer_scanner; }
	const char* get_name() const override { return "Ptr Scan"; }

private:
	struct pointer_chain_t
	{
		uint64_t base_address;     // static address (in module)
		std::string base_module;
		std::vector<int64_t> offsets;
	};

	uint64_t m_target_address = 0;
	char m_target_buf[32] = {};
	int m_max_depth = 5;
	int m_max_offset = 0x1000;

	std::vector<pointer_chain_t> m_chains;
	std::mutex m_chains_mutex;

	std::thread m_scan_thread;
	std::atomic<bool> m_scanning = false;
	std::atomic<float> m_progress = 0.0f;
	std::atomic<int> m_found = 0;

	void start_scan();
	void scan_thread_func();
};
