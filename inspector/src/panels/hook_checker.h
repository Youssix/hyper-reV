#pragma once
#include "panel.h"
#include "../widgets/filter_bar.h"
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>

class HookCheckerPanel : public IPanel
{
public:
	~HookCheckerPanel() override;
	void render() override;
	tab_id get_id() const override { return tab_id::hook_checker; }
	const char* get_name() const override { return "Hooks"; }

private:
	struct hook_result_t
	{
		std::string module_name;
		std::string function_name;
		uint64_t address;
		std::string hook_type;   // "Inline (JMP)", "Inline (PUSH/RET)", "IAT", "EPT"
		std::string details;     // target address, original vs hooked module
	};

	std::vector<hook_result_t> m_results;
	std::mutex m_results_mutex;
	widgets::filter_state_t m_filter;

	std::thread m_scan_thread;
	std::atomic<bool> m_scanning = false;
	std::atomic<float> m_progress = 0.0f;
	std::atomic<int> m_found = 0;

	void scan_inline_hooks();
	void scan_iat_hooks();
	void scan_ept_hooks();
};
