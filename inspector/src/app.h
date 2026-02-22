#pragma once
#include "panels/panel.h"
#include "system/system.h"

#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <cstdint>

struct trap_frame_log_t;

namespace app
{
	struct app_state_t
	{
		tab_id current_tab = tab_id::memory_viewer;

		// hypervisor connection
		bool hv_connected = false;
		std::string hv_status = "Not connected";

		// attached process
		bool process_attached = false;
		sys::process_info_t attached_process = {};

		// navigation request from other panels
		uint64_t goto_address = 0;
		bool goto_address_pending = false;
		tab_id goto_tab = tab_id::memory_viewer;

		// attach modal
		bool show_attach_modal = false;
	};

	void initialize();
	void shutdown();
	void render();

	IPanel* get_panel(tab_id id);

	void switch_tab(tab_id tab);
	void navigate_to_address(uint64_t address, tab_id target_tab = tab_id::memory_viewer);
	void attach_process(const sys::process_info_t& process);
	void detach_process();

	app_state_t& state();

	// cross-panel: disasm -> breakpoints
	void add_breakpoint_from_disasm(uint64_t address);

	// cross-panel: sig maker -> scanner (pending AOB pattern)
	void set_pending_aob_pattern(const std::string& pattern);
	const std::string& pending_aob_pattern();
	void clear_pending_aob_pattern();

	// cross-panel: hex view -> code filter
	void request_code_filter(uint64_t address);
	uint64_t consume_code_filter_request(); // returns 0 if none

	// cross-panel: hex view -> watch list
	void request_add_watch(uint64_t address);
	uint64_t consume_add_watch_request(); // returns 0 if none

	// shared log dispatcher for EPT page monitoring
	struct page_monitor_callback_t
	{
		uint32_t id;
		uint64_t gpa;
		std::function<void(const trap_frame_log_t&)> callback;
	};

	uint32_t register_page_monitor(uint64_t gpa, std::function<void(const trap_frame_log_t&)> callback);
	void unregister_page_monitor(uint32_t id);
	void flush_shared_logs();
}
