#pragma once
#include "panel.h"
#include "../widgets/filter_bar.h"
#include "../widgets/module_resolver.h"
#include <vector>
#include <string>
#include <cstdint>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <unordered_set>

struct trap_frame_log_t;

enum class fn_source_t { pdata, call_scan, trace, combined };
enum class fn_phase_t  { idle, loading, loaded, monitoring };

struct function_entry_t
{
	uint64_t va = 0;
	uint64_t gpa = 0;       // page-aligned GPA
	uint32_t size = 0;      // function size in bytes (from pdata, 0 if unknown)
	std::string name;        // "module+0x1234" or export name
	bool executed = false;
};

struct monitored_page_t
{
	uint64_t gpa = 0;
	uint32_t monitor_id = 0;        // registration ID from app::register_page_monitor
	std::vector<uint64_t> fn_vas;   // VAs of functions on this page (stable across sorts)
	bool registered = false;
};

class FunctionFilterPanel : public IPanel
{
public:
	~FunctionFilterPanel() override;
	void render() override;
	tab_id get_id() const override { return tab_id::function_filter; }
	const char* get_name() const override { return "FuncFilter"; }

	// MCP API
	void api_load(const std::string& module_name, fn_source_t source);
	void api_start_monitoring();
	void api_stop_monitoring();
	void api_keep_executed();
	void api_remove_executed();
	std::string api_status() const;
	std::vector<function_entry_t> api_get_functions(int limit = 500) const;

private:
	fn_phase_t m_phase = fn_phase_t::idle;
	fn_source_t m_current_source = fn_source_t::pdata;
	std::string m_module_name;

	std::vector<function_entry_t> m_functions;
	std::unordered_map<uint64_t, monitored_page_t> m_page_map; // gpa -> page info
	std::unordered_set<uint64_t> m_va_set; // all tracked VAs for O(1) dedup
	bool m_monitoring = false;

	// UI state
	int m_selected_module = 0;
	int m_source_radio = 3; // 0=pdata, 1=call_scan, 2=trace, 3=combined
	widgets::filter_state_t m_filter;

	// background loading (for call_scan)
	std::thread m_load_thread;
	std::atomic<bool> m_load_done = false;
	std::vector<function_entry_t> m_load_result;

	// trace state
	std::vector<uint64_t> m_trace_gpas; // pages being traced
	std::vector<uint32_t> m_trace_monitor_ids; // registration IDs for trace pages
	std::unordered_set<uint64_t> m_trace_rips; // unique RIPs collected
	std::vector<uint64_t> m_trace_pending_unmonitor; // pages to unmonitor (deferred from callback)
	std::unordered_set<uint64_t> m_trace_hit_pages; // pages already hit (one-shot)
	bool m_tracing = false;

	// code section info (cached after first PE parse)
	struct code_section_t { uint32_t rva; uint32_t size; };

	void load_from_pdata(const widgets::module_info_t& mod);
	void load_from_call_scan(const widgets::module_info_t& mod);
	void load_from_trace(const widgets::module_info_t& mod);
	void load_combined(const widgets::module_info_t& mod);
	void merge_call_scan_results(); // merge CALL scan results into existing pdata
	void stop_trace();

	// PE helpers
	static std::vector<code_section_t> find_code_sections(uint64_t base);

	void rebuild_va_set();
	void build_page_map();
	void start_monitoring();
	void stop_monitoring();
	void on_page_hit(const trap_frame_log_t& log);
	void process_pending_unmonitor(); // deferred unmonitor for trace one-shot

	// resolve indirect CALL targets from trap frame registers
	uint64_t resolve_indirect_call_target(const trap_frame_log_t& log);
	uint64_t get_register_value(const trap_frame_log_t& log, int zydis_reg) const;

	void keep_executed();
	void remove_executed();
	void reset_flags();
	void clear_all();

	int count_executed() const;
};
