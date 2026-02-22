#pragma once
#include "panel.h"
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <string>

class ScannerPanel : public IPanel
{
public:
	~ScannerPanel() override;
	void render() override;
	tab_id get_id() const override { return tab_id::scanner; }
	const char* get_name() const override { return "Scanner"; }

private:
	enum class scan_type_t
	{
		exact_value,
		greater_than,
		less_than,
		value_between,
		changed,
		unchanged,
		increased,
		decreased,
		unknown_initial
	};

	enum class value_type_t
	{
		int8, uint8, int16, uint16,
		int32, uint32, int64, uint64,
		float32, float64, aob
	};

	enum class scan_scope_t
	{
		all_memory,
		by_module,
		custom_range
	};

	struct scan_result_t
	{
		uint64_t address;
		uint8_t current_value[8];  // live value (refreshed periodically)
		uint8_t previous_value[8]; // value before last scan
		uint8_t scan_value[8];     // value at time of scan (red if live != scan)
	};

	// --- Address list (integrated cheat table) ---
	enum class watch_type_t { u8, u16, u32, u64, i32, f32, f64 };

	struct address_entry_t
	{
		std::string description;
		uint64_t address = 0;
		watch_type_t type = watch_type_t::u32;
		bool active = false;        // freeze checkbox
		uint64_t frozen_value = 0;
		std::string value_str;
		bool show_hex = false;
		bool show_signed = false;
		uint8_t prev_refresh[8] = {};  // previous refresh value (for change detection)
		float change_time = 0.0f;       // time of last change (red highlight for 2s)
	};

	// scan parameters
	value_type_t m_value_type = value_type_t::int32;
	scan_type_t m_scan_type = scan_type_t::exact_value;
	char m_value_buf[256] = {};
	char m_value_buf2[256] = {}; // for "between" scans
	uint64_t m_scan_start = 0x10000;
	uint64_t m_scan_end = 0x7FFFFFFFFFFF;
	char m_start_buf[32] = "10000";
	char m_end_buf[32] = "7FFFFFFFFFFF";

	// scope selector
	scan_scope_t m_scan_scope = scan_scope_t::all_memory;
	int m_scope_module_idx = -1;

	// AOB pattern
	char m_aob_buf[512] = {};

	// results
	std::vector<scan_result_t> m_results;
	std::mutex m_results_mutex;
	bool m_has_results = false;

	// undo scan
	std::vector<scan_result_t> m_undo_results;
	bool m_has_undo = false;

	// found list live refresh
	float m_found_refresh_timer = 0.0f;

	// multi-select state (found list)
	std::vector<bool> m_selected;
	int m_last_clicked_idx = -1;

	// background scanning
	std::thread m_scan_thread;
	std::atomic<bool> m_scanning = false;
	std::atomic<float> m_scan_progress = 0.0f;
	std::atomic<int> m_scan_found = 0;

	// layout
	float m_splitter_ratio = 0.55f; // top/bottom split

	// --- Address list state ---
	std::vector<address_entry_t> m_address_entries;
	float m_addr_refresh_timer = 0.0f;

	// add address modal
	bool m_show_add_modal = false;
	char m_add_addr_buf[32] = {};
	char m_add_desc_buf[64] = {};
	int m_add_type_idx = 2; // default u32

	// edit address modal
	bool m_show_edit_modal = false;
	int m_edit_entry_idx = -1;
	char m_edit_addr_buf[32] = {};
	char m_edit_desc_buf[64] = {};
	int m_edit_type_idx = 2;

	// inline value edit
	int m_editing_value_idx = -1;
	char m_edit_value_buf[64] = {};

	int value_size() const;
	void do_first_scan();
	void do_next_scan();
	void do_undo_scan();
	void scan_thread_func(bool is_next);
	bool compare_value(const uint8_t* mem, const uint8_t* target, const uint8_t* prev);
	bool parse_value(const char* str, uint8_t* out);
	bool parse_aob(const char* str, std::vector<uint8_t>& pattern, std::vector<bool>& mask);

	// found list live refresh
	void refresh_found_values();

	// address list helpers
	void add_address_entry(uint64_t address, watch_type_t type, const char* desc);
	void refresh_address_values();
	void write_address_value(int index, const char* value_str);
	void add_selected_results_to_address_list();
	std::string format_entry_value(const address_entry_t& entry) const;

	static int watch_type_size(watch_type_t type);
	static const char* watch_type_name(watch_type_t type);

	// render sub-sections
	void render_found_list();
	void render_scan_controls();
	void render_address_list();
};
