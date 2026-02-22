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
		uint8_t current_value[8];
		uint8_t previous_value[8];
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

	// background scanning
	std::thread m_scan_thread;
	std::atomic<bool> m_scanning = false;
	std::atomic<float> m_scan_progress = 0.0f;
	std::atomic<int> m_scan_found = 0;

	int value_size() const;
	void do_first_scan();
	void do_next_scan();
	void scan_thread_func(bool is_next);
	bool compare_value(const uint8_t* mem, const uint8_t* target, const uint8_t* prev);
	bool parse_value(const char* str, uint8_t* out);
	bool parse_aob(const char* str, std::vector<uint8_t>& pattern, std::vector<bool>& mask);
};
