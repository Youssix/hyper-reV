#pragma once
#include "panel.h"
#include "../widgets/filter_bar.h"
#include <vector>
#include <string>
#include <cstdint>
#include <structures/trap_frame.h>

class BreakpointsPanel : public IPanel
{
public:
	~BreakpointsPanel() override;
	void render() override;
	tab_id get_id() const override { return tab_id::breakpoints; }
	const char* get_name() const override { return "Breakpoints"; }

	// public API for cross-panel use
	void add_breakpoint_public(uint64_t va, const char* label) { add_breakpoint(va, label); }

private:
	struct breakpoint_t
	{
		uint64_t virtual_address;
		uint64_t physical_address; // page-aligned GPA
		std::string label;
		bool active = true;
		int hit_count = 0;
	};

	std::vector<breakpoint_t> m_breakpoints;
	std::vector<trap_frame_log_t> m_log_entries;
	float m_last_flush = 0.0f;

	char m_addr_buf[32] = {};
	char m_label_buf[64] = {};
	widgets::filter_state_t m_log_filter;
	int m_filter_bp_idx = -1; // -1 = all breakpoints

	void add_breakpoint(uint64_t va, const char* label);
	void remove_breakpoint(int index);
	void toggle_breakpoint(int index);
	void flush_logs();
};
