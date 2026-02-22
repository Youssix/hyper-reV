#pragma once
#include "panel.h"
#include "../widgets/filter_bar.h"
#include <vector>
#include <string>
#include <cstdint>

class CodeFilterPanel : public IPanel
{
public:
	struct access_entry_t
	{
		uint64_t rip;
		std::string instruction;     // disassembled text at RIP
		std::string module_rip;      // module+offset of RIP
		std::string access_type;     // "Read", "Write", "Execute"
		int hit_count = 0;
	};

	~CodeFilterPanel() override;
	void render() override;
	tab_id get_id() const override { return tab_id::code_filter; }
	const char* get_name() const override { return "CodeFilter"; }

	// public API for MCP server
	void api_start(uint64_t va);
	void api_stop();
	bool api_is_monitoring() const { return m_monitoring; }
	uint64_t api_target() const { return m_target_address; }
	std::vector<access_entry_t> api_entries() const { return m_entries; }

private:
	uint64_t m_target_address = 0;
	uint64_t m_target_gpa = 0;
	uint32_t m_monitor_id = 0;
	bool m_monitoring = false;
	std::vector<access_entry_t> m_entries;
	widgets::filter_state_t m_filter;

	char m_addr_buf[32] = {};

	void start_monitoring(uint64_t va);
	void stop_monitoring();
	void on_log_entry(uint64_t rip, uint64_t cr3);
};
