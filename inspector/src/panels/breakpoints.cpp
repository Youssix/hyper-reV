#include "breakpoints.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../renderer/anim.h"
#include "../memory/memory_reader.h"
#include "../widgets/module_resolver.h"
#include "../widgets/address_input.h"
#include "../widgets/ui_helpers.h"
#include "hypercall/hypercall.h"
#include <cstdio>
#include <cstring>

BreakpointsPanel::~BreakpointsPanel()
{
	// unmonitor all active breakpoints on cleanup
	for (auto& bp : m_breakpoints)
	{
		if (bp.active && bp.physical_address)
			hypercall::unmonitor_physical_page(bp.physical_address);
	}
}

void BreakpointsPanel::add_breakpoint(uint64_t va, const char* label)
{
	uint64_t cr3 = memory::get_cr3();
	if (cr3 == 0) return;

	uint64_t gpa = hypercall::translate_guest_virtual_address(va, cr3);
	if (gpa == 0) return;

	uint64_t page_gpa = gpa & ~0xFFFull;

	// check if already monitoring this page
	for (auto& bp : m_breakpoints)
	{
		if (bp.physical_address == page_gpa)
		{
			// page already monitored, just add a new virtual address entry
			breakpoint_t new_bp = {};
			new_bp.virtual_address = va;
			new_bp.physical_address = page_gpa;
			new_bp.label = (label && label[0]) ? label : widgets::format_address_short(va);
			new_bp.active = true;
			m_breakpoints.push_back(new_bp);
			return;
		}
	}

	hypercall::monitor_physical_page(page_gpa);

	breakpoint_t bp = {};
	bp.virtual_address = va;
	bp.physical_address = page_gpa;
	bp.label = (label && label[0]) ? label : widgets::format_address_short(va);
	bp.active = true;
	m_breakpoints.push_back(bp);
}

void BreakpointsPanel::remove_breakpoint(int index)
{
	if (index < 0 || index >= (int)m_breakpoints.size()) return;

	auto& bp = m_breakpoints[index];
	uint64_t page_gpa = bp.physical_address;

	// check if any other breakpoint uses the same page
	bool others_use_page = false;
	for (int i = 0; i < (int)m_breakpoints.size(); i++)
	{
		if (i != index && m_breakpoints[i].physical_address == page_gpa && m_breakpoints[i].active)
		{
			others_use_page = true;
			break;
		}
	}

	if (!others_use_page && bp.active)
		hypercall::unmonitor_physical_page(page_gpa);

	m_breakpoints.erase(m_breakpoints.begin() + index);
}

void BreakpointsPanel::toggle_breakpoint(int index)
{
	if (index < 0 || index >= (int)m_breakpoints.size()) return;

	auto& bp = m_breakpoints[index];
	bp.active = !bp.active;

	if (bp.active)
	{
		hypercall::monitor_physical_page(bp.physical_address);
	}
	else
	{
		// check if any other active breakpoint uses the same page
		bool others_use_page = false;
		for (int i = 0; i < (int)m_breakpoints.size(); i++)
		{
			if (i != index && m_breakpoints[i].physical_address == bp.physical_address && m_breakpoints[i].active)
			{
				others_use_page = true;
				break;
			}
		}
		if (!others_use_page)
			hypercall::unmonitor_physical_page(bp.physical_address);
	}
}

void BreakpointsPanel::flush_logs()
{
	std::vector<trap_frame_log_t> new_logs(256);
	uint64_t count = hypercall::flush_logs(new_logs);

	if (count > 0)
	{
		new_logs.resize(count);

		// update hit counts
		for (auto& log : new_logs)
		{
			for (auto& bp : m_breakpoints)
			{
				if (!bp.active) continue;
				// match by page (RIP may be on the same page)
				uint64_t log_gpa = hypercall::translate_guest_virtual_address(log.rip, log.cr3);
				if (log_gpa && (log_gpa & ~0xFFFull) == bp.physical_address)
					bp.hit_count++;
			}
		}

		m_log_entries.insert(m_log_entries.end(), new_logs.begin(), new_logs.end());

		// cap log size
		if (m_log_entries.size() > 10000)
			m_log_entries.erase(m_log_entries.begin(), m_log_entries.begin() + (m_log_entries.size() - 10000));
	}
}

void BreakpointsPanel::render()
{
	auto& st = app::state();

	if (!st.process_attached)
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"Attach a process to use breakpoints.");
		return;
	}

	// auto-flush logs when any breakpoint is active
	bool any_active = false;
	for (auto& bp : m_breakpoints)
		if (bp.active) { any_active = true; break; }

	if (any_active && anim::time() - m_last_flush > 0.5f)
	{
		flush_logs();
		m_last_flush = anim::time();
	}

	// ---- Top: Add breakpoint controls ----
	ImGui::PushFont(renderer::font_small());
	ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Address");
	ImGui::PopFont();
	ImGui::SameLine();
	ImGui::PushItemWidth(180);
	ImGui::InputTextWithHint("##bp_addr", "7FF6A1B20000", m_addr_buf, sizeof(m_addr_buf), ImGuiInputTextFlags_CharsHexadecimal);
	ImGui::PopItemWidth();

	ImGui::SameLine(0, 10);
	ImGui::PushFont(renderer::font_small());
	ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Label");
	ImGui::PopFont();
	ImGui::SameLine();
	ImGui::PushItemWidth(150);
	ImGui::InputTextWithHint("##bp_label", "optional", m_label_buf, sizeof(m_label_buf));
	ImGui::PopItemWidth();

	ImGui::SameLine(0, 10);
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.4f, 0.1f, 0.8f));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.0f, 0.5f, 0.15f, 1.0f));
	if (ImGui::Button("Add", ImVec2(60, 28)))
	{
		uint64_t addr = strtoull(m_addr_buf, nullptr, 16);
		if (addr)
		{
			add_breakpoint(addr, m_label_buf);
			m_addr_buf[0] = '\0';
			m_label_buf[0] = '\0';
		}
	}
	ImGui::PopStyleColor(2);

	ImGui::SameLine(0, 20);
	if (ImGui::Button("Clear Log", ImVec2(80, 28)))
		m_log_entries.clear();

	ImGui::Spacing();

	// split: breakpoints top, log bottom
	ImVec2 avail = ImGui::GetContentRegionAvail();
	float bp_height = avail.y * 0.3f;

	// breakpoint list
	ImGui::BeginChild("##bp_list", ImVec2(-1, bp_height), true);
	ui::section("Breakpoints", renderer::font_bold());
	ImGui::SameLine();
	ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "(%d)", (int)m_breakpoints.size());

	if (ImGui::BeginTable("##bptable", 6,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
		ImVec2(-1, -1)))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 30.0f);
		ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f);
		ImGui::TableSetupColumn("Page GPA", ImGuiTableColumnFlags_WidthFixed, 160.0f);
		ImGui::TableSetupColumn("Hits", ImGuiTableColumnFlags_WidthFixed, 70.0f);
		ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 40.0f);
		ImGui::TableHeadersRow();

		int remove_idx = -1;
		for (int i = 0; i < (int)m_breakpoints.size(); i++)
		{
			auto& bp = m_breakpoints[i];
			ImGui::TableNextRow();

			// toggle checkbox
			ImGui::TableNextColumn();
			char check_id[32];
			snprintf(check_id, sizeof(check_id), "##bpc%d", i);
			if (ImGui::Checkbox(check_id, &bp.active))
				toggle_breakpoint(i);

			// label
			ImGui::TableNextColumn();
			ImGui::Text("%s", bp.label.c_str());

			// address
			ImGui::TableNextColumn();
			ImGui::PushFont(renderer::font_mono());
			ImGui::Text("0x%llX", bp.virtual_address);
			ImGui::PopFont();

			// page GPA
			ImGui::TableNextColumn();
			ImGui::PushFont(renderer::font_mono());
			ImGui::Text("0x%llX", bp.physical_address);
			ImGui::PopFont();

			// hits (color-coded: white < 100, orange < 10000, red >= 10000)
			ImGui::TableNextColumn();
			if (bp.hit_count >= 10000)
				ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.2f, 1.0f), "%d", bp.hit_count);
			else if (bp.hit_count >= 100)
				ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), "%d", bp.hit_count);
			else
				ImGui::Text("%d", bp.hit_count);

			// remove
			ImGui::TableNextColumn();
			char rm_id[32];
			snprintf(rm_id, sizeof(rm_id), "X##rm%d", i);
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.15f, 0.1f, 0.8f));
			if (ImGui::SmallButton(rm_id))
				remove_idx = i;
			ImGui::PopStyleColor();
		}

		ImGui::EndTable();

		if (remove_idx >= 0)
			remove_breakpoint(remove_idx);
	}
	ImGui::EndChild();

	ImGui::Spacing();

	// ---- Bottom: Log table ----
	ImGui::BeginChild("##bp_log", ImVec2(-1, -1), true);

	ui::section("Trap Log", renderer::font_bold());
	ImGui::SameLine();
	ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "(%d entries)", (int)m_log_entries.size());
	if ((int)m_log_entries.size() > 2000)
	{
		ImGui::SameLine(0, 8);
		ImGui::PushFont(renderer::font_small());
		ImGui::TextColored(ImVec4(0.9f, 0.6f, 0.1f, 1.0f), "showing last 2000");
		ImGui::PopFont();
	}

	ImGui::SameLine(0, 16);
	ImGui::PushFont(renderer::font_small());
	ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Filter");
	ImGui::PopFont();
	ImGui::SameLine();
	ImGui::PushItemWidth(120);
	const char* bp_filter_preview = m_filter_bp_idx < 0 ? "All" :
		(m_filter_bp_idx < (int)m_breakpoints.size() ? m_breakpoints[m_filter_bp_idx].label.c_str() : "All");
	if (ImGui::BeginCombo("##bp_filter_combo", bp_filter_preview))
	{
		if (ImGui::Selectable("All", m_filter_bp_idx < 0))
			m_filter_bp_idx = -1;
		for (int i = 0; i < (int)m_breakpoints.size(); i++)
		{
			if (ImGui::Selectable(m_breakpoints[i].label.c_str(), m_filter_bp_idx == i))
				m_filter_bp_idx = i;
		}
		ImGui::EndCombo();
	}
	ImGui::PopItemWidth();

	ImGui::PushFont(renderer::font_mono());

	if (ImGui::BeginTable("##logtable", 7,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_Resizable,
		ImVec2(-1, -1)))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("RIP", ImGuiTableColumnFlags_WidthFixed, 200.0f);
		ImGui::TableSetupColumn("CR3", ImGuiTableColumnFlags_WidthFixed, 140.0f);
		ImGui::TableSetupColumn("RAX", ImGuiTableColumnFlags_WidthFixed, 130.0f);
		ImGui::TableSetupColumn("RCX", ImGuiTableColumnFlags_WidthFixed, 130.0f);
		ImGui::TableSetupColumn("RDX", ImGuiTableColumnFlags_WidthFixed, 130.0f);
		ImGui::TableSetupColumn("RSP", ImGuiTableColumnFlags_WidthFixed, 130.0f);
		ImGui::TableSetupColumn("Stack[0]", ImGuiTableColumnFlags_WidthFixed, 130.0f);
		ImGui::TableHeadersRow();

		int display_count = (int)m_log_entries.size();
		int start = display_count > 2000 ? display_count - 2000 : 0;

		for (int i = start; i < display_count; i++)
		{
			auto& log = m_log_entries[i];

			// filter by breakpoint
			if (m_filter_bp_idx >= 0 && m_filter_bp_idx < (int)m_breakpoints.size())
			{
				uint64_t gpa = hypercall::translate_guest_virtual_address(log.rip, log.cr3);
				if (!gpa || (gpa & ~0xFFFull) != m_breakpoints[m_filter_bp_idx].physical_address)
					continue;
			}

			ImGui::TableNextRow();

			// RIP
			ImGui::TableNextColumn();
			std::string rip_str = widgets::format_address_short(log.rip);
			char sel_label[280];
			snprintf(sel_label, sizeof(sel_label), "%s##l%d", rip_str.c_str(), i);
			ImGui::Selectable(sel_label, false, ImGuiSelectableFlags_SpanAllColumns);

			if (ImGui::BeginPopupContextItem())
			{
				if (ImGui::MenuItem("View in Disasm"))
					app::navigate_to_address(log.rip, tab_id::disassembler);
				if (ImGui::MenuItem("View in Memory"))
					app::navigate_to_address(log.rip, tab_id::memory_viewer);
				ImGui::Separator();
				if (ImGui::MenuItem("Copy RIP"))
				{
					char buf[32];
					snprintf(buf, sizeof(buf), "0x%llX", log.rip);
					ui::clipboard(buf, "RIP copied");
				}
				if (ImGui::MenuItem("Copy Row"))
				{
					char row_buf[512];
					snprintf(row_buf, sizeof(row_buf),
						"RIP=0x%llX CR3=0x%llX RAX=0x%llX RCX=0x%llX RDX=0x%llX RSP=0x%llX",
						log.rip, log.cr3, log.rax, log.rcx, log.rdx, log.rsp);
					ui::clipboard(row_buf, "Row copied");
				}
				ImGui::EndPopup();
			}

			// CR3
			ImGui::TableNextColumn();
			ImGui::Text("0x%llX", log.cr3);

			// RAX
			ImGui::TableNextColumn();
			ImGui::Text("0x%llX", log.rax);

			// RCX
			ImGui::TableNextColumn();
			ImGui::Text("0x%llX", log.rcx);

			// RDX
			ImGui::TableNextColumn();
			ImGui::Text("0x%llX", log.rdx);

			// RSP
			ImGui::TableNextColumn();
			ImGui::Text("0x%llX", log.rsp);

			// Stack[0]
			ImGui::TableNextColumn();
			ImGui::Text("0x%llX", log.stack_data[0]);
		}

		ImGui::EndTable();
	}

	ImGui::PopFont();
	ImGui::EndChild();
}

void BreakpointsPanel::api_remove(uint64_t va)
{
	for (int i = 0; i < (int)m_breakpoints.size(); i++)
	{
		if (m_breakpoints[i].virtual_address == va)
		{
			remove_breakpoint(i);
			return;
		}
	}
}

std::vector<trap_frame_log_t> BreakpointsPanel::api_logs(int limit) const
{
	if (limit <= 0 || limit >= (int)m_log_entries.size())
		return m_log_entries;

	// return the most recent entries
	return std::vector<trap_frame_log_t>(
		m_log_entries.end() - limit,
		m_log_entries.end()
	);
}
