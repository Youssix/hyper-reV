#include "code_filter.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../renderer/anim.h"
#include "../memory/memory_reader.h"
#include "../widgets/address_input.h"
#include "../widgets/module_resolver.h"
#include "../widgets/ui_helpers.h"
#include "hypercall/hypercall.h"
#include <Zydis/Zydis.h>
#include <structures/trap_frame.h>
#include <cstdio>
#include <cstring>

CodeFilterPanel::~CodeFilterPanel()
{
	if (m_monitoring)
		stop_monitoring();
}

void CodeFilterPanel::start_monitoring(uint64_t va)
{
	uint64_t cr3 = memory::get_cr3();
	if (cr3 == 0) return;

	uint64_t gpa = hypercall::translate_guest_virtual_address(va, cr3);
	if (gpa == 0) return;

	uint64_t page_gpa = gpa & ~0xFFFull;

	m_target_address = va;
	m_target_gpa = page_gpa;
	m_entries.clear();
	m_monitoring = true;

	// register with shared log dispatcher
	m_monitor_id = app::register_page_monitor(page_gpa, [this](const trap_frame_log_t& log) {
		on_log_entry(log.rip, log.cr3);
	});

	hypercall::monitor_physical_page(page_gpa);
}

void CodeFilterPanel::stop_monitoring()
{
	if (!m_monitoring) return;

	hypercall::unmonitor_physical_page(m_target_gpa);
	app::unregister_page_monitor(m_monitor_id);
	m_monitor_id = 0;
	m_monitoring = false;
}

void CodeFilterPanel::on_log_entry(uint64_t rip, uint64_t cr3)
{
	// check if this RIP already exists
	for (auto& entry : m_entries)
	{
		if (entry.rip == rip)
		{
			entry.hit_count++;
			return;
		}
	}

	// new unique RIP — disassemble 1 instruction to determine access type
	access_entry_t entry = {};
	entry.rip = rip;
	entry.hit_count = 1;
	entry.module_rip = widgets::format_address_short(rip);

	uint8_t code[15] = {};
	if (memory::read(code, rip, sizeof(code)))
	{
		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

		ZydisFormatter formatter;
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

		ZydisDecodedInstruction instruction;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

		if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code, sizeof(code),
			&instruction, operands)))
		{
			char buf[128] = {};
			ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
				instruction.operand_count, buf, sizeof(buf), rip, nullptr);
			entry.instruction = buf;

			// determine access type from operand actions
			bool reads = false, writes = false;
			for (int op = 0; op < instruction.operand_count; op++)
			{
				if (operands[op].type == ZYDIS_OPERAND_TYPE_MEMORY)
				{
					if (operands[op].actions & ZYDIS_OPERAND_ACTION_READ)
						reads = true;
					if (operands[op].actions & ZYDIS_OPERAND_ACTION_WRITE)
						writes = true;
				}
			}

			if (writes && reads)
				entry.access_type = "Read/Write";
			else if (writes)
				entry.access_type = "Write";
			else if (reads)
				entry.access_type = "Read";
			else
				entry.access_type = "Execute";
		}
		else
		{
			entry.instruction = "<decode failed>";
			entry.access_type = "?";
		}
	}
	else
	{
		entry.instruction = "<read failed>";
		entry.access_type = "?";
	}

	m_entries.push_back(std::move(entry));
}

void CodeFilterPanel::render()
{
	auto& st = app::state();

	if (!st.process_attached)
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"Attach a process to use CodeFilter.");
		return;
	}

	// check for pending request from hex view
	uint64_t pending = app::consume_code_filter_request();
	if (pending)
	{
		snprintf(m_addr_buf, sizeof(m_addr_buf), "%llX", pending);
		if (m_monitoring)
			stop_monitoring();
		start_monitoring(pending);
	}

	// toolbar
	ImGui::PushFont(renderer::font_small());
	ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Target Address");
	ImGui::PopFont();
	ImGui::SameLine();
	ImGui::PushItemWidth(180);
	ImGui::InputTextWithHint("##cf_addr", "7FF6A1B20000", m_addr_buf, sizeof(m_addr_buf), ImGuiInputTextFlags_CharsHexadecimal);
	ImGui::PopItemWidth();

	ImGui::SameLine(0, 10);

	if (!m_monitoring)
	{
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.4f, 0.1f, 0.8f));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.0f, 0.5f, 0.15f, 1.0f));
		if (ImGui::Button("Find Accesses", ImVec2(110, 28)))
		{
			uint64_t addr = strtoull(m_addr_buf, nullptr, 16);
			if (addr)
				start_monitoring(addr);
		}
		ImGui::PopStyleColor(2);
	}
	else
	{
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.15f, 0.1f, 0.8f));
		if (ImGui::Button("Stop", ImVec2(110, 28)))
			stop_monitoring();
		ImGui::PopStyleColor();

		ImGui::SameLine(0, 12);
		ui::status_dot(true);
		ImGui::SameLine(0, 4);
		ImGui::PushFont(renderer::font_mono());
		ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.4f, 1.0f), "0x%llX", m_target_address);
		ImGui::PopFont();
	}

	ImGui::SameLine(0, 16);
	if (ImGui::Button("Clear", ImVec2(60, 28)))
		m_entries.clear();

	ImGui::SameLine(0, 16);
	ImGui::PushFont(renderer::font_small());
	ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Unique RIPs:");
	ImGui::PopFont();
	ImGui::SameLine(0, 6);
	ImGui::Text("%d", (int)m_entries.size());

	ImGui::Spacing();

	// results table
	ImGui::PushFont(renderer::font_mono());

	if (ImGui::BeginTable("##cf_table", 4,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_Sortable | ImGuiTableFlags_Resizable,
		ImVec2(-1, -1)))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Instruction Address", ImGuiTableColumnFlags_WidthFixed, 200.0f);
		ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Access Type", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		ImGui::TableSetupColumn("Hit Count", ImGuiTableColumnFlags_WidthFixed, 80.0f);
		ImGui::TableHeadersRow();

		// sort by hit count if requested
		if (ImGuiTableSortSpecs* sorts = ImGui::TableGetSortSpecs())
		{
			if (sorts->SpecsDirty && sorts->SpecsCount > 0)
			{
				auto spec = sorts->Specs[0];
				bool asc = (spec.SortDirection == ImGuiSortDirection_Ascending);
				std::sort(m_entries.begin(), m_entries.end(),
					[&](const access_entry_t& a, const access_entry_t& b) {
						switch (spec.ColumnIndex)
						{
						case 0: return asc ? (a.rip < b.rip) : (a.rip > b.rip);
						case 1: return asc ? (a.instruction < b.instruction) : (a.instruction > b.instruction);
						case 2: return asc ? (a.access_type < b.access_type) : (a.access_type > b.access_type);
						case 3: return asc ? (a.hit_count < b.hit_count) : (a.hit_count > b.hit_count);
						default: return false;
						}
					});
				sorts->SpecsDirty = false;
			}
		}

		for (int i = 0; i < (int)m_entries.size(); i++)
		{
			auto& e = m_entries[i];
			ImGui::TableNextRow();

			// instruction address
			ImGui::TableNextColumn();
			char sel_id[280];
			snprintf(sel_id, sizeof(sel_id), "%s##cf%d", e.module_rip.c_str(), i);
			ImGui::Selectable(sel_id, false, ImGuiSelectableFlags_SpanAllColumns);

			if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0))
				app::navigate_to_address(e.rip, tab_id::disassembler);

			if (ImGui::BeginPopupContextItem())
			{
				if (ImGui::MenuItem("View in Disasm"))
					app::navigate_to_address(e.rip, tab_id::disassembler);
				if (ImGui::MenuItem("View in Memory"))
					app::navigate_to_address(e.rip, tab_id::memory_viewer);
				if (ImGui::MenuItem("Add Breakpoint"))
					app::add_breakpoint_from_disasm(e.rip);
				ImGui::Separator();
				if (ImGui::MenuItem("Copy RIP"))
				{
					char buf[32];
					snprintf(buf, sizeof(buf), "0x%llX", e.rip);
					ui::clipboard(buf, "RIP copied");
				}
				if (ImGui::MenuItem("Copy Line"))
				{
					std::string line = e.module_rip + "  " + e.instruction + "  " + e.access_type;
					ui::clipboard(line.c_str(), "Line copied");
				}
				ImGui::EndPopup();
			}

			// instruction
			ImGui::TableNextColumn();
			ImGui::Text("%s", e.instruction.c_str());

			// access type
			ImGui::TableNextColumn();
			ImVec4 type_color(0.92f, 0.92f, 0.94f, 1.0f);
			if (e.access_type == "Write" || e.access_type == "Read/Write")
				type_color = ImVec4(0.9f, 0.3f, 0.3f, 1.0f);
			else if (e.access_type == "Read")
				type_color = ImVec4(0.3f, 0.9f, 0.4f, 1.0f);
			ImGui::TextColored(type_color, "%s", e.access_type.c_str());

			// hit count
			ImGui::TableNextColumn();
			ImGui::Text("%d", e.hit_count);
		}

		ImGui::EndTable();
	}

	ImGui::PopFont();
}

void CodeFilterPanel::api_start(uint64_t va)
{
	if (m_monitoring)
		stop_monitoring();
	start_monitoring(va);
}

void CodeFilterPanel::api_stop()
{
	stop_monitoring();
}
