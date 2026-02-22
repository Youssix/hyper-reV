#include "scanner.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../memory/memory_reader.h"
#include "../widgets/address_input.h"
#include "../widgets/module_resolver.h"
#include "hypercall/hypercall.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sstream>
#include <algorithm>

ScannerPanel::~ScannerPanel()
{
	m_scanning = false;
	if (m_scan_thread.joinable())
		m_scan_thread.join();
}

int ScannerPanel::value_size() const
{
	switch (m_value_type)
	{
	case value_type_t::int8: case value_type_t::uint8: return 1;
	case value_type_t::int16: case value_type_t::uint16: return 2;
	case value_type_t::int32: case value_type_t::uint32: case value_type_t::float32: return 4;
	case value_type_t::int64: case value_type_t::uint64: case value_type_t::float64: return 8;
	case value_type_t::aob: return 0;
	}
	return 4;
}

bool ScannerPanel::parse_value(const char* str, uint8_t* out)
{
	memset(out, 0, 8);
	switch (m_value_type)
	{
	case value_type_t::int8:    { int8_t v = (int8_t)atoi(str); memcpy(out, &v, 1); return true; }
	case value_type_t::uint8:   { uint8_t v = (uint8_t)atoi(str); memcpy(out, &v, 1); return true; }
	case value_type_t::int16:   { int16_t v = (int16_t)atoi(str); memcpy(out, &v, 2); return true; }
	case value_type_t::uint16:  { uint16_t v = (uint16_t)atoi(str); memcpy(out, &v, 2); return true; }
	case value_type_t::int32:   { int32_t v = atoi(str); memcpy(out, &v, 4); return true; }
	case value_type_t::uint32:  { uint32_t v = (uint32_t)strtoul(str, nullptr, 10); memcpy(out, &v, 4); return true; }
	case value_type_t::int64:   { int64_t v = _atoi64(str); memcpy(out, &v, 8); return true; }
	case value_type_t::uint64:  { uint64_t v = strtoull(str, nullptr, 10); memcpy(out, &v, 8); return true; }
	case value_type_t::float32: { float v = (float)atof(str); memcpy(out, &v, 4); return true; }
	case value_type_t::float64: { double v = atof(str); memcpy(out, &v, 8); return true; }
	default: return false;
	}
}

bool ScannerPanel::parse_aob(const char* str, std::vector<uint8_t>& pattern, std::vector<bool>& mask)
{
	pattern.clear();
	mask.clear();

	std::istringstream ss(str);
	std::string token;
	while (ss >> token)
	{
		if (token == "?" || token == "??")
		{
			pattern.push_back(0);
			mask.push_back(false);
		}
		else
		{
			uint8_t byte = (uint8_t)strtoul(token.c_str(), nullptr, 16);
			pattern.push_back(byte);
			mask.push_back(true);
		}
	}
	return !pattern.empty();
}

bool ScannerPanel::compare_value(const uint8_t* mem, const uint8_t* target, const uint8_t* prev)
{
	int sz = value_size();

	switch (m_scan_type)
	{
	case scan_type_t::exact_value:
		return memcmp(mem, target, sz) == 0;

	case scan_type_t::greater_than:
	{
		switch (m_value_type)
		{
		case value_type_t::int32: { int32_t a, b; memcpy(&a, mem, 4); memcpy(&b, target, 4); return a > b; }
		case value_type_t::float32: { float a, b; memcpy(&a, mem, 4); memcpy(&b, target, 4); return a > b; }
		default: return memcmp(mem, target, sz) > 0;
		}
	}

	case scan_type_t::less_than:
	{
		switch (m_value_type)
		{
		case value_type_t::int32: { int32_t a, b; memcpy(&a, mem, 4); memcpy(&b, target, 4); return a < b; }
		case value_type_t::float32: { float a, b; memcpy(&a, mem, 4); memcpy(&b, target, 4); return a < b; }
		default: return memcmp(mem, target, sz) < 0;
		}
	}

	case scan_type_t::changed:
		return prev && memcmp(mem, prev, sz) != 0;

	case scan_type_t::unchanged:
		return prev && memcmp(mem, prev, sz) == 0;

	case scan_type_t::increased:
	{
		if (!prev) return false;
		switch (m_value_type)
		{
		case value_type_t::int32: { int32_t a, b; memcpy(&a, mem, 4); memcpy(&b, prev, 4); return a > b; }
		case value_type_t::float32: { float a, b; memcpy(&a, mem, 4); memcpy(&b, prev, 4); return a > b; }
		default: return memcmp(mem, prev, sz) > 0;
		}
	}

	case scan_type_t::decreased:
	{
		if (!prev) return false;
		switch (m_value_type)
		{
		case value_type_t::int32: { int32_t a, b; memcpy(&a, mem, 4); memcpy(&b, prev, 4); return a < b; }
		case value_type_t::float32: { float a, b; memcpy(&a, mem, 4); memcpy(&b, prev, 4); return a < b; }
		default: return memcmp(mem, prev, sz) < 0;
		}
	}

	case scan_type_t::unknown_initial:
		return true;

	default:
		return false;
	}
}

void ScannerPanel::scan_thread_func(bool is_next)
{
	uint64_t cr3 = memory::get_cr3();
	if (cr3 == 0) { m_scanning = false; return; }

	int sz = value_size();

	if (!is_next)
	{
		// first scan
		uint8_t target[8] = {};

		bool is_aob = (m_value_type == value_type_t::aob);
		std::vector<uint8_t> aob_pattern;
		std::vector<bool> aob_mask;

		if (is_aob)
		{
			parse_aob(m_aob_buf, aob_pattern, aob_mask);
			sz = (int)aob_pattern.size();
		}
		else if (m_scan_type != scan_type_t::unknown_initial)
		{
			parse_value(m_value_buf, target);
		}

		std::vector<scan_result_t> new_results;
		uint64_t total_range = m_scan_end - m_scan_start;
		uint8_t page_buf[0x1000];

		for (uint64_t addr = m_scan_start; addr < m_scan_end && m_scanning; addr += 0x1000)
		{
			m_scan_progress = (float)(addr - m_scan_start) / (float)total_range;

			// check if page is mapped
			uint64_t phys = hypercall::translate_guest_virtual_address(addr, cr3);
			if (phys == 0)
				continue;

			uint64_t bytes_read = hypercall::read_guest_virtual_memory(page_buf, addr, cr3, 0x1000);
			if (bytes_read != 0x1000)
				continue;

			for (int offset = 0; offset <= 0x1000 - sz; offset++)
			{
				bool match = false;

				if (is_aob)
				{
					match = true;
					for (int j = 0; j < sz && match; j++)
					{
						if (aob_mask[j] && page_buf[offset + j] != aob_pattern[j])
							match = false;
					}
				}
				else if (m_scan_type == scan_type_t::unknown_initial)
				{
					match = true;
				}
				else
				{
					match = compare_value(page_buf + offset, target, nullptr);
				}

				if (match)
				{
					scan_result_t result = {};
					result.address = addr + offset;
					int copy_sz = sz < 8 ? sz : 8;
					memcpy(result.current_value, page_buf + offset, copy_sz);
					memcpy(result.previous_value, result.current_value, 8);

					std::lock_guard<std::mutex> lock(m_results_mutex);
					new_results.push_back(result);
					m_scan_found = (int)new_results.size();

					if (new_results.size() >= 10000000)
					{
						m_scanning = false;
						break;
					}
				}
			}
		}

		std::lock_guard<std::mutex> lock(m_results_mutex);
		m_results = std::move(new_results);
		m_has_results = true;
	}
	else
	{
		// next scan
		uint8_t target[8] = {};

		if (m_scan_type == scan_type_t::exact_value ||
			m_scan_type == scan_type_t::greater_than ||
			m_scan_type == scan_type_t::less_than)
		{
			parse_value(m_value_buf, target);
		}

		std::vector<scan_result_t> filtered;
		uint64_t total = m_results.size();

		for (size_t i = 0; i < m_results.size() && m_scanning; i++)
		{
			m_scan_progress = (float)i / (float)total;

			uint8_t current[8] = {};
			uint64_t bytes = hypercall::read_guest_virtual_memory(
				current, m_results[i].address, cr3, sz);

			if (bytes != (uint64_t)sz)
				continue;

			bool match = compare_value(current, target, m_results[i].current_value);

			if (match)
			{
				scan_result_t result = m_results[i];
				memcpy(result.previous_value, result.current_value, 8);
				memcpy(result.current_value, current, 8);
				filtered.push_back(result);
				m_scan_found = (int)filtered.size();
			}
		}

		std::lock_guard<std::mutex> lock(m_results_mutex);
		m_results = std::move(filtered);
	}

	m_scan_progress = 1.0f;
	m_scanning = false;
}

void ScannerPanel::do_first_scan()
{
	if (m_scanning) return;

	// compute scan range from scope
	switch (m_scan_scope)
	{
	case scan_scope_t::all_memory:
		m_scan_start = 0x10000;
		m_scan_end = 0x7FFFFFFFFFFF;
		break;
	case scan_scope_t::by_module:
		if (m_scope_module_idx >= 0 && m_scope_module_idx < (int)widgets::g_modules.size())
		{
			auto& mod = widgets::g_modules[m_scope_module_idx];
			m_scan_start = mod.base;
			m_scan_end = mod.base + mod.size;
		}
		else
		{
			return; // no module selected
		}
		break;
	case scan_scope_t::custom_range:
		m_scan_start = strtoull(m_start_buf, nullptr, 16);
		m_scan_end = strtoull(m_end_buf, nullptr, 16);
		break;
	}

	m_scanning = true;
	m_scan_progress = 0.0f;
	m_scan_found = 0;

	if (m_scan_thread.joinable())
		m_scan_thread.join();

	m_scan_thread = std::thread(&ScannerPanel::scan_thread_func, this, false);
}

void ScannerPanel::do_next_scan()
{
	if (m_scanning || !m_has_results) return;

	m_scanning = true;
	m_scan_progress = 0.0f;
	m_scan_found = 0;

	if (m_scan_thread.joinable())
		m_scan_thread.join();

	m_scan_thread = std::thread(&ScannerPanel::scan_thread_func, this, true);
}

void ScannerPanel::render()
{
	auto& st = app::state();

	if (!st.process_attached)
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"Attach a process to use the scanner.");
		return;
	}

	// check for pending AOB pattern from sig maker
	if (!app::pending_aob_pattern().empty())
	{
		const auto& pat = app::pending_aob_pattern();
		strncpy(m_aob_buf, pat.c_str(), sizeof(m_aob_buf) - 1);
		m_aob_buf[sizeof(m_aob_buf) - 1] = '\0';
		m_value_type = value_type_t::aob;
		app::clear_pending_aob_pattern();
	}

	// scan controls

	// value type combo
	ImGui::Text("Type:");
	ImGui::SameLine();
	ImGui::PushItemWidth(100);
	const char* type_names[] = {
		"Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32",
		"Int64", "UInt64", "Float", "Double", "AOB"
	};
	int type_idx = (int)m_value_type;
	if (ImGui::Combo("##type", &type_idx, type_names, IM_ARRAYSIZE(type_names)))
		m_value_type = (value_type_t)type_idx;
	ImGui::PopItemWidth();

	// scan type combo
	ImGui::SameLine(0, 16);
	ImGui::Text("Scan:");
	ImGui::SameLine();
	ImGui::PushItemWidth(130);
	const char* scan_names[] = {
		"Exact", "Greater", "Less", "Between",
		"Changed", "Unchanged", "Increased", "Decreased", "Unknown"
	};
	int scan_idx = (int)m_scan_type;
	if (ImGui::Combo("##scan", &scan_idx, scan_names, IM_ARRAYSIZE(scan_names)))
		m_scan_type = (scan_type_t)scan_idx;
	ImGui::PopItemWidth();

	// value input
	if (m_value_type == value_type_t::aob)
	{
		ImGui::SameLine(0, 16);
		ImGui::PushItemWidth(300);
		ImGui::InputTextWithHint("##aob", "AA BB CC ?? DD", m_aob_buf, sizeof(m_aob_buf));
		ImGui::PopItemWidth();
	}
	else if (m_scan_type != scan_type_t::changed &&
		m_scan_type != scan_type_t::unchanged &&
		m_scan_type != scan_type_t::increased &&
		m_scan_type != scan_type_t::decreased &&
		m_scan_type != scan_type_t::unknown_initial)
	{
		ImGui::SameLine(0, 16);
		ImGui::Text("Value:");
		ImGui::SameLine();
		ImGui::PushItemWidth(150);
		ImGui::InputText("##value", m_value_buf, sizeof(m_value_buf));
		ImGui::PopItemWidth();

		if (m_scan_type == scan_type_t::value_between)
		{
			ImGui::SameLine();
			ImGui::Text("-");
			ImGui::SameLine();
			ImGui::PushItemWidth(150);
			ImGui::InputText("##value2", m_value_buf2, sizeof(m_value_buf2));
			ImGui::PopItemWidth();
		}
	}

	// ---- Scope selector ----
	ImGui::Text("Scope:");
	ImGui::SameLine();
	ImGui::PushItemWidth(120);
	const char* scope_names[] = { "All Memory", "Module", "Custom Range" };
	int scope_idx = (int)m_scan_scope;
	if (ImGui::Combo("##scope", &scope_idx, scope_names, IM_ARRAYSIZE(scope_names)))
		m_scan_scope = (scan_scope_t)scope_idx;
	ImGui::PopItemWidth();

	if (m_scan_scope == scan_scope_t::by_module)
	{
		ImGui::SameLine(0, 16);
		ImGui::PushItemWidth(200);
		const char* preview = (m_scope_module_idx >= 0 && m_scope_module_idx < (int)widgets::g_modules.size())
			? widgets::g_modules[m_scope_module_idx].name.c_str() : "Select module...";
		if (ImGui::BeginCombo("##scope_mod", preview))
		{
			for (int i = 0; i < (int)widgets::g_modules.size(); i++)
			{
				bool selected = (i == m_scope_module_idx);
				if (ImGui::Selectable(widgets::g_modules[i].name.c_str(), selected))
					m_scope_module_idx = i;
			}
			ImGui::EndCombo();
		}
		ImGui::PopItemWidth();

		// show computed range
		if (m_scope_module_idx >= 0 && m_scope_module_idx < (int)widgets::g_modules.size())
		{
			auto& mod = widgets::g_modules[m_scope_module_idx];
			ImGui::SameLine(0, 16);
			ImGui::PushFont(renderer::font_mono());
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
				"0x%llX - 0x%llX (0x%X)", mod.base, mod.base + mod.size, mod.size);
			ImGui::PopFont();
		}
	}
	else if (m_scan_scope == scan_scope_t::custom_range)
	{
		ImGui::SameLine(0, 16);
		ImGui::PushItemWidth(140);
		ImGui::InputText("##start", m_start_buf, sizeof(m_start_buf), ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::PopItemWidth();
		ImGui::SameLine();
		ImGui::Text("-");
		ImGui::SameLine();
		ImGui::PushItemWidth(140);
		ImGui::InputText("##end", m_end_buf, sizeof(m_end_buf), ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::PopItemWidth();
	}

	// scan buttons
	ImGui::SameLine(0, 24);

	if (m_scanning)
	{
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.15f, 0.1f, 0.8f));
		if (ImGui::Button("Stop", ImVec2(80, 28)))
			m_scanning = false;
		ImGui::PopStyleColor();

		ImGui::SameLine();
		ImGui::ProgressBar(m_scan_progress.load(), ImVec2(200, 28));
		ImGui::SameLine();
		ImGui::Text("Found: %d", m_scan_found.load());
	}
	else
	{
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.4f, 0.1f, 0.8f));
		if (ImGui::Button(m_has_results ? "Next Scan" : "First Scan", ImVec2(100, 28)))
		{
			if (m_has_results)
				do_next_scan();
			else
				do_first_scan();
		}
		ImGui::PopStyleColor();

		if (m_has_results)
		{
			ImGui::SameLine(0, 8);
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.5f, 0.1f, 0.1f, 0.8f));
			if (ImGui::Button("New Scan", ImVec2(80, 28)))
			{
				std::lock_guard<std::mutex> lock(m_results_mutex);
				m_results.clear();
				m_has_results = false;
			}
			ImGui::PopStyleColor();
		}
	}

	ImGui::Spacing();
	ImGui::Separator();
	ImGui::Spacing();

	// results table
	{
		std::lock_guard<std::mutex> lock(m_results_mutex);

		ImGui::Text("Results: %d", (int)m_results.size());
		if (m_results.size() > 5000)
			ImGui::SameLine(), ImGui::TextColored(ImVec4(0.9f, 0.6f, 0.1f, 1.0f), "(showing first 5000)");

		ImGui::SameLine(0, 16);
		if (ImGui::Button("Copy All Addresses", ImVec2(0, 0)))
		{
			std::string all;
			int copy_count = (int)m_results.size() < 5000 ? (int)m_results.size() : 5000;
			for (int ci = 0; ci < copy_count; ci++)
			{
				if (!all.empty()) all += "\n";
				char buf[32];
				snprintf(buf, sizeof(buf), "0x%llX", m_results[ci].address);
				all += buf;
			}
			ImGui::SetClipboardText(all.c_str());
		}

		if (ImGui::BeginTable("##results", 4,
			ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
			ImVec2(-1, -1)))
		{
			ImGui::TableSetupScrollFreeze(0, 1);
			ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f);
			ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 140.0f);
			ImGui::TableSetupColumn("Previous", ImGuiTableColumnFlags_WidthFixed, 140.0f);
			ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 80.0f);
			ImGui::TableHeadersRow();

			int result_count = (int)m_results.size();
			int display_count = result_count < 5000 ? result_count : 5000;
			for (int i = 0; i < display_count; i++)
			{
				auto& r = m_results[i];
				ImGui::TableNextRow();
				ImGui::TableNextColumn();

				ImGui::PushFont(renderer::font_mono());

				// show module-relative address
				std::string mod_addr = widgets::format_address_short(r.address);
				char sel_label[280];
				snprintf(sel_label, sizeof(sel_label), "%s##sr%d", mod_addr.c_str(), i);
				ImGui::Selectable(sel_label, false, ImGuiSelectableFlags_SpanAllColumns);

				// right-click context menu
				if (ImGui::BeginPopupContextItem())
				{
					if (ImGui::MenuItem("View in Memory"))
						app::navigate_to_address(r.address, tab_id::memory_viewer);
					if (ImGui::MenuItem("Disassemble"))
						app::navigate_to_address(r.address, tab_id::disassembler);
					ImGui::Separator();
					if (ImGui::MenuItem("Copy Address"))
					{
						char buf[32];
						snprintf(buf, sizeof(buf), "0x%llX", r.address);
						ImGui::SetClipboardText(buf);
					}
					if (ImGui::MenuItem("Copy Module+Offset"))
						ImGui::SetClipboardText(mod_addr.c_str());
					ImGui::EndPopup();
				}

				ImGui::TableNextColumn();

				char val_buf[32];
				switch (m_value_type)
				{
				case value_type_t::int32: { int32_t v; memcpy(&v, r.current_value, 4); snprintf(val_buf, sizeof(val_buf), "%d", v); break; }
				case value_type_t::uint32: { uint32_t v; memcpy(&v, r.current_value, 4); snprintf(val_buf, sizeof(val_buf), "%u", v); break; }
				case value_type_t::float32: { float v; memcpy(&v, r.current_value, 4); snprintf(val_buf, sizeof(val_buf), "%.4f", v); break; }
				case value_type_t::int64: { int64_t v; memcpy(&v, r.current_value, 8); snprintf(val_buf, sizeof(val_buf), "%lld", v); break; }
				case value_type_t::uint64: { uint64_t v; memcpy(&v, r.current_value, 8); snprintf(val_buf, sizeof(val_buf), "%llu", v); break; }
				case value_type_t::float64: { double v; memcpy(&v, r.current_value, 8); snprintf(val_buf, sizeof(val_buf), "%.6f", v); break; }
				default: snprintf(val_buf, sizeof(val_buf), "0x%02X", r.current_value[0]); break;
				}
				ImGui::Text("%s", val_buf);

				ImGui::TableNextColumn();
				switch (m_value_type)
				{
				case value_type_t::int32: { int32_t v; memcpy(&v, r.previous_value, 4); snprintf(val_buf, sizeof(val_buf), "%d", v); break; }
				case value_type_t::uint32: { uint32_t v; memcpy(&v, r.previous_value, 4); snprintf(val_buf, sizeof(val_buf), "%u", v); break; }
				case value_type_t::float32: { float v; memcpy(&v, r.previous_value, 4); snprintf(val_buf, sizeof(val_buf), "%.4f", v); break; }
				default: snprintf(val_buf, sizeof(val_buf), "-"); break;
				}
				ImGui::Text("%s", val_buf);
				ImGui::PopFont();

				ImGui::TableNextColumn();
				char goto_id[32];
				snprintf(goto_id, sizeof(goto_id), "View##%d", i);
				if (ImGui::SmallButton(goto_id))
					app::navigate_to_address(r.address, tab_id::memory_viewer);
			}

			ImGui::EndTable();
		}
	}

}
