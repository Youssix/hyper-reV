#include "scanner.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../renderer/anim.h"
#include "../memory/memory_reader.h"
#include "../widgets/address_input.h"
#include "../widgets/module_resolver.h"
#include "../widgets/ui_helpers.h"
#include "hypercall/hypercall.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sstream>
#include <algorithm>

// ---- Static helpers ----

int ScannerPanel::watch_type_size(watch_type_t type)
{
	switch (type)
	{
	case watch_type_t::u8:  return 1;
	case watch_type_t::u16: return 2;
	case watch_type_t::u32: return 4;
	case watch_type_t::u64: return 8;
	case watch_type_t::i32: return 4;
	case watch_type_t::f32: return 4;
	case watch_type_t::f64: return 8;
	}
	return 4;
}

const char* ScannerPanel::watch_type_name(watch_type_t type)
{
	switch (type)
	{
	case watch_type_t::u8:  return "UInt8";
	case watch_type_t::u16: return "UInt16";
	case watch_type_t::u32: return "UInt32";
	case watch_type_t::u64: return "UInt64";
	case watch_type_t::i32: return "Int32";
	case watch_type_t::f32: return "Float";
	case watch_type_t::f64: return "Double";
	}
	return "?";
}

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
					memcpy(result.scan_value, result.current_value, 8);

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
				memcpy(result.scan_value, current, 8);
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

	// clear undo on first scan
	m_undo_results.clear();
	m_has_undo = false;

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

	// save current results for undo
	{
		std::lock_guard<std::mutex> lock(m_results_mutex);
		m_undo_results = m_results;
		m_has_undo = true;
	}

	m_scanning = true;
	m_scan_progress = 0.0f;
	m_scan_found = 0;

	if (m_scan_thread.joinable())
		m_scan_thread.join();

	m_scan_thread = std::thread(&ScannerPanel::scan_thread_func, this, true);
}

void ScannerPanel::do_undo_scan()
{
	if (m_scanning || !m_has_undo) return;

	std::lock_guard<std::mutex> lock(m_results_mutex);
	m_results = std::move(m_undo_results);
	m_undo_results.clear();
	m_has_undo = false;
	m_selected.clear();
}

// ---- Found list live refresh ----

void ScannerPanel::refresh_found_values()
{
	if (m_scanning || !m_has_results) return;

	std::lock_guard<std::mutex> lock(m_results_mutex);
	int count = (int)m_results.size();
	int refresh_count = count < 5000 ? count : 5000;
	int sz = value_size();
	if (sz <= 0) return;

	uint64_t cr3 = memory::get_cr3();
	if (cr3 == 0) return;

	for (int i = 0; i < refresh_count; i++)
	{
		uint8_t buf[8] = {};
		uint64_t bytes = hypercall::read_guest_virtual_memory(
			buf, m_results[i].address, cr3, sz);
		if (bytes == (uint64_t)sz)
			memcpy(m_results[i].current_value, buf, sz < 8 ? sz : 8);
	}
}

// ---- Address list helpers ----

void ScannerPanel::add_address_entry(uint64_t address, watch_type_t type, const char* desc)
{
	address_entry_t entry = {};
	entry.address = address;
	entry.type = type;
	entry.description = (desc && desc[0]) ? desc : widgets::format_address_short(address);
	m_address_entries.push_back(std::move(entry));
}

void ScannerPanel::add_selected_results_to_address_list()
{
	std::lock_guard<std::mutex> lock(m_results_mutex);

	// map scanner value_type to address list watch_type
	watch_type_t wt = watch_type_t::u32;
	switch (m_value_type)
	{
	case value_type_t::int8:    wt = watch_type_t::u8;  break;
	case value_type_t::uint8:   wt = watch_type_t::u8;  break;
	case value_type_t::int16:   wt = watch_type_t::u16; break;
	case value_type_t::uint16:  wt = watch_type_t::u16; break;
	case value_type_t::int32:   wt = watch_type_t::i32; break;
	case value_type_t::uint32:  wt = watch_type_t::u32; break;
	case value_type_t::int64:   wt = watch_type_t::u64; break;
	case value_type_t::uint64:  wt = watch_type_t::u64; break;
	case value_type_t::float32: wt = watch_type_t::f32; break;
	case value_type_t::float64: wt = watch_type_t::f64; break;
	default: break;
	}

	for (int i = 0; i < (int)m_selected.size() && i < (int)m_results.size(); i++)
	{
		if (m_selected[i])
			add_address_entry(m_results[i].address, wt, nullptr);
	}
}

void ScannerPanel::refresh_address_values()
{
	float now = anim::time();

	for (auto& entry : m_address_entries)
	{
		int sz = watch_type_size(entry.type);
		uint8_t buf[8] = {};

		// freeze: write frozen value before reading
		if (entry.active)
			memory::write(&entry.frozen_value, entry.address, sz);

		if (!memory::read(buf, entry.address, sz))
		{
			entry.value_str = "<invalid>";
			continue;
		}

		// detect change for red highlight (compare with previous refresh)
		if (memcmp(buf, entry.prev_refresh, sz) != 0)
		{
			entry.change_time = now;
			memcpy(entry.prev_refresh, buf, sz < 8 ? sz : 8);
		}

		char val[64];
		switch (entry.type)
		{
		case watch_type_t::u8:  snprintf(val, sizeof(val), "%u", buf[0]); break;
		case watch_type_t::u16: { uint16_t v; memcpy(&v, buf, 2); snprintf(val, sizeof(val), "%u", v); break; }
		case watch_type_t::u32: { uint32_t v; memcpy(&v, buf, 4); snprintf(val, sizeof(val), "%u", v); break; }
		case watch_type_t::u64: { uint64_t v; memcpy(&v, buf, 8); snprintf(val, sizeof(val), "%llu", v); break; }
		case watch_type_t::i32: { int32_t v; memcpy(&v, buf, 4); snprintf(val, sizeof(val), "%d", v); break; }
		case watch_type_t::f32: { float v; memcpy(&v, buf, 4); snprintf(val, sizeof(val), "%.6g", v); break; }
		case watch_type_t::f64: { double v; memcpy(&v, buf, 8); snprintf(val, sizeof(val), "%.10g", v); break; }
		}
		entry.value_str = val;
	}
}

std::string ScannerPanel::format_entry_value(const address_entry_t& entry) const
{
	return entry.value_str;
}

void ScannerPanel::write_address_value(int index, const char* value_str)
{
	if (index < 0 || index >= (int)m_address_entries.size()) return;
	auto& entry = m_address_entries[index];
	int sz = watch_type_size(entry.type);
	uint8_t buf[8] = {};

	switch (entry.type)
	{
	case watch_type_t::u8:  { uint8_t v = (uint8_t)atoi(value_str); memcpy(buf, &v, 1); break; }
	case watch_type_t::u16: { uint16_t v = (uint16_t)atoi(value_str); memcpy(buf, &v, 2); break; }
	case watch_type_t::u32: { uint32_t v = (uint32_t)strtoul(value_str, nullptr, 10); memcpy(buf, &v, 4); break; }
	case watch_type_t::u64: { uint64_t v = strtoull(value_str, nullptr, 10); memcpy(buf, &v, 8); break; }
	case watch_type_t::i32: { int32_t v = atoi(value_str); memcpy(buf, &v, 4); break; }
	case watch_type_t::f32: { float v = (float)atof(value_str); memcpy(buf, &v, 4); break; }
	case watch_type_t::f64: { double v = atof(value_str); memcpy(buf, &v, 8); break; }
	}

	memory::write(buf, entry.address, sz);

	if (entry.active)
		memcpy(&entry.frozen_value, buf, sz < 8 ? sz : 8);
}

// ---- Render: found list (left panel) ----

void ScannerPanel::render_found_list()
{
	std::lock_guard<std::mutex> lock(m_results_mutex);

	int result_count = (int)m_results.size();
	int display_count = result_count < 5000 ? result_count : 5000;

	// resize selection vector
	if ((int)m_selected.size() != result_count)
	{
		m_selected.assign(result_count, false);
		m_last_clicked_idx = -1;
	}

	// count selected
	int sel_count = 0;
	for (int i = 0; i < (int)m_selected.size(); i++)
		if (m_selected[i]) sel_count++;

	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(ImVec4(0.72f, 0.72f, 0.78f, 1.0f), "Found");
	ImGui::PopFont();
	ImGui::SameLine(0, 8);
	ImGui::Text("%d", result_count);
	if (result_count > 5000)
	{
		ImGui::SameLine(0, 6);
		ImGui::PushFont(renderer::font_small());
		ImGui::TextColored(ImVec4(0.9f, 0.6f, 0.1f, 1.0f), "(showing 5000)");
		ImGui::PopFont();
	}
	if (sel_count > 0)
	{
		ImGui::SameLine(0, 10);
		ImGui::PushFont(renderer::font_small());
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "%d selected", sel_count);
		ImGui::PopFont();
	}

	if (ImGui::BeginTable("##results", 3,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
		ImVec2(-1, -1)))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150.0f);
		ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		ImGui::TableSetupColumn("Previous", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableHeadersRow();

		ImGui::PushFont(renderer::font_mono());

		for (int i = 0; i < display_count; i++)
		{
			auto& r = m_results[i];
			ImGui::TableNextRow();
			ImGui::TableNextColumn();

			bool is_selected = (i < (int)m_selected.size()) ? m_selected[i] : false;

			// address column with selectable
			std::string mod_addr = widgets::format_address_short(r.address);
			char sel_label[280];
			snprintf(sel_label, sizeof(sel_label), "%s##sr%d", mod_addr.c_str(), i);

			if (ImGui::Selectable(sel_label, is_selected,
				ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
			{
				if (ImGui::IsMouseDoubleClicked(0))
				{
					// double-click: add this single result to address list
					watch_type_t wt = watch_type_t::u32;
					switch (m_value_type)
					{
					case value_type_t::int8:    wt = watch_type_t::u8;  break;
					case value_type_t::uint8:   wt = watch_type_t::u8;  break;
					case value_type_t::int16:   wt = watch_type_t::u16; break;
					case value_type_t::uint16:  wt = watch_type_t::u16; break;
					case value_type_t::int32:   wt = watch_type_t::i32; break;
					case value_type_t::uint32:  wt = watch_type_t::u32; break;
					case value_type_t::int64:   wt = watch_type_t::u64; break;
					case value_type_t::uint64:  wt = watch_type_t::u64; break;
					case value_type_t::float32: wt = watch_type_t::f32; break;
					case value_type_t::float64: wt = watch_type_t::f64; break;
					default: break;
					}
					add_address_entry(r.address, wt, nullptr);
				}
				else
				{
					ImGuiIO& io = ImGui::GetIO();

					if (io.KeyCtrl)
					{
						// Ctrl+Click: toggle
						m_selected[i] = !m_selected[i];
					}
					else if (io.KeyShift && m_last_clicked_idx >= 0 && m_last_clicked_idx < result_count)
					{
						// Shift+Click: range select
						int lo = (m_last_clicked_idx < i) ? m_last_clicked_idx : i;
						int hi = (m_last_clicked_idx < i) ? i : m_last_clicked_idx;
						for (int j = lo; j <= hi && j < result_count; j++)
							m_selected[j] = true;
					}
					else
					{
						// plain click: select single
						std::fill(m_selected.begin(), m_selected.end(), false);
						m_selected[i] = true;
					}

					m_last_clicked_idx = i;
				}
			}

			// right-click context menu
			if (ImGui::BeginPopupContextItem())
			{
				if (sel_count > 1 && ImGui::MenuItem("Add selected to address list"))
				{
					// unlock mutex first — we're already inside the lock
					// actually we already hold it, and add_selected just reads m_selected + m_results
					for (int si = 0; si < (int)m_selected.size() && si < (int)m_results.size(); si++)
					{
						if (m_selected[si])
						{
							watch_type_t wt = watch_type_t::u32;
							switch (m_value_type)
							{
							case value_type_t::int32:   wt = watch_type_t::i32; break;
							case value_type_t::uint32:  wt = watch_type_t::u32; break;
							case value_type_t::float32: wt = watch_type_t::f32; break;
							case value_type_t::float64: wt = watch_type_t::f64; break;
							case value_type_t::int8: case value_type_t::uint8: wt = watch_type_t::u8; break;
							case value_type_t::int16: case value_type_t::uint16: wt = watch_type_t::u16; break;
							case value_type_t::int64: case value_type_t::uint64: wt = watch_type_t::u64; break;
							default: break;
							}
							add_address_entry(m_results[si].address, wt, nullptr);
						}
					}
				}

				if (ImGui::MenuItem("Add to address list"))
				{
					watch_type_t wt = watch_type_t::u32;
					switch (m_value_type)
					{
					case value_type_t::int32:   wt = watch_type_t::i32; break;
					case value_type_t::uint32:  wt = watch_type_t::u32; break;
					case value_type_t::float32: wt = watch_type_t::f32; break;
					case value_type_t::float64: wt = watch_type_t::f64; break;
					case value_type_t::int8: case value_type_t::uint8: wt = watch_type_t::u8; break;
					case value_type_t::int16: case value_type_t::uint16: wt = watch_type_t::u16; break;
					case value_type_t::int64: case value_type_t::uint64: wt = watch_type_t::u64; break;
					default: break;
					}
					add_address_entry(r.address, wt, nullptr);
				}

				if (ImGui::MenuItem("Select All"))
				{
					int cnt = result_count < 5000 ? result_count : 5000;
					for (int j = 0; j < cnt; j++)
						m_selected[j] = true;
				}

				ImGui::Separator();

				if (ImGui::MenuItem("View in Memory"))
					app::navigate_to_address(r.address, tab_id::memory_viewer);
				if (ImGui::MenuItem("Disassemble"))
					app::navigate_to_address(r.address, tab_id::disassembler);

				ImGui::Separator();

				if (ImGui::MenuItem("Copy Address"))
				{
					char buf[32];
					snprintf(buf, sizeof(buf), "0x%llX", r.address);
					ui::clipboard(buf, "Address copied");
				}
				if (ImGui::MenuItem("Copy Module+Offset"))
					ui::clipboard(mod_addr.c_str(), "Module+Offset copied");

				ImGui::EndPopup();
			}

			// check if live value differs from scan value
			int cmp_sz = value_size();
			if (cmp_sz <= 0) cmp_sz = 1;
			bool value_changed = (memcmp(r.current_value, r.scan_value, cmp_sz) != 0);

			// value column (red if changed)
			ImGui::TableNextColumn();
			{
				char val_buf[32];
				switch (m_value_type)
				{
				case value_type_t::int32:   { int32_t v; memcpy(&v, r.current_value, 4); snprintf(val_buf, sizeof(val_buf), "%d", v); break; }
				case value_type_t::uint32:  { uint32_t v; memcpy(&v, r.current_value, 4); snprintf(val_buf, sizeof(val_buf), "%u", v); break; }
				case value_type_t::float32: { float v; memcpy(&v, r.current_value, 4); snprintf(val_buf, sizeof(val_buf), "%.4f", v); break; }
				case value_type_t::int64:   { int64_t v; memcpy(&v, r.current_value, 8); snprintf(val_buf, sizeof(val_buf), "%lld", v); break; }
				case value_type_t::uint64:  { uint64_t v; memcpy(&v, r.current_value, 8); snprintf(val_buf, sizeof(val_buf), "%llu", v); break; }
				case value_type_t::float64: { double v; memcpy(&v, r.current_value, 8); snprintf(val_buf, sizeof(val_buf), "%.6f", v); break; }
				default: snprintf(val_buf, sizeof(val_buf), "0x%02X", r.current_value[0]); break;
				}
				if (value_changed)
					ImGui::TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f), "%s", val_buf);
				else
					ImGui::Text("%s", val_buf);
			}

			// previous column
			ImGui::TableNextColumn();
			{
				char val_buf[32];
				switch (m_value_type)
				{
				case value_type_t::int32:   { int32_t v; memcpy(&v, r.previous_value, 4); snprintf(val_buf, sizeof(val_buf), "%d", v); break; }
				case value_type_t::uint32:  { uint32_t v; memcpy(&v, r.previous_value, 4); snprintf(val_buf, sizeof(val_buf), "%u", v); break; }
				case value_type_t::float32: { float v; memcpy(&v, r.previous_value, 4); snprintf(val_buf, sizeof(val_buf), "%.4f", v); break; }
				default: snprintf(val_buf, sizeof(val_buf), "-"); break;
				}
				ImGui::Text("%s", val_buf);
			}
		}

		ImGui::PopFont();
		ImGui::EndTable();
	}
}

// ---- Render: scan controls (right panel) ----

void ScannerPanel::render_scan_controls()
{
	// value type combo
	ImGui::Text("Value Type:");
	ImGui::PushItemWidth(-1);
	const char* type_names[] = {
		"Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32",
		"Int64", "UInt64", "Float", "Double", "AOB"
	};
	int type_idx = (int)m_value_type;
	if (ImGui::Combo("##type", &type_idx, type_names, IM_ARRAYSIZE(type_names)))
		m_value_type = (value_type_t)type_idx;
	ImGui::PopItemWidth();

	ImGui::Spacing();

	// scan type combo
	ImGui::Text("Scan Type:");
	ImGui::PushItemWidth(-1);
	const char* scan_names[] = {
		"Exact", "Greater", "Less", "Between",
		"Changed", "Unchanged", "Increased", "Decreased", "Unknown"
	};
	int scan_idx = (int)m_scan_type;
	if (ImGui::Combo("##scan", &scan_idx, scan_names, IM_ARRAYSIZE(scan_names)))
		m_scan_type = (scan_type_t)scan_idx;
	ImGui::PopItemWidth();

	ImGui::Spacing();

	// value input
	if (m_value_type == value_type_t::aob)
	{
		ImGui::Text("AOB Pattern:");
		ImGui::PushItemWidth(-1);
		ImGui::InputTextWithHint("##aob", "AA BB CC ?? DD", m_aob_buf, sizeof(m_aob_buf));
		ImGui::PopItemWidth();
	}
	else if (m_scan_type != scan_type_t::changed &&
		m_scan_type != scan_type_t::unchanged &&
		m_scan_type != scan_type_t::increased &&
		m_scan_type != scan_type_t::decreased &&
		m_scan_type != scan_type_t::unknown_initial)
	{
		ImGui::Text("Value:");
		ImGui::PushItemWidth(-1);
		ImGui::InputText("##value", m_value_buf, sizeof(m_value_buf));
		ImGui::PopItemWidth();

		if (m_scan_type == scan_type_t::value_between)
		{
			ImGui::Text("To:");
			ImGui::PushItemWidth(-1);
			ImGui::InputText("##value2", m_value_buf2, sizeof(m_value_buf2));
			ImGui::PopItemWidth();
		}
	}

	ImGui::Spacing();

	// scope selector
	ImGui::Text("Scope:");
	ImGui::PushItemWidth(-1);
	const char* scope_names[] = { "All Memory", "Module", "Custom Range" };
	int scope_idx = (int)m_scan_scope;
	if (ImGui::Combo("##scope", &scope_idx, scope_names, IM_ARRAYSIZE(scope_names)))
		m_scan_scope = (scan_scope_t)scope_idx;
	ImGui::PopItemWidth();

	if (m_scan_scope == scan_scope_t::by_module)
	{
		ImGui::PushItemWidth(-1);
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

		if (m_scope_module_idx >= 0 && m_scope_module_idx < (int)widgets::g_modules.size())
		{
			auto& mod = widgets::g_modules[m_scope_module_idx];
			ImGui::PushFont(renderer::font_mono());
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
				"0x%llX-0x%llX", mod.base, mod.base + mod.size);
			ImGui::PopFont();
		}
	}
	else if (m_scan_scope == scan_scope_t::custom_range)
	{
		ImGui::PushItemWidth(-1);
		ImGui::InputText("##start", m_start_buf, sizeof(m_start_buf), ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::PopItemWidth();
		ImGui::Text("-");
		ImGui::PushItemWidth(-1);
		ImGui::InputText("##end", m_end_buf, sizeof(m_end_buf), ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::PopItemWidth();
	}

	ImGui::Spacing();
	ImGui::Spacing();

	// scan buttons
	float btn_w = (ImGui::GetContentRegionAvail().x - 8) * 0.5f;

	if (m_scanning)
	{
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.15f, 0.1f, 0.8f));
		if (ImGui::Button("Stop", ImVec2(-1, 30)))
			m_scanning = false;
		ImGui::PopStyleColor();

		ImGui::Spacing();
		float progress = m_scan_progress.load();
		char progress_text[32];
		snprintf(progress_text, sizeof(progress_text), "%d%%  (%d found)", (int)(progress * 100), m_scan_found.load());
		ImGui::ProgressBar(progress, ImVec2(-1, 20), progress_text);
	}
	else
	{
		// First Scan / Next Scan
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.4f, 0.1f, 0.8f));
		if (ImGui::Button(m_has_results ? "Next Scan" : "First Scan", ImVec2(btn_w, 30)))
		{
			if (m_has_results)
				do_next_scan();
			else
				do_first_scan();
		}
		ImGui::PopStyleColor();

		ImGui::SameLine(0, 8);

		// Undo Scan
		ImGui::BeginDisabled(!m_has_undo);
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.35f, 0.25f, 0.0f, 0.8f));
		if (ImGui::Button("Undo Scan", ImVec2(-1, 30)))
			do_undo_scan();
		ImGui::PopStyleColor();
		ImGui::EndDisabled();

		// New Scan (only when has results)
		if (m_has_results)
		{
			ImGui::Spacing();
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.5f, 0.1f, 0.1f, 0.8f));
			if (ImGui::Button("New Scan", ImVec2(-1, 30)))
			{
				std::lock_guard<std::mutex> lock(m_results_mutex);
				m_results.clear();
				m_has_results = false;
				m_undo_results.clear();
				m_has_undo = false;
				m_selected.clear();
			}
			ImGui::PopStyleColor();
		}

		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();

		// result count
		{
			std::lock_guard<std::mutex> lock(m_results_mutex);
			ImGui::Text("Results: %d", (int)m_results.size());
		}

		// Copy All Addresses
		if (m_has_results)
		{
			if (ImGui::Button("Copy All Addresses", ImVec2(-1, 0)))
			{
				std::lock_guard<std::mutex> lock(m_results_mutex);
				std::string all;
				int copy_count = (int)m_results.size() < 5000 ? (int)m_results.size() : 5000;
				for (int ci = 0; ci < copy_count; ci++)
				{
					if (!all.empty()) all += "\n";
					char buf[32];
					snprintf(buf, sizeof(buf), "0x%llX", m_results[ci].address);
					all += buf;
				}
				char toast_msg[64];
				snprintf(toast_msg, sizeof(toast_msg), "%d addresses copied", copy_count);
				ui::clipboard(all.c_str(), toast_msg);
			}
		}
	}
}

// ---- Render: integrated address list (bottom panel) ----

void ScannerPanel::render_address_list()
{
	// auto refresh at 10Hz
	if (anim::time() - m_addr_refresh_timer > 0.1f && !m_address_entries.empty())
	{
		refresh_address_values();
		m_addr_refresh_timer = anim::time();
	}

	// toolbar
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.4f, 0.1f, 0.8f));
	if (ImGui::Button("Add Address Manually", ImVec2(0, 24)))
	{
		m_show_add_modal = true;
		m_add_addr_buf[0] = '\0';
		m_add_desc_buf[0] = '\0';
	}
	ImGui::PopStyleColor();

	ImGui::SameLine(0, 12);
	ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Entries: %d", (int)m_address_entries.size());

	ImGui::Spacing();

	// table
	ImGui::PushFont(renderer::font_mono());

	if (ImGui::BeginTable("##addr_table", 5,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_Resizable,
		ImVec2(-1, -1)))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Active", ImGuiTableColumnFlags_WidthFixed, 45.0f);
		ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150.0f);
		ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 70.0f);
		ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 140.0f);
		ImGui::TableHeadersRow();

		int remove_idx = -1;
		int edit_req_idx = -1;

		for (int i = 0; i < (int)m_address_entries.size(); i++)
		{
			auto& e = m_address_entries[i];
			ImGui::TableNextRow();

			// active (freeze) checkbox
			ImGui::TableNextColumn();
			char chk_id[32];
			snprintf(chk_id, sizeof(chk_id), "##af%d", i);
			if (ImGui::Checkbox(chk_id, &e.active))
			{
				if (e.active)
				{
					int sz = watch_type_size(e.type);
					uint8_t buf[8] = {};
					memory::read(buf, e.address, sz);
					memcpy(&e.frozen_value, buf, sz < 8 ? sz : 8);
				}
			}

			// description
			ImGui::TableNextColumn();
			ImGui::Text("%s", e.description.c_str());

			// address
			ImGui::TableNextColumn();
			char addr_str[32];
			snprintf(addr_str, sizeof(addr_str), "0x%llX", e.address);
			ImGui::Text("%s", addr_str);

			// type dropdown
			ImGui::TableNextColumn();
			ImGui::PushItemWidth(-1);
			const char* types[] = { "UInt8", "UInt16", "UInt32", "UInt64", "Int32", "Float", "Double" };
			int type_idx = (int)e.type;
			char combo_id[32];
			snprintf(combo_id, sizeof(combo_id), "##at%d", i);
			if (ImGui::Combo(combo_id, &type_idx, types, IM_ARRAYSIZE(types)))
				e.type = (watch_type_t)type_idx;
			ImGui::PopItemWidth();

			// value (double-click to inline edit)
			ImGui::TableNextColumn();
			if (m_editing_value_idx == i)
			{
				ImGui::PushItemWidth(-1);
				char edit_id[32];
				snprintf(edit_id, sizeof(edit_id), "##aev%d", i);
				if (ImGui::InputText(edit_id, m_edit_value_buf, sizeof(m_edit_value_buf),
					ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll))
				{
					write_address_value(i, m_edit_value_buf);
					m_editing_value_idx = -1;
				}
				if (!ImGui::IsItemActive() && ImGui::IsMouseClicked(0))
					m_editing_value_idx = -1;
				ImGui::PopItemWidth();
			}
			else
			{
				// format value based on flags
				std::string display_val;
				if (e.value_str == "<invalid>")
				{
					display_val = e.value_str;
				}
				else if (e.show_hex)
				{
					int sz = watch_type_size(e.type);
					uint8_t buf[8] = {};
					memory::read(buf, e.address, sz);
					char hex[32];
					switch (sz)
					{
					case 1: snprintf(hex, sizeof(hex), "0x%02X", buf[0]); break;
					case 2: { uint16_t v; memcpy(&v, buf, 2); snprintf(hex, sizeof(hex), "0x%04X", v); break; }
					case 4: { uint32_t v; memcpy(&v, buf, 4); snprintf(hex, sizeof(hex), "0x%08X", v); break; }
					case 8: { uint64_t v; memcpy(&v, buf, 8); snprintf(hex, sizeof(hex), "0x%llX", v); break; }
					default: snprintf(hex, sizeof(hex), "%s", e.value_str.c_str()); break;
					}
					display_val = hex;
				}
				else if (e.show_signed && (e.type == watch_type_t::u32 || e.type == watch_type_t::u64))
				{
					int sz = watch_type_size(e.type);
					uint8_t buf[8] = {};
					memory::read(buf, e.address, sz);
					char sv[32];
					if (e.type == watch_type_t::u32) { int32_t v; memcpy(&v, buf, 4); snprintf(sv, sizeof(sv), "%d", v); }
					else { int64_t v; memcpy(&v, buf, 8); snprintf(sv, sizeof(sv), "%lld", v); }
					display_val = sv;
				}
				else
				{
					display_val = e.value_str;
				}

				// red highlight for 2s after value changes
				bool recently_changed = (e.change_time > 0.0f && anim::time() - e.change_time < 2.0f);
				if (recently_changed)
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.2f, 0.2f, 1.0f));

				char val_label[280];
				snprintf(val_label, sizeof(val_label), "%s##av%d", display_val.c_str(), i);
				if (ImGui::Selectable(val_label, false, ImGuiSelectableFlags_AllowDoubleClick))
				{
					if (ImGui::IsMouseDoubleClicked(0))
					{
						m_editing_value_idx = i;
						strncpy(m_edit_value_buf, e.value_str.c_str(), sizeof(m_edit_value_buf) - 1);
					}
				}

				if (recently_changed)
					ImGui::PopStyleColor();
			}

			// context menu for address list row
			char ctx_id[32];
			snprintf(ctx_id, sizeof(ctx_id), "##alctx%d", i);
			if (ImGui::BeginPopupContextItem(ctx_id))
			{
				if (ImGui::MenuItem("Delete this record"))
					remove_idx = i;
				if (ImGui::MenuItem("Change record"))
					edit_req_idx = i;

				ImGui::Separator();

				if (ImGui::MenuItem("Browse this memory region"))
					app::navigate_to_address(e.address, tab_id::memory_viewer);
				if (ImGui::MenuItem("Disassemble this memory region"))
					app::navigate_to_address(e.address, tab_id::disassembler);

				ImGui::Separator();

				if (ImGui::MenuItem("Show as Hex", nullptr, e.show_hex))
					e.show_hex = !e.show_hex;
				if (ImGui::MenuItem("Show as Signed", nullptr, e.show_signed))
					e.show_signed = !e.show_signed;

				ImGui::Separator();

				if (ImGui::MenuItem("Pointer scan for this address"))
					app::navigate_to_address(e.address, tab_id::pointer_scanner);
				if (ImGui::MenuItem("Find out what reads this address"))
					app::request_code_filter(e.address);
				if (ImGui::MenuItem("Find out what writes to this address"))
					app::request_code_filter(e.address);

				ImGui::EndPopup();
			}
		}

		ImGui::EndTable();

		if (remove_idx >= 0)
			m_address_entries.erase(m_address_entries.begin() + remove_idx);

		if (edit_req_idx >= 0)
		{
			m_show_edit_modal = true;
			m_edit_entry_idx = edit_req_idx;
			auto& e = m_address_entries[edit_req_idx];
			snprintf(m_edit_addr_buf, sizeof(m_edit_addr_buf), "%llX", e.address);
			strncpy(m_edit_desc_buf, e.description.c_str(), sizeof(m_edit_desc_buf) - 1);
			m_edit_type_idx = (int)e.type;
		}
	}

	ImGui::PopFont();

	// ---- Add Address modal ----
	if (m_show_add_modal)
	{
		ImGui::OpenPopup("Add Address##scanner");
		m_show_add_modal = false;
	}

	ImVec2 center = ImGui::GetMainViewport()->GetCenter();
	ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
	if (ImGui::BeginPopupModal("Add Address##scanner", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("Address (hex):");
		ImGui::PushItemWidth(200);
		ImGui::InputText("##aa_addr", m_add_addr_buf, sizeof(m_add_addr_buf),
			ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::PopItemWidth();

		ImGui::Text("Description:");
		ImGui::PushItemWidth(200);
		ImGui::InputText("##aa_desc", m_add_desc_buf, sizeof(m_add_desc_buf));
		ImGui::PopItemWidth();

		ImGui::Text("Type:");
		ImGui::PushItemWidth(120);
		const char* types[] = { "UInt8", "UInt16", "UInt32", "UInt64", "Int32", "Float", "Double" };
		ImGui::Combo("##aa_type", &m_add_type_idx, types, IM_ARRAYSIZE(types));
		ImGui::PopItemWidth();

		ImGui::Spacing();

		if (ImGui::Button("Add", ImVec2(80, 0)))
		{
			uint64_t addr = strtoull(m_add_addr_buf, nullptr, 16);
			if (addr)
			{
				add_address_entry(addr, (watch_type_t)m_add_type_idx, m_add_desc_buf);
				ImGui::CloseCurrentPopup();
			}
		}
		ImGui::SameLine(0, 8);
		if (ImGui::Button("Cancel", ImVec2(80, 0)))
			ImGui::CloseCurrentPopup();

		ImGui::EndPopup();
	}

	// ---- Edit record modal ----
	if (m_show_edit_modal)
	{
		ImGui::OpenPopup("Change Record##scanner");
		m_show_edit_modal = false;
	}

	ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
	if (ImGui::BeginPopupModal("Change Record##scanner", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("Address (hex):");
		ImGui::PushItemWidth(200);
		ImGui::InputText("##er_addr", m_edit_addr_buf, sizeof(m_edit_addr_buf),
			ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::PopItemWidth();

		ImGui::Text("Description:");
		ImGui::PushItemWidth(200);
		ImGui::InputText("##er_desc", m_edit_desc_buf, sizeof(m_edit_desc_buf));
		ImGui::PopItemWidth();

		ImGui::Text("Type:");
		ImGui::PushItemWidth(120);
		const char* types[] = { "UInt8", "UInt16", "UInt32", "UInt64", "Int32", "Float", "Double" };
		ImGui::Combo("##er_type", &m_edit_type_idx, types, IM_ARRAYSIZE(types));
		ImGui::PopItemWidth();

		ImGui::Spacing();

		if (ImGui::Button("OK", ImVec2(80, 0)))
		{
			if (m_edit_entry_idx >= 0 && m_edit_entry_idx < (int)m_address_entries.size())
			{
				auto& e = m_address_entries[m_edit_entry_idx];
				e.address = strtoull(m_edit_addr_buf, nullptr, 16);
				e.description = m_edit_desc_buf;
				e.type = (watch_type_t)m_edit_type_idx;
			}
			ImGui::CloseCurrentPopup();
		}
		ImGui::SameLine(0, 8);
		if (ImGui::Button("Cancel", ImVec2(80, 0)))
			ImGui::CloseCurrentPopup();

		ImGui::EndPopup();
	}
}

// ---- Main render ----

void ScannerPanel::render()
{
	auto& st = app::state();

	if (!st.process_attached)
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"Attach a process to use the scanner.");
		return;
	}

	// refresh found list values periodically (1 Hz — reading 5000 addresses is heavy)
	if (m_has_results && !m_scanning && anim::time() - m_found_refresh_timer > 1.0f)
	{
		refresh_found_values();
		m_found_refresh_timer = anim::time();
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

	ImVec2 avail = ImGui::GetContentRegionAvail();
	float top_height = avail.y * m_splitter_ratio;
	float bottom_height = avail.y - top_height - 6; // 6 px for splitter area

	// ---- TOP HALF: results left, controls right ----
	ImGui::BeginChild("##scanner_top", ImVec2(-1, top_height), false);
	{
		ImVec2 top_avail = ImGui::GetContentRegionAvail();
		float left_width = top_avail.x * 0.55f;

		// left: found list
		ImGui::BeginChild("##found_list", ImVec2(left_width, -1), true);
		render_found_list();
		ImGui::EndChild();

		ImGui::SameLine(0, 0);

		// right: scan controls
		ImGui::BeginChild("##scan_controls", ImVec2(-1, -1), true);
		render_scan_controls();
		ImGui::EndChild();
	}
	ImGui::EndChild();

	// ---- Splitter ----
	bool splitter_hovered = false;
	{
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.18f, 0.18f, 0.22f, 1.0f));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.28f, 0.28f, 0.35f, 1.0f));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.35f, 0.35f, 0.45f, 1.0f));
		ImGui::Button("##hsplitter", ImVec2(-1, 6));
		ImGui::PopStyleColor(3);

		splitter_hovered = ImGui::IsItemHovered() || ImGui::IsItemActive();

		// draw grip dots on splitter
		ImVec2 smin = ImGui::GetItemRectMin();
		ImVec2 smax = ImGui::GetItemRectMax();
		ui::draw_splitter_grip(smin, smax);

		if (ImGui::IsItemActive())
		{
			float delta = ImGui::GetIO().MouseDelta.y;
			float new_top = top_height + delta;
			float min_h = 80.0f;
			float max_h = avail.y - 80.0f;
			if (new_top >= min_h && new_top <= max_h)
				m_splitter_ratio = new_top / avail.y;
		}
		if (splitter_hovered)
			ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
	}

	// ---- BOTTOM HALF: address list / cheat table ----
	ImGui::BeginChild("##scanner_bottom", ImVec2(-1, bottom_height), false);
	render_address_list();
	ImGui::EndChild();
}
