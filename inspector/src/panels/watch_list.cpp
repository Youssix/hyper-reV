#include "watch_list.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../renderer/anim.h"
#include "../memory/memory_reader.h"
#include "../widgets/module_resolver.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

int WatchListPanel::type_size(watch_type_t type)
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
	case watch_type_t::aob: return 4;
	}
	return 4;
}

const char* WatchListPanel::type_name(watch_type_t type)
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
	case watch_type_t::aob: return "AOB";
	}
	return "?";
}

void WatchListPanel::refresh_values()
{
	for (auto& entry : m_entries)
	{
		int sz = type_size(entry.type);
		uint8_t buf[8] = {};

		// freeze: write frozen value before reading
		if (entry.frozen)
		{
			memory::write(&entry.frozen_value, entry.address, sz);
		}

		if (!memory::read(buf, entry.address, sz))
		{
			entry.value_str = "<invalid>";
			continue;
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
		case watch_type_t::aob:
		{
			std::string hex;
			for (int i = 0; i < entry.aob_size && i < (int)sizeof(buf); i++)
			{
				if (i > 0) hex += " ";
				char hb[4];
				snprintf(hb, sizeof(hb), "%02X", buf[i]);
				hex += hb;
			}
			entry.value_str = hex;
			continue;
		}
		}
		entry.value_str = val;
	}
}

void WatchListPanel::add_entry(uint64_t address, watch_type_t type, const char* label)
{
	watch_entry_t entry = {};
	entry.address = address;
	entry.type = type;
	entry.label = (label && label[0]) ? label : widgets::format_address_short(address);
	m_entries.push_back(std::move(entry));
}

void WatchListPanel::write_value(int index, const char* value_str)
{
	if (index < 0 || index >= (int)m_entries.size()) return;
	auto& entry = m_entries[index];
	int sz = type_size(entry.type);
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
	default: return;
	}

	memory::write(buf, entry.address, sz);

	if (entry.frozen)
		memcpy(&entry.frozen_value, buf, sz < 8 ? sz : 8);
}

void WatchListPanel::render()
{
	auto& st = app::state();

	if (!st.process_attached)
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"Attach a process to use the watch list.");
		return;
	}

	// check for pending add request from hex view
	uint64_t pending = app::consume_add_watch_request();
	if (pending)
		add_entry(pending, watch_type_t::u32, nullptr);

	// auto refresh
	if (anim::time() - m_refresh_timer > 0.1f && !m_entries.empty())
	{
		refresh_values();
		m_refresh_timer = anim::time();
	}

	// toolbar
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.4f, 0.1f, 0.8f));
	if (ImGui::Button("Add Address", ImVec2(100, 28)))
	{
		m_show_add_modal = true;
		m_add_addr_buf[0] = '\0';
		m_add_label_buf[0] = '\0';
	}
	ImGui::PopStyleColor();

	ImGui::SameLine(0, 8);
	if (ImGui::Button("Clear All", ImVec2(80, 28)))
		m_entries.clear();

	ImGui::SameLine(0, 16);
	ImGui::Text("Entries: %d", (int)m_entries.size());

	ImGui::Spacing();

	// watch table
	ImGui::PushFont(renderer::font_mono());

	if (ImGui::BeginTable("##wl_table", 5,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_Resizable,
		ImVec2(-1, -1)))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Freeze", ImGuiTableColumnFlags_WidthFixed, 45.0f);
		ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f);
		ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 70.0f);
		ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 160.0f);
		ImGui::TableHeadersRow();

		int remove_idx = -1;

		for (int i = 0; i < (int)m_entries.size(); i++)
		{
			auto& e = m_entries[i];
			ImGui::TableNextRow();

			// freeze checkbox
			ImGui::TableNextColumn();
			char chk_id[32];
			snprintf(chk_id, sizeof(chk_id), "##fr%d", i);
			if (ImGui::Checkbox(chk_id, &e.frozen))
			{
				if (e.frozen)
				{
					// capture current value as frozen value
					int sz = type_size(e.type);
					uint8_t buf[8] = {};
					memory::read(buf, e.address, sz);
					memcpy(&e.frozen_value, buf, sz < 8 ? sz : 8);
				}
			}

			// description (editable label)
			ImGui::TableNextColumn();
			ImGui::Text("%s", e.label.c_str());

			// address
			ImGui::TableNextColumn();
			char addr_buf[32];
			snprintf(addr_buf, sizeof(addr_buf), "0x%llX", e.address);
			ImGui::Text("%s", addr_buf);

			// type (dropdown on click)
			ImGui::TableNextColumn();
			ImGui::PushItemWidth(-1);
			const char* types[] = { "UInt8", "UInt16", "UInt32", "UInt64", "Int32", "Float", "Double", "AOB" };
			int type_idx = (int)e.type;
			char combo_id[32];
			snprintf(combo_id, sizeof(combo_id), "##ty%d", i);
			if (ImGui::Combo(combo_id, &type_idx, types, IM_ARRAYSIZE(types)))
				e.type = (watch_type_t)type_idx;
			ImGui::PopItemWidth();

			// value (double-click to edit)
			ImGui::TableNextColumn();
			if (m_editing_value_idx == i)
			{
				ImGui::PushItemWidth(-1);
				char edit_id[32];
				snprintf(edit_id, sizeof(edit_id), "##ev%d", i);
				if (ImGui::InputText(edit_id, m_edit_value_buf, sizeof(m_edit_value_buf),
					ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll))
				{
					write_value(i, m_edit_value_buf);
					m_editing_value_idx = -1;
				}
				if (!ImGui::IsItemActive() && ImGui::IsMouseClicked(0))
					m_editing_value_idx = -1;
				ImGui::PopItemWidth();
			}
			else
			{
				char val_label[280];
				snprintf(val_label, sizeof(val_label), "%s##v%d", e.value_str.c_str(), i);
				if (ImGui::Selectable(val_label, false))
				{
					if (ImGui::IsMouseDoubleClicked(0))
					{
						m_editing_value_idx = i;
						strncpy(m_edit_value_buf, e.value_str.c_str(), sizeof(m_edit_value_buf) - 1);
					}
				}
			}

			// context menu on the row
			char ctx_id[32];
			snprintf(ctx_id, sizeof(ctx_id), "##wlctx%d", i);
			if (ImGui::BeginPopupContextItem(ctx_id))
			{
				if (ImGui::MenuItem("View in Memory"))
					app::navigate_to_address(e.address, tab_id::memory_viewer);
				if (ImGui::MenuItem("View in Disasm"))
					app::navigate_to_address(e.address, tab_id::disassembler);
				if (ImGui::MenuItem("Find What Accesses"))
					app::request_code_filter(e.address);
				ImGui::Separator();
				if (ImGui::MenuItem("Copy Address"))
					ImGui::SetClipboardText(addr_buf);
				if (ImGui::MenuItem("Copy Value"))
					ImGui::SetClipboardText(e.value_str.c_str());
				ImGui::Separator();
				if (ImGui::MenuItem("Delete"))
					remove_idx = i;
				ImGui::EndPopup();
			}
		}

		ImGui::EndTable();

		if (remove_idx >= 0)
			m_entries.erase(m_entries.begin() + remove_idx);
	}

	ImGui::PopFont();

	// ---- Add Address modal ----
	if (m_show_add_modal)
	{
		ImGui::OpenPopup("Add Watch Address");
		m_show_add_modal = false;
	}

	ImVec2 center = ImGui::GetMainViewport()->GetCenter();
	ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
	if (ImGui::BeginPopupModal("Add Watch Address", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("Address (hex):");
		ImGui::PushItemWidth(200);
		ImGui::InputText("##wl_addr", m_add_addr_buf, sizeof(m_add_addr_buf),
			ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::PopItemWidth();

		ImGui::Text("Label:");
		ImGui::PushItemWidth(200);
		ImGui::InputText("##wl_label", m_add_label_buf, sizeof(m_add_label_buf));
		ImGui::PopItemWidth();

		ImGui::Text("Type:");
		ImGui::PushItemWidth(120);
		const char* types[] = { "UInt8", "UInt16", "UInt32", "UInt64", "Int32", "Float", "Double", "AOB" };
		ImGui::Combo("##wl_type", &m_add_type_idx, types, IM_ARRAYSIZE(types));
		ImGui::PopItemWidth();

		ImGui::Spacing();

		if (ImGui::Button("Add", ImVec2(80, 0)))
		{
			uint64_t addr = strtoull(m_add_addr_buf, nullptr, 16);
			if (addr)
			{
				add_entry(addr, (watch_type_t)m_add_type_idx, m_add_label_buf);
				ImGui::CloseCurrentPopup();
			}
		}

		ImGui::SameLine(0, 8);
		if (ImGui::Button("Cancel", ImVec2(80, 0)))
			ImGui::CloseCurrentPopup();

		ImGui::EndPopup();
	}

	// Ctrl+C: copy selected entry
	// (handled by context menu above)
}
