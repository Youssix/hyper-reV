#include "struct_editor.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../memory/memory_reader.h"
#include "../widgets/address_input.h"
#include <cstdio>
#include <cstring>

void StructEditorPanel::add_field(int struct_idx)
{
	if (struct_idx < 0 || struct_idx >= (int)m_structs.size())
		return;

	auto& s = m_structs[struct_idx];
	project::field_def_t field;
	field.name = "field_" + std::to_string(s.fields.size());
	field.type = project::field_type_t::int32;
	field.offset = s.fields.empty() ? 0 : (s.fields.back().offset + project::field_size(s.fields.back().type));
	field.array_count = 1;
	s.fields.push_back(field);
}

void StructEditorPanel::render_struct_list()
{
	ImGui::BeginChild("##struct_list", ImVec2(250, -1), true);

	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "Structures");
	ImGui::PopFont();

	if (ImGui::Button("New Struct", ImVec2(-1, 24)))
	{
		project::struct_def_t s;
		s.name = "Struct_" + std::to_string(m_structs.size());
		m_structs.push_back(s);
		m_selected_struct = (int)m_structs.size() - 1;
	}

	ImGui::Spacing();

	for (int i = 0; i < (int)m_structs.size(); i++)
	{
		bool selected = (i == m_selected_struct);
		if (ImGui::Selectable(m_structs[i].name.c_str(), selected))
			m_selected_struct = i;

		if (ImGui::BeginPopupContextItem())
		{
			if (ImGui::MenuItem("Rename"))
			{
				m_editing_name = true;
				strncpy(m_name_buf, m_structs[i].name.c_str(), sizeof(m_name_buf) - 1);
			}
			if (ImGui::MenuItem("Delete"))
			{
				m_structs.erase(m_structs.begin() + i);
				if (m_selected_struct >= (int)m_structs.size())
					m_selected_struct = (int)m_structs.size() - 1;
				ImGui::EndPopup();
				ImGui::EndChild();
				return;
			}
			ImGui::EndPopup();
		}
	}

	ImGui::Spacing();
	ImGui::Separator();
	ImGui::Spacing();

	if (ImGui::Button("Save All", ImVec2(-1, 24)))
		project::save_structs("inspector_structs.json", m_structs);

	if (ImGui::Button("Load", ImVec2(-1, 24)))
		project::load_structs("inspector_structs.json", m_structs);

	ImGui::EndChild();
}

void StructEditorPanel::render_struct_view()
{
	ImGui::BeginChild("##struct_view", ImVec2(-1, -1), true);

	if (m_selected_struct < 0 || m_selected_struct >= (int)m_structs.size())
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Select or create a structure.");
		ImGui::EndChild();
		return;
	}

	auto& s = m_structs[m_selected_struct];

	// struct header
	ImGui::PushFont(renderer::font_bold());

	if (m_editing_name)
	{
		ImGui::PushItemWidth(200);
		if (ImGui::InputText("##rename", m_name_buf, sizeof(m_name_buf),
			ImGuiInputTextFlags_EnterReturnsTrue))
		{
			s.name = m_name_buf;
			m_editing_name = false;
		}
		ImGui::PopItemWidth();

		if (ImGui::IsKeyPressed(ImGuiKey_Escape))
			m_editing_name = false;
	}
	else
	{
		ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "%s", s.name.c_str());
	}
	ImGui::PopFont();

	ImGui::SameLine(0, 16);
	ImGui::Text("Address:");
	ImGui::SameLine();
	widgets::address_input("##struct_addr", m_view_address, 180.0f);

	ImGui::SameLine(0, 16);
	if (ImGui::Button("Add Field"))
		add_field(m_selected_struct);

	ImGui::Spacing();

	// fields table
	if (ImGui::BeginTable("##fields", 5,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
		ImVec2(-1, -1)))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 70.0f);
		ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 160.0f);
		ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("##actions", ImGuiTableColumnFlags_WidthFixed, 30.0f);
		ImGui::TableHeadersRow();

		int to_delete = -1;

		for (int i = 0; i < (int)s.fields.size(); i++)
		{
			auto& field = s.fields[i];
			ImGui::TableNextRow();

			// offset
			ImGui::TableNextColumn();
			ImGui::PushFont(renderer::font_mono());
			ImGui::Text("0x%03X", field.offset);
			ImGui::PopFont();

			// type (right-click to change)
			ImGui::TableNextColumn();
			const char* type_name = project::field_type_name(field.type);
			ImGui::Text("%s", type_name);

			char type_popup_id[32];
			snprintf(type_popup_id, sizeof(type_popup_id), "##type_popup_%d", i);
			if (ImGui::BeginPopupContextItem(type_popup_id))
			{
				const char* types[] = {
					"Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32",
					"Int64", "UInt64", "Float", "Double", "Ptr64", "Char[16]",
					"Char[32]", "Char[64]", "Bool"
				};
				const project::field_type_t type_vals[] = {
					project::field_type_t::int8, project::field_type_t::uint8,
					project::field_type_t::int16, project::field_type_t::uint16,
					project::field_type_t::int32, project::field_type_t::uint32,
					project::field_type_t::int64, project::field_type_t::uint64,
					project::field_type_t::float32, project::field_type_t::float64,
					project::field_type_t::ptr64, project::field_type_t::char16,
					project::field_type_t::char32, project::field_type_t::char64,
					project::field_type_t::bool8
				};

				for (int t = 0; t < IM_ARRAYSIZE(types); t++)
				{
					if (ImGui::MenuItem(types[t]))
						field.type = type_vals[t];
				}
				ImGui::EndPopup();
			}

			// name (editable)
			ImGui::TableNextColumn();
			char name_id[32];
			snprintf(name_id, sizeof(name_id), "##fn_%d", i);
			char name_buf[128];
			strncpy(name_buf, field.name.c_str(), sizeof(name_buf) - 1);
			name_buf[sizeof(name_buf) - 1] = '\0';
			ImGui::PushItemWidth(-1);
			if (ImGui::InputText(name_id, name_buf, sizeof(name_buf)))
				field.name = name_buf;
			ImGui::PopItemWidth();

			// live value
			ImGui::TableNextColumn();
			if (m_view_address != 0 && app::state().process_attached)
			{
				uint64_t addr = m_view_address + field.offset;
				int sz = project::field_size(field.type);
				uint8_t buf[64] = {};

				if (memory::read(buf, addr, sz))
				{
					ImGui::PushFont(renderer::font_mono());
					char val[128] = {};

					switch (field.type)
					{
					case project::field_type_t::int8: snprintf(val, sizeof(val), "%d", *(int8_t*)buf); break;
					case project::field_type_t::uint8: snprintf(val, sizeof(val), "%u", *(uint8_t*)buf); break;
					case project::field_type_t::int16: snprintf(val, sizeof(val), "%d", *(int16_t*)buf); break;
					case project::field_type_t::uint16: snprintf(val, sizeof(val), "%u", *(uint16_t*)buf); break;
					case project::field_type_t::int32: snprintf(val, sizeof(val), "%d", *(int32_t*)buf); break;
					case project::field_type_t::uint32: snprintf(val, sizeof(val), "%u", *(uint32_t*)buf); break;
					case project::field_type_t::int64: snprintf(val, sizeof(val), "%lld", *(int64_t*)buf); break;
					case project::field_type_t::uint64: snprintf(val, sizeof(val), "%llu", *(uint64_t*)buf); break;
					case project::field_type_t::float32: snprintf(val, sizeof(val), "%.6g", *(float*)buf); break;
					case project::field_type_t::float64: snprintf(val, sizeof(val), "%.10g", *(double*)buf); break;
					case project::field_type_t::ptr64:
					{
						uint64_t ptr = *(uint64_t*)buf;
						snprintf(val, sizeof(val), "-> 0x%llX", ptr);
						break;
					}
					case project::field_type_t::char16:
					case project::field_type_t::char32:
					case project::field_type_t::char64:
						buf[sz - 1] = '\0';
						snprintf(val, sizeof(val), "\"%s\"", (char*)buf);
						break;
					case project::field_type_t::bool8:
						snprintf(val, sizeof(val), "%s", buf[0] ? "true" : "false");
						break;
					}

					// highlight changed values
					bool changed = memory::did_byte_change(addr);
					if (changed)
						ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "%s", val);
					else
						ImGui::Text("%s", val);

					// ptr expansion
					if (field.type == project::field_type_t::ptr64)
					{
						uint64_t ptr = *(uint64_t*)buf;
						if (ptr != 0)
						{
							ImGui::SameLine();
							char ptr_btn[32];
							snprintf(ptr_btn, sizeof(ptr_btn), ">>##ptr_%d", i);
							if (ImGui::SmallButton(ptr_btn))
								m_view_address = ptr;
						}
					}

					ImGui::PopFont();
				}
				else
				{
					ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "???");
				}
			}
			else
			{
				ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "-");
			}

			// delete button
			ImGui::TableNextColumn();
			char del_id[32];
			snprintf(del_id, sizeof(del_id), "X##del_%d", i);
			if (ImGui::SmallButton(del_id))
				to_delete = i;
		}

		if (to_delete >= 0)
			s.fields.erase(s.fields.begin() + to_delete);

		ImGui::EndTable();
	}

	ImGui::EndChild();
}

void StructEditorPanel::render()
{
	render_struct_list();
	ImGui::SameLine();
	render_struct_view();
}
