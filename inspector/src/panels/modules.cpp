#include "modules.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../memory/memory_reader.h"
#include "../widgets/module_resolver.h"
#include "hypercall/hypercall.h"
#include "system/system.h"
#include <portable_executable/image.hpp>
#include "../widgets/ui_helpers.h"
#include <cstdio>
#include <algorithm>
#include <cstring>

void ModulesPanel::load_modules()
{
	m_modules.clear();
	m_exports.clear();
	m_all_exports.clear();
	m_selected_module = -1;

	auto& st = app::state();
	if (!st.process_attached) return;

	// Read PEB to walk the module list
	uint64_t cr3 = st.attached_process.cr3;
	uint64_t eprocess = st.attached_process.eprocess;
	uint64_t peb_addr = 0;

	memory::read(&peb_addr, eprocess + sys::offsets::eprocess_peb, 8);
	if (peb_addr == 0) return;

	// PEB.Ldr (offset 0x18 on x64)
	uint64_t ldr_addr = 0;
	hypercall::read_guest_virtual_memory(&ldr_addr, peb_addr + 0x18, cr3, 8);
	if (ldr_addr == 0) return;

	// InLoadOrderModuleList is at offset 0x10 in PEB_LDR_DATA
	uint64_t list_head = ldr_addr + 0x10;
	uint64_t first_entry = 0;
	hypercall::read_guest_virtual_memory(&first_entry, list_head, cr3, 8);

	if (first_entry == 0 || first_entry == list_head) return;

	uint64_t current = first_entry;
	int count = 0;

	while (current != list_head && current != 0 && count < 512)
	{
		count++;
		module_entry_t mod = {};

		hypercall::read_guest_virtual_memory(&mod.base, current + 0x30, cr3, 8);

		uint32_t size_of_image = 0;
		hypercall::read_guest_virtual_memory(&size_of_image, current + 0x40, cr3, 4);
		mod.size = size_of_image;

		// read BaseDllName
		uint16_t name_len = 0;
		uint64_t name_buf_ptr = 0;
		hypercall::read_guest_virtual_memory(&name_len, current + 0x58, cr3, 2);
		hypercall::read_guest_virtual_memory(&name_buf_ptr, current + 0x58 + 8, cr3, 8);

		if (name_len > 0 && name_len < 512 && name_buf_ptr != 0)
		{
			std::wstring wname(name_len / 2, L'\0');
			hypercall::read_guest_virtual_memory(wname.data(), name_buf_ptr, cr3, name_len);
			mod.name = sys::user::to_string(wname);
		}
		else
		{
			mod.name = "<unknown>";
		}

		if (mod.base != 0)
			m_modules.push_back(mod);

		// follow Flink
		hypercall::read_guest_virtual_memory(&current, current, cr3, 8);
	}

	m_modules_loaded = true;

	// populate global module list for address resolution
	widgets::g_modules.clear();
	for (auto& mod : m_modules)
	{
		widgets::module_info_t info;
		info.name = mod.name;
		info.base = mod.base;
		info.size = mod.size;
		widgets::g_modules.push_back(info);
	}
	widgets::g_modules_valid = true;

	// load all exports for function finder
	load_all_exports();
}

void ModulesPanel::load_exports(int module_index)
{
	m_exports.clear();
	if (module_index < 0 || module_index >= (int)m_modules.size())
		return;

	auto& mod = m_modules[module_index];
	uint64_t cr3 = app::state().attached_process.cr3;

	// read PE headers
	uint8_t headers[0x1000] = {};
	hypercall::read_guest_virtual_memory(headers, mod.base, cr3, 0x1000);

	if (*(uint16_t*)headers != 0x5A4D)
		return;

	auto* image = reinterpret_cast<const portable_executable::image_t*>(headers);
	auto* nt = image->nt_headers();
	if (!nt) return;

	auto& export_dir = nt->optional_header.data_directories.export_directory;
	if (export_dir.virtual_address == 0 || export_dir.size == 0)
		return;

	// read export directory
	uint8_t export_data[0x1000] = {};
	uint64_t export_rva = export_dir.virtual_address;
	uint32_t read_size = export_dir.size < sizeof(export_data) ? export_dir.size : (uint32_t)sizeof(export_data);
	hypercall::read_guest_virtual_memory(export_data, mod.base + export_rva, cr3, read_size);

	struct export_dir_t {
		uint32_t characteristics, time_date_stamp;
		uint16_t major_version, minor_version;
		uint32_t name_rva, ordinal_base, number_of_functions, number_of_names;
		uint32_t address_of_functions, address_of_names, address_of_name_ordinals;
	};

	auto* exp = reinterpret_cast<export_dir_t*>(export_data);

	if (exp->number_of_names > 10000 || exp->number_of_names == 0)
		return;

	// read name RVAs
	std::vector<uint32_t> name_rvas(exp->number_of_names);
	hypercall::read_guest_virtual_memory(name_rvas.data(), mod.base + exp->address_of_names,
		cr3, exp->number_of_names * 4);

	// read ordinals
	std::vector<uint16_t> ordinals(exp->number_of_names);
	hypercall::read_guest_virtual_memory(ordinals.data(), mod.base + exp->address_of_name_ordinals,
		cr3, exp->number_of_names * 2);

	// read function RVAs
	std::vector<uint32_t> func_rvas(exp->number_of_functions);
	hypercall::read_guest_virtual_memory(func_rvas.data(), mod.base + exp->address_of_functions,
		cr3, exp->number_of_functions * 4);

	for (uint32_t i = 0; i < exp->number_of_names; i++)
	{
		char name[256] = {};
		hypercall::read_guest_virtual_memory(name, mod.base + name_rvas[i], cr3, sizeof(name) - 1);

		export_entry_t entry;
		entry.name = name;

		uint16_t ordinal = ordinals[i];
		if (ordinal < exp->number_of_functions)
			entry.address = mod.base + func_rvas[ordinal];
		else
			entry.address = 0;

		m_exports.push_back(entry);
	}
}

void ModulesPanel::load_all_exports()
{
	m_all_exports.clear();

	uint64_t cr3 = app::state().attached_process.cr3;

	for (auto& mod : m_modules)
	{
		// read PE headers
		uint8_t headers[0x1000] = {};
		hypercall::read_guest_virtual_memory(headers, mod.base, cr3, 0x1000);

		if (*(uint16_t*)headers != 0x5A4D)
			continue;

		auto* image = reinterpret_cast<const portable_executable::image_t*>(headers);
		auto* nt = image->nt_headers();
		if (!nt) continue;

		auto& export_dir = nt->optional_header.data_directories.export_directory;
		if (export_dir.virtual_address == 0 || export_dir.size == 0)
			continue;

		uint8_t export_data[0x1000] = {};
		uint32_t read_size = export_dir.size < sizeof(export_data) ? export_dir.size : (uint32_t)sizeof(export_data);
		hypercall::read_guest_virtual_memory(export_data, mod.base + export_dir.virtual_address, cr3, read_size);

		struct export_dir_t {
			uint32_t characteristics, time_date_stamp;
			uint16_t major_version, minor_version;
			uint32_t name_rva, ordinal_base, number_of_functions, number_of_names;
			uint32_t address_of_functions, address_of_names, address_of_name_ordinals;
		};
		auto* exp = reinterpret_cast<export_dir_t*>(export_data);

		if (exp->number_of_names > 10000 || exp->number_of_names == 0)
			continue;

		std::vector<uint32_t> name_rvas(exp->number_of_names);
		hypercall::read_guest_virtual_memory(name_rvas.data(), mod.base + exp->address_of_names,
			cr3, exp->number_of_names * 4);

		std::vector<uint16_t> ordinals(exp->number_of_names);
		hypercall::read_guest_virtual_memory(ordinals.data(), mod.base + exp->address_of_name_ordinals,
			cr3, exp->number_of_names * 2);

		std::vector<uint32_t> func_rvas(exp->number_of_functions);
		hypercall::read_guest_virtual_memory(func_rvas.data(), mod.base + exp->address_of_functions,
			cr3, exp->number_of_functions * 4);

		for (uint32_t i = 0; i < exp->number_of_names; i++)
		{
			char name[256] = {};
			hypercall::read_guest_virtual_memory(name, mod.base + name_rvas[i], cr3, sizeof(name) - 1);

			global_export_t ge;
			ge.module_name = mod.name;
			ge.export_name = name;

			uint16_t ordinal = ordinals[i];
			if (ordinal < exp->number_of_functions)
				ge.address = mod.base + func_rvas[ordinal];
			else
				ge.address = 0;

			m_all_exports.push_back(ge);
		}
	}
}

void ModulesPanel::render()
{
	auto& st = app::state();

	if (!st.process_attached)
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"Attach a process to view modules.");
		return;
	}

	if (!m_modules_loaded)
		load_modules();

	// toolbar
	if (ImGui::Button("Refresh", ImVec2(80, 28)))
		load_modules();

	ImGui::SameLine(0, 16);
	ImGui::Text("Modules: %d", (int)m_modules.size());

	ImGui::SameLine(0, 24);
	ImGui::Text("Exports: %d", (int)m_all_exports.size());

	ImGui::Spacing();

	// ---- Function Finder search bar ----
	ImGui::PushItemWidth(-1);
	ImGui::InputTextWithHint("##func_search", "Search all exports... (e.g. CreateFile, NtQuery)", m_function_search, sizeof(m_function_search));
	ImGui::PopItemWidth();

	// if search is active, show cross-module results instead of normal split view
	if (m_function_search[0] != '\0')
	{
		ImGui::Spacing();

		// case-insensitive filter
		std::string needle(m_function_search);
		std::transform(needle.begin(), needle.end(), needle.begin(), ::tolower);

		int match_count = 0;
		for (auto& ge : m_all_exports)
		{
			std::string haystack = ge.export_name;
			std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
			if (haystack.find(needle) != std::string::npos)
				match_count++;
		}

		ImGui::Text("Matches: %d", match_count);
		if (match_count > 2000)
			ImGui::SameLine(), ImGui::TextColored(ImVec4(0.9f, 0.6f, 0.1f, 1.0f), "(showing first 2000)");

		ImGui::Spacing();

		if (ImGui::BeginTable("##func_results", 3,
			ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_Resizable,
			ImVec2(-1, -1)))
		{
			ImGui::TableSetupScrollFreeze(0, 1);
			ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, 140.0f);
			ImGui::TableSetupColumn("Export", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f);
			ImGui::TableHeadersRow();

			int shown = 0;
			for (int i = 0; i < (int)m_all_exports.size() && shown < 2000; i++)
			{
				auto& ge = m_all_exports[i];

				std::string haystack = ge.export_name;
				std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
				if (haystack.find(needle) == std::string::npos)
					continue;

				shown++;
				ImGui::TableNextRow();

				ImGui::TableNextColumn();
				char sel_label[280];
				snprintf(sel_label, sizeof(sel_label), "%s##fe%d", ge.module_name.c_str(), i);

				if (ImGui::Selectable(sel_label, false,
					ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
				{
					if (ImGui::IsMouseDoubleClicked(0))
						app::navigate_to_address(ge.address, tab_id::disassembler);
				}

				if (ImGui::BeginPopupContextItem())
				{
					if (ImGui::MenuItem("Disassemble"))
						app::navigate_to_address(ge.address, tab_id::disassembler);
					if (ImGui::MenuItem("View in Memory"))
						app::navigate_to_address(ge.address, tab_id::memory_viewer);
					ImGui::Separator();
					if (ImGui::MenuItem("Copy Address"))
					{
						char buf[32];
						snprintf(buf, sizeof(buf), "0x%llX", ge.address);
						ui::clipboard(buf, "Address copied");
					}
					if (ImGui::MenuItem("Copy Module+Offset"))
					{
						std::string mod_str = widgets::format_address_short(ge.address);
						ui::clipboard(mod_str.c_str(), "Address copied");
					}
					ImGui::EndPopup();
				}

				ImGui::TableNextColumn();
				ImGui::Text("%s", ge.export_name.c_str());

				ImGui::TableNextColumn();
				ImGui::PushFont(renderer::font_mono());
				ImGui::Text("0x%llX", ge.address);
				ImGui::PopFont();
			}

			ImGui::EndTable();
		}

		return; // skip normal split view when searching
	}

	ImGui::Spacing();

	// split view: modules left, exports right
	ImVec2 avail = ImGui::GetContentRegionAvail();
	float left_width = avail.x * 0.45f;

	// modules table
	ImGui::BeginChild("##modules_left", ImVec2(left_width, -1), true);
	widgets::filter_bar("##mod_filter", m_module_filter, -1.0f);

	if (ImGui::BeginTable("##modtable", 3,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
		ImVec2(-1, -1)))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 140.0f);
		ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 80.0f);
		ImGui::TableHeadersRow();

		for (int i = 0; i < (int)m_modules.size(); i++)
		{
			auto& mod = m_modules[i];
			if (!m_module_filter.passes(mod.name.c_str()))
				continue;

			ImGui::TableNextRow();
			ImGui::TableNextColumn();

			bool selected = (i == m_selected_module);
			if (ImGui::Selectable(mod.name.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns))
			{
				m_selected_module = i;
				load_exports(i);
			}

			// context menu
			if (ImGui::BeginPopupContextItem())
			{
				if (ImGui::MenuItem("View in Memory"))
					app::navigate_to_address(mod.base, tab_id::memory_viewer);
				if (ImGui::MenuItem("Disassemble Entry"))
					app::navigate_to_address(mod.base, tab_id::disassembler);
				ImGui::Separator();
				if (ImGui::MenuItem("Copy Base Address"))
				{
					char buf[32];
					snprintf(buf, sizeof(buf), "0x%llX", mod.base);
					ui::clipboard(buf, "Address copied");
				}
				ImGui::EndPopup();
			}

			ImGui::TableNextColumn();
			ImGui::PushFont(renderer::font_mono());
			ImGui::Text("0x%llX", mod.base);
			ImGui::PopFont();

			ImGui::TableNextColumn();
			ImGui::Text("0x%X", mod.size);
		}

		ImGui::EndTable();
	}
	ImGui::EndChild();

	ImGui::SameLine();

	// exports table
	ImGui::BeginChild("##exports_right", ImVec2(-1, -1), true);

	if (m_selected_module >= 0)
	{
		ImGui::PushFont(renderer::font_bold());
		ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "%s Exports (%d)",
			m_modules[m_selected_module].name.c_str(), (int)m_exports.size());
		ImGui::PopFont();

		widgets::filter_bar("##exp_filter", m_export_filter, -1.0f);

		if (ImGui::BeginTable("##exptable", 2,
			ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
			ImVec2(-1, -1)))
		{
			ImGui::TableSetupScrollFreeze(0, 1);
			ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f);
			ImGui::TableHeadersRow();

			for (auto& exp : m_exports)
			{
				if (!m_export_filter.passes(exp.name.c_str()))
					continue;

				ImGui::TableNextRow();
				ImGui::TableNextColumn();
				ImGui::Text("%s", exp.name.c_str());

				if (ImGui::BeginPopupContextItem(exp.name.c_str()))
				{
					if (ImGui::MenuItem("View in Memory"))
						app::navigate_to_address(exp.address, tab_id::memory_viewer);
					if (ImGui::MenuItem("Disassemble"))
						app::navigate_to_address(exp.address, tab_id::disassembler);
					ImGui::Separator();
					if (ImGui::MenuItem("Copy Address"))
					{
						char buf[32];
						snprintf(buf, sizeof(buf), "0x%llX", exp.address);
						ui::clipboard(buf, "Address copied");
					}
					if (ImGui::MenuItem("Copy Module+Offset"))
					{
						std::string mod_str = widgets::format_address_short(exp.address);
						ui::clipboard(mod_str.c_str(), "Address copied");
					}
					ImGui::EndPopup();
				}

				ImGui::TableNextColumn();
				ImGui::PushFont(renderer::font_mono());
				ImGui::Text("0x%llX", exp.address);
				ImGui::PopFont();
			}

			ImGui::EndTable();
		}
	}
	else
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Select a module to view exports.");
	}

	ImGui::EndChild();
}
