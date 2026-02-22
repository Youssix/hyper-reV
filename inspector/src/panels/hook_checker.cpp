#include "hook_checker.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../memory/memory_reader.h"
#include "../widgets/module_resolver.h"
#include "hypercall/hypercall.h"
#include "system/system.h"
#include <portable_executable/image.hpp>
#include "../widgets/ui_helpers.h"
#include <cstdio>
#include <cstring>

HookCheckerPanel::~HookCheckerPanel()
{
	m_scanning = false;
	if (m_scan_thread.joinable())
		m_scan_thread.join();
}

void HookCheckerPanel::scan_inline_hooks()
{
	if (m_scanning) return;

	m_scanning = true;
	m_progress = 0.0f;
	m_found = 0;

	if (m_scan_thread.joinable())
		m_scan_thread.join();

	m_scan_thread = std::thread([this]()
	{
		auto& st = app::state();
		uint64_t cr3 = st.attached_process.cr3;

		std::vector<hook_result_t> results;
		int total_modules = (int)widgets::g_modules.size();

		for (int mi = 0; mi < total_modules && m_scanning; mi++)
		{
			m_progress = (float)mi / (float)total_modules;
			auto& mod = widgets::g_modules[mi];

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

			// read export directory
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

			// read name RVAs, ordinals, function RVAs
			std::vector<uint32_t> name_rvas(exp->number_of_names);
			hypercall::read_guest_virtual_memory(name_rvas.data(), mod.base + exp->address_of_names, cr3, exp->number_of_names * 4);

			std::vector<uint16_t> ordinals(exp->number_of_names);
			hypercall::read_guest_virtual_memory(ordinals.data(), mod.base + exp->address_of_name_ordinals, cr3, exp->number_of_names * 2);

			std::vector<uint32_t> func_rvas(exp->number_of_functions);
			hypercall::read_guest_virtual_memory(func_rvas.data(), mod.base + exp->address_of_functions, cr3, exp->number_of_functions * 4);

			// check first bytes of each export
			for (uint32_t i = 0; i < exp->number_of_names && m_scanning; i++)
			{
				char name[256] = {};
				hypercall::read_guest_virtual_memory(name, mod.base + name_rvas[i], cr3, sizeof(name) - 1);

				uint16_t ordinal = ordinals[i];
				if (ordinal >= exp->number_of_functions) continue;

				uint64_t func_addr = mod.base + func_rvas[ordinal];
				uint8_t code[16] = {};
				hypercall::read_guest_virtual_memory(code, func_addr, cr3, 16);

				hook_result_t hook = {};
				hook.module_name = mod.name;
				hook.function_name = name;
				hook.address = func_addr;
				bool found = false;

				// jmp rel32 (E9 xx xx xx xx)
				if (code[0] == 0xE9)
				{
					int32_t disp = 0;
					memcpy(&disp, code + 1, 4);
					uint64_t target = func_addr + 5 + disp;
					hook.hook_type = "Inline (JMP)";
					char buf[64];
					snprintf(buf, sizeof(buf), "-> %s", widgets::format_address_short(target).c_str());
					hook.details = buf;
					found = true;
				}
				// jmp [rip+disp32] (FF 25 xx xx xx xx)
				else if (code[0] == 0xFF && code[1] == 0x25)
				{
					int32_t disp = 0;
					memcpy(&disp, code + 2, 4);
					uint64_t ptr_addr = func_addr + 6 + disp;
					uint64_t target = 0;
					hypercall::read_guest_virtual_memory(&target, ptr_addr, cr3, 8);

					// check if target is outside this module (legitimate thunks stay in module)
					if (target < mod.base || target >= mod.base + mod.size)
					{
						hook.hook_type = "Inline (JMP [RIP])";
						char buf[64];
						snprintf(buf, sizeof(buf), "-> %s", widgets::format_address_short(target).c_str());
						hook.details = buf;
						found = true;
					}
				}
				// push low32 / mov [rsp+4], high32 / ret (our 14-byte pattern)
				else if (code[0] == 0x68) // push imm32
				{
					// check for mov dword ptr [rsp+4], imm32 at +5 (C7 44 24 04 xx xx xx xx) + ret (C3) at +13
					if (code[5] == 0xC7 && code[6] == 0x44 && code[7] == 0x24 && code[8] == 0x04 && code[13] == 0xC3)
					{
						uint32_t low = 0, high = 0;
						memcpy(&low, code + 1, 4);
						memcpy(&high, code + 9, 4);
						uint64_t target = ((uint64_t)high << 32) | low;
						hook.hook_type = "Inline (PUSH/RET)";
						char buf[64];
						snprintf(buf, sizeof(buf), "-> %s", widgets::format_address_short(target).c_str());
						hook.details = buf;
						found = true;
					}
				}
				// int3 patch at entry
				else if (code[0] == 0xCC)
				{
					hook.hook_type = "Inline (INT3)";
					hook.details = "Breakpoint at entry";
					found = true;
				}

				if (found)
				{
					std::lock_guard<std::mutex> lock(m_results_mutex);
					results.push_back(hook);
					m_found = (int)results.size();
				}
			}
		}

		std::lock_guard<std::mutex> lock(m_results_mutex);
		for (auto& r : results)
			m_results.push_back(std::move(r));

		m_progress = 1.0f;
		m_scanning = false;
	});
}

void HookCheckerPanel::scan_iat_hooks()
{
	if (m_scanning) return;

	m_scanning = true;
	m_progress = 0.0f;
	m_found = 0;

	if (m_scan_thread.joinable())
		m_scan_thread.join();

	m_scan_thread = std::thread([this]()
	{
		auto& st = app::state();
		uint64_t cr3 = st.attached_process.cr3;

		std::vector<hook_result_t> results;
		int total_modules = (int)widgets::g_modules.size();

		for (int mi = 0; mi < total_modules && m_scanning; mi++)
		{
			m_progress = (float)mi / (float)total_modules;
			auto& mod = widgets::g_modules[mi];

			// read PE headers
			uint8_t headers[0x1000] = {};
			hypercall::read_guest_virtual_memory(headers, mod.base, cr3, 0x1000);
			if (*(uint16_t*)headers != 0x5A4D)
				continue;

			auto* image = reinterpret_cast<const portable_executable::image_t*>(headers);
			auto* nt = image->nt_headers();
			if (!nt) continue;

			auto& import_dir = nt->optional_header.data_directories.import_directory;
			if (import_dir.virtual_address == 0 || import_dir.size == 0)
				continue;

			// read import descriptors
			struct import_desc_t {
				uint32_t original_first_thunk;
				uint32_t time_date_stamp;
				uint32_t forwarder_chain;
				uint32_t name_rva;
				uint32_t first_thunk;
			};

			uint8_t import_data[0x2000] = {};
			uint32_t read_size = import_dir.size < sizeof(import_data) ? import_dir.size : (uint32_t)sizeof(import_data);
			hypercall::read_guest_virtual_memory(import_data, mod.base + import_dir.virtual_address, cr3, read_size);

			auto* descs = reinterpret_cast<import_desc_t*>(import_data);

			for (int di = 0; descs[di].first_thunk != 0 && di < 256 && m_scanning; di++)
			{
				// read imported module name
				char imp_mod_name[128] = {};
				hypercall::read_guest_virtual_memory(imp_mod_name, mod.base + descs[di].name_rva, cr3, sizeof(imp_mod_name) - 1);

				// find expected module
				widgets::module_info_t* expected_mod = nullptr;
				for (auto& m : widgets::g_modules)
				{
					if (_stricmp(m.name.c_str(), imp_mod_name) == 0)
					{
						expected_mod = &m;
						break;
					}
				}

				// walk IAT entries
				uint64_t iat_addr = mod.base + descs[di].first_thunk;
				uint64_t oft_addr = descs[di].original_first_thunk ?
					mod.base + descs[di].original_first_thunk : iat_addr;

				for (int ei = 0; ei < 4096 && m_scanning; ei++)
				{
					uint64_t iat_entry = 0;
					hypercall::read_guest_virtual_memory(&iat_entry, iat_addr + ei * 8, cr3, 8);
					if (iat_entry == 0) break;

					// read function name from OFT hint/name table
					uint64_t oft_entry = 0;
					hypercall::read_guest_virtual_memory(&oft_entry, oft_addr + ei * 8, cr3, 8);

					char func_name[128] = {};
					if (oft_entry && !(oft_entry & (1ull << 63)))
					{
						// hint/name — name starts at +2
						hypercall::read_guest_virtual_memory(func_name, mod.base + (uint32_t)oft_entry + 2, cr3, sizeof(func_name) - 1);
					}

					// check if IAT entry points outside expected module
					if (expected_mod && (iat_entry < expected_mod->base ||
						iat_entry >= expected_mod->base + expected_mod->size))
					{
						hook_result_t hook = {};
						hook.module_name = mod.name;
						hook.function_name = func_name[0] ? func_name : "<ordinal>";
						hook.address = iat_addr + ei * 8;
						hook.hook_type = "IAT";

						char buf[128];
						snprintf(buf, sizeof(buf), "%s -> %s (expected: %s)",
							imp_mod_name,
							widgets::format_address_short(iat_entry).c_str(),
							expected_mod->name.c_str());
						hook.details = buf;

						std::lock_guard<std::mutex> lock(m_results_mutex);
						results.push_back(hook);
						m_found = (int)results.size();
					}
				}
			}
		}

		std::lock_guard<std::mutex> lock(m_results_mutex);
		for (auto& r : results)
			m_results.push_back(std::move(r));

		m_progress = 1.0f;
		m_scanning = false;
	});
}

void HookCheckerPanel::scan_ept_hooks()
{
	if (m_scanning) return;

	m_scanning = true;
	m_progress = 0.0f;
	m_found = 0;

	if (m_scan_thread.joinable())
		m_scan_thread.join();

	m_scan_thread = std::thread([this]()
	{
		auto& st = app::state();
		uint64_t cr3 = st.attached_process.cr3;

		std::vector<hook_result_t> results;
		int total_modules = (int)widgets::g_modules.size();

		for (int mi = 0; mi < total_modules && m_scanning; mi++)
		{
			m_progress = (float)mi / (float)total_modules;
			auto& mod = widgets::g_modules[mi];

			// scan each page of the module
			for (uint64_t page = mod.base; page < mod.base + mod.size && m_scanning; page += 0x1000)
			{
				uint64_t gpa = hypercall::translate_guest_virtual_address(page, cr3);
				if (gpa == 0) continue;

				uint64_t page_gpa = gpa & ~0xFFFull;

				// read EPT PTE from both hyperv_cr3 (index 0) and hook_cr3 (index 1)
				uint64_t pte0 = hypercall::read_ept_pte(page_gpa, 0);
				uint64_t pte1 = hypercall::read_ept_pte(page_gpa, 1);

				// extract execute permission (bit 2) and found flag (bit 3)
				bool found0 = (pte0 >> 3) & 1;
				bool found1 = (pte1 >> 3) & 1;
				if (!found0 || !found1) continue;

				// extract PFN (bits 12+)
				uint64_t pfn0 = pte0 >> 12;
				uint64_t pfn1 = pte1 >> 12;

				// if execute PFN differs between the two EPTs, it's an EPT hook
				bool exec0 = (pte0 >> 2) & 1;
				bool exec1 = (pte1 >> 2) & 1;

				if (pfn0 != pfn1 || exec0 != exec1)
				{
					hook_result_t hook = {};
					hook.module_name = mod.name;
					hook.address = page;

					char func_buf[64];
					snprintf(func_buf, sizeof(func_buf), "Page 0x%llX", page);
					hook.function_name = func_buf;
					hook.hook_type = "EPT";

					char buf[128];
					snprintf(buf, sizeof(buf), "PFN: 0x%llX vs 0x%llX, X: %d vs %d",
						pfn0, pfn1, (int)exec0, (int)exec1);
					hook.details = buf;

					std::lock_guard<std::mutex> lock(m_results_mutex);
					results.push_back(hook);
					m_found = (int)results.size();
				}
			}
		}

		std::lock_guard<std::mutex> lock(m_results_mutex);
		for (auto& r : results)
			m_results.push_back(std::move(r));

		m_progress = 1.0f;
		m_scanning = false;
	});
}

void HookCheckerPanel::render()
{
	auto& st = app::state();

	if (!st.process_attached)
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"Attach a process to scan for hooks.");
		return;
	}

	// toolbar
	if (m_scanning)
	{
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.15f, 0.1f, 0.8f));
		if (ImGui::Button("Stop", ImVec2(80, 28)))
			m_scanning = false;
		ImGui::PopStyleColor();

		ImGui::SameLine();
		ImGui::ProgressBar(m_progress.load(), ImVec2(200, 28));
		ImGui::SameLine();
		ImGui::Text("Found: %d", m_found.load());
	}
	else
	{
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.4f, 0.1f, 0.8f));
		if (ImGui::Button("Scan Inline", ImVec2(100, 28)))
			scan_inline_hooks();
		ImGui::PopStyleColor();

		ImGui::SameLine(0, 8);
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.3f, 0.4f, 0.8f));
		if (ImGui::Button("Scan IAT", ImVec2(100, 28)))
			scan_iat_hooks();
		ImGui::PopStyleColor();

		ImGui::SameLine(0, 8);
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.4f, 0.1f, 0.4f, 0.8f));
		if (ImGui::Button("Scan EPT", ImVec2(100, 28)))
			scan_ept_hooks();
		ImGui::PopStyleColor();

		ImGui::SameLine(0, 16);
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.5f, 0.1f, 0.1f, 0.8f));
		if (ImGui::Button("Clear", ImVec2(60, 28)))
		{
			std::lock_guard<std::mutex> lock(m_results_mutex);
			m_results.clear();
			m_found = 0;
		}
		ImGui::PopStyleColor();
	}

	ImGui::SameLine(0, 24);
	widgets::filter_bar("##hook_filter", m_filter, 250.0f);

	ImGui::Spacing();

	// results table
	{
		std::lock_guard<std::mutex> lock(m_results_mutex);

		ImGui::Text("Results: %d", (int)m_results.size());
		ImGui::Spacing();

		if (ImGui::BeginTable("##hooks", 5,
			ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_Sortable | ImGuiTableFlags_Resizable,
			ImVec2(-1, -1)))
		{
			ImGui::TableSetupScrollFreeze(0, 1);
			ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, 120.0f);
			ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f);
			ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 120.0f);
			ImGui::TableSetupColumn("Details", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableHeadersRow();

			for (int i = 0; i < (int)m_results.size(); i++)
			{
				auto& r = m_results[i];

				if (m_filter.is_active())
				{
					if (!m_filter.passes(r.module_name.c_str()) &&
						!m_filter.passes(r.function_name.c_str()) &&
						!m_filter.passes(r.hook_type.c_str()))
						continue;
				}

				ImGui::TableNextRow();
				ImGui::TableNextColumn();

				char sel_label[128];
				snprintf(sel_label, sizeof(sel_label), "%s##h%d", r.module_name.c_str(), i);
				ImGui::Selectable(sel_label, false, ImGuiSelectableFlags_SpanAllColumns);

				if (ImGui::BeginPopupContextItem())
				{
					if (ImGui::MenuItem("View in Disasm"))
						app::navigate_to_address(r.address, tab_id::disassembler);
					if (ImGui::MenuItem("View in Memory"))
						app::navigate_to_address(r.address, tab_id::memory_viewer);
					ImGui::Separator();
					if (ImGui::MenuItem("Copy Address"))
					{
						char buf[32];
						snprintf(buf, sizeof(buf), "0x%llX", r.address);
						ui::clipboard(buf, "Address copied");
					}
					ImGui::EndPopup();
				}

				ImGui::TableNextColumn();
				ImGui::Text("%s", r.function_name.c_str());

				ImGui::TableNextColumn();
				ImGui::PushFont(renderer::font_mono());
				ImGui::Text("0x%llX", r.address);
				ImGui::PopFont();

				ImGui::TableNextColumn();
				ImVec4 type_color(0.92f, 0.92f, 0.94f, 1.0f);
				if (r.hook_type.find("JMP") != std::string::npos) type_color = ImVec4(0.9f, 0.4f, 0.3f, 1.0f);
				else if (r.hook_type.find("PUSH") != std::string::npos) type_color = ImVec4(1.0f, 0.42f, 0.0f, 1.0f);
				else if (r.hook_type == "IAT") type_color = ImVec4(0.4f, 0.7f, 1.0f, 1.0f);
				else if (r.hook_type == "EPT") type_color = ImVec4(0.7f, 0.3f, 0.9f, 1.0f);
				ImGui::TextColored(type_color, "%s", r.hook_type.c_str());

				ImGui::TableNextColumn();
				ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "%s", r.details.c_str());
			}

			ImGui::EndTable();
		}
	}
}
