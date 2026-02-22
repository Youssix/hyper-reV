#include "system_info.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "hypercall/hypercall.h"
#include "system/system.h"
#include <cstdio>

void SystemInfoPanel::render()
{
	auto& st = app::state();

	// Hypervisor status section
	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "Hypervisor Status");
	ImGui::PopFont();
	ImGui::Separator();
	ImGui::Spacing();

	auto info_row = [](const char* label, const char* fmt, ...) {
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "%-24s", label);
		ImGui::SameLine(220);
		ImGui::PushFont(renderer::font_mono());
		va_list args;
		va_start(args, fmt);
		ImGui::TextV(fmt, args);
		va_end(args);
		ImGui::PopFont();
	};

	info_row("Connection", "%s", st.hv_connected ? "Online" : "Offline");

	if (st.hv_connected)
	{
		info_row("Guest CR3", "0x%llX", sys::current_cr3);
		info_row("Heap Free Pages", "%llu", hypercall::get_heap_free_page_count());
		info_row("CR3 Exit Count", "%llu", hypercall::read_cr3_exit_count());
		info_row("CR3 Swap Count", "%llu", hypercall::read_cr3_swap_count());
		info_row("SLAT Violations", "%llu", hypercall::read_slat_violation_count());
		info_row("MMAF Hits", "%llu", hypercall::read_mmaf_hit_count());
		info_row("Hijack CPUID Count", "%llu", hypercall::read_hijack_cpuid_count());
		info_row("Hijack Armed", "%llu", hypercall::read_hijack_armed_state());
	}

	ImGui::Spacing();
	ImGui::Spacing();

	// EPROCESS offsets
	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "Resolved Offsets");
	ImGui::PopFont();
	ImGui::Separator();
	ImGui::Spacing();

	info_row("ActiveProcessLinks", "0x%llX", sys::offsets::eprocess_active_process_links);
	info_row("UniqueProcessId", "0x%llX", sys::offsets::eprocess_unique_process_id);
	info_row("DirectoryTableBase", "0x%llX", sys::offsets::eprocess_directory_table_base);
	info_row("ImageFileName", "0x%llX", sys::offsets::eprocess_image_file_name);
	info_row("SectionBaseAddress", "0x%llX", sys::offsets::eprocess_section_base_address);
	info_row("Peb", "0x%llX", sys::offsets::eprocess_peb);
	info_row("ThreadListHead", "0x%llX", sys::offsets::eprocess_thread_list_head);
	info_row("KThread.TrapFrame", "0x%llX", sys::offsets::kthread_trap_frame);
	info_row("KThread.State", "0x%llX", sys::offsets::kthread_state);
	info_row("MmAccessFault RVA", "0x%llX", sys::offsets::mm_access_fault_rva);
	info_row("KiSysServiceExit RVA", "0x%llX", sys::offsets::ki_system_service_exit_rva);
	info_row("NtClose RVA", "0x%llX", sys::offsets::nt_close_rva);

	ImGui::Spacing();
	ImGui::Spacing();

	// Kernel modules
	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "Kernel Modules (%d)",
		(int)sys::kernel::modules_list.size());
	ImGui::PopFont();
	ImGui::Separator();
	ImGui::Spacing();

	if (ImGui::BeginTable("##kernmods", 3,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
		ImVec2(-1, 300)))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 160.0f);
		ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		ImGui::TableHeadersRow();

		for (auto& [name, mod] : sys::kernel::modules_list)
		{
			ImGui::TableNextRow();
			ImGui::TableNextColumn();
			ImGui::Text("%s", name.c_str());

			ImGui::TableNextColumn();
			ImGui::PushFont(renderer::font_mono());
			ImGui::Text("0x%llX", mod.base_address);
			ImGui::PopFont();

			ImGui::TableNextColumn();
			ImGui::Text("0x%X", mod.size);
		}

		ImGui::EndTable();
	}
}
