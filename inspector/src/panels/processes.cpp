#include "processes.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../renderer/anim.h"
#include <algorithm>
#include <cstdio>

void ProcessesPanel::refresh_list()
{
	if (!app::state().hv_connected)
		return;

	m_processes = sys::process::enumerate_processes();
	m_last_refresh = anim::time();
}

void ProcessesPanel::render()
{
	// auto-refresh every 3 seconds
	if (anim::time() - m_last_refresh > 3.0f)
		refresh_list();

	if (!app::state().hv_connected)
	{
		ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f),
			"Hypervisor not connected. Load hyperv-attachment first.");
		return;
	}

	// toolbar

	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.1f, 0.1f, 0.18f, 1.0f));
	if (ImGui::Button("Refresh", ImVec2(100, 28)))
		refresh_list();
	ImGui::PopStyleColor();

	ImGui::SameLine(0, 16);
	widgets::filter_bar("##proc_filter", m_filter, 300.0f);

	ImGui::SameLine();
	ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "(%d processes)", (int)m_processes.size());

	ImGui::Spacing();

	// process table
	ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
		ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_Sortable | ImGuiTableFlags_SortMulti;

	if (ImGui::BeginTable("##proctable", 5, flags, ImVec2(-1, -1)))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed, 70.0f);
		ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 180.0f);
		ImGui::TableSetupColumn("CR3", ImGuiTableColumnFlags_WidthFixed, 160.0f);
		ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 160.0f);
		ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_NoSort | ImGuiTableColumnFlags_WidthFixed, 100.0f);
		ImGui::TableHeadersRow();

		// sort
		if (ImGuiTableSortSpecs* sorts = ImGui::TableGetSortSpecs())
		{
			if (sorts->SpecsDirty && sorts->SpecsCount > 0)
			{
				auto spec = sorts->Specs[0];
				bool asc = (spec.SortDirection == ImGuiSortDirection_Ascending);

				std::sort(m_processes.begin(), m_processes.end(),
					[&](const sys::process_info_t& a, const sys::process_info_t& b) {
						switch (spec.ColumnIndex)
						{
						case 0: return asc ? (a.pid < b.pid) : (a.pid > b.pid);
						case 1: return asc ? (a.name < b.name) : (a.name > b.name);
						case 2: return asc ? (a.cr3 < b.cr3) : (a.cr3 > b.cr3);
						case 3: return asc ? (a.base_address < b.base_address) : (a.base_address > b.base_address);
						default: return false;
						}
					});

				sorts->SpecsDirty = false;
			}
		}

		for (const auto& proc : m_processes)
		{
			if (!m_filter.passes(proc.name.c_str()))
				continue;

			ImGui::TableNextRow();
			ImGui::TableNextColumn();

			// highlight attached process
			bool is_attached = app::state().process_attached &&
				app::state().attached_process.pid == proc.pid;

			if (is_attached)
				ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(255, 107, 0, 25));

			ImGui::Text("%llu", proc.pid);

			ImGui::TableNextColumn();
			if (is_attached)
				ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "%s", proc.name.c_str());
			else
				ImGui::Text("%s", proc.name.c_str());

			ImGui::TableNextColumn();
			ImGui::PushFont(renderer::font_mono());
			ImGui::Text("0x%llX", proc.cr3);
			ImGui::PopFont();

			ImGui::TableNextColumn();
			ImGui::PushFont(renderer::font_mono());
			ImGui::Text("0x%llX", proc.base_address);
			ImGui::PopFont();

			ImGui::TableNextColumn();
			char btn_id[32];
			snprintf(btn_id, sizeof(btn_id), "Attach##%llu", proc.pid);

			if (is_attached)
			{
				ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.4f, 1.0f), "Attached");
			}
			else
			{
				ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
				ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.42f, 0.0f, 0.15f));
				if (ImGui::SmallButton(btn_id))
				{
					app::attach_process(proc);
					app::switch_tab(tab_id::memory_viewer);
				}
				ImGui::PopStyleColor(2);
			}
		}

		ImGui::EndTable();
	}
}
