#include "app.h"
#include "memory/memory_reader.h"
#include "renderer/renderer.h"
#include "renderer/anim.h"
#include "hypercall/hypercall.h"
#include "widgets/module_resolver.h"
#include "widgets/filter_bar.h"
#include "widgets/ui_helpers.h"

#include "panels/memory_viewer.h"
#include "panels/scanner.h"
#include "panels/disassembler.h"
#include "panels/modules.h"
#include "panels/threads.h"
#include "panels/system_info.h"
#include "panels/struct_editor.h"
#include "panels/hook_checker.h"
#include "panels/breakpoints.h"
#include "panels/pointer_scanner.h"
#include "panels/code_filter.h"
#include "panels/watch_list.h"
#include "panels/function_filter.h"

#include <imgui_internal.h>
#include <print>
#include <algorithm>
#include <structures/trap_frame.h>

namespace app
{
	static app_state_t s_state;

	static constexpr int PANEL_COUNT = 13;
	static std::unique_ptr<IPanel> s_panels[PANEL_COUNT];

	static constexpr float STATUS_BAR_HEIGHT = 32.0f;
	static constexpr float CAPTION_BTN_W = 46.0f;
	static constexpr int   CAPTION_BTN_COUNT = 3;

	// attach modal state
	static std::vector<sys::process_info_t> s_modal_processes;
	static widgets::filter_state_t s_modal_filter;
	static float s_modal_last_refresh = -10.0f;

	// cross-panel state
	static std::string s_pending_aob_pattern;
	static uint64_t s_pending_code_filter_addr = 0;
	static uint64_t s_pending_add_watch_addr = 0;

	// shared log dispatcher
	static std::vector<page_monitor_callback_t> s_page_monitors;
	static float s_last_shared_flush = 0.0f;

	// maps tab_id to the dockable window name
	static const char* window_name(tab_id id)
	{
		switch (id)
		{
		case tab_id::memory_viewer:  return "Memory";
		case tab_id::scanner:        return "Scanner";
		case tab_id::disassembler:   return "Disasm";
		case tab_id::modules:        return "Modules";
		case tab_id::threads:        return "Threads";
		case tab_id::struct_editor:  return "Structs";
		case tab_id::hook_checker:   return "Hooks";
		case tab_id::breakpoints:    return "Breakpoints";
		case tab_id::pointer_scanner:return "Ptr Scan";
		case tab_id::code_filter:    return "CodeFilter";
		case tab_id::watch_list:     return "Watch List";
		case tab_id::system_info:    return "System";
		case tab_id::function_filter:return "FuncFilter";
		}
		return "Unknown";
	}

	void initialize()
	{
		sys::current_cr3 = hypercall::read_guest_cr3();

		if (sys::current_cr3 != 0)
		{
			s_state.hv_connected = true;
			s_state.hv_status = "Connected";
			std::println("[+] Hypervisor connected, CR3: 0x{:X}", sys::current_cr3);

			sys::set_up();
		}
		else
		{
			s_state.hv_status = "Not loaded";
			std::println("[-] Hypervisor not detected");
		}

		// create panels
		s_panels[0]  = std::make_unique<MemoryViewerPanel>();
		s_panels[1]  = std::make_unique<ScannerPanel>();
		s_panels[2]  = std::make_unique<DisassemblerPanel>();
		s_panels[3]  = std::make_unique<ModulesPanel>();
		s_panels[4]  = std::make_unique<ThreadsPanel>();
		s_panels[5]  = std::make_unique<StructEditorPanel>();
		s_panels[6]  = std::make_unique<HookCheckerPanel>();
		s_panels[7]  = std::make_unique<BreakpointsPanel>();
		s_panels[8]  = std::make_unique<PointerScannerPanel>();
		s_panels[9]  = std::make_unique<CodeFilterPanel>();
		s_panels[10] = std::make_unique<WatchListPanel>();
		s_panels[11] = std::make_unique<SystemInfoPanel>();
		s_panels[12] = std::make_unique<FunctionFilterPanel>();
	}

	void shutdown()
	{
		memory::invalidate_cache();

		for (auto& p : s_panels)
			p.reset();
	}

	static void render_title_bar()
	{
		ImGuiIO& io = ImGui::GetIO();
		float window_w = io.DisplaySize.x;
		float tb_h = renderer::TITLE_BAR_HEIGHT;

		// tell renderer where the caption buttons are (for WM_NCHITTEST)
		renderer::set_caption_button_width(CAPTION_BTN_W * CAPTION_BTN_COUNT);

		ImGui::SetCursorPos(ImVec2(0, 0));
		ImGui::BeginChild("##titlebar", ImVec2(window_w, tb_h), false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 origin = ImGui::GetWindowPos();
		dl->AddRectFilled(origin, ImVec2(origin.x + window_w, origin.y + tb_h), IM_COL32(10, 10, 15, 255));
		dl->AddLine(ImVec2(origin.x, origin.y + tb_h - 1), ImVec2(origin.x + window_w, origin.y + tb_h - 1), IM_COL32(42, 42, 58, 255));

		ImGui::PushFont(renderer::font_title());
		ImGui::SetCursorPos(ImVec2(16, 10));
		ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "HYPERREV");
		ImGui::SameLine();
		ImGui::TextColored(ImVec4(0.92f, 0.92f, 0.94f, 1.0f), "INSPECTOR");
		ImGui::PopFont();

		if (s_state.process_attached)
		{
			ImGui::SameLine(0, 40);
			ImGui::SetCursorPosY(14);
			ImGui::PushFont(renderer::font_regular());
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Process:");
			ImGui::SameLine();
			ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "%s",
				s_state.attached_process.name.c_str());
			ImGui::SameLine();
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "(PID:%llu)",
				s_state.attached_process.pid);
			ImGui::PopFont();
		}

		// ---- HV status (before buttons) ----
		ImGui::PushFont(renderer::font_regular());
		const char* status_text = s_state.hv_connected ? "HV: Online" : "HV: Offline";
		ImVec2 status_size = ImGui::CalcTextSize(status_text);
		float status_x = window_w - CAPTION_BTN_W * CAPTION_BTN_COUNT - status_size.x - 16;
		ImGui::SetCursorPos(ImVec2(status_x, 14));
		ImGui::TextColored(
			s_state.hv_connected ? ImVec4(0.3f, 0.9f, 0.4f, 1.0f) : ImVec4(0.9f, 0.3f, 0.3f, 1.0f),
			"%s", status_text);
		ImGui::PopFont();

		// ---- Caption buttons: minimize / maximize / close ----
		float btn_x = window_w - CAPTION_BTN_W * CAPTION_BTN_COUNT;
		HWND hwnd = renderer::get_hwnd();
		bool maximized = renderer::is_maximized();

		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 0.0f);
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
		ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));

		// minimize
		ImGui::SetCursorPos(ImVec2(btn_x, 0));
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1, 1, 1, 0.10f));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1, 1, 1, 0.20f));
		if (ImGui::InvisibleButton("##caption_min", ImVec2(CAPTION_BTN_W, tb_h)))
			ShowWindow(hwnd, SW_MINIMIZE);
		{
			// draw icon: horizontal line
			ImVec2 p = ImGui::GetItemRectMin();
			ImVec2 s = ImGui::GetItemRectSize();
			ImU32 col = ImGui::IsItemHovered() ? IM_COL32(255, 255, 255, 230) : IM_COL32(180, 180, 190, 200);
			float cx = p.x + s.x * 0.5f;
			float cy = p.y + s.y * 0.5f;
			dl->AddLine(ImVec2(cx - 6, cy), ImVec2(cx + 6, cy), col, 1.2f);
		}
		ImGui::PopStyleColor(3);

		// maximize / restore
		ImGui::SetCursorPos(ImVec2(btn_x + CAPTION_BTN_W, 0));
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1, 1, 1, 0.10f));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1, 1, 1, 0.20f));
		if (ImGui::InvisibleButton("##caption_max", ImVec2(CAPTION_BTN_W, tb_h)))
			ShowWindow(hwnd, maximized ? SW_RESTORE : SW_MAXIMIZE);
		{
			ImVec2 p = ImGui::GetItemRectMin();
			ImVec2 s = ImGui::GetItemRectSize();
			ImU32 col = ImGui::IsItemHovered() ? IM_COL32(255, 255, 255, 230) : IM_COL32(180, 180, 190, 200);
			float cx = p.x + s.x * 0.5f;
			float cy = p.y + s.y * 0.5f;
			if (maximized)
			{
				// restore icon: two overlapping rectangles
				dl->AddRect(ImVec2(cx - 4, cy - 2), ImVec2(cx + 4, cy + 6), col, 0, 0, 1.2f);
				dl->AddRect(ImVec2(cx - 2, cy - 5), ImVec2(cx + 6, cy + 3), col, 0, 0, 1.2f);
				dl->AddRectFilled(ImVec2(cx - 2, cy - 5), ImVec2(cx + 6, cy - 2), IM_COL32(10, 10, 15, 255));
				dl->AddRect(ImVec2(cx - 2, cy - 5), ImVec2(cx + 6, cy + 3), col, 0, 0, 1.2f);
			}
			else
			{
				// maximize icon: single rectangle
				dl->AddRect(ImVec2(cx - 5, cy - 4), ImVec2(cx + 5, cy + 5), col, 0, 0, 1.2f);
			}
		}
		ImGui::PopStyleColor(3);

		// close
		ImGui::SetCursorPos(ImVec2(btn_x + CAPTION_BTN_W * 2, 0));
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.86f, 0.15f, 0.15f, 0.8f));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.70f, 0.10f, 0.10f, 1.0f));
		if (ImGui::InvisibleButton("##caption_close", ImVec2(CAPTION_BTN_W, tb_h)))
			renderer::request_close();
		{
			ImVec2 p = ImGui::GetItemRectMin();
			ImVec2 s = ImGui::GetItemRectSize();
			ImU32 col = ImGui::IsItemHovered() ? IM_COL32(255, 255, 255, 240) : IM_COL32(180, 180, 190, 200);
			float cx = p.x + s.x * 0.5f;
			float cy = p.y + s.y * 0.5f;
			dl->AddLine(ImVec2(cx - 5, cy - 5), ImVec2(cx + 5, cy + 5), col, 1.2f);
			dl->AddLine(ImVec2(cx + 5, cy - 5), ImVec2(cx - 5, cy + 5), col, 1.2f);
		}
		// draw hover background for close button (red tint)
		if (ImGui::IsItemHovered())
		{
			ImVec2 rmin = ImGui::GetItemRectMin();
			ImVec2 rmax = ImGui::GetItemRectMax();
			dl->AddRectFilled(rmin, rmax, IM_COL32(220, 40, 40, 50));
		}
		ImGui::PopStyleColor(3);

		ImGui::PopStyleVar(3);

		ImGui::EndChild();
	}

	static void render_status_bar()
	{
		ImGuiIO& io = ImGui::GetIO();
		float window_w = io.DisplaySize.x;
		float window_h = io.DisplaySize.y;
		float bar_y = window_h - STATUS_BAR_HEIGHT;

		ImGui::SetCursorPos(ImVec2(0, bar_y));
		ImGui::BeginChild("##statusbar", ImVec2(window_w, STATUS_BAR_HEIGHT), false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 origin = ImGui::GetWindowPos();
		dl->AddRectFilled(origin, ImVec2(origin.x + window_w, origin.y + STATUS_BAR_HEIGHT), IM_COL32(13, 13, 20, 255));
		dl->AddLine(origin, ImVec2(origin.x + window_w, origin.y), IM_COL32(42, 42, 58, 255));

		ImGui::SetCursorPos(ImVec2(12, 8));
		ImGui::PushFont(renderer::font_mono());

		if (s_state.process_attached)
		{
			ImGui::TextColored(ImVec4(0.92f, 0.92f, 0.94f, 1.0f), "%s",
				s_state.attached_process.name.c_str());
			ImGui::SameLine(0, 6);
			ImGui::TextColored(ImVec4(0.38f, 0.38f, 0.43f, 1.0f), "PID %llu",
				s_state.attached_process.pid);

			ImGui::SameLine(0, 14);
			ImGui::TextColored(ImVec4(0.28f, 0.28f, 0.35f, 1.0f), "\xC2\xB7"); // middle dot
			ImGui::SameLine(0, 14);
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "CR3");
			ImGui::SameLine(0, 6);
			ImGui::TextColored(ImVec4(0.60f, 0.60f, 0.66f, 1.0f), "0x%llX",
				s_state.attached_process.cr3);

			ImGui::SameLine(0, 14);
			ImGui::TextColored(ImVec4(0.28f, 0.28f, 0.35f, 1.0f), "\xC2\xB7");
			ImGui::SameLine(0, 14);
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Modules");
			ImGui::SameLine(0, 6);
			ImGui::TextColored(ImVec4(0.60f, 0.60f, 0.66f, 1.0f), "%d",
				(int)widgets::g_modules.size());

			ImGui::SameLine(0, 14);
			ImGui::TextColored(ImVec4(0.28f, 0.28f, 0.35f, 1.0f), "\xC2\xB7");
			ImGui::SameLine(0, 14);
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Heap");
			ImGui::SameLine(0, 6);
			ImGui::TextColored(ImVec4(0.60f, 0.60f, 0.66f, 1.0f), "%llu pg",
				hypercall::get_heap_free_page_count());
		}
		else
		{
			ImGui::TextColored(ImVec4(0.38f, 0.38f, 0.43f, 1.0f), "No process attached");
		}

		const char* status = s_state.hv_connected ? "Ready" : "HV Offline";
		ImVec2 sz = ImGui::CalcTextSize(status);
		ImGui::SetCursorPos(ImVec2(window_w - sz.x - 16, 8));
		ImGui::TextColored(
			s_state.hv_connected ? ImVec4(0.3f, 0.9f, 0.4f, 1.0f) : ImVec4(0.9f, 0.3f, 0.3f, 1.0f),
			"%s", status);

		ImGui::PopFont();
		ImGui::EndChild();
	}

	static void render_sidebar_window()
	{
		if (s_state.hv_connected)
		{
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.35f, 0.1f, 0.9f));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.0f, 0.5f, 0.15f, 1.0f));
			if (ImGui::Button("Attach Process...", ImVec2(-1, 30)))
			{
				s_state.show_attach_modal = true;
				s_modal_processes = sys::process::enumerate_processes();
				s_modal_filter.clear();
				s_modal_last_refresh = anim::time();
			}
			ImGui::PopStyleColor(2);
			ImGui::Spacing();
			ImGui::Separator();
			ImGui::Spacing();
		}

		if (s_state.process_attached)
		{
			ImGui::PushFont(renderer::font_bold());
			ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "%s", s_state.attached_process.name.c_str());
			ImGui::PopFont();
			ImGui::Spacing();

			constexpr float LABEL_W = 80.0f;

			ImGui::PushFont(renderer::font_small());
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "PID");
			ImGui::PopFont();
			ImGui::SameLine(LABEL_W);
			ImGui::Text("%llu", s_state.attached_process.pid);

			ImGui::PushFont(renderer::font_small());
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "CR3");
			ImGui::PopFont();
			ui::tooltip("Page table root (DirectoryTableBase) for this process");
			ImGui::SameLine(LABEL_W);
			ImGui::PushFont(renderer::font_mono());
			ImGui::Text("0x%llX", s_state.attached_process.cr3);
			ImGui::PopFont();

			ImGui::PushFont(renderer::font_small());
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Base");
			ImGui::PopFont();
			ui::tooltip("Main module base address");
			ImGui::SameLine(LABEL_W);
			ImGui::PushFont(renderer::font_mono());
			ImGui::Text("0x%llX", s_state.attached_process.base_address);
			ImGui::PopFont();

			ImGui::PushFont(renderer::font_small());
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "EPROCESS");
			ImGui::PopFont();
			ui::tooltip("Kernel EPROCESS structure address");
			ImGui::SameLine(LABEL_W);
			ImGui::PushFont(renderer::font_mono());
			ImGui::Text("0x%llX", s_state.attached_process.eprocess);
			ImGui::PopFont();

			ImGui::Spacing();
			ImGui::Spacing();

			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.5f, 0.12f, 0.08f, 0.7f));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.7f, 0.18f, 0.12f, 0.9f));
			if (ImGui::Button("Detach", ImVec2(-1, 26)))
				detach_process();
			ImGui::PopStyleColor(2);

			if (s_state.hv_connected)
			{
				ImGui::Spacing();
				ImGui::Separator();
				ImGui::Spacing();

				ImGui::PushFont(renderer::font_small());
				ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "HV Heap");
				ImGui::PopFont();
				ui::tooltip("Free hypervisor heap pages available for EPT operations");
				ImGui::SameLine(LABEL_W);
				ImGui::Text("%llu pages", hypercall::get_heap_free_page_count());
			}

			ImGui::Spacing();
			ImGui::Separator();
			ImGui::Spacing();

			// keyboard shortcuts hint
			ImGui::PushFont(renderer::font_small());
			ImGui::TextColored(ImVec4(0.35f, 0.35f, 0.42f, 1.0f), "Ctrl+1..9  Switch panels");
			ImGui::PopFont();
		}
		else
		{
			ImGui::Spacing();
			ImGui::TextColored(ImVec4(0.42f, 0.42f, 0.48f, 1.0f), "No process attached");
			ImGui::Spacing();
			ImGui::PushFont(renderer::font_small());
			ImGui::TextWrapped("Click \"Attach Process\" above to select a target process.");
			ImGui::PopFont();
		}
	}

	static void render_attach_modal()
	{
		if (!s_state.show_attach_modal)
			return;

		ImGui::OpenPopup("Attach Process");

		ImVec2 center = ImGui::GetMainViewport()->GetCenter();
		ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
		ImGui::SetNextWindowSize(ImVec2(700, 500), ImGuiCond_Appearing);

		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 12));
		if (ImGui::BeginPopupModal("Attach Process", &s_state.show_attach_modal,
			ImGuiWindowFlags_NoScrollbar))
		{
			ImGui::PopStyleVar();

			if (anim::time() - s_modal_last_refresh > 3.0f)
			{
				s_modal_processes = sys::process::enumerate_processes();
				s_modal_last_refresh = anim::time();
			}

			if (ImGui::Button("Refresh", ImVec2(80, 28)))
			{
				s_modal_processes = sys::process::enumerate_processes();
				s_modal_last_refresh = anim::time();
			}
			ImGui::SameLine(0, 12);
			widgets::filter_bar("##attach_filter", s_modal_filter, 300.0f);
			ImGui::SameLine(0, 12);
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
				"%d processes", (int)s_modal_processes.size());
			ImGui::SameLine(0, 20);
			ImGui::PushFont(renderer::font_small());
			ImGui::TextColored(ImVec4(0.35f, 0.35f, 0.42f, 1.0f), "Double-click to attach");
			ImGui::PopFont();

			ImGui::Spacing();

			if (ImGui::BeginTable("##attach_table", 4,
				ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
				ImGuiTableFlags_ScrollY | ImGuiTableFlags_Sortable,
				ImVec2(-1, -1)))
			{
				ImGui::TableSetupScrollFreeze(0, 1);
				ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed, 70.0f);
				ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
				ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 150.0f);
				ImGui::TableSetupColumn("CR3", ImGuiTableColumnFlags_WidthFixed, 150.0f);
				ImGui::TableHeadersRow();

				if (ImGuiTableSortSpecs* sorts = ImGui::TableGetSortSpecs())
				{
					if (sorts->SpecsDirty && sorts->SpecsCount > 0)
					{
						auto spec = sorts->Specs[0];
						bool asc = (spec.SortDirection == ImGuiSortDirection_Ascending);

						std::sort(s_modal_processes.begin(), s_modal_processes.end(),
							[&](const sys::process_info_t& a, const sys::process_info_t& b) {
								switch (spec.ColumnIndex)
								{
								case 0: return asc ? (a.pid < b.pid) : (a.pid > b.pid);
								case 1: return asc ? (a.name < b.name) : (a.name > b.name);
								case 2: return asc ? (a.base_address < b.base_address) : (a.base_address > b.base_address);
								case 3: return asc ? (a.cr3 < b.cr3) : (a.cr3 > b.cr3);
								default: return false;
								}
							});

						sorts->SpecsDirty = false;
					}
				}

				for (const auto& proc : s_modal_processes)
				{
					if (!s_modal_filter.passes(proc.name.c_str()))
						continue;

					ImGui::TableNextRow();
					ImGui::TableNextColumn();

					bool is_attached = s_state.process_attached &&
						s_state.attached_process.pid == proc.pid;

					if (is_attached)
						ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(255, 107, 0, 25));

					char sel_label[64];
					snprintf(sel_label, sizeof(sel_label), "%llu##p%llu", proc.pid, proc.pid);

					if (ImGui::Selectable(sel_label, is_attached,
						ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
					{
						if (ImGui::IsMouseDoubleClicked(0))
						{
							attach_process(proc);
							s_state.show_attach_modal = false;
							ImGui::CloseCurrentPopup();
							ImGui::EndTable();
							ImGui::EndPopup();
							return;
						}
					}

					ImGui::TableNextColumn();
					if (is_attached)
						ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "%s", proc.name.c_str());
					else
						ImGui::Text("%s", proc.name.c_str());

					ImGui::TableNextColumn();
					ImGui::PushFont(renderer::font_mono());
					ImGui::Text("0x%llX", proc.base_address);
					ImGui::PopFont();

					ImGui::TableNextColumn();
					ImGui::PushFont(renderer::font_mono());
					ImGui::Text("0x%llX", proc.cr3);
					ImGui::PopFont();
				}

				ImGui::EndTable();
			}

			ImGui::EndPopup();
		}
		else
		{
			ImGui::PopStyleVar();
		}
	}

	static void setup_default_dock_layout(ImGuiID dockspace_id, float width, float height)
	{
		ImGui::DockBuilderRemoveNode(dockspace_id);
		ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
		ImGui::DockBuilderSetNodeSize(dockspace_id, ImVec2(width, height));

		ImGuiID dock_sidebar, dock_rest;
		ImGui::DockBuilderSplitNode(dockspace_id, ImGuiDir_Left, 0.14f, &dock_sidebar, &dock_rest);

		ImGuiID dock_main, dock_bottom;
		ImGui::DockBuilderSplitNode(dock_rest, ImGuiDir_Down, 0.45f, &dock_bottom, &dock_main);

		ImGui::DockBuilderDockWindow("Process Info", dock_sidebar);

		ImGui::DockBuilderDockWindow("Disasm", dock_main);
		ImGui::DockBuilderDockWindow("Modules", dock_main);
		ImGui::DockBuilderDockWindow("Threads", dock_main);
		ImGui::DockBuilderDockWindow("Structs", dock_main);
		ImGui::DockBuilderDockWindow("Hooks", dock_main);
		ImGui::DockBuilderDockWindow("Breakpoints", dock_main);
		ImGui::DockBuilderDockWindow("Ptr Scan", dock_main);
		ImGui::DockBuilderDockWindow("CodeFilter", dock_main);
		ImGui::DockBuilderDockWindow("Watch List", dock_main);
		ImGui::DockBuilderDockWindow("FuncFilter", dock_main);
		ImGui::DockBuilderDockWindow("System", dock_main);
		ImGui::DockBuilderDockWindow("Memory", dock_main); // last = active tab

		ImGui::DockBuilderDockWindow("Scanner", dock_bottom);

		ImGui::DockBuilderFinish(dockspace_id);
	}

	void render()
	{
		ImGuiIO& io = ImGui::GetIO();

		// shared log flush
		if (!s_page_monitors.empty() && anim::time() - s_last_shared_flush > 0.5f)
		{
			flush_shared_logs();
			s_last_shared_flush = anim::time();
		}

		if (s_state.goto_address_pending)
			ImGui::SetWindowFocus(window_name(s_state.goto_tab));

		const ImGuiViewport* viewport = ImGui::GetMainViewport();
		ImGui::SetNextWindowPos(viewport->WorkPos);
		ImGui::SetNextWindowSize(viewport->WorkSize);
		ImGui::SetNextWindowViewport(viewport->ID);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
		ImGui::Begin("##main", nullptr,
			ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
			ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
			ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
			ImGuiWindowFlags_NoDocking);
		ImGui::PopStyleVar();

		render_title_bar();

		float dock_y = renderer::TITLE_BAR_HEIGHT;
		float dock_w = viewport->WorkSize.x;
		float dock_h = viewport->WorkSize.y - dock_y - STATUS_BAR_HEIGHT;

		ImGui::SetCursorPos(ImVec2(0, dock_y));
		ImGuiID dockspace_id = ImGui::GetID("InspectorDock");
		ImGui::DockSpace(dockspace_id, ImVec2(dock_w, dock_h));

		if (ImGui::DockBuilderGetNode(dockspace_id) == nullptr ||
			ImGui::DockBuilderGetNode(dockspace_id)->IsEmpty())
		{
			setup_default_dock_layout(dockspace_id, dock_w, dock_h);
		}

		render_status_bar();

		ImGui::End(); // ##main

		// ---- Render sidebar as a dockable window ----
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12, 12));
		ImGui::Begin("Process Info");
		ImGui::PopStyleVar();
		render_sidebar_window();
		ImGui::End();

		// ---- Render all panels as dockable windows ----
		for (auto& p : s_panels)
		{
			if (!p) continue;
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12, 8));
			ImGui::Begin(p->get_name());
			ImGui::PopStyleVar();
			p->render();
			ImGui::End();
		}

		render_attach_modal();

		// keyboard shortcuts
		if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_1)) switch_tab(tab_id::memory_viewer);
		if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_2)) switch_tab(tab_id::scanner);
		if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_3)) switch_tab(tab_id::disassembler);
		if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_4)) switch_tab(tab_id::modules);
		if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_5)) switch_tab(tab_id::threads);
		if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_6)) switch_tab(tab_id::struct_editor);
		if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_7)) switch_tab(tab_id::hook_checker);
		if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_8)) switch_tab(tab_id::breakpoints);
		if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_9)) switch_tab(tab_id::pointer_scanner);
		if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_0)) switch_tab(tab_id::system_info);

		// toast notifications
		ui::render_toast();

		// accent border around main viewport (viewport-aware coordinates)
		{
			ImGuiViewport* vp = ImGui::GetMainViewport();
			ImDrawList* fg = ImGui::GetForegroundDrawList(vp);
			ImVec2 p0 = vp->Pos;
			ImVec2 p1(vp->Pos.x + vp->Size.x, vp->Pos.y + vp->Size.y);
			fg->AddRect(p0, p1, IM_COL32(255, 107, 0, 180), 0.0f, 0, 1.0f);
		}
	}

	void switch_tab(tab_id tab)
	{
		s_state.current_tab = tab;
		ImGui::SetWindowFocus(window_name(tab));
	}

	void navigate_to_address(uint64_t address, tab_id target_tab)
	{
		s_state.goto_address = address;
		s_state.goto_address_pending = true;
		s_state.goto_tab = target_tab;
	}

	void attach_process(const sys::process_info_t& process)
	{
		s_state.process_attached = true;
		s_state.attached_process = process;
		memory::set_context(process.cr3, process.eprocess);
		std::println("[+] Attached to {} (PID:{}, CR3:0x{:X})", process.name, process.pid, process.cr3);
	}

	void detach_process()
	{
		std::println("[-] Detached from {}", s_state.attached_process.name);
		s_state.process_attached = false;
		s_state.attached_process = {};
		memory::set_context(0, 0);
		memory::invalidate_cache();
	}

	app_state_t& state() { return s_state; }

	IPanel* get_panel(tab_id id)
	{
		for (auto& p : s_panels)
		{
			if (p && p->get_id() == id)
				return p.get();
		}
		return nullptr;
	}

	// ---- Cross-panel helpers ----

	void add_breakpoint_from_disasm(uint64_t address)
	{
		// find the breakpoints panel and call add_breakpoint
		for (auto& p : s_panels)
		{
			if (p && p->get_id() == tab_id::breakpoints)
			{
				auto* bp_panel = static_cast<BreakpointsPanel*>(p.get());
				bp_panel->add_breakpoint_public(address, nullptr);
				break;
			}
		}
	}

	void set_pending_aob_pattern(const std::string& pattern) { s_pending_aob_pattern = pattern; }
	const std::string& pending_aob_pattern() { return s_pending_aob_pattern; }
	void clear_pending_aob_pattern() { s_pending_aob_pattern.clear(); }

	void request_code_filter(uint64_t address)
	{
		s_pending_code_filter_addr = address;
		switch_tab(tab_id::code_filter);
	}
	uint64_t consume_code_filter_request()
	{
		uint64_t addr = s_pending_code_filter_addr;
		s_pending_code_filter_addr = 0;
		return addr;
	}

	void request_add_watch(uint64_t address)
	{
		s_pending_add_watch_addr = address;
		switch_tab(tab_id::watch_list);
	}
	uint64_t consume_add_watch_request()
	{
		uint64_t addr = s_pending_add_watch_addr;
		s_pending_add_watch_addr = 0;
		return addr;
	}

	// ---- Shared log dispatcher ----

	static uint32_t s_next_monitor_id = 1;

	uint32_t register_page_monitor(uint64_t gpa, std::function<void(const trap_frame_log_t&)> callback)
	{
		uint32_t id = s_next_monitor_id++;
		s_page_monitors.push_back({ id, gpa, std::move(callback) });
		return id;
	}

	void unregister_page_monitor(uint32_t id)
	{
		s_page_monitors.erase(
			std::remove_if(s_page_monitors.begin(), s_page_monitors.end(),
				[id](const page_monitor_callback_t& m) { return m.id == id; }),
			s_page_monitors.end());
	}

	void flush_shared_logs()
	{
		if (s_page_monitors.empty()) return;

		std::vector<trap_frame_log_t> logs(256);
		uint64_t count = hypercall::flush_logs(logs);
		if (count == 0) return;

		logs.resize(count);

		for (auto& log : logs)
		{
			uint64_t gpa = hypercall::translate_guest_virtual_address(log.rip, log.cr3);
			if (gpa == 0) continue;

			uint64_t page_gpa = gpa & ~0xFFFull;

			for (auto& monitor : s_page_monitors)
			{
				if (monitor.gpa == page_gpa)
					monitor.callback(log);
			}
		}
	}
}
