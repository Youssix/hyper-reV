#include "threads.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../widgets/module_resolver.h"
#include "hypercall/hypercall.h"
#include "system/system.h"
#include <cstdio>
#include <cstring>

void ThreadsPanel::load_threads()
{
	m_threads.clear();
	m_stack_frames.clear();
	m_selected_thread = -1;

	auto& st = app::state();
	if (!st.process_attached) return;

	uint64_t eprocess = st.attached_process.eprocess;
	uint64_t cr3 = sys::current_cr3;

	if (sys::offsets::eprocess_thread_list_head == 0) return;

	// read ThreadListHead.Flink
	uint64_t list_head_addr = eprocess + sys::offsets::eprocess_thread_list_head;
	uint64_t first_entry = 0;
	hypercall::read_guest_virtual_memory(&first_entry, list_head_addr, cr3, 8);

	if (first_entry == 0 || first_entry == list_head_addr) return;

	uint64_t current_entry = first_entry;
	int count = 0;

	while (current_entry != list_head_addr && current_entry != 0 && count < 256)
	{
		count++;
		uint64_t ethread = current_entry - sys::offsets::ethread_thread_list_entry;

		thread_entry_t entry = {};
		entry.ethread = ethread;

		// read KTHREAD.State
		hypercall::read_guest_virtual_memory(&entry.state, ethread + sys::offsets::kthread_state, cr3, 1);

		// read KTHREAD.TrapFrame pointer
		hypercall::read_guest_virtual_memory(&entry.trap_frame_ptr, ethread + sys::offsets::kthread_trap_frame, cr3, 8);

		m_threads.push_back(entry);

		// follow Flink
		hypercall::read_guest_virtual_memory(&current_entry, current_entry, cr3, 8);
	}

	m_threads_loaded = true;
}

void ThreadsPanel::load_registers(int thread_index)
{
	if (thread_index < 0 || thread_index >= (int)m_threads.size()) return;

	auto& t = m_threads[thread_index];
	t.regs = {};
	t.regs.valid = false;

	if (t.trap_frame_ptr == 0) return;

	uint64_t cr3 = sys::current_cr3;
	uint64_t tf = t.trap_frame_ptr;

	// read all registers from KTRAP_FRAME
	hypercall::read_guest_virtual_memory(&t.regs.rax, tf + ktrap_offsets::rax, cr3, 8);
	hypercall::read_guest_virtual_memory(&t.regs.rcx, tf + ktrap_offsets::rcx, cr3, 8);
	hypercall::read_guest_virtual_memory(&t.regs.rdx, tf + ktrap_offsets::rdx, cr3, 8);
	hypercall::read_guest_virtual_memory(&t.regs.r8, tf + ktrap_offsets::r8, cr3, 8);
	hypercall::read_guest_virtual_memory(&t.regs.r9, tf + ktrap_offsets::r9, cr3, 8);
	hypercall::read_guest_virtual_memory(&t.regs.r10, tf + ktrap_offsets::r10, cr3, 8);
	hypercall::read_guest_virtual_memory(&t.regs.r11, tf + ktrap_offsets::r11, cr3, 8);
	hypercall::read_guest_virtual_memory(&t.regs.rbx, tf + ktrap_offsets::rbx, cr3, 8);
	hypercall::read_guest_virtual_memory(&t.regs.rdi, tf + ktrap_offsets::rdi, cr3, 8);
	hypercall::read_guest_virtual_memory(&t.regs.rsi, tf + ktrap_offsets::rsi, cr3, 8);
	hypercall::read_guest_virtual_memory(&t.regs.rbp, tf + ktrap_offsets::rbp, cr3, 8);
	hypercall::read_guest_virtual_memory(&t.regs.rip, tf + ktrap_offsets::rip, cr3, 8);
	hypercall::read_guest_virtual_memory(&t.regs.rsp, tf + ktrap_offsets::rsp, cr3, 8);
	hypercall::read_guest_virtual_memory(&t.regs.eflags, tf + ktrap_offsets::eflags, cr3, 4);

	t.regs.valid = (t.regs.rip != 0);
}

void ThreadsPanel::walk_stack(int thread_index)
{
	m_stack_frames.clear();

	if (thread_index < 0 || thread_index >= (int)m_threads.size()) return;

	auto& t = m_threads[thread_index];
	if (!t.regs.valid || t.regs.rsp == 0) return;

	uint64_t proc_cr3 = app::state().attached_process.cr3;
	uint64_t rsp = t.regs.rsp;

	// read up to 2KB of stack (256 QWORDs)
	constexpr int MAX_QWORDS = 256;
	uint64_t stack_data[MAX_QWORDS] = {};
	uint64_t bytes_read = hypercall::read_guest_virtual_memory(
		stack_data, rsp, proc_cr3, MAX_QWORDS * 8);

	int qwords_read = (int)(bytes_read / 8);

	for (int i = 0; i < qwords_read; i++)
	{
		uint64_t value = stack_data[i];

		// filter: check if this looks like a return address inside a known module
		bool is_module_addr = false;
		for (auto& mod : widgets::g_modules)
		{
			if (value >= mod.base && value < mod.base + mod.size)
			{
				is_module_addr = true;
				break;
			}
		}

		if (!is_module_addr || value == 0)
			continue;

		stack_frame_t frame = {};
		frame.address = value;
		frame.stack_ptr = rsp + i * 8;
		frame.module_str = widgets::format_address_short(value);

		// read up to 4 QWORDs after this entry as "args"
		for (int a = 0; a < 4; a++)
		{
			int arg_idx = i + 1 + a;
			if (arg_idx < qwords_read)
				frame.args[a] = stack_data[arg_idx];
		}

		m_stack_frames.push_back(frame);

		if (m_stack_frames.size() >= 64) break;
	}
}

void ThreadsPanel::render()
{
	auto& st = app::state();

	if (!st.process_attached)
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"Attach a process to view threads.");
		return;
	}

	if (!m_threads_loaded)
		load_threads();

	// toolbar
	if (ImGui::Button("Refresh", ImVec2(80, 28)))
	{
		load_threads();
		if (m_selected_thread >= 0 && m_selected_thread < (int)m_threads.size())
		{
			load_registers(m_selected_thread);
			walk_stack(m_selected_thread);
		}
	}
	ImGui::SameLine(0, 16);
	ImGui::Text("Threads: %d", (int)m_threads.size());

	ImGui::Spacing();

	// 3-column layout: thread list | registers+flags | stack
	ImVec2 avail = ImGui::GetContentRegionAvail();
	float col1_w = 240.0f;
	float col2_w = 280.0f;
	float col3_w = avail.x - col1_w - col2_w - 16.0f;
	if (col3_w < 200.0f) col3_w = 200.0f;

	// ---- Thread List ----
	ImGui::BeginChild("##thread_list", ImVec2(col1_w, -1), true);
	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "Threads");
	ImGui::PopFont();
	ImGui::Separator();

	if (ImGui::BeginTable("##threadtable", 3,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
		ImVec2(-1, -1)))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 30.0f);
		ImGui::TableSetupColumn("ETHREAD", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 50.0f);
		ImGui::TableHeadersRow();

		for (int i = 0; i < (int)m_threads.size(); i++)
		{
			auto& t = m_threads[i];
			ImGui::TableNextRow();
			ImGui::TableNextColumn();

			bool selected = (i == m_selected_thread);
			char label[16];
			snprintf(label, sizeof(label), "%d", i);

			if (ImGui::Selectable(label, selected, ImGuiSelectableFlags_SpanAllColumns))
			{
				m_selected_thread = i;
				load_registers(i);
				walk_stack(i);
			}

			// context menu
			if (ImGui::BeginPopupContextItem())
			{
				if (t.regs.valid && t.regs.rip != 0 && ImGui::MenuItem("Disassemble at RIP"))
					app::navigate_to_address(t.regs.rip, tab_id::disassembler);
				if (t.regs.valid && t.regs.rsp != 0 && ImGui::MenuItem("View Stack in Memory"))
					app::navigate_to_address(t.regs.rsp, tab_id::memory_viewer);
				ImGui::EndPopup();
			}

			ImGui::TableNextColumn();
			ImGui::PushFont(renderer::font_mono());
			ImGui::Text("%llX", t.ethread);
			ImGui::PopFont();

			ImGui::TableNextColumn();
			const char* state_names[] = {
				"Init", "Ready", "Run", "Stby", "Term", "Wait", "Trans", "DfRdy" };
			const char* sn = (t.state < 8) ? state_names[t.state] : "?";
			ImVec4 sc = (t.state == 5) ? ImVec4(0.3f, 0.9f, 0.4f, 1.0f) :
				(t.state == 2) ? ImVec4(1.0f, 0.42f, 0.0f, 1.0f) :
				ImVec4(0.48f, 0.48f, 0.53f, 1.0f);
			ImGui::TextColored(sc, "%s", sn);
		}

		ImGui::EndTable();
	}
	ImGui::EndChild();

	ImGui::SameLine(0, 4);

	// ---- Registers + Flags ----
	ImGui::BeginChild("##regs_flags", ImVec2(col2_w, -1), true);
	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "Registers");
	ImGui::PopFont();
	ImGui::Separator();

	if (m_selected_thread >= 0 && m_selected_thread < (int)m_threads.size())
	{
		auto& t = m_threads[m_selected_thread];
		if (t.regs.valid)
		{
			ImGui::PushFont(renderer::font_mono());

			auto reg_row = [](const char* name, uint64_t value) {
				ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "%-4s", name);
				ImGui::SameLine(50);
				ImGui::Text("%016llX", value);
			};

			reg_row("RAX", t.regs.rax);
			reg_row("RCX", t.regs.rcx);
			reg_row("RDX", t.regs.rdx);
			reg_row("RBX", t.regs.rbx);
			reg_row("RSP", t.regs.rsp);
			reg_row("RBP", t.regs.rbp);
			reg_row("RSI", t.regs.rsi);
			reg_row("RDI", t.regs.rdi);
			reg_row("R8 ", t.regs.r8);
			reg_row("R9 ", t.regs.r9);
			reg_row("R10", t.regs.r10);
			reg_row("R11", t.regs.r11);

			ImGui::Spacing();
			ImGui::Separator();
			ImGui::Spacing();

			// RIP with module resolution
			ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "RIP ");
			ImGui::SameLine(50);
			ImGui::Text("%016llX", t.regs.rip);
			std::string rip_mod = widgets::format_address_short(t.regs.rip);
			ImGui::SameLine();
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "(%s)", rip_mod.c_str());

			ImGui::Spacing();
			ImGui::Separator();
			ImGui::Spacing();

			// Flags
			ImGui::PopFont();
			ImGui::PushFont(renderer::font_bold());
			ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "Flags");
			ImGui::PopFont();
			ImGui::PushFont(renderer::font_mono());

			uint32_t ef = t.regs.eflags;
			ImGui::Text("EFLAGS: %08X", ef);
			ImGui::Spacing();

			auto flag_chip = [](const char* name, bool set) {
				ImVec4 color = set ?
					ImVec4(1.0f, 0.42f, 0.0f, 1.0f) :
					ImVec4(0.3f, 0.3f, 0.35f, 1.0f);
				ImGui::TextColored(color, "%s=%d", name, set ? 1 : 0);
				ImGui::SameLine(0, 12);
			};

			flag_chip("CF", ef & (1 << 0));
			flag_chip("PF", ef & (1 << 2));
			flag_chip("AF", ef & (1 << 4));
			ImGui::NewLine();
			flag_chip("ZF", ef & (1 << 6));
			flag_chip("SF", ef & (1 << 7));
			flag_chip("TF", ef & (1 << 8));
			ImGui::NewLine();
			flag_chip("IF", ef & (1 << 9));
			flag_chip("DF", ef & (1 << 10));
			flag_chip("OF", ef & (1 << 11));
			ImGui::NewLine();

			ImGui::PopFont();
		}
		else
		{
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
				"No trap frame (thread may be running or has no saved context)");
		}
	}
	else
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Select a thread");
	}

	ImGui::EndChild();

	ImGui::SameLine(0, 4);

	// ---- Stack ----
	ImGui::BeginChild("##stack_view", ImVec2(col3_w, -1), true);
	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "Call Stack");
	ImGui::PopFont();
	ImGui::Separator();

	if (m_selected_thread >= 0 && !m_stack_frames.empty())
	{
		if (ImGui::BeginTable("##stacktable", 3,
			ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
			ImVec2(-1, -1)))
		{
			ImGui::TableSetupScrollFreeze(0, 1);
			ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableSetupColumn("Args", ImGuiTableColumnFlags_WidthFixed, 220.0f);
			ImGui::TableSetupColumn("SP", ImGuiTableColumnFlags_WidthFixed, 120.0f);
			ImGui::TableHeadersRow();

			ImGui::PushFont(renderer::font_mono());
			for (int i = 0; i < (int)m_stack_frames.size(); i++)
			{
				auto& f = m_stack_frames[i];
				ImGui::TableNextRow();
				ImGui::TableNextColumn();

				// module+offset as selectable
				char sel_id[32];
				snprintf(sel_id, sizeof(sel_id), "##sf%d", i);
				if (ImGui::Selectable(f.module_str.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
					app::navigate_to_address(f.address, tab_id::disassembler);

				// right-click context menu
				if (ImGui::BeginPopupContextItem())
				{
					if (ImGui::MenuItem("Disassemble"))
						app::navigate_to_address(f.address, tab_id::disassembler);
					if (ImGui::MenuItem("View in Memory"))
						app::navigate_to_address(f.address, tab_id::memory_viewer);
					if (ImGui::MenuItem("View Stack Location"))
						app::navigate_to_address(f.stack_ptr, tab_id::memory_viewer);

					ImGui::Separator();
					if (ImGui::MenuItem("Copy Address"))
					{
						char buf[32];
						snprintf(buf, sizeof(buf), "0x%llX", f.address);
						ImGui::SetClipboardText(buf);
					}
					if (ImGui::MenuItem("Copy Module+Offset"))
						ImGui::SetClipboardText(f.module_str.c_str());
					ImGui::EndPopup();
				}

				ImGui::TableNextColumn();
				// show first 3 "args" as hex values (like CE)
				char args_buf[128];
				snprintf(args_buf, sizeof(args_buf), "%08llX,%08llX,%08llX",
					f.args[0] & 0xFFFFFFFF, f.args[1] & 0xFFFFFFFF, f.args[2] & 0xFFFFFFFF);
				ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "%s", args_buf);

				ImGui::TableNextColumn();
				ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "%llX", f.stack_ptr);
			}
			ImGui::PopFont();

			ImGui::EndTable();
		}
	}
	else if (m_selected_thread >= 0)
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"No stack frames found (thread may be running)");
	}
	else
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Select a thread");
	}

	ImGui::EndChild();
}
