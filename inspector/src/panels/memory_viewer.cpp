#include "memory_viewer.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../widgets/address_input.h"
#include "../widgets/module_resolver.h"
#include "../memory/memory_reader.h"
#include <cstdio>

void MemoryViewerPanel::render()
{
	auto& st = app::state();

	if (!st.process_attached)
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"Attach a process from the Processes tab to view memory.");
		return;
	}

	// init to process base on first attach
	if (!m_initialized)
	{
		m_hex_state.base_address = st.attached_process.base_address;
		m_goto_address = m_hex_state.base_address;

		// set up goto callback for hex view context menu "Follow QWORD"
		m_hex_state.on_goto = [this](uint64_t addr) {
			m_hex_state.base_address = addr & ~0xFull;
			m_goto_address = addr;
			m_hex_state.selected_offset = 0;
		};

		// wire "Find What Accesses" to code filter
		m_hex_state.on_find_accesses = [](uint64_t addr) {
			app::request_code_filter(addr);
		};

		// wire "Add to Watch List"
		m_hex_state.on_add_watch = [](uint64_t addr) {
			app::request_add_watch(addr);
		};

		m_initialized = true;
	}

	// handle goto from other panels
	if (st.goto_address_pending && st.goto_tab == tab_id::memory_viewer)
	{
		st.goto_address_pending = false; // consume
		m_hex_state.base_address = st.goto_address & ~0xFull;
		m_goto_address = st.goto_address;
		m_hex_state.selected_offset = 0;
	}

	// toolbar
	ImGui::Text("Address:");
	ImGui::SameLine();

	if (widgets::address_input("##goto", m_goto_address, 200.0f))
	{
		m_hex_state.base_address = m_goto_address & ~0xFull;
		m_hex_state.selected_offset = 0;
	}

	ImGui::SameLine(0, 16);
	if (ImGui::Button("Go to Base", ImVec2(0, 28)))
	{
		m_hex_state.base_address = st.attached_process.base_address;
		m_goto_address = m_hex_state.base_address;
		m_hex_state.selected_offset = 0;
	}

	ImGui::SameLine(0, 8);
	if (ImGui::Button("Refresh", ImVec2(0, 28)))
		memory::invalidate_cache();

	ImGui::SameLine(0, 16);
	ImGui::Text("View:");
	ImGui::SameLine();
	ImGui::PushItemWidth(100);
	const char* display_names[] = {
		"Hex8", "Hex16", "Hex32", "Hex64",
		"Int32", "UInt32", "Float", "Double"
	};
	int disp_idx = (int)m_hex_state.display_mode;
	if (ImGui::Combo("##dispmode", &disp_idx, display_names, IM_ARRAYSIZE(display_names)))
		m_hex_state.display_mode = (widgets::display_mode_t)disp_idx;
	ImGui::PopItemWidth();

	ImGui::SameLine(0, 16);
	ImGui::PushFont(renderer::font_mono());
	std::string view_mod = widgets::format_address_short(m_hex_state.base_address);
	ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
		"Viewing: %s", view_mod.c_str());
	ImGui::PopFont();

	ImGui::Spacing();

	// hex view uses full available width
	ImVec2 avail = ImGui::GetContentRegionAvail();
	widgets::hex_view("##hexview", m_hex_state, avail.x, avail.y - 8);

	// Ctrl+G to focus address input
	if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_G))
		ImGui::SetKeyboardFocusHere(-1);
}
