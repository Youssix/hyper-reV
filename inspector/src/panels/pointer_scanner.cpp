#include "pointer_scanner.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../memory/memory_reader.h"
#include "../widgets/module_resolver.h"
#include "hypercall/hypercall.h"
#include "../widgets/ui_helpers.h"
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <algorithm>

PointerScannerPanel::~PointerScannerPanel()
{
	m_scanning = false;
	if (m_scan_thread.joinable())
		m_scan_thread.join();
}

void PointerScannerPanel::start_scan()
{
	if (m_scanning) return;

	m_target_address = strtoull(m_target_buf, nullptr, 16);
	if (m_target_address == 0) return;

	m_scanning = true;
	m_progress = 0.0f;
	m_found = 0;

	if (m_scan_thread.joinable())
		m_scan_thread.join();

	{
		std::lock_guard<std::mutex> lock(m_chains_mutex);
		m_chains.clear();
	}

	m_scan_thread = std::thread(&PointerScannerPanel::scan_thread_func, this);
}

void PointerScannerPanel::scan_thread_func()
{
	uint64_t cr3 = memory::get_cr3();
	if (cr3 == 0) { m_scanning = false; return; }

	// Step 1: Build a map of all pointer values in writable memory
	// We scan the process address space for 8-byte aligned values
	// that could be pointers

	struct found_ptr_t
	{
		uint64_t address;    // where the pointer lives
		uint64_t value;      // the pointer value
	};

	// For each level, we need to find addresses whose value + some offset == target
	// Level 0: find addr where [addr + off] == target
	// Level 1: find addr where [addr + off] == level0_addr
	// etc.

	std::vector<pointer_chain_t> results;

	// Working set: addresses we're looking for pointers TO
	struct search_target_t
	{
		uint64_t target_addr;           // the address we want to reach
		std::vector<int64_t> offsets;   // offsets accumulated so far (reverse order)
	};

	std::vector<search_target_t> current_targets;
	search_target_t initial;
	initial.target_addr = m_target_address;
	current_targets.push_back(initial);

	for (int depth = 0; depth < m_max_depth && m_scanning && !current_targets.empty(); depth++)
	{
		m_progress = (float)depth / (float)m_max_depth;

		std::vector<search_target_t> next_targets;

		// For each target, scan all memory for pointers to it (with offset tolerance)
		// We scan page by page for efficiency
		uint64_t scan_start = 0x10000;
		uint64_t scan_end = 0x7FFFFFFFFFFF;

		// Build a set of target ranges for fast lookup
		// target - max_offset to target + max_offset
		struct target_range_t
		{
			uint64_t low;
			uint64_t high;
			int target_idx;
		};

		std::vector<target_range_t> ranges;
		for (int ti = 0; ti < (int)current_targets.size() && ti < 1000; ti++)
		{
			target_range_t r;
			r.low = current_targets[ti].target_addr > (uint64_t)m_max_offset ?
				current_targets[ti].target_addr - m_max_offset : 0;
			r.high = current_targets[ti].target_addr;
			r.target_idx = ti;
			ranges.push_back(r);
		}

		std::sort(ranges.begin(), ranges.end(), [](const target_range_t& a, const target_range_t& b) {
			return a.low < b.low;
		});

		// scan memory page by page
		uint8_t page_buf[0x1000];
		uint64_t total_range = scan_end - scan_start;

		for (uint64_t addr = scan_start; addr < scan_end && m_scanning; addr += 0x1000)
		{
			float sub_progress = (float)(addr - scan_start) / (float)total_range;
			m_progress = ((float)depth + sub_progress) / (float)m_max_depth;

			uint64_t phys = hypercall::translate_guest_virtual_address(addr, cr3);
			if (phys == 0) continue;

			uint64_t bytes = hypercall::read_guest_virtual_memory(page_buf, addr, cr3, 0x1000);
			if (bytes != 0x1000) continue;

			// scan for pointer-sized values
			for (int offset = 0; offset <= 0x1000 - 8; offset += 8)
			{
				uint64_t value = 0;
				memcpy(&value, page_buf + offset, 8);

				if (value < 0x10000 || value > 0x7FFFFFFFFFFF)
					continue;

				uint64_t ptr_addr = addr + offset;

				// check against all target ranges
				for (auto& range : ranges)
				{
					if (value >= range.low && value <= range.high)
					{
						int64_t off = (int64_t)(current_targets[range.target_idx].target_addr - value);

						// check if ptr_addr is in a module (static base = end of chain)
						std::string mod_name;
						uint64_t mod_off;
						bool is_static = widgets::resolve_module(ptr_addr, mod_name, mod_off);

						// build chain
						pointer_chain_t chain;
						chain.offsets = current_targets[range.target_idx].offsets;
						chain.offsets.insert(chain.offsets.begin(), off);

						if (is_static)
						{
							chain.base_address = ptr_addr;
							chain.base_module = mod_name;

							std::lock_guard<std::mutex> lock(m_chains_mutex);
							results.push_back(chain);
							m_found = (int)results.size();

							if (results.size() >= 50000)
							{
								m_scanning = false;
								break;
							}
						}
						else if (depth + 1 < m_max_depth)
						{
							// add as next level target
							search_target_t next;
							next.target_addr = ptr_addr;
							next.offsets = chain.offsets;

							if (next_targets.size() < 5000)
								next_targets.push_back(next);
						}
					}
				}

				if (!m_scanning) break;
			}

			if (!m_scanning) break;
		}

		current_targets = std::move(next_targets);
	}

	std::lock_guard<std::mutex> lock(m_chains_mutex);
	m_chains = std::move(results);

	m_progress = 1.0f;
	m_scanning = false;
}

void PointerScannerPanel::render()
{
	auto& st = app::state();

	if (!st.process_attached)
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"Attach a process to use the pointer scanner.");
		return;
	}

	// toolbar
	ImGui::Text("Target:");
	ImGui::SameLine();
	ImGui::PushItemWidth(180);
	ImGui::InputText("##ptr_target", m_target_buf, sizeof(m_target_buf), ImGuiInputTextFlags_CharsHexadecimal);
	ImGui::PopItemWidth();

	ImGui::SameLine(0, 16);
	ImGui::Text("Depth:");
	ImGui::SameLine();
	ImGui::PushItemWidth(60);
	ImGui::InputInt("##ptr_depth", &m_max_depth, 0, 0);
	if (m_max_depth < 1) m_max_depth = 1;
	if (m_max_depth > 10) m_max_depth = 10;
	ImGui::PopItemWidth();

	ImGui::SameLine(0, 16);
	ImGui::Text("Max Offset:");
	ImGui::SameLine();
	ImGui::PushItemWidth(80);
	ImGui::InputInt("##ptr_maxoff", &m_max_offset, 0, 0);
	if (m_max_offset < 0) m_max_offset = 0;
	if (m_max_offset > 0x10000) m_max_offset = 0x10000;
	ImGui::PopItemWidth();

	ImGui::SameLine(0, 16);

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
		if (ImGui::Button("Scan", ImVec2(80, 28)))
			start_scan();
		ImGui::PopStyleColor();

		ImGui::SameLine(0, 8);
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.5f, 0.1f, 0.1f, 0.8f));
		if (ImGui::Button("Clear", ImVec2(60, 28)))
		{
			std::lock_guard<std::mutex> lock(m_chains_mutex);
			m_chains.clear();
			m_found = 0;
		}
		ImGui::PopStyleColor();
	}

	ImGui::Spacing();
	ImGui::Separator();
	ImGui::Spacing();

	// results table
	{
		std::lock_guard<std::mutex> lock(m_chains_mutex);

		ImGui::Text("Results: %d", (int)m_chains.size());
		if (m_chains.size() > 5000)
			ImGui::SameLine(), ImGui::TextColored(ImVec4(0.9f, 0.6f, 0.1f, 1.0f), "(showing first 5000)");

		ImGui::Spacing();

		if (ImGui::BeginTable("##ptrtable", 4,
			ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_Resizable,
			ImVec2(-1, -1)))
		{
			ImGui::TableSetupScrollFreeze(0, 1);
			ImGui::TableSetupColumn("Base Module", ImGuiTableColumnFlags_WidthFixed, 120.0f);
			ImGui::TableSetupColumn("Base+Offset", ImGuiTableColumnFlags_WidthFixed, 200.0f);
			ImGui::TableSetupColumn("Chain", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthFixed, 160.0f);
			ImGui::TableHeadersRow();

			int display_count = (int)m_chains.size();
			if (display_count > 5000) display_count = 5000;

			ImGui::PushFont(renderer::font_mono());

			for (int i = 0; i < display_count; i++)
			{
				auto& chain = m_chains[i];
				ImGui::TableNextRow();

				// base module
				ImGui::TableNextColumn();
				char sel_label[128];
				snprintf(sel_label, sizeof(sel_label), "%s##pt%d", chain.base_module.c_str(), i);
				ImGui::Selectable(sel_label, false, ImGuiSelectableFlags_SpanAllColumns);

				if (ImGui::BeginPopupContextItem())
				{
					if (ImGui::MenuItem("View Base in Memory"))
						app::navigate_to_address(chain.base_address, tab_id::memory_viewer);
					if (ImGui::MenuItem("View Base in Disasm"))
						app::navigate_to_address(chain.base_address, tab_id::disassembler);
					ImGui::Separator();
					if (ImGui::MenuItem("Copy Chain"))
					{
						// format: "module+0x1234 -> +0x10 -> +0x48 = target"
						std::string str = widgets::format_address_short(chain.base_address);
						for (auto off : chain.offsets)
						{
							char buf[32];
							if (off >= 0)
								snprintf(buf, sizeof(buf), " -> +0x%llX", (uint64_t)off);
							else
								snprintf(buf, sizeof(buf), " -> -0x%llX", (uint64_t)(-off));
							str += buf;
						}
						ui::clipboard(str.c_str(), "Copied");
					}
					ImGui::EndPopup();
				}

				// base+offset
				ImGui::TableNextColumn();
				ImGui::Text("%s", widgets::format_address_short(chain.base_address).c_str());

				// chain offsets
				ImGui::TableNextColumn();
				std::string chain_str;
				for (int j = 0; j < (int)chain.offsets.size(); j++)
				{
					if (j > 0) chain_str += " -> ";
					char buf[32];
					if (chain.offsets[j] >= 0)
						snprintf(buf, sizeof(buf), "+0x%llX", (uint64_t)chain.offsets[j]);
					else
						snprintf(buf, sizeof(buf), "-0x%llX", (uint64_t)(-chain.offsets[j]));
					chain_str += buf;
				}
				ImGui::TextColored(ImVec4(0.4f, 0.85f, 0.9f, 1.0f), "%s", chain_str.c_str());

				// target
				ImGui::TableNextColumn();
				ImGui::Text("0x%llX", m_target_address);
			}

			ImGui::PopFont();
			ImGui::EndTable();
		}
	}
}
