#include "hex_view.h"
#include "../memory/memory_reader.h"
#include "../renderer/renderer.h"
#include "module_resolver.h"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <algorithm>

namespace widgets
{
	static int cell_size(display_mode_t mode)
	{
		switch (mode)
		{
		case display_mode_t::hex_byte:    return 1;
		case display_mode_t::hex_int16:   return 2;
		case display_mode_t::hex_int32:   return 4;
		case display_mode_t::hex_int64:   return 8;
		case display_mode_t::dec_int32:   return 4;
		case display_mode_t::dec_uint32:  return 4;
		case display_mode_t::float32:     return 4;
		case display_mode_t::float64:     return 8;
		}
		return 1;
	}

	static int cell_chars(display_mode_t mode)
	{
		switch (mode)
		{
		case display_mode_t::hex_byte:    return 2;
		case display_mode_t::hex_int16:   return 4;
		case display_mode_t::hex_int32:   return 8;
		case display_mode_t::hex_int64:   return 16;
		case display_mode_t::dec_int32:   return 11;
		case display_mode_t::dec_uint32:  return 10;
		case display_mode_t::float32:     return 12;
		case display_mode_t::float64:     return 16;
		}
		return 2;
	}

	static int format_cell(char* buf, int buf_size, const uint8_t* data, display_mode_t mode)
	{
		switch (mode)
		{
		case display_mode_t::hex_byte:
			return snprintf(buf, buf_size, "%02X", data[0]);
		case display_mode_t::hex_int16:
		{
			uint16_t v; memcpy(&v, data, 2);
			return snprintf(buf, buf_size, "%04X", v);
		}
		case display_mode_t::hex_int32:
		{
			uint32_t v; memcpy(&v, data, 4);
			return snprintf(buf, buf_size, "%08X", v);
		}
		case display_mode_t::hex_int64:
		{
			uint64_t v; memcpy(&v, data, 8);
			return snprintf(buf, buf_size, "%016llX", v);
		}
		case display_mode_t::dec_int32:
		{
			int32_t v; memcpy(&v, data, 4);
			return snprintf(buf, buf_size, "%d", v);
		}
		case display_mode_t::dec_uint32:
		{
			uint32_t v; memcpy(&v, data, 4);
			return snprintf(buf, buf_size, "%u", v);
		}
		case display_mode_t::float32:
		{
			float v; memcpy(&v, data, 4);
			if (std::isnan(v) || std::isinf(v))
				return snprintf(buf, buf_size, "---");
			return snprintf(buf, buf_size, "%.4g", v);
		}
		case display_mode_t::float64:
		{
			double v; memcpy(&v, data, 8);
			if (std::isnan(v) || std::isinf(v))
				return snprintf(buf, buf_size, "---");
			return snprintf(buf, buf_size, "%.6g", v);
		}
		}
		return 0;
	}

	bool hex_view(const char* id, hex_view_state_t& state, float width, float height)
	{
		bool modified = false;
		ImFont* mono = renderer::font_mono();

		if (!mono)
			return false;

		ImGui::PushFont(mono);

		int csz = cell_size(state.display_mode);
		int cchars = cell_chars(state.display_mode);
		int cells_per_row = state.bytes_per_row / csz;

		ImVec2 char_size = ImGui::CalcTextSize("0");
		float line_height = char_size.y + 2.0f;
		float header_height = line_height + 4.0f;
		float addr_width = char_size.x * 18;
		float cell_width = char_size.x * (cchars + 1);
		float data_region_width = cells_per_row * cell_width;

		// ASCII always visible
		float ascii_start = addr_width + data_region_width + char_size.x * 2;
		float content_width = ascii_start + state.bytes_per_row * char_size.x + 16;

		ImGui::BeginChild(id, ImVec2(width, height), false,
			ImGuiWindowFlags_HorizontalScrollbar);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 origin = ImGui::GetCursorScreenPos();

		float data_height = height - header_height;
		int visible_lines = (int)(data_height / line_height) + 1;
		int scroll_line = (int)(ImGui::GetScrollY() / line_height);

		int total_pages_estimate = 256;
		ImGui::Dummy(ImVec2(content_width,
			total_pages_estimate * (0x1000 / state.bytes_per_row) * line_height + header_height));
		ImGui::SetCursorScreenPos(origin);

		float now = (float)ImGui::GetTime();

		// compute selection range min/max
		int sel_min = -1, sel_max = -1;
		if (state.selection_start >= 0 && state.selection_end >= 0)
		{
			sel_min = (std::min)(state.selection_start, state.selection_end);
			sel_max = (std::max)(state.selection_start, state.selection_end);
		}

		// --- Draw data rows (below header) ---
		float data_y_start = origin.y + header_height;

		for (int line = 0; line < visible_lines; line++)
		{
			int abs_line = scroll_line + line;
			uint64_t line_addr = state.base_address + (uint64_t)abs_line * state.bytes_per_row;

			float y = data_y_start + line * line_height;

			if (y > origin.y + height)
				break;

			uint8_t line_data[16] = {};
			bool line_valid = true;

			uint64_t page_addr = line_addr & ~0xFFFull;
			memory::cached_page_t* page = memory::cache_read_page(page_addr);

			if (page && page->valid)
			{
				uint32_t offset_in_page = (uint32_t)(line_addr - page_addr);
				int bytes_to_copy = state.bytes_per_row;
				if (offset_in_page + bytes_to_copy > 0x1000)
					bytes_to_copy = 0x1000 - offset_in_page;
				memcpy(line_data, page->data + offset_in_page, bytes_to_copy);

				if (bytes_to_copy < state.bytes_per_row)
				{
					memory::cached_page_t* page2 = memory::cache_read_page(page_addr + 0x1000);
					if (page2 && page2->valid)
						memcpy(line_data + bytes_to_copy, page2->data, state.bytes_per_row - bytes_to_copy);
					else
						line_valid = false;
				}
			}
			else
			{
				line_valid = false;
			}

			// address column
			char addr_buf[24];
			snprintf(addr_buf, sizeof(addr_buf), "%016llX", line_addr);
			dl->AddText(mono, mono->FontSize, ImVec2(origin.x, y),
				IM_COL32(0x48, 0x48, 0x53, 0xFF), addr_buf);

			// data cells
			for (int cell = 0; cell < cells_per_row; cell++)
			{
				int byte_offset = cell * csz;
				float x = origin.x + addr_width + cell * cell_width;
				uint64_t cell_addr = line_addr + byte_offset;

				if (!line_valid)
				{
					dl->AddText(mono, mono->FontSize, ImVec2(x, y),
						IM_COL32(0x45, 0x45, 0x50, 0xFF), "??");
					continue;
				}

				ImU32 color = IM_COL32(0xEA, 0xEA, 0xF0, 0xFF);

				bool all_zero = true;
				bool any_changed = false;
				float max_change_alpha = 0.0f;
				for (int b = 0; b < csz; b++)
				{
					if (line_data[byte_offset + b] != 0x00)
						all_zero = false;
					float ct = memory::byte_change_time(cell_addr + b);
					if (ct >= 0.0f)
					{
						float elapsed = now - ct;
						if (elapsed < 2.0f)
						{
							any_changed = true;
							float a = 1.0f - (elapsed / 2.0f);
							if (a > max_change_alpha) max_change_alpha = a;
						}
					}
				}

				if (all_zero)
					color = IM_COL32(0x45, 0x45, 0x50, 0xFF);

				int global_offset = abs_line * state.bytes_per_row + byte_offset;

				// red flash rectangle for changed bytes
				if (any_changed)
				{
					int alpha = (int)(max_change_alpha * 100);
					dl->AddRectFilled(
						ImVec2(x - 1, y - 1),
						ImVec2(x + char_size.x * cchars + 1, y + line_height - 1),
						IM_COL32(255, 30, 30, alpha));
					color = IM_COL32(0xFF, 0x30, 0x30, 0xFF);
				}

				// selected highlight (single click)
				if (state.selected_offset >= global_offset &&
					state.selected_offset < global_offset + csz)
				{
					dl->AddRectFilled(
						ImVec2(x - 1, y - 1),
						ImVec2(x + char_size.x * cchars + 1, y + line_height - 1),
						IM_COL32(0xFF, 0x6B, 0x00, 0x40));
				}

				// range selection highlight
				if (sel_min >= 0 && global_offset >= sel_min && global_offset <= sel_max)
				{
					dl->AddRectFilled(
						ImVec2(x - 1, y - 1),
						ImVec2(x + char_size.x * cchars + 1, y + line_height - 1),
						IM_COL32(0x40, 0x80, 0xFF, 0x30));
				}

				char cell_buf[32];
				format_cell(cell_buf, sizeof(cell_buf), line_data + byte_offset, state.display_mode);
				dl->AddText(mono, mono->FontSize, ImVec2(x, y), color, cell_buf);

				// click to select / shift+click for range
				ImGui::SetCursorScreenPos(ImVec2(x, y));
				std::string btn_id = "##cell" + std::to_string(abs_line * 16 + cell);
				ImGui::InvisibleButton(btn_id.c_str(),
					ImVec2(cell_width, line_height));
				if (ImGui::IsItemClicked())
				{
					if (ImGui::GetIO().KeyShift && state.selected_offset >= 0)
					{
						if (state.selection_start < 0)
							state.selection_start = state.selected_offset;
						state.selection_end = global_offset;
					}
					else
					{
						state.selected_offset = global_offset;
						state.selection_start = global_offset;
						state.selection_end = global_offset;
					}
				}

				// right-click context menu
				if (ImGui::BeginPopupContextItem(("##ctx" + std::to_string(abs_line * 16 + cell)).c_str()))
				{
					state.selected_offset = global_offset;
					std::string ctx_mod = format_address_short(cell_addr);

					if (ImGui::MenuItem("Copy Address"))
					{
						char abuf[32];
						snprintf(abuf, sizeof(abuf), "0x%llX", cell_addr);
						ImGui::SetClipboardText(abuf);
					}
					if (ImGui::MenuItem("Copy Module+Offset"))
						ImGui::SetClipboardText(ctx_mod.c_str());

					if (ImGui::MenuItem("Copy Value"))
					{
						char vbuf[32];
						format_cell(vbuf, sizeof(vbuf), line_data + byte_offset, state.display_mode);
						ImGui::SetClipboardText(vbuf);
					}

					if (sel_min >= 0 && sel_max > sel_min)
					{
						ImGui::Separator();
						int range_bytes = sel_max - sel_min + csz;

						if (ImGui::MenuItem("Copy Selection as AOB"))
						{
							std::string aob;
							for (int b = 0; b < range_bytes; b++)
							{
								uint64_t a = state.base_address + sel_min + b;
								uint8_t byte_val = 0;
								memory::read(&byte_val, a, 1);
								if (!aob.empty()) aob += " ";
								char hb[4];
								snprintf(hb, sizeof(hb), "%02X", byte_val);
								aob += hb;
							}
							ImGui::SetClipboardText(aob.c_str());
						}

						if (ImGui::MenuItem("Copy Selection as C Array"))
						{
							std::string arr = "{ ";
							for (int b = 0; b < range_bytes; b++)
							{
								uint64_t a = state.base_address + sel_min + b;
								uint8_t byte_val = 0;
								memory::read(&byte_val, a, 1);
								if (b > 0) arr += ", ";
								char hb[8];
								snprintf(hb, sizeof(hb), "0x%02X", byte_val);
								arr += hb;
							}
							arr += " }";
							ImGui::SetClipboardText(arr.c_str());
						}
					}

					ImGui::Separator();

					if (state.on_goto)
					{
						if (line_valid && ImGui::MenuItem("Follow QWORD as Address"))
						{
							uint64_t ptr_val = 0;
							if (byte_offset + 8 <= state.bytes_per_row)
								memcpy(&ptr_val, line_data + byte_offset, 8);
							else
								memory::read(&ptr_val, cell_addr, 8);

							if (ptr_val != 0)
								state.on_goto(ptr_val);
						}
					}

					if (state.on_find_accesses && ImGui::MenuItem("Find What Accesses"))
						state.on_find_accesses(cell_addr);

					if (state.on_add_watch && ImGui::MenuItem("Add to Watch List"))
						state.on_add_watch(cell_addr);

					ImGui::EndPopup();
				}

				// double-click to edit
				if (state.display_mode == display_mode_t::hex_byte &&
					ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && line_valid)
				{
					state.editing = true;
					state.selected_offset = global_offset;
					state.edit_nibble = 0;
					snprintf(state.edit_buf, sizeof(state.edit_buf), "%02X", line_data[byte_offset]);
				}
			}

			// ASCII column (always visible regardless of display mode)
			{
				float sep_x = origin.x + addr_width + data_region_width + char_size.x;
				dl->AddLine(ImVec2(sep_x, y), ImVec2(sep_x, y + line_height),
					IM_COL32(0x2A, 0x2A, 0x3A, 0xFF));

				for (int col = 0; col < state.bytes_per_row; col++)
				{
					float x = origin.x + ascii_start + col * char_size.x;
					uint64_t byte_addr = line_addr + col;

					if (!line_valid)
					{
						dl->AddText(mono, mono->FontSize, ImVec2(x, y),
							IM_COL32(0x45, 0x45, 0x50, 0xFF), ".");
						continue;
					}

					char ch = (line_data[col] >= 0x20 && line_data[col] < 0x7F)
						? (char)line_data[col] : '.';
					char ascii_buf[2] = { ch, '\0' };

					ImU32 ascii_color = (ch == '.') ?
						IM_COL32(0x45, 0x45, 0x50, 0xFF) :
						IM_COL32(0x7A, 0x7A, 0x88, 0xFF);

					// red flash on ASCII too
					float ct = memory::byte_change_time(byte_addr);
					if (ct >= 0.0f)
					{
						float elapsed = now - ct;
						if (elapsed < 2.0f)
						{
							float alpha = 1.0f - (elapsed / 2.0f);
							dl->AddRectFilled(
								ImVec2(x - 1, y - 1),
								ImVec2(x + char_size.x + 1, y + line_height - 1),
								IM_COL32(255, 30, 30, (int)(alpha * 100)));
							ascii_color = IM_COL32(0xFF, 0x30, 0x30, 0xFF);
						}
					}

					dl->AddText(mono, mono->FontSize, ImVec2(x, y), ascii_color, ascii_buf);
				}
			}
		}

		// --- Frozen header overlay (drawn last, on top of everything) ---
		{
			// solid background to cover any data that scrolled behind header
			dl->AddRectFilled(
				ImVec2(origin.x, origin.y),
				ImVec2(origin.x + content_width, origin.y + header_height),
				IM_COL32(0x0A, 0x0A, 0x0F, 0xFF));

			ImU32 hdr_color = IM_COL32(0x7A, 0x7A, 0x88, 0xFF);
			float hdr_y = origin.y + 2.0f;

			// "Address" label
			dl->AddText(mono, mono->FontSize, ImVec2(origin.x, hdr_y),
				hdr_color, "Address");

			// byte offset headers aligned with data cells
			for (int cell = 0; cell < cells_per_row; cell++)
			{
				float x = origin.x + addr_width + cell * cell_width;
				char hdr_buf[32];
				int byte_off = cell * csz;
				snprintf(hdr_buf, sizeof(hdr_buf), "%02X", byte_off);
				dl->AddText(mono, mono->FontSize, ImVec2(x, hdr_y), hdr_color, hdr_buf);
			}

			// ASCII header separator
			float sep_x = origin.x + addr_width + data_region_width + char_size.x;
			dl->AddLine(ImVec2(sep_x, origin.y), ImVec2(sep_x, origin.y + header_height),
				IM_COL32(0x2A, 0x2A, 0x3A, 0xFF));

			// ASCII header "0123456789ABCDEF"
			dl->AddText(mono, mono->FontSize,
				ImVec2(origin.x + ascii_start, hdr_y),
				hdr_color, "0123456789ABCDEF");

			// orange separator line under header
			dl->AddLine(
				ImVec2(origin.x, origin.y + header_height - 1),
				ImVec2(origin.x + content_width, origin.y + header_height - 1),
				IM_COL32(0xFF, 0x6B, 0x00, 0x50));
		}

		// keyboard editing
		if (state.editing && state.selected_offset >= 0 &&
			state.display_mode == display_mode_t::hex_byte)
		{
			ImGuiIO& io = ImGui::GetIO();
			for (int i = 0; i < io.InputQueueCharacters.Size; i++)
			{
				char c = (char)io.InputQueueCharacters[i];
				if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
				{
					state.edit_buf[state.edit_nibble] = (char)toupper(c);
					state.edit_nibble++;

					if (state.edit_nibble >= 2)
					{
						uint8_t value = (uint8_t)strtoul(state.edit_buf, nullptr, 16);
						uint64_t write_addr = state.base_address +
							(uint64_t)state.selected_offset;
						memory::write(&value, write_addr, 1);
						modified = true;

						state.editing = false;
						state.selected_offset++;
					}
				}
			}

			if (ImGui::IsKeyPressed(ImGuiKey_Escape))
				state.editing = false;
		}

		// Ctrl+C: copy selected bytes
		if (!state.editing && ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C))
		{
			if (sel_min >= 0 && sel_max >= sel_min)
			{
				int range = sel_max - sel_min + csz;
				std::string hex;
				for (int b = 0; b < range; b++)
				{
					uint64_t a = state.base_address + sel_min + b;
					uint8_t byte_val = 0;
					memory::read(&byte_val, a, 1);
					if (!hex.empty()) hex += " ";
					char hb[4];
					snprintf(hb, sizeof(hb), "%02X", byte_val);
					hex += hb;
				}
				ImGui::SetClipboardText(hex.c_str());
			}
			else if (state.selected_offset >= 0)
			{
				uint64_t a = state.base_address + state.selected_offset;
				uint8_t data[8] = {};
				memory::read(data, a, csz);
				char buf[32];
				format_cell(buf, sizeof(buf), data, state.display_mode);
				ImGui::SetClipboardText(buf);
			}
		}

		// keyboard navigation
		if (!state.editing)
		{
			if (ImGui::IsKeyPressed(ImGuiKey_DownArrow) && state.selected_offset >= 0)
				state.selected_offset += state.bytes_per_row;
			if (ImGui::IsKeyPressed(ImGuiKey_UpArrow) && state.selected_offset >= state.bytes_per_row)
				state.selected_offset -= state.bytes_per_row;
			if (ImGui::IsKeyPressed(ImGuiKey_RightArrow) && state.selected_offset >= 0)
				state.selected_offset += csz;
			if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow) && state.selected_offset >= csz)
				state.selected_offset -= csz;
		}

		ImGui::EndChild();
		ImGui::PopFont();

		return modified;
	}
}
