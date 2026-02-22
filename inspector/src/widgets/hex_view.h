#pragma once
#include <cstdint>
#include <imgui.h>
#include <functional>

namespace widgets
{
	enum class display_mode_t
	{
		hex_byte,    // FF FF FF ... + ASCII (classic CE view)
		hex_int16,   // FFFF FFFF ... (2-byte groups)
		hex_int32,   // FFFFFFFF FFFFFFFF ... (4-byte groups)
		hex_int64,   // FFFFFFFFFFFFFFFF ... (8-byte groups)
		dec_int32,   // signed decimal int32
		dec_uint32,  // unsigned decimal uint32
		float32,     // float display
		float64,     // double display
	};

	struct hex_view_state_t
	{
		uint64_t base_address = 0;
		int bytes_per_row = 16;
		int selected_offset = -1;
		bool editing = false;
		char edit_buf[3] = {};
		int edit_nibble = 0;

		// display
		display_mode_t display_mode = display_mode_t::hex_byte;

		// scroll
		float scroll_y = 0.0f;

		// range selection
		int selection_start = -1;
		int selection_end = -1;

		// callback for navigation
		std::function<void(uint64_t)> on_goto = nullptr;

		// callback for "Find What Accesses" (hex view -> code filter)
		std::function<void(uint64_t)> on_find_accesses = nullptr;

		// callback for "Add to Watch List"
		std::function<void(uint64_t)> on_add_watch = nullptr;
	};

	// render hex view. returns true if a byte was modified.
	bool hex_view(const char* id, hex_view_state_t& state, float width, float height);
}
