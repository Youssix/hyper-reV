#pragma once
#include <imgui.h>

namespace theme
{
	void apply();

	inline const ImVec4 accent        = ImVec4(1.0f, 0.42f, 0.0f, 1.0f);
	inline const ImVec4 accent_hover  = ImVec4(1.0f, 0.55f, 0.16f, 1.0f);
	inline const ImVec4 accent_active = ImVec4(0.8f, 0.33f, 0.0f, 1.0f);
	inline const ImVec4 text_primary  = ImVec4(0.92f, 0.92f, 0.95f, 1.0f);
	inline const ImVec4 text_dim      = ImVec4(0.48f, 0.48f, 0.55f, 1.0f);
	inline const ImVec4 green         = ImVec4(0.3f, 0.95f, 0.45f, 1.0f);
	inline const ImVec4 yellow        = ImVec4(1.0f, 0.8f, 0.2f, 1.0f);
	inline const ImVec4 red           = ImVec4(1.0f, 0.28f, 0.28f, 1.0f);
	inline const ImVec4 link_color    = ImVec4(0.45f, 0.5f, 1.0f, 0.8f);
	inline const ImVec4 card_bg       = ImVec4(0.065f, 0.065f, 0.09f, 1.0f);

	inline const ImU32 accent_u32     = IM_COL32(255, 107, 0, 255);
	inline const ImU32 accent_u32_50  = IM_COL32(255, 107, 0, 50);
	inline const ImU32 green_u32      = IM_COL32(76, 242, 115, 255);
	inline const ImU32 red_u32        = IM_COL32(255, 72, 72, 255);
	inline const ImU32 separator_u32  = IM_COL32(40, 40, 55, 255);
}
