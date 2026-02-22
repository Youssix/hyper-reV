#include "theme.h"
#include <imgui.h>

namespace theme
{
	static ImVec4 hex(unsigned int hex, float a = 1.0f)
	{
		return ImVec4(
			((hex >> 16) & 0xFF) / 255.0f,
			((hex >> 8) & 0xFF) / 255.0f,
			(hex & 0xFF) / 255.0f,
			a);
	}

	void apply()
	{
		ImGuiStyle& style = ImGui::GetStyle();

		// geometry
		style.WindowRounding    = 0.0f;
		style.ChildRounding     = 4.0f;
		style.FrameRounding     = 4.0f;
		style.GrabRounding      = 4.0f;
		style.PopupRounding     = 4.0f;
		style.ScrollbarRounding = 4.0f;
		style.TabRounding       = 4.0f;

		style.WindowPadding    = ImVec2(0, 0);
		style.FramePadding     = ImVec2(12, 6);
		style.ItemSpacing      = ImVec2(10, 6);
		style.ItemInnerSpacing = ImVec2(8, 4);
		style.ScrollbarSize    = 8.0f;
		style.GrabMinSize      = 8.0f;
		style.WindowBorderSize = 0.0f;
		style.ChildBorderSize  = 0.0f;
		style.FrameBorderSize  = 0.0f;
		style.TabBorderSize    = 0.0f;

		// anti-aliasing
		style.AntiAliasedLines = true;
		style.AntiAliasedFill  = true;

		ImVec4* c = style.Colors;

		// backgrounds
		ImVec4 bg_dark    = hex(0x0A0A0F);
		ImVec4 bg_mid     = hex(0x101018);
		ImVec4 bg_panel   = hex(0x151520);
		ImVec4 bg_light   = hex(0x1C1C2A);
		ImVec4 bg_lighter = hex(0x252535);
		ImVec4 border     = hex(0x2A2A3A);

		// accent
		ImVec4 accent        = hex(0xFF6B00);
		ImVec4 accent_hover  = hex(0xFF8C33);
		ImVec4 accent_active = hex(0xCC5500);
		ImVec4 accent_dim    = hex(0xFF6B00, 0.15f);
		ImVec4 accent_muted  = hex(0xFF6B00, 0.35f);

		// text
		ImVec4 text_primary   = hex(0xEAEAF0);
		ImVec4 text_secondary = hex(0x7A7A88);
		ImVec4 text_disabled  = hex(0x454550);

		c[ImGuiCol_Text]                  = text_primary;
		c[ImGuiCol_TextDisabled]          = text_disabled;
		c[ImGuiCol_WindowBg]              = bg_dark;
		c[ImGuiCol_ChildBg]               = bg_mid;
		c[ImGuiCol_PopupBg]               = bg_panel;
		c[ImGuiCol_Border]                = border;
		c[ImGuiCol_BorderShadow]          = ImVec4(0, 0, 0, 0);
		c[ImGuiCol_FrameBg]               = hex(0x181824);
		c[ImGuiCol_FrameBgHovered]        = hex(0x1E1E2E);
		c[ImGuiCol_FrameBgActive]         = hex(0x222234);
		c[ImGuiCol_TitleBg]               = bg_dark;
		c[ImGuiCol_TitleBgActive]         = bg_dark;
		c[ImGuiCol_TitleBgCollapsed]      = bg_dark;
		c[ImGuiCol_MenuBarBg]             = bg_mid;
		c[ImGuiCol_ScrollbarBg]           = hex(0x0A0A0F, 0.5f);
		c[ImGuiCol_ScrollbarGrab]         = hex(0x333344);
		c[ImGuiCol_ScrollbarGrabHovered]  = accent_muted;
		c[ImGuiCol_ScrollbarGrabActive]   = accent;
		c[ImGuiCol_CheckMark]             = accent;
		c[ImGuiCol_SliderGrab]            = accent;
		c[ImGuiCol_SliderGrabActive]      = accent_active;
		c[ImGuiCol_Button]                = hex(0x1A1A28);
		c[ImGuiCol_ButtonHovered]         = hex(0xFF6B00, 0.20f);
		c[ImGuiCol_ButtonActive]          = accent_active;
		c[ImGuiCol_Header]                = hex(0x1A1A28);
		c[ImGuiCol_HeaderHovered]         = hex(0xFF6B00, 0.12f);
		c[ImGuiCol_HeaderActive]          = hex(0xFF6B00, 0.25f);
		c[ImGuiCol_Separator]             = hex(0x222233);
		c[ImGuiCol_SeparatorHovered]      = accent;
		c[ImGuiCol_SeparatorActive]       = accent;
		c[ImGuiCol_ResizeGrip]            = bg_lighter;
		c[ImGuiCol_ResizeGripHovered]     = accent;
		c[ImGuiCol_ResizeGripActive]      = accent_active;
		c[ImGuiCol_Tab]                   = bg_light;
		c[ImGuiCol_TabHovered]            = accent_dim;
		c[ImGuiCol_TabSelected]           = accent_active;
		c[ImGuiCol_TabDimmed]             = bg_mid;
		c[ImGuiCol_TabDimmedSelected]     = bg_light;
		c[ImGuiCol_PlotLines]             = accent;
		c[ImGuiCol_PlotLinesHovered]      = accent_hover;
		c[ImGuiCol_PlotHistogram]         = accent;
		c[ImGuiCol_PlotHistogramHovered]  = accent_hover;
		c[ImGuiCol_TableHeaderBg]         = bg_panel;
		c[ImGuiCol_TableBorderStrong]     = border;
		c[ImGuiCol_TableBorderLight]      = bg_light;
		c[ImGuiCol_TableRowBg]            = ImVec4(0, 0, 0, 0);
		c[ImGuiCol_TableRowBgAlt]         = hex(0xFFFFFF, 0.015f);
		c[ImGuiCol_TextSelectedBg]        = accent_dim;
		c[ImGuiCol_DragDropTarget]        = accent;
		c[ImGuiCol_NavCursor]             = accent;
		c[ImGuiCol_NavWindowingHighlight] = accent;
		c[ImGuiCol_NavWindowingDimBg]     = hex(0x000000, 0.5f);
		c[ImGuiCol_ModalWindowDimBg]      = hex(0x000000, 0.5f);

		// docking colors
		c[ImGuiCol_DockingPreview]        = hex(0xFF6B00, 0.6f);
		c[ImGuiCol_DockingEmptyBg]        = bg_dark;

		// add border to docked windows so splits are visible
		style.WindowBorderSize = 1.0f;
		style.DockingSeparatorSize = 2.0f;

		// viewport style tweaks
		if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
		{
			style.WindowRounding = 0.0f;
			style.Colors[ImGuiCol_WindowBg].w = 1.0f;
		}
	}
}
