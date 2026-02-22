#pragma once
#include <imgui.h>
#include <cmath>
#include <cstring>

namespace ui
{
	// ---- Tooltip ----
	// Call immediately after any ImGui widget to add a hover tooltip
	inline void tooltip(const char* text)
	{
		if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
			ImGui::SetItemTooltip("%s", text);
	}

	// ---- Status dot ----
	// Pulsing circle indicator for active monitoring states
	inline void status_dot(bool active, float size = 8.0f)
	{
		ImVec2 cursor = ImGui::GetCursorScreenPos();
		float radius = size * 0.5f;
		float cy = cursor.y + ImGui::GetTextLineHeight() * 0.5f;
		float cx = cursor.x + radius + 1.0f;

		ImU32 color;
		if (active)
		{
			float t = (sinf((float)ImGui::GetTime() * 3.0f) + 1.0f) * 0.5f;
			int alpha = (int)(140.0f + 115.0f * t);
			color = IM_COL32(76, 230, 102, alpha);
		}
		else
		{
			color = IM_COL32(100, 100, 115, 160);
		}

		ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(cx, cy), radius, color);
		ImGui::Dummy(ImVec2(size + 4.0f, ImGui::GetTextLineHeight()));
	}

	// ---- Toast notification system ----

	struct toast_state_t
	{
		float show_time = -10.0f;
		char text[128] = {};
	};

	inline toast_state_t& toast_state()
	{
		static toast_state_t s;
		return s;
	}

	// Copy text to clipboard and show a toast notification
	inline void clipboard(const char* text, const char* message = nullptr)
	{
		ImGui::SetClipboardText(text);
		auto& t = toast_state();
		t.show_time = (float)ImGui::GetTime();
		const char* msg = message ? message : "Copied to clipboard";
		strncpy(t.text, msg, sizeof(t.text) - 1);
		t.text[sizeof(t.text) - 1] = '\0';
	}

	// Render the toast overlay — call once per frame from the main render loop
	inline void render_toast()
	{
		auto& t = toast_state();
		float elapsed = (float)ImGui::GetTime() - t.show_time;
		if (elapsed > 2.0f || t.text[0] == '\0') return;

		float alpha = elapsed < 1.5f ? 1.0f : 1.0f - (elapsed - 1.5f) / 0.5f;
		if (alpha <= 0.0f) return;

		ImGuiViewport* vp = ImGui::GetMainViewport();
		ImVec2 text_size = ImGui::CalcTextSize(t.text);
		float pad_x = 16.0f, pad_y = 10.0f;
		float w = text_size.x + pad_x * 2;
		float h = text_size.y + pad_y * 2;

		// bottom-center position, above status bar
		ImVec2 pos(vp->Pos.x + vp->Size.x * 0.5f - w * 0.5f,
		           vp->Pos.y + vp->Size.y - 72.0f);

		ImDrawList* fg = ImGui::GetForegroundDrawList(vp);
		fg->AddRectFilled(pos, ImVec2(pos.x + w, pos.y + h),
			IM_COL32(25, 25, 35, (int)(230 * alpha)), 6.0f);
		fg->AddRect(pos, ImVec2(pos.x + w, pos.y + h),
			IM_COL32(255, 107, 0, (int)(160 * alpha)), 6.0f, 0, 1.0f);
		fg->AddText(ImVec2(pos.x + pad_x, pos.y + pad_y),
			IM_COL32(234, 234, 240, (int)(255 * alpha)), t.text);
	}

	// ---- Section header ----
	// Renders a styled section title with a subtle separator line

	inline void section(const char* title, ImFont* bold_font = nullptr)
	{
		ImGui::Spacing();
		if (bold_font) ImGui::PushFont(bold_font);
		ImGui::TextColored(ImVec4(0.72f, 0.72f, 0.78f, 1.0f), "%s", title);
		if (bold_font) ImGui::PopFont();

		ImVec2 p = ImGui::GetCursorScreenPos();
		float w = ImGui::GetContentRegionAvail().x;
		ImGui::GetWindowDrawList()->AddLine(
			ImVec2(p.x, p.y), ImVec2(p.x + w, p.y),
			IM_COL32(50, 50, 70, 180), 1.0f);
		ImGui::Dummy(ImVec2(0, 2));
	}

	// ---- Badge ----
	// A small colored tag (e.g., "Monitoring", "Loading")

	inline void badge(const char* text, ImU32 bg_color, ImU32 text_color = IM_COL32(255, 255, 255, 230))
	{
		ImVec2 text_size = ImGui::CalcTextSize(text);
		ImVec2 cursor = ImGui::GetCursorScreenPos();
		float pad_x = 8.0f, pad_y = 2.0f;
		float h = text_size.y + pad_y * 2;
		float w = text_size.x + pad_x * 2;

		ImDrawList* dl = ImGui::GetWindowDrawList();
		dl->AddRectFilled(cursor, ImVec2(cursor.x + w, cursor.y + h), bg_color, 3.0f);
		dl->AddText(ImVec2(cursor.x + pad_x, cursor.y + pad_y), text_color, text);
		ImGui::Dummy(ImVec2(w + 4.0f, h));
	}

	// ---- Splitter grip ----
	// Draw dots/grip pattern on a horizontal splitter

	inline void draw_splitter_grip(ImVec2 min, ImVec2 max)
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		float cx = (min.x + max.x) * 0.5f;
		float cy = (min.y + max.y) * 0.5f;
		ImU32 dot_color = IM_COL32(100, 100, 120, 180);
		float spacing = 8.0f;

		for (int i = -2; i <= 2; i++)
			dl->AddCircleFilled(ImVec2(cx + i * spacing, cy), 1.5f, dot_color);
	}
}
