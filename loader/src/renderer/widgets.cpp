#include "widgets.h"
#include "renderer.h"
#include "theme.h"
#include "anim.h"
#include "../app.h"
#include "../vendor/IconsFontAwesome6.h"

#include <imgui.h>
#include <imgui_internal.h>
#include <shellapi.h>
#include <cmath>

namespace widgets
{
	void accent_line(float x1, float x2, float y, float thickness)
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		dl->AddLine(ImVec2(wp.x + x1, wp.y + y), ImVec2(wp.x + x2, wp.y + y), theme::accent_u32, thickness);
	}

	void h_line(float x1, float x2, float y, ImU32 color, float thickness)
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		dl->AddLine(ImVec2(wp.x + x1, wp.y + y), ImVec2(wp.x + x2, wp.y + y), color, thickness);
	}

	void render_title_bar(float enter_time, const char* page_label, bool show_user_info)
	{
		const float W = (float)renderer::WINDOW_WIDTH;
		const float BAR_H = renderer::TITLE_BAR_HEIGHT;

		const float title_h = renderer::font_title()->FontSize;
		const float text_h  = renderer::font_bold()->FontSize;
		const float btn_h   = 28.0f;
		const float title_y = (BAR_H - title_h) * 0.5f;
		const float text_y  = (BAR_H - text_h) * 0.5f;
		const float btn_y   = (BAR_H - btn_h) * 0.5f;

		// subtle darker background for title bar (dashboard has it, keep consistent)
		if (page_label || show_user_info)
		{
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 wp = ImGui::GetWindowPos();
			dl->AddRectFilled(wp, ImVec2(wp.x + W, wp.y + BAR_H), IM_COL32(8, 8, 14, 255));
		}

		// "ZEROHOOK" with glow pulse
		float glow_alpha = anim::pulse_range(0.7f, 1.0f, 1.5f);
		ImGui::SetCursorPos(ImVec2(20, title_y));
		ImGui::PushFont(renderer::font_title());
		ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, glow_alpha), "ZEROHOOK");
		ImGui::PopFont();

		// optional page label with fade
		if (page_label)
		{
			float dash_alpha = anim::fade_in(enter_time + 0.2f, 0.4f);
			ImGui::SetCursorPos(ImVec2(175, text_y));
			ImGui::PushStyleVar(ImGuiStyleVar_Alpha, dash_alpha);
			ImGui::PushFont(renderer::font_bold());
			ImGui::TextColored(theme::text_dim, "%s", page_label);
			ImGui::PopFont();
			ImGui::PopStyleVar();
		}

		// track how much right-side space is non-draggable
		float exclude_w = 72.0f; // min + close buttons baseline

		// user info (dashboard only)
		if (show_user_info)
		{
			auto& state = app::state();
			float info_alpha = anim::fade_in(enter_time + 0.4f, 0.4f);
			ImGui::PushStyleVar(ImGuiStyleVar_Alpha, info_alpha);

			ImGui::PushFont(renderer::font_bold());
			float username_w = ImGui::CalcTextSize(state.session.username.c_str()).x;
			float plan_w = ImGui::CalcTextSize(state.session.subscription.plan.c_str()).x;
			float logout_w = ImGui::CalcTextSize(ICON_FA_RIGHT_FROM_BRACKET " Logout").x;
			ImGui::PopFont();

			float sep_w = ImGui::CalcTextSize("  |  ").x;
			float total_w = username_w + sep_w + plan_w + sep_w + logout_w + 24;
			float user_x = W - 80 - total_w;

			ImGui::SetCursorPos(ImVec2(user_x, text_y));
			ImGui::TextColored(theme::accent, "%s", state.session.username.c_str());
			ImGui::SameLine(0, 6);
			ImGui::TextColored(ImVec4(0.35f, 0.35f, 0.42f, 1.0f), "|");
			ImGui::SameLine(0, 6);
			ImGui::TextColored(theme::text_dim, "%s", state.session.subscription.plan.c_str());
			ImGui::SameLine(0, 6);
			ImGui::TextColored(ImVec4(0.35f, 0.35f, 0.42f, 1.0f), "|");
			ImGui::SameLine(0, 6);

			// logout button
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.8f, 0.15f, 0.15f, 0.3f));
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.3f, 0.3f, 1.0f));
			ImGui::SetCursorPosY(text_y - 2);
			if (ImGui::Button(ICON_FA_RIGHT_FROM_BRACKET " Logout##titlebar"))
				app::logout();
			ImGui::PopStyleColor(3);

			ImGui::PopStyleVar(); // info alpha

			exclude_w = W - user_x + 8;
		}

		// minimize + close buttons
		ImGui::SetCursorPos(ImVec2(W - 72, btn_y));
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 1.0f, 1.0f, 0.08f));
		if (ImGui::Button(ICON_FA_WINDOW_MINIMIZE "##min", ImVec2(30, btn_h)))
			ShowWindow(renderer::get_hwnd(), SW_MINIMIZE);
		ImGui::PopStyleColor(2);

		ImGui::SameLine(0, 4);
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.85f, 0.15f, 0.15f, 0.8f));
		if (ImGui::Button(ICON_FA_XMARK "##close", ImVec2(30, btn_h)))
			renderer::request_close();
		ImGui::PopStyleColor(2);

		renderer::set_caption_exclude_width(exclude_w);

		// accent line under title bar
		accent_line(0, W, BAR_H, 2.0f);
	}

	void render_footer()
	{
		const float W = (float)renderer::WINDOW_WIDTH;
		const float H = (float)renderer::WINDOW_HEIGHT;
		float footer_y = H - 32;

		ImGui::SetCursorPos(ImVec2(20, footer_y + 6));
		ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 0.6f), "ZeroHook.gg");

		float discord_w = ImGui::CalcTextSize(ICON_FA_COMMENT " Discord").x + 24;
		ImGui::SetCursorPos(ImVec2(W - discord_w - 16, footer_y + 2));
		link_button(ICON_FA_COMMENT " Discord", theme::link_color, "https://discord.gg/zerohook");
	}

	bool icon_input(const char* icon, const char* id, char* buf, int buf_size, float width, ImGuiInputTextFlags flags)
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 cursor = ImGui::GetCursorScreenPos();
		float h = ImGui::GetFrameHeight();

		// draw custom background
		ImVec2 frame_min = cursor;
		ImVec2 frame_max(cursor.x + width, cursor.y + h);
		dl->AddRectFilled(frame_min, frame_max, IM_COL32(15, 15, 26, 255), 4.0f);
		dl->AddRect(frame_min, frame_max, IM_COL32(45, 45, 60, 255), 4.0f);

		// icon in left 34px zone
		float icon_zone = 34.0f;
		ImVec2 icon_size = ImGui::CalcTextSize(icon);
		float icon_x = cursor.x + (icon_zone - icon_size.x) * 0.5f;
		float icon_y = cursor.y + (h - icon_size.y) * 0.5f;
		dl->AddText(ImVec2(icon_x, icon_y), IM_COL32(122, 122, 140, 255), icon);

		// vertical separator
		dl->AddLine(ImVec2(cursor.x + icon_zone, cursor.y + 4),
		            ImVec2(cursor.x + icon_zone, cursor.y + h - 4),
		            IM_COL32(45, 45, 60, 255));

		// input text inset after icon zone
		float input_w = width - icon_zone - 4;
		ImGui::SetCursorScreenPos(ImVec2(cursor.x + icon_zone + 4, cursor.y));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0, 0, 0, 0));
		ImGui::PushItemWidth(input_w);
		bool enter = ImGui::InputText(id, buf, buf_size, flags);
		ImGui::PopItemWidth();
		ImGui::PopStyleColor(3);

		// restore cursor to after the full-width widget
		ImGui::SetCursorScreenPos(ImVec2(cursor.x, frame_max.y + ImGui::GetStyle().ItemSpacing.y));

		return enter;
	}

	bool password_input(const char* id, char* buf, int buf_size, float width, bool* show_password)
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 cursor = ImGui::GetCursorScreenPos();
		float h = ImGui::GetFrameHeight();

		// draw custom background
		ImVec2 frame_min = cursor;
		ImVec2 frame_max(cursor.x + width, cursor.y + h);
		dl->AddRectFilled(frame_min, frame_max, IM_COL32(15, 15, 26, 255), 4.0f);
		dl->AddRect(frame_min, frame_max, IM_COL32(45, 45, 60, 255), 4.0f);

		// lock icon in left 34px zone
		const char* lock_icon = ICON_FA_LOCK;
		float icon_zone = 34.0f;
		ImVec2 icon_size = ImGui::CalcTextSize(lock_icon);
		float icon_x = cursor.x + (icon_zone - icon_size.x) * 0.5f;
		float icon_y = cursor.y + (h - icon_size.y) * 0.5f;
		dl->AddText(ImVec2(icon_x, icon_y), IM_COL32(122, 122, 140, 255), lock_icon);

		// left separator
		dl->AddLine(ImVec2(cursor.x + icon_zone, cursor.y + 4),
		            ImVec2(cursor.x + icon_zone, cursor.y + h - 4),
		            IM_COL32(45, 45, 60, 255));

		// eye toggle in right 30px zone
		float eye_zone = 30.0f;
		const char* eye_icon = *show_password ? ICON_FA_EYE_SLASH : ICON_FA_EYE;
		ImVec2 eye_size = ImGui::CalcTextSize(eye_icon);
		float eye_x = cursor.x + width - eye_zone + (eye_zone - eye_size.x) * 0.5f;
		float eye_y = cursor.y + (h - eye_size.y) * 0.5f;

		// eye button (invisible, overlapping)
		ImGui::SetCursorScreenPos(ImVec2(cursor.x + width - eye_zone, cursor.y));
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1, 1, 1, 0.05f));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1, 1, 1, 0.1f));

		char eye_id[64];
		snprintf(eye_id, sizeof(eye_id), "%s_eye", id);
		if (ImGui::Button(eye_id, ImVec2(eye_zone, h)))
			*show_password = !*show_password;
		ImGui::PopStyleColor(3);

		// draw eye icon over button
		ImU32 eye_col = ImGui::IsItemHovered() ? IM_COL32(180, 180, 200, 255) : IM_COL32(122, 122, 140, 255);
		dl->AddText(ImVec2(eye_x, eye_y), eye_col, eye_icon);

		// right separator
		dl->AddLine(ImVec2(cursor.x + width - eye_zone, cursor.y + 4),
		            ImVec2(cursor.x + width - eye_zone, cursor.y + h - 4),
		            IM_COL32(45, 45, 60, 255));

		// password input field between icon and eye toggle
		float input_w = width - icon_zone - eye_zone - 8;
		ImGui::SetCursorScreenPos(ImVec2(cursor.x + icon_zone + 4, cursor.y));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0, 0, 0, 0));
		ImGui::PushItemWidth(input_w);
		ImGuiInputTextFlags pw_flags = ImGuiInputTextFlags_EnterReturnsTrue;
		if (!*show_password) pw_flags |= ImGuiInputTextFlags_Password;
		bool enter = ImGui::InputText(id, buf, buf_size, pw_flags);
		ImGui::PopItemWidth();
		ImGui::PopStyleColor(3);

		// restore cursor
		ImGui::SetCursorScreenPos(ImVec2(cursor.x, frame_max.y + ImGui::GetStyle().ItemSpacing.y));

		return enter;
	}

	bool accent_button(const char* label, ImVec2 size)
	{
		ImGui::PushStyleColor(ImGuiCol_Button, theme::accent);
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, theme::accent_hover);
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, theme::accent_active);
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.0f, 0.0f, 1.0f));
		bool clicked = ImGui::Button(label, size);
		ImGui::PopStyleColor(4);
		return clicked;
	}

	bool link_button(const char* label, const ImVec4& color, const char* url)
	{
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_Text, color);

		bool clicked = ImGui::Button(label);
		bool hovered = ImGui::IsItemHovered();

		// underline on hover
		if (hovered)
		{
			ImVec2 min = ImGui::GetItemRectMin();
			ImVec2 max = ImGui::GetItemRectMax();
			ImGui::GetWindowDrawList()->AddLine(
				ImVec2(min.x, max.y - 1), ImVec2(max.x, max.y - 1),
				ImGui::ColorConvertFloat4ToU32(color));
		}

		ImGui::PopStyleColor(4);

		if (clicked && url)
			ShellExecuteA(nullptr, "open", url, nullptr, nullptr, SW_SHOWNORMAL);

		return clicked;
	}

	void spinner(const char* label, float radius)
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 pos = ImGui::GetCursorScreenPos();
		float cx = pos.x + radius;
		float cy = pos.y + radius;

		float t = anim::time();
		int segments = 24;
		float start_angle = fmodf(t * 4.0f, 2.0f * 3.14159265f);

		for (int i = 0; i < segments; i++)
		{
			float a0 = start_angle + (float)i / segments * 2.0f * 3.14159265f;
			float a1 = start_angle + (float)(i + 1) / segments * 2.0f * 3.14159265f;
			float alpha = (float)i / segments; // tail-to-head gradient
			ImU32 col = IM_COL32(255, 107, 0, (int)(255 * alpha));
			dl->AddLine(
				ImVec2(cx + cosf(a0) * radius, cy + sinf(a0) * radius),
				ImVec2(cx + cosf(a1) * radius, cy + sinf(a1) * radius),
				col, 2.0f);
		}

		// label text to the right
		ImVec2 text_pos(pos.x + radius * 2 + 8, pos.y + radius - ImGui::GetTextLineHeight() * 0.5f);
		dl->AddText(text_pos, ImGui::ColorConvertFloat4ToU32(theme::accent), label);

		// advance cursor
		float text_w = ImGui::CalcTextSize(label).x;
		ImGui::Dummy(ImVec2(radius * 2 + 8 + text_w, radius * 2));
	}
}
