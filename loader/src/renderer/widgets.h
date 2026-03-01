#pragma once
#include <imgui.h>

namespace widgets
{
	// Title bar (shared across all 3 pages)
	// page_label: "Dashboard" or nullptr; show_user_info: true on dashboard only
	void render_title_bar(float enter_time, const char* page_label = nullptr, bool show_user_info = false);

	// Footer (ZeroHook.gg + Discord)
	void render_footer();

	// Styled input with leading FA icon. Returns true on Enter.
	bool icon_input(const char* icon, const char* id, char* buf, int buf_size, float width, ImGuiInputTextFlags flags = 0);

	// Password input with lock icon + eye toggle. Returns true on Enter.
	bool password_input(const char* id, char* buf, int buf_size, float width, bool* show_password);

	// Orange primary button (black text)
	bool accent_button(const char* label, ImVec2 size = ImVec2(0, 36));

	// Underline-on-hover link. If url != nullptr, ShellExecute on click.
	bool link_button(const char* label, const ImVec4& color, const char* url = nullptr);

	// Rotating arc spinner
	void spinner(const char* label, float radius = 8.0f);

	// Accent line / separator line helpers
	void accent_line(float x1, float x2, float y, float thickness = 2.0f);
	void h_line(float x1, float x2, float y, ImU32 color, float thickness = 1.0f);
}
