#include "dashboard.h"
#include "../app.h"
#include "../auth/auth_client.h"
#include "../backend/loader_backend.h"
#include "../renderer/renderer.h"
#include "../renderer/anim.h"

#include <imgui.h>
#include <shellapi.h>
#include <vector>
#include <cctype>

static const ImU32 U32_ACCENT     = IM_COL32(255, 107, 0, 255);
static const ImU32 U32_ACCENT80   = IM_COL32(255, 107, 0, 80);
static const ImU32 U32_ACCENT50   = IM_COL32(255, 107, 0, 50);
static const ImU32 U32_ACCENT20   = IM_COL32(255, 107, 0, 20);
static const ImU32 U32_GREEN      = IM_COL32(76, 242, 115, 255);
static const ImU32 U32_RED        = IM_COL32(255, 72, 72, 255);
static const ImU32 U32_SEPARATOR  = IM_COL32(40, 40, 55, 255);

static const ImVec4 COL_ACCENT = ImVec4(1.0f, 0.42f, 0.0f, 1.0f);
static const ImVec4 COL_DIM    = ImVec4(0.48f, 0.48f, 0.55f, 1.0f);
static const ImVec4 COL_GREEN  = ImVec4(0.3f, 0.95f, 0.45f, 1.0f);
static const ImVec4 COL_YELLOW = ImVec4(1.0f, 0.8f, 0.2f, 1.0f);
static const ImVec4 COL_RED    = ImVec4(1.0f, 0.28f, 0.28f, 1.0f);
static const ImVec4 COL_TEXT   = ImVec4(0.92f, 0.92f, 0.95f, 1.0f);

static constexpr float LEFT_PANEL_WIDTH = 270.0f;
static constexpr float BOTTOM_BAR_HEIGHT = 44.0f;
static constexpr float TITLE_BAR_HEIGHT = 44.0f;

// --- helpers ---

static void draw_accent_line(float x1, float x2, float y, float thickness = 2.0f)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	dl->AddLine(ImVec2(wp.x + x1, wp.y + y), ImVec2(wp.x + x2, wp.y + y), U32_ACCENT, thickness);
}

static void draw_h_line(float x1, float x2, float y, ImU32 col, float thickness = 1.0f)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	dl->AddLine(ImVec2(wp.x + x1, wp.y + y), ImVec2(wp.x + x2, wp.y + y), col, thickness);
}

// generate a consistent color from a game name
static ImVec4 game_logo_color(const std::string& name)
{
	unsigned hash = 5381;
	for (char c : name) hash = hash * 33 + (unsigned)c;

	static const ImVec4 palette[] = {
		ImVec4(0.25f, 0.55f, 1.00f, 1.0f), // blue
		ImVec4(0.90f, 0.25f, 0.40f, 1.0f), // red-pink
		ImVec4(0.15f, 0.80f, 0.55f, 1.0f), // teal-green
		ImVec4(0.90f, 0.55f, 0.10f, 1.0f), // orange
		ImVec4(0.65f, 0.35f, 0.90f, 1.0f), // purple
		ImVec4(0.95f, 0.75f, 0.15f, 1.0f), // gold
	};
	return palette[hash % 6];
}

static void draw_game_logo(ImVec2 pos, float size, const std::string& name, bool dimmed, float alpha = 1.0f)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	ImVec2 p_min(wp.x + pos.x, wp.y + pos.y);
	ImVec2 p_max(p_min.x + size, p_min.y + size);

	ImVec4 col = game_logo_color(name);
	if (dimmed) { col.x *= 0.35f; col.y *= 0.35f; col.z *= 0.35f; }
	col.w = alpha;

	// subtle shadow behind logo
	dl->AddRectFilled(ImVec2(p_min.x + 1, p_min.y + 1), ImVec2(p_max.x + 1, p_max.y + 1),
		IM_COL32(0, 0, 0, (int)(50 * alpha)), 6.0f);
	dl->AddRectFilled(p_min, p_max, ImGui::ColorConvertFloat4ToU32(col), 6.0f);

	// first letter centered
	char letter[2] = { (char)toupper(name[0]), 0 };
	ImFont* font = renderer::font_title();
	ImVec2 ts = font->CalcTextSizeA(font->FontSize, FLT_MAX, 0.0f, letter);
	ImVec2 tp(p_min.x + (size - ts.x) * 0.5f, p_min.y + (size - ts.y) * 0.5f);
	int text_a = dimmed ? (int)(100 * alpha) : (int)(240 * alpha);
	dl->AddText(font, font->FontSize, tp, IM_COL32(255, 255, 255, text_a), letter);
}

static void draw_game_entry(int index, const game_info_t& game, bool dimmed, float enter_time, int stagger_index)
{
	auto& state = app::state();

	float item_alpha = anim::stagger(enter_time + 0.3f, stagger_index, 0.1f, 0.4f);
	float item_slide = anim::slide_stagger(enter_time + 0.3f, stagger_index, 12.0f, 0.1f, 0.4f);

	ImVec4 dot_color;
	const char* status_text;
	switch (game.status)
	{
	case game_status::online:   dot_color = COL_GREEN;  status_text = "Online";   break;
	case game_status::updating: dot_color = COL_YELLOW; status_text = "Updating"; break;
	case game_status::offline:  dot_color = COL_RED;    status_text = "Offline";  break;
	default:                    dot_color = COL_DIM;    status_text = "Unknown";  break;
	}

	if (dimmed) dot_color = ImVec4(dot_color.x * 0.45f, dot_color.y * 0.45f, dot_color.z * 0.45f, 1.0f);

	ImGui::PushID(index);
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, item_alpha);

	float cursor_y = ImGui::GetCursorPosY() + item_slide;
	ImGui::SetCursorPosY(cursor_y);

	bool selected = (state.selected_game == index);
	constexpr float LOGO_SIZE = 36.0f;
	constexpr float ROW_H = 52.0f;

	// selectable background
	ImGui::SetCursorPosX(6);
	if (selected)
		ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(1.0f, 0.42f, 0.0f, 0.12f));

	bool can_select = !dimmed;
	if (dimmed) ImGui::PushStyleVar(ImGuiStyleVar_Alpha, 0.55f * item_alpha);

	if (ImGui::Selectable("##sel", selected, can_select ? 0 : ImGuiSelectableFlags_Disabled,
		ImVec2(LEFT_PANEL_WIDTH - 20, ROW_H)))
		state.selected_game = index;

	if (dimmed) ImGui::PopStyleVar();
	if (selected) ImGui::PopStyleColor();

	// accent left bar on selected
	if (selected)
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		dl->AddRectFilled(
			ImVec2(wp.x + 2, wp.y + cursor_y),
			ImVec2(wp.x + 5, wp.y + cursor_y + ROW_H),
			IM_COL32(255, 107, 0, (int)(255 * item_alpha)), 2.0f);
	}

	// logo
	draw_game_logo(ImVec2(14, cursor_y + (ROW_H - LOGO_SIZE) * 0.5f), LOGO_SIZE, game.name, dimmed, item_alpha);

	// text
	float text_x = 14 + LOGO_SIZE + 10;

	ImGui::SetCursorPos(ImVec2(text_x, cursor_y + 7));
	ImGui::PushFont(renderer::font_bold());
	if (dimmed)
		ImGui::TextColored(ImVec4(0.55f, 0.55f, 0.60f, 1.0f), "%s", game.name.c_str());
	else
		ImGui::TextColored(COL_TEXT, "%s", game.name.c_str());
	ImGui::PopFont();

	// status dot with pulse for online games
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		float dot_y = cursor_y + 32;
		ImU32 dc = ImGui::ColorConvertFloat4ToU32(dot_color);
		float dot_r = 3.5f;

		// subtle pulse on online status
		if (game.status == game_status::online && !dimmed)
		{
			float pulse_a = anim::pulse_range(0.15f, 0.4f, 2.0f);
			ImU32 glow = IM_COL32(76, 242, 115, (int)(255 * pulse_a * item_alpha));
			dl->AddCircleFilled(ImVec2(wp.x + text_x + 4, wp.y + dot_y + 5), dot_r + 3, glow);
		}

		dl->AddCircleFilled(ImVec2(wp.x + text_x + 4, wp.y + dot_y + 5), dot_r, dc);
	}

	ImGui::SetCursorPos(ImVec2(text_x + 14, cursor_y + 28));
	ImGui::TextColored(dot_color, "%s", status_text);
	ImGui::SameLine(0, 8);
	ImGui::TextColored(COL_DIM, "v%s", game.version.c_str());

	ImGui::SetCursorPosY(cursor_y + ROW_H + 2);

	ImGui::PopStyleVar(); // item alpha
	ImGui::PopID();
}

// --- page methods ---

void DashboardPage::on_enter()
{
	auto& state = app::state();
	if (state.session.patch_notes.empty())
		state.session.patch_notes = auth::fetch_patch_notes();
}

void DashboardPage::on_exit() {}

void DashboardPage::render()
{
	const float W = (float)renderer::WINDOW_WIDTH;
	const float H = (float)renderer::WINDOW_HEIGHT;
	float page_alpha = anim::fade_in(m_enter_time, 0.3f);

	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::SetNextWindowSize(ImVec2(W, H));
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, page_alpha);
	ImGui::Begin("##dashboard", nullptr,
		ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
		ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
		ImGuiWindowFlags_NoScrollbar);

	render_title_bar();

	float content_y = TITLE_BAR_HEIGHT + 2;
	float content_h = H - content_y - BOTTOM_BAR_HEIGHT - 2;

	// left panel
	ImGui::SetCursorPos(ImVec2(0, content_y));
	ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.045f, 0.045f, 0.065f, 1.0f));
	ImGui::BeginChild("##left_panel", ImVec2(LEFT_PANEL_WIDTH, content_h), ImGuiChildFlags_None);
	render_game_list();
	ImGui::EndChild();
	ImGui::PopStyleColor();

	// vertical separator between panels with fade
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		float sep_alpha = anim::fade_in(m_enter_time + 0.4f, 0.3f);
		dl->AddLine(
			ImVec2(wp.x + LEFT_PANEL_WIDTH, wp.y + content_y),
			ImVec2(wp.x + LEFT_PANEL_WIDTH, wp.y + content_y + content_h),
			IM_COL32(255, 107, 0, (int)(40 * sep_alpha)), 1.0f);
	}

	// right panel
	ImGui::SetCursorPos(ImVec2(LEFT_PANEL_WIDTH + 1, content_y));
	ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.04f, 0.04f, 0.055f, 1.0f));
	ImGui::BeginChild("##right_panel", ImVec2(W - LEFT_PANEL_WIDTH - 1, content_h), ImGuiChildFlags_None);
	render_patch_notes();
	ImGui::EndChild();
	ImGui::PopStyleColor();

	render_bottom_bar();

	renderer::draw_window_border();

	ImGui::End();
	ImGui::PopStyleVar(); // page alpha
}

void DashboardPage::render_title_bar()
{
	const float W = (float)renderer::WINDOW_WIDTH;
	const float BAR_H = TITLE_BAR_HEIGHT;

	const float title_h = renderer::font_title()->FontSize;
	const float text_h = renderer::font_bold()->FontSize;
	const float btn_h = 28.0f;
	const float title_y = (BAR_H - title_h) * 0.5f;
	const float text_y = (BAR_H - text_h) * 0.5f;
	const float btn_y = (BAR_H - btn_h) * 0.5f;

	// subtle darker background for title bar
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		dl->AddRectFilled(wp, ImVec2(wp.x + W, wp.y + BAR_H),
			IM_COL32(8, 8, 14, 255));
	}

	// "ZEROHOOK" title with glow pulse
	float glow_alpha = anim::pulse_range(0.7f, 1.0f, 1.5f);
	ImGui::SetCursorPos(ImVec2(20, title_y));
	ImGui::PushFont(renderer::font_title());
	ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, glow_alpha), "ZEROHOOK");
	ImGui::PopFont();

	// "Dashboard" label with fade
	float dash_alpha = anim::fade_in(m_enter_time + 0.2f, 0.4f);
	ImGui::SetCursorPos(ImVec2(175, text_y));
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, dash_alpha);
	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(COL_DIM, "Dashboard");
	ImGui::PopFont();
	ImGui::PopStyleVar();

	// user info — staggered fade from right
	auto& state = app::state();
	float info_alpha = anim::fade_in(m_enter_time + 0.4f, 0.4f);
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, info_alpha);

	ImGui::PushFont(renderer::font_bold());
	float username_w = ImGui::CalcTextSize(state.session.username.c_str()).x;
	float plan_w = ImGui::CalcTextSize(state.session.subscription.plan.c_str()).x;
	float logout_w = ImGui::CalcTextSize("Logout").x;
	ImGui::PopFont();

	float sep_w = ImGui::CalcTextSize("  |  ").x;
	float total_w = username_w + sep_w + plan_w + sep_w + logout_w + 24;
	float user_x = W - 80 - total_w;

	ImGui::SetCursorPos(ImVec2(user_x, text_y));
	ImGui::TextColored(COL_ACCENT, "%s", state.session.username.c_str());
	ImGui::SameLine(0, 6);
	ImGui::TextColored(ImVec4(0.35f, 0.35f, 0.42f, 1.0f), "|");
	ImGui::SameLine(0, 6);
	ImGui::TextColored(COL_DIM, "%s", state.session.subscription.plan.c_str());
	ImGui::SameLine(0, 6);
	ImGui::TextColored(ImVec4(0.35f, 0.35f, 0.42f, 1.0f), "|");
	ImGui::SameLine(0, 6);

	// logout button
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.8f, 0.15f, 0.15f, 0.3f));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.3f, 0.3f, 1.0f));
	float logout_btn_y = text_y - 2;
	ImGui::SetCursorPosY(logout_btn_y);
	if (ImGui::Button("Logout##titlebar"))
		app::logout();
	ImGui::PopStyleColor(3);

	ImGui::PopStyleVar(); // info alpha

	// minimize + close
	ImGui::SetCursorPos(ImVec2(W - 72, btn_y));
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 1.0f, 1.0f, 0.08f));
	if (ImGui::Button(" _ ##min", ImVec2(30, btn_h)))
		ShowWindow(renderer::get_hwnd(), SW_MINIMIZE);
	ImGui::PopStyleColor(2);

	ImGui::SameLine(0, 4);
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.85f, 0.15f, 0.15f, 0.8f));
	if (ImGui::Button(" X ##close", ImVec2(30, btn_h)))
		renderer::request_close();
	ImGui::PopStyleColor(2);

	// accent line under title bar
	draw_accent_line(0, W, BAR_H, 2.0f);
}

void DashboardPage::render_game_list()
{
	auto& state = app::state();
	auto& games = state.session.games;

	std::vector<int> available, unavailable;
	for (int i = 0; i < (int)games.size(); i++)
	{
		if (games[i].status == game_status::offline)
			unavailable.push_back(i);
		else
			available.push_back(i);
	}

	// === Available section ===
	float section_alpha = anim::fade_in(m_enter_time + 0.2f, 0.4f);
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, section_alpha);

	ImGui::SetCursorPos(ImVec2(14, 14));
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		float pulse_r = 4.0f + anim::pulse_range(0.0f, 1.0f, 2.5f);
		dl->AddCircleFilled(ImVec2(wp.x + 14, wp.y + 22), pulse_r, U32_GREEN);
	}
	ImGui::SetCursorPos(ImVec2(26, 14));
	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(COL_TEXT, "Available");
	ImGui::PopFont();
	ImGui::SameLine(0, 6);
	ImGui::TextColored(COL_DIM, "(%d)", (int)available.size());

	ImGui::PopStyleVar(); // section alpha

	// thin separator
	float sep_y = ImGui::GetCursorPosY() + 2;
	draw_h_line(12, LEFT_PANEL_WIDTH - 12, sep_y, U32_SEPARATOR);
	ImGui::SetCursorPosY(sep_y + 6);

	if (available.empty())
	{
		ImGui::SetCursorPosX(26);
		ImGui::TextColored(COL_DIM, "No games available");
		ImGui::Spacing();
	}
	else
	{
		int stagger_i = 0;
		for (int idx : available)
			draw_game_entry(idx, games[idx], false, m_enter_time, stagger_i++);
	}

	ImGui::Spacing();
	ImGui::Spacing();

	// === Unavailable section ===
	float section2_alpha = anim::fade_in(m_enter_time + 0.5f, 0.4f);
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, section2_alpha);

	float uav_y = ImGui::GetCursorPosY();
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		dl->AddCircleFilled(ImVec2(wp.x + 14, wp.y + uav_y + 8), 4.0f, U32_RED);
	}
	ImGui::SetCursorPos(ImVec2(26, uav_y));
	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(COL_TEXT, "Unavailable");
	ImGui::PopFont();
	ImGui::SameLine(0, 6);
	ImGui::TextColored(COL_DIM, "(%d)", (int)unavailable.size());

	ImGui::PopStyleVar(); // section2 alpha

	sep_y = ImGui::GetCursorPosY() + 2;
	draw_h_line(12, LEFT_PANEL_WIDTH - 12, sep_y, U32_SEPARATOR);
	ImGui::SetCursorPosY(sep_y + 6);

	if (unavailable.empty())
	{
		ImGui::SetCursorPosX(26);
		ImGui::TextColored(COL_DIM, "All games available!");
		ImGui::Spacing();
	}
	else
	{
		int stagger_i = (int)available.size(); // continue stagger index
		for (int idx : unavailable)
			draw_game_entry(idx, games[idx], true, m_enter_time, stagger_i++);
	}
}

void DashboardPage::render_patch_notes()
{
	float notes_alpha = anim::fade_in(m_enter_time + 0.3f, 0.5f);
	float notes_slide = anim::slide_in(m_enter_time + 0.3f, 15.0f, 0.5f);

	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, notes_alpha);

	// header with accent dot
	float header_y = 14 + notes_slide;
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		dl->AddCircleFilled(ImVec2(wp.x + 18, wp.y + header_y + 8), 4.0f,
			IM_COL32(255, 107, 0, (int)(255 * notes_alpha)));
	}

	ImGui::SetCursorPos(ImVec2(30, header_y));
	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(COL_TEXT, "Patch Notes");
	ImGui::PopFont();

	float sep_y = ImGui::GetCursorPosY() + 2;
	float panel_w = (float)renderer::WINDOW_WIDTH - LEFT_PANEL_WIDTH;
	draw_h_line(14, panel_w - 14, sep_y, U32_SEPARATOR);
	ImGui::SetCursorPosY(sep_y + 10);

	auto& state = app::state();
	ImGui::SetCursorPosX(20);
	ImGui::PushTextWrapPos(panel_w - 20);
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.72f, 0.72f, 0.78f, 1.0f));
	ImGui::TextUnformatted(state.session.patch_notes.c_str());
	ImGui::PopStyleColor();
	ImGui::PopTextWrapPos();

	ImGui::PopStyleVar(); // notes alpha
}

void DashboardPage::render_bottom_bar()
{
	auto& state = app::state();
	const float W = (float)renderer::WINDOW_WIDTH;
	const float H = (float)renderer::WINDOW_HEIGHT;
	const float BAR_H = BOTTOM_BAR_HEIGHT;
	float y = H - BAR_H;

	const float text_h = renderer::font_regular()->FontSize;
	const float text_y = (BAR_H - text_h) * 0.5f;
	const float btn_h = 28.0f;
	const float btn_y = (BAR_H - btn_h) * 0.5f;

	// bottom bar fade
	float bar_alpha = anim::fade_in(m_enter_time + 0.5f, 0.4f);
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, bar_alpha);

	ImGui::SetCursorPos(ImVec2(0, y));
	ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.035f, 0.035f, 0.05f, 1.0f));
	ImGui::BeginChild("##bottom_bar", ImVec2(W, BAR_H), ImGuiChildFlags_None);

	// accent top line on bar
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		dl->AddRectFilled(wp, ImVec2(wp.x + W, wp.y + 1), IM_COL32(255, 107, 0, 60));

		// shimmer sweep across bottom bar
		float sx = anim::shimmer_x(W, 0.3f, m_enter_time + 0.5f);
		float sw = 50.0f;
		if (sx > 0 && sx < W)
		{
			ImU32 shimmer = IM_COL32(255, 200, 120, 40);
			dl->AddRectFilled(
				ImVec2(wp.x + sx, wp.y), ImVec2(wp.x + sx + sw, wp.y + 1), shimmer);
		}
	}

	// === left: ZeroHook.gg + Discord ===
	ImGui::SetCursorPos(ImVec2(16, text_y));
	ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 0.7f), "ZeroHook.gg");

	ImGui::SetCursorPos(ImVec2(118, btn_y));
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.35f, 0.4f, 0.95f, 0.15f));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.5f, 1.0f, 0.75f));
	if (ImGui::Button("Discord", ImVec2(0, btn_h)))
		ShellExecuteA(nullptr, "open", "https://discord.gg/zerohook", nullptr, nullptr, SW_SHOWNORMAL);
	ImGui::PopStyleColor(3);

	// === center: status text ===
	std::string status = backend::get_status_text();
	float status_w = ImGui::CalcTextSize(status.c_str()).x;
	ImGui::SetCursorPos(ImVec2((W - status_w) * 0.5f, text_y));

	auto bstate = backend::get_state();
	ImVec4 status_col = COL_DIM;
	if (bstate == backend::inject_state::success) status_col = COL_GREEN;
	if (bstate == backend::inject_state::failed)  status_col = COL_RED;
	if (bstate == backend::inject_state::running) status_col = COL_ACCENT;
	ImGui::TextColored(status_col, "%s", status.c_str());

	// === right: expiry, spoofer, apply (right-to-left) ===
	const float apply_w = 90.0f;
	const float apply_x = W - apply_w - 14;

	bool busy = backend::is_busy();
	bool no_game = state.session.games.empty();
	bool game_offline = !no_game &&
		state.session.games[state.selected_game].status == game_status::offline;

	if (busy || no_game || game_offline)
		ImGui::BeginDisabled();

	ImGui::SetCursorPos(ImVec2(apply_x, btn_y));
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.42f, 0.0f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.55f, 0.16f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.8f, 0.33f, 0.0f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.0f, 0.0f, 1.0f));

	if (ImGui::Button("Apply", ImVec2(apply_w, btn_h)))
	{
		auto& game = state.session.games[state.selected_game];
		backend::inject_async(game.dll_path, game.process_name);
	}

	ImGui::PopStyleColor(4);

	if (busy || no_game || game_offline)
		ImGui::EndDisabled();

	// Spoofer checkbox
	float spoof_w = ImGui::CalcTextSize("Spoofer").x + 24;
	float spoof_x = apply_x - spoof_w - 16;
	float checkbox_y = (BAR_H - 20.0f) * 0.5f;
	ImGui::SetCursorPos(ImVec2(spoof_x, checkbox_y));
	ImGui::Checkbox("Spoofer", &state.spoofer_enabled);

	// Expiry
	char exp_buf[64];
	snprintf(exp_buf, sizeof(exp_buf), "Exp: %s", state.session.subscription.expiry.c_str());
	float exp_w = ImGui::CalcTextSize(exp_buf).x;
	float exp_x = spoof_x - exp_w - 16;
	ImGui::SetCursorPos(ImVec2(exp_x, text_y));
	ImGui::TextColored(COL_DIM, "%s", exp_buf);

	ImGui::EndChild();
	ImGui::PopStyleColor(); // child bg

	ImGui::PopStyleVar(); // bar alpha
}
