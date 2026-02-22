#include "system_check.h"
#include "../app.h"
#include "../system_check/system_info.h"
#include "../renderer/renderer.h"
#include "../renderer/anim.h"

#include <imgui.h>
#include <shellapi.h>

void SystemCheckPage::on_enter()
{
	m_checks_done = false;
	m_force_skip = false;
	app::state().checks = system_info::run_all_checks();
	m_checks_done = true;
}

void SystemCheckPage::on_exit() {}

static const ImU32 U32_ACCENT   = IM_COL32(255, 107, 0, 255);
static const ImU32 U32_ACCENT50 = IM_COL32(255, 107, 0, 50);
static const ImVec4 COL_ACCENT  = ImVec4(1.0f, 0.42f, 0.0f, 1.0f);
static const ImVec4 COL_GREEN   = ImVec4(0.3f, 0.95f, 0.45f, 1.0f);
static const ImVec4 COL_RED     = ImVec4(1.0f, 0.28f, 0.28f, 1.0f);
static const ImVec4 COL_YELLOW  = ImVec4(1.0f, 0.8f, 0.2f, 1.0f);
static const ImVec4 COL_DIM     = ImVec4(0.48f, 0.48f, 0.55f, 1.0f);
static const ImVec4 COL_TEXT    = ImVec4(0.92f, 0.92f, 0.95f, 1.0f);

static void draw_accent_line(float x1, float x2, float y, float thickness = 2.0f)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	dl->AddLine(ImVec2(wp.x + x1, wp.y + y), ImVec2(wp.x + x2, wp.y + y), U32_ACCENT, thickness);
}

static void draw_status_dot(float x, float y, bool passed, float enter_time, int index)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	ImVec2 center(wp.x + x, wp.y + y);

	float alpha = anim::stagger(enter_time + 0.3f, index, 0.15f, 0.4f);
	float scale = anim::stagger(enter_time + 0.3f, index, 0.15f, 0.3f);

	ImU32 col = passed
		? IM_COL32(76, 242, 115, (int)(255 * alpha))
		: IM_COL32(255, 72, 72, (int)(255 * alpha));
	ImU32 glow = passed
		? IM_COL32(76, 242, 115, (int)(40 * alpha))
		: IM_COL32(255, 72, 72, (int)(40 * alpha));

	float r = 5.0f * scale;
	dl->AddCircleFilled(center, r + 3, glow);
	dl->AddCircleFilled(center, r, col);
}

static void draw_check_row(float base_x, const char* label, const system_info::check_result_t& check,
	float enter_time, int index)
{
	float alpha = anim::stagger(enter_time + 0.3f, index, 0.15f, 0.4f);
	float slide = anim::slide_stagger(enter_time + 0.3f, index, 15.0f, 0.15f, 0.4f);

	float cy = ImGui::GetCursorPosY();

	draw_status_dot(base_x + 6, cy + 10 + slide, check.passed, enter_time, index);

	ImGui::SetCursorPos(ImVec2(base_x + 22, cy + slide));
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, alpha);
	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(COL_TEXT, "%s", label);
	ImGui::PopFont();

	ImGui::SameLine(base_x + 220);
	ImGui::TextColored(COL_DIM, "%s", check.detail.c_str());
	ImGui::PopStyleVar();

	ImGui::SetCursorPosY(cy + 32);
}

void SystemCheckPage::render()
{
	const float W = (float)renderer::WINDOW_WIDTH;
	const float H = (float)renderer::WINDOW_HEIGHT;
	const float TITLE_H = 44.0f;
	float page_alpha = anim::fade_in(m_enter_time, 0.3f);

	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::SetNextWindowSize(ImVec2(W, H));
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, page_alpha);
	ImGui::Begin("##system_check", nullptr,
		ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
		ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
		ImGuiWindowFlags_NoScrollbar);

	// === title bar ===
	float title_font_h = renderer::font_title()->FontSize;
	float title_y = (TITLE_H - title_font_h) * 0.5f;
	float btn_h = 28.0f;
	float btn_y = (TITLE_H - btn_h) * 0.5f;

	// ZEROHOOK with glow pulse
	float glow_alpha = anim::pulse_range(0.7f, 1.0f, 1.5f);
	ImGui::SetCursorPos(ImVec2(20, title_y));
	ImGui::PushFont(renderer::font_title());
	ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, glow_alpha), "ZEROHOOK");
	ImGui::PopFont();

	ImGui::SetCursorPos(ImVec2(W - 72, btn_y));
	if (ImGui::Button(" _ ##min", ImVec2(30, btn_h)))
		ShowWindow(renderer::get_hwnd(), SW_MINIMIZE);
	ImGui::SameLine(0, 4);
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.8f, 0.15f, 0.15f, 1.0f));
	if (ImGui::Button(" X ##close", ImVec2(30, btn_h)))
		renderer::request_close();
	ImGui::PopStyleColor();

	draw_accent_line(0, W, TITLE_H, 2.0f);

	// === card with slide-up + fade ===
	float card_w = 520.0f;
	float card_h = 400.0f;
	float card_x = (W - card_w) * 0.5f;
	float card_base_y = (H - card_h) * 0.5f - 16;
	float card_slide = anim::slide_in(m_enter_time, 30.0f, 0.4f);
	float card_y = card_base_y + card_slide;

	ImGui::SetCursorPos(ImVec2(card_x, card_y));
	ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.065f, 0.065f, 0.09f, 1.0f));
	ImGui::BeginChild("##check_card", ImVec2(card_w, card_h), ImGuiChildFlags_None);

	// accent top edge + shimmer
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		dl->AddRectFilled(wp, ImVec2(wp.x + card_w, wp.y + 2), U32_ACCENT);
		dl->AddRectFilledMultiColor(
			ImVec2(wp.x, wp.y + 2), ImVec2(wp.x + card_w, wp.y + 12),
			U32_ACCENT50, U32_ACCENT50, IM_COL32(0, 0, 0, 0), IM_COL32(0, 0, 0, 0));

		// shimmer sweep
		float sx = anim::shimmer_x(card_w, 0.4f, m_enter_time);
		float sw = 40.0f;
		if (sx > 0 && sx < card_w)
		{
			ImU32 shimmer = IM_COL32(255, 200, 120, 60);
			dl->AddRectFilled(
				ImVec2(wp.x + sx, wp.y), ImVec2(wp.x + sx + sw, wp.y + 2), shimmer);
		}
	}

	ImGui::SetCursorPos(ImVec2(32, 24));
	ImGui::PushFont(renderer::font_title());
	ImGui::TextColored(COL_TEXT, "System Compatibility");
	ImGui::PopFont();

	ImGui::SetCursorPos(ImVec2(32, 52));
	ImGui::TextColored(COL_DIM, "Verifying your system meets the requirements");

	ImGui::SetCursorPosY(78);

	if (!m_checks_done)
	{
		ImGui::SetCursorPosX(32);
		// animated dots
		int dots = ((int)(anim::time() * 3.0f)) % 4;
		const char* dot_str[] = { "", ".", "..", "..." };
		ImGui::TextColored(COL_ACCENT, "Running checks%s", dot_str[dots]);
	}
	else
	{
		auto& checks = app::state().checks;

		ImGui::SetCursorPosY(84);
		draw_check_row(32, "CPU Vendor", checks.cpu_vendor, m_enter_time, 0);
		draw_check_row(32, "Hyper-V", checks.hyperv, m_enter_time, 1);
		draw_check_row(32, "Windows Version", checks.windows, m_enter_time, 2);
		draw_check_row(32, "Secure Boot", checks.secure_boot, m_enter_time, 3);
		draw_check_row(32, "PDB Loader", checks.pdb_loader, m_enter_time, 4);

		ImGui::Spacing();

		float warn_alpha = anim::fade_in(m_enter_time + 1.0f, 0.5f);
		ImGui::PushStyleVar(ImGuiStyleVar_Alpha, warn_alpha);

		if (!checks.cpu_vendor.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(COL_RED, "! Intel CPU required. AMD is not supported.");
		}
		if (!checks.hyperv.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(COL_RED, "! Hyper-V is required. Enable it in Windows Features.");
		}
		if (!checks.windows.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(COL_RED, "! Windows 10 Build 19041+ is required.");
		}
		if (!checks.secure_boot.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(COL_RED, "! Secure Boot must be disabled in BIOS/UEFI settings.");
		}
		if (!checks.pdb_loader.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(COL_YELLOW, "! PDB loader unavailable. Install VS Build Tools or place msdia140.dll next to exe.");
		}

		ImGui::PopStyleVar();

		ImGui::Spacing();
		ImGui::Spacing();

		// buttons fade in after checks
		float btn_alpha = anim::fade_in(m_enter_time + 1.2f, 0.4f);
		ImGui::PushStyleVar(ImGuiStyleVar_Alpha, btn_alpha);

		bool can_continue = checks.all_critical_passed();

		// Continue button (centered with force skip to the right)
		float btn_w = 200.0f;
		float total_w = btn_w + 100.0f; // continue + gap + skip
		float start_x = (card_w - total_w) * 0.5f;

		ImGui::SetCursorPosX(start_x);

		if (!can_continue && !m_force_skip) ImGui::BeginDisabled();

		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.42f, 0.0f, 1.0f));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.55f, 0.16f, 1.0f));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.8f, 0.33f, 0.0f, 1.0f));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.0f, 0.0f, 1.0f));

		if (ImGui::Button("Continue", ImVec2(btn_w, 36)))
			app::navigate_to(page_id::login);

		ImGui::PopStyleColor(4);

		if (!can_continue && !m_force_skip) ImGui::EndDisabled();

		// Force skip link
		ImGui::SameLine(0, 16);
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 1.0f, 1.0f, 0.06f));
		ImGui::PushStyleColor(ImGuiCol_Text, COL_DIM);

		if (ImGui::Button("Force Skip >>", ImVec2(0, 36)))
		{
			m_force_skip = true;
			app::navigate_to(page_id::login);
		}

		ImGui::PopStyleColor(3);

		ImGui::PopStyleVar();
	}

	ImGui::EndChild();
	ImGui::PopStyleColor();

	// footer
	float footer_y = H - 32;
	ImGui::SetCursorPos(ImVec2(20, footer_y + 6));
	ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 0.6f), "ZeroHook.gg");

	float discord_w = ImGui::CalcTextSize("Discord").x + 24;
	ImGui::SetCursorPos(ImVec2(W - discord_w - 16, footer_y + 2));
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.35f, 0.4f, 0.95f, 0.2f));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.5f, 1.0f, 0.8f));
	if (ImGui::Button("Discord"))
		ShellExecuteA(nullptr, "open", "https://discord.gg/zerohook", nullptr, nullptr, SW_SHOWNORMAL);
	ImGui::PopStyleColor(3);

	renderer::draw_window_border();

	ImGui::End();
	ImGui::PopStyleVar(); // page alpha
}
