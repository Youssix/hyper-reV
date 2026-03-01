#include "system_check.h"
#include "../app.h"
#include "../system_check/system_info.h"
#include "../renderer/renderer.h"
#include "../renderer/anim.h"
#include "../renderer/theme.h"
#include "../renderer/widgets.h"
#include "../vendor/IconsFontAwesome6.h"

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

static void draw_check_row(float base_x, const char* icon, const char* label,
	const system_info::check_result_t& check, float enter_time, int index)
{
	float alpha = anim::stagger(enter_time + 0.3f, index, 0.15f, 0.4f);
	float slide = anim::slide_stagger(enter_time + 0.3f, index, 15.0f, 0.15f, 0.4f);

	float cy = ImGui::GetCursorPosY();

	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, alpha);

	// status icon (check or xmark)
	ImGui::SetCursorPos(ImVec2(base_x, cy + slide));
	if (check.passed)
		ImGui::TextColored(theme::green, ICON_FA_CIRCLE_CHECK);
	else
		ImGui::TextColored(theme::red, ICON_FA_CIRCLE_XMARK);

	// category icon
	ImGui::SameLine(0, 8);
	ImGui::TextColored(theme::text_dim, "%s", icon);

	// label
	ImGui::SameLine(0, 8);
	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(theme::text_primary, "%s", label);
	ImGui::PopFont();

	// detail
	ImGui::SameLine(base_x + 240);
	ImGui::TextColored(theme::text_dim, "%s", check.detail.c_str());

	ImGui::PopStyleVar();

	ImGui::SetCursorPosY(cy + 32);
}

void SystemCheckPage::render()
{
	const float W = (float)renderer::WINDOW_WIDTH;
	const float H = (float)renderer::WINDOW_HEIGHT;
	const float TITLE_H = renderer::TITLE_BAR_HEIGHT;
	float page_alpha = anim::fade_in(m_enter_time, 0.3f);

	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::SetNextWindowSize(ImVec2(W, H));
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, page_alpha);
	ImGui::Begin("##system_check", nullptr,
		ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
		ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
		ImGuiWindowFlags_NoScrollbar);

	// === title bar ===
	widgets::render_title_bar(m_enter_time);

	// === card with slide-up + fade ===
	float card_w = 520.0f;
	float card_h = 400.0f;
	float card_x = (W - card_w) * 0.5f;
	float card_base_y = (H - card_h) * 0.5f - 16;
	float card_slide = anim::slide_in(m_enter_time, 30.0f, 0.4f);
	float card_y = card_base_y + card_slide;

	ImGui::SetCursorPos(ImVec2(card_x, card_y));
	ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::card_bg);
	ImGui::BeginChild("##check_card", ImVec2(card_w, card_h), ImGuiChildFlags_None);

	// accent top edge + shimmer
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		dl->AddRectFilled(wp, ImVec2(wp.x + card_w, wp.y + 2), theme::accent_u32);
		dl->AddRectFilledMultiColor(
			ImVec2(wp.x, wp.y + 2), ImVec2(wp.x + card_w, wp.y + 12),
			theme::accent_u32_50, theme::accent_u32_50, IM_COL32(0, 0, 0, 0), IM_COL32(0, 0, 0, 0));

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
	ImGui::TextColored(theme::text_primary, "System Compatibility");
	ImGui::PopFont();

	ImGui::SetCursorPos(ImVec2(32, 52));
	ImGui::TextColored(theme::text_dim, "Verifying your system meets the requirements");

	ImGui::SetCursorPosY(78);

	if (!m_checks_done)
	{
		ImGui::SetCursorPosX(32);
		widgets::spinner("Running checks");
	}
	else
	{
		auto& checks = app::state().checks;

		ImGui::SetCursorPosY(84);
		draw_check_row(32, ICON_FA_MICROCHIP,      "CPU Vendor",      checks.cpu_vendor,  m_enter_time, 0);
		draw_check_row(32, ICON_FA_SHIELD_HALVED,   "Hyper-V",         checks.hyperv,      m_enter_time, 1);
		draw_check_row(32, ICON_FA_DESKTOP,          "Windows Version", checks.windows,     m_enter_time, 2);
		draw_check_row(32, ICON_FA_LOCK,             "Secure Boot",     checks.secure_boot, m_enter_time, 3);
		draw_check_row(32, ICON_FA_DATABASE,         "PDB Loader",      checks.pdb_loader,  m_enter_time, 4);

		ImGui::Spacing();

		float warn_alpha = anim::fade_in(m_enter_time + 1.0f, 0.5f);
		ImGui::PushStyleVar(ImGuiStyleVar_Alpha, warn_alpha);

		if (!checks.cpu_vendor.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(theme::red, ICON_FA_TRIANGLE_EXCLAMATION " Intel CPU required. AMD is not supported.");
		}
		if (!checks.hyperv.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(theme::red, ICON_FA_TRIANGLE_EXCLAMATION " Hyper-V is required. Enable it in Windows Features.");
		}
		if (!checks.windows.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(theme::red, ICON_FA_TRIANGLE_EXCLAMATION " Windows 10 Build 19041+ is required.");
		}
		if (!checks.secure_boot.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(theme::red, ICON_FA_TRIANGLE_EXCLAMATION " Secure Boot must be disabled in BIOS/UEFI settings.");
		}
		if (!checks.pdb_loader.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(theme::yellow, ICON_FA_TRIANGLE_EXCLAMATION " PDB loader unavailable. Install VS Build Tools or place msdia140.dll next to exe.");
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

		if (widgets::accent_button(ICON_FA_ARROW_RIGHT " Continue", ImVec2(btn_w, 36)))
			app::navigate_to(page_id::login);

		if (!can_continue && !m_force_skip) ImGui::EndDisabled();

		// Force skip link
		ImGui::SameLine(0, 16);
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 1.0f, 1.0f, 0.06f));
		ImGui::PushStyleColor(ImGuiCol_Text, theme::text_dim);

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
	widgets::render_footer();

	renderer::draw_window_border();

	ImGui::End();
	ImGui::PopStyleVar(); // page alpha
}
