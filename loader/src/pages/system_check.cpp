#include "system_check.h"
#include "../app.h"
#include "../system_check/system_info.h"
#include "../renderer/renderer.h"

#include <imgui.h>
#include <shellapi.h>

void SystemCheckPage::on_enter()
{
	m_checks_done = false;
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

// draw accent horizontal line
static void draw_accent_line(float x1, float x2, float y, float thickness = 2.0f)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	dl->AddLine(ImVec2(wp.x + x1, wp.y + y), ImVec2(wp.x + x2, wp.y + y), U32_ACCENT, thickness);
}

// draw a filled circle status indicator
static void draw_status_dot(float x, float y, bool passed, float radius = 5.0f)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	ImVec2 center(wp.x + x, wp.y + y);
	ImU32 col = passed ? IM_COL32(76, 242, 115, 255) : IM_COL32(255, 72, 72, 255);
	ImU32 glow = passed ? IM_COL32(76, 242, 115, 40) : IM_COL32(255, 72, 72, 40);
	dl->AddCircleFilled(center, radius + 3, glow);
	dl->AddCircleFilled(center, radius, col);
}

static void draw_check_row(float base_x, const char* label, const system_info::check_result_t& check)
{
	float cy = ImGui::GetCursorPosY();
	// status dot
	draw_status_dot(base_x + 6, cy + 10, check.passed);

	// label
	ImGui::SetCursorPos(ImVec2(base_x + 22, cy));
	ImGui::PushFont(renderer::font_bold());
	ImGui::TextColored(COL_TEXT, "%s", label);
	ImGui::PopFont();

	// detail on the right
	ImGui::SameLine(base_x + 220);
	ImGui::TextColored(COL_DIM, "%s", check.detail.c_str());

	ImGui::SetCursorPosY(cy + 32);
}

void SystemCheckPage::render()
{
	const float W = (float)renderer::WINDOW_WIDTH;
	const float H = (float)renderer::WINDOW_HEIGHT;
	const float TITLE_H = 44.0f;

	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::SetNextWindowSize(ImVec2(W, H));
	ImGui::Begin("##system_check", nullptr,
		ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
		ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
		ImGuiWindowFlags_NoScrollbar);

	// === title bar ===
	float title_font_h = renderer::font_title()->FontSize;
	float title_y = (TITLE_H - title_font_h) * 0.5f;
	float btn_h = 28.0f;
	float btn_y = (TITLE_H - btn_h) * 0.5f;

	ImGui::SetCursorPos(ImVec2(20, title_y));
	ImGui::PushFont(renderer::font_title());
	ImGui::TextColored(COL_ACCENT, "ZEROHOOK");
	ImGui::PopFont();

	ImGui::SetCursorPos(ImVec2(W - 72, btn_y));
	if (ImGui::Button(" _ ##min", ImVec2(30, btn_h)))
		ShowWindow(renderer::get_hwnd(), SW_MINIMIZE);
	ImGui::SameLine(0, 4);
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.8f, 0.15f, 0.15f, 1.0f));
	if (ImGui::Button(" X ##close", ImVec2(30, btn_h)))
		renderer::request_close();
	ImGui::PopStyleColor();

	// accent line under title
	draw_accent_line(0, W, TITLE_H, 2.0f);

	// === content card ===
	float card_w = 520.0f;
	float card_h = 340.0f;
	float card_x = (W - card_w) * 0.5f;
	float card_y = (H - card_h) * 0.5f - 16;

	// card background
	ImGui::SetCursorPos(ImVec2(card_x, card_y));
	ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.065f, 0.065f, 0.09f, 1.0f));
	ImGui::BeginChild("##check_card", ImVec2(card_w, card_h), ImGuiChildFlags_None);

	// accent top edge on card
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		dl->AddRectFilled(wp, ImVec2(wp.x + card_w, wp.y + 2), U32_ACCENT);
		// subtle glow below accent edge
		dl->AddRectFilledMultiColor(
			ImVec2(wp.x, wp.y + 2), ImVec2(wp.x + card_w, wp.y + 12),
			U32_ACCENT50, U32_ACCENT50, IM_COL32(0, 0, 0, 0), IM_COL32(0, 0, 0, 0));
	}

	// title
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
		ImGui::TextColored(COL_ACCENT, "Running checks...");
	}
	else
	{
		auto& checks = app::state().checks;

		ImGui::SetCursorPosY(90);
		draw_check_row(32, "Hyper-V", checks.hyperv);
		draw_check_row(32, "Windows Version", checks.windows);
		draw_check_row(32, "Secure Boot", checks.secure_boot);
		draw_check_row(32, "TPM Module", checks.tpm);

		ImGui::Spacing();

		// warnings
		if (!checks.hyperv.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(COL_RED, "! Hyper-V is required. Enable it in Windows Features.");
		}
		else if (!checks.windows.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(COL_RED, "! Windows 10 Build 19041+ is required.");
		}
		if (!checks.secure_boot.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(COL_YELLOW, "! Secure Boot off. Some features may not work.");
		}
		if (!checks.tpm.passed)
		{
			ImGui::SetCursorPosX(32);
			ImGui::TextColored(COL_YELLOW, "! No TPM detected. HWID spoofer requires TPM.");
		}

		ImGui::Spacing();
		ImGui::Spacing();

		// continue button
		bool can_continue = checks.all_critical_passed();
		if (!can_continue) ImGui::BeginDisabled();

		float btn_w = 200.0f;
		float btn_ht = 36.0f;
		ImGui::SetCursorPosX((card_w - btn_w) * 0.5f);

		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.42f, 0.0f, 1.0f));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.55f, 0.16f, 1.0f));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.8f, 0.33f, 0.0f, 1.0f));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.0f, 0.0f, 1.0f));

		if (ImGui::Button("Continue", ImVec2(btn_w, btn_ht)))
			app::navigate_to(page_id::login);

		ImGui::PopStyleColor(4);

		if (!can_continue) ImGui::EndDisabled();
	}

	ImGui::EndChild();
	ImGui::PopStyleColor();

	// === footer ===
	float footer_y = H - 32;
	float footer_text_y = footer_y + 6;

	ImGui::SetCursorPos(ImVec2(20, footer_text_y));
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
}
