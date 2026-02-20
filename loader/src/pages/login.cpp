#include "login.h"
#include "../app.h"
#include "../auth/auth_client.h"
#include "../renderer/renderer.h"

#include <imgui.h>
#include <shellapi.h>
#include <future>

static const ImU32 U32_ACCENT   = IM_COL32(255, 107, 0, 255);
static const ImU32 U32_ACCENT50 = IM_COL32(255, 107, 0, 50);
static const ImVec4 COL_ACCENT  = ImVec4(1.0f, 0.42f, 0.0f, 1.0f);
static const ImVec4 COL_DIM     = ImVec4(0.48f, 0.48f, 0.55f, 1.0f);
static const ImVec4 COL_RED     = ImVec4(1.0f, 0.28f, 0.28f, 1.0f);
static const ImVec4 COL_TEXT    = ImVec4(0.92f, 0.92f, 0.95f, 1.0f);

static void draw_accent_line(float x1, float x2, float y, float thickness = 2.0f)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	dl->AddLine(ImVec2(wp.x + x1, wp.y + y), ImVec2(wp.x + x2, wp.y + y), U32_ACCENT, thickness);
}

void LoginPage::on_enter()
{
	memset(m_key_buf, 0, sizeof(m_key_buf));
	memset(m_username_buf, 0, sizeof(m_username_buf));
	memset(m_password_buf, 0, sizeof(m_password_buf));
	m_error.clear();
	m_logging_in = false;
	m_tab = 0;
}

void LoginPage::on_exit() {}

void LoginPage::render()
{
	auto& state = app::state();
	const float W = (float)renderer::WINDOW_WIDTH;
	const float H = (float)renderer::WINDOW_HEIGHT;
	const float TITLE_H = 44.0f;

	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::SetNextWindowSize(ImVec2(W, H));
	ImGui::Begin("##login", nullptr,
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

	draw_accent_line(0, W, TITLE_H, 2.0f);

	// === login card ===
	float card_w = 420.0f;
	float card_h = m_tab == 0 ? 300.0f : 360.0f;
	float card_x = (W - card_w) * 0.5f;
	float card_y = (H - card_h) * 0.5f - 10;

	ImGui::SetCursorPos(ImVec2(card_x, card_y));
	ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.065f, 0.065f, 0.09f, 1.0f));
	ImGui::BeginChild("##login_card", ImVec2(card_w, card_h), ImGuiChildFlags_None);

	// accent top edge
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		dl->AddRectFilled(wp, ImVec2(wp.x + card_w, wp.y + 2), U32_ACCENT);
		dl->AddRectFilledMultiColor(
			ImVec2(wp.x, wp.y + 2), ImVec2(wp.x + card_w, wp.y + 12),
			U32_ACCENT50, U32_ACCENT50, IM_COL32(0, 0, 0, 0), IM_COL32(0, 0, 0, 0));
	}

	// title
	ImGui::SetCursorPos(ImVec2(32, 22));
	ImGui::PushFont(renderer::font_title());
	ImGui::TextColored(COL_TEXT, "Login");
	ImGui::PopFont();

	ImGui::SetCursorPos(ImVec2(32, 50));
	ImGui::TextColored(COL_DIM, "Authenticate to access the dashboard");

	// === tab bar (underline style) ===
	float tab_y = 82;
	float tab_w = (card_w - 64) * 0.5f;

	ImGui::SetCursorPos(ImVec2(32, tab_y));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);

	// tab 0: license key
	{
		bool active = (m_tab == 0);
		ImGui::PushStyleColor(ImGuiCol_Button, active ? ImVec4(1.0f, 0.42f, 0.0f, 0.15f) : ImVec4(0.08f, 0.08f, 0.12f, 1.0f));
		ImGui::PushStyleColor(ImGuiCol_Text, active ? COL_ACCENT : COL_DIM);
		if (ImGui::Button("License Key", ImVec2(tab_w, 30)))
			m_tab = 0;
		ImGui::PopStyleColor(2);

		// underline for active tab
		if (active)
		{
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 wp = ImGui::GetWindowPos();
			dl->AddRectFilled(
				ImVec2(wp.x + 32, wp.y + tab_y + 30),
				ImVec2(wp.x + 32 + tab_w, wp.y + tab_y + 32),
				U32_ACCENT);
		}
	}

	ImGui::SameLine(0, 0);

	// tab 1: account
	{
		bool active = (m_tab == 1);
		ImGui::PushStyleColor(ImGuiCol_Button, active ? ImVec4(1.0f, 0.42f, 0.0f, 0.15f) : ImVec4(0.08f, 0.08f, 0.12f, 1.0f));
		ImGui::PushStyleColor(ImGuiCol_Text, active ? COL_ACCENT : COL_DIM);
		if (ImGui::Button("Account", ImVec2(tab_w, 30)))
			m_tab = 1;
		ImGui::PopStyleColor(2);

		if (active)
		{
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 wp = ImGui::GetWindowPos();
			float x0 = 32 + tab_w;
			dl->AddRectFilled(
				ImVec2(wp.x + x0, wp.y + tab_y + 30),
				ImVec2(wp.x + x0 + tab_w, wp.y + tab_y + 32),
				U32_ACCENT);
		}
	}

	ImGui::PopStyleVar();

	ImGui::SetCursorPosY(tab_y + 44);
	float field_w = card_w - 64;
	bool enter_pressed = false;

	// input field styling
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.06f, 0.06f, 0.10f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.08f, 0.08f, 0.14f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0.08f, 0.08f, 0.14f, 1.0f));

	if (m_tab == 0)
	{
		ImGui::SetCursorPosX(32);
		ImGui::TextColored(COL_DIM, "License Key");
		ImGui::SetCursorPosX(32);
		ImGui::PushItemWidth(field_w);
		enter_pressed = ImGui::InputText("##key", m_key_buf, sizeof(m_key_buf),
			ImGuiInputTextFlags_EnterReturnsTrue);
		ImGui::PopItemWidth();
	}
	else
	{
		ImGui::SetCursorPosX(32);
		ImGui::TextColored(COL_DIM, "Username");
		ImGui::SetCursorPosX(32);
		ImGui::PushItemWidth(field_w);
		ImGui::InputText("##user", m_username_buf, sizeof(m_username_buf));
		ImGui::PopItemWidth();

		ImGui::Spacing();
		ImGui::SetCursorPosX(32);
		ImGui::TextColored(COL_DIM, "Password");
		ImGui::SetCursorPosX(32);
		ImGui::PushItemWidth(field_w);
		enter_pressed = ImGui::InputText("##pass", m_password_buf, sizeof(m_password_buf),
			ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
		ImGui::PopItemWidth();
	}

	ImGui::PopStyleColor(3);

	ImGui::Spacing();
	ImGui::Spacing();

	// check async result
	if (m_logging_in && m_login_future.valid() &&
		m_login_future.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready)
	{
		m_logging_in = false;
		if (state.authenticated)
		{
			app::navigate_to(page_id::dashboard);
			ImGui::EndChild();
			ImGui::PopStyleColor();
			ImGui::End();
			return;
		}
	}

	if (m_logging_in)
		ImGui::BeginDisabled();

	// login button
	float login_btn_w = 180.0f;
	float login_btn_h = 36.0f;
	ImGui::SetCursorPosX((card_w - login_btn_w) * 0.5f);

	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.42f, 0.0f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.55f, 0.16f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.8f, 0.33f, 0.0f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.0f, 0.0f, 1.0f));

	if ((ImGui::Button("Login", ImVec2(login_btn_w, login_btn_h)) || enter_pressed) && !m_logging_in)
	{
		std::string key;
		if (m_tab == 0)
			key = m_key_buf;
		else
			key = std::string(m_username_buf) + ":" + std::string(m_password_buf);

		if (key.empty() || (m_tab == 1 && (strlen(m_username_buf) == 0 || strlen(m_password_buf) == 0)))
		{
			m_error = m_tab == 0 ? "Please enter a license key" : "Please fill in all fields";
		}
		else
		{
			m_logging_in = true;
			m_error.clear();

			m_login_future = std::async(std::launch::async, [this, key]()
			{
				auto result = auth::login_with_key(key);
				auto& s = app::state();

				if (result.success)
				{
					s.session = result.session;
					s.authenticated = true;
				}
				else
				{
					m_error = result.error;
					s.authenticated = false;
				}
			});
		}
	}

	ImGui::PopStyleColor(4);

	if (m_logging_in)
	{
		ImGui::EndDisabled();
		ImGui::Spacing();
		ImGui::SetCursorPosX((card_w - ImGui::CalcTextSize("Authenticating...").x) * 0.5f);
		ImGui::TextColored(COL_ACCENT, "Authenticating...");
	}

	if (!m_error.empty())
	{
		ImGui::Spacing();
		ImGui::SetCursorPosX(32);
		ImGui::PushTextWrapPos(card_w - 32);
		ImGui::TextColored(COL_RED, "%s", m_error.c_str());
		ImGui::PopTextWrapPos();
	}

	ImGui::EndChild();
	ImGui::PopStyleColor();

	// === footer ===
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
}
