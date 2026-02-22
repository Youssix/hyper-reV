#include "login.h"
#include "../app.h"
#include "../auth/auth_client.h"
#include "../renderer/renderer.h"
#include "../renderer/anim.h"

#include <imgui.h>
#include <shellapi.h>
#include <future>
#include <algorithm>

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
	m_error.clear();
	m_logging_in = false;
	m_show_key_dropdown = false;
	m_key_to_remove = -1;

	// load saved credentials
	if (!m_loaded_creds)
	{
		m_saved = credential_store::load();
		m_loaded_creds = true;
	}

	m_tab = m_saved.last_tab;

	// pre-fill from saved credentials
	memset(m_key_buf, 0, sizeof(m_key_buf));
	memset(m_username_buf, 0, sizeof(m_username_buf));
	memset(m_password_buf, 0, sizeof(m_password_buf));

	if (!m_saved.keys.empty() && m_saved.last_key_index < (int)m_saved.keys.size())
	{
		strncpy_s(m_key_buf, m_saved.keys[m_saved.last_key_index].c_str(), sizeof(m_key_buf) - 1);
	}

	if (!m_saved.username.empty())
		strncpy_s(m_username_buf, m_saved.username.c_str(), sizeof(m_username_buf) - 1);
	if (!m_saved.password.empty())
		strncpy_s(m_password_buf, m_saved.password.c_str(), sizeof(m_password_buf) - 1);

	// auto-login on first enter if credentials are saved
	if (!m_auto_login_tried && m_saved.auto_login)
	{
		m_auto_login_tried = true;
		bool has_key_creds = (m_tab == 0 && !m_saved.keys.empty());
		bool has_account_creds = (m_tab == 1 && !m_saved.username.empty() && !m_saved.password.empty());
		if (has_key_creds || has_account_creds)
			do_login();
	}
}

void LoginPage::on_exit() {}

void LoginPage::do_login()
{
	if (m_logging_in) return;

	if (m_tab == 0)
	{
		std::string key = m_key_buf;
		if (key.empty())
		{
			m_error = "Please enter a license key";
			return;
		}

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

				// save key to history
				credential_store::add_key(m_saved, key);
				m_saved.last_tab = 0;
				credential_store::save(m_saved);
			}
			else
			{
				m_error = result.error;
				s.authenticated = false;
			}
		});
	}
	else
	{
		std::string user = m_username_buf;
		std::string pass = m_password_buf;

		if (user.empty() || pass.empty())
		{
			m_error = "Please fill in all fields";
			return;
		}

		m_logging_in = true;
		m_error.clear();

		m_login_future = std::async(std::launch::async, [this, user, pass]()
		{
			auto result = auth::login_with_account(user, pass);
			auto& s = app::state();

			if (result.success)
			{
				s.session = result.session;
				s.authenticated = true;

				// save account credentials
				m_saved.last_tab = 1;
				m_saved.username = user;
				m_saved.password = pass;
				credential_store::save(m_saved);
			}
			else
			{
				m_error = result.error;
				s.authenticated = false;
			}
		});
	}
}

void LoginPage::render()
{
	auto& state = app::state();
	const float W = (float)renderer::WINDOW_WIDTH;
	const float H = (float)renderer::WINDOW_HEIGHT;
	const float TITLE_H = 44.0f;
	float page_alpha = anim::fade_in(m_enter_time, 0.3f);

	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::SetNextWindowSize(ImVec2(W, H));
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, page_alpha);
	ImGui::Begin("##login", nullptr,
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

	// === handle deferred key removal ===
	if (m_key_to_remove >= 0)
	{
		credential_store::remove_key(m_saved, m_key_to_remove);
		credential_store::save(m_saved);
		if (!m_saved.keys.empty() && m_saved.last_key_index < (int)m_saved.keys.size())
			strncpy_s(m_key_buf, m_saved.keys[m_saved.last_key_index].c_str(), sizeof(m_key_buf) - 1);
		else
			memset(m_key_buf, 0, sizeof(m_key_buf));
		m_key_to_remove = -1;
	}

	// === login card with slide-up + fade ===
	float card_w = 420.0f;
	float card_h = m_tab == 0 ? 340.0f : 390.0f;
	float card_x = (W - card_w) * 0.5f;
	float card_base_y = (H - card_h) * 0.5f - 10;
	float card_slide = anim::slide_in(m_enter_time, 30.0f, 0.4f);
	float card_y = card_base_y + card_slide;

	ImGui::SetCursorPos(ImVec2(card_x, card_y));
	ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.065f, 0.065f, 0.09f, 1.0f));
	ImGui::BeginChild("##login_card", ImVec2(card_w, card_h), ImGuiChildFlags_None);

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

	// title with staggered fade
	float content_alpha = anim::stagger(m_enter_time + 0.2f, 0, 0.12f, 0.4f);
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, content_alpha);

	ImGui::SetCursorPos(ImVec2(32, 22));
	ImGui::PushFont(renderer::font_title());
	ImGui::TextColored(COL_TEXT, "Login");
	ImGui::PopFont();

	ImGui::SetCursorPos(ImVec2(32, 50));
	ImGui::TextColored(COL_DIM, "Authenticate to access the dashboard");
	ImGui::PopStyleVar();

	// === tab bar with stagger ===
	float tab_alpha = anim::stagger(m_enter_time + 0.2f, 1, 0.12f, 0.4f);
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, tab_alpha);

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
		{
			m_tab = 0;
			m_error.clear();
		}
		ImGui::PopStyleColor(2);

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
		{
			m_tab = 1;
			m_error.clear();
		}
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

	ImGui::PopStyleVar(); // FrameRounding
	ImGui::PopStyleVar(); // tab alpha

	// === form fields with stagger ===
	float form_alpha = anim::stagger(m_enter_time + 0.2f, 2, 0.12f, 0.4f);
	float form_slide = anim::slide_stagger(m_enter_time + 0.2f, 2, 10.0f, 0.12f, 0.4f);
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, form_alpha);

	ImGui::SetCursorPosY(tab_y + 44 + form_slide);
	float field_w = card_w - 64;
	bool enter_pressed = false;

	// input field styling
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.06f, 0.06f, 0.10f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.08f, 0.08f, 0.14f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0.08f, 0.08f, 0.14f, 1.0f));

	if (m_tab == 0)
	{
		// === License Key tab ===
		ImGui::SetCursorPosX(32);
		ImGui::TextColored(COL_DIM, "License Key");

		float dropdown_btn_w = 28.0f;
		float input_w = field_w - dropdown_btn_w - 4;

		ImGui::SetCursorPosX(32);
		ImGui::PushItemWidth(input_w);
		enter_pressed = ImGui::InputText("##key", m_key_buf, sizeof(m_key_buf),
			ImGuiInputTextFlags_EnterReturnsTrue);
		ImGui::PopItemWidth();

		if (!m_saved.keys.empty())
		{
			ImGui::SameLine(0, 4);
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.08f, 0.08f, 0.14f, 1.0f));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.12f, 0.12f, 0.20f, 1.0f));
			if (ImGui::Button("v##dropdown", ImVec2(dropdown_btn_w, 0)))
				m_show_key_dropdown = !m_show_key_dropdown;
			ImGui::PopStyleColor(2);
		}

		// key dropdown list
		if (m_show_key_dropdown && !m_saved.keys.empty())
		{
			ImGui::SetCursorPosX(32);
			ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.05f, 0.05f, 0.08f, 1.0f));
			float dropdown_h = (float)m_saved.keys.size() * 28.0f + 4.0f;
			if (dropdown_h > 120.0f) dropdown_h = 120.0f;
			ImGui::BeginChild("##key_dropdown", ImVec2(field_w, dropdown_h), ImGuiChildFlags_Borders);

			for (int i = 0; i < (int)m_saved.keys.size(); i++)
			{
				ImGui::PushID(i);

				bool is_selected = (i == m_saved.last_key_index);
				float item_w = field_w - 36;

				if (is_selected)
					ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(1.0f, 0.42f, 0.0f, 0.15f));

				if (ImGui::Selectable(m_saved.keys[i].c_str(), is_selected, 0, ImVec2(item_w, 22)))
				{
					m_saved.last_key_index = i;
					strncpy_s(m_key_buf, m_saved.keys[i].c_str(), sizeof(m_key_buf) - 1);
					credential_store::save(m_saved);
					m_show_key_dropdown = false;
				}

				if (is_selected)
					ImGui::PopStyleColor();

				// X remove button
				ImGui::SameLine(field_w - 30);
				ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
				ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.8f, 0.15f, 0.15f, 0.5f));
				ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.3f, 0.3f, 1.0f));
				if (ImGui::Button("x##rm", ImVec2(20, 22)))
					m_key_to_remove = i;
				ImGui::PopStyleColor(3);

				ImGui::PopID();
			}

			ImGui::EndChild();
			ImGui::PopStyleColor();
		}
	}
	else
	{
		// === Account tab ===
		bool has_saved_account = !m_saved.username.empty();

		ImGui::SetCursorPosX(32);
		ImGui::TextColored(COL_DIM, "Username");
		if (has_saved_account)
		{
			ImGui::SameLine(0, 8);
			ImGui::TextColored(ImVec4(0.3f, 0.75f, 0.4f, 0.7f), "(saved)");
		}
		ImGui::SetCursorPosX(32);
		ImGui::PushItemWidth(field_w);
		ImGui::InputText("##user", m_username_buf, sizeof(m_username_buf));
		ImGui::PopItemWidth();

		ImGui::Spacing();
		ImGui::SetCursorPosX(32);
		ImGui::TextColored(COL_DIM, "Password");
		if (has_saved_account)
		{
			ImGui::SameLine(0, 8);
			ImGui::TextColored(ImVec4(0.3f, 0.75f, 0.4f, 0.7f), "(saved)");
		}
		ImGui::SetCursorPosX(32);
		ImGui::PushItemWidth(field_w);
		enter_pressed = ImGui::InputText("##pass", m_password_buf, sizeof(m_password_buf),
			ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
		ImGui::PopItemWidth();
	}

	ImGui::PopStyleColor(3); // frame bg colors

	ImGui::Spacing();

	// "Remember me" checkbox
	ImGui::SetCursorPosX(32);
	if (ImGui::Checkbox("Remember me", &m_saved.auto_login))
		credential_store::save(m_saved);

	if (m_saved.auto_login)
	{
		ImGui::SameLine(0, 12);
		ImGui::TextColored(ImVec4(0.38f, 0.38f, 0.45f, 1.0f), "(auto-login on next launch)");
	}

	ImGui::PopStyleVar(); // form alpha

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
			ImGui::PopStyleVar(); // page alpha
			return;
		}
	}

	if (m_logging_in)
		ImGui::BeginDisabled();

	// login button with delayed fade
	float btn_alpha = anim::fade_in(m_enter_time + 0.8f, 0.4f);
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, btn_alpha);

	float login_btn_w = 180.0f;
	float login_btn_h = 36.0f;
	ImGui::SetCursorPosX((card_w - login_btn_w) * 0.5f);

	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.42f, 0.0f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.55f, 0.16f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.8f, 0.33f, 0.0f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.0f, 0.0f, 1.0f));

	if ((ImGui::Button("Login", ImVec2(login_btn_w, login_btn_h)) || enter_pressed) && !m_logging_in)
		do_login();

	ImGui::PopStyleColor(4);
	ImGui::PopStyleVar(); // btn alpha

	if (m_logging_in)
	{
		ImGui::EndDisabled();
		ImGui::Spacing();
		// animated dots for loading
		int dots = ((int)(anim::time() * 3.0f)) % 4;
		const char* dot_str[] = { "", ".", "..", "..." };
		char auth_text[32];
		snprintf(auth_text, sizeof(auth_text), "Authenticating%s", dot_str[dots]);
		float auth_w = ImGui::CalcTextSize(auth_text).x;
		ImGui::SetCursorPosX((card_w - auth_w) * 0.5f);
		ImGui::TextColored(COL_ACCENT, "%s", auth_text);
	}

	if (!m_error.empty())
	{
		ImGui::Spacing();
		// error fade in
		float err_alpha = anim::fade_in(m_enter_time + 0.5f, 0.3f);
		ImGui::PushStyleVar(ImGuiStyleVar_Alpha, err_alpha);
		ImGui::SetCursorPosX(32);
		ImGui::PushTextWrapPos(card_w - 32);
		ImGui::TextColored(COL_RED, "%s", m_error.c_str());
		ImGui::PopTextWrapPos();
		ImGui::PopStyleVar();
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
	ImGui::PopStyleVar(); // page alpha
}
