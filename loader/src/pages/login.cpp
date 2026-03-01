#include "login.h"
#include "../app.h"
#include "../auth/auth_client.h"
#include "../security/integrity.h"
#include "../renderer/renderer.h"
#include "../renderer/anim.h"
#include "../renderer/theme.h"
#include "../renderer/widgets.h"
#include "../vendor/IconsFontAwesome6.h"

#include <imgui.h>
#include <shellapi.h>
#include <future>
#include <algorithm>

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

	// pre-auth integrity gate: verify binary not tampered before sending credentials
	if (!integrity::verify_all())
	{
		auth::send_report("", "pre_auth_tamper", "Integrity check failed before auth");
		TerminateProcess(GetCurrentProcess(), 1);
	}

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
				// post-auth: telemetry
				if (!auth::send_telemetry(result.session.token))
				{
					m_error = "Account is blacklisted or telemetry failed";
					s.authenticated = false;
					return;
				}

				// post-auth: verify loader integrity
				if (!auth::verify_loader(result.session.token))
				{
					m_error = "Loader integrity check failed. Please re-download.";
					s.authenticated = false;
					return;
				}

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
				// post-auth: telemetry
				if (!auth::send_telemetry(result.session.token))
				{
					m_error = "Account is blacklisted or telemetry failed";
					s.authenticated = false;
					return;
				}

				// post-auth: verify loader integrity
				if (!auth::verify_loader(result.session.token))
				{
					m_error = "Loader integrity check failed. Please re-download.";
					s.authenticated = false;
					return;
				}

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
	const float TITLE_H = renderer::TITLE_BAR_HEIGHT;
	float page_alpha = anim::fade_in(m_enter_time, 0.3f);

	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::SetNextWindowSize(ImVec2(W, H));
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, page_alpha);
	ImGui::Begin("##login", nullptr,
		ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
		ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
		ImGuiWindowFlags_NoScrollbar);

	// === title bar ===
	widgets::render_title_bar(m_enter_time);

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
	float card_h = m_tab == 0 ? 340.0f : 420.0f;
	float card_x = (W - card_w) * 0.5f;
	float card_base_y = (H - card_h) * 0.5f - 10;
	float card_slide = anim::slide_in(m_enter_time, 30.0f, 0.4f);
	float card_y = card_base_y + card_slide;

	ImGui::SetCursorPos(ImVec2(card_x, card_y));
	ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::card_bg);
	ImGui::BeginChild("##login_card", ImVec2(card_w, card_h), ImGuiChildFlags_None);

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

	// title with staggered fade
	float content_alpha = anim::stagger(m_enter_time + 0.2f, 0, 0.12f, 0.4f);
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, content_alpha);

	ImGui::SetCursorPos(ImVec2(32, 22));
	ImGui::PushFont(renderer::font_title());
	ImGui::TextColored(theme::text_primary, "Login");
	ImGui::PopFont();

	ImGui::SetCursorPos(ImVec2(32, 50));
	ImGui::TextColored(theme::text_dim, "Authenticate to access the dashboard");
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
		ImGui::PushStyleColor(ImGuiCol_Text, active ? theme::accent : theme::text_dim);
		if (ImGui::Button(ICON_FA_KEY " License Key", ImVec2(tab_w, 30)))
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
				theme::accent_u32);
		}
	}

	ImGui::SameLine(0, 0);

	// tab 1: account
	{
		bool active = (m_tab == 1);
		ImGui::PushStyleColor(ImGuiCol_Button, active ? ImVec4(1.0f, 0.42f, 0.0f, 0.15f) : ImVec4(0.08f, 0.08f, 0.12f, 1.0f));
		ImGui::PushStyleColor(ImGuiCol_Text, active ? theme::accent : theme::text_dim);
		if (ImGui::Button(ICON_FA_USER " Account", ImVec2(tab_w, 30)))
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
				theme::accent_u32);
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

	if (m_tab == 0)
	{
		// === License Key tab ===
		ImGui::SetCursorPosX(32);
		ImGui::TextColored(theme::text_dim, "License Key");

		float dropdown_btn_w = m_saved.keys.empty() ? 0.0f : 28.0f;
		float input_w = field_w - dropdown_btn_w - (dropdown_btn_w > 0 ? 4.0f : 0.0f);

		ImGui::SetCursorPosX(32);
		enter_pressed = widgets::icon_input(ICON_FA_KEY, "##key", m_key_buf, sizeof(m_key_buf),
			input_w, ImGuiInputTextFlags_EnterReturnsTrue);

		if (!m_saved.keys.empty())
		{
			ImGui::SameLine(0, 4);
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.08f, 0.08f, 0.14f, 1.0f));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.12f, 0.12f, 0.20f, 1.0f));
			if (ImGui::Button(ICON_FA_CHEVRON_DOWN "##dropdown", ImVec2(dropdown_btn_w, 0)))
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
				if (ImGui::Button(ICON_FA_XMARK "##rm", ImVec2(20, 22)))
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
		ImGui::TextColored(theme::text_dim, "Username");
		if (has_saved_account)
		{
			ImGui::SameLine(0, 8);
			ImGui::TextColored(ImVec4(0.3f, 0.75f, 0.4f, 0.7f), "(saved)");
		}
		ImGui::SetCursorPosX(32);
		widgets::icon_input(ICON_FA_USER, "##user", m_username_buf, sizeof(m_username_buf), field_w);

		ImGui::Spacing();
		ImGui::SetCursorPosX(32);
		ImGui::TextColored(theme::text_dim, "Password");
		if (has_saved_account)
		{
			ImGui::SameLine(0, 8);
			ImGui::TextColored(ImVec4(0.3f, 0.75f, 0.4f, 0.7f), "(saved)");
		}
		ImGui::SetCursorPosX(32);
		enter_pressed = widgets::password_input("##pass", m_password_buf, sizeof(m_password_buf),
			field_w, &m_show_password);

		// Forgot Password / Create Account links
		ImGui::SetCursorPosX(32);
		widgets::link_button("Forgot Password?", theme::link_color, "https://zerohook.gg/forgot-password");
		ImGui::SameLine(0, 16);
		widgets::link_button("Create Account", theme::link_color, "https://zerohook.gg/register");
	}

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
	ImGui::SetCursorPosX((card_w - login_btn_w) * 0.5f);

	if ((widgets::accent_button(ICON_FA_ARROW_RIGHT " Login", ImVec2(login_btn_w, 36)) || enter_pressed) && !m_logging_in)
		do_login();

	ImGui::PopStyleVar(); // btn alpha

	if (m_logging_in)
	{
		ImGui::EndDisabled();
		ImGui::Spacing();
		float spinner_w = 8.0f * 2 + 8 + ImGui::CalcTextSize("Authenticating").x;
		ImGui::SetCursorPosX((card_w - spinner_w) * 0.5f);
		widgets::spinner("Authenticating");
	}

	if (!m_error.empty())
	{
		ImGui::Spacing();
		// error fade in
		float err_alpha = anim::fade_in(m_enter_time + 0.5f, 0.3f);
		ImGui::PushStyleVar(ImGuiStyleVar_Alpha, err_alpha);
		ImGui::SetCursorPosX(32);
		ImGui::PushTextWrapPos(card_w - 32);
		ImGui::TextColored(theme::red, "%s", m_error.c_str());
		ImGui::PopTextWrapPos();
		ImGui::PopStyleVar();
	}

	ImGui::EndChild();
	ImGui::PopStyleColor();

	// === footer ===
	widgets::render_footer();

	renderer::draw_window_border();

	ImGui::End();
	ImGui::PopStyleVar(); // page alpha
}
