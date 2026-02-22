#include "app.h"
#include "backend/loader_backend.h"
#include "security/anti_debug.h"
#include "security/integrity.h"
#include "auth/auth_client.h"

#include "pages/system_check.h"
#include "pages/login.h"
#include "pages/dashboard.h"
#include "renderer/anim.h"

namespace app
{
	static app_state_t s_state;
	static bool s_logout_pending = false;

	static std::unique_ptr<IPage> s_pages[3];
	static IPage* s_current_page = nullptr;

	void initialize()
	{
		// security: hide main thread from debugger
		anti_debug::hide_thread();

		// security: capture binary integrity baseline
		integrity::capture_baseline();

		// security: start background monitors
		anti_debug::start_monitor();
		integrity::start_monitor();

		// create pages
		s_pages[0] = std::make_unique<SystemCheckPage>();
		s_pages[1] = std::make_unique<LoginPage>();
		s_pages[2] = std::make_unique<DashboardPage>();

		navigate_to(page_id::system_check);
	}

	void shutdown()
	{
		if (s_current_page)
			s_current_page->on_exit();

		// stop heartbeat
		auth::stop_heartbeat();

		// stop security monitors
		anti_debug::stop_monitor();
		integrity::stop_monitor();

		backend::cleanup();
	}

	void render()
	{
		// handle deferred logout (must happen before render, not during)
		if (s_logout_pending)
		{
			s_logout_pending = false;
			auth::stop_heartbeat();
			s_state.authenticated = false;
			s_state.session = {};
			s_state.selected_game = 0;
			s_state.spoofer_enabled = false;
			navigate_to(page_id::login);
			return;
		}

		// check if session was revoked by server
		if (s_state.authenticated && !auth::is_session_alive())
		{
			s_state.authenticated = false;
			s_state.session = {};
			navigate_to(page_id::login);
			return;
		}

		if (s_current_page)
			s_current_page->render();
	}

	void navigate_to(page_id page)
	{
		if (s_current_page)
			s_current_page->on_exit();

		s_state.current_page = page;

		IPage* target = nullptr;
		switch (page)
		{
		case page_id::system_check: target = s_pages[0].get(); break;
		case page_id::login:        target = s_pages[1].get(); break;
		case page_id::dashboard:    target = s_pages[2].get(); break;
		}

		s_current_page = target;

		if (s_current_page)
		{
			s_current_page->m_enter_time = anim::time();
			s_current_page->on_enter();
		}

		// start heartbeat when entering dashboard
		if (page == page_id::dashboard && s_state.authenticated)
			auth::start_heartbeat(s_state.session.token, 30);
	}

	void logout()
	{
		// defer to next frame — can't navigate while ImGui is mid-render
		s_logout_pending = true;
	}

	app_state_t& state() { return s_state; }
}
