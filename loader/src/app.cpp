#include "app.h"
#include "backend/loader_backend.h"

#include "pages/system_check.h"
#include "pages/login.h"
#include "pages/dashboard.h"

namespace app
{
	static app_state_t s_state;

	static std::unique_ptr<IPage> s_pages[3];
	static IPage* s_current_page = nullptr;

	void initialize()
	{
		s_pages[0] = std::make_unique<SystemCheckPage>();
		s_pages[1] = std::make_unique<LoginPage>();
		s_pages[2] = std::make_unique<DashboardPage>();

		navigate_to(page_id::system_check);
	}

	void shutdown()
	{
		if (s_current_page)
			s_current_page->on_exit();

		backend::cleanup();
	}

	void render()
	{
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
			s_current_page->on_enter();
	}

	app_state_t& state() { return s_state; }
}
