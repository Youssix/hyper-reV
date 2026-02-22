#pragma once
#include "pages/page.h"
#include "system_check/system_info.h"
#include "auth/auth_types.h"

#include <memory>
#include <unordered_map>

namespace app
{
	struct app_state_t
	{
		page_id current_page = page_id::system_check;
		system_info::system_checks_t checks = {};

		// auth
		user_session_t session = {};
		bool authenticated = false;

		// dashboard
		int selected_game = 0;
		bool spoofer_enabled = false;
	};

	void initialize();
	void shutdown();
	void render();

	void navigate_to(page_id page);
	void logout();
	app_state_t& state();
}
