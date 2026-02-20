#pragma once
#include "auth_types.h"
#include <optional>
#include <string>

namespace auth
{
	struct login_result_t
	{
		bool success = false;
		std::string error;
		user_session_t session;
	};

	login_result_t login_with_key(const std::string& key);

	std::string fetch_patch_notes();

	bool send_heartbeat(const std::string& token);

	std::string get_hwid();
}
