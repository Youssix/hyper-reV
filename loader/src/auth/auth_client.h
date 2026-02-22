#pragma once
#include "auth_types.h"
#include <string>

namespace auth
{
	struct login_result_t
	{
		bool success = false;
		std::string error;
		user_session_t session;
	};

	// configure API base URL (call before any API calls)
	void set_api_url(const std::string& base_url);

	// authentication
	login_result_t login_with_key(const std::string& key);
	login_result_t login_with_account(const std::string& username, const std::string& password);

	// session
	bool validate_session(const std::string& token);
	std::string fetch_patch_notes();

	// heartbeat system
	bool send_heartbeat(const std::string& token);
	void start_heartbeat(const std::string& token, int interval_seconds = 30);
	void stop_heartbeat();
	bool is_session_alive(); // false if server revoked or heartbeat failed

	// HWID
	std::string get_hwid();
}
