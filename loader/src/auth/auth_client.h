#pragma once
#include "auth_types.h"
#include <string>
#include <vector>

namespace auth
{
	struct login_result_t
	{
		bool success = false;
		std::string error;
		user_session_t session;
	};

	struct download_result_t
	{
		bool success = false;
		std::string error;
		std::vector<uint8_t> dll_data;
	};

	// configure API base URL (call before any API calls)
	void set_api_url(const std::string& base_url);

	// authentication
	login_result_t login_with_key(const std::string& key);
	login_result_t login_with_account(const std::string& username, const std::string& password);

	// session
	bool validate_session(const std::string& token);
	std::string fetch_patch_notes();

	// telemetry (mandatory after auth)
	bool send_telemetry(const std::string& token);

	// loader integrity verify
	bool verify_loader(const std::string& token);

	// download encrypted DLL — returns decrypted bytes in memory, empty on failure
	download_result_t download_dll(const std::string& token, const std::string& game_id);

	// encrypted tampering report
	bool send_report(const std::string& token, const std::string& reason,
		const std::string& details);

	// heartbeat system
	bool send_heartbeat(const std::string& token);
	void start_heartbeat(const std::string& token, int interval_seconds = 30);
	void stop_heartbeat();
	bool is_session_alive(); // false if server revoked or heartbeat failed

	// integrity heartbeat — server compares CRCs against known-good values
	bool send_integrity_heartbeat(const std::string& token,
		uint32_t text_crc, uint32_t rdata_crc,
		const std::string& loader_hash);

	// HWID
	std::string get_hwid();

	// get loader's own SHA-256 hash
	std::string get_loader_hash();
}
