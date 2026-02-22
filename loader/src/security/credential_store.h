#pragma once
#include <string>
#include <vector>

namespace credential_store
{
	struct saved_credentials_t
	{
		int last_tab = 0;                    // 0 = key, 1 = account
		std::vector<std::string> keys;       // saved license keys
		int last_key_index = 0;              // last selected key index
		std::string username;                // saved account username
		std::string password;                // saved account password (DPAPI encrypted on disk)
		bool auto_login = true;              // try auto-login on startup
	};

	// load/save credentials from %APPDATA%\ZeroHook\credentials.dat
	saved_credentials_t load();
	void save(const saved_credentials_t& creds);

	// helpers
	void add_key(saved_credentials_t& creds, const std::string& key);
	void remove_key(saved_credentials_t& creds, int index);
}
