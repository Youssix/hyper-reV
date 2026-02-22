#include "auth_client.h"
#include <Windows.h>
#include <bcrypt.h>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>

#pragma comment(lib, "bcrypt.lib")

// cpp-httplib is available via vcpkg but we keep mock mode for now
// Uncomment when backend server is ready:
// #define ZEROHOOK_USE_REAL_API
// #include <httplib.h>

namespace auth
{
	static std::string s_api_url = "https://api.zerohook.gg";
	static std::atomic<bool> s_heartbeat_running{ false };
	static std::atomic<bool> s_session_alive{ true };
	static std::thread s_heartbeat_thread;
	static std::mutex s_heartbeat_mutex;

	void set_api_url(const std::string& base_url)
	{
		s_api_url = base_url;
	}

	// ========== HWID ==========

	std::string get_hwid()
	{
		HKEY hkey;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
			"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hkey) != ERROR_SUCCESS)
			return "unknown";

		char guid[256] = {};
		DWORD size = sizeof(guid);
		DWORD type = REG_SZ;
		RegQueryValueExA(hkey, "MachineGuid", nullptr, &type, (LPBYTE)guid, &size);
		RegCloseKey(hkey);

		BCRYPT_ALG_HANDLE alg = nullptr;
		BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
		if (!alg) return guid;

		BCRYPT_HASH_HANDLE hash = nullptr;
		BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
		BCryptHashData(hash, (PUCHAR)guid, (ULONG)strlen(guid), 0);

		UCHAR digest[32] = {};
		BCryptFinishHash(hash, digest, sizeof(digest), 0);
		BCryptDestroyHash(hash);
		BCryptCloseAlgorithmProvider(alg, 0);

		char hex[65] = {};
		for (int i = 0; i < 32; i++)
			sprintf_s(hex + i * 2, 3, "%02x", digest[i]);

		return std::string(hex);
	}

	// ========== Real API (when server is ready) ==========

#ifdef ZEROHOOK_USE_REAL_API

	login_result_t login_with_key(const std::string& key)
	{
		login_result_t result;

		httplib::Client cli(s_api_url);
		cli.set_connection_timeout(10);
		cli.set_read_timeout(10);

		nlohmann::json body;
		body["key"] = key;
		body["hwid"] = get_hwid();

		auto res = cli.Post("/api/v1/auth/key",
			body.dump(), "application/json");

		if (!res)
		{
			result.error = "Connection failed. Check your internet.";
			return result;
		}

		if (res->status != 200)
		{
			auto j = nlohmann::json::parse(res->body, nullptr, false);
			result.error = j.value("error", "Authentication failed (HTTP " + std::to_string(res->status) + ")");
			return result;
		}

		auto j = nlohmann::json::parse(res->body, nullptr, false);
		if (j.is_discarded())
		{
			result.error = "Invalid server response";
			return result;
		}

		result.success = true;
		result.session.username = j.value("username", "user");
		result.session.token = j.value("token", "");
		result.session.is_reseller = j.value("is_reseller", false);
		result.session.subscription.plan = j.value("plan", "Standard");
		result.session.subscription.expiry = j.value("expiry", "N/A");
		result.session.subscription.is_active = j.value("active", false);

		if (j.contains("games") && j["games"].is_array())
		{
			for (auto& g : j["games"])
			{
				game_info_t game;
				game.name = g.value("name", "Unknown");
				game.process_name = g.value("process", "");
				game.dll_path = g.value("dll_path", "");
				game.version = g.value("version", "1.0");
				std::string status_str = g.value("status", "offline");
				if (status_str == "online")       game.status = game_status::online;
				else if (status_str == "updating") game.status = game_status::updating;
				else                               game.status = game_status::offline;
				result.session.games.push_back(game);
			}
		}

		result.session.patch_notes = fetch_patch_notes();
		return result;
	}

	login_result_t login_with_account(const std::string& username, const std::string& password)
	{
		login_result_t result;

		httplib::Client cli(s_api_url);
		cli.set_connection_timeout(10);
		cli.set_read_timeout(10);

		nlohmann::json body;
		body["username"] = username;
		body["password"] = password;
		body["hwid"] = get_hwid();

		auto res = cli.Post("/api/v1/auth/login",
			body.dump(), "application/json");

		if (!res)
		{
			result.error = "Connection failed. Check your internet.";
			return result;
		}

		if (res->status != 200)
		{
			auto j = nlohmann::json::parse(res->body, nullptr, false);
			result.error = j.value("error", "Login failed");
			return result;
		}

		// same parsing as login_with_key...
		auto j = nlohmann::json::parse(res->body, nullptr, false);
		result.success = true;
		result.session.username = j.value("username", username);
		result.session.token = j.value("token", "");
		result.session.subscription.plan = j.value("plan", "Standard");
		result.session.subscription.expiry = j.value("expiry", "N/A");
		result.session.subscription.is_active = j.value("active", false);
		result.session.patch_notes = fetch_patch_notes();
		return result;
	}

	bool validate_session(const std::string& token)
	{
		httplib::Client cli(s_api_url);
		cli.set_connection_timeout(5);

		httplib::Headers headers = { {"Authorization", "Bearer " + token} };
		auto res = cli.Get("/api/v1/auth/validate", headers);

		return res && res->status == 200;
	}

	std::string fetch_patch_notes()
	{
		httplib::Client cli(s_api_url);
		cli.set_connection_timeout(5);

		auto res = cli.Get("/api/v1/patch-notes");
		if (res && res->status == 200)
			return res->body;

		return "Failed to fetch patch notes.";
	}

	bool send_heartbeat(const std::string& token)
	{
		httplib::Client cli(s_api_url);
		cli.set_connection_timeout(5);

		nlohmann::json body;
		body["token"] = token;
		body["hwid"] = get_hwid();

		auto res = cli.Post("/api/v1/heartbeat",
			body.dump(), "application/json");

		return res && res->status == 200;
	}

#else
	// ========== Mock implementations ==========

	login_result_t login_with_key(const std::string& key)
	{
		login_result_t result;

		if (key.size() >= 3 && key.substr(0, 3) == "ZH-")
		{
			result.success = true;
			result.session.username = "user_" + key.substr(3, 6);
			result.session.token = "mock_token_" + get_hwid().substr(0, 8);
			result.session.is_reseller = (key.find("RESELLER") != std::string::npos);

			result.session.subscription.plan = result.session.is_reseller ? "Reseller" : "Premium";
			result.session.subscription.expiry = "2026-12-31";
			result.session.subscription.is_active = true;

			result.session.games.push_back({
				"Fortnite", "FortniteClient-Win64-Shipping.exe",
				"C:\\ZeroHook\\fortnite.dll", "3.2.1", game_status::online });
			result.session.games.push_back({
				"Valorant", "VALORANT-Win64-Shipping.exe",
				"C:\\ZeroHook\\valorant.dll", "2.1.0", game_status::updating });
			result.session.games.push_back({
				"Apex Legends", "r5apex.exe",
				"C:\\ZeroHook\\apex.dll", "1.5.0", game_status::offline });

			result.session.patch_notes = fetch_patch_notes();
		}
		else
		{
			result.success = false;
			result.error = "Invalid license key format. Keys start with ZH-";
		}

		return result;
	}

	login_result_t login_with_account(const std::string& username, const std::string& password)
	{
		login_result_t result;

		if (!username.empty() && !password.empty())
		{
			result.success = true;
			result.session.username = username;
			result.session.token = "mock_token_" + get_hwid().substr(0, 8);
			result.session.subscription.plan = "Premium";
			result.session.subscription.expiry = "2026-12-31";
			result.session.subscription.is_active = true;

			result.session.games.push_back({
				"Fortnite", "FortniteClient-Win64-Shipping.exe",
				"C:\\ZeroHook\\fortnite.dll", "3.2.1", game_status::online });
			result.session.games.push_back({
				"Valorant", "VALORANT-Win64-Shipping.exe",
				"C:\\ZeroHook\\valorant.dll", "2.1.0", game_status::updating });
			result.session.games.push_back({
				"Apex Legends", "r5apex.exe",
				"C:\\ZeroHook\\apex.dll", "1.5.0", game_status::offline });

			result.session.patch_notes = fetch_patch_notes();
		}
		else
		{
			result.error = "Invalid credentials";
		}

		return result;
	}

	bool validate_session(const std::string& /*token*/)
	{
		return true;
	}

	std::string fetch_patch_notes()
	{
		return
			"v3.2.1 - February 2026\n"
			"- Added HWID spoofer toggle\n"
			"- Improved EPT hook stability\n"
			"- Fixed crash on certain AMD CPUs\n"
			"\n"
			"v3.2.0 - January 2026\n"
			"- New DLL injection via syscall exit EPT hook\n"
			"- MmAccessFault hidden memory support\n"
			"- CR3 intercept + KPTI UserDTB fix\n"
			"\n"
			"v3.1.0 - December 2025\n"
			"- Initial release with Hyper-V VMEXIT hooks\n"
			"- Full SLAT page table manipulation\n";
	}

	bool send_heartbeat(const std::string& /*token*/)
	{
		return true;
	}

#endif

	// ========== Heartbeat thread (works in both modes) ==========

	void start_heartbeat(const std::string& token, int interval_seconds)
	{
		if (s_heartbeat_running.exchange(true))
			return;

		s_session_alive.store(true);

		std::string tok = token;
		int interval = interval_seconds;

		s_heartbeat_thread = std::thread([tok, interval]()
		{
			int consecutive_failures = 0;
			const int max_failures = 3;

			while (s_heartbeat_running.load())
			{
				// sleep in short bursts so stop_heartbeat() doesn't block
				int wait_ms = interval * 1000;
				while (wait_ms > 0 && s_heartbeat_running.load())
				{
					Sleep(200);
					wait_ms -= 200;
				}

				if (!s_heartbeat_running.load())
					break;

				bool ok = send_heartbeat(tok);
				if (ok)
				{
					consecutive_failures = 0;
				}
				else
				{
					consecutive_failures++;
					if (consecutive_failures >= max_failures)
					{
						s_session_alive.store(false);
						break;
					}
				}
			}
		});
	}

	void stop_heartbeat()
	{
		s_heartbeat_running.store(false);
		if (s_heartbeat_thread.joinable())
			s_heartbeat_thread.join();
	}

	bool is_session_alive()
	{
		return s_session_alive.load();
	}
}
