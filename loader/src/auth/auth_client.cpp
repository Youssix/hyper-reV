#include "auth_client.h"
#include "../crypto/crypto.h"
#include "../security/fingerprint.h"
#include "../vendor/skCrypter.h"

// winsock2.h must come before Windows.h (httplib + OpenSSL requirement)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <bcrypt.h>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <fstream>
#include <chrono>

#pragma comment(lib, "bcrypt.lib")

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <nlohmann/json.hpp>

// helper: skCrypt that decays to const char* for nlohmann json compat
#define SK(s) ((const char*)skCrypt(s))

namespace auth
{
	static std::string s_api_url = "https://api.zerohook.gg";
	static std::atomic<bool> s_heartbeat_running{ false };
	static std::atomic<bool> s_session_alive{ true };
	static std::thread s_heartbeat_thread;
	static std::mutex s_heartbeat_mutex;

	// REPORT_SECRET split into two XOR halves for obfuscation
	static const uint8_t REPORT_KEY_A[32] = {
		0x78, 0x68, 0x38, 0xf9, 0x84, 0x1b, 0xf6, 0x6e,
		0x44, 0xe6, 0x24, 0x93, 0xe2, 0x0b, 0x4b, 0xed,
		0x77, 0x7d, 0x8b, 0xcd, 0x8e, 0x75, 0xd2, 0xcc,
		0x75, 0x90, 0xc6, 0xb0, 0xa9, 0x7a, 0xb6, 0xb6,
	};
	static const uint8_t REPORT_KEY_B[32] = { 0 };

	static std::string get_report_secret()
	{
		char hex[65] = {};
		for (int i = 0; i < 32; i++)
			sprintf_s(hex + i * 2, 3, "%02x", REPORT_KEY_A[i] ^ REPORT_KEY_B[i]);
		return std::string(hex);
	}

	void set_api_url(const std::string& base_url)
	{
		s_api_url = base_url;
	}

	// ========== HWID ==========

	std::string get_hwid()
	{
		HKEY hkey;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
			SK("SOFTWARE\\Microsoft\\Cryptography"), 0, KEY_READ, &hkey) != ERROR_SUCCESS)
			return "unknown";

		char guid[256] = {};
		DWORD size = sizeof(guid);
		DWORD type = REG_SZ;
		RegQueryValueExA(hkey, SK("MachineGuid"), nullptr, &type, (LPBYTE)guid, &size);
		RegCloseKey(hkey);

		return crypto::sha256_hex(guid, strlen(guid));
	}

	// ========== Loader Hash ==========

	std::string get_loader_hash()
	{
		char path[MAX_PATH] = {};
		GetModuleFileNameA(nullptr, path, MAX_PATH);

		std::ifstream file(path, std::ios::binary | std::ios::ate);
		if (!file.is_open()) return {};

		auto file_size = file.tellg();
		file.seekg(0, std::ios::beg);

		std::vector<uint8_t> data((size_t)file_size);
		file.read(reinterpret_cast<char*>(data.data()), file_size);

		auto hash = crypto::sha256_hex(data.data(), data.size());
		crypto::secure_zero(data);

		return hash;
	}

	// ========== HTTP helper ==========

	static httplib::Client make_client()
	{
		httplib::Client cli(s_api_url);
		cli.set_connection_timeout(10);
		cli.set_read_timeout(30);
		return cli;
	}

	// ========== Shared login response parser ==========

	static login_result_t parse_login_response(httplib::Result& res)
	{
		login_result_t result;

		if (!res)
		{
			result.error = "Connection failed. Check your internet.";
			return result;
		}

		auto j = nlohmann::json::parse(res->body, nullptr, false);

		if (res->status != 200)
		{
			if (!j.is_discarded())
				result.error = j.value(SK("error"), std::string("Authentication failed"));
			else
				result.error = "Authentication failed";
			return result;
		}

		if (j.is_discarded())
		{
			result.error = "Invalid server response";
			return result;
		}

		result.success = true;
		result.session.username = j.value(SK("username"), std::string("user"));
		result.session.token = j.value(SK("token"), std::string(""));
		result.session.is_reseller = j.value(SK("is_reseller"), false);
		result.session.subscription.plan = j.value(SK("plan"), std::string("Standard"));
		result.session.subscription.expiry = j.value(SK("expiry"), std::string("N/A"));
		result.session.subscription.is_active = j.value(SK("active"), false);

		const char* games_key = SK("games");
		if (j.contains(games_key) && j[games_key].is_array())
		{
			for (auto& g : j[games_key])
			{
				game_info_t game;
				game.id = g.value(SK("id"), std::string(""));
				game.name = g.value(SK("name"), std::string("Unknown"));
				game.process_name = g.value(SK("process"), std::string(""));
				game.version = g.value(SK("version"), std::string("1.0"));
				std::string status_str = g.value(SK("status"), std::string("offline"));
				if (status_str == "online")       game.status = game_status::online;
				else if (status_str == "updating") game.status = game_status::updating;
				else                               game.status = game_status::offline;
				result.session.games.push_back(game);
			}
		}

		result.session.patch_notes = fetch_patch_notes();
		return result;
	}

	// ========== Authentication ==========

	login_result_t login_with_key(const std::string& key)
	{
		auto cli = make_client();

		nlohmann::json body;
		body[SK("key")] = key;
		body[SK("hwid")] = get_hwid();

		auto res = cli.Post(SK("/api/v1/auth/key"),
			body.dump(), SK("application/json"));

		return parse_login_response(res);
	}

	login_result_t login_with_account(const std::string& username, const std::string& password)
	{
		auto cli = make_client();

		nlohmann::json body;
		body[SK("username")] = username;
		body[SK("password")] = password;
		body[SK("hwid")] = get_hwid();

		auto res = cli.Post(SK("/api/v1/auth/login"),
			body.dump(), SK("application/json"));

		return parse_login_response(res);
	}

	bool validate_session(const std::string& token)
	{
		auto cli = make_client();
		cli.set_connection_timeout(5);

		std::string auth_header = std::string(SK("Bearer ")) + token;
		httplib::Headers headers = { {SK("Authorization"), auth_header} };
		auto res = cli.Get(SK("/api/v1/auth/validate"), headers);

		return res && res->status == 200;
	}

	std::string fetch_patch_notes()
	{
		auto cli = make_client();
		cli.set_connection_timeout(5);

		auto res = cli.Get(SK("/api/v1/patch-notes"));
		if (res && res->status == 200)
			return res->body;

		return "Failed to fetch patch notes.";
	}

	// ========== Telemetry ==========

	bool send_telemetry(const std::string& token)
	{
		auto cli = make_client();

		auto fp = fingerprint::collect();

		nlohmann::json body;
		body[SK("token")] = token;
		body[SK("hwid")] = get_hwid();
		body[SK("loader_version")] = SK("3.0.0");
		body[SK("loader_hash")] = get_loader_hash();
		body[SK("timestamp")] = std::to_string(
			std::chrono::duration_cast<std::chrono::seconds>(
				std::chrono::system_clock::now().time_since_epoch()).count());
		body[SK("fingerprint")] = fingerprint::to_json(fp);

		auto res = cli.Post(SK("/api/v1/telemetry"),
			body.dump(), SK("application/json"));

		if (!res) return false;

		return res->status == 200;
	}

	// ========== Loader Verify ==========

	bool verify_loader(const std::string& token)
	{
		auto cli = make_client();

		nlohmann::json body;
		body[SK("token")] = token;
		body[SK("hwid")] = get_hwid();
		body[SK("loader_hash")] = get_loader_hash();

		auto res = cli.Post(SK("/api/v1/verify"),
			body.dump(), SK("application/json"));

		return res && res->status == 200;
	}

	// ========== Download DLL ==========

	download_result_t download_dll(const std::string& token, const std::string& game_id)
	{
		download_result_t result;

		auto cli = make_client();
		cli.set_read_timeout(60);

		nlohmann::json body;
		body[SK("token")] = token;
		body[SK("hwid")] = get_hwid();
		body[SK("game_id")] = game_id;

		auto res = cli.Post(SK("/api/v1/download"),
			body.dump(), SK("application/json"));

		if (!res)
		{
			result.error = "Connection failed";
			return result;
		}

		if (res->status != 200)
		{
			auto j = nlohmann::json::parse(res->body, nullptr, false);
			result.error = j.is_discarded() ? "Download failed"
				: j.value(SK("error"), std::string("Download failed"));
			return result;
		}

		auto j = nlohmann::json::parse(res->body, nullptr, false);
		if (j.is_discarded())
		{
			result.error = "Invalid download response";
			return result;
		}

		// extract encrypted DLL + metadata
		std::string encrypted_b64 = j.value(SK("data"), std::string(""));
		std::string iv_b64 = j.value(SK("iv"), std::string(""));
		std::string key_nonce_b64 = j.value(SK("key_nonce"), std::string(""));
		std::string expected_hash = j.value(SK("hash"), std::string(""));

		if (encrypted_b64.empty() || iv_b64.empty() || key_nonce_b64.empty())
		{
			result.error = "Missing download fields";
			return result;
		}

		// decode
		auto encrypted = crypto::base64_decode(encrypted_b64);
		auto iv = crypto::base64_decode(iv_b64);

		if (iv.size() != 16)
		{
			result.error = "Invalid IV size";
			return result;
		}

		// derive AES key: SHA256(token + hwid + key_nonce_b64)
		std::string key_material = token + get_hwid() + key_nonce_b64;
		auto aes_key = crypto::sha256(key_material.data(), key_material.size());
		crypto::secure_zero(key_material);

		// decrypt
		result.dll_data = crypto::aes256_cbc_decrypt(encrypted, aes_key, iv);
		crypto::secure_zero(aes_key);

		if (result.dll_data.empty())
		{
			result.error = "Decryption failed";
			return result;
		}

		// verify hash
		if (!expected_hash.empty())
		{
			auto actual_hash = crypto::sha256_hex(result.dll_data.data(), result.dll_data.size());
			if (actual_hash != expected_hash)
			{
				crypto::secure_zero(result.dll_data);
				result.error = "DLL hash mismatch";
				return result;
			}
		}

		result.success = true;
		return result;
	}

	// ========== Heartbeat ==========

	bool send_heartbeat(const std::string& token)
	{
		auto cli = make_client();
		cli.set_connection_timeout(5);

		nlohmann::json body;
		body[SK("token")] = token;
		body[SK("hwid")] = get_hwid();

		auto res = cli.Post(SK("/api/v1/heartbeat"),
			body.dump(), SK("application/json"));

		if (!res) return false;

		if (res->status != 200)
		{
			s_session_alive.store(false);
			return false;
		}

		return true;
	}

	// ========== Report ==========

	bool send_report(const std::string& token, const std::string& reason,
		const std::string& details)
	{
		auto cli = make_client();
		cli.set_connection_timeout(5);

		std::string hwid = get_hwid();

		nlohmann::json payload;
		payload[SK("reason")] = reason;
		payload[SK("details")] = details;
		payload[SK("hwid")] = hwid;
		payload[SK("token")] = token;
		payload[SK("timestamp")] = std::to_string(
			std::chrono::duration_cast<std::chrono::seconds>(
				std::chrono::system_clock::now().time_since_epoch()).count());

		std::string payload_str = payload.dump();

		auto nonce = crypto::random_bytes(16);
		std::string nonce_b64 = crypto::base64_encode(nonce);

		std::string secret = get_report_secret();
		std::string key_material = secret + hwid + nonce_b64;
		auto aes_key = crypto::sha256(key_material.data(), key_material.size());
		crypto::secure_zero(key_material);
		crypto::secure_zero(secret);

		auto iv = crypto::random_bytes(16);

		std::vector<uint8_t> plaintext(payload_str.begin(), payload_str.end());
		auto encrypted = crypto::aes256_cbc_encrypt(plaintext, aes_key, iv);
		crypto::secure_zero(aes_key);
		crypto::secure_zero(plaintext);

		if (encrypted.empty())
			return false;

		nlohmann::json body;
		body[SK("data")] = crypto::base64_encode(encrypted);
		body[SK("iv")] = crypto::base64_encode(iv);
		body[SK("nonce")] = nonce_b64;
		body[SK("hwid")] = hwid;

		auto res = cli.Post(SK("/api/v1/report"),
			body.dump(), SK("application/json"));

		return res && res->status == 200;
	}

	// ========== Integrity Heartbeat ==========

	bool send_integrity_heartbeat(const std::string& token,
		uint32_t text_crc, uint32_t rdata_crc,
		const std::string& loader_hash)
	{
		auto cli = make_client();
		cli.set_connection_timeout(5);

		nlohmann::json body;
		body[SK("token")] = token;
		body[SK("hwid")] = get_hwid();
		body[SK("text_crc")] = text_crc;
		body[SK("rdata_crc")] = rdata_crc;
		body[SK("loader_hash")] = loader_hash;
		body[SK("timestamp")] = std::to_string(
			std::chrono::duration_cast<std::chrono::seconds>(
				std::chrono::system_clock::now().time_since_epoch()).count());

		auto res = cli.Post(SK("/api/v1/integrity-check"),
			body.dump(), SK("application/json"));

		if (!res) return false;

		if (res->status != 200)
		{
			s_session_alive.store(false);
			return false;
		}

		return true;
	}

	// ========== Heartbeat thread ==========

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
			int heartbeat_count = 0;

			while (s_heartbeat_running.load())
			{
				int wait_ms = interval * 1000;
				while (wait_ms > 0 && s_heartbeat_running.load())
				{
					Sleep(200);
					wait_ms -= 200;
				}

				if (!s_heartbeat_running.load())
					break;

				bool ok = send_heartbeat(tok);

				// every 3rd heartbeat (~90s), also send integrity data
				heartbeat_count++;
				if (ok && (heartbeat_count % 3) == 0)
				{
					// import these at call time to avoid circular header deps
					uint32_t text_crc = 0, rdata_crc = 0;
					std::string loader_hash;

					// get fresh CRCs via extern declarations
					extern uint32_t integrity_get_text_crc();
					extern uint32_t integrity_get_rdata_crc();
					text_crc = integrity_get_text_crc();
					rdata_crc = integrity_get_rdata_crc();
					loader_hash = get_loader_hash();

					if (!send_integrity_heartbeat(tok, text_crc, rdata_crc, loader_hash))
					{
						s_session_alive.store(false);
						break;
					}
				}

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
