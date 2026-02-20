#include "auth_client.h"
#include <Windows.h>
#include <bcrypt.h>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace auth
{
	// HWID: hash MachineGuid from registry with SHA-256
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

		// SHA-256 hash via BCrypt
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

		// hex encode
		char hex[65] = {};
		for (int i = 0; i < 32; i++)
			sprintf_s(hex + i * 2, 3, "%02x", digest[i]);

		return std::string(hex);
	}

	// ========== Mock implementations (swap to real API later) ==========

	login_result_t login_with_key(const std::string& key)
	{
		login_result_t result;

		// mock: accept any key that starts with "ZH-"
		if (key.size() >= 3 && key.substr(0, 3) == "ZH-")
		{
			result.success = true;
			result.session.username = "user_" + key.substr(3, 6);
			result.session.token = "mock_token_" + get_hwid().substr(0, 8);
			result.session.is_reseller = (key.find("RESELLER") != std::string::npos);

			result.session.subscription.plan = result.session.is_reseller ? "Reseller" : "Premium";
			result.session.subscription.expiry = "2026-12-31";
			result.session.subscription.is_active = true;

			// mock game list
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

	std::string fetch_patch_notes()
	{
		// mock patch notes
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
		// mock: always succeed
		return true;
	}
}
