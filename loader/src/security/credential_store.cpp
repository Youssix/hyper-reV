#include "credential_store.h"
#include <Windows.h>
#include <wincrypt.h>
#include <ShlObj.h>
#include <fstream>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "crypt32.lib")

namespace credential_store
{
	// DPAPI encrypt a string
	static std::string dpapi_encrypt(const std::string& plaintext)
	{
		if (plaintext.empty()) return {};

		DATA_BLOB input, output;
		input.pbData = (BYTE*)plaintext.data();
		input.cbData = (DWORD)plaintext.size();

		if (!CryptProtectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output))
			return {};

		// hex-encode the encrypted blob
		std::string hex;
		hex.reserve(output.cbData * 2);
		for (DWORD i = 0; i < output.cbData; i++)
		{
			char buf[3];
			sprintf_s(buf, "%02x", output.pbData[i]);
			hex += buf;
		}
		LocalFree(output.pbData);
		return hex;
	}

	// DPAPI decrypt a hex-encoded string
	static std::string dpapi_decrypt(const std::string& hex_cipher)
	{
		if (hex_cipher.empty() || hex_cipher.size() % 2 != 0) return {};

		// decode hex
		std::vector<BYTE> raw(hex_cipher.size() / 2);
		for (size_t i = 0; i < raw.size(); i++)
		{
			unsigned val = 0;
			sscanf_s(hex_cipher.c_str() + i * 2, "%02x", &val);
			raw[i] = (BYTE)val;
		}

		DATA_BLOB input, output;
		input.pbData = raw.data();
		input.cbData = (DWORD)raw.size();

		if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output))
			return {};

		std::string result((char*)output.pbData, output.cbData);
		LocalFree(output.pbData);
		return result;
	}

	static std::string get_store_path()
	{
		char appdata[MAX_PATH] = {};
		SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appdata);
		std::string dir = std::string(appdata) + "\\ZeroHook";
		CreateDirectoryA(dir.c_str(), nullptr);
		return dir + "\\credentials.dat";
	}

	// simple line-based format:
	// line 0: tab_index
	// line 1: key_count
	// line 2..N: keys
	// line N+1: last_key_index
	// line N+2: encrypted_username
	// line N+3: encrypted_password
	// line N+4: auto_login (0 or 1)

	saved_credentials_t load()
	{
		saved_credentials_t creds;
		std::ifstream f(get_store_path());
		if (!f.is_open()) return creds;

		std::string line;

		// tab
		if (!std::getline(f, line)) return creds;
		creds.last_tab = std::atoi(line.c_str());

		// key count
		if (!std::getline(f, line)) return creds;
		int key_count = std::atoi(line.c_str());

		// keys
		for (int i = 0; i < key_count; i++)
		{
			if (!std::getline(f, line)) break;
			std::string decrypted = dpapi_decrypt(line);
			if (!decrypted.empty())
				creds.keys.push_back(decrypted);
		}

		// last key index
		if (std::getline(f, line))
			creds.last_key_index = std::atoi(line.c_str());

		// username (encrypted)
		if (std::getline(f, line))
			creds.username = dpapi_decrypt(line);

		// password (encrypted)
		if (std::getline(f, line))
			creds.password = dpapi_decrypt(line);

		// auto_login
		if (std::getline(f, line))
			creds.auto_login = std::atoi(line.c_str()) != 0;

		// clamp
		if (creds.last_key_index >= (int)creds.keys.size())
			creds.last_key_index = 0;

		return creds;
	}

	void save(const saved_credentials_t& creds)
	{
		std::ofstream f(get_store_path(), std::ios::trunc);
		if (!f.is_open()) return;

		f << creds.last_tab << "\n";
		f << creds.keys.size() << "\n";
		for (const auto& key : creds.keys)
			f << dpapi_encrypt(key) << "\n";
		f << creds.last_key_index << "\n";
		f << dpapi_encrypt(creds.username) << "\n";
		f << dpapi_encrypt(creds.password) << "\n";
		f << (creds.auto_login ? 1 : 0) << "\n";
	}

	void add_key(saved_credentials_t& creds, const std::string& key)
	{
		// don't add duplicates
		auto it = std::find(creds.keys.begin(), creds.keys.end(), key);
		if (it != creds.keys.end())
		{
			creds.last_key_index = (int)(it - creds.keys.begin());
			return;
		}
		creds.keys.push_back(key);
		creds.last_key_index = (int)creds.keys.size() - 1;
	}

	void remove_key(saved_credentials_t& creds, int index)
	{
		if (index < 0 || index >= (int)creds.keys.size()) return;
		creds.keys.erase(creds.keys.begin() + index);
		if (creds.last_key_index >= (int)creds.keys.size())
			creds.last_key_index = (int)creds.keys.size() - 1;
		if (creds.last_key_index < 0)
			creds.last_key_index = 0;
	}
}
