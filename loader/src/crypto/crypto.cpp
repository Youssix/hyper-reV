#include "crypto.h"
#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace crypto
{
	// ========== SHA-256 ==========

	std::vector<uint8_t> sha256(const void* data, size_t len)
	{
		std::vector<uint8_t> digest(32);

		BCRYPT_ALG_HANDLE alg = nullptr;
		if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
			return digest;

		BCRYPT_HASH_HANDLE hash = nullptr;
		BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
		BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0);
		BCryptFinishHash(hash, digest.data(), 32, 0);
		BCryptDestroyHash(hash);
		BCryptCloseAlgorithmProvider(alg, 0);

		return digest;
	}

	std::string sha256_hex(const void* data, size_t len)
	{
		auto digest = sha256(data, len);
		char hex[65] = {};
		for (int i = 0; i < 32; i++)
			sprintf_s(hex + i * 2, 3, "%02x", digest[i]);
		return std::string(hex);
	}

	std::string sha256_hex(const std::string& str)
	{
		return sha256_hex(str.data(), str.size());
	}

	// ========== AES-256-CBC ==========

	static std::vector<uint8_t> aes256_cbc_op(const uint8_t* input, size_t input_len,
		const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, bool encrypt)
	{
		if (key.size() != 32 || iv.size() != 16 || input_len == 0)
			return {};

		BCRYPT_ALG_HANDLE alg = nullptr;
		if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
			return {};

		BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
			(PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

		BCRYPT_KEY_HANDLE hkey = nullptr;
		if (BCryptGenerateSymmetricKey(alg, &hkey, nullptr, 0,
			(PUCHAR)key.data(), (ULONG)key.size(), 0) != 0)
		{
			BCryptCloseAlgorithmProvider(alg, 0);
			return {};
		}

		// copy IV since CNG modifies it in-place
		std::vector<uint8_t> iv_copy = iv;

		ULONG result_len = 0;
		NTSTATUS status;

		if (encrypt)
		{
			// get output size first
			status = BCryptEncrypt(hkey, (PUCHAR)input, (ULONG)input_len,
				nullptr, iv_copy.data(), (ULONG)iv_copy.size(),
				nullptr, 0, &result_len, BCRYPT_BLOCK_PADDING);
		}
		else
		{
			status = BCryptDecrypt(hkey, (PUCHAR)input, (ULONG)input_len,
				nullptr, iv_copy.data(), (ULONG)iv_copy.size(),
				nullptr, 0, &result_len, BCRYPT_BLOCK_PADDING);
		}

		if (status != 0 || result_len == 0)
		{
			BCryptDestroyKey(hkey);
			BCryptCloseAlgorithmProvider(alg, 0);
			return {};
		}

		std::vector<uint8_t> output(result_len);

		// reset IV copy
		iv_copy = iv;

		if (encrypt)
		{
			status = BCryptEncrypt(hkey, (PUCHAR)input, (ULONG)input_len,
				nullptr, iv_copy.data(), (ULONG)iv_copy.size(),
				output.data(), (ULONG)output.size(), &result_len, BCRYPT_BLOCK_PADDING);
		}
		else
		{
			status = BCryptDecrypt(hkey, (PUCHAR)input, (ULONG)input_len,
				nullptr, iv_copy.data(), (ULONG)iv_copy.size(),
				output.data(), (ULONG)output.size(), &result_len, BCRYPT_BLOCK_PADDING);
		}

		BCryptDestroyKey(hkey);
		BCryptCloseAlgorithmProvider(alg, 0);

		if (status != 0)
			return {};

		output.resize(result_len);
		return output;
	}

	std::vector<uint8_t> aes256_cbc_decrypt(const std::vector<uint8_t>& ciphertext,
		const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv)
	{
		return aes256_cbc_op(ciphertext.data(), ciphertext.size(), key, iv, false);
	}

	std::vector<uint8_t> aes256_cbc_encrypt(const std::vector<uint8_t>& plaintext,
		const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv)
	{
		return aes256_cbc_op(plaintext.data(), plaintext.size(), key, iv, true);
	}

	// ========== Base64 ==========

	std::string base64_encode(const uint8_t* data, size_t len)
	{
		DWORD chars_needed = 0;
		CryptBinaryToStringA(data, (DWORD)len,
			CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &chars_needed);

		if (chars_needed == 0)
			return {};

		std::string result(chars_needed, '\0');
		CryptBinaryToStringA(data, (DWORD)len,
			CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, result.data(), &chars_needed);

		// trim trailing null
		while (!result.empty() && result.back() == '\0')
			result.pop_back();

		return result;
	}

	std::string base64_encode(const std::vector<uint8_t>& data)
	{
		return base64_encode(data.data(), data.size());
	}

	std::vector<uint8_t> base64_decode(const std::string& encoded)
	{
		DWORD bytes_needed = 0;
		if (!CryptStringToBinaryA(encoded.c_str(), (DWORD)encoded.size(),
			CRYPT_STRING_BASE64, nullptr, &bytes_needed, nullptr, nullptr))
			return {};

		std::vector<uint8_t> result(bytes_needed);
		if (!CryptStringToBinaryA(encoded.c_str(), (DWORD)encoded.size(),
			CRYPT_STRING_BASE64, result.data(), &bytes_needed, nullptr, nullptr))
			return {};

		result.resize(bytes_needed);
		return result;
	}

	// ========== Random ==========

	std::vector<uint8_t> random_bytes(size_t count)
	{
		std::vector<uint8_t> buf(count);

		BCRYPT_ALG_HANDLE alg = nullptr;
		BCryptOpenAlgorithmProvider(&alg, BCRYPT_RNG_ALGORITHM, nullptr, 0);
		if (alg)
		{
			BCryptGenRandom(alg, buf.data(), (ULONG)buf.size(), 0);
			BCryptCloseAlgorithmProvider(alg, 0);
		}

		return buf;
	}

	// ========== Secure Zero ==========

	void secure_zero(std::vector<uint8_t>& buf)
	{
		SecureZeroMemory(buf.data(), buf.size());
		buf.clear();
	}

	void secure_zero(std::string& buf)
	{
		SecureZeroMemory(buf.data(), buf.size());
		buf.clear();
	}
}
