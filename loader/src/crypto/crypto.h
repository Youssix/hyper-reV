#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace crypto
{
	// SHA-256
	std::vector<uint8_t> sha256(const void* data, size_t len);
	std::string sha256_hex(const void* data, size_t len);
	std::string sha256_hex(const std::string& str);

	// AES-256-CBC
	std::vector<uint8_t> aes256_cbc_decrypt(const std::vector<uint8_t>& ciphertext,
		const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
	std::vector<uint8_t> aes256_cbc_encrypt(const std::vector<uint8_t>& plaintext,
		const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);

	// base64
	std::string base64_encode(const std::vector<uint8_t>& data);
	std::string base64_encode(const uint8_t* data, size_t len);
	std::vector<uint8_t> base64_decode(const std::string& encoded);

	// random
	std::vector<uint8_t> random_bytes(size_t count);

	// secure erase
	void secure_zero(std::vector<uint8_t>& buf);
	void secure_zero(std::string& buf);
}
