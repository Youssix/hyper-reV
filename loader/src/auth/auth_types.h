#pragma once
#include <string>
#include <vector>
#include <cstdint>

enum class game_status
{
	online,
	updating,
	offline
};

struct game_info_t
{
	std::string name;
	std::string process_name;
	std::string dll_path;
	std::string version;
	game_status status = game_status::offline;
};

struct subscription_t
{
	std::string plan;
	std::string expiry;
	bool is_active = false;
};

struct user_session_t
{
	std::string username;
	std::string token;
	bool is_reseller = false;
	subscription_t subscription;
	std::vector<game_info_t> games;
	std::string patch_notes;
};
