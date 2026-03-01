#pragma once
#include <string>
#include <nlohmann/json.hpp>

namespace fingerprint
{
	struct machine_fingerprint_t
	{
		std::string computer_name;
		std::string user_name;
		std::string os_version;
		std::string os_architecture;
		std::string mac_address;
		std::string disk_serial;
		std::string cpu_id;
		std::string cpu_name;
		std::string motherboard_serial;
		std::string windows_product_id;
		std::string registry_fingerprint;
		std::string total_ram;
		std::string gpu_name;
	};

	machine_fingerprint_t collect();
	nlohmann::json to_json(const machine_fingerprint_t& fp);
}
