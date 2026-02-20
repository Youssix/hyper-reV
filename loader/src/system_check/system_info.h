#pragma once
#include <string>

namespace system_info
{
	struct check_result_t
	{
		bool passed = false;
		std::string detail;
	};

	struct system_checks_t
	{
		check_result_t hyperv;
		check_result_t windows;
		check_result_t secure_boot;
		check_result_t tpm;

		bool all_critical_passed() const
		{
			return hyperv.passed && windows.passed;
		}
	};

	system_checks_t run_all_checks();

	check_result_t check_hyperv();
	check_result_t check_windows_version();
	check_result_t check_secure_boot();
	check_result_t check_tpm();
}
