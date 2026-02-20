#include "system_info.h"
#include <Windows.h>
#include <intrin.h>
#include <tbs.h>
#include <cstdio>

#pragma comment(lib, "tbs.lib")

namespace system_info
{
	check_result_t check_hyperv()
	{
		check_result_t result;

		// CPUID leaf 1, bit 31 of ECX = hypervisor present
		int regs[4] = {};
		__cpuid(regs, 1);
		bool cpuid_hv = (regs[2] >> 31) & 1;

		// also check registry
		HKEY hkey;
		bool registry_ok = false;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
			"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization", 0,
			KEY_READ, &hkey) == ERROR_SUCCESS)
		{
			registry_ok = true;
			RegCloseKey(hkey);
		}

		result.passed = cpuid_hv;
		if (cpuid_hv && registry_ok)
			result.detail = "Hyper-V active (CPUID + Registry)";
		else if (cpuid_hv)
			result.detail = "Hypervisor detected (CPUID)";
		else
			result.detail = "Hyper-V not detected — enable in Windows Features";

		return result;
	}

	check_result_t check_windows_version()
	{
		check_result_t result;

		// use RtlGetVersion to bypass compatibility shims
		typedef NTSTATUS(NTAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
		auto RtlGetVersion = (RtlGetVersion_t)GetProcAddress(
			GetModuleHandleA("ntdll.dll"), "RtlGetVersion");

		if (!RtlGetVersion)
		{
			result.passed = false;
			result.detail = "Cannot query OS version";
			return result;
		}

		RTL_OSVERSIONINFOW osvi = {};
		osvi.dwOSVersionInfoSize = sizeof(osvi);
		RtlGetVersion(&osvi);

		char buf[128];
		sprintf_s(buf, "Windows %lu.%lu Build %lu",
			osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);

		// require build 19041+ (Windows 10 2004 / 20H1)
		result.passed = (osvi.dwBuildNumber >= 19041);
		result.detail = buf;
		if (!result.passed)
			result.detail += " (Build 19041+ required)";

		return result;
	}

	check_result_t check_secure_boot()
	{
		check_result_t result;

		BYTE value = 0;
		DWORD size = GetFirmwareEnvironmentVariableA(
			"SecureBoot",
			"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
			&value, sizeof(value));

		if (size > 0)
		{
			result.passed = (value == 1);
			result.detail = value ? "Secure Boot ON" : "Secure Boot OFF";
		}
		else
		{
			// GetFirmwareEnvironmentVariable fails on legacy BIOS
			DWORD err = GetLastError();
			if (err == ERROR_INVALID_FUNCTION)
			{
				result.passed = false;
				result.detail = "Legacy BIOS (no UEFI)";
			}
			else
			{
				result.passed = false;
				result.detail = "Cannot query Secure Boot";
			}
		}

		return result;
	}

	check_result_t check_tpm()
	{
		check_result_t result;

		TBS_CONTEXT_PARAMS2 params = {};
		params.version = TBS_CONTEXT_VERSION_TWO;
		TBS_HCONTEXT ctx = 0;

		TBS_RESULT tbs_result = Tbsi_Context_Create(
			(PCTBS_CONTEXT_PARAMS)&params, &ctx);

		if (tbs_result == TBS_SUCCESS)
		{
			result.passed = true;
			result.detail = "TPM 2.0 available";
			Tbsip_Context_Close(ctx);
		}
		else
		{
			// try TPM 1.2
			TBS_CONTEXT_PARAMS params1 = {};
			params1.version = TBS_CONTEXT_VERSION_ONE;
			tbs_result = Tbsi_Context_Create(&params1, &ctx);

			if (tbs_result == TBS_SUCCESS)
			{
				result.passed = true;
				result.detail = "TPM 1.2 available";
				Tbsip_Context_Close(ctx);
			}
			else
			{
				result.passed = false;
				result.detail = "No TPM detected";
			}
		}

		return result;
	}

	system_checks_t run_all_checks()
	{
		system_checks_t checks;
		checks.hyperv      = check_hyperv();
		checks.windows     = check_windows_version();
		checks.secure_boot = check_secure_boot();
		checks.tpm         = check_tpm();
		return checks;
	}
}
