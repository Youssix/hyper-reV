#include "system_info.h"
#include <Windows.h>
#include <intrin.h>
#include <cstdio>
#include <cstring>

namespace system_info
{
	check_result_t check_cpu_vendor()
	{
		check_result_t result;

		int regs[4] = {};
		__cpuid(regs, 0);

		char vendor[13] = {};
		memcpy(vendor + 0, &regs[1], 4); // EBX
		memcpy(vendor + 4, &regs[3], 4); // EDX
		memcpy(vendor + 8, &regs[2], 4); // ECX
		vendor[12] = '\0';

		result.passed = (strcmp(vendor, "GenuineIntel") == 0);
		result.detail = vendor;
		if (!result.passed)
			result.detail += " (Intel CPU required)";

		return result;
	}

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
			result.detail = "Hyper-V not detected";

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

		HKEY hkey;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0,
			KEY_READ, &hkey) == ERROR_SUCCESS)
		{
			DWORD value = 0;
			DWORD size = sizeof(value);
			if (RegQueryValueExA(hkey, "UEFISecureBootEnabled", nullptr,
				nullptr, (LPBYTE)&value, &size) == ERROR_SUCCESS)
			{
				result.passed = (value == 0);
				result.detail = value ? "Secure Boot ON (must be disabled)" : "Secure Boot OFF";
			}
			else
			{
				result.passed = false;
				result.detail = "Secure Boot state unknown";
			}
			RegCloseKey(hkey);
		}
		else
		{
			// Key doesn't exist on legacy BIOS systems
			result.passed = false;
			result.detail = "Legacy BIOS (UEFI required)";
		}

		return result;
	}

	check_result_t check_pdb_loader()
	{
		check_result_t result;

		// PDB symbol resolution needs msdia140.dll (DIA SDK)
		// The pdb_load() function uses NoRegCoCreate as fallback,
		// which just needs the DLL loadable from search path
		HMODULE hmod = LoadLibraryW(L"msdia140.dll");
		if (hmod)
		{
			result.passed = true;
			result.detail = "PDB loader ready (msdia140.dll)";
			FreeLibrary(hmod);
			return result;
		}

		// check if registered as COM server (Visual Studio installed)
		HKEY hkey;
		if (RegOpenKeyExA(HKEY_CLASSES_ROOT,
			"TypeLib\\{108296C1-281E-11d3-BD22-0000F80849BD}", 0,
			KEY_READ, &hkey) == ERROR_SUCCESS)
		{
			result.passed = true;
			result.detail = "PDB loader ready (DIA SDK registered)";
			RegCloseKey(hkey);
			return result;
		}

		result.passed = false;
		result.detail = "msdia140.dll not found";
		return result;
	}

	system_checks_t run_all_checks()
	{
		system_checks_t checks;
		checks.cpu_vendor  = check_cpu_vendor();
		checks.hyperv      = check_hyperv();
		checks.windows     = check_windows_version();
		checks.secure_boot = check_secure_boot();
		checks.pdb_loader  = check_pdb_loader();
		return checks;
	}
}
