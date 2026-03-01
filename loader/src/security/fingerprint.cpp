#include "fingerprint.h"
#include "../crypto/crypto.h"
#include "../vendor/skCrypter.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <intrin.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <cstdio>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

#define SK(s) ((const char*)skCrypt(s))
#define SKW(s) ((const wchar_t*)skCrypt(s))

namespace fingerprint
{
	// ========== WMI helper ==========

	static std::string wmi_query_string(const wchar_t* wmi_class, const wchar_t* property)
	{
		std::string result;

		IWbemLocator* locator = nullptr;
		IWbemServices* services = nullptr;
		IEnumWbemClassObject* enumerator = nullptr;

		HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
			IID_IWbemLocator, (void**)&locator);
		if (FAILED(hr)) return result;

		hr = locator->ConnectServer(_bstr_t(SKW(L"ROOT\\CIMV2")), nullptr, nullptr, nullptr,
			0, nullptr, nullptr, &services);
		if (FAILED(hr)) { locator->Release(); return result; }

		CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
			RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

		wchar_t query[256];
		swprintf_s(query, L"SELECT %s FROM %s", property, wmi_class);

		hr = services->ExecQuery(_bstr_t(SKW(L"WQL")), _bstr_t(query),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &enumerator);

		if (SUCCEEDED(hr))
		{
			IWbemClassObject* obj = nullptr;
			ULONG returned = 0;

			if (enumerator->Next(WBEM_INFINITE, 1, &obj, &returned) == S_OK && returned > 0)
			{
				VARIANT val;
				VariantInit(&val);
				hr = obj->Get(property, 0, &val, nullptr, nullptr);
				if (SUCCEEDED(hr) && val.vt == VT_BSTR && val.bstrVal)
				{
					_bstr_t bstr(val.bstrVal, false);
					result = (const char*)bstr;
				}
				VariantClear(&val);
				obj->Release();
			}

			enumerator->Release();
		}

		services->Release();
		locator->Release();

		return result;
	}

	// ========== Registry helpers ==========

	static std::string read_registry_string(HKEY root, const char* subkey, const char* value)
	{
		HKEY hkey;
		if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hkey) != ERROR_SUCCESS)
			return {};

		char buf[512] = {};
		DWORD size = sizeof(buf);
		DWORD type = REG_SZ;
		RegQueryValueExA(hkey, value, nullptr, &type, (LPBYTE)buf, &size);
		RegCloseKey(hkey);

		return std::string(buf);
	}

	// ========== Collection functions ==========

	static std::string get_computer_name()
	{
		wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
		DWORD size = (DWORD)std::size(buf);
		GetComputerNameW(buf, &size);

		char mbuf[MAX_COMPUTERNAME_LENGTH + 1] = {};
		WideCharToMultiByte(CP_UTF8, 0, buf, -1, mbuf, sizeof(mbuf), nullptr, nullptr);
		return std::string(mbuf);
	}

	static std::string get_user_name()
	{
		wchar_t buf[256] = {};
		DWORD size = (DWORD)std::size(buf);
		GetUserNameW(buf, &size);

		char mbuf[256] = {};
		WideCharToMultiByte(CP_UTF8, 0, buf, -1, mbuf, sizeof(mbuf), nullptr, nullptr);
		return std::string(mbuf);
	}

	static std::string get_os_version()
	{
		auto product = read_registry_string(HKEY_LOCAL_MACHINE,
			SK("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
			SK("ProductName"));
		auto display = read_registry_string(HKEY_LOCAL_MACHINE,
			SK("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
			SK("DisplayVersion"));

		if (!display.empty())
			return product + " " + display;
		return product;
	}

	static std::string get_os_architecture()
	{
		SYSTEM_INFO si = {};
		GetNativeSystemInfo(&si);

		switch (si.wProcessorArchitecture)
		{
		case PROCESSOR_ARCHITECTURE_AMD64: return "x64";
		case PROCESSOR_ARCHITECTURE_ARM64: return "ARM64";
		case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
		default: return "unknown";
		}
	}

	static std::string get_mac_address()
	{
		ULONG buf_size = 0;
		GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &buf_size);
		if (buf_size == 0) return {};

		std::vector<uint8_t> buf(buf_size);
		auto adapters = (PIP_ADAPTER_ADDRESSES)buf.data();

		if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &buf_size) != NO_ERROR)
			return {};

		for (auto a = adapters; a; a = a->Next)
		{
			if (a->IfType == IF_TYPE_ETHERNET_CSMACD || a->IfType == IF_TYPE_IEEE80211)
			{
				if (a->PhysicalAddressLength == 6)
				{
					char mac[18] = {};
					sprintf_s(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
						a->PhysicalAddress[0], a->PhysicalAddress[1],
						a->PhysicalAddress[2], a->PhysicalAddress[3],
						a->PhysicalAddress[4], a->PhysicalAddress[5]);
					return std::string(mac);
				}
			}
		}

		return {};
	}

	static std::string get_disk_serial()
	{
		return wmi_query_string(SKW(L"Win32_DiskDrive"), SKW(L"SerialNumber"));
	}

	static std::string get_cpu_id()
	{
		int cpuinfo[4] = {};
		__cpuid(cpuinfo, 1);
		char buf[16] = {};
		sprintf_s(buf, "%08X", cpuinfo[0]);
		return std::string(buf);
	}

	static std::string get_cpu_name()
	{
		return read_registry_string(HKEY_LOCAL_MACHINE,
			SK("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"),
			SK("ProcessorNameString"));
	}

	static std::string get_motherboard_serial()
	{
		return wmi_query_string(SKW(L"Win32_BaseBoard"), SKW(L"SerialNumber"));
	}

	static std::string get_windows_product_id()
	{
		return read_registry_string(HKEY_LOCAL_MACHINE,
			SK("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
			SK("ProductId"));
	}

	static std::string get_registry_fingerprint()
	{
		auto machine_guid = read_registry_string(HKEY_LOCAL_MACHINE,
			SK("SOFTWARE\\Microsoft\\Cryptography"),
			SK("MachineGuid"));
		auto product_id = get_windows_product_id();
		auto install_date = read_registry_string(HKEY_LOCAL_MACHINE,
			SK("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
			SK("InstallDate"));

		std::string combined = machine_guid + product_id + install_date;
		return crypto::sha256_hex(combined);
	}

	static std::string get_total_ram()
	{
		MEMORYSTATUSEX mem = {};
		mem.dwLength = sizeof(mem);
		GlobalMemoryStatusEx(&mem);
		return std::to_string(mem.ullTotalPhys / 1024 / 1024);
	}

	static std::string get_gpu_name()
	{
		return wmi_query_string(SKW(L"Win32_VideoController"), SKW(L"Name"));
	}

	// ========== Public API ==========

	machine_fingerprint_t collect()
	{
		HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
		bool com_init = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;

		machine_fingerprint_t fp;
		fp.computer_name = get_computer_name();
		fp.user_name = get_user_name();
		fp.os_version = get_os_version();
		fp.os_architecture = get_os_architecture();
		fp.mac_address = get_mac_address();
		fp.disk_serial = get_disk_serial();
		fp.cpu_id = get_cpu_id();
		fp.cpu_name = get_cpu_name();
		fp.motherboard_serial = get_motherboard_serial();
		fp.windows_product_id = get_windows_product_id();
		fp.registry_fingerprint = get_registry_fingerprint();
		fp.total_ram = get_total_ram();
		fp.gpu_name = get_gpu_name();

		if (com_init && SUCCEEDED(hr))
			CoUninitialize();

		return fp;
	}

	nlohmann::json to_json(const machine_fingerprint_t& fp)
	{
		return {
			{SK("computerName"),        fp.computer_name},
			{SK("userName"),            fp.user_name},
			{SK("osVersion"),           fp.os_version},
			{SK("osArchitecture"),      fp.os_architecture},
			{SK("macAddress"),          fp.mac_address},
			{SK("diskSerial"),          fp.disk_serial},
			{SK("cpuId"),              fp.cpu_id},
			{SK("cpuName"),            fp.cpu_name},
			{SK("motherboardSerial"),   fp.motherboard_serial},
			{SK("windowsProductId"),    fp.windows_product_id},
			{SK("registryFingerprint"), fp.registry_fingerprint},
			{SK("totalRam"),            fp.total_ram},
			{SK("gpuName"),            fp.gpu_name},
		};
	}
}
