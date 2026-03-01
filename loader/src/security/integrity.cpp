#include "integrity.h"
#include "../auth/auth_client.h"
#include "../vendor/skCrypter.h"

#define SK(s) ((const char*)skCrypt(s))

#include <Windows.h>
#include <thread>
#include <atomic>
#include <vector>
#include <intrin.h>

namespace integrity
{
	static std::atomic<bool> s_running{ false };
	static std::thread s_thread;

	// baseline CRC32 of .text section
	static uint32_t s_text_crc = 0;
	static void* s_text_base = nullptr;
	static size_t s_text_size = 0;
	static bool s_text_valid = false;

	// baseline CRC32 of .rdata section
	static uint32_t s_rdata_crc = 0;
	static void* s_rdata_base = nullptr;
	static size_t s_rdata_size = 0;
	static bool s_rdata_valid = false;

	// IAT snapshot
	struct iat_entry_t
	{
		uint32_t module_hash;
		uint32_t func_hash;
		void* expected_addr;
	};
	static std::vector<iat_entry_t> s_iat_snapshot;
	static bool s_iat_valid = false;

	// watchdog tick — updated each monitor loop iteration
	static std::atomic<uint64_t> s_last_tick{ 0 };

	// fast CRC32 using intrinsics if available, otherwise software
	static uint32_t compute_crc32(const void* data, size_t size)
	{
		uint32_t crc = 0xFFFFFFFF;
		auto p = (const uint8_t*)data;

#ifdef _M_X64
		int cpuinfo[4];
		__cpuid(cpuinfo, 1);
		bool has_sse42 = (cpuinfo[2] & (1 << 20)) != 0;

		if (has_sse42)
		{
			size_t i = 0;
			for (; i + 8 <= size; i += 8)
				crc = (uint32_t)_mm_crc32_u64(crc, *(const uint64_t*)(p + i));
			for (; i < size; i++)
				crc = _mm_crc32_u8(crc, p[i]);
			return crc ^ 0xFFFFFFFF;
		}
#endif
		static uint32_t table[256] = {};
		static bool table_init = false;
		if (!table_init)
		{
			for (uint32_t n = 0; n < 256; n++)
			{
				uint32_t c = n;
				for (int k = 0; k < 8; k++)
					c = (c >> 1) ^ (c & 1 ? 0xEDB88320 : 0);
				table[n] = c;
			}
			table_init = true;
		}

		for (size_t i = 0; i < size; i++)
			crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);

		return crc ^ 0xFFFFFFFF;
	}

	// simple djb2 hash for strings
	static uint32_t hash_string(const char* s)
	{
		uint32_t h = 5381;
		while (*s)
			h = ((h << 5) + h) + (uint8_t)*s++;
		return h;
	}

	// find a named PE section of our own module
	static bool find_section(const char* name, void*& base, size_t& size)
	{
		HMODULE mod = GetModuleHandleA(nullptr);
		if (!mod) return false;

		auto dos = (IMAGE_DOS_HEADER*)mod;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

		auto nt = (IMAGE_NT_HEADERS*)((uint8_t*)mod + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

		size_t name_len = strlen(name);
		auto section = IMAGE_FIRST_SECTION(nt);
		for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
		{
			if (memcmp(section->Name, name, name_len) == 0)
			{
				base = (uint8_t*)mod + section->VirtualAddress;
				size = section->Misc.VirtualSize;
				return true;
			}
		}
		return false;
	}

	// snapshot the IAT
	static bool capture_iat_snapshot()
	{
		HMODULE mod = GetModuleHandleA(nullptr);
		if (!mod) return false;

		auto dos = (IMAGE_DOS_HEADER*)mod;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

		auto nt = (IMAGE_NT_HEADERS*)((uint8_t*)mod + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

		auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (import_dir.VirtualAddress == 0 || import_dir.Size == 0)
			return false;

		auto desc = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)mod + import_dir.VirtualAddress);

		s_iat_snapshot.clear();

		for (; desc->Name != 0; desc++)
		{
			const char* dll_name = (const char*)((uint8_t*)mod + desc->Name);
			uint32_t mod_hash = hash_string(dll_name);

			auto thunk_orig = (IMAGE_THUNK_DATA*)((uint8_t*)mod +
				(desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
			auto thunk_iat = (IMAGE_THUNK_DATA*)((uint8_t*)mod + desc->FirstThunk);

			for (; thunk_orig->u1.AddressOfData != 0; thunk_orig++, thunk_iat++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk_orig->u1.Ordinal))
					continue; // skip ordinal imports

				auto import = (IMAGE_IMPORT_BY_NAME*)((uint8_t*)mod + thunk_orig->u1.AddressOfData);

				iat_entry_t entry;
				entry.module_hash = mod_hash;
				entry.func_hash = hash_string(import->Name);
				entry.expected_addr = (void*)thunk_iat->u1.Function;
				s_iat_snapshot.push_back(entry);
			}
		}

		return !s_iat_snapshot.empty();
	}

	void capture_baseline()
	{
		if (!find_section(SK(".text"), s_text_base, s_text_size)) return;
		s_text_crc = compute_crc32(s_text_base, s_text_size);
		s_text_valid = true;
	}

	void capture_all_baselines()
	{
		// .text
		if (find_section(SK(".text"), s_text_base, s_text_size))
		{
			s_text_crc = compute_crc32(s_text_base, s_text_size);
			s_text_valid = true;
		}

		// .rdata
		if (find_section(SK(".rdata"), s_rdata_base, s_rdata_size))
		{
			s_rdata_crc = compute_crc32(s_rdata_base, s_rdata_size);
			s_rdata_valid = true;
		}

		// IAT
		s_iat_valid = capture_iat_snapshot();
	}

	bool verify_text_section()
	{
		if (!s_text_valid) return true;
		uint32_t current = compute_crc32(s_text_base, s_text_size);
		return current == s_text_crc;
	}

	bool verify_rdata_section()
	{
		if (!s_rdata_valid) return true;
		uint32_t current = compute_crc32(s_rdata_base, s_rdata_size);
		return current == s_rdata_crc;
	}

	bool verify_iat()
	{
		if (!s_iat_valid || s_iat_snapshot.empty()) return true;

		HMODULE mod = GetModuleHandleA(nullptr);
		if (!mod) return false;

		auto dos = (IMAGE_DOS_HEADER*)mod;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

		auto nt = (IMAGE_NT_HEADERS*)((uint8_t*)mod + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

		auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (import_dir.VirtualAddress == 0) return false;

		auto desc = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)mod + import_dir.VirtualAddress);

		size_t idx = 0;
		for (; desc->Name != 0 && idx < s_iat_snapshot.size(); desc++)
		{
			const char* dll_name = (const char*)((uint8_t*)mod + desc->Name);
			uint32_t mod_hash = hash_string(dll_name);

			auto thunk_orig = (IMAGE_THUNK_DATA*)((uint8_t*)mod +
				(desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
			auto thunk_iat = (IMAGE_THUNK_DATA*)((uint8_t*)mod + desc->FirstThunk);

			for (; thunk_orig->u1.AddressOfData != 0 && idx < s_iat_snapshot.size();
				thunk_orig++, thunk_iat++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk_orig->u1.Ordinal))
					continue;

				auto& snap = s_iat_snapshot[idx];
				if (snap.module_hash == mod_hash)
				{
					auto import = (IMAGE_IMPORT_BY_NAME*)((uint8_t*)mod + thunk_orig->u1.AddressOfData);
					if (snap.func_hash == hash_string(import->Name))
					{
						void* current_addr = (void*)thunk_iat->u1.Function;
						if (current_addr != snap.expected_addr)
							return false;
					}
				}
				idx++;
			}
		}

		return true;
	}

	static bool check_single_api(const char* mod_name, const char* func_name)
	{
		HMODULE mod = GetModuleHandleA(mod_name);
		if (!mod) return true;

		auto addr = (const uint8_t*)GetProcAddress(mod, func_name);
		if (!addr) return true;

		if (addr[0] == 0xE9)                          return false;
		if (addr[0] == 0xEB)                          return false;
		if (addr[0] == 0xFF && addr[1] == 0x25)       return false;
		if (addr[0] == 0x68 && addr[5] == 0xC3)       return false;
		if (addr[0] == 0x48 && addr[1] == 0xB8 &&
			addr[10] == 0xFF && addr[11] == 0xE0)     return false;

		return true;
	}

	bool check_api_hooks()
	{
		if (!check_single_api(SK("ntdll.dll"),    SK("NtQueryInformationProcess")))  return false;
		if (!check_single_api(SK("ntdll.dll"),    SK("NtSetInformationThread")))     return false;
		if (!check_single_api(SK("ntdll.dll"),    SK("NtCreateFile")))               return false;
		if (!check_single_api(SK("kernel32.dll"), SK("IsDebuggerPresent")))          return false;
		if (!check_single_api(SK("kernel32.dll"), SK("CheckRemoteDebuggerPresent"))) return false;
		if (!check_single_api(SK("kernel32.dll"), SK("GetThreadContext")))            return false;
		if (!check_single_api(SK("kernel32.dll"), SK("VirtualAlloc")))               return false;
		if (!check_single_api(SK("kernel32.dll"), SK("VirtualProtect")))             return false;
		return true;
	}

	bool verify_all()
	{
		if (!verify_text_section())  return false;
		if (!verify_rdata_section()) return false;
		if (!verify_iat())           return false;
		if (!check_api_hooks())      return false;
		return true;
	}

	// crash with varying methods — harder to blanket-catch with VEH
	__declspec(noinline) static void tamper_response()
	{
		// fire-and-forget tampering report
		auth::send_report("", SK("integrity_violation"),
			SK("Binary integrity check failed"));

		auto method = __rdtsc() % 5;
		switch (method)
		{
		case 0: *(volatile int*)0 = 0; break;
		case 1: TerminateProcess(GetCurrentProcess(), 0xDEAD); break;
		case 2: ExitProcess(0xDEAD); break;
		case 3: RaiseFailFastException(nullptr, nullptr, 0); break;
		case 4: __fastfail(FAST_FAIL_FATAL_APP_EXIT); break;
		}
		// unreachable fallback
		TerminateProcess(GetCurrentProcess(), 1);
	}

	void inline_check()
	{
		if (!s_text_valid) return;
		uint32_t current = compute_crc32(s_text_base, s_text_size);
		if (current != s_text_crc)
			tamper_response();
	}

	bool is_monitor_alive()
	{
		uint64_t last = s_last_tick.load();
		if (last == 0) return true; // not started yet
		uint64_t now = GetTickCount64();
		return (now - last) < 15000;
	}

	uint32_t get_text_crc()
	{
		if (!s_text_valid) return 0;
		return compute_crc32(s_text_base, s_text_size);
	}

	uint32_t get_rdata_crc()
	{
		if (!s_rdata_valid) return 0;
		return compute_crc32(s_rdata_base, s_rdata_size);
	}

	void start_monitor()
	{
		if (s_running.exchange(true))
			return;

		s_last_tick.store(GetTickCount64());

		s_thread = std::thread([]()
		{
			int cycle = 0;
			while (s_running.load())
			{
				s_last_tick.store(GetTickCount64());

				// rotate check type each cycle for faster individual cycles
				bool ok = true;
				switch (cycle % 4)
				{
				case 0: ok = verify_text_section();  break;
				case 1: ok = verify_rdata_section(); break;
				case 2: ok = verify_iat();           break;
				case 3: ok = check_api_hooks();      break;
				}
				cycle++;

				if (!ok)
					tamper_response();

				// 2-4s jitter (faster cycles than before)
				LARGE_INTEGER freq, now;
				QueryPerformanceFrequency(&freq);
				QueryPerformanceCounter(&now);
				DWORD jitter = (DWORD)(now.QuadPart % 2000) + 2000;
				Sleep(jitter);
			}
		});
	}

	void stop_monitor()
	{
		s_running.store(false);
		if (s_thread.joinable())
			s_thread.join();
	}
}

// extern bridge for auth_client heartbeat (avoids circular header dependency)
uint32_t integrity_get_text_crc()  { return integrity::get_text_crc(); }
uint32_t integrity_get_rdata_crc() { return integrity::get_rdata_crc(); }
