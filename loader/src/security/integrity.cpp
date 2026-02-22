#include "integrity.h"
#include <Windows.h>
#include <thread>
#include <atomic>
#include <vector>

namespace integrity
{
	static std::atomic<bool> s_running{ false };
	static std::thread s_thread;

	// baseline CRC32 of our .text section
	static uint32_t s_text_crc = 0;
	static void* s_text_base = nullptr;
	static size_t s_text_size = 0;
	static bool s_baseline_valid = false;

	// fast CRC32 using intrinsics if available, otherwise software
	static uint32_t compute_crc32(const void* data, size_t size)
	{
		uint32_t crc = 0xFFFFFFFF;
		auto p = (const uint8_t*)data;

#ifdef _M_X64
		// use hardware CRC32 (SSE4.2) if available
		int cpuinfo[4];
		__cpuid(cpuinfo, 1);
		bool has_sse42 = (cpuinfo[2] & (1 << 20)) != 0;

		if (has_sse42)
		{
			size_t i = 0;
			// process 8 bytes at a time
			for (; i + 8 <= size; i += 8)
				crc = (uint32_t)_mm_crc32_u64(crc, *(const uint64_t*)(p + i));
			// remaining bytes
			for (; i < size; i++)
				crc = _mm_crc32_u8(crc, p[i]);
			return crc ^ 0xFFFFFFFF;
		}
#endif
		// software fallback
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

	// find .text section of our own module
	static bool find_text_section()
	{
		HMODULE base = GetModuleHandleA(nullptr);
		if (!base) return false;

		auto dos = (IMAGE_DOS_HEADER*)base;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

		auto nt = (IMAGE_NT_HEADERS*)((uint8_t*)base + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

		auto section = IMAGE_FIRST_SECTION(nt);
		for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
		{
			if (memcmp(section->Name, ".text", 5) == 0)
			{
				s_text_base = (uint8_t*)base + section->VirtualAddress;
				s_text_size = section->Misc.VirtualSize;
				return true;
			}
		}
		return false;
	}

	void capture_baseline()
	{
		if (!find_text_section()) return;
		s_text_crc = compute_crc32(s_text_base, s_text_size);
		s_baseline_valid = true;
	}

	bool verify_text_section()
	{
		if (!s_baseline_valid) return true; // no baseline = skip
		uint32_t current = compute_crc32(s_text_base, s_text_size);
		return current == s_text_crc;
	}

	bool check_api_hooks()
	{
		// check first bytes of critical APIs for inline hooks
		// a hooked function typically starts with 0xE9 (JMP) or 0xFF25 (JMP [rip+...])
		struct api_check_t
		{
			const char* module;
			const char* function;
		};

		static const api_check_t apis[] = {
			{ "ntdll.dll",    "NtQueryInformationProcess" },
			{ "ntdll.dll",    "NtSetInformationThread" },
			{ "ntdll.dll",    "NtCreateFile" },
			{ "kernel32.dll", "IsDebuggerPresent" },
			{ "kernel32.dll", "CheckRemoteDebuggerPresent" },
			{ "kernel32.dll", "GetThreadContext" },
			{ "kernel32.dll", "VirtualAlloc" },
			{ "kernel32.dll", "VirtualProtect" },
		};

		for (const auto& api : apis)
		{
			HMODULE mod = GetModuleHandleA(api.module);
			if (!mod) continue;

			auto addr = (const uint8_t*)GetProcAddress(mod, api.function);
			if (!addr) continue;

			// check for common hook patterns at function entry
			if (addr[0] == 0xE9)                          return false; // relative JMP
			if (addr[0] == 0xEB)                          return false; // short JMP
			if (addr[0] == 0xFF && addr[1] == 0x25)       return false; // JMP [rip+disp32]
			if (addr[0] == 0x68 && addr[5] == 0xC3)       return false; // push+ret
			if (addr[0] == 0x48 && addr[1] == 0xB8 &&
				addr[10] == 0xFF && addr[11] == 0xE0)     return false; // mov rax, imm; jmp rax
		}

		return true; // all clean
	}

	bool verify_all()
	{
		if (!verify_text_section()) return false;
		if (!check_api_hooks())     return false;
		return true;
	}

	void start_monitor()
	{
		if (s_running.exchange(true))
			return;

		s_thread = std::thread([]()
		{
			while (s_running.load())
			{
				if (!verify_all())
				{
					// tampering detected
					*(volatile int*)0 = 0;
				}

				// check every 5 seconds with jitter
				LARGE_INTEGER freq, now;
				QueryPerformanceFrequency(&freq);
				QueryPerformanceCounter(&now);
				DWORD jitter = (DWORD)(now.QuadPart % 2000) + 4000;
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
