#include "anti_debug.h"
#include "../auth/auth_client.h"
#include "../vendor/skCrypter.h"
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <thread>
#include <atomic>

#pragma comment(lib, "ntdll.lib")

#define SK(s) ((const char*)skCrypt(s))

// ntdll function types
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG);

namespace anti_debug
{
	static std::atomic<bool> s_running{ false };
	static std::thread s_thread;

	// --- individual checks ---

	static bool check_is_debugger_present()
	{
		return IsDebuggerPresent() != FALSE;
	}

	static bool check_remote_debugger()
	{
		BOOL present = FALSE;
		CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
		return present != FALSE;
	}

	static bool check_nt_global_flag()
	{
#ifdef _WIN64
		auto peb = (PPEB)__readgsqword(0x60);
		DWORD flags = *(DWORD*)((BYTE*)peb + 0xBC);
#else
		auto peb = (PPEB)__readfsdword(0x30);
		DWORD flags = *(DWORD*)((BYTE*)peb + 0x68);
#endif
		return (flags & 0x70) != 0;
	}

	static bool check_debug_port()
	{
		auto NtQueryInformationProcess = (pNtQueryInformationProcess)
			GetProcAddress(GetModuleHandleA(SK("ntdll.dll")), SK("NtQueryInformationProcess"));
		if (!NtQueryInformationProcess) return false;

		DWORD_PTR debug_port = 0;
		NTSTATUS status = NtQueryInformationProcess(
			GetCurrentProcess(),
			(PROCESSINFOCLASS)7,
			&debug_port,
			sizeof(debug_port),
			nullptr);

		return NT_SUCCESS(status) && debug_port != 0;
	}

	static bool check_debug_object_handle()
	{
		auto NtQueryInformationProcess = (pNtQueryInformationProcess)
			GetProcAddress(GetModuleHandleA(SK("ntdll.dll")), SK("NtQueryInformationProcess"));
		if (!NtQueryInformationProcess) return false;

		HANDLE debug_obj = nullptr;
		NTSTATUS status = NtQueryInformationProcess(
			GetCurrentProcess(),
			(PROCESSINFOCLASS)30,
			&debug_obj,
			sizeof(debug_obj),
			nullptr);

		return NT_SUCCESS(status);
	}

	static bool check_hardware_breakpoints()
	{
		CONTEXT ctx = {};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (!GetThreadContext(GetCurrentThread(), &ctx))
			return false;

		return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
	}

	static bool check_timing()
	{
		unsigned __int64 t1 = __rdtsc();

		volatile int dummy = 0;
		for (int i = 0; i < 100; i++)
			dummy += i;

		unsigned __int64 t2 = __rdtsc();

		return (t2 - t1) > 100000;
	}

	static bool check_process_debug_flags()
	{
		auto NtQueryInformationProcess = (pNtQueryInformationProcess)
			GetProcAddress(GetModuleHandleA(SK("ntdll.dll")), SK("NtQueryInformationProcess"));
		if (!NtQueryInformationProcess) return false;

		DWORD no_debug_inherit = 0;
		NTSTATUS status = NtQueryInformationProcess(
			GetCurrentProcess(),
			(PROCESSINFOCLASS)31,
			&no_debug_inherit,
			sizeof(no_debug_inherit),
			nullptr);

		return NT_SUCCESS(status) && no_debug_inherit == 0;
	}

	// --- public API ---

	bool is_debugger_detected()
	{
		if (check_is_debugger_present())  return true;
		if (check_remote_debugger())      return true;
		if (check_nt_global_flag())       return true;
		if (check_debug_port())           return true;
		if (check_debug_object_handle())  return true;
		if (check_hardware_breakpoints()) return true;
		if (check_process_debug_flags())  return true;
		if (check_timing())               return true;
		return false;
	}

	void hide_thread()
	{
		auto NtSetInformationThread = (pNtSetInformationThread)
			GetProcAddress(GetModuleHandleA(SK("ntdll.dll")), SK("NtSetInformationThread"));
		if (!NtSetInformationThread) return;

		NtSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)0x11, nullptr, 0);
	}

	void start_monitor()
	{
		if (s_running.exchange(true))
			return;

		s_thread = std::thread([]()
		{
			hide_thread();

			while (s_running.load())
			{
				if (is_debugger_detected())
				{
					// fire-and-forget tampering report
					auth::send_report("", SK("debugger_detected"),
						SK("Anti-debug monitor triggered"));

					*(volatile int*)0 = 0;
				}

				LARGE_INTEGER freq, now;
				QueryPerformanceFrequency(&freq);
				QueryPerformanceCounter(&now);
				DWORD jitter = (DWORD)(now.QuadPart % 1000) + 2000;
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
