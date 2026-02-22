#include "anti_debug.h"
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <thread>
#include <atomic>

#pragma comment(lib, "ntdll.lib")

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
		// PEB->NtGlobalFlag: debugger sets FLG_HEAP_ENABLE_TAIL_CHECK |
		// FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS (0x70)
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
			GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
		if (!NtQueryInformationProcess) return false;

		DWORD_PTR debug_port = 0;
		NTSTATUS status = NtQueryInformationProcess(
			GetCurrentProcess(),
			(PROCESSINFOCLASS)7, // ProcessDebugPort
			&debug_port,
			sizeof(debug_port),
			nullptr);

		return NT_SUCCESS(status) && debug_port != 0;
	}

	static bool check_debug_object_handle()
	{
		auto NtQueryInformationProcess = (pNtQueryInformationProcess)
			GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
		if (!NtQueryInformationProcess) return false;

		HANDLE debug_obj = nullptr;
		NTSTATUS status = NtQueryInformationProcess(
			GetCurrentProcess(),
			(PROCESSINFOCLASS)30, // ProcessDebugObjectHandle
			&debug_obj,
			sizeof(debug_obj),
			nullptr);

		// if STATUS_SUCCESS, debugger is attached; STATUS_PORT_NOT_SET means no debugger
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
		// rdtsc timing check: debugger stepping causes large deltas
		unsigned __int64 t1 = __rdtsc();

		// do a small amount of work
		volatile int dummy = 0;
		for (int i = 0; i < 100; i++)
			dummy += i;

		unsigned __int64 t2 = __rdtsc();

		// threshold: a normal loop takes <10k cycles, debugger stepping takes 100k+
		return (t2 - t1) > 100000;
	}

	static bool check_process_debug_flags()
	{
		auto NtQueryInformationProcess = (pNtQueryInformationProcess)
			GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
		if (!NtQueryInformationProcess) return false;

		DWORD no_debug_inherit = 0;
		NTSTATUS status = NtQueryInformationProcess(
			GetCurrentProcess(),
			(PROCESSINFOCLASS)31, // ProcessDebugFlags
			&no_debug_inherit,
			sizeof(no_debug_inherit),
			nullptr);

		// if NoDebugInherit == 0, debugger is present
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
			GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
		if (!NtSetInformationThread) return;

		// ThreadHideFromDebugger = 0x11
		NtSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)0x11, nullptr, 0);
	}

	void start_monitor()
	{
		if (s_running.exchange(true))
			return; // already running

		s_thread = std::thread([]()
		{
			hide_thread();

			while (s_running.load())
			{
				if (is_debugger_detected())
				{
					// detected: corrupt memory and exit to make analysis harder
					// overwrite our own PEB and exit
					*(volatile int*)0 = 0;
				}

				// check every 2-3 seconds with jitter
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
