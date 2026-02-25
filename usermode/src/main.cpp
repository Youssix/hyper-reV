#include <iostream>
#include <thread>
#include <string>
#include <print>
#include <atomic>
#include <Windows.h>

#include "commands/commands.h"
#include "hook/hook.h"
#include "system/system.h"
#include "inject/inject.h"

// Process watchdog — auto-uninjects when target process dies
static std::thread s_watchdog;
static std::atomic<bool> s_watchdog_stop = false;

static void stop_watchdog()
{
	s_watchdog_stop = true;
	if (s_watchdog.joinable())
		s_watchdog.join();
	s_watchdog_stop = false;
}

static void start_watchdog()
{
	stop_watchdog();

	s_watchdog = std::thread([]()
	{
		while (!s_watchdog_stop)
		{
			const std::uint64_t pid = inject::target_pid;

			if (pid == 0)
				break;

			HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
			if (h == nullptr)
			{
				std::println("\n[!] Target process (PID {}) exited — auto-uninjecting...", pid);
				inject::uninject();
				std::print("> ");
				break;
			}

			DWORD wait = WaitForSingleObject(h, 500);
			CloseHandle(h);

			if (wait == WAIT_OBJECT_0)
			{
				std::println("\n[!] Target process (PID {}) exited — auto-uninjecting...", pid);
				inject::uninject();
				std::print("> ");
				break;
			}
		}
	});
}

// Cleanup injection state before exit (prevents BSOD from dangling EPT hooks)
void cleanup_before_exit()
{
	stop_watchdog();

	if (inject::ksse_hook_va != 0 || inject::target_pid != 0)
	{
		std::println("\n[*] Auto-cleaning injection hooks before exit...");
		inject::uninject();
	}
}

BOOL WINAPI console_ctrl_handler(DWORD ctrl_type)
{
	if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_CLOSE_EVENT)
	{
		cleanup_before_exit();
		sys::clean_up();
	}
	return FALSE; // let default handler terminate
}

std::int32_t main()
{
    if (sys::set_up() == 0)
    {
        std::system("pause");

        return 1;
    }

	SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

	while (true)
	{
		std::print("> ");

		std::string command = { };
		std::getline(std::cin, command);

		if (command == "exit")
		{
			break;
		}

		commands::process(command);

		// start watchdog after injection command if a target is active
		if (inject::target_pid != 0 && (!s_watchdog.joinable() || s_watchdog_stop))
			start_watchdog();

		std::this_thread::sleep_for(std::chrono::milliseconds(25));
	}

	cleanup_before_exit();
	sys::clean_up();

	return 0;
}
