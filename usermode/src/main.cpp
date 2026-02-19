#include <iostream>
#include <thread>
#include <string>
#include <print>
#include <Windows.h>

#include "commands/commands.h"
#include "hook/hook.h"
#include "system/system.h"
#include "inject/inject.h"

// Cleanup injection state before exit (prevents BSOD from dangling EPT hooks)
void cleanup_before_exit()
{
	if (inject::mmaf_hook_va != 0 || inject::ksse_hook_va != 0)
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

		std::this_thread::sleep_for(std::chrono::milliseconds(25));
	}

	cleanup_before_exit();
	sys::clean_up();

	return 0;
}
