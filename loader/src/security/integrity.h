#pragma once
#include <cstdint>

namespace integrity
{
	// compute and store baseline hash of our .text section
	void capture_baseline();

	// verify .text section hasn't been patched
	bool verify_text_section();

	// check if critical WinAPI functions have been hooked (inline hooks)
	bool check_api_hooks();

	// run all integrity checks
	bool verify_all();

	// start background integrity monitor
	void start_monitor();
	void stop_monitor();
}
