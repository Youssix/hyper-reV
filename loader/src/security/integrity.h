#pragma once
#include <cstdint>

namespace integrity
{
	// compute and store baseline hash of our .text section
	void capture_baseline();

	// compute and store baselines for .text + .rdata + IAT
	void capture_all_baselines();

	// verify .text section hasn't been patched
	bool verify_text_section();

	// verify .rdata section hasn't been patched
	bool verify_rdata_section();

	// verify IAT entries haven't been redirected
	bool verify_iat();

	// check if critical WinAPI functions have been hooked (inline hooks)
	bool check_api_hooks();

	// run all integrity checks
	bool verify_all();

	// fast inline check — crashes immediately on failure, no return
	void inline_check();

	// thread watchdog — returns false if monitor thread died/stalled
	bool is_monitor_alive();

	// export CRCs for server-side verification (computed fresh, not cached)
	uint32_t get_text_crc();
	uint32_t get_rdata_crc();

	// start background integrity monitor
	void start_monitor();
	void stop_monitor();
}
