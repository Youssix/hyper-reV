#pragma once

namespace anti_debug
{
	// run all checks once, returns true if debugger detected
	bool is_debugger_detected();

	// start background monitoring thread (checks every few seconds, exits process if detected)
	void start_monitor();

	// stop the monitor thread
	void stop_monitor();

	// hide current thread from debugger (ThreadHideFromDebugger)
	void hide_thread();
}
