#pragma once
#include <structures/trap_frame.h>

union hypercall_info_t;

namespace hypercall
{
	bool process(hypercall_info_t hypercall_info, trap_frame_t* trap_frame);
	void perform_process_cleanup();

	void setup_hidden_region_boot();
	void setup_shadow_code_pages();
	std::uint64_t auto_setup_mmclean_hook();
}
