#pragma once
#include <ia32-doc/ia32.hpp>
#include <cstdint>

namespace slat
{
	cr3 hyperv_cr3();
	cr3 hook_cr3();

	cr3 get_cr3();
	void set_cr3(cr3 slat_cr3);

	// Check if an EPTP belongs to our VTL 0 context (hyperv_cr3 or hook_cr3 PML4)
	// Returns false for VTL 1 or unknown EPTPs — these must not be modified
	bool is_our_eptp(cr3 current_eptp);

	void flush_current_logical_processor_cache(std::uint8_t has_slat_cr3_changed = 0);
	void flush_all_logical_processors_cache();

	void set_up_hyperv_cr3();
	void set_up_hook_cr3();
} 
