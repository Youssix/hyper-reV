#pragma once
#include <ia32-doc/ia32.hpp>
#include <cstdint>

#include "amd_def.h"

namespace arch
{
	std::uint64_t get_vmexit_reason();
	std::uint8_t is_cpuid(std::uint64_t vmexit_reason);
	std::uint8_t is_slat_violation(std::uint64_t vmexit_reason);

	std::uint8_t is_non_maskable_interrupt_exit(std::uint64_t vmexit_reason);
	std::uint8_t is_mov_cr(std::uint64_t vmexit_reason);

	void enable_cr3_exiting();
	void disable_cr3_exiting();

	cr3 get_guest_cr3();
	void set_guest_cr3(cr3 guest_cr3);

	cr3 get_slat_cr3();
	void set_slat_cr3(cr3 slat_cr3);

	std::uint64_t get_guest_rsp();
	void set_guest_rsp(std::uint64_t guest_rsp);

	std::uint64_t get_guest_rip();
	void set_guest_rip(std::uint64_t guest_rip);

	void advance_guest_rip();

#ifdef _INTELMACHINE
	vmx_exit_qualification_ept_violation get_exit_qualification();
	vmx_exit_qualification_mov_cr get_exit_qualification_mov_cr();

	std::uint64_t get_guest_physical_address();

	void invalidate_vpid_current();
#else
	vmcb_t* get_vmcb();
	void parse_vmcb_gadget(const std::uint8_t* get_vmcb_gadget);
#endif
}
