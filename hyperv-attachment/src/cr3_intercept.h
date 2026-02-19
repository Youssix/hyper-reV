#pragma once
#include <cstdint>
#include <ia32-doc/ia32.hpp>
#include <structures/trap_frame.h>
#include "memory_manager/memory_manager.h"
#include "slat/slat.h"
#include "crt/crt.h"

namespace cr3_intercept
{
	// compare only PFN (bits 39:12), ignore PCID (bits 11:0) and reserved/noflush (bits 63:40)
	constexpr std::uint64_t cr3_pfn_mask = 0xFFFFFFFFF000ull;

	inline std::uint8_t enabled = 0;
	inline std::uint8_t enforce_active = 0; // when set, force clone CR3 at every VM exit
	inline std::uint64_t cr3_exit_count = 0;
	inline std::uint64_t cr3_swap_count = 0;
	inline std::uint64_t cr3_last_seen = 0;
	inline std::uint64_t mmaf_hit_count = 0; // incremented each time write_guest_cr3 hypercall fires (from MmAccessFault hook)
	inline std::uint64_t target_original_cr3 = 0;
	inline std::uint64_t cloned_cr3_value = 0;
	inline void* cloned_pml4_host_va = nullptr;
	inline std::uint64_t reserved_pml4e_index = 0;
	inline void* hidden_pt_host_va = nullptr;
	inline std::uint64_t target_user_cr3 = 0; // UserDirectoryTableBase value — intercepted like kernel DTB

	// syscall exit hook hijack state
	inline std::uint8_t syscall_hijack_armed = 0;
	inline std::uint64_t syscall_hijack_shellcode_va = 0;
	inline std::uint64_t saved_original_rip = 0; // saved by CPUID handler (reserved_data=7), retrieved by reserved_data=10

	inline void sync_page_tables(const std::uint64_t new_original_cr3_value)
	{
		const cr3 new_original_cr3 = { .flags = new_original_cr3_value };
		const cr3 slat_cr3 = slat::hyperv_cr3();

		const auto original_pml4 = static_cast<const pml4e_64*>(
			memory_manager::map_guest_physical(slat_cr3, new_original_cr3.address_of_page_directory << 12));

		if (original_pml4 == nullptr)
		{
			return;
		}

		const auto cloned_pml4 = static_cast<pml4e_64*>(cloned_pml4_host_va);

		for (std::uint64_t i = 0; i < 512; i++)
		{
			if (i != reserved_pml4e_index)
			{
				cloned_pml4[i].flags = original_pml4[i].flags;
			}
		}

		target_original_cr3 = new_original_cr3_value;
	}

	inline std::uint64_t read_gpr(const trap_frame_t* const trap_frame, const std::uint64_t reg)
	{
		return reinterpret_cast<const std::uint64_t*>(trap_frame)[reg];
	}

	inline void write_gpr(trap_frame_t* const trap_frame, const std::uint64_t reg, const std::uint64_t value)
	{
		reinterpret_cast<std::uint64_t*>(trap_frame)[reg] = value;
	}
}
