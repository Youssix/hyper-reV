#include "violation.h"
#include "mtf_context.h"
#include "../cr3/cr3.h"
#include "../cr3/pte.h"
#include "../cr3/fork_registry.h"
#include "../hook/hook_entry.h"
#include "../monitor/monitor_entry.h"

#include "../../arch/arch.h"
#include "../../logs/logs.h"
#include "../../crt/crt.h"
#include "../../structures/virtual_address.h"
#include "../../cr3_intercept.h"

#ifdef _INTELMACHINE
namespace slat::violation
{
	// Per-VPID pending GPA for fork sync (checked by Hook 2 after Hyper-V handler)
	std::uint64_t fork_sync_pending_gpa[mtf::max_contexts] = { };
}
#endif

std::uint8_t slat::violation::process()
{
#ifdef _INTELMACHINE
	const auto qualification = arch::get_exit_qualification();

	if (!qualification.caused_by_translation)
	{
		return 0;
	}

	const std::uint64_t physical_address = arch::get_guest_physical_address();

	// Check for monitored page access first (read violation)
	if (qualification.read_access && !qualification.execute_access)
	{
		monitor::entry_t* const monitor_entry = monitor::entry_t::find(physical_address >> 12);

		if (monitor_entry != nullptr)
		{
			// Log the access
			trap_frame_log_t log_entry = { };
			log_entry.rip = arch::get_guest_rip();
			log_entry.cr3 = arch::get_guest_cr3().flags;

			// Store physical address in r8 for identification
			log_entry.r8 = physical_address;

			// Store access count in r9
			log_entry.r9 = monitor_entry->access_count();

			logs::add_log(log_entry);

			// Increment access count
			monitor_entry->increment_access_count();

			// Restore read access so the operation can proceed
			virtual_address_t gpa = { .address = physical_address };
			slat_pte* const target_pte = get_pte(hyperv_cr3(), gpa);

			if (target_pte != nullptr)
			{
				target_pte->read_access = 1;
			}

			return 1;
		}
	}

	// Diagnostic: track EPT violations on a watched PFN
	const std::uint64_t faulting_pfn = physical_address >> 12;

	if (cr3_intercept::diag_watch_pfn != 0 && faulting_pfn == cr3_intercept::diag_watch_pfn)
	{
		if (qualification.execute_access)
			cr3_intercept::diag_watch_pfn_exec_count++;
		else
			cr3_intercept::diag_watch_pfn_rw_count++;
	}

	const hook::entry_t* const hook_entry = hook::entry_t::find(faulting_pfn);

	if (hook_entry == nullptr)
	{
		// Check if this violation is in a forked region — queue for sync after Hyper-V handles it
		const virtual_address_t gpa = { .address = physical_address };

		if (fork_registry::is_in_forked_region(gpa.pml4_idx, gpa.pdpt_idx, gpa.pd_idx))
		{
			const std::uint16_t vpid = arch::get_current_vpid();

			if (vpid < mtf::max_contexts)
			{
				fork_sync_pending_gpa[vpid] = physical_address;
			}
		}

		// Always restore hyperv_cr3 before falling through to Hyper-V.
		// If we're on hook_cr3 (from a previous toggle), Hyper-V doesn't
		// recognize that EPTP and will VMRESUME without fixing -> loop -> BSOD.
		set_cr3(hyperv_cr3());
		return 0;
	}

	if (qualification.execute_access)
	{
		set_cr3(hyperv_cr3());

		// page is now --x, and with shadow pfn

		// Usermode EPT hooks: the shadow page JMPs to a detour in hidden memory
		// (PML4[reserved_index]), which only exists in the clone CR3.
		// If the game thread is under the original CR3, the JMP would #PF.
		// MmAccessFault can't fix this because KPTI overwrites our CR3 swap
		// on the return-to-user path (MOV CR3, user_dtb happens AFTER MmAccessFault
		// returns but BEFORE IRETQ), causing an infinite #PF loop -> bugcheck 0x139.
		// Fix: swap guest CR3 to clone here in VMX root, before VMRESUME.
		if (cr3_intercept::enabled)
		{
			if (cr3_intercept::find_usermode_ept_hook((physical_address >> 12) << 12) != nullptr)
			{
				const cr3 guest_cr3 = arch::get_guest_cr3();
				const std::uint64_t guest_pfn = guest_cr3.flags & cr3_intercept::cr3_pfn_mask;

				const bool is_original = guest_pfn == (cr3_intercept::target_original_cr3 & cr3_intercept::cr3_pfn_mask);
				const bool is_user_dtb = cr3_intercept::target_user_cr3 != 0
					&& guest_pfn == (cr3_intercept::target_user_cr3 & cr3_intercept::cr3_pfn_mask);

				if (is_original || is_user_dtb)
				{
					arch::set_guest_cr3({ .flags = cr3_intercept::cloned_cr3_value });
					arch::invalidate_vpid_current();
				}
			}
		}
	}
	else if (qualification.write_access)
	{
		// Write to hooked page on hook_cr3 (R-- permission)
		// Grant temp RW, arm MTF to restore R-- and sync shadow after one instruction
		const std::uint16_t vpid = arch::get_current_vpid();

		if (vpid >= mtf::max_contexts)
		{
			// Cannot arm MTF for this VPID — fall through to Hyper-V
			set_cr3(hyperv_cr3());
			return 0;
		}

		const virtual_address_t gpa = { .address = physical_address };

		slat_pte* const hook_pte = get_pte(hook_cr3(), gpa);

		if (hook_pte != nullptr)
		{
			const std::uint64_t saved_flags = hook_pte->flags;

			// Grant temporary write access
			hook_pte->read_access = 1;
			hook_pte->write_access = 1;

			// Arm MTF context for this LP
			mtf::arm(vpid, physical_address, hook_pte, saved_flags);

			// Enable monitor trap flag — fires after next guest instruction
			arch::enable_mtf();

			// Flush EPT cache so the temp permission takes effect
			flush_current_logical_processor_cache();
		}
	}
	else
	{
		set_cr3(hook_cr3());

		// page is now r--, and with original pfn
	}
#else
	const vmcb_t* const vmcb = arch::get_vmcb();

	const npf_exit_info_1 npf_info = { .flags = vmcb->control.first_exit_info };

	if (npf_info.present == 0 || npf_info.execute_access == 0)
	{
		return 0;
	}

	const std::uint64_t physical_address = vmcb->control.second_exit_info;

	const hook::entry_t* const hook_entry = hook::entry_t::find(physical_address >> 12);

	const cr3 hook_slat_cr3 = hook_cr3();

	if (hook_entry == nullptr)
	{
		if (vmcb->control.nested_cr3.flags == hook_slat_cr3.flags)
		{
			set_cr3(hyperv_cr3());

			return 1;
		}

		return 0;
	}

	set_cr3(hook_slat_cr3);
#endif

	return 1;
}
