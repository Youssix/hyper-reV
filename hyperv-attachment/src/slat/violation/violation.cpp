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
			slat_pte* const target_pte = get_pte(hook_cr3(), gpa);

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
		// New scheme: hook_cr3 has shadow PFN --X, so execute violations on hooked
		// pages should not occur. Defensive fallback — flush and let retry.
		flush_current_logical_processor_cache();
	}
	else if (qualification.write_access)
	{
		// Write to hooked page on hook_cr3 (shadow --X, no W).
		// Swap to hyperv_cr3 where original page has RWX (2MB identity, untouched).
		set_cr3(hyperv_cr3());

		const std::uint16_t vpid = arch::get_current_vpid();

		if (vpid >= mtf::max_contexts)
		{
			// Cannot arm MTF — fall through on hyperv_cr3
			return 0;
		}

		// Arm MTF: after 1 instruction (the write), sync shadow and swap back
		mtf::arm(vpid, physical_address, nullptr, 0, 1);
		arch::enable_mtf();
		flush_current_logical_processor_cache();
	}
	else
	{
		// Read on hooked page on hook_cr3 (shadow --X, no R).
		// Swap to hyperv_cr3 where original page has RWX (shows clean original data).
		set_cr3(hyperv_cr3());

		const std::uint16_t vpid = arch::get_current_vpid();

		if (vpid >= mtf::max_contexts)
		{
			// Cannot arm MTF — fall through on hyperv_cr3
			return 0;
		}

		// Arm MTF: after 1 instruction (the read), swap back (no sync needed)
		mtf::arm(vpid, physical_address, nullptr, 0, 0);
		arch::enable_mtf();
		flush_current_logical_processor_cache();
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
