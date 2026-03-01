#include "violation.h"
#include "mtf_context.h"
#include "../cr3/cr3.h"
#include "../cr3/pte.h"
#include "../cr3/fork_registry.h"
#include "../hook/hook_entry.h"
#include "../monitor/monitor_entry.h"

#include "../../arch/arch.h"
#include "../../logs/logs.h"
#include "../../logs/serial.h"
#include "../../crt/crt.h"
#include "../../structures/virtual_address.h"
#include "../../cr3_intercept.h"

#ifdef _INTELMACHINE
namespace slat::violation
{
	// Per-VPID pending GPA for fork sync (checked by Hook 2 after Hyper-V handler)
	std::uint64_t fork_sync_pending_gpa[mtf::max_contexts] = { };

	// One-shot serial log flags (fire once per type, then silent)
	static volatile std::uint8_t logged_write = 0;
	static volatile std::uint8_t logged_self_read = 0;
	static volatile std::uint8_t logged_ext_read = 0;
	static volatile std::uint8_t logged_exec = 0;
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

		// Restore hyperv_cr3 before falling through to Hyper-V — unless Hook 3 is active
		// (Hook 3 keeps all VPs on hook_cr3; HvSetEptPointer shellcode handles EPTP).
		if (!slat::is_vmwrite_hook_active())
			set_cr3(hyperv_cr3());
		return 0;
	}

	if (qualification.execute_access)
	{
		// New scheme: hook_cr3 has shadow PFN --X, so execute violations on hooked
		// pages should not occur. Defensive fallback — flush and let retry.
		if (!logged_exec) { logged_exec = 1; serial::print("[ept] EXEC violation (unexpected) GPA="); serial::print_hex(physical_address); serial::println(""); }
		flush_current_logical_processor_cache();
	}
	else if (qualification.write_access)
	{
		// Write to hooked page on hook_cr3 (shadow --X, no W).
		// Use per-VP EPTP swap (NOT shared PTE modification) to avoid multi-VP race:
		// PTE modification sets RW- (removes X) → other VPs executing on same page
		// get infinite EPT execute violations until MTF restores --X → cascade freeze.
		// EPTP swap: hyperv_cr3 has original page RWX (2MB identity), per-VP only.
		// MTF handler syncs original→shadow after write completes, then swaps back.
		const std::uint16_t vpid = arch::get_current_vpid();

		if (vpid >= mtf::max_contexts)
		{
			set_cr3(hyperv_cr3());
			return 0;
		}

		if (!logged_write) { logged_write = 1; serial::print("[ept] WRITE violation GPA="); serial::print_hex(physical_address); serial::print(" origPFN="); serial::print_hex(hook_entry->original_pfn()); serial::println(""); }

		set_cr3(hyperv_cr3());  // includes INVEPT
		mtf::arm(vpid, physical_address, nullptr, 0, 1);
		arch::enable_mtf();
	}
	else
	{
		// Read on hooked page on hook_cr3 (shadow --X, no R).
		const std::uint64_t guest_rip = arch::get_guest_rip();
		const std::uint64_t guest_linear = arch::get_guest_linear_address();
		const std::uint64_t rip_page = guest_rip & ~0xFFFull;
		const std::uint64_t fault_page = guest_linear & ~0xFFFull;

		const std::uint16_t vpid = arch::get_current_vpid();

		if (vpid >= mtf::max_contexts)
		{
			set_cr3(hyperv_cr3());
			return 0;
		}

		if (rip_page == fault_page)
		{
			// SELF-READ: code on shadow page reading its own data (RIP-relative constants, strings).
			// Keep shadow PFN, add Read permission → R-X for 1 instruction.
			// Safe for multi-VP: R-X keeps X (other VPs can still execute).
			if (!logged_self_read) { logged_self_read = 1; serial::print("[ept] SELF-READ violation GPA="); serial::print_hex(physical_address); serial::print(" RIP="); serial::print_hex(guest_rip); serial::println(""); }

			virtual_address_t gpa = { .address = physical_address };
			slat_pte* const pte = get_pte(hook_cr3(), gpa);
			if (pte)
			{
				const std::uint64_t saved = pte->flags;
				pte->read_access = 1;  // R-X (was --X)
				mtf::arm(vpid, physical_address, pte, saved, 0);
				arch::enable_mtf();
				flush_current_logical_processor_cache();  // needed: PTE change, no set_cr3
			}
		}
		else
		{
			// EXTERNAL READ: different page reading our shadow.
			// Use per-VP EPTP swap (NOT shared PTE modification) to avoid multi-VP race:
			// PTE modification sets R-- (removes X) → other VPs executing on same page
			// get infinite EPT execute violations until MTF restores --X → cascade freeze.
			// EPTP swap: hyperv_cr3 has original page RWX (2MB identity), per-VP only.
			// Stealth: reader sees original CC bytes (correct — shadow = our code, hidden).
			if (!logged_ext_read) { logged_ext_read = 1; serial::print("[ept] EXT-READ violation GPA="); serial::print_hex(physical_address); serial::print(" RIP="); serial::print_hex(guest_rip); serial::println(""); }

			set_cr3(hyperv_cr3());  // includes INVEPT
			mtf::arm(vpid, physical_address, nullptr, 0, 0);
			arch::enable_mtf();
		}
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
