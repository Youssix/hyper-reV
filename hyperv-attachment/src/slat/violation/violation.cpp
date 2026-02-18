#include "violation.h"
#include "../cr3/cr3.h"
#include "../cr3/pte.h"
#include "../hook/hook_entry.h"
#include "../monitor/monitor_entry.h"

#include "../../arch/arch.h"
#include "../../logs/logs.h"
#include "../../crt/crt.h"
#include "../../structures/virtual_address.h"

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

	const hook::entry_t* const hook_entry = hook::entry_t::find(physical_address >> 12);

	if (hook_entry == nullptr)
	{
		// potentially newly added executable page
		if (qualification.execute_access)
		{
			set_cr3(hyperv_cr3());
		}

		return 0;
	}

	if (qualification.execute_access)
	{
		set_cr3(hyperv_cr3());

		// page is now --x, and with shadow pfn
	}
	else
	{
		set_cr3(hook_cr3());

		// page is now rw-, and with original pfn
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
