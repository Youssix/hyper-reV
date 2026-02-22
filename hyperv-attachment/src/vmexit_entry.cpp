#include "arch/arch.h"
#include "hypercall/hypercall.h"
#include "hypercall/hypercall_def.h"
#include "slat/slat.h"
#include "slat/cr3/cr3.h"
#include "slat/violation/violation.h"
#include "slat/violation/mtf_context.h"
#include "interrupts/interrupts.h"
#include "cr3_intercept.h"
#include <structures/trap_frame.h>
#include <ia32-doc/ia32.hpp>
#include <cstdint>

void process_first_vmexit();

// Set by process_first_vmexit() in Hook 2 after all subsystems are initialized
extern "C" volatile std::uint8_t hook2_initialized;

extern "C" std::uint8_t vmexit_entry_fast_handler(trap_frame_t* const trap_frame)
{
    // Don't process until Hook 2 has initialized all subsystems (EPTP, interrupts, etc.)
    // Before init: NMI bitmap is null, hyperv_slat_cr3 is {0} — touching them would crash.
    if (!hook2_initialized)
    {
        return 0;
    }

    // With VSM (Virtual Secure Mode), both VTL 0 and VTL 1 VMEXITs go through the same handler.
    // VTL 1 has a different VMCS with a different EPTP. We must NOT modify VTL 1's VMCS.
    // Only process VMEXITs where the EPTP PML4 matches our known VTL 0 EPTPs.
    const cr3 entry_eptp = arch::get_slat_cr3();

    if (!slat::is_our_eptp(entry_eptp))
    {
        return 0;
    }

    if (cr3_intercept::enabled)
    {
        arch::enable_cr3_exiting();
    }

    const std::uint64_t exit_reason = arch::get_vmexit_reason();

#ifdef _INTELMACHINE
    if (arch::is_mtf(exit_reason))
    {
        if (slat::mtf::process() == 1)
        {
            return 1;
        }

        // Not our MTF — fall through to Hyper-V
        return 0;
    }
#endif

    if (arch::is_mov_cr(exit_reason) == 1)
    {
        const vmx_exit_qualification_mov_cr qualification = arch::get_exit_qualification_mov_cr();

        if (qualification.control_register == 3)
        {
            cr3_intercept::cr3_exit_count++;

            const std::uint64_t gpr_index = qualification.general_purpose_register;

            if (qualification.access_type == VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR)
            {
                const std::uint64_t raw_cr3_value = (gpr_index == VMX_EXIT_QUALIFICATION_GENREG_RSP)
                    ? arch::get_guest_rsp()
                    : cr3_intercept::read_gpr(trap_frame, gpr_index);

                const std::uint64_t new_cr3_value = raw_cr3_value & ~(1ull << 63);

                cr3_intercept::cr3_last_seen = new_cr3_value;

                if (cr3_intercept::enabled)
                {
                    const std::uint64_t new_pfn = new_cr3_value & cr3_intercept::cr3_pfn_mask;
                    const bool is_kernel_dtb = new_pfn == (cr3_intercept::target_original_cr3 & cr3_intercept::cr3_pfn_mask);
                    const bool is_user_dtb = cr3_intercept::target_user_cr3 != 0 &&
                        new_pfn == (cr3_intercept::target_user_cr3 & cr3_intercept::cr3_pfn_mask);

                    if (is_kernel_dtb || is_user_dtb)
                    {
                        // Sync PML4 entries from original to clone before swap.
                        // The clone shares PDPT/PD/PT with the original, but the PML4
                        // is a separate copy. Windows may have added/modified PML4 entries
                        // (new DLL loads, heap regions) since the last sync.
                        // Only sync from kernel DTB (has complete PML4 with user+kernel entries).
                        if (is_kernel_dtb)
                        {
                            cr3_intercept::sync_page_tables(cr3_intercept::target_original_cr3);
                        }

                        arch::set_guest_cr3({ .flags = cr3_intercept::cloned_cr3_value });
                        cr3_intercept::cr3_swap_count++;
                    }
                    else
                    {
                        arch::set_guest_cr3({ .flags = new_cr3_value });
                    }
                }
                else
                {
                    arch::set_guest_cr3({ .flags = new_cr3_value });
                }

                arch::invalidate_vpid_current();
            }
            else if (qualification.access_type == VMX_EXIT_QUALIFICATION_ACCESS_MOV_FROM_CR)
            {
                const cr3 current_cr3 = arch::get_guest_cr3();

                const std::uint64_t value_to_return = (cr3_intercept::enabled &&
                    (current_cr3.flags & cr3_intercept::cr3_pfn_mask) == (cr3_intercept::cloned_cr3_value & cr3_intercept::cr3_pfn_mask))
                    ? cr3_intercept::target_original_cr3
                    : current_cr3.flags;

                if (gpr_index == VMX_EXIT_QUALIFICATION_GENREG_RSP)
                {
                    arch::set_guest_rsp(value_to_return);
                }
                else
                {
                    cr3_intercept::write_gpr(trap_frame, gpr_index, value_to_return);
                }
            }

            arch::advance_guest_rip();
            return 1;
        }
    }
    else if (arch::is_slat_violation(exit_reason) == 1)
    {
        cr3_intercept::slat_violation_count++;

        if (slat::violation::process() == 1)
        {
            return 1;
        }

        // violation::process returned 0 (no hook entry) — it already reset EPTP to hyperv_cr3
        return 0;
    }
    else if (arch::is_cpuid(exit_reason) == 1)
    {
        const hypercall_info_t hypercall_info = { .value = trap_frame->rcx };

        if (hypercall_info.primary_key == hypercall_primary_key && hypercall_info.secondary_key == hypercall_secondary_key)
        {
            trap_frame->rsp = arch::get_guest_rsp();

            hypercall::process(hypercall_info, trap_frame);

            arch::set_guest_rsp(trap_frame->rsp);
            arch::advance_guest_rip();

            return 1;
        }
    }
    else if (arch::is_non_maskable_interrupt_exit(exit_reason) == 1)
    {
        interrupts::process_nmi();
        // fall through to Hyper-V — it needs to handle NMI re-injection/windowing
    }

    // Not handled — fall through to Hyper-V via trampoline.
    // EPTP reset to partition EPTP will be added later when hooks are active.
    return 0;
}
