#include "arch/arch.h"
#include "hypercall/hypercall.h"
#include "hypercall/hypercall_def.h"
#include "slat/slat.h"
#include "slat/cr3/cr3.h"
#include "slat/violation/violation.h"
#include "slat/violation/mtf_context.h"
#include "interrupts/interrupts.h"
#include "cr3_intercept.h"
#include "memory_manager/memory_manager.h"
#include "logs/serial.h"
#include <structures/trap_frame.h>
#include <ia32-doc/ia32.hpp>
#include <cstdint>
#include <intrin.h>

void process_first_vmexit();

// Set by process_first_vmexit() in Hook 2 after all subsystems are initialized
extern "C" volatile std::uint8_t hook2_initialized;


extern "C" std::uint8_t vmexit_entry_fast_handler(trap_frame_t* const trap_frame)
{
    // Capture entry timestamp for TSC compensation (used by CPUID path when CR8==0xF).
    // Must be first — measures ALL our C handler overhead, not just the CPUID branch.
    const std::uint64_t handler_tsc_enter = __rdtsc();

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

    // EPTP management: hook_cr3 for target process ONLY, hyperv_cr3 for everyone else.
    // EPT hooks redirect to hidden region (PML4[hidden]) which only exists in the target
    // process's cloned CR3. Non-target on hook_cr3 → #PF → MmAccessFault hook → JMP hidden
    // → #PF → infinite recursion → double fault (0x7F Arg1=8, proven by crash dump).
    //
    // For fall-through exits (return 0): MUST restore hyperv_cr3 — HV expects its own EPTP.
    const cr3 hook_eptp = slat::hook_cr3();
    const bool need_eptp_management = hook_eptp.flags != 0 && slat::is_hook_cr3_ready();
    const bool hook3_active = slat::is_vmwrite_hook_active();
    bool on_hook_cr3_now = false;

    if (need_eptp_management)
    {
        // Check if the target process is running on this VP
        const cr3 guest_cr3 = arch::get_guest_cr3();
        const std::uint64_t guest_pfn = guest_cr3.flags & cr3_intercept::cr3_pfn_mask;

        const bool is_target = cr3_intercept::enabled &&
            (guest_pfn == (cr3_intercept::target_original_cr3 & cr3_intercept::cr3_pfn_mask) ||
             guest_pfn == (cr3_intercept::cloned_cr3_value & cr3_intercept::cr3_pfn_mask) ||
             (cr3_intercept::target_user_cr3 != 0 &&
              guest_pfn == (cr3_intercept::target_user_cr3 & cr3_intercept::cr3_pfn_mask)));

        if (is_target && entry_eptp.address_of_page_directory != hook_eptp.address_of_page_directory)
        {
            // Target process on hyperv_cr3 → swap to hook_cr3 (hooks visible)
            cr3 bootstrap = entry_eptp;
            bootstrap.address_of_page_directory = hook_eptp.address_of_page_directory;
            arch::set_slat_cr3(bootstrap);
            // Lazy INVEPT: only flush if hook_cr3 EPT was modified since last INVEPT on this LP
            {
                const auto vpid = arch::get_current_vpid();
                if (vpid < slat::max_logical_processors && slat::hook_cr3_ept_dirty[vpid])
                {
                    slat::flush_current_logical_processor_cache(1);
                    slat::hook_cr3_ept_dirty[vpid] = 0;
                }
            }
            // slat::flush_current_logical_processor_cache(1);
            on_hook_cr3_now = true;
        }
        else if (is_target && entry_eptp.address_of_page_directory == hook_eptp.address_of_page_directory)
        {
            on_hook_cr3_now = true;
        }
        else if (!is_target && !hook3_active && entry_eptp.address_of_page_directory == hook_eptp.address_of_page_directory)
        {
            // Non-target process on hook_cr3 → swap back to hyperv_cr3 (prevent #PF on hidden region)
            // When Hook 3 active: all hooks use shadow code pages (kernel VA, all processes safe)
            cr3 restore = entry_eptp;
            restore.address_of_page_directory = slat::hyperv_cr3().address_of_page_directory;
            arch::set_slat_cr3(restore);
            // Lazy INVEPT: only flush if hook_cr3 EPT was modified since last INVEPT on this LP
            {
                const auto vpid = arch::get_current_vpid();
                if (vpid < slat::max_logical_processors && slat::hook_cr3_ept_dirty[vpid])
                {
                    slat::flush_current_logical_processor_cache(1);
                    slat::hook_cr3_ept_dirty[vpid] = 0;
                }
            }
            // slat::flush_current_logical_processor_cache(1);
        }
        // else: non-target on hyperv_cr3 → already correct, do nothing
    }

    // Deferred MmClean cleanup: CPUID(22) set this flag on a previous VMEXIT.
    // The MmClean shellcode has since finished executing and returned to original code.
    // Safe to remove all EPT hooks now (including MmClean's own shadow page).
    if (cr3_intercept::cleanup_hook::cleanup_pending)
    {
        if (_InterlockedExchange8(
            reinterpret_cast<volatile char*>(&cr3_intercept::cleanup_hook::cleanup_pending), 0))
        {
            hypercall::perform_process_cleanup();
        }
        // Fall through: enabled=0 now, CR3/hook logic naturally skipped
    }

    // CR3 swap is in Hook 2 ONLY (post-handler), NOT here.
    // Swapping before exit processing would expose clone CR3 to HV's handler
    // for fall-through exits (return 0) — HV doesn't know about the clone,
    // causing TLB/address-space state inconsistency → CLOCK_WATCHDOG_TIMEOUT.

    const std::uint64_t exit_reason = arch::get_vmexit_reason();

#ifdef _INTELMACHINE
    if (arch::is_mtf(exit_reason))
    {
        if (slat::mtf::process() == 1)
        {
            return 1;
        }

        // Not our MTF — fall through to Hyper-V (restore hyperv_cr3 first)
        // When Hook 3 active: stay on hook_cr3, HV handles MTF fine on shallow copy
        if (on_hook_cr3_now && !hook3_active)
        {
            cr3 restore = arch::get_slat_cr3();
            restore.address_of_page_directory = slat::hyperv_cr3().address_of_page_directory;
            arch::set_slat_cr3(restore);
            // Lazy INVEPT: only flush if hook_cr3 EPT was modified since last INVEPT on this LP
            {
                const auto vpid = arch::get_current_vpid();
                if (vpid < slat::max_logical_processors && slat::hook_cr3_ept_dirty[vpid])
                {
                    slat::flush_current_logical_processor_cache(1);
                    slat::hook_cr3_ept_dirty[vpid] = 0;
                }
            }
        }
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

            const bool rip_redirected = hypercall::process(hypercall_info, trap_frame);

            arch::set_guest_rsp(trap_frame->rsp);
            if (!rip_redirected)
                arch::advance_guest_rip();

            return 1;
        }

        // [BISECT] TSC compensation disabled for debugging
        /*
        // TSC compensation only at IRQL 15 (CR8=0xF).
        // EAC raises to IRQL 15 before RDTSC/CPUID/RDTSC timing — normal kernel code never
        // does CPUID at that IRQL. Avoids TSC_OFFSET drift from compensating every CPUID.
        // Guest CR8 = VTPR[7:4] in the Virtual-APIC page.
        const auto* vtpr = reinterpret_cast<const std::uint8_t*>(
            memory_manager::map_host_physical(arch::get_virtual_apic_address())) + 0x80;
        const std::uint8_t guest_cr8 = *vtpr >> 4;

        if (guest_cr8 == 0xF)
        {
            const std::uint64_t tsc_now = __rdtsc();
            constexpr std::int64_t asm_overhead_before = 120;
            constexpr std::int64_t asm_overhead_after = 130;
            const std::int64_t c_handler_time = static_cast<std::int64_t>(tsc_now - handler_tsc_enter);
            arch::adjust_tsc_offset(-(c_handler_time + asm_overhead_before + asm_overhead_after));
        }
        */
    }
    // [BISECT] VMX instruction handler disabled for debugging
    /*
    else if (exit_reason >= VMX_EXIT_REASON_EXECUTE_VMCLEAR && exit_reason <= VMX_EXIT_REASON_EXECUTE_VMXON)
    {
        arch::inject_exception(6);
        return 1;
    }
    */
    else if (arch::is_non_maskable_interrupt_exit(exit_reason) == 1)
    {
        interrupts::process_nmi();
        // fall through to Hyper-V — it needs to handle NMI re-injection/windowing
    }

    // Not handled — fall through to Hyper-V via trampoline.
    // Restore hyperv_cr3 before falling through: HV must see its own EPTP.
    // When Hook 3 active: stay on hook_cr3, HvSetEptPointer shellcode handles EPTP.
    if (on_hook_cr3_now && !hook3_active)
    {
        cr3 restore = arch::get_slat_cr3();
        restore.address_of_page_directory = slat::hyperv_cr3().address_of_page_directory;
        arch::set_slat_cr3(restore);
        // Lazy INVEPT: only flush if hook_cr3 EPT was modified since last INVEPT on this LP
        {
            const auto vpid = arch::get_current_vpid();
            if (vpid < slat::max_logical_processors && slat::hook_cr3_ept_dirty[vpid])
            {
                slat::flush_current_logical_processor_cache(1);
                slat::hook_cr3_ept_dirty[vpid] = 0;
            }
        }
    }
    return 0;
}
