#include "arch/arch.h"
#include "hypercall/hypercall.h"
#include "hypercall/hypercall_def.h"
#include "memory_manager/memory_manager.h"
#include "memory_manager/heap_manager.h"
#include "logs/logs.h"
#include "structures/trap_frame.h"
#include <ia32-doc/ia32.hpp>
#include <cstdint>

#include "crt/crt.h"
#include "interrupts/interrupts.h"
#include "slat/slat.h"
#include "slat/cr3/cr3.h"
#include "slat/cr3/fork_registry.h"
#include "slat/violation/violation.h"
#include "slat/violation/mtf_context.h"
#include "cr3_intercept.h"

#include <intrin.h>

typedef std::uint64_t(*vmexit_handler_t)(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4);

extern "C"
{
    void vmexit_entry_hook_stub();
    std::uint64_t original_vmexit_entry_trampoline = 0;
}

namespace
{
    std::uint8_t* original_vmexit_handler = nullptr;
    std::uint64_t uefi_boot_physical_base_address = 0;
    std::uint64_t uefi_boot_image_size = 0;
}

void clean_up_uefi_boot_image()
{
    // todo: check if windows has used this reclaimed memory
    const auto mapped_uefi_boot_base = static_cast<std::uint8_t*>(memory_manager::map_host_physical(uefi_boot_physical_base_address));

    crt::set_memory(mapped_uefi_boot_base, 0, uefi_boot_image_size);
}

// Flag for fast handler: don't process exits until Hook 2 init is done
extern "C" volatile std::uint8_t hook2_initialized = 0;

void process_first_vmexit()
{
    // Atomic guard: only one core runs init, others skip entirely.
    static volatile long is_first_vmexit = 1;

    if (_InterlockedCompareExchange(&is_first_vmexit, 0, 1) == 1)
    {
        slat::process_first_vmexit();
        interrupts::set_up();

        clean_up_uefi_boot_image();

        // Boot-time hidden region — allocate page tables now (doesn't need ntoskrnl).
        // PML4 entry auto-inserted into clone by sync_page_tables later.
        // [BISECT] hypercall::setup_hidden_region_boot();

        // Signal fast handler that all subsystems are ready
        hook2_initialized = 1;
    }
}

std::uint64_t vmexit_handler_detour(const std::uint64_t a1, const std::uint64_t a2, const std::uint64_t a3, const std::uint64_t a4)
{
#ifdef _INTELMACHINE
    // Hook 2 runs for ALL VMEXITs (VTL 0 + VTL 1). Init must run regardless of VTL.
    process_first_vmexit();

    // Deferred MmClean cleanup: pick up flag set by CPUID(22) on previous VMEXIT.
    // Hook 1 also checks this, but only for its 5 filtered exit types.
    // Hook 2 covers all other VMEXITs (EXTERNAL_INTERRUPT, etc.).
    if (cr3_intercept::cleanup_hook::cleanup_pending)
    {
        if (_InterlockedExchange8(
            reinterpret_cast<volatile char*>(&cr3_intercept::cleanup_hook::cleanup_pending), 0))
        {
            const auto result = reinterpret_cast<vmexit_handler_t>(original_vmexit_handler)(a1, a2, a3, a4);
            hypercall::perform_process_cleanup();
            return result;
        }
    }

    const cr3 hk_cr3 = slat::hook_cr3();

    // Fix C: Fast path — no hooks active, skip all EPTP logic
    if (hk_cr3.flags == 0)
    {
        const auto result = reinterpret_cast<vmexit_handler_t>(original_vmexit_handler)(a1, a2, a3, a4);

        return result;
    }

    // With VSM, VTL 1 VMEXITs go through the same handler but have a different VMCS/EPTP.
    // Only swap EPTP for VTL 0 VMEXITs where we're on our hook_cr3.
    // VTL 1 and hyperv_cr3 contexts pass through untouched.
    const cr3 current_eptp = arch::get_slat_cr3();

    const bool on_hook_cr3 =
        current_eptp.address_of_page_directory == hk_cr3.address_of_page_directory;

    if (on_hook_cr3)
    {
        // [BISECT STEP 15] Pure passthrough — identical to step 7 which WORKED.
        // NO swap before, NO restore after, NO guard. Just call and return.
        // If HV's handler overwrites EPTP to hyperv_cr3, VP falls off hook_cr3.
        // Re-bootstrap in bottom path (hook_cr3_ready) brings it back next VMEXIT.
        const auto result = reinterpret_cast<vmexit_handler_t>(original_vmexit_handler)(a1, a2, a3, a4);

        // Per-VMEXIT CR3 swap (ring-1 style): catch context switches after HV handler.
        if (cr3_intercept::enabled)
        {
            const cr3 guest_cr3 = arch::get_guest_cr3();
            const std::uint64_t guest_pfn = guest_cr3.flags & cr3_intercept::cr3_pfn_mask;
            const std::uint64_t clone_pfn = cr3_intercept::cloned_cr3_value & cr3_intercept::cr3_pfn_mask;

            if (guest_pfn != clone_pfn)
            {
                const std::uint64_t target_pfn = cr3_intercept::target_original_cr3 & cr3_intercept::cr3_pfn_mask;

                if (guest_pfn == target_pfn ||
                    (cr3_intercept::target_user_cr3 != 0 &&
                     guest_pfn == (cr3_intercept::target_user_cr3 & cr3_intercept::cr3_pfn_mask)))
                {
                    arch::set_guest_cr3({ .flags = cr3_intercept::cloned_cr3_value });
                    cr3_intercept::cr3_swap_count++;
                }
            }
        }

        return result;
    }

    const auto result = reinterpret_cast<vmexit_handler_t>(original_vmexit_handler)(a1, a2, a3, a4);

    // Fork sync: if Hook 1's violation handler queued a fork sync (unhandled EPT
    // violation in forked region), do the sync now. Don't write hook_cr3 to VMCS here —
    // Hook 1 re-bootstraps on next VMEXIT (writing EPTP after HV handler = crash).
    {
        const std::uint16_t vpid = arch::get_current_vpid();

        if (vpid < slat::mtf::max_contexts && slat::violation::fork_sync_pending_gpa[vpid] != 0)
        {
            slat::fork_registry::sync_forked_entry(slat::violation::fork_sync_pending_gpa[vpid]);
            slat::violation::fork_sync_pending_gpa[vpid] = 0;
        }

        // [REMOVED] re-bootstrap from Hook 2 — writing hook_cr3 to VMCS AFTER HV's handler
        // causes CLOCK_WATCHDOG / KERNEL_MODE_TRAP (bisect steps 9-14).
        // Re-bootstrap is now in Hook 1 (vmexit_entry.cpp), BEFORE HV's handler.
    }

    // Per-VMEXIT CR3 swap — same as on_hook_cr3 path above.
    if (cr3_intercept::enabled && slat::is_our_eptp(current_eptp))
    {
        const cr3 guest_cr3 = arch::get_guest_cr3();
        const std::uint64_t guest_pfn = guest_cr3.flags & cr3_intercept::cr3_pfn_mask;
        const std::uint64_t clone_pfn = cr3_intercept::cloned_cr3_value & cr3_intercept::cr3_pfn_mask;

        if (guest_pfn != clone_pfn)
        {
            const std::uint64_t target_pfn = cr3_intercept::target_original_cr3 & cr3_intercept::cr3_pfn_mask;

            if (guest_pfn == target_pfn ||
                (cr3_intercept::target_user_cr3 != 0 &&
                 guest_pfn == (cr3_intercept::target_user_cr3 & cr3_intercept::cr3_pfn_mask)))
            {
                arch::set_guest_cr3({ .flags = cr3_intercept::cloned_cr3_value });
                cr3_intercept::cr3_swap_count++;
            }
        }
    }

    return result;
#else
    // AMD path: keep existing behavior (no fast-path entry hook on AMD)
    process_first_vmexit();

    if (cr3_intercept::enabled)
    {
        const cr3 current = arch::get_guest_cr3();
        const std::uint64_t current_pfn = current.flags & cr3_intercept::cr3_pfn_mask;
        const std::uint64_t target_pfn = cr3_intercept::target_original_cr3 & cr3_intercept::cr3_pfn_mask;

        if (current_pfn == target_pfn ||
            (cr3_intercept::target_user_cr3 != 0 &&
             current_pfn == (cr3_intercept::target_user_cr3 & cr3_intercept::cr3_pfn_mask)))
        {
            arch::set_guest_cr3({ .flags = cr3_intercept::cloned_cr3_value });
            cr3_intercept::cr3_swap_count++;
        }
    }

    const std::uint64_t exit_reason = arch::get_vmexit_reason();

    if (arch::is_cpuid(exit_reason) == 1)
    {
        trap_frame_t* const trap_frame = *reinterpret_cast<trap_frame_t**>(a2);

        const hypercall_info_t hypercall_info = { .value = trap_frame->rcx };

        if (hypercall_info.primary_key == hypercall_primary_key && hypercall_info.secondary_key == hypercall_secondary_key)
        {
            vmcb_t* const vmcb = arch::get_vmcb();

            trap_frame->rax = vmcb->save_state.rax;

            trap_frame->rsp = arch::get_guest_rsp();

            hypercall::process(hypercall_info, trap_frame);

            vmcb->save_state.rax = trap_frame->rax;

            arch::set_guest_rsp(trap_frame->rsp);
            arch::advance_guest_rip();

            return __readgsqword(0);
        }
    }
    else if (arch::is_slat_violation(exit_reason) == 1 && slat::violation::process() == 1)
    {
        return __readgsqword(0);
    }
    else if (arch::is_non_maskable_interrupt_exit(exit_reason) == 1)
    {
        interrupts::process_nmi();
    }

    return reinterpret_cast<vmexit_handler_t>(original_vmexit_handler)(a1, a2, a3, a4);
#endif
}

void entry_point(std::uint8_t** const detours_out, std::uint8_t* const original_vmexit_handler_routine, const std::uint64_t heap_physical_base, const std::uint64_t heap_physical_usable_base, const std::uint64_t heap_total_size, const std::uint64_t _uefi_boot_physical_base_address, const std::uint32_t _uefi_boot_image_size,
#ifdef _INTELMACHINE
    const std::uint64_t _reserved_get_vmcb_gadget, const std::uint64_t vmexit_entry_trampoline)
{
    (void)_reserved_get_vmcb_gadget;
    original_vmexit_entry_trampoline = vmexit_entry_trampoline;

#else
const std::uint8_t* const get_vmcb_gadget, const std::uint64_t _reserved_vmexit_entry_trampoline)
{
    (void)_reserved_vmexit_entry_trampoline;
    arch::parse_vmcb_gadget(get_vmcb_gadget);
#endif
    original_vmexit_handler = original_vmexit_handler_routine;
    uefi_boot_physical_base_address = _uefi_boot_physical_base_address;
    uefi_boot_image_size = _uefi_boot_image_size;

    heap_manager::initial_physical_base = heap_physical_base;
    heap_manager::initial_size = heap_total_size;

    detours_out[0] = reinterpret_cast<std::uint8_t*>(vmexit_handler_detour);
#ifdef _INTELMACHINE
    detours_out[1] = reinterpret_cast<std::uint8_t*>(vmexit_entry_hook_stub);
#endif

    const std::uint64_t heap_physical_end = heap_physical_base + heap_total_size;
    const std::uint64_t heap_usable_size = heap_physical_end - heap_physical_usable_base;

    void* const mapped_heap_usable_base = memory_manager::map_host_physical(heap_physical_usable_base);

    heap_manager::set_up(mapped_heap_usable_base, heap_usable_size);

    logs::set_up();
    slat::set_up();
}
