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
#include "logs/serial.h"
#include "slat/slat.h"
#include "slat/cr3/cr3.h"
#include "slat/cr3/fork_registry.h"
#include "slat/violation/violation.h"
#include "slat/violation/mtf_context.h"
#include "cr3_intercept.h"

#include "slat/shadow_code/shadow_code.h"

#include <intrin.h>

typedef std::uint64_t(*vmexit_handler_t)(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4);

extern "C"
{
    void vmexit_entry_hook_stub();
    std::uint64_t original_vmexit_entry_trampoline = 0;
}

// Hook 3 diagnostic counters — tracks EPTP state at Hook 2 entry
volatile long long hook3_on_hook_cr3_count = 0;     // VP arrived on hook_cr3 (Hook 3 working)
volatile long long hook3_on_hyperv_cr3_count = 0;   // VP arrived on hyperv_cr3 (bounce — Hook 3 failed/inactive)
volatile long long hook3_rebootstrap_count = 0;     // Hook 2 had to re-set EPTP to hook_cr3


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

// Deferred shadow_code init: set when boot-time init fails (bad CR3 at first VMEXIT).
// Hook 2 retries on subsequent VMEXITs until a valid kernel CR3 is found.
// Split into 2 phases across separate VMEXITs to limit stack depth
// (full init in one VMEXIT can overflow Hyper-V's host stack → triple fault).
static volatile std::uint8_t shadow_code_deferred = 0;

// Phase 2: MmClean hook setup (runs on the NEXT VMEXIT after shadow_code init succeeds).
static volatile std::uint8_t mmclean_deferred = 0;
// CR3 captured during phase 1, reused for phase 2.
static volatile std::uint64_t deferred_init_cr3 = 0;


void process_first_vmexit()
{
    // Atomic guard: only one core runs init, others skip entirely.
    static volatile long is_first_vmexit = 1;

    if (_InterlockedCompareExchange(&is_first_vmexit, 0, 1) == 1)
    {
        serial::init();
        serial::println("[boot] process_first_vmexit: START");

        // Log enlightened VMCS offsets from HvSetEptPointer sig scan (boot-time, one-shot)
        serial::print("[boot] enlightened VMCS: gs_per_vp=0x");
        serial::print_hex(arch::get_enlightened_gs_per_vp_offset());
        serial::print(" eptp_cache=0x");
        serial::print_hex(arch::get_enlightened_eptp_cache_offset());
        serial::print(" clean_fields=0x");
        serial::print_hex(arch::get_enlightened_clean_fields_offset());
        serial::println("");

        slat::process_first_vmexit();
        serial::println("[boot] slat::process_first_vmexit done");

        interrupts::set_up();
        serial::println("[boot] interrupts::set_up done");

        clean_up_uefi_boot_image();
        serial::println("[boot] clean_up_uefi_boot_image done");

        // Deferred shadow_code + MmClean init: scan ntoskrnl .text on next VTL0 VMEXIT
        // (current VMEXIT may have KPTI user CR3 or VTL1 context → bad for IDT-based ntos lookup)
        // CRITICAL: suppress NMI broadcasts during boot-time EPT setup.
        // hook::add() calls flush_all_logical_processors_cache() which sends NMI IPI.
        // NMI during guest execution → VMEXIT(NMI) → Hook 1 falls through → Hyper-V
        // re-injects NMI to guest → Windows NMI handler at early boot → BSOD/freeze.
        // Lazy INVEPT (dirty flags) handles TLB flush when VPs switch to hook_cr3 later.
        slat::suppress_nmi_broadcast = 1;
        shadow_code_deferred = 1;
        serial::println("[boot] shadow_code deferred, NMI suppressed");

        // Signal fast handler that all subsystems are ready
        hook2_initialized = 1;
        serial::println("[boot] hook2_initialized=1, boot COMPLETE");
    }
}

std::uint64_t vmexit_handler_detour(const std::uint64_t a1, const std::uint64_t a2, const std::uint64_t a3, const std::uint64_t a4)
{
#ifdef _INTELMACHINE
    // Hook 2 runs for ALL VMEXITs (VTL 0 + VTL 1). Init must run regardless of VTL.
    process_first_vmexit();

    // ======================================================================
    // PHASE 1: Deferred shadow_code init (scan ntoskrnl .text, EPT-split).
    // Split from MmClean setup to reduce peak stack depth — both together
    // can overflow Hyper-V's host stack → triple fault → instant reboot.
    // ======================================================================
    if (shadow_code_deferred && !cr3_intercept::enabled)
    {
        // VTL1 VMEXITs have different IDTR/CR3 — reading IDT here would find
        // securekernel handlers, not ntoskrnl. Only attempt on VTL0 VMEXITs.
        const cr3 deferred_eptp = arch::get_slat_cr3();
        if (!slat::is_our_eptp(deferred_eptp))
        {
            // VTL1 or unknown EPTP — skip this VMEXIT
        }
        else
        {
        static volatile long trying_init = 0;
        static volatile long retry_count = 0;

        if (_InterlockedCompareExchange(&trying_init, 1, 0) == 0)
        {
            const long attempt = _InterlockedIncrement(&retry_count);

            if (attempt > 500)
            {
                shadow_code_deferred = 0;
                slat::suppress_nmi_broadcast = 0;
                serial::println("[boot] shadow_code GAVE UP (500 attempts)");
                trying_init = 0;
            }
            else
            {
                const std::uint64_t guest_cr3 = arch::get_guest_cr3().flags;

                // Silent retries — no serial logging per attempt (causes triple fault)
                const std::uint64_t saved = cr3_intercept::target_original_cr3;
                cr3_intercept::target_original_cr3 = guest_cr3;
                hypercall::setup_shadow_code_pages();

                if (shadow_code::initialized)
                {
                    shadow_code_deferred = 0;
                    // [STEP 2b] Investigating cave_exec=0 — Hook 3 shellcode never fires.
                    // shadow_code + hook_cr3 stable. No mmclean until cave is fixed.
                    /* mmclean_deferred = 1; */
                    /* deferred_init_cr3 = guest_cr3; */
                    slat::suppress_nmi_broadcast = 0;
                    serial::print("[boot] shadow_code OK (attempt ");
                    serial::print_dec(attempt); serial::println("), NMI re-enabled. NO mmclean.");
                }

                cr3_intercept::target_original_cr3 = saved;
                trying_init = 0;
            }
        }
        } // end VTL0 check
    }

    // ======================================================================
    // PHASE 2: MmClean hook setup (separate VMEXIT from phase 1).
    // ======================================================================
    if (mmclean_deferred && !cr3_intercept::enabled && slat::is_our_eptp(arch::get_slat_cr3()))
    {
        static volatile long trying_mmclean = 0;

        if (_InterlockedCompareExchange(&trying_mmclean, 1, 0) == 0)
        {
            const std::uint64_t saved = cr3_intercept::target_original_cr3;
            cr3_intercept::target_original_cr3 = deferred_init_cr3;

            const std::uint64_t mm_result = hypercall::auto_setup_mmclean_hook();

            mmclean_deferred = 0;

            // Both phases complete — re-enable NMI broadcasts for runtime EPT ops.
            slat::suppress_nmi_broadcast = 0;
            // Log only result (runs once)
            serial::print("[boot] mmclean ");
            serial::println(mm_result ? "OK" : "FAILED");

            cr3_intercept::target_original_cr3 = saved;
            trying_mmclean = 0;
        }
    }

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
        hook3_on_hook_cr3_count++;

        const auto result = reinterpret_cast<vmexit_handler_t>(original_vmexit_handler)(a1, a2, a3, a4);

        // [REMOVED] Option B: patch_eptp_source_table POST-handler.
        // No longer needed: HvSetEptPointer entry hook handles PFN swap.
        // HV calls HvSetEptPointer during handler → shellcode swaps → hook_cr3 in cache.

        // [REVERTED] Option D: Post-handler EPTP fixup — causes HYPERVISOR_ERROR 0x26
        // (VMWRITE + enlightened VMCS cache write during VP idle → inconsistency).
        // Replaced by Option B: EPTP source table patched with hook_cr3 so Hyper-V
        // reconstructs hook_cr3 naturally via HvGetEptPointer.
        /*
        {
            const cr3 post_eptp = arch::get_slat_cr3();
            if (post_eptp.address_of_page_directory == slat::hyperv_cr3().address_of_page_directory)
            {
                cr3 fixed = post_eptp;
                fixed.address_of_page_directory = hk_cr3.address_of_page_directory;
                arch::set_slat_cr3(fixed);

                const std::uint16_t vpid = arch::get_current_vpid();
                if (vpid < slat::max_logical_processors && slat::hook_cr3_ept_dirty[vpid])
                {
                    slat::flush_current_logical_processor_cache();
                    slat::hook_cr3_ept_dirty[vpid] = 0;
                }
                hook3_rebootstrap_count++;
            }
        }
        */

        // Per-VMEXIT CR3 swap: catch context switches after HV handler.
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

    if (slat::is_our_eptp(current_eptp))
        hook3_on_hyperv_cr3_count++;

    const auto result = reinterpret_cast<vmexit_handler_t>(original_vmexit_handler)(a1, a2, a3, a4);

    // Fork sync: if Hook 1's violation handler queued a fork sync (unhandled EPT
    // violation in forked region), do the sync now.
    {
        const std::uint16_t vpid = arch::get_current_vpid();

        if (vpid < slat::mtf::max_contexts && slat::violation::fork_sync_pending_gpa[vpid] != 0)
        {
            slat::fork_registry::sync_forked_entry(slat::violation::fork_sync_pending_gpa[vpid]);
            slat::violation::fork_sync_pending_gpa[vpid] = 0;
        }
    }

    // [REMOVED] Option B: patch_eptp_source_table (non-on_hook_cr3 path).
    // No longer needed: HvSetEptPointer entry hook handles PFN swap for all paths.

    // [REVERTED] Option D: Post-handler EPTP fixup — causes HYPERVISOR_ERROR 0x26.
    // Replaced by Option B: EPTP source table patched with hook_cr3.
    /*
    {
        const cr3 post_eptp = arch::get_slat_cr3();
        const bool is_vtl0 = slat::is_our_eptp(post_eptp);
        const bool needs_fixup = is_vtl0 &&
            (cr3_intercept::enabled || slat::is_vmwrite_hook_active()) &&
            post_eptp.address_of_page_directory != hk_cr3.address_of_page_directory;

        if (needs_fixup)
        {
            const bool safe =
                !cr3_intercept::enabled ||
                (!cr3_intercept::mmaf_hook::ctx.active || cr3_intercept::mmaf_hook::ctx.stub_pfn_offset != 0);

            if (safe)
            {
                cr3 fixed = post_eptp;
                fixed.address_of_page_directory = hk_cr3.address_of_page_directory;
                arch::set_slat_cr3(fixed);

                const std::uint16_t vpid = arch::get_current_vpid();
                if (vpid < slat::max_logical_processors && slat::hook_cr3_ept_dirty[vpid])
                {
                    slat::flush_current_logical_processor_cache();
                    slat::hook_cr3_ept_dirty[vpid] = 0;
                }
                hook3_rebootstrap_count++;
            }
        }
    }
    */

    // CR3 swap: target process → clone CR3 (only with active cr3_intercept)
    {
        const cr3 post_eptp = arch::get_slat_cr3();
        const bool is_vtl0 = slat::is_our_eptp(post_eptp);
        if (cr3_intercept::enabled && is_vtl0)
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
    const std::uint64_t _reserved_get_vmcb_gadget, const std::uint64_t vmexit_entry_trampoline, const std::uint64_t _vmwrite_hook_cave_pa, const std::uint64_t _enlightened_vmcs_offsets)
{
    (void)_reserved_get_vmcb_gadget;
    original_vmexit_entry_trampoline = vmexit_entry_trampoline;
    slat::set_vmwrite_hook_cave_pa(_vmwrite_hook_cave_pa);
    arch::set_enlightened_vmcs_offsets(_enlightened_vmcs_offsets);

#else
const std::uint8_t* const get_vmcb_gadget, const std::uint64_t _reserved_vmexit_entry_trampoline, const std::uint64_t _vmwrite_hook_cave_pa, const std::uint64_t _enlightened_vmcs_offsets)
{
    (void)_reserved_vmexit_entry_trampoline;
    (void)_vmwrite_hook_cave_pa;
    (void)_enlightened_vmcs_offsets;
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
