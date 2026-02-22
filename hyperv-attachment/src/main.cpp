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

#ifndef _INTELMACHINE
#include <intrin.h>
#endif

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
    static std::uint8_t is_first_vmexit = 1;

    if (is_first_vmexit == 1)
    {
        slat::process_first_vmexit();
        interrupts::set_up();

        clean_up_uefi_boot_image();

        is_first_vmexit = 0;

        // Signal fast handler that all subsystems are ready
        hook2_initialized = 1;
    }

    static std::uint8_t has_hidden_heap_pages = 0;
    static std::uint64_t vmexit_count = 0;

    if (has_hidden_heap_pages == 0 && 10000 <= ++vmexit_count)
    {
        // hides heap from Hyper-V slat cr3. when the hook slat cr3 is initialised, the heap must also be hidden from it

        has_hidden_heap_pages = slat::hide_heap_pages(slat::hyperv_cr3());
    }
}

std::uint64_t vmexit_handler_detour(const std::uint64_t a1, const std::uint64_t a2, const std::uint64_t a3, const std::uint64_t a4)
{
#ifdef _INTELMACHINE
    // Hook 2 runs for ALL VMEXITs (VTL 0 + VTL 1). Init must run regardless of VTL.
    process_first_vmexit();

    // With VSM, VTL 1 VMEXITs go through the same handler but have a different VMCS/EPTP.
    // Only swap EPTP for VTL 0 VMEXITs where we're on our hook_cr3.
    // VTL 1 and hyperv_cr3 contexts pass through untouched.
    const cr3 current_eptp = arch::get_slat_cr3();
    const cr3 hk_cr3 = slat::hook_cr3();

    const bool on_hook_cr3 = hk_cr3.flags != 0 &&
        current_eptp.address_of_page_directory == hk_cr3.address_of_page_directory;

    if (on_hook_cr3)
    {
        // Swap to Hyper-V's EPTP so its handler sees clean page tables.
        // Preserve EPTP metadata bits [11:0] from current VMCS — only change PML4 address.
        cr3 hyperv_eptp = current_eptp;
        hyperv_eptp.address_of_page_directory = slat::hyperv_cr3().address_of_page_directory;
        arch::set_slat_cr3(hyperv_eptp);

        const auto result = reinterpret_cast<vmexit_handler_t>(original_vmexit_handler)(a1, a2, a3, a4);

        // Check if violation handler queued a fork sync for this LP
        const std::uint16_t vpid = arch::get_current_vpid();

        if (vpid < slat::mtf::max_contexts && slat::violation::fork_sync_pending_gpa[vpid] != 0)
        {
            slat::fork_registry::sync_forked_entry(slat::violation::fork_sync_pending_gpa[vpid]);
            slat::violation::fork_sync_pending_gpa[vpid] = 0;
        }

        // Restore hook EPTP after Hyper-V's handler returns.
        // Read fresh metadata in case Hyper-V modified any EPTP bits during handling.
        cr3 restored_eptp = arch::get_slat_cr3();
        restored_eptp.address_of_page_directory = hk_cr3.address_of_page_directory;
        arch::set_slat_cr3(restored_eptp);

        return result;
    }

    const auto result = reinterpret_cast<vmexit_handler_t>(original_vmexit_handler)(a1, a2, a3, a4);

    // Check fork sync even when not on hook_cr3 — Hook 1 may have swapped EPTP
    // to hyperv_cr3 before falling through (e.g., unhandled EPT violation in forked region)
    if (hk_cr3.flags != 0)
    {
        const std::uint16_t vpid = arch::get_current_vpid();

        if (vpid < slat::mtf::max_contexts && slat::violation::fork_sync_pending_gpa[vpid] != 0)
        {
            slat::fork_registry::sync_forked_entry(slat::violation::fork_sync_pending_gpa[vpid]);
            slat::violation::fork_sync_pending_gpa[vpid] = 0;

            // Restore hook_cr3 EPTP since we were on it before Hook 1 swapped away
            cr3 restored_eptp = arch::get_slat_cr3();
            restored_eptp.address_of_page_directory = hk_cr3.address_of_page_directory;
            arch::set_slat_cr3(restored_eptp);
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
