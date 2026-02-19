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
#include "slat/violation/violation.h"
#include "cr3_intercept.h"

#ifndef _INTELMACHINE
#include <intrin.h>
#endif

typedef std::uint64_t(*vmexit_handler_t)(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4);

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

void process_first_vmexit()
{
    static std::uint8_t is_first_vmexit = 1;

    if (is_first_vmexit == 1)
    {
        slat::process_first_vmexit();
        interrupts::set_up();

        clean_up_uefi_boot_image();

        is_first_vmexit = 0;
    }

    static std::uint8_t has_hidden_heap_pages = 0;
    static std::uint64_t vmexit_count = 0;

    if (has_hidden_heap_pages == 0 && 10000 <= ++vmexit_count)
    {
        // hides heap from Hyper-V slat cr3. when the hook slat cr3 is initialised, the heap must also be hidden from it

        has_hidden_heap_pages = slat::hide_heap_pages(slat::hyperv_cr3());
    }
}

std::uint64_t do_vmexit_premature_return()
{
#ifdef _INTELMACHINE
    if (cr3_intercept::enabled)
    {
        arch::enable_cr3_exiting();
    }
    return 0;
#else
    return __readgsqword(0);
#endif
}

std::uint64_t vmexit_handler_detour(const std::uint64_t a1, const std::uint64_t a2, const std::uint64_t a3, const std::uint64_t a4)
{
    process_first_vmexit();

    // enforce: force clone CR3 at every VM exit when active
    if (cr3_intercept::enforce_active)
    {
        const cr3 current = arch::get_guest_cr3();
        if ((current.flags & cr3_intercept::cr3_pfn_mask) == (cr3_intercept::target_original_cr3 & cr3_intercept::cr3_pfn_mask))
        {
            arch::set_guest_cr3({ .flags = cr3_intercept::cloned_cr3_value });
            arch::invalidate_vpid_current();
            cr3_intercept::cr3_swap_count++;
        }
    }

    const std::uint64_t exit_reason = arch::get_vmexit_reason();

    if (arch::is_cpuid(exit_reason) == 1)
    {
#ifdef _INTELMACHINE
        trap_frame_t* const trap_frame = *reinterpret_cast<trap_frame_t**>(a1);
#else
        trap_frame_t* const trap_frame = *reinterpret_cast<trap_frame_t**>(a2);
#endif

        const hypercall_info_t hypercall_info = { .value = trap_frame->rcx };

        if (hypercall_info.primary_key == hypercall_primary_key && hypercall_info.secondary_key == hypercall_secondary_key)
        {
#ifndef _INTELMACHINE
            vmcb_t* const vmcb = arch::get_vmcb();

            trap_frame->rax = vmcb->save_state.rax;
#endif

            trap_frame->rsp = arch::get_guest_rsp();

            hypercall::process(hypercall_info, trap_frame);

#ifndef _INTELMACHINE
            vmcb->save_state.rax = trap_frame->rax;
#endif

            arch::set_guest_rsp(trap_frame->rsp);
            arch::advance_guest_rip();

            return do_vmexit_premature_return();
        }
    }
    else if (arch::is_mov_cr(exit_reason) == 1)
    {
#ifdef _INTELMACHINE
        const vmx_exit_qualification_mov_cr qualification = arch::get_exit_qualification_mov_cr();

        if (qualification.control_register == 3)
        {
            cr3_intercept::cr3_exit_count++;

            trap_frame_t* const trap_frame = *reinterpret_cast<trap_frame_t**>(a1);
            const std::uint64_t gpr_index = qualification.general_purpose_register;

            if (qualification.access_type == VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR)
            {
                const std::uint64_t raw_cr3_value = (gpr_index == VMX_EXIT_QUALIFICATION_GENREG_RSP)
                    ? arch::get_guest_rsp()
                    : cr3_intercept::read_gpr(trap_frame, gpr_index);

                // bit 63 = PCID no-invalidate flag, consumed by MOV CR3 instruction
                // must NOT be written to VMCS guest CR3 (reserved bits above MAXPHYADDR)
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

                // if running under clone, spoof back the kernel DTB (hide clone from guest)
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
            return do_vmexit_premature_return();
        }
#endif
    }
    else if (arch::is_slat_violation(exit_reason) == 1 && slat::violation::process() == 1)
    {
        return do_vmexit_premature_return();
    }
    else if (arch::is_non_maskable_interrupt_exit(exit_reason) == 1)
    {
        interrupts::process_nmi();
    }

#ifdef _INTELMACHINE
    if (cr3_intercept::enabled)
    {
        arch::enable_cr3_exiting();
    }
#endif

    return reinterpret_cast<vmexit_handler_t>(original_vmexit_handler)(a1, a2, a3, a4);
}

void entry_point(std::uint8_t** const vmexit_handler_detour_out, std::uint8_t* const original_vmexit_handler_routine, const std::uint64_t heap_physical_base, const std::uint64_t heap_physical_usable_base, const std::uint64_t heap_total_size, const std::uint64_t _uefi_boot_physical_base_address, const std::uint32_t _uefi_boot_image_size,
#ifdef _INTELMACHINE
    const std::uint64_t reserved_one)
{
    (void)reserved_one;

#else
const std::uint8_t* const get_vmcb_gadget)
{
    arch::parse_vmcb_gadget(get_vmcb_gadget);
#endif
    original_vmexit_handler = original_vmexit_handler_routine;
    uefi_boot_physical_base_address = _uefi_boot_physical_base_address;
    uefi_boot_image_size = _uefi_boot_image_size;

    heap_manager::initial_physical_base = heap_physical_base;
    heap_manager::initial_size = heap_total_size;

    *vmexit_handler_detour_out = reinterpret_cast<std::uint8_t*>(vmexit_handler_detour);

    const std::uint64_t heap_physical_end = heap_physical_base + heap_total_size;
    const std::uint64_t heap_usable_size = heap_physical_end - heap_physical_usable_base;

    void* const mapped_heap_usable_base = memory_manager::map_host_physical(heap_physical_usable_base);

    heap_manager::set_up(mapped_heap_usable_base, heap_usable_size);

    logs::set_up();
    slat::set_up();
}
