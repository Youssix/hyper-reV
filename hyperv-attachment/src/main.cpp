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

#ifndef _INTELMACHINE
#include <intrin.h>
#endif

// original sub_FFFFF800002228DC — the per-exit dispatch called from the default case
// handles all exit types (CPUID, NPF, NMI, etc.), TimeCompensation runs after it returns
typedef void(*sub_handler_t)(std::uint64_t context);

namespace
{
    std::uint8_t* original_sub_handler = nullptr;
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

// deep hook: replaces the call to sub_FFFFF800002228DC in the default case
// called from INSIDE Hyper-V's vmexit handler — pre-processing (STGI) already ran,
// TimeCompensation runs naturally AFTER we return. no premature returns needed.
void sub_handler_detour(const std::uint64_t context)
{
    process_first_vmexit();

    const std::uint64_t exit_reason = arch::get_vmexit_reason();

    if (arch::is_cpuid(exit_reason) == 1)
    {
        trap_frame_t* const trap_frame = *reinterpret_cast<trap_frame_t**>(context);

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

            return; // TimeCompensation runs after we return
        }
    }
    else if (arch::is_slat_violation(exit_reason) == 1 && slat::violation::process() == 1)
    {
        return; // TimeCompensation runs after we return
    }
    else if (arch::is_non_maskable_interrupt_exit(exit_reason) == 1)
    {
        interrupts::process_nmi();
    }

    // not our exit — let original sub handle it
    reinterpret_cast<sub_handler_t>(original_sub_handler)(context);
}

void entry_point(std::uint8_t** const vmexit_handler_detour_out, std::uint8_t* const original_sub_handler_routine, const std::uint64_t heap_physical_base, const std::uint64_t heap_physical_usable_base, const std::uint64_t heap_total_size, const std::uint64_t _uefi_boot_physical_base_address, const std::uint32_t _uefi_boot_image_size,
#ifdef _INTELMACHINE
    const std::uint64_t reserved_one)
{
    (void)reserved_one;

#else
const std::uint8_t* const get_vmcb_gadget)
{
    arch::parse_vmcb_gadget(get_vmcb_gadget);
#endif
    original_sub_handler = original_sub_handler_routine;
    uefi_boot_physical_base_address = _uefi_boot_physical_base_address;
    uefi_boot_image_size = _uefi_boot_image_size;

    heap_manager::initial_physical_base = heap_physical_base;
    heap_manager::initial_size = heap_total_size;

    *vmexit_handler_detour_out = reinterpret_cast<std::uint8_t*>(sub_handler_detour);

    const std::uint64_t heap_physical_end = heap_physical_base + heap_total_size;
    const std::uint64_t heap_usable_size = heap_physical_end - heap_physical_usable_base;

    void* const mapped_heap_usable_base = memory_manager::map_host_physical(heap_physical_usable_base);

    heap_manager::set_up(mapped_heap_usable_base, heap_usable_size);

    logs::set_up();
    slat::set_up();
}
