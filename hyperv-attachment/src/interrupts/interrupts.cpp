#include "interrupts.h"
#include "../memory_manager/heap_manager.h"
#include "../slat/cr3/cr3.h"
#include "../arch/arch.h"
#include "../cr3_intercept.h"
#include "../logs/serial.h"

#include "ia32-doc/ia32.hpp"
#include <intrin.h>

extern "C"
{
    std::uint64_t original_nmi_handler = 0;

    void nmi_standalone_entry();
    void nmi_entry();
}

namespace
{
    crt::bitmap_t processor_nmi_states = { };
}

void set_up_nmi_handling()
{
    segment_descriptor_register_64 idtr = { };

    __sidt(&idtr);

    if (idtr.base_address == 0)
    {
        return;
    }

    const auto interrupt_gates = reinterpret_cast<segment_descriptor_interrupt_gate_64*>(idtr.base_address);
    segment_descriptor_interrupt_gate_64* const nmi_gate = &interrupt_gates[2];
    segment_descriptor_interrupt_gate_64 new_gate = *nmi_gate;

    std::uint64_t new_handler = reinterpret_cast<std::uint64_t>(nmi_entry);

    if (new_gate.present == 0)
    {
        constexpr segment_selector gate_segment_selector = { .index = 1 };

        new_gate.segment_selector = gate_segment_selector.flags;
        new_gate.type = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE;
        new_gate.present = 1;

        new_handler = reinterpret_cast<std::uint64_t>(nmi_standalone_entry);
    }
    else
    {
        original_nmi_handler = nmi_gate->offset_low | (nmi_gate->offset_middle << 16) | (static_cast<uint64_t>(nmi_gate->offset_high) << 32);
    }

    new_gate.offset_low = new_handler & 0xFFFF;
    new_gate.offset_middle = (new_handler >> 16) & 0xFFFF;
    new_gate.offset_high = (new_handler >> 32) & 0xFFFFFFFF;

    *nmi_gate = new_gate;
}

void interrupts::set_up()
{
    constexpr std::uint64_t processor_nmi_state_count = 0x1000 / sizeof(crt::bitmap_t::size_type);

    processor_nmi_states.set_value(static_cast<crt::bitmap_t::pointer>(heap_manager::allocate_page()));
    processor_nmi_states.set_count(processor_nmi_state_count);

    apic = apic_t::create_instance();

#ifdef _INTELMACHINE
    set_up_nmi_handling();
#endif
}

void interrupts::set_all_nmi_ready()
{
    processor_nmi_states.set_all();
}

void interrupts::set_nmi_ready(const std::uint64_t apic_id)
{
    processor_nmi_states.set(apic_id);
}

void interrupts::clear_nmi_ready(const std::uint64_t apic_id)
{
    processor_nmi_states.clear(apic_id);
}

crt::bitmap_t::bit_type interrupts::is_nmi_ready(const std::uint64_t apic_id)
{
    return processor_nmi_states.is_set(apic_id);
}

void interrupts::process_nmi()
{
    const std::uint64_t current_apic_id = apic_t::current_apic_id();

    if (is_nmi_ready(current_apic_id) == 1)
    {
        // [REMOVED] Option B: patch_eptp_source_table via NMI.
        // Root cause of freeze: dereferences KERNEL_GS_BASE with unverified offsets
        // (per_vp+0xCD8 wrong struct, count@0xBD0 not a count field per IDA).
        // No longer needed: HvSetEptPointer entry hook (shellcode in hvix64 code cave)
        // swaps PFN in [RCX] before the function runs → both lazy and direct paths
        // write hook_cr3 natively. HV's own cache bookkeeping works for us.

        // If Hook 3 active, force this LP onto hook_cr3.
        // CRITICAL: Only write to VTL 0 VMCS. NMI can arrive while VP is processing
        // a VTL 1 VMEXIT — writing VTL 0's hook_cr3 into VTL 1's VMCS causes
        // HYPERVISOR_ERROR on next VTL 1 VMRESUME (wrong EPTP for Secure Kernel).
        if (slat::is_vmwrite_hook_active() && slat::is_hook_cr3_ready())
        {
            const cr3 current_eptp = arch::get_slat_cr3();
            if (slat::is_our_eptp(current_eptp))
            {
                static volatile std::uint8_t logged_nmi_force = 0;
                if (!logged_nmi_force) { logged_nmi_force = 1; serial::println("[nmi] forcing LP onto hook_cr3 (Hook 3)"); }
                // Preserve current VMCS metadata bits [11:0], only replace PML4 PFN
                cr3 target = current_eptp;
                target.address_of_page_directory = slat::hook_cr3().address_of_page_directory;
                slat::set_cr3(target);
            }
        }

        slat::flush_current_logical_processor_cache();

        // NOTE: enable_cr3_exiting() REMOVED permanently.
        // Writing proc-based controls triggers HyperGuard. See vmexit_entry.cpp.

        clear_nmi_ready(current_apic_id);
    }
}

void interrupts::send_nmi_all_but_self()
{
    apic->send_nmi(icr_destination_shorthand_t::all_but_self);
}
