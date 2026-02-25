#pragma once
#include <cstdint>
#include <structures/memory_operation.h>

enum class hypercall_type_t : std::uint64_t
{
    guest_physical_memory_operation,
    guest_virtual_memory_operation,
    translate_guest_virtual_address,
    read_guest_cr3,
    add_slat_code_hook,
    remove_slat_code_hook,
    hide_guest_physical_page,
    log_current_state,
    flush_logs,
    get_heap_free_page_count,
    monitor_physical_page,      // Monitor read access to a physical page (EPT violation on read)
    unmonitor_physical_page,    // Remove monitoring from a physical page
    write_guest_cr3,            // Write a new CR3 value to the guest VMCS
    clone_guest_cr3,            // Clone a guest CR3 (copy PML4, return new GPA)
    enable_cr3_intercept,       // Enable CR3 intercept (swap target CR3 with clone on context switch)
    disable_cr3_intercept       // Disable CR3 intercept and restore original CR3
};

#pragma warning(push)
#pragma warning(disable: 4201)

constexpr std::uint64_t hypercall_primary_key = 0xA3D8;
constexpr std::uint64_t hypercall_secondary_key = 0x53;

union hypercall_info_t
{
    std::uint64_t value;

    struct
    {
        std::uint64_t primary_key : 16;
        hypercall_type_t call_type : 4;
        std::uint64_t secondary_key : 7;
        std::uint64_t call_reserved_data : 37;
    };
};

union virt_memory_op_hypercall_info_t
{
    std::uint64_t value;

    struct
    {
        std::uint64_t primary_key : 16;
        hypercall_type_t call_type : 4;
        std::uint64_t secondary_key : 7;
        memory_operation_t memory_operation : 1;
        std::uint64_t address_of_page_directory : 36; // we will construct the other cr3 (aside from the caller process) involved in the operation from this
    };
};

// Sig scan request — passed by guest VA pointer to hypervisor
struct sig_scan_request_t
{
    std::uint64_t scan_base_va;    // start of scan region (e.g. ntoskrnl base)
    std::uint64_t scan_size;       // size of scan region
    std::uint32_t pattern_len;     // length of pattern/mask (max 64)
    std::uint8_t resolve_call;     // 1 = match is E8 CALL site, resolve target VA
    std::uint8_t _pad[3];
    std::uint8_t pattern[64];      // byte pattern
    char mask[64];                 // 'x' = must match, '?' = wildcard
};

#pragma warning(pop)
