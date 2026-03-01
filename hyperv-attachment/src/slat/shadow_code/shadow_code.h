#pragma once
#include <cstdint>

namespace shadow_code
{
    // EPT-split page containing one or more CC run slots.
    struct page_t
    {
        std::uint64_t guest_va;        // ntoskrnl kernel VA of page (page-aligned)
        std::uint64_t guest_pa;        // original GPA (page-aligned)
        void* shadow_host_va;          // host VA of shadow copy (for writing code)
        std::uint8_t active;
    };

    // Free slot: a contiguous CC/NOP run within an EPT-split page.
    // Bump-allocated: cursor moves forward, never freed.
    struct region_t
    {
        std::uint8_t page_index;       // index into pages[]
        std::uint8_t _pad;
        std::uint16_t cursor;          // next free offset (16-byte aligned, bumps forward)
        std::uint16_t end;             // end of CC run (exclusive)
    };

    constexpr int max_pages = 32;
    constexpr int max_regions = 128;
    constexpr std::uint32_t min_run_size = 32; // minimum CC run to register

    inline page_t pages[max_pages] = {};
    inline int page_count = 0;
    inline region_t regions[max_regions] = {};
    inline int region_count = 0;
    inline bool initialized = false;

    // Init: scan ntoskrnl .text for CC/NOP padding runs, EPT-split pages containing them.
    // guest_cr3_flags: guest CR3 for kernel VA → PA translation (must be kernel DTB, not KPTI user DTB).
    // Returns number of regions found.
    std::uint64_t init(std::uint64_t text_va, std::uint64_t text_size, std::uint64_t guest_cr3_flags);

    // Allocate 'size' bytes from shadow code pool. Returns kernel VA, sets *host_ptr.
    // Returns 0 on failure.
    std::uint64_t alloc(std::uint32_t size, void** host_ptr);

    // Convenience: alloc + write trampoline (displaced bytes + 14B abs JMP back).
    // Returns kernel VA of trampoline. 0 on failure.
    std::uint64_t alloc_trampoline(const std::uint8_t* orig_bytes,
        std::uint32_t displaced_count, std::uint64_t resume_va);
}
