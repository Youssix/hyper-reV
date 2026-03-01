#include "shadow_code.h"

#include "../cr3/cr3.h"
#include "../cr3/pte.h"
#include "../hook/hook.h"
#include "../hook/hook_entry.h"
#include "../slat.h"

#include "../../arch/arch.h"
#include "../../memory_manager/memory_manager.h"
#include "../../memory_manager/heap_manager.h"
#include "../../crt/crt.h"
#include "../../logs/serial.h"

#include "../../structures/virtual_address.h"

using slat::hook::entry_t;

// Build a 14-byte absolute JMP: push low32; mov [rsp+4], high32; ret
static void build_abs_jmp(std::uint8_t* buf, std::uint64_t target)
{
    const std::uint32_t lo = static_cast<std::uint32_t>(target);
    const std::uint32_t hi = static_cast<std::uint32_t>(target >> 32);

    buf[0] = 0x68; // push imm32
    *reinterpret_cast<std::uint32_t*>(buf + 1) = lo;
    buf[5] = 0xC7; // mov [rsp+4], imm32
    buf[6] = 0x44;
    buf[7] = 0x24;
    buf[8] = 0x04;
    *reinterpret_cast<std::uint32_t*>(buf + 9) = hi;
    buf[13] = 0xC3; // ret
}

// EPT-split a page and register it as a shadow code page.
// Returns page_index or -1 on failure.
static int ept_split_page(
    const cr3 slat_cr3,
    const std::uint64_t va,
    const std::uint64_t pa_page,
    const std::uint8_t* orig_data)
{
    if (shadow_code::page_count >= shadow_code::max_pages)
        return -1;

    // Allocate shadow, copy original page contents
    void* shadow = heap_manager::allocate_page();
    if (!shadow) return -1;
    crt::copy_memory(shadow, orig_data, 0x1000);

    const std::uint64_t shadow_pa = memory_manager::unmap_host_physical(shadow);

    // NOTE: No explicit unhide needed here. Shadow page is a heap page, already
    // accessible in hook_cr3 via Hyper-V's 2MB identity-mapped EPT (shared with hyperv_cr3).
    // Heap hiding is disabled (set_up_hook_cr3 skips hide_heap_pages).
    // DO NOT call get_pte(hook_cr3, ..., force_split=1) here — it would modify shared
    // intermediate pages and corrupt hyperv_cr3 → HyperGuard PAGE_HASH_MISMATCH.

    // EPT-split: execute -> shadow (--X), read/write -> original (via hyperv_cr3)
    if (slat::hook::add({ .address = pa_page }, { .address = shadow_pa }, 0) == 0)
    {
        heap_manager::free_page(shadow);
        return -1;
    }

    // Mark as shadow_code_page (skip MTF write sync)
    entry_t* entry = entry_t::find(pa_page >> 12);
    if (entry)
        entry->set_shadow_code_page(1);

    const int idx = shadow_code::page_count;
    shadow_code::page_t& pg = shadow_code::pages[idx];
    pg.guest_va = va;
    pg.guest_pa = pa_page;
    pg.shadow_host_va = shadow;
    pg.active = 1;
    shadow_code::page_count++;

    return idx;
}

// Scan a page for CC/NOP runs and register them as regions.
// Returns number of regions added.
static int scan_and_register_runs(const std::uint8_t* data, int page_index)
{
    int added = 0;
    std::uint32_t run_start = 0;
    bool in_run = false;

    for (std::uint32_t i = 0; i <= 0x1000; i++)
    {
        const bool is_pad = (i < 0x1000) && (data[i] == 0xCC || data[i] == 0x90);

        if (is_pad && !in_run)
        {
            run_start = i;
            in_run = true;
        }
        else if (!is_pad && in_run)
        {
            const std::uint32_t run_len = i - run_start;

            if (run_len >= shadow_code::min_run_size &&
                shadow_code::region_count < shadow_code::max_regions)
            {
                // Align cursor to 16 bytes
                const std::uint16_t aligned_start = static_cast<std::uint16_t>((run_start + 15) & ~15u);
                if (aligned_start < i && (i - aligned_start) >= shadow_code::min_run_size)
                {
                    shadow_code::region_t& r = shadow_code::regions[shadow_code::region_count];
                    r.page_index = static_cast<std::uint8_t>(page_index);
                    r._pad = 0;
                    r.cursor = aligned_start;
                    r.end = static_cast<std::uint16_t>(i);
                    shadow_code::region_count++;
                    added++;
                }
            }

            in_run = false;
        }
    }

    return added;
}

std::uint64_t shadow_code::init(const std::uint64_t text_va, const std::uint64_t text_size, const std::uint64_t guest_cr3_flags)
{
    if (initialized)
        return region_count;

    // No per-attempt serial logging — this is called from VMEXIT handler (deferred retry).
    // Serial wait_tx_ready() at 115200 baud can stall ~7ms per log line → Hyper-V timeout.

    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 guest_cr3 = { .flags = guest_cr3_flags };

    const std::uint64_t text_end = text_va + text_size;

    for (std::uint64_t va = text_va & ~0xFFFull; va < text_end; va += 0x1000)
    {
        // Stop if we've filled up
        if (page_count >= max_pages || region_count >= max_regions)
            break;

        // Translate VA -> PA
        const std::uint64_t pa = memory_manager::translate_guest_virtual_address(
            guest_cr3, slat_cr3, { .address = va });
        if (pa == 0) continue;

        const std::uint64_t pa_page = pa & ~0xFFFull;

        // Skip if already EPT-hooked
        if (entry_t::find(pa_page >> 12) != nullptr)
            continue;

        // Map and scan for CC/NOP runs
        const auto* orig = static_cast<const std::uint8_t*>(
            memory_manager::map_guest_physical(slat_cr3, pa_page));
        if (!orig) continue;

        // Quick pre-scan: count total CC/NOP bytes. Skip if too few.
        int pad_count = 0;
        for (int i = 0; i < 0x1000; i++)
        {
            if (orig[i] == 0xCC || orig[i] == 0x90)
                pad_count++;
        }
        if (static_cast<std::uint32_t>(pad_count) < min_run_size)
            continue;

        // Detailed scan: find individual runs
        // Temporarily count runs without registering to avoid EPT-splitting pages with no usable runs
        int usable_runs = 0;
        {
            std::uint32_t rs = 0;
            bool ir = false;
            for (std::uint32_t i = 0; i <= 0x1000; i++)
            {
                const bool ip = (i < 0x1000) && (orig[i] == 0xCC || orig[i] == 0x90);
                if (ip && !ir) { rs = i; ir = true; }
                else if (!ip && ir)
                {
                    const std::uint32_t rl = i - rs;
                    const std::uint16_t as = static_cast<std::uint16_t>((rs + 15) & ~15u);
                    if (rl >= min_run_size && as < i && (i - as) >= min_run_size)
                        usable_runs++;
                    ir = false;
                }
            }
        }
        if (usable_runs == 0)
            continue;

        // EPT-split this page
        const int pg_idx = ept_split_page(slat_cr3, va, pa_page, orig);
        if (pg_idx < 0)
            continue;

        // Register all CC/NOP runs as regions
        const int added = scan_and_register_runs(orig, pg_idx);

        // per-page logging removed (called from VMEXIT handler, serial too slow)
    }

    initialized = true;

    // Single summary log (runs once, after all scanning is done)
    std::uint32_t total_free = 0;
    for (int i = 0; i < region_count; i++)
        total_free += regions[i].end - regions[i].cursor;
    serial::print("shadow_code: "); serial::print_dec(page_count); serial::print(" pages, ");
    serial::print_dec(region_count); serial::print(" regions, ");
    serial::print_dec(total_free); serial::println("B usable");

    return region_count;
}

std::uint64_t shadow_code::alloc(const std::uint32_t size, void** host_ptr)
{
    if (!initialized || size == 0 || size > 0x1000)
        return 0;

    for (int i = 0; i < region_count; i++)
    {
        region_t& r = regions[i];
        const page_t& pg = pages[r.page_index];
        if (!pg.active) continue;

        // Align cursor to 16 bytes
        const std::uint16_t aligned = static_cast<std::uint16_t>((r.cursor + 15) & ~15u);

        if (aligned + size <= r.end)
        {
            const std::uint64_t kernel_va = pg.guest_va + aligned;
            if (host_ptr)
                *host_ptr = static_cast<std::uint8_t*>(pg.shadow_host_va) + aligned;
            r.cursor = static_cast<std::uint16_t>(aligned + size);

            serial::reinit();  // reclaim COM1 from VMX root (serial.sys may have reconfigured)
            serial::print("shadow_code: alloc "); serial::print_dec(size);
            serial::print("B at "); serial::print_hex(kernel_va); serial::println("");

            return kernel_va;
        }
    }

    serial::reinit();  // reclaim COM1 from VMX root
    serial::println("shadow_code: alloc FAILED — no space");
    return 0;
}

std::uint64_t shadow_code::alloc_trampoline(
    const std::uint8_t* orig_bytes,
    const std::uint32_t displaced_count,
    const std::uint64_t resume_va)
{
    const std::uint32_t total = displaced_count + 14; // displaced bytes + abs JMP

    void* host_ptr = nullptr;
    const std::uint64_t tramp_va = alloc(total, &host_ptr);
    if (tramp_va == 0 || host_ptr == nullptr)
        return 0;

    auto* buf = static_cast<std::uint8_t*>(host_ptr);

    // Copy displaced prologue bytes
    crt::copy_memory(buf, orig_bytes, displaced_count);

    // Append 14-byte absolute JMP back to resume_va
    build_abs_jmp(buf + displaced_count, resume_va);

    serial::print("shadow_code: trampoline at "); serial::print_hex(tramp_va);
    serial::print(" -> "); serial::print_hex(resume_va); serial::println("");

    return tramp_va;
}
