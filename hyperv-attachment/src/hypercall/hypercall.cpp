#include "hypercall.h"
#include "../memory_manager/memory_manager.h"
#include "../memory_manager/heap_manager.h"

#include "../slat/slat.h"
#include "../slat/cr3/cr3.h"
#include "../slat/violation/mtf_context.h"
#include "../slat/cr3/pte.h"
#include "../slat/hook/hook.h"
#include "../slat/hook/hook_entry.h"
#include "../slat/monitor/monitor.h"
#include "../slat/shadow_code/shadow_code.h"

#include "../arch/arch.h"
#include "../logs/logs.h"
#include "../logs/serial.h"
#include "../crt/crt.h"
#include "../cr3_intercept.h"
#include "../interrupts/interrupts.h"

#include <ia32-doc/ia32.hpp>
#include <hypercall/hypercall_def.h>
#include <intrin.h>

// Hook 3 diagnostic counters (defined in main.cpp)
extern volatile long long hook3_on_hook_cr3_count;
extern volatile long long hook3_on_hyperv_cr3_count;
extern volatile long long hook3_rebootstrap_count;

//=============================================================================
// Shadow guest page helpers
//=============================================================================

// Unhide a heap page in hook_cr3 ONLY (set to RWX).
// CRITICAL: Must use fork_get_pte, NOT get_pte. hook_cr3 is a shallow copy
// of hyperv_cr3 — intermediate pages (PDPT, PD) are SHARED. Using get_pte
// with force_split writes to shared pages → corrupts hyperv_cr3 → HyperGuard
// PAGE_HASH_MISMATCH → instant reboot (triple fault in host mode).
// fork_get_pte forks intermediate pages before modifying, keeping hyperv_cr3 pristine.
void unhide_physical_page(const cr3& /*slat_cr3*/, std::uint64_t pa)
{
    const cr3 hook = slat::hook_cr3();
    if (hook.flags == 0)
        return;

    std::uint8_t split_state = 0;
    slat_pte* pte = slat::fork_get_pte(hook, slat::hyperv_cr3(), { .address = pa }, 1, &split_state);
    if (!pte) return;

    pte->page_frame_number = pa >> 12;
    pte->read_access = 1;
    pte->write_access = 1;
    pte->execute_access = 1;
}

// Clone a guest page table page (PDPT, PD, or PT) privately for clone CR3.
// Returns host VA of the new page (caller uses unmap_host_physical to get PA).
void* clone_guest_pt_page(const cr3& slat_cr3, std::uint64_t original_gpa)
{
    void* new_page = heap_manager::allocate_page();
    if (!new_page) return nullptr;
    crt::set_memory(new_page, 0, 0x1000);

    const void* original = memory_manager::map_guest_physical(slat_cr3, original_gpa);
    if (original) crt::copy_memory(new_page, original, 0x1000);

    std::uint64_t new_pa = memory_manager::unmap_host_physical(new_page);
    unhide_physical_page(slat_cr3, new_pa);
    return new_page;
}

// Shadow a single 4KB guest page under the clone CR3.
// Uses find-or-create pattern with shadow registry. No PML4 protection.
// Returns shadow physical address on success, 0 on failure.
std::uint64_t shadow_guest_page_impl(const cr3& slat_cr3, std::uint64_t target_va)
{
    if (cr3_intercept::cloned_pml4_host_va == nullptr)
        return 0;

    const virtual_address_t va = { .address = target_va };
    const cr3 original_cr3 = { .flags = cr3_intercept::target_original_cr3 };

    // --- PML4 level ---
    auto* clone_pml4 = static_cast<pml4e_64*>(cr3_intercept::cloned_pml4_host_va);
    const auto* orig_pml4 = static_cast<const pml4e_64*>(
        memory_manager::map_guest_physical(slat_cr3, original_cr3.address_of_page_directory << 12));
    if (!orig_pml4) return 0;

    pml4e_64& clone_pml4e = clone_pml4[va.pml4_idx];
    const pml4e_64 orig_pml4e = orig_pml4[va.pml4_idx];
    if (!orig_pml4e.present || !clone_pml4e.present) return 0;

    // Find or create cloned PDPT
    auto* pdpt_reg = cr3_intercept::find_shadow_pdpt(static_cast<std::uint16_t>(va.pml4_idx));
    if (!pdpt_reg && clone_pml4e.page_frame_number == orig_pml4e.page_frame_number)
    {
        if (cr3_intercept::shadow_pdpt_count >= cr3_intercept::max_shadow_pdpts) return 0;
        void* new_pdpt = clone_guest_pt_page(slat_cr3, orig_pml4e.page_frame_number << 12);
        if (!new_pdpt) return 0;
        std::uint64_t new_pa = memory_manager::unmap_host_physical(new_pdpt);
        clone_pml4e.page_frame_number = new_pa >> 12;
        pdpt_reg = &cr3_intercept::shadow_pdpts[cr3_intercept::shadow_pdpt_count++];
        pdpt_reg->pml4_idx = static_cast<std::uint16_t>(va.pml4_idx);
        pdpt_reg->cloned_pa = new_pa;
    }

    // --- PDPT level ---
    auto* clone_pdpt = static_cast<pdpte_64*>(
        memory_manager::map_guest_physical(slat_cr3, clone_pml4e.page_frame_number << 12));
    const auto* orig_pdpt = static_cast<const pdpte_64*>(
        memory_manager::map_guest_physical(slat_cr3, orig_pml4e.page_frame_number << 12));
    if (!clone_pdpt || !orig_pdpt) return 0;

    pdpte_64& clone_pdpte = clone_pdpt[va.pdpt_idx];
    const pdpte_64 orig_pdpte = orig_pdpt[va.pdpt_idx];
    if (!orig_pdpte.present || !clone_pdpte.present) return 0;
    if (orig_pdpte.large_page) return 0; // 1GB page not supported

    // Find or create cloned PD
    auto* pd_reg = cr3_intercept::find_shadow_pd(
        static_cast<std::uint16_t>(va.pml4_idx), static_cast<std::uint16_t>(va.pdpt_idx));
    if (!pd_reg && clone_pdpte.page_frame_number == orig_pdpte.page_frame_number)
    {
        if (cr3_intercept::shadow_pd_count >= cr3_intercept::max_shadow_pds) return 0;
        void* new_pd = clone_guest_pt_page(slat_cr3, orig_pdpte.page_frame_number << 12);
        if (!new_pd) return 0;
        std::uint64_t new_pa = memory_manager::unmap_host_physical(new_pd);
        clone_pdpte.page_frame_number = new_pa >> 12;
        pd_reg = &cr3_intercept::shadow_pds[cr3_intercept::shadow_pd_count++];
        pd_reg->pml4_idx = static_cast<std::uint16_t>(va.pml4_idx);
        pd_reg->pdpt_idx = static_cast<std::uint16_t>(va.pdpt_idx);
        pd_reg->cloned_pa = new_pa;
    }

    // --- PD level ---
    auto* clone_pd = static_cast<pde_64*>(
        memory_manager::map_guest_physical(slat_cr3, clone_pdpte.page_frame_number << 12));
    const auto* orig_pd = static_cast<const pde_64*>(
        memory_manager::map_guest_physical(slat_cr3, orig_pdpte.page_frame_number << 12));
    if (!clone_pd || !orig_pd) return 0;

    pde_64& clone_pde = clone_pd[va.pd_idx];
    const pde_64 orig_pde = orig_pd[va.pd_idx];
    if (!orig_pde.present || !clone_pde.present) return 0;
    if (orig_pde.large_page) return 0; // 2MB page — TODO: split

    // Find or create cloned PT
    auto* pt_reg = cr3_intercept::find_shadow_pt(
        static_cast<std::uint16_t>(va.pml4_idx), static_cast<std::uint16_t>(va.pdpt_idx),
        static_cast<std::uint16_t>(va.pd_idx));
    if (!pt_reg && clone_pde.page_frame_number == orig_pde.page_frame_number)
    {
        if (cr3_intercept::shadow_pt_count >= cr3_intercept::max_shadow_pts) return 0;
        void* new_pt = clone_guest_pt_page(slat_cr3, orig_pde.page_frame_number << 12);
        if (!new_pt) return 0;
        std::uint64_t new_pa = memory_manager::unmap_host_physical(new_pt);
        clone_pde.page_frame_number = new_pa >> 12;
        pt_reg = &cr3_intercept::shadow_pts[cr3_intercept::shadow_pt_count++];
        pt_reg->pml4_idx = static_cast<std::uint16_t>(va.pml4_idx);
        pt_reg->pdpt_idx = static_cast<std::uint16_t>(va.pdpt_idx);
        pt_reg->pd_idx = static_cast<std::uint16_t>(va.pd_idx);
        pt_reg->cloned_pa = new_pa;
    }

    // --- PT level ---
    auto* clone_pt = static_cast<pte_64*>(
        memory_manager::map_guest_physical(slat_cr3, clone_pde.page_frame_number << 12));
    if (!clone_pt) return 0;

    pte_64& clone_pte = clone_pt[va.pt_idx];
    if (!clone_pte.present) return 0;

    // Check if already shadowed
    auto* existing_leaf = cr3_intercept::find_shadow_leaf(
        static_cast<std::uint16_t>(va.pml4_idx), static_cast<std::uint16_t>(va.pdpt_idx),
        static_cast<std::uint16_t>(va.pd_idx), static_cast<std::uint16_t>(va.pt_idx));
    if (existing_leaf) return existing_leaf->shadow_pa;

    // Allocate shadow physical page and copy original content
    if (cr3_intercept::shadow_leaf_count >= cr3_intercept::max_shadow_leaves) return 0;

    void* shadow_page = heap_manager::allocate_page();
    if (!shadow_page) return 0;

    const std::uint64_t orig_pa = clone_pte.page_frame_number << 12;
    const void* orig_mapped = memory_manager::map_guest_physical(slat_cr3, orig_pa);
    if (orig_mapped)
        crt::copy_memory(shadow_page, orig_mapped, 0x1000);
    else
        crt::set_memory(shadow_page, 0, 0x1000);

    std::uint64_t shadow_pa = memory_manager::unmap_host_physical(shadow_page);
    unhide_physical_page(slat_cr3, shadow_pa);

    // Point clone PTE at shadow page, make writable (shadow exists to be modified)
    clone_pte.page_frame_number = shadow_pa >> 12;
    clone_pte.write = 1;

    // Register shadow leaf
    auto& leaf = cr3_intercept::shadow_leaves[cr3_intercept::shadow_leaf_count++];
    leaf.pml4_idx = static_cast<std::uint16_t>(va.pml4_idx);
    leaf.pdpt_idx = static_cast<std::uint16_t>(va.pdpt_idx);
    leaf.pd_idx = static_cast<std::uint16_t>(va.pd_idx);
    leaf.pt_idx = static_cast<std::uint16_t>(va.pt_idx);
    leaf.shadow_pa = shadow_pa;
    leaf.saved_pte_flags = clone_pte.flags;

    slat::flush_all_logical_processors_cache();

    // INVEPT alone only invalidates GPA->HPA (EPT) cached translations.
    // We also need INVVPID to flush the guest-linear TLB entries (GVA->GPA)
    // so the CPU re-walks the clone page tables and sees our new shadow PTE.
#ifdef _INTELMACHINE
    arch::invalidate_vpid_current();
#endif

    return shadow_pa;
}

// Unshadow a single 4KB guest page: registry-based lookup, restore original PFN, free shadow.
// Returns 1 on success, 0 on failure.
std::uint64_t unshadow_guest_page_impl(const cr3& slat_cr3, std::uint64_t target_va)
{
    if (cr3_intercept::cloned_pml4_host_va == nullptr)
        return 0;

    const virtual_address_t va = { .address = target_va };

    // 1. Find shadow leaf in registry
    auto* leaf = cr3_intercept::find_shadow_leaf(
        static_cast<std::uint16_t>(va.pml4_idx), static_cast<std::uint16_t>(va.pdpt_idx),
        static_cast<std::uint16_t>(va.pd_idx), static_cast<std::uint16_t>(va.pt_idx));
    if (!leaf) return 0;

    // 2. Walk original CR3 to get original PFN
    const cr3 original_cr3 = { .flags = cr3_intercept::target_original_cr3 };
    const std::uint64_t orig_pa = memory_manager::translate_guest_virtual_address(
        original_cr3, slat_cr3, va);
    if (orig_pa == 0) return 0;

    const std::uint64_t orig_pfn = (orig_pa & ~0xFFFull) >> 12;

    // 3. Find parent cloned PT and restore original PFN
    auto* pt_reg = cr3_intercept::find_shadow_pt(
        static_cast<std::uint16_t>(va.pml4_idx), static_cast<std::uint16_t>(va.pdpt_idx),
        static_cast<std::uint16_t>(va.pd_idx));
    if (pt_reg)
    {
        auto* cloned_pt = static_cast<pte_64*>(memory_manager::map_host_physical(pt_reg->cloned_pa));
        if (cloned_pt)
            cloned_pt[va.pt_idx].page_frame_number = orig_pfn;
    }

    // 4. Free shadow page
    const std::uint64_t shadow_pa = leaf->shadow_pa;
    void* shadow_host_va = memory_manager::map_host_physical(shadow_pa);
    if (shadow_host_va)
        heap_manager::free_page(shadow_host_va);

    // 5. Remove leaf from registry
    const int leaf_idx = static_cast<int>(leaf - cr3_intercept::shadow_leaves);
    cr3_intercept::remove_shadow_leaf(leaf_idx);

    slat::flush_all_logical_processors_cache();
#ifdef _INTELMACHINE
    arch::invalidate_vpid_current();
#endif
    return 1;
}

//=============================================================================
// External stealth R/W via clone CR3
//
// These functions let usermode read/write the target process memory through
// the clone CR3 instead of the original. The anticheat reads via the original
// CR3 and sees clean bytes; the target executes via the clone and sees our
// modifications. Pages that aren't yet forked (shadow == original) get
// auto-shadowed on first write so the original stays untouched.
//=============================================================================

// WriteCloneVirtualMemory: write into the clone CR3's address space.
// Auto-shadows pages that haven't been forked yet (clone PTE == original PTE).
//
// Parameters (from trap frame):
//   RDX = dest_va      — destination VA in the target process (clone CR3)
//   R8  = source_va    — source VA in the caller's address space
//   R9  = size         — number of bytes to write
//
// Returns: number of bytes successfully written
std::uint64_t WriteCloneVirtualMemory_impl(const trap_frame_t* trap_frame)
{
    // 1. Validate: clone must exist
    if (cr3_intercept::cloned_pml4_host_va == nullptr)
        return 0;

    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 clone_cr3   = { .address_of_page_directory = cr3_intercept::cloned_cr3_value >> 12 };
    const cr3 original_cr3 = { .flags = cr3_intercept::target_original_cr3 };
    const cr3 caller_cr3  = arch::get_guest_cr3(); // usermode caller's CR3

    const std::uint64_t dest_va   = trap_frame->rdx;
    const std::uint64_t source_va = trap_frame->r8;
    std::uint64_t size_remaining  = trap_frame->r9;
    std::uint64_t bytes_written   = 0;

    // 2. Process page by page (handles cross-page writes)
    while (size_remaining > 0)
    {
        const std::uint64_t current_dest = dest_va + bytes_written;
        const std::uint64_t current_src  = source_va + bytes_written;

        // 2a. Translate dest_va through clone CR3 → get current clone GPA
        std::uint64_t dest_virt_left = 0;
        const std::uint64_t clone_gpa = memory_manager::translate_guest_virtual_address(
            clone_cr3, slat_cr3, { .address = current_dest }, &dest_virt_left);
        if (clone_gpa == 0) break;

        // 2b. Translate dest_va through original CR3 → get original GPA
        const std::uint64_t orig_gpa = memory_manager::translate_guest_virtual_address(
            original_cr3, slat_cr3, { .address = current_dest });
        if (orig_gpa == 0) break;

        // 2c. If page-aligned GPAs match, the page isn't shadowed yet → auto-shadow
        if ((clone_gpa & ~0xFFFull) == (orig_gpa & ~0xFFFull))
        {
            const std::uint64_t shadow_result = shadow_guest_page_impl(slat_cr3, current_dest);
            if (shadow_result == 0) break; // shadow allocation failed
        }

        // 2d. Re-translate through clone (now points to shadow page)
        std::uint64_t shadow_virt_left = 0;
        const std::uint64_t shadow_gpa = memory_manager::translate_guest_virtual_address(
            clone_cr3, slat_cr3, { .address = current_dest }, &shadow_virt_left);
        if (shadow_gpa == 0) break;

        // 2e. Translate source VA in caller's address space
        std::uint64_t src_virt_left = 0;
        const std::uint64_t src_gpa = memory_manager::translate_guest_virtual_address(
            caller_cr3, slat_cr3, { .address = current_src }, &src_virt_left);
        if (src_gpa == 0) break;

        // 2f. Map both physical pages and copy
        void* dst_mapped = memory_manager::map_guest_physical(slat_cr3, shadow_gpa);
        const void* src_mapped = memory_manager::map_guest_physical(slat_cr3, src_gpa);
        if (!dst_mapped || !src_mapped) break;

        // Calculate how many bytes we can copy within current page boundaries
        const std::uint64_t page_budget = crt::min(shadow_virt_left, src_virt_left);
        const std::uint64_t copy_size   = crt::min(size_remaining, page_budget);
        if (copy_size == 0) break;

        crt::copy_memory(dst_mapped, src_mapped, copy_size);

        bytes_written  += copy_size;
        size_remaining -= copy_size;
    }

    return bytes_written;
}

// ReadCloneVirtualMemory: read from the clone CR3's address space.
// Returns what the target process actually sees (shadow pages if present,
// original pages otherwise). Useful to verify stealth writes.
//
// Parameters (from trap frame):
//   RDX = source_va    — source VA in the target process (clone CR3)
//   R8  = dest_va      — destination VA in the caller's address space
//   R9  = size         — number of bytes to read
//
// Returns: number of bytes successfully read
std::uint64_t ReadCloneVirtualMemory_impl(const trap_frame_t* trap_frame)
{
    // 1. Validate: clone must exist
    if (cr3_intercept::cloned_pml4_host_va == nullptr)
        return 0;

    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 clone_cr3  = { .address_of_page_directory = cr3_intercept::cloned_cr3_value >> 12 };
    const cr3 caller_cr3 = arch::get_guest_cr3(); // usermode caller's CR3

    const std::uint64_t source_va = trap_frame->rdx;
    const std::uint64_t dest_va   = trap_frame->r8;
    std::uint64_t size_remaining  = trap_frame->r9;
    std::uint64_t bytes_read      = 0;

    // 2. Process page by page
    while (size_remaining > 0)
    {
        const std::uint64_t current_src  = source_va + bytes_read;
        const std::uint64_t current_dest = dest_va + bytes_read;

        // 2a. Translate source VA through clone CR3
        std::uint64_t src_virt_left = 0;
        const std::uint64_t src_gpa = memory_manager::translate_guest_virtual_address(
            clone_cr3, slat_cr3, { .address = current_src }, &src_virt_left);
        if (src_gpa == 0) break;

        // 2b. Translate dest VA in caller's address space
        std::uint64_t dst_virt_left = 0;
        const std::uint64_t dst_gpa = memory_manager::translate_guest_virtual_address(
            caller_cr3, slat_cr3, { .address = current_dest }, &dst_virt_left);
        if (dst_gpa == 0) break;

        // 2c. Map both and copy
        const void* src_mapped = memory_manager::map_guest_physical(slat_cr3, src_gpa);
        void* dst_mapped = memory_manager::map_guest_physical(slat_cr3, dst_gpa);
        if (!src_mapped || !dst_mapped) break;

        const std::uint64_t page_budget = crt::min(src_virt_left, dst_virt_left);
        const std::uint64_t copy_size   = crt::min(size_remaining, page_budget);
        if (copy_size == 0) break;

        crt::copy_memory(dst_mapped, src_mapped, copy_size);

        bytes_read     += copy_size;
        size_remaining -= copy_size;
    }

    return bytes_read;
}

//=============================================================================
// EPT inline hook helpers (relay commands 4/5/6)
//=============================================================================

std::uint64_t ept_hook_code_impl(const cr3& slat_cr3, std::uint64_t target_va, std::uint64_t detour_va)
{
    // Error codes: 0xE0 = no clone, 0xE1 = translate fail, 0xE2 = page boundary,
    // 0xE3 = registry full, 0xE4 = already hooked, 0xE5 = alloc fail, 0xE6 = hook::add fail

    if (cr3_intercept::cloned_pml4_host_va == nullptr)
        return 0xE0;

    // 1. Translate target_va → target_pa using the game's original CR3
    const cr3 original_cr3 = { .flags = cr3_intercept::target_original_cr3 };
    const std::uint64_t target_pa = memory_manager::translate_guest_virtual_address(
        original_cr3, slat_cr3, { .address = target_va });
    if (target_pa == 0) return 0xE1;

    // 2. Check page boundary (14-byte JMP must not cross pages)
    const std::uint64_t page_offset = target_pa & 0xFFF;
    const std::uint64_t target_pa_page = target_pa & ~0xFFFull;
    if (page_offset + 14 > 0x1000) return 0xE2;

    // 3. Check registry limit
    if (cr3_intercept::usermode_ept_hook_count >= cr3_intercept::max_usermode_ept_hooks)
        return 0xE3;

    // 4. Check if page already has a hook — if so, merge onto same shadow page
    auto* existing = cr3_intercept::find_usermode_ept_hook(target_pa_page);
    if (existing != nullptr)
    {
        // Same-page hook: reuse existing shadow page, just patch the new detour
        auto* shadow_va = static_cast<std::uint8_t*>(existing->shadow_heap_va);
        auto* patch = shadow_va + page_offset;
        patch[0] = 0x68;                                                    // push imm32
        *reinterpret_cast<std::uint32_t*>(patch + 1) = static_cast<std::uint32_t>(detour_va);
        patch[5] = 0xC7; patch[6] = 0x44; patch[7] = 0x24; patch[8] = 0x04; // mov [rsp+4], imm32
        *reinterpret_cast<std::uint32_t*>(patch + 9) = static_cast<std::uint32_t>(detour_va >> 32);
        patch[13] = 0xC3;                                                    // ret

        // Register second hook region in the hook_entry
        slat::hook::add_to_same_page({ .address = target_pa_page | page_offset }, 14);

        // Flush EPT on all LPs so every CPU re-fetches from the updated shadow page
        slat::flush_all_logical_processors_cache();

        return (target_pa_page & ~0xFFFull) | 1;
    }

    // 5. Allocate shadow heap page
    void* shadow_va = heap_manager::allocate_page();
    if (shadow_va == nullptr) return 0xE5;

    // 6. Copy original code page into shadow
    const void* orig = memory_manager::map_guest_physical(slat_cr3, target_pa_page);
    if (orig != nullptr)
        crt::copy_memory(shadow_va, orig, 0x1000);
    else
        crt::set_memory(shadow_va, 0, 0x1000);

    // 7. Write 14-byte absolute JMP at shadow[page_offset]
    auto* patch = static_cast<std::uint8_t*>(shadow_va) + page_offset;
    patch[0] = 0x68;                                                    // push imm32
    *reinterpret_cast<std::uint32_t*>(patch + 1) = static_cast<std::uint32_t>(detour_va);
    patch[5] = 0xC7; patch[6] = 0x44; patch[7] = 0x24; patch[8] = 0x04; // mov [rsp+4], imm32
    *reinterpret_cast<std::uint32_t*>(patch + 9) = static_cast<std::uint32_t>(detour_va >> 32);
    patch[13] = 0xC3;                                                    // ret

    // 8. Get shadow physical address and unhide in EPT
    const std::uint64_t shadow_pa = memory_manager::unmap_host_physical(shadow_va);
    unhide_physical_page(slat_cr3, shadow_pa);

    // 9. Add EPT hook: hyperv_cr3[target_pa_page] = shadow --X, hook_cr3[target_pa_page] = original RW-
    if (slat::hook::add({ .address = target_pa_page }, { .address = shadow_pa }, 14) == 0)
    {
        heap_manager::free_page(shadow_va);
        return 0xE6;
    }

    // 10. Register in usermode EPT hook registry
    auto& entry = cr3_intercept::usermode_ept_hooks[cr3_intercept::usermode_ept_hook_count++];
    entry.target_pa_page = target_pa_page;
    entry.shadow_heap_va = shadow_va;

    // 11. Arm diagnostic: watch this PFN for EPT violations
    cr3_intercept::diag_watch_pfn = target_pa_page >> 12;
    cr3_intercept::diag_watch_pfn_exec_count = 0;
    cr3_intercept::diag_watch_pfn_rw_count = 0;

    // Encode target_pa_page into upper bits of success result so DLL can log it
    // Result: bits [63:12] = target_pa_page, bits [11:0] = 1 (success)
    return (target_pa_page & ~0xFFFull) | 1;
}

std::uint64_t ept_unhook_code_impl(const cr3& slat_cr3, std::uint64_t target_va)
{
    if (cr3_intercept::cloned_pml4_host_va == nullptr)
        return 0;

    // 1. Translate target_va → target_pa
    const cr3 original_cr3 = { .flags = cr3_intercept::target_original_cr3 };
    const std::uint64_t target_pa = memory_manager::translate_guest_virtual_address(
        original_cr3, slat_cr3, { .address = target_va });
    if (target_pa == 0) return 0;

    const std::uint64_t target_pa_page = target_pa & ~0xFFFull;

    // 2. Find in registry
    auto* hook_entry = cr3_intercept::find_usermode_ept_hook(target_pa_page);
    if (hook_entry == nullptr) return 0;

    const int hook_idx = static_cast<int>(hook_entry - cr3_intercept::usermode_ept_hooks);
    void* shadow_heap_va = hook_entry->shadow_heap_va;

    // 3. Remove EPT hook (restores original EPT PTEs)
    slat::hook::remove({ .address = target_pa_page });

    // 4. Free shadow heap page
    heap_manager::free_page(shadow_heap_va);

    // 5. Remove from registry (swap-and-decrement)
    cr3_intercept::remove_usermode_ept_hook(hook_idx);

    return 1;
}

std::uint64_t alloc_hidden_page_impl()
{
    if (cr3_intercept::hidden_pt_host_va == nullptr)
        return 0;

    // 1. Scan PT for free slot
    auto* pt = static_cast<pte_64*>(cr3_intercept::hidden_pt_host_va);
    int free_index = -1;
    for (int i = 0; i < 512; i++)
    {
        if (!pt[i].present)
        {
            free_index = i;
            break;
        }
    }
    if (free_index < 0) return 0;

    // 2. Allocate heap page, zero it
    void* page_va = heap_manager::allocate_page();
    if (page_va == nullptr) return 0;
    crt::set_memory(page_va, 0, 0x1000);

    // 3. Get PA, unhide in hook_cr3 only (RWX + user_mode_execute).
    // hyperv_cr3 already covers heap pages via Hyper-V's 2MB identity-mapped EPT.
    // DO NOT modify hyperv_cr3 — force-splitting triggers HyperGuard hash mismatch.
    const std::uint64_t data_pa = memory_manager::unmap_host_physical(page_va);
    const cr3 hook = slat::hook_cr3();

    if (hook.flags != 0)
    {
        std::uint8_t split_state_579 = 0;
        slat_pte* const pte = slat::fork_get_pte(hook, slat::hyperv_cr3(), { .address = data_pa }, 1, &split_state_579);
        if (pte != nullptr)
        {
            pte->page_frame_number = data_pa >> 12;
            pte->read_access = 1;
            pte->write_access = 1;
            pte->execute_access = 1;
#ifdef _INTELMACHINE
            pte->user_mode_execute = 1;
#endif
        }
    }

    // 4. Set PT[free_index] -> data page (present + write + user = 0x7)
    pt[free_index].flags = (data_pa & 0xFFFFFFFFF000ull) | 0x7;

    // 5. Flush EPT + guest-linear TLB caches
    slat::flush_all_logical_processors_cache();
#ifdef _INTELMACHINE
    arch::invalidate_vpid_current();
#endif

    // 6. Return VA in the hidden region
    return (cr3_intercept::reserved_pml4e_index << 39) + (static_cast<std::uint64_t>(free_index) * 0x1000);
}

//=============================================================================
// KiDispatchException EPT hook — safe memory probes
//=============================================================================

// Setup exception handler: EPT hook KiDispatchException with CPUID stub on shadow page
// Args: target_va = KiDispatchException VA, displaced_count = instruction-aligned bytes >= 8,
//       packed_offsets = (displaced_count & 0xFF) | (ktf_r10_offset << 8) | (ktf_rax_offset << 24)
// Returns: 1 on success, error codes on failure
std::uint64_t setup_exception_handler_impl(const cr3& slat_cr3, std::uint64_t target_va, std::uint64_t packed_offsets)
{
    if (cr3_intercept::exception_handler::active)
        return 0xF0; // already active

    const std::uint32_t displaced_count = static_cast<std::uint32_t>(packed_offsets & 0xFF);
    const std::uint32_t ktf_r10_off = static_cast<std::uint32_t>((packed_offsets >> 8) & 0xFFFF);
    const std::uint32_t ktf_rax_off = static_cast<std::uint32_t>((packed_offsets >> 24) & 0xFFFF);

    if (displaced_count < 10 || displaced_count > 32)
        return 0xF1; // invalid displaced count (need >= 10 for push rcx + stub)

    // 1. Translate VA → PA using target process CR3
    const cr3 original_cr3 = { .flags = cr3_intercept::target_original_cr3 };
    const std::uint64_t target_pa = memory_manager::translate_guest_virtual_address(
        original_cr3, slat_cr3, { .address = target_va });
    if (target_pa == 0) return 0xF2;

    const std::uint64_t page_offset = target_pa & 0xFFF;
    const std::uint64_t target_pa_page = target_pa & ~0xFFFull;

    // Stub must fit within page (10 bytes: push rcx + mov ecx + cpuid + pop rcx + ret)
    if (page_offset + 10 > 0x1000) return 0xF3;

    // 2. Allocate shadow page
    void* shadow_va = heap_manager::allocate_page();
    if (shadow_va == nullptr) return 0xF4;

    // 3. Copy original code page into shadow
    const void* orig = memory_manager::map_guest_physical(slat_cr3, target_pa_page);
    if (orig != nullptr)
        crt::copy_memory(shadow_va, orig, 0x1000);
    else
        crt::set_memory(shadow_va, 0, 0x1000);

    // 4. Build CPUID value: hypercall_info_t with call_type=read_guest_cr3, reserved_data=21
    hypercall_info_t cpuid_info;
    cpuid_info.value = 0;
    cpuid_info.primary_key = hypercall_primary_key;
    cpuid_info.secondary_key = hypercall_secondary_key;
    cpuid_info.call_type = hypercall_type_t::read_guest_cr3;
    cpuid_info.call_reserved_data = 21;
    const std::uint32_t cpuid_value = static_cast<std::uint32_t>(cpuid_info.value);

    // 5. Write 10-byte stub at shadow[page_offset]:
    //    +0: push rcx                (51)              1 byte  — save ExceptionRecord
    //    +1: mov ecx, <cpuid_value>  (B9 xx xx xx xx)  5 bytes
    //    +6: cpuid                    (0F A2)           2 bytes — VMEXIT
    //    +8: pop rcx                  (59)              1 byte  — restore RCX
    //    +9: ret                      (C3)              1 byte  — suppress path
    auto* stub = static_cast<std::uint8_t*>(shadow_va) + page_offset;
    stub[0] = 0x51; // push rcx
    stub[1] = 0xB9; // mov ecx, imm32
    *reinterpret_cast<std::uint32_t*>(stub + 2) = cpuid_value;
    stub[6] = 0x0F;
    stub[7] = 0xA2;
    stub[8] = 0x59; // pop rcx
    stub[9] = 0xC3; // ret

    // 6. Scan shadow page for CC padding >= (1 + displaced_count + 14) bytes for trampoline
    //    Trampoline layout: pop rcx (1) + displaced bytes (N) + 14-byte JMP
    const std::uint32_t trampoline_size = 1 + displaced_count + 14;
    std::uint64_t cc_offset = 0;
    bool found_cc = false;

    for (std::uint64_t i = 0; i + trampoline_size <= 0x1000; i++)
    {
        // Skip the area we just patched (10-byte stub)
        if (i >= page_offset && i < page_offset + 10) continue;

        bool all_cc = true;
        for (std::uint32_t j = 0; j < trampoline_size; j++)
        {
            if (static_cast<std::uint8_t*>(shadow_va)[i + j] != 0xCC)
            {
                all_cc = false;
                break;
            }
        }
        if (all_cc)
        {
            cc_offset = i;
            found_cc = true;
            break;
        }
    }

    // 7. Trampoline placement — try KDE page first, then scan adjacent pages
    void* tramp_page_shadow_va = nullptr;
    std::uint64_t tramp_page_pa = 0;
    std::uint64_t tramp_page_va_base = 0;

    if (!found_cc)
    {
        // Fallback: scan adjacent kernel .text pages (±64 pages / 512KB) for CC padding
        const std::uint64_t kde_page_va = target_va - page_offset;

        for (int delta = 1; delta <= 512 && !found_cc; delta++)
        {
            for (int sign = 1; sign >= -1 && !found_cc; sign -= 2)
            {
                const std::uint64_t adj_va = kde_page_va + static_cast<std::int64_t>(sign * delta) * 0x1000;
                const std::uint64_t adj_pa = memory_manager::translate_guest_virtual_address(
                    original_cr3, slat_cr3, { .address = adj_va });
                if (adj_pa == 0) continue;

                const std::uint64_t adj_pa_page = adj_pa & ~0xFFFull;
                const void* adj_orig = memory_manager::map_guest_physical(slat_cr3, adj_pa_page);
                if (!adj_orig) continue;

                for (std::uint64_t i = 0; i + trampoline_size <= 0x1000; i++)
                {
                    bool all_cc = true;
                    for (std::uint32_t j = 0; j < trampoline_size; j++)
                    {
                        if (static_cast<const std::uint8_t*>(adj_orig)[i + j] != 0xCC)
                        {
                            all_cc = false;
                            break;
                        }
                    }
                    if (all_cc)
                    {
                        tramp_page_shadow_va = heap_manager::allocate_page();
                        if (!tramp_page_shadow_va) break; // alloc failed, try next page

                        crt::copy_memory(tramp_page_shadow_va, adj_orig, 0x1000);
                        tramp_page_pa = adj_pa_page;
                        tramp_page_va_base = adj_va;
                        cc_offset = i;
                        found_cc = true;
                        break;
                    }
                }
            }
        }

        if (!found_cc)
        {
            heap_manager::free_page(shadow_va);
            return 0xF5; // no CC padding found on KDE page or adjacent pages
        }
    }

    // 8. Write trampoline: pop rcx + displaced bytes + 14-byte JMP
    const auto* orig_bytes = static_cast<const std::uint8_t*>(orig) + page_offset;
    auto* trampoline = (tramp_page_shadow_va != nullptr)
        ? static_cast<std::uint8_t*>(tramp_page_shadow_va) + cc_offset
        : static_cast<std::uint8_t*>(shadow_va) + cc_offset;

    trampoline[0] = 0x59; // pop rcx — restore RCX saved by push rcx in stub
    crt::copy_memory(trampoline + 1, orig_bytes, displaced_count);

    const std::uint64_t resume_va = target_va + displaced_count;
    auto* jmp = trampoline + 1 + displaced_count;
    jmp[0] = 0x68; // push imm32
    *reinterpret_cast<std::uint32_t*>(jmp + 1) = static_cast<std::uint32_t>(resume_va);
    jmp[5] = 0xC7; jmp[6] = 0x44; jmp[7] = 0x24; jmp[8] = 0x04; // mov [rsp+4], imm32
    *reinterpret_cast<std::uint32_t*>(jmp + 9) = static_cast<std::uint32_t>(resume_va >> 32);
    jmp[13] = 0xC3; // ret

    // 9. If trampoline is on a separate page, install its EPT hook first
    if (tramp_page_shadow_va != nullptr)
    {
        const std::uint64_t tramp_shadow_pa = memory_manager::unmap_host_physical(tramp_page_shadow_va);
        unhide_physical_page(slat_cr3, tramp_shadow_pa);

        if (slat::hook::add({ .address = tramp_page_pa }, { .address = tramp_shadow_pa }, trampoline_size) == 0)
        {
            heap_manager::free_page(tramp_page_shadow_va);
            heap_manager::free_page(shadow_va);
            return 0xF7; // trampoline page EPT hook failed
        }
    }

    // 10. Get KDE shadow PA, unhide in EPT, add EPT hook
    const std::uint64_t shadow_pa = memory_manager::unmap_host_physical(shadow_va);
    unhide_physical_page(slat_cr3, shadow_pa);

    if (slat::hook::add({ .address = target_pa_page }, { .address = shadow_pa }, 10) == 0)
    {
        if (tramp_page_shadow_va != nullptr)
        {
            slat::hook::remove({ .address = tramp_page_pa });
            heap_manager::free_page(tramp_page_shadow_va);
        }
        heap_manager::free_page(shadow_va);
        return 0xF6; // hook::add failed
    }

    // 11. Store state
    cr3_intercept::exception_handler::ki_dispatch_exception_va = target_va;
    cr3_intercept::exception_handler::shadow_heap_va = shadow_va;
    cr3_intercept::exception_handler::target_pa_page = target_pa_page;
    cr3_intercept::exception_handler::ktf_rax_offset = ktf_rax_off;
    cr3_intercept::exception_handler::ktf_r10_offset = ktf_r10_off;
    cr3_intercept::exception_handler::ktf_rip_offset = 0x168; // standard, not packed

    if (tramp_page_shadow_va != nullptr)
    {
        cr3_intercept::exception_handler::trampoline_va = tramp_page_va_base + cc_offset;
        cr3_intercept::exception_handler::trampoline_shadow_heap_va = tramp_page_shadow_va;
        cr3_intercept::exception_handler::trampoline_pa_page = tramp_page_pa;
    }
    else
    {
        const std::uint64_t page_base_va = target_va - page_offset;
        cr3_intercept::exception_handler::trampoline_va = page_base_va + cc_offset;
        cr3_intercept::exception_handler::trampoline_shadow_heap_va = nullptr;
        cr3_intercept::exception_handler::trampoline_pa_page = 0;
    }

    cr3_intercept::exception_handler::suppress_ret_va = target_va + 8; // pop rcx; ret at stub+8

    cr3_intercept::exception_handler::active = true;

    return 1;
}

// KiPageFault inline EPT hook — zero-VMEXIT safety net for hidden memory #PFs
// Split design: 28-byte inline check on shadow page + full handler in code cave.
//
// Inline (28B at KiPageFault entry):
//   1. Check CR2 PML4 index == hidden_pml4_index (9-bit compare)
//   2. je  → code cave handler
//   3. jmp → code cave trampoline (displaced prologue → jmp back)
//
// Code cave (in CC padding, ~111 bytes):
//   [0-64]  Full CR3 check + swap + iretq (or fall through to .not_target)
//   [65-66] .not_target: pop rbx, pop rax
//   [67+]   Trampoline: displaced prologue + 14-byte jmp back
//
// Benefits over old 85-byte design:
//   - Only ~28-30 bytes displaced (standard prologue, zero RIP-relative risk)
//   - Correct 9-bit PML4 comparison (and eax, 0x1FF) — no PML4[N+256] collision
//   - Correct hook_byte_offset for MTF sync
std::uint64_t setup_ki_page_fault_hook_impl(const cr3& slat_cr3, std::uint64_t target_va, std::uint64_t packed_args)
{
    if (cr3_intercept::page_fault_hook::active)
        return 0xE0; // already active

    const std::uint8_t hidden_pml4_index = static_cast<std::uint8_t>(packed_args & 0xFF);
    const std::uint32_t displaced_count = static_cast<std::uint32_t>((packed_args >> 8) & 0xFF);

    constexpr std::uint32_t inline_handler_size = 28;
    constexpr std::uint32_t handler_cave_size = 67; // CR3 check + swap + iretq + .not_target pops

    // Cap displaced_count: cave_total_size = 81 + displaced_count must fit in
    // hook_byte_length2 (7 bits, max 127) for same-page caves.
    // 127 - 81 = 46 max displaced. Realistic values are ~28-30.
    if (displaced_count < inline_handler_size || displaced_count > 46)
        return 0xE1; // invalid displaced count

    // 1. Translate VA → PA
    const cr3 original_cr3 = { .flags = cr3_intercept::target_original_cr3 };
    const std::uint64_t target_pa = memory_manager::translate_guest_virtual_address(
        original_cr3, slat_cr3, { .address = target_va });
    if (target_pa == 0) return 0xE2;

    const std::uint64_t page_offset = target_pa & 0xFFF;
    const std::uint64_t target_pa_page = target_pa & ~0xFFFull;

    if (page_offset + displaced_count > 0x1000) return 0xE3; // crosses page boundary

    // 2. Allocate shadow page
    void* shadow_va = heap_manager::allocate_page();
    if (!shadow_va) return 0xE4;

    // 3. Copy original page
    const void* orig = memory_manager::map_guest_physical(slat_cr3, target_pa_page);
    if (orig)
        crt::copy_memory(shadow_va, orig, 0x1000);
    else
        crt::set_memory(shadow_va, 0, 0x1000);

    // 4. Extract constants from cr3_intercept state
    const std::uint64_t target_kernel_pfn = cr3_intercept::target_original_cr3 >> 12;
    const std::uint64_t target_user_pfn = cr3_intercept::target_user_cr3 >> 12;
    const std::uint64_t clone_cr3 = cr3_intercept::cloned_cr3_value;

    // 5. Find CC padding for code cave: handler + trampoline
    const std::uint32_t cave_total_size = handler_cave_size + displaced_count + 14;
    std::uint64_t cc_offset = 0;
    bool found_cc = false;
    bool cave_on_same_page = false;

    // Try same page first (skip over inline handler region)
    for (std::uint64_t i = 0; i + cave_total_size <= 0x1000; i++)
    {
        if (i >= page_offset && i < page_offset + displaced_count) continue;
        // Also skip if cave would overlap inline handler
        if (i + cave_total_size > page_offset && i < page_offset + inline_handler_size) continue;

        bool all_cc = true;
        for (std::uint32_t j = 0; j < cave_total_size; j++)
        {
            if (static_cast<std::uint8_t*>(shadow_va)[i + j] != 0xCC)
            {
                all_cc = false;
                break;
            }
        }
        if (all_cc) { cc_offset = i; found_cc = true; cave_on_same_page = true; break; }
    }

    void* cave_page_shadow_va = nullptr;
    std::uint64_t cave_page_pa = 0;
    std::uint64_t cave_page_va_base = 0;

    if (!found_cc)
    {
        // Scan adjacent kernel .text pages (±512 pages)
        const std::uint64_t page_va_base = target_va - page_offset;

        for (int delta = 1; delta <= 512 && !found_cc; delta++)
        {
            for (int sign = 1; sign >= -1 && !found_cc; sign -= 2)
            {
                const std::uint64_t adj_va = page_va_base + static_cast<std::int64_t>(sign * delta) * 0x1000;
                const std::uint64_t adj_pa = memory_manager::translate_guest_virtual_address(
                    original_cr3, slat_cr3, { .address = adj_va });
                if (adj_pa == 0) continue;

                const std::uint64_t adj_pa_page = adj_pa & ~0xFFFull;
                const void* adj_orig = memory_manager::map_guest_physical(slat_cr3, adj_pa_page);
                if (!adj_orig) continue;

                for (std::uint64_t i = 0; i + cave_total_size <= 0x1000; i++)
                {
                    bool all_cc = true;
                    for (std::uint32_t j = 0; j < cave_total_size; j++)
                    {
                        if (static_cast<const std::uint8_t*>(adj_orig)[i + j] != 0xCC)
                        {
                            all_cc = false;
                            break;
                        }
                    }
                    if (all_cc)
                    {
                        cave_page_shadow_va = heap_manager::allocate_page();
                        if (!cave_page_shadow_va) break;

                        crt::copy_memory(cave_page_shadow_va, adj_orig, 0x1000);
                        cave_page_pa = adj_pa_page;
                        cave_page_va_base = adj_va;
                        cc_offset = i;
                        found_cc = true;
                        break;
                    }
                }
            }
        }

        if (!found_cc)
        {
            heap_manager::free_page(shadow_va);
            return 0xE5; // no CC padding found
        }
    }

    // 6. Build code cave: handler (67B) + trampoline (displaced + 14B)
    auto* cave = cave_on_same_page
        ? static_cast<std::uint8_t*>(shadow_va) + cc_offset
        : static_cast<std::uint8_t*>(cave_page_shadow_va) + cc_offset;
    std::uint32_t cp = 0; // cave position

    auto cave_emit = [&](std::uint8_t b) { cave[cp++] = b; };
    auto cave_emit32 = [&](std::uint32_t v) {
        *reinterpret_cast<std::uint32_t*>(cave + cp) = v; cp += 4;
    };
    auto cave_emit64 = [&](std::uint64_t v) {
        *reinterpret_cast<std::uint64_t*>(cave + cp) = v; cp += 8;
    };

    // === Handler: CR3 PFN check + swap + iretq (67 bytes) ===
    // cave+0
    cave_emit(0x50);                                         // push rax
    cave_emit(0x53);                                         // push rbx
    cave_emit(0x0F); cave_emit(0x20); cave_emit(0xD8);       // mov rax, cr3
    cave_emit(0x48); cave_emit(0xC1); cave_emit(0xE8); cave_emit(0x0C); // shr rax, 12
    // cave+9
    cave_emit(0x48); cave_emit(0xBB); cave_emit64(target_kernel_pfn); // movabs rbx, kernel_pfn
    // cave+19
    cave_emit(0x48); cave_emit(0x39); cave_emit(0xD8);       // cmp rax, rbx
    cave_emit(0x74); cave_emit(0x14);                         // je .swap (cave+44 - cave+24 = 20)
    // cave+24
    cave_emit(0x48); cave_emit(0xBB); cave_emit64(target_user_pfn);   // movabs rbx, user_pfn
    // cave+34
    cave_emit(0x48); cave_emit(0x85); cave_emit(0xDB);       // test rbx, rbx
    cave_emit(0x74); cave_emit(0x1A);                         // jz .not_target (cave+65 - cave+39 = 26)
    // cave+39
    cave_emit(0x48); cave_emit(0x39); cave_emit(0xD8);       // cmp rax, rbx
    cave_emit(0x75); cave_emit(0x15);                         // jne .not_target (cave+65 - cave+44 = 21)

    // === .swap at cave+44 (21 bytes) ===
    cave_emit(0x5B);                                         // pop rbx
    cave_emit(0x48); cave_emit(0xB8); cave_emit64(clone_cr3); // movabs rax, clone_cr3_value
    cave_emit(0x0F); cave_emit(0x22); cave_emit(0xD8);       // mov cr3, rax
    cave_emit(0x58);                                         // pop rax
    cave_emit(0x48); cave_emit(0x83); cave_emit(0xC4); cave_emit(0x08); // add rsp, 8
    cave_emit(0x48); cave_emit(0xCF);                         // iretq

    // === .not_target at cave+65 (2 bytes) ===
    cave_emit(0x5B);                                         // pop rbx
    cave_emit(0x58);                                         // pop rax

    // cp should be 67 = handler_cave_size

    // === Trampoline at cave+67: displaced prologue + 14-byte JMP back ===
    const auto* orig_bytes = static_cast<const std::uint8_t*>(orig) + page_offset;
    crt::copy_memory(cave + cp, orig_bytes, displaced_count);
    cp += displaced_count;

    const std::uint64_t resume_va = target_va + displaced_count;
    cave[cp++] = 0x68; // push imm32
    *reinterpret_cast<std::uint32_t*>(cave + cp) = static_cast<std::uint32_t>(resume_va);
    cp += 4;
    cave[cp++] = 0xC7; cave[cp++] = 0x44; cave[cp++] = 0x24; cave[cp++] = 0x04; // mov [rsp+4], imm32
    *reinterpret_cast<std::uint32_t*>(cave + cp) = static_cast<std::uint32_t>(resume_va >> 32);
    cp += 4;
    cave[cp++] = 0xC3; // ret

    // cp should be handler_cave_size + displaced_count + 14 = cave_total_size

    // 7. Build inline handler (28 bytes) on shadow page
    auto* code = static_cast<std::uint8_t*>(shadow_va) + page_offset;
    std::uint32_t pos = 0;

    auto emit = [&](std::uint8_t b) { code[pos++] = b; };
    auto emit32 = [&](std::uint32_t v) {
        *reinterpret_cast<std::uint32_t*>(code + pos) = v; pos += 4;
    };

    // === CR2 PML4 index check with correct 9-bit comparison (17 bytes) ===
    emit(0x50);                                         // push rax
    emit(0x0F); emit(0x20); emit(0xD0);                 // mov rax, cr2
    emit(0x48); emit(0xC1); emit(0xE8); emit(0x27);     // shr rax, 39
    emit(0x25); emit32(0x000001FF);                      // and eax, 0x1FF (9-bit mask)
    emit(0x83); emit(0xF8); emit(hidden_pml4_index);     // cmp eax, imm8
    emit(0x58);                                         // pop rax
    // pos = 17

    // === je code_cave_handler (6 bytes, offset 17) ===
    emit(0x0F); emit(0x84);                              // je rel32
    emit32(0x00000000);                                  // placeholder — patched below
    // pos = 23

    // === jmp trampoline (5 bytes, offset 23) ===
    emit(0xE9);                                          // jmp rel32
    emit32(0x00000000);                                  // placeholder — patched below
    // pos = 28 = inline_handler_size

    // 8. Compute code cave VAs and patch inline jumps
    std::uint64_t cave_handler_va;  // cave+0
    std::uint64_t cave_trampoline_va; // cave+handler_cave_size = cave+67
    if (cave_on_same_page)
    {
        const std::uint64_t page_va_base = target_va - page_offset;
        cave_handler_va = page_va_base + cc_offset;
        cave_trampoline_va = page_va_base + cc_offset + handler_cave_size;
    }
    else
    {
        cave_handler_va = cave_page_va_base + cc_offset;
        cave_trampoline_va = cave_page_va_base + cc_offset + handler_cave_size;
    }

    // Patch je rel32 at inline offset 19 (after 0F 84): target = cave_handler_va
    const std::int64_t je_delta = static_cast<std::int64_t>(cave_handler_va)
                                - static_cast<std::int64_t>(target_va + 23); // next insn after je
    *reinterpret_cast<std::int32_t*>(code + 19) = static_cast<std::int32_t>(je_delta);

    // Patch jmp rel32 at inline offset 24 (after E9): target = cave_trampoline_va
    const std::int64_t jmp_delta = static_cast<std::int64_t>(cave_trampoline_va)
                                 - static_cast<std::int64_t>(target_va + 28); // next insn after jmp
    *reinterpret_cast<std::int32_t*>(code + 24) = static_cast<std::int32_t>(jmp_delta);

    // 9. Install EPT hooks
    if (!cave_on_same_page)
    {
        // Cave is on a separate page — needs its own EPT hook
        const std::uint64_t cave_shadow_pa = memory_manager::unmap_host_physical(cave_page_shadow_va);
        unhide_physical_page(slat_cr3, cave_shadow_pa);

        if (slat::hook::add({ .address = cave_page_pa | cc_offset }, { .address = cave_shadow_pa }, cave_total_size) == 0)
        {
            heap_manager::free_page(cave_page_shadow_va);
            heap_manager::free_page(shadow_va);
            return 0xE7; // code cave EPT hook failed
        }
    }

    const std::uint64_t shadow_pa = memory_manager::unmap_host_physical(shadow_va);
    unhide_physical_page(slat_cr3, shadow_pa);

    // Pass full PA (with page_offset) so hook_byte_offset is set correctly for MTF sync
    if (slat::hook::add({ .address = target_pa }, { .address = shadow_pa }, inline_handler_size) == 0)
    {
        if (!cave_on_same_page)
        {
            slat::hook::remove({ .address = cave_page_pa });
            heap_manager::free_page(cave_page_shadow_va);
        }
        heap_manager::free_page(shadow_va);
        return 0xE6; // KiPageFault EPT hook failed
    }

    // If cave is on the same page, register it as second hook region for MTF sync
    if (cave_on_same_page)
    {
        slat::hook::add_to_same_page({ .address = target_pa_page | cc_offset }, cave_total_size);
    }

    // 10. Store state
    cr3_intercept::page_fault_hook::ki_page_fault_va = target_va;
    cr3_intercept::page_fault_hook::shadow_heap_va = shadow_va;
    cr3_intercept::page_fault_hook::target_pa_page = target_pa_page;

    if (!cave_on_same_page)
    {
        cr3_intercept::page_fault_hook::trampoline_shadow_heap_va = cave_page_shadow_va;
        cr3_intercept::page_fault_hook::trampoline_pa_page = cave_page_pa;
    }
    else
    {
        cr3_intercept::page_fault_hook::trampoline_shadow_heap_va = nullptr;
        cr3_intercept::page_fault_hook::trampoline_pa_page = 0;
    }

    cr3_intercept::page_fault_hook::active = true;

    return 1;
}

// 14-byte absolute JMP: push low32; mov [rsp+4], high32; ret
// Identical to ring-1's BuildAbsoluteJump_14Bytes_PushRet
void build_abs_jmp(std::uint8_t* buf, std::uint64_t target)
{
    buf[0] = 0x68;
    *reinterpret_cast<std::uint32_t*>(buf + 1) = static_cast<std::uint32_t>(target);
    buf[5] = 0xC7; buf[6] = 0x44; buf[7] = 0x24; buf[8] = 0x04;
    *reinterpret_cast<std::uint32_t*>(buf + 9) = static_cast<std::uint32_t>(target >> 32);
    buf[13] = 0xC3;
}

//=============================================================================
// Attachment image mapping — makes compiled C++ code guest-executable
//=============================================================================

// MSVC linker auto-generated symbol — base of current PE image
extern "C" const std::uint8_t __ImageBase;

// Map the entire hyperv-attachment PE image into the hidden region.
// This makes compiled C++ functions (and their global data) accessible from
// guest context via the clone CR3, with the same RIP-relative offsets as
// in host mode. Like ring-1's mapping loop in hook_hv_launch, but into
// the hidden region (invisible to anti-cheat via PsWatch/KiPageFault hooks).
std::uint64_t map_attachment_to_hidden_region()
{
    using namespace cr3_intercept;

    if (attachment_mapping::mapped)
        return attachment_mapping::hidden_base_va;

    if (hidden_pt_host_va == nullptr || reserved_pml4e_index >= 512)
        return 0;

    // 1. Compute image base PA and size from PE headers
    const auto* base = &__ImageBase;
    const std::uint64_t image_base_host_va = reinterpret_cast<std::uint64_t>(base);
    const std::uint64_t image_base_pa = image_base_host_va - (255ull << 39);

    const std::uint32_t pe_offset = *reinterpret_cast<const std::uint32_t*>(base + 0x3C);
    const std::uint32_t size_of_image = *reinterpret_cast<const std::uint32_t*>(base + pe_offset + 0x50);
    const std::uint32_t page_count = (size_of_image + 0xFFF) >> 12;

    if (page_count == 0 || page_count > 256)
        return 0;

    // 2. Map from end of hidden PT downward (slots 0..255 reserved for dynamic alloc)
    auto* pt = static_cast<pte_64*>(hidden_pt_host_va);
    const std::uint16_t start_slot = static_cast<std::uint16_t>(512 - page_count);

    for (std::uint32_t i = 0; i < page_count; i++)
    {
        if (pt[start_slot + i].present)
            return 0; // slot conflict
    }

    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 hook = slat::hook_cr3();

    // 3. Map each image page into the hidden PT
    for (std::uint32_t i = 0; i < page_count; i++)
    {
        const std::uint64_t page_pa = image_base_pa + (static_cast<std::uint64_t>(i) << 12);

        // Guest PT entry: present + write + user (0x7) — matches existing hidden pages
        pt[start_slot + i].flags = (page_pa & 0xFFFFFFFFF000ull) | 0x7;

        // Ensure EPT allows RWX + UME in hook_cr3 only.
        // hyperv_cr3 already covers these pages via Hyper-V's 2MB identity-mapped EPT.
        // DO NOT modify hyperv_cr3 — force-splitting 2MB pages there triggers
        // HyperGuard PAGE_HASH_MISMATCH (EPT structure hash changes).
        if (hook.flags != 0)
        {
            std::uint8_t split_state_1220 = 0;
            slat_pte* pte = slat::fork_get_pte(hook, slat::hyperv_cr3(), { .address = page_pa }, 1, &split_state_1220);
            if (pte)
            {
                pte->page_frame_number = page_pa >> 12;
                pte->read_access = 1;
                pte->write_access = 1;
                pte->execute_access = 1;
#ifdef _INTELMACHINE
                pte->user_mode_execute = 1;
#endif
            }
        }
    }

    // 4. Flush TLBs
    slat::flush_all_logical_processors_cache();
#ifdef _INTELMACHINE
    arch::invalidate_vpid_current();
#endif

    // 5. Store state
    attachment_mapping::image_base_pa = image_base_pa;
    attachment_mapping::image_page_count = page_count;
    attachment_mapping::hidden_base_va = (reserved_pml4e_index << 39)
        + (static_cast<std::uint64_t>(start_slot) << 12);
    attachment_mapping::mapped = true;

    return attachment_mapping::hidden_base_va;
}

// Convert a host VA (PML4[255] identity map) to the equivalent hidden region VA
std::uint64_t host_va_to_hidden_va(std::uint64_t host_va)
{
    const std::uint64_t pa = host_va - (255ull << 39);
    const std::uint64_t offset = pa - cr3_intercept::attachment_mapping::image_base_pa;
    return cr3_intercept::attachment_mapping::hidden_base_va + offset;
}

// Forward declarations (defined later in file)
static std::uint64_t resolve_kernel_export(std::uint64_t module_base, const char* export_name);
std::uint64_t sig_scan_guest_pages(std::uint64_t base_va, std::uint64_t scan_size,
    const std::uint8_t* pattern, const char* mask, std::uint32_t pattern_len);
std::uint64_t setup_mmclean_inline_hook_impl(
    std::uint64_t target_va, std::uint64_t target_eprocess, std::uint32_t displaced_count);
std::uint64_t setup_mmclean_precheck_hook_impl(
    std::uint64_t target_va, std::uint64_t target_eprocess, std::uint32_t displaced_count);

// Helper: returns a valid guest CR3 for kernel VA translation.
// At boot (no target process yet), uses the current guest CR3 from VMCS.
// At runtime (target set), uses the cached target CR3.
static cr3 get_guest_cr3_for_translation()
{
    if (cr3_intercept::target_original_cr3 != 0)
        return { .flags = cr3_intercept::target_original_cr3 };
    return arch::get_guest_cr3();
}

//=============================================================================
// Autonomous kernel resolution — zero usermode dependency
//=============================================================================

// Forward declaration (defined below find_module_base)
static std::uint64_t get_module_size(std::uint64_t module_base);

// Scan backwards from a VA inside a module to find the MZ header (PE base).
// va_must_be_within: if nonzero, verify that this VA falls within [base, base+SizeOfImage).
// On KPTI systems, IDT handlers point to KVASCODE (mapped far from ntoskrnl .text).
// Walking backward can hit MZ headers of other modules in between.
// Passing the IDT handler VA here ensures we only return a base that actually owns it.
static std::uint64_t find_module_base(std::uint64_t va_inside_module, std::uint64_t va_must_be_within = 0)
{
    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 guest_cr3 = get_guest_cr3_for_translation();

    std::uint64_t page = va_inside_module & ~0xFFFull;
    for (int i = 0; i < 0x10000; i++) // max 256MB back
    {
        const std::uint64_t pa = memory_manager::translate_guest_virtual_address(
            guest_cr3, slat_cr3, { .address = page });
        if (pa != 0)
        {
            const auto* ptr = static_cast<const std::uint8_t*>(
                memory_manager::map_guest_physical(slat_cr3, pa));
            if (ptr && ptr[0] == 'M' && ptr[1] == 'Z')
            {
                // If caller requires the target VA to be within this module, verify SizeOfImage
                if (va_must_be_within != 0)
                {
                    const std::uint64_t mod_size = get_module_size(page);
                    if (mod_size == 0 || va_must_be_within < page || va_must_be_within >= page + mod_size)
                    {
                        // This MZ doesn't own the target VA — skip and keep scanning
                        page -= 0x1000;
                        continue;
                    }
                }
                return page;
            }
        }
        page -= 0x1000;
    }
    return 0;
}

// Read guest IDT handler VA for a given vector
static std::uint64_t read_idt_handler(std::uint8_t vector)
{
    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 guest_cr3 = get_guest_cr3_for_translation();
    const std::uint64_t idt_base = arch::get_guest_idtr_base();
    const std::uint64_t entry_va = idt_base + static_cast<std::uint64_t>(vector) * 16;

    const std::uint64_t entry_pa = memory_manager::translate_guest_virtual_address(
        guest_cr3, slat_cr3, { .address = entry_va });
    if (entry_pa == 0) return 0;

    const auto* desc = static_cast<const std::uint8_t*>(
        memory_manager::map_guest_physical(slat_cr3, entry_pa));
    if (!desc) return 0;

    const std::uint64_t offset_low = *reinterpret_cast<const std::uint16_t*>(desc);
    const std::uint64_t offset_mid = *reinterpret_cast<const std::uint16_t*>(desc + 6);
    const std::uint64_t offset_high = *reinterpret_cast<const std::uint32_t*>(desc + 8);
    return offset_low | (offset_mid << 16) | (offset_high << 32);
}

// Find ntoskrnl base via IDT — IDT #DE handler is in ntoskrnl (possibly KVASCODE section).
// On KPTI systems, IDT entries point to KVASCODE stubs mapped far from .text.
// find_module_base with va_must_be_within skips MZ headers of modules between KVASCODE and ntoskrnl base.
static std::uint64_t find_ntoskrnl_base()
{
    const std::uint64_t handler_va = read_idt_handler(0); // #DE always in ntoskrnl
    if (handler_va == 0) return 0;
    // No log here — called on every deferred retry (serial stalls VMEXIT handler)
    return find_module_base(handler_va, handler_va);
}

// Get ntoskrnl size from PE headers (for sig scan bounds)
static std::uint64_t get_module_size(std::uint64_t module_base)
{
    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 guest_cr3 = get_guest_cr3_for_translation();

    const std::uint64_t dos_pa = memory_manager::translate_guest_virtual_address(
        guest_cr3, slat_cr3, { .address = module_base });
    if (dos_pa == 0) return 0;
    const auto* dos = static_cast<const std::uint8_t*>(
        memory_manager::map_guest_physical(slat_cr3, dos_pa));
    if (!dos || dos[0] != 'M' || dos[1] != 'Z') return 0;

    const std::uint32_t e_lfanew = *reinterpret_cast<const std::uint32_t*>(dos + 0x3C);
    const std::uint64_t pe_va = module_base + e_lfanew;
    const std::uint64_t pe_pa = memory_manager::translate_guest_virtual_address(
        guest_cr3, slat_cr3, { .address = pe_va });
    if (pe_pa == 0) return 0;
    const auto* pe = static_cast<const std::uint8_t*>(
        memory_manager::map_guest_physical(slat_cr3, pe_pa));
    if (!pe || pe[0] != 'P' || pe[1] != 'E') return 0;

    // SizeOfImage at optional header offset 56 (PE64)
    return *reinterpret_cast<const std::uint32_t*>(pe + 24 + 56);
}

// Find .text section VA and size from PE headers.
// Returns true on success, fills text_va and text_size.
static bool find_text_section(std::uint64_t module_base, std::uint64_t* text_va, std::uint64_t* text_size)
{
    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 guest_cr3 = get_guest_cr3_for_translation();

    // Read DOS header → e_lfanew
    const std::uint64_t dos_pa = memory_manager::translate_guest_virtual_address(
        guest_cr3, slat_cr3, { .address = module_base });
    if (dos_pa == 0) return false;
    const auto* dos = static_cast<const std::uint8_t*>(
        memory_manager::map_guest_physical(slat_cr3, dos_pa));
    if (!dos || dos[0] != 'M' || dos[1] != 'Z') return false;

    const std::uint32_t e_lfanew = *reinterpret_cast<const std::uint32_t*>(dos + 0x3C);
    const std::uint64_t pe_va = module_base + e_lfanew;
    const std::uint64_t pe_pa = memory_manager::translate_guest_virtual_address(
        guest_cr3, slat_cr3, { .address = pe_va });
    if (pe_pa == 0) return false;
    const auto* pe = static_cast<const std::uint8_t*>(
        memory_manager::map_guest_physical(slat_cr3, pe_pa));
    if (!pe || pe[0] != 'P' || pe[1] != 'E') return false;

    // COFF FileHeader: NumberOfSections at PE+6, SizeOfOptionalHeader at PE+20
    const std::uint16_t num_sections = *reinterpret_cast<const std::uint16_t*>(pe + 6);
    const std::uint16_t opt_header_size = *reinterpret_cast<const std::uint16_t*>(pe + 20);

    // Section headers start at PE + 24 + SizeOfOptionalHeader, each 40 bytes
    const std::uint64_t sections_rva = e_lfanew + 24 + opt_header_size;

    for (std::uint16_t i = 0; i < num_sections && i < 32; i++)
    {
        const std::uint64_t sec_va = module_base + sections_rva + i * 40ull;
        const std::uint64_t sec_pa = memory_manager::translate_guest_virtual_address(
            guest_cr3, slat_cr3, { .address = sec_va });
        if (sec_pa == 0) continue;

        const auto* sec = static_cast<const std::uint8_t*>(
            memory_manager::map_guest_physical(slat_cr3, sec_pa));
        if (!sec) continue;

        // Section name is first 8 bytes
        const bool is_text = (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' &&
                              sec[3] == 'x' && sec[4] == 't');
        // Characteristics at offset 36: IMAGE_SCN_CNT_CODE = 0x00000020
        const std::uint32_t characteristics = *reinterpret_cast<const std::uint32_t*>(sec + 36);
        const bool is_code = (characteristics & 0x20) != 0;

        if (is_text || (i == 0 && is_code))
        {
            // VirtualSize at offset 8, VirtualAddress at offset 12
            *text_size = *reinterpret_cast<const std::uint32_t*>(sec + 8);
            *text_va = module_base + *reinterpret_cast<const std::uint32_t*>(sec + 12);
            return true;
        }
    }

    return false;
}

// MmCleanProcessAddressSpace prologue sig (Win11 23H2)
// 4C 8B DC 49 89 5B ? 49 89 6B ? 49 89 73 ?
static const std::uint8_t mmclean_pattern[] = {
    0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x00, 0x49, 0x89, 0x6B, 0x00, 0x49, 0x89, 0x73, 0x00
};
static const char mmclean_mask[] = "xxxxxx?xxx?xxx?";
static constexpr std::uint32_t mmclean_pattern_len = 15;
// Displaced count for CPUID stub: push rcx (1) + mov ecx,imm32 (5) + cpuid (2) = 8 bytes.
// 4C 8B DC (3) + 49 89 5B xx (4) + 49 89 6B (first byte of next) = need at least 8 bytes.
// Use 15 bytes (full sig match) for comfortable margin.
static constexpr std::uint32_t mmclean_displaced_count = 15;

// CPUID stub RCX value: encodes hypercall_info for reserved_data=10, call_type=read_guest_cr3
// Layout: primary_key=0xA3D8 [15:0], call_type=3 [19:16], secondary_key=0x53 [26:20], reserved_data=10 [31:27]
// Fits in 32 bits → mov ecx, imm32 (5 bytes) + cpuid (2 bytes) = 7 bytes total.
static constexpr std::uint32_t mmclean_cpuid_rcx = 0x5533A3D8;

// Hardcoded target process name (bootloader-style — zero usermode dependency)
static constexpr const char default_target_process[] = "fc26.exe";

// Default PML4 index for hidden region (must match usermode convention: inject.h uses 70)
static constexpr std::uint64_t default_hidden_pml4_index = 70;

//=============================================================================
// Boot-time shadow code pages — scan ntoskrnl .text for CC padding pages
//=============================================================================

void hypercall::setup_shadow_code_pages()
{
    if (shadow_code::initialized)
        return;

    // No serial logging here — this runs on every deferred VMEXIT retry (up to 500x).
    // Serial wait_tx_ready() blocking at 115200 baud (~87µs/char) inside a VMEXIT handler
    // causes Hyper-V host stack timeout → triple fault → instant reboot.

    // At boot, target_original_cr3 is 0. Use current guest CR3 for kernel VA translation.
    const std::uint64_t saved_cr3 = cr3_intercept::target_original_cr3;
    if (saved_cr3 == 0)
        cr3_intercept::target_original_cr3 = arch::get_guest_cr3().flags;

    // 1. Find ntoskrnl base via IDT (silent — fails on VTL1/KPTI user CR3)
    const std::uint64_t ntos_base = find_ntoskrnl_base();
    if (ntos_base == 0)
    {
        cr3_intercept::target_original_cr3 = saved_cr3;
        return;
    }

    // 2. Find .text section
    std::uint64_t text_va = 0, text_size = 0;
    if (!find_text_section(ntos_base, &text_va, &text_size))
    {
        cr3_intercept::target_original_cr3 = saved_cr3;
        return;
    }

    // SUCCESS — now safe to log (runs only once)
    serial::print("shadow_code: ntoskrnl="); serial::print_hex(ntos_base);
    serial::print(" .text="); serial::print_hex(text_va);
    serial::print(" size="); serial::print_hex(text_size); serial::println("");

    // 3. Scan .text for CC/NOP padding runs, EPT-split pages containing them
    shadow_code::init(text_va, text_size, cr3_intercept::target_original_cr3);

    // Restore (boot-time temp CR3 should not persist)
    cr3_intercept::target_original_cr3 = saved_cr3;
}

//=============================================================================
// Boot-time hidden region setup — allocate page table hierarchy for ept_install_hook
//=============================================================================

void hypercall::setup_hidden_region_boot()
{
    if (cr3_intercept::hidden_pt_host_va != nullptr)
        return; // already set up

    // allocate 3 pages: PDPT, PD, PT
    void* const pdpt_va = heap_manager::allocate_page();
    void* const pd_va = heap_manager::allocate_page();
    void* const pt_va = heap_manager::allocate_page();

    if (!pdpt_va || !pd_va || !pt_va)
    {
        if (pdpt_va) heap_manager::free_page(pdpt_va);
        if (pd_va) heap_manager::free_page(pd_va);
        if (pt_va) heap_manager::free_page(pt_va);
        return;
    }

    crt::set_memory(pdpt_va, 0, 0x1000);
    crt::set_memory(pd_va, 0, 0x1000);
    crt::set_memory(pt_va, 0, 0x1000);

    const std::uint64_t pdpt_pa = memory_manager::unmap_host_physical(pdpt_va);
    const std::uint64_t pd_pa = memory_manager::unmap_host_physical(pd_va);
    const std::uint64_t pt_pa = memory_manager::unmap_host_physical(pt_va);

    // DO NOT unhide in hyperv_cr3 — heap pages are already accessible there via
    // Hyper-V's 2MB identity-mapped EPT large pages. Splitting those 2MB pages
    // modifies hyperv_cr3's EPT structure → HyperGuard PAGE_HASH_MISMATCH.
    // hook_cr3 doesn't exist yet at boot (created on first hook::add), so unhide
    // is deferred to set_up_hook_cr3() which calls hide_heap_pages(hook_cr3) —
    // these 3 pages will be explicitly unhidden there when needed.

    // build hierarchy: PDPT[0] -> PD, PD[0] -> PT
    auto* const pdpt = static_cast<pdpte_64*>(pdpt_va);
    pdpt[0].flags = (pd_pa & 0xFFFFFFFFF000ull) | 0x7;

    auto* const pd = static_cast<pde_64*>(pd_va);
    pd[0].flags = (pt_pa & 0xFFFFFFFFF000ull) | 0x7;

    // store state — NO PML4 write (no clone PML4 yet)
    // sync_page_tables will auto-insert PML4[hidden] when clone is created
    cr3_intercept::reserved_pml4e_index = default_hidden_pml4_index;
    cr3_intercept::hidden_pt_host_va = pt_va;
    cr3_intercept::hidden_pml4e_flags = (pdpt_pa & 0xFFFFFFFFF000ull) | 0x7;
}

//=============================================================================
// Boot-time autonomous MmClean hook — zero usermode dependency (ring-1 style)
//=============================================================================

std::uint64_t hypercall::auto_setup_mmclean_hook()
{
    // At boot, target_original_cr3 is 0. Use current guest CR3 for kernel VA translation.
    // KPTI fix already applied by setup_shadow_code_pages() (runs before us).
    // If that didn't run or target_original_cr3 was restored, re-apply.
    const std::uint64_t saved_cr3 = cr3_intercept::target_original_cr3;
    if (saved_cr3 == 0)
        cr3_intercept::target_original_cr3 = arch::get_guest_cr3().flags;

    // 1. Find ntoskrnl base via IDT (may fail at boot — VTL 1 or KPTI user CR3)
    const std::uint64_t ntos_base = find_ntoskrnl_base();
    if (ntos_base == 0) { cr3_intercept::target_original_cr3 = saved_cr3; return 0; }

    cr3_intercept::cleanup_hook::ntoskrnl_base = ntos_base;

    // 2. Get ntoskrnl size
    const std::uint64_t ntos_size = get_module_size(ntos_base);
    if (ntos_size == 0) { cr3_intercept::target_original_cr3 = saved_cr3; return 0; }

    // 3. Sig scan for MmCleanProcessAddressSpace
    const std::uint64_t mmclean_va = sig_scan_guest_pages(
        ntos_base, ntos_size, mmclean_pattern, mmclean_mask, mmclean_pattern_len);
    if (mmclean_va == 0) { cr3_intercept::target_original_cr3 = saved_cr3; return 0; }

    // 4. Install EPT hook (dormant — no VP uses our EPTPs yet)
    // Pre-check version: 67B inline shellcode (zero VMEXIT), replaces CPUID stub.
    const auto result = setup_mmclean_precheck_hook_impl(
        mmclean_va, 0, mmclean_displaced_count);
    if (result != 1) { cr3_intercept::target_original_cr3 = saved_cr3; return 0; }

    // 5. Resolve PsGetProcessImageFileName via PE export walk
    cr3_intercept::cleanup_hook::fn_PsGetProcessImageFileName =
        resolve_kernel_export(ntos_base, "PsGetProcessImageFileName");

    // 6. Set default target name (hardcoded, zero usermode)
    for (int i = 0; default_target_process[i] && i < 15; i++)
        cr3_intercept::cleanup_hook::target_process_name[i] = default_target_process[i];

    // 7. Armed at boot — safe because no VP uses our EPTPs until CR3 intercept is enabled.
    // Name-based matching (fn_PsGetProcessImageFileName) means no EPROCESS needed upfront.
    cr3_intercept::cleanup_hook::armed = 1;

    // Restore (boot-time temp CR3 should not persist)
    cr3_intercept::target_original_cr3 = saved_cr3;

    return 1;
}

//=============================================================================
// PE export walk — resolve kernel export by name (ring-1 LookupExport_ByName)
//=============================================================================

// Reads guest virtual memory via SLAT. Works from VMX root (hypercall handler)
// or from guest ring-0 (compiled EPT hook) — both paths have valid SLAT.
static std::uint64_t resolve_kernel_export(std::uint64_t module_base, const char* export_name)
{
    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 guest_cr3 = get_guest_cr3_for_translation();

    // Read DOS header
    const std::uint64_t dos_pa = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = module_base });
    if (dos_pa == 0) return 0;
    const auto* dos = static_cast<const std::uint8_t*>(memory_manager::map_guest_physical(slat_cr3, dos_pa));
    if (!dos || dos[0] != 'M' || dos[1] != 'Z') return 0;

    // e_lfanew at offset 0x3C
    const std::uint32_t e_lfanew = *reinterpret_cast<const std::uint32_t*>(dos + 0x3C);

    // Read PE signature + optional header
    const std::uint64_t pe_va = module_base + e_lfanew;
    const std::uint64_t pe_pa = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = pe_va });
    if (pe_pa == 0) return 0;
    const auto* pe = static_cast<const std::uint8_t*>(memory_manager::map_guest_physical(slat_cr3, pe_pa));
    if (!pe || pe[0] != 'P' || pe[1] != 'E') return 0;

    // Export directory RVA: optional header offset 112 (0x70) for PE64
    // PE sig (4) + FileHeader (20) + optional header starts at offset 24
    const auto* opt = pe + 24;
    const std::uint32_t export_dir_rva = *reinterpret_cast<const std::uint32_t*>(opt + 112);
    const std::uint32_t export_dir_size = *reinterpret_cast<const std::uint32_t*>(opt + 116);
    if (export_dir_rva == 0 || export_dir_size == 0) return 0;

    // Read IMAGE_EXPORT_DIRECTORY
    const std::uint64_t export_va = module_base + export_dir_rva;
    const std::uint64_t export_pa = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = export_va });
    if (export_pa == 0) return 0;
    const auto* export_dir = static_cast<const std::uint8_t*>(memory_manager::map_guest_physical(slat_cr3, export_pa));
    if (!export_dir) return 0;

    const std::uint32_t number_of_names = *reinterpret_cast<const std::uint32_t*>(export_dir + 24);
    const std::uint32_t addr_table_rva = *reinterpret_cast<const std::uint32_t*>(export_dir + 28);
    const std::uint32_t name_table_rva = *reinterpret_cast<const std::uint32_t*>(export_dir + 32);
    const std::uint32_t ordinal_table_rva = *reinterpret_cast<const std::uint32_t*>(export_dir + 36);

    // Walk name table
    std::uint32_t target_len = 0;
    while (export_name[target_len] != '\0') target_len++;

    for (std::uint32_t i = 0; i < number_of_names; i++)
    {
        // Read name RVA from name table
        const std::uint64_t name_entry_va = module_base + name_table_rva + (i * 4);
        const std::uint64_t name_entry_pa = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = name_entry_va });
        if (name_entry_pa == 0) continue;
        const auto* name_rva_ptr = static_cast<const std::uint32_t*>(memory_manager::map_guest_physical(slat_cr3, name_entry_pa));
        if (!name_rva_ptr) continue;

        // Read the actual name string
        const std::uint64_t name_va = module_base + *name_rva_ptr;
        const std::uint64_t name_pa = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = name_va });
        if (name_pa == 0) continue;
        const auto* name_str = static_cast<const char*>(memory_manager::map_guest_physical(slat_cr3, name_pa));
        if (!name_str) continue;

        // Compare
        bool match = true;
        for (std::uint32_t j = 0; j <= target_len; j++)
        {
            if (name_str[j] != export_name[j]) { match = false; break; }
        }
        if (!match) continue;

        // Found — read ordinal, then address
        const std::uint64_t ordinal_va = module_base + ordinal_table_rva + (i * 2);
        const std::uint64_t ordinal_pa = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = ordinal_va });
        if (ordinal_pa == 0) return 0;
        const auto* ordinal_ptr = static_cast<const std::uint16_t*>(memory_manager::map_guest_physical(slat_cr3, ordinal_pa));
        if (!ordinal_ptr) return 0;

        const std::uint64_t addr_va = module_base + addr_table_rva + (*ordinal_ptr * 4);
        const std::uint64_t addr_pa = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = addr_va });
        if (addr_pa == 0) return 0;
        const auto* func_rva_ptr = static_cast<const std::uint32_t*>(memory_manager::map_guest_physical(slat_cr3, addr_pa));
        if (!func_rva_ptr) return 0;

        return module_base + *func_rva_ptr;
    }

    return 0;
}

//=============================================================================
// MmCleanProcessAddressSpace hook — compiled C++ function (ring-1 style)
//=============================================================================

// This function executes in guest ring-0 context (via hidden region mapping).
// Zero CPUID, zero VMEXIT. All globals via RIP-relative (attachment mapped contiguously).
// Returns __int64 so MSVC /O2 emits jmp (tail call) instead of call+ret (like ring-1's jmp rax).
// MmClean is void but the caller ignores RAX — return type mismatch is harmless.
extern "C" __declspec(noinline) __int64 hook_MmCleanProcessAddressSpace(std::uint64_t eprocess, std::uint64_t a2)
{
    cr3_intercept::g_executing_ept_hook = 1;
    cr3_intercept::cleanup_hook::hook_entry_count++;

    // Name-based process matching (ring-1 style)
    // Call PsGetProcessImageFileName(EPROCESS) — returns pointer to char[15] inside EPROCESS
    if (cr3_intercept::cleanup_hook::armed &&
        cr3_intercept::cleanup_hook::fn_PsGetProcessImageFileName != 0)
    {
        cr3_intercept::cleanup_hook::hook_hit_count++;

        using fn_t = const char*(*)(std::uint64_t);
        const char* dying_name = reinterpret_cast<fn_t>(
            cr3_intercept::cleanup_hook::fn_PsGetProcessImageFileName)(eprocess);
        const char* target_name = cr3_intercept::cleanup_hook::target_process_name;

        // Case-insensitive compare (ImageFileName is max 14 chars + null)
        bool match = true;
        for (int i = 0; i < 15; i++)
        {
            char a = dying_name[i];
            char b = target_name[i];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = false; break; }
            if (a == '\0') break;
        }

        if (match)
        {
            cr3_intercept::cleanup_hook::hook_match_count++;
            cr3_intercept::cleanup_hook::target_eprocess = eprocess;
            cr3_intercept::cleanup_hook::cleanup_pending = 1;
        }
    }

    // Tail call — compiler emits jmp (not call) because this is the return statement.
    // Same as ring-1: jmp rax → MmClean ret goes directly back to original caller.
    using fn_t = __int64(*)(std::uint64_t, std::uint64_t);
    return reinterpret_cast<fn_t>(cr3_intercept::mmclean_hook::ctx.trampoline_va)(eprocess, a2);
}

//=============================================================================
// MmAccessFault compiled C++ EPT hook — REPLACED by inline 44B shellcode
//=============================================================================
// Old version ran in guest ring-0 via hidden region (PML4[70]).
// New version: 44B position-independent shellcode in ntoskrnl shadow code page.
// Accessible to ALL processes (kernel VA), no hidden memory dependency.
// See setup_mmaf_inline_hook_impl() for the new shellcode assembly.
/*
extern "C" __declspec(noinline) __int64 hook_MmAccessFault(
    std::uint64_t fault_status, std::uint64_t virtual_address,
    std::uint64_t previous_mode, std::uint64_t trap_information)
{
    cr3_intercept::mmaf_hook::total_count++;
    const std::uint8_t pml4_index = static_cast<std::uint8_t>((virtual_address >> 39) & 0x1FF);
    if (pml4_index == cr3_intercept::mmaf_hook::hidden_pml4_index)
    {
        cr3_intercept::mmaf_hook::hit_count++;
        __writecr3(cr3_intercept::mmaf_hook::clone_cr3_value);
        return 0;
    }
    using fn_t = __int64(*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
    return reinterpret_cast<fn_t>(cr3_intercept::mmaf_hook::ctx.trampoline_va)(
        fault_status, virtual_address, previous_mode, trap_information);
}
*/

//=============================================================================
// Generic EPT inline hook — ring-1 EptInstallHook equivalent
//=============================================================================

// Installs an inline EPT hook: shadow page with JMP → detour (hidden region) + trampoline → original.
// detour_fn is a compiled C++ function pointer (host VA, auto-converted to hidden VA).
// displaced_count = number of prologue bytes to relocate (instruction-aligned).
//   - stub_clone_pfn == 0: direct 14B JMP, displaced_count >= 14
//   - stub_clone_pfn != 0: stub filter (35B), displaced_count >= 35
// stub_clone_pfn: when nonzero, embeds a CR3 PFN check on the shadow page:
//   target process (PFN match) → hidden handler, other processes → trampoline (safe).
//   This allows Hook 2 EPTP re-bootstrap without crashing non-target processes.
// Returns 1 on success, error code on failure.
std::uint64_t ept_install_hook(
    std::uint64_t target_va, void* detour_fn,
    std::uint32_t displaced_count, cr3_intercept::ept_hook_context_t* ctx,
    std::uint32_t stub_clone_pfn)
{
    if (ctx->active)
        return 0xD0;

    const std::uint32_t min_displaced = (stub_clone_pfn != 0) ? 35 : 14;
    if (displaced_count < min_displaced || displaced_count > 128)
        return 0xD1;

    // 1. Map attachment into hidden region (idempotent)
    const std::uint64_t hidden_base = map_attachment_to_hidden_region();
    if (!hidden_base) return 0xD8;

    // 2. Compute detour function's hidden VA
    const std::uint64_t detour_hidden_va = host_va_to_hidden_va(
        reinterpret_cast<std::uint64_t>(detour_fn));

    // 3. Translate target VA → PA
    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 orig_cr3 = get_guest_cr3_for_translation();
    const std::uint64_t target_pa = memory_manager::translate_guest_virtual_address(
        orig_cr3, slat_cr3, { .address = target_va });
    if (!target_pa) return 0xD2;

    const std::uint64_t page_off = target_pa & 0xFFF;
    const std::uint64_t pa_page = target_pa & ~0xFFFull;
    if (page_off + displaced_count > 0x1000) return 0xD3;

    // 4. Shadow page: copy original
    void* shadow = heap_manager::allocate_page();
    if (!shadow) return 0xD4;
    const void* orig_page = memory_manager::map_guest_physical(slat_cr3, pa_page);
    if (!orig_page) { heap_manager::free_page(shadow); return 0xD4; }
    crt::copy_memory(shadow, orig_page, 0x1000);

    // 5. Allocate hidden page for trampoline (displaced bytes + 14B JMP back)
    //    This trampoline is for the TARGET process (accessible via PML4[hidden]).
    const std::uint64_t trampoline_va = alloc_hidden_page_impl();
    if (!trampoline_va) { heap_manager::free_page(shadow); return 0xD5; }

    const std::uint64_t tramp_slot = (trampoline_va & ((1ull << 39) - 1)) / 0x1000;
    auto* hpt = static_cast<pte_64*>(cr3_intercept::hidden_pt_host_va);
    auto* tramp_page = static_cast<std::uint8_t*>(
        memory_manager::map_host_physical(hpt[tramp_slot].page_frame_number << 12));
    if (!tramp_page) { heap_manager::free_page(shadow); return 0xD6; }

    crt::copy_memory(tramp_page,
        static_cast<const std::uint8_t*>(orig_page) + page_off, displaced_count);
    build_abs_jmp(tramp_page + displaced_count, target_va + displaced_count);

    // 6. Write hook on shadow page
    auto* sp = static_cast<std::uint8_t*>(shadow) + page_off;
    std::uint32_t hook_byte_len = 14;
    std::uint32_t pfn_offset_in_page = 0;
    std::uint64_t cc_tramp_page_off = 0;   // CC trampoline offset in shadow page (0 = none)
    std::uint32_t cc_tramp_byte_size = 0;  // CC trampoline total size (displaced + 5)
    void* cc_adj_shadow_out = nullptr;     // adjacent page shadow heap ptr (for context)
    std::uint64_t cc_adj_pa_out = 0;       // adjacent page target PA (for context)

    if (stub_clone_pfn != 0)
    {
        // --- Stub filter mode (35 bytes) ---
        // Non-target processes: stub → CC trampoline (displaced bytes on kernel page, safe).
        // Target process: stub → hidden handler (PML4[hidden], only in clone CR3).

        // 6a. Find CC padding on same shadow page for non-target trampoline
        const std::uint32_t cc_tramp_size = displaced_count + 5; // displaced + E9 rel32 JMP back
        std::uint64_t cc_off = 0;
        bool found_cc = false;

        for (std::uint64_t i = 0; i + cc_tramp_size <= 0x1000; i++)
        {
            // Skip any candidate overlapping the hook area [page_off, page_off + displaced_count)
            if (i + cc_tramp_size > page_off && i < page_off + displaced_count) continue;

            bool all_cc = true;
            for (std::uint32_t j = 0; j < cc_tramp_size; j++)
            {
                if (static_cast<std::uint8_t*>(shadow)[i + j] != 0xCC)
                {
                    all_cc = false;
                    break;
                }
            }
            if (all_cc) { cc_off = i; found_cc = true; break; }
        }

        // 6a-2. If no CC padding on same page, scan adjacent pages using PHYSICAL addresses
        //        (VA translation can fail; PA ± N*0x1000 always works within ntoskrnl .text)
        std::uint64_t cc_tramp_va = 0;           // VA of CC trampoline (for stub E9 rel32)

        // Also check for NOP (0x90) padding if no CC found
        const std::uint8_t pad_bytes[] = { 0xCC, 0x90 };

        if (!found_cc)
        {
            // Re-check same page for NOP padding (first scan only checked CC)
            for (int pb = 1; !found_cc && pb < 2; pb++)
            {
                const std::uint8_t pad = pad_bytes[pb];
                for (std::uint64_t i = 0; i + cc_tramp_size <= 0x1000; i++)
                {
                    if (i + cc_tramp_size > page_off && i < page_off + displaced_count) continue;

                    bool all_pad = true;
                    for (std::uint32_t j = 0; j < cc_tramp_size; j++)
                    {
                        if (static_cast<std::uint8_t*>(shadow)[i + j] != pad)
                        { all_pad = false; break; }
                    }
                    if (all_pad) { cc_off = i; found_cc = true; break; }
                }
            }
        }

        // 6a-3. Scan adjacent VIRTUAL pages (±64 pages) — translate VA → PA for each
        //        ntoskrnl pages are virtually contiguous but NOT physically contiguous,
        //        so we must walk guest page tables to find the real PA of each neighbor.
        if (!found_cc)
        {
            const std::uint64_t target_va_page = target_va & ~0xFFFull;

            for (int dist = 1; !found_cc && dist <= 64; dist++)
            {
                for (int sign = -1; !found_cc && sign <= 1; sign += 2)
                {
                    const std::int64_t delta = static_cast<std::int64_t>(sign) * dist;
                    const std::uint64_t adj_va_base = target_va_page + delta * 0x1000;

                    // Translate adjacent VA → PA via guest page tables
                    const std::uint64_t adj_pa = memory_manager::translate_guest_virtual_address(
                        orig_cr3, slat_cr3, { .address = adj_va_base });
                    if (!adj_pa) continue; // unmapped page — skip

                    const std::uint64_t adj_pa_pg = adj_pa & ~0xFFFull;

                    const auto* adj_orig = static_cast<const std::uint8_t*>(
                        memory_manager::map_guest_physical(slat_cr3, adj_pa_pg));
                    if (!adj_orig) continue;

                    // Scan for CC (0xCC) and NOP (0x90) padding
                    for (int pb = 0; !found_cc && pb < 2; pb++)
                    {
                        const std::uint8_t pad = pad_bytes[pb];
                        for (std::uint64_t i = 0; i + cc_tramp_size <= 0x1000; i++)
                        {
                            bool all_pad = true;
                            for (std::uint32_t j = 0; j < cc_tramp_size; j++)
                            {
                                if (adj_orig[i + j] != pad) { all_pad = false; break; }
                            }
                            if (!all_pad) continue;

                            // Found padding on adjacent virtual page — create shadow + hook
                            void* adj_shd = heap_manager::allocate_page();
                            if (!adj_shd) break;
                            crt::copy_memory(adj_shd, adj_orig, 0x1000);

                            // Write CC trampoline on adjacent shadow
                            auto* adj_trp = static_cast<std::uint8_t*>(adj_shd) + i;
                            crt::copy_memory(adj_trp,
                                static_cast<const std::uint8_t*>(orig_page) + page_off, displaced_count);
                            const std::uint64_t resume_va = target_va + displaced_count;
                            const std::uint64_t adj_jmp_rip = adj_va_base + i + displaced_count + 5;
                            const std::int32_t adj_jmp_rel = static_cast<std::int32_t>(
                                static_cast<std::int64_t>(resume_va) - static_cast<std::int64_t>(adj_jmp_rip));
                            adj_trp[displaced_count] = 0xE9;
                            *reinterpret_cast<std::int32_t*>(adj_trp + displaced_count + 1) = adj_jmp_rel;

                            // EPT hook adjacent page (execute → adj shadow, read/write → original)
                            const std::uint64_t adj_shd_pa = memory_manager::unmap_host_physical(adj_shd);
                            unhide_physical_page(slat_cr3, adj_shd_pa);
                            if (slat::hook::add({ .address = adj_pa_pg }, { .address = adj_shd_pa }, 0) == 0)
                            {
                                heap_manager::free_page(adj_shd);
                                break;
                            }

                            cc_tramp_va = adj_va_base + i;
                            cc_adj_shadow_out = adj_shd;
                            cc_adj_pa_out = adj_pa_pg;
                            found_cc = true;
                            break;
                        }
                    }
                }
            }
        }

        /* ---- FALLBACK: Scan adjacent PHYSICAL pages (±64 pages) ----
         * Kept as fallback in case virtual translation fails for all neighbors.
         * Original code assumed physical contiguity (ntoskrnl .text is NOT always
         * physically contiguous), so the virtual scan above is the primary method.
         */
        if (!found_cc)
        {
            // Scan adjacent physical pages (±64 pages) — no VA translation needed
            // ntoskrnl .text is linearly mapped: adj_va = target_va + (adj_pa - target_pa)
            const std::uint64_t base_va = target_va - page_off;

            for (int dist = 1; !found_cc && dist <= 64; dist++)
            {
                for (int sign = -1; !found_cc && sign <= 1; sign += 2)
                {
                    const std::int64_t delta = static_cast<std::int64_t>(sign) * dist;
                    if (delta < 0 && pa_page < static_cast<std::uint64_t>(-delta) * 0x1000) continue;
                    const std::uint64_t adj_pa_pg = pa_page + delta * 0x1000;
                    const std::uint64_t adj_va_base = base_va + delta * 0x1000;

                    const auto* adj_orig = static_cast<const std::uint8_t*>(
                        memory_manager::map_guest_physical(slat_cr3, adj_pa_pg));
                    if (!adj_orig) continue;

                    // Scan for CC (0xCC) and NOP (0x90) padding
                    for (int pb = 0; !found_cc && pb < 2; pb++)
                    {
                        const std::uint8_t pad = pad_bytes[pb];
                        for (std::uint64_t i = 0; i + cc_tramp_size <= 0x1000; i++)
                        {
                            bool all_pad = true;
                            for (std::uint32_t j = 0; j < cc_tramp_size; j++)
                            {
                                if (adj_orig[i + j] != pad) { all_pad = false; break; }
                            }
                            if (!all_pad) continue;

                            // Found padding on adjacent page — create shadow + hook
                            void* adj_shd = heap_manager::allocate_page();
                            if (!adj_shd) break;
                            crt::copy_memory(adj_shd, adj_orig, 0x1000);

                            // Write CC trampoline on adjacent shadow
                            auto* adj_trp = static_cast<std::uint8_t*>(adj_shd) + i;
                            crt::copy_memory(adj_trp,
                                static_cast<const std::uint8_t*>(orig_page) + page_off, displaced_count);
                            const std::uint64_t resume_va = target_va + displaced_count;
                            const std::uint64_t adj_jmp_rip = adj_va_base + i + displaced_count + 5;
                            const std::int32_t adj_jmp_rel = static_cast<std::int32_t>(
                                static_cast<std::int64_t>(resume_va) - static_cast<std::int64_t>(adj_jmp_rip));
                            adj_trp[displaced_count] = 0xE9;
                            *reinterpret_cast<std::int32_t*>(adj_trp + displaced_count + 1) = adj_jmp_rel;

                            // EPT hook adjacent page (execute → adj shadow, read/write → original)
                            const std::uint64_t adj_shd_pa = memory_manager::unmap_host_physical(adj_shd);
                            unhide_physical_page(slat_cr3, adj_shd_pa);
                            if (slat::hook::add({ .address = adj_pa_pg }, { .address = adj_shd_pa }, 0) == 0)
                            {
                                heap_manager::free_page(adj_shd);
                                break;
                            }

                            cc_tramp_va = adj_va_base + i;
                            cc_adj_shadow_out = adj_shd;
                            cc_adj_pa_out = adj_pa_pg;
                            found_cc = true;
                            break;
                        }
                    }
                }
            }
        }

        if (!found_cc)
        {
            hpt[tramp_slot].flags = 0;
            heap_manager::free_page(tramp_page);
            heap_manager::free_page(shadow);
            return 0xDA; // no CC/NOP padding found within ±64 physical pages
        }

        // 6b. Write CC trampoline on same-page shadow (if found on same page)
        if (cc_tramp_va == 0)
        {
            // Same page — write CC trampoline directly on shadow
            auto* cc_tramp = static_cast<std::uint8_t*>(shadow) + cc_off;
            crt::copy_memory(cc_tramp,
                static_cast<const std::uint8_t*>(orig_page) + page_off, displaced_count);

            const std::uint64_t resume_va = target_va + displaced_count;
            const std::uint64_t jmp_back_rip = (target_va - page_off) + cc_off + displaced_count + 5;
            const std::int32_t jmp_back_rel = static_cast<std::int32_t>(
                static_cast<std::int64_t>(resume_va) - static_cast<std::int64_t>(jmp_back_rip));
            cc_tramp[displaced_count] = 0xE9;
            *reinterpret_cast<std::int32_t*>(cc_tramp + displaced_count + 1) = jmp_back_rel;

            cc_tramp_va = (target_va - page_off) + cc_off;
            cc_tramp_page_off = cc_off;
            cc_tramp_byte_size = cc_tramp_size;
        }
        // Adjacent page CC trampoline was already written in the scan loop above.

        // 6c. Write 35-byte stub on shadow page
        // [0]:  push rax                (50)
        // [1]:  mov rax, cr3            (0F 20 D8)
        // [4]:  shr rax, 12             (48 C1 E8 0C)
        // [8]:  cmp eax, CLONE_PFN      (3D xx xx xx xx)
        // [13]: pop rax                 (58)
        // [14]: jne .not_target         (75 0E)
        // [16]: <14B JMP hidden handler>
        // [30]: .not_target: E9 rel32 → CC trampoline
        sp[0] = 0x50;                                  // push rax
        sp[1] = 0x0F; sp[2] = 0x20; sp[3] = 0xD8;     // mov rax, cr3
        sp[4] = 0x48; sp[5] = 0xC1; sp[6] = 0xE8; sp[7] = 0x0C; // shr rax, 12
        sp[8] = 0x3D;                                  // cmp eax, imm32
        *reinterpret_cast<std::uint32_t*>(sp + 9) = stub_clone_pfn;
        sp[13] = 0x58;                                 // pop rax
        sp[14] = 0x75; sp[15] = 0x0E;                  // jne +14 (skip 14B JMP)

        build_abs_jmp(sp + 16, detour_hidden_va);      // [16..29] target: JMP hidden handler

        // [30..34] not_target: E9 rel32 → CC trampoline (same or adjacent page)
        const std::uint64_t jne_rip = target_va + 35;  // RIP after E9 rel32
        const std::int32_t jne_rel = static_cast<std::int32_t>(
            static_cast<std::int64_t>(cc_tramp_va) - static_cast<std::int64_t>(jne_rip));
        sp[30] = 0xE9;
        *reinterpret_cast<std::int32_t*>(sp + 31) = jne_rel;

        // NOP padding after stub
        for (std::uint32_t i = 35; i < displaced_count; i++)
            sp[i] = 0x90;

        hook_byte_len = displaced_count;
        pfn_offset_in_page = static_cast<std::uint32_t>(page_off) + 9; // offset of imm32 in shadow page
    }
    else
    {
        // --- Direct mode (14 bytes) --- original behavior
        build_abs_jmp(sp, detour_hidden_va);
        for (std::uint32_t i = 14; i < displaced_count; i++)
            sp[i] = 0x90;
    }

    // 7. EPT split: execute → shadow, read → original
    const std::uint64_t shadow_pa = memory_manager::unmap_host_physical(shadow);
    unhide_physical_page(slat_cr3, shadow_pa);
    if (slat::hook::add({ .address = target_pa }, { .address = shadow_pa }, hook_byte_len) == 0)
    {
        // Clean up adjacent page EPT hook if it was installed
        if (cc_adj_pa_out != 0)
        {
            slat::hook::remove({ .address = cc_adj_pa_out });
            heap_manager::free_page(cc_adj_shadow_out);
        }
        hpt[tramp_slot].flags = 0;
        heap_manager::free_page(tramp_page);
        heap_manager::free_page(shadow);
        return 0xD7;
    }

    // 7b. Protect CC trampoline area from MTF write sync (same-page only)
    if (cc_tramp_byte_size != 0)
    {
        slat::hook::entry_t* entry = slat::hook::entry_t::find(target_pa >> 12);
        if (entry != nullptr)
        {
            entry->set_hook_byte_offset2(cc_tramp_page_off);
            entry->set_hook_byte_length2(cc_tramp_byte_size < 127 ? cc_tramp_byte_size : 127);
        }
    }

    // 8. Fill context
    ctx->active = true;
    ctx->target_va = target_va;
    ctx->target_pa_page = pa_page;
    ctx->shadow_heap_va = shadow;
    ctx->trampoline_va = trampoline_va;
    ctx->trampoline_hidden_slot = tramp_slot;
    ctx->stub_pfn_offset = pfn_offset_in_page;
    ctx->displaced_count = displaced_count;
    ctx->cc_adj_target_pa = cc_adj_pa_out;
    ctx->cc_adj_shadow_heap_va = cc_adj_shadow_out;

    return 1;
}

// Removes an inline EPT hook: removes EPT split, frees shadow + trampoline pages, resets context.
void ept_remove_hook(cr3_intercept::ept_hook_context_t* ctx)
{
    if (!ctx->active)
        return;

    slat::hook::remove({ .address = ctx->target_pa_page });

    if (ctx->shadow_heap_va)
        heap_manager::free_page(ctx->shadow_heap_va);

    // Free trampoline hidden page and clear PT entry
    if (ctx->trampoline_hidden_slot < 512 && cr3_intercept::hidden_pt_host_va)
    {
        auto* hpt = static_cast<pte_64*>(cr3_intercept::hidden_pt_host_va);
        if (hpt[ctx->trampoline_hidden_slot].present)
        {
            void* hv = memory_manager::map_host_physical(
                hpt[ctx->trampoline_hidden_slot].page_frame_number << 12);
            if (hv) heap_manager::free_page(hv);
            hpt[ctx->trampoline_hidden_slot].flags = 0;
        }
    }

    // Remove adjacent page CC trampoline shadow (if any)
    if (ctx->cc_adj_target_pa != 0)
    {
        slat::hook::remove({ .address = ctx->cc_adj_target_pa });
        if (ctx->cc_adj_shadow_heap_va)
            heap_manager::free_page(ctx->cc_adj_shadow_heap_va);
    }

    ctx->active = false;
    ctx->target_va = 0;
    ctx->target_pa_page = 0;
    ctx->shadow_heap_va = nullptr;
    ctx->trampoline_va = 0;
    ctx->trampoline_hidden_slot = 0xFFFF;
    ctx->stub_pfn_offset = 0;
    ctx->displaced_count = 0;
    ctx->cc_adj_target_pa = 0;
    ctx->cc_adj_shadow_heap_va = nullptr;
}

//=============================================================================
// CPUID-based EPT hook — safe for ALL processes (no hidden region dependency)
//=============================================================================
//
// Shadow page gets a 7-byte CPUID stub: mov ecx, imm32; cpuid
// CPUID VMEXIT → existing hypercall dispatch → handler processes the hook.
// CC trampoline (displaced bytes + E9 JMP back) on same or adjacent page.
// Any process can safely execute the stub: CPUID triggers VMEXIT, handler
// checks CR3 PFN and redirects to trampoline. No PML4[hidden] dependency.
//
std::uint64_t ept_install_cpuid_hook(
    std::uint64_t target_va,
    std::uint32_t displaced_count,
    cr3_intercept::ept_hook_context_t* ctx,
    std::uint32_t cpuid_rcx_imm32)
{
    if (ctx->active)
        return 0xD0;

    if (displaced_count < 8 || displaced_count > 128)
        return 0xD1;

    // 1. Translate target VA → PA
    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 orig_cr3 = get_guest_cr3_for_translation();
    const std::uint64_t target_pa = memory_manager::translate_guest_virtual_address(
        orig_cr3, slat_cr3, { .address = target_va });
    if (!target_pa) return 0xD2;

    const std::uint64_t page_off = target_pa & 0xFFF;
    const std::uint64_t pa_page = target_pa & ~0xFFFull;
    if (page_off + displaced_count > 0x1000) return 0xD3;

    // 2. Shadow page: copy original
    void* shadow = heap_manager::allocate_page();
    if (!shadow) return 0xD4;
    const void* orig_page = memory_manager::map_guest_physical(slat_cr3, pa_page);
    if (!orig_page) { heap_manager::free_page(shadow); return 0xD4; }
    crt::copy_memory(shadow, orig_page, 0x1000);

    // 3. Find CC/NOP padding for trampoline (1 + displaced_count + 5 bytes)
    //    pop rcx (1) + displaced bytes + rel32 JMP back (5)
    const std::uint32_t cc_tramp_size = 1 + displaced_count + 5;
    std::uint64_t cc_off = 0;
    bool found_cc = false;
    std::uint64_t cc_tramp_va = 0;
    void* cc_adj_shadow_out = nullptr;
    std::uint64_t cc_adj_pa_out = 0;
    std::uint64_t cc_tramp_page_off_out = 0;
    std::uint32_t cc_tramp_byte_size_out = 0;

    const std::uint8_t pad_bytes[] = { 0xCC, 0x90 };

    // 3a. Same-page scan (CC then NOP)
    for (int pb = 0; !found_cc && pb < 2; pb++)
    {
        const std::uint8_t pad = pad_bytes[pb];
        for (std::uint64_t i = 0; i + cc_tramp_size <= 0x1000; i++)
        {
            if (i + cc_tramp_size > page_off && i < page_off + displaced_count) continue;
            bool all_pad = true;
            for (std::uint32_t j = 0; j < cc_tramp_size; j++)
            {
                if (static_cast<std::uint8_t*>(shadow)[i + j] != pad)
                { all_pad = false; break; }
            }
            if (all_pad) { cc_off = i; found_cc = true; break; }
        }
    }

    // 3b. Adjacent virtual page scan (±64 pages)
    if (!found_cc)
    {
        const std::uint64_t target_va_page = target_va & ~0xFFFull;
        for (int dist = 1; !found_cc && dist <= 64; dist++)
        {
            for (int sign = -1; !found_cc && sign <= 1; sign += 2)
            {
                const std::int64_t delta = static_cast<std::int64_t>(sign) * dist;
                const std::uint64_t adj_va_base = target_va_page + delta * 0x1000;
                const std::uint64_t adj_pa = memory_manager::translate_guest_virtual_address(
                    orig_cr3, slat_cr3, { .address = adj_va_base });
                if (!adj_pa) continue;
                const std::uint64_t adj_pa_pg = adj_pa & ~0xFFFull;
                const auto* adj_orig = static_cast<const std::uint8_t*>(
                    memory_manager::map_guest_physical(slat_cr3, adj_pa_pg));
                if (!adj_orig) continue;

                for (int pb = 0; !found_cc && pb < 2; pb++)
                {
                    const std::uint8_t pad = pad_bytes[pb];
                    for (std::uint64_t i = 0; i + cc_tramp_size <= 0x1000; i++)
                    {
                        bool all_pad = true;
                        for (std::uint32_t j = 0; j < cc_tramp_size; j++)
                        {
                            if (adj_orig[i + j] != pad) { all_pad = false; break; }
                        }
                        if (!all_pad) continue;

                        void* adj_shd = heap_manager::allocate_page();
                        if (!adj_shd) break;
                        crt::copy_memory(adj_shd, adj_orig, 0x1000);

                        auto* adj_trp = static_cast<std::uint8_t*>(adj_shd) + i;
                        adj_trp[0] = 0x59; // pop rcx
                        crt::copy_memory(adj_trp + 1,
                            static_cast<const std::uint8_t*>(orig_page) + page_off, displaced_count);
                        const std::uint64_t resume_va = target_va + displaced_count;
                        const std::uint64_t adj_jmp_rip = adj_va_base + i + 1 + displaced_count + 5;
                        const std::int32_t adj_jmp_rel = static_cast<std::int32_t>(
                            static_cast<std::int64_t>(resume_va) - static_cast<std::int64_t>(adj_jmp_rip));
                        adj_trp[1 + displaced_count] = 0xE9;
                        *reinterpret_cast<std::int32_t*>(adj_trp + 1 + displaced_count + 1) = adj_jmp_rel;

                        const std::uint64_t adj_shd_pa = memory_manager::unmap_host_physical(adj_shd);
                        unhide_physical_page(slat_cr3, adj_shd_pa);
                        if (slat::hook::add({ .address = adj_pa_pg }, { .address = adj_shd_pa }, 0) == 0)
                        {
                            heap_manager::free_page(adj_shd);
                            break;
                        }

                        cc_tramp_va = adj_va_base + i;
                        cc_adj_shadow_out = adj_shd;
                        cc_adj_pa_out = adj_pa_pg;
                        found_cc = true;
                        break;
                    }
                }
            }
        }
    }

    // 3c. Adjacent physical page scan (fallback, ±64 pages)
    if (!found_cc)
    {
        const std::uint64_t base_va = target_va - page_off;
        for (int dist = 1; !found_cc && dist <= 64; dist++)
        {
            for (int sign = -1; !found_cc && sign <= 1; sign += 2)
            {
                const std::int64_t delta = static_cast<std::int64_t>(sign) * dist;
                if (delta < 0 && pa_page < static_cast<std::uint64_t>(-delta) * 0x1000) continue;
                const std::uint64_t adj_pa_pg = pa_page + delta * 0x1000;
                const std::uint64_t adj_va_base = base_va + delta * 0x1000;
                const auto* adj_orig = static_cast<const std::uint8_t*>(
                    memory_manager::map_guest_physical(slat_cr3, adj_pa_pg));
                if (!adj_orig) continue;

                for (int pb = 0; !found_cc && pb < 2; pb++)
                {
                    const std::uint8_t pad = pad_bytes[pb];
                    for (std::uint64_t i = 0; i + cc_tramp_size <= 0x1000; i++)
                    {
                        bool all_pad = true;
                        for (std::uint32_t j = 0; j < cc_tramp_size; j++)
                        {
                            if (adj_orig[i + j] != pad) { all_pad = false; break; }
                        }
                        if (!all_pad) continue;

                        void* adj_shd = heap_manager::allocate_page();
                        if (!adj_shd) break;
                        crt::copy_memory(adj_shd, adj_orig, 0x1000);

                        auto* adj_trp = static_cast<std::uint8_t*>(adj_shd) + i;
                        adj_trp[0] = 0x59; // pop rcx
                        crt::copy_memory(adj_trp + 1,
                            static_cast<const std::uint8_t*>(orig_page) + page_off, displaced_count);
                        const std::uint64_t resume_va = target_va + displaced_count;
                        const std::uint64_t adj_jmp_rip = adj_va_base + i + 1 + displaced_count + 5;
                        const std::int32_t adj_jmp_rel = static_cast<std::int32_t>(
                            static_cast<std::int64_t>(resume_va) - static_cast<std::int64_t>(adj_jmp_rip));
                        adj_trp[1 + displaced_count] = 0xE9;
                        *reinterpret_cast<std::int32_t*>(adj_trp + 1 + displaced_count + 1) = adj_jmp_rel;

                        const std::uint64_t adj_shd_pa = memory_manager::unmap_host_physical(adj_shd);
                        unhide_physical_page(slat_cr3, adj_shd_pa);
                        if (slat::hook::add({ .address = adj_pa_pg }, { .address = adj_shd_pa }, 0) == 0)
                        {
                            heap_manager::free_page(adj_shd);
                            break;
                        }

                        cc_tramp_va = adj_va_base + i;
                        cc_adj_shadow_out = adj_shd;
                        cc_adj_pa_out = adj_pa_pg;
                        found_cc = true;
                        break;
                    }
                }
            }
        }
    }

    if (!found_cc)
    {
        heap_manager::free_page(shadow);
        return 0xDA;
    }

    // 4. Write same-page CC trampoline (if found on same page)
    //    pop rcx (1) + displaced bytes + JMP back (5)
    if (cc_tramp_va == 0)
    {
        auto* cc_tramp = static_cast<std::uint8_t*>(shadow) + cc_off;
        cc_tramp[0] = 0x59; // pop rcx — restore original RCX saved by push rcx in stub
        crt::copy_memory(cc_tramp + 1,
            static_cast<const std::uint8_t*>(orig_page) + page_off, displaced_count);
        const std::uint64_t resume_va = target_va + displaced_count;
        const std::uint64_t jmp_back_rip = (target_va - page_off) + cc_off + 1 + displaced_count + 5;
        const std::int32_t jmp_back_rel = static_cast<std::int32_t>(
            static_cast<std::int64_t>(resume_va) - static_cast<std::int64_t>(jmp_back_rip));
        cc_tramp[1 + displaced_count] = 0xE9;
        *reinterpret_cast<std::int32_t*>(cc_tramp + 1 + displaced_count + 1) = jmp_back_rel;
        cc_tramp_va = (target_va - page_off) + cc_off;
        cc_tramp_page_off_out = cc_off;
        cc_tramp_byte_size_out = cc_tramp_size;
    }

    // 5. Write CPUID stub on shadow page (8 bytes)
    //    push rcx         (51)              — 1 byte  (save original RCX = EPROCESS etc.)
    //    mov ecx, imm32   (B9 xx xx xx xx)  — 5 bytes (hypercall key)
    //    cpuid             (0F A2)           — 2 bytes (VMEXIT → handler redirects RIP)
    //    NOP fill to displaced_count (dead code — CPUID VMEXIT redirects RIP)
    auto* sp = static_cast<std::uint8_t*>(shadow) + page_off;
    sp[0] = 0x51; // push rcx
    sp[1] = 0xB9;
    *reinterpret_cast<std::uint32_t*>(sp + 2) = cpuid_rcx_imm32;
    sp[6] = 0x0F; sp[7] = 0xA2;
    for (std::uint32_t i = 8; i < displaced_count; i++)
        sp[i] = 0x90;

    // 6. EPT split: execute → shadow, read/write → original
    const std::uint64_t shadow_pa = memory_manager::unmap_host_physical(shadow);
    unhide_physical_page(slat_cr3, shadow_pa);
    if (slat::hook::add({ .address = target_pa }, { .address = shadow_pa }, displaced_count) == 0)
    {
        if (cc_adj_pa_out != 0)
        {
            slat::hook::remove({ .address = cc_adj_pa_out });
            heap_manager::free_page(cc_adj_shadow_out);
        }
        heap_manager::free_page(shadow);
        return 0xD7;
    }

    // 6b. Protect CC trampoline from MTF write sync (same-page only)
    if (cc_tramp_byte_size_out != 0)
    {
        slat::hook::entry_t* entry = slat::hook::entry_t::find(target_pa >> 12);
        if (entry != nullptr)
        {
            entry->set_hook_byte_offset2(cc_tramp_page_off_out);
            entry->set_hook_byte_length2(cc_tramp_byte_size_out < 127 ? cc_tramp_byte_size_out : 127);
        }
    }

    // 7. Fill context — no hidden trampoline (trampoline_hidden_slot = 0xFFFF)
    ctx->active = true;
    ctx->target_va = target_va;
    ctx->target_pa_page = pa_page;
    ctx->shadow_heap_va = shadow;
    ctx->trampoline_va = cc_tramp_va;
    ctx->trampoline_hidden_slot = 0xFFFF;
    ctx->stub_pfn_offset = 0;
    ctx->displaced_count = displaced_count;
    ctx->cc_adj_target_pa = cc_adj_pa_out;
    ctx->cc_adj_shadow_heap_va = cc_adj_shadow_out;

    return 1;
}

//=============================================================================
// Generic signature scan over guest virtual memory (ring-1 IDASignatureScan equivalent)
//=============================================================================

std::uint64_t sig_scan_guest_pages(
    std::uint64_t base_va, std::uint64_t scan_size,
    const std::uint8_t* pattern, const char* mask, std::uint32_t pattern_len)
{
    if (pattern_len == 0 || pattern_len > 64 || scan_size == 0)
        return 0;

    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 guest_cr3 = get_guest_cr3_for_translation();

    std::uint64_t va = base_va;
    const std::uint64_t end_va = base_va + scan_size;

    while (va + pattern_len <= end_va)
    {
        const std::uint64_t pa = memory_manager::translate_guest_virtual_address(
            guest_cr3, slat_cr3, { .address = va });
        if (!pa)
        {
            va = (va & ~0xFFFull) + 0x1000;
            continue;
        }

        const auto* page = static_cast<const std::uint8_t*>(
            memory_manager::map_guest_physical(slat_cr3, pa & ~0xFFFull));
        if (!page)
        {
            va = (va & ~0xFFFull) + 0x1000;
            continue;
        }

        const std::uint64_t page_off = va & 0xFFF;
        const std::uint64_t bytes_in_page = 0x1000 - page_off;
        // Only match patterns that fit entirely within this page
        const std::uint64_t scannable = (bytes_in_page >= pattern_len) ?
            bytes_in_page - pattern_len + 1 : 0;

        for (std::uint64_t i = 0; i < scannable; i++)
        {
            const std::uint8_t* data = page + page_off + i;
            bool match = true;
            for (std::uint32_t j = 0; j < pattern_len; j++)
            {
                if (mask[j] == 'x' && data[j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
                return va + i;
        }

        va = (va & ~0xFFFull) + 0x1000;
    }

    return 0;
}

// MmClean hook setup — CPUID mode (Option A).
// Shadow page has 7-byte CPUID stub. CPUID VMEXIT handler (reserved_data=10)
// checks CR3 PFN and sets cleanup_pending for target process.
// Safe for ALL processes: any process calling MmClean → CPUID → VMEXIT → handler
// → non-target: passthrough via trampoline, target: cleanup_pending + trampoline.
// No hidden region dependency, no PML4[hidden] required.
std::uint64_t setup_mmclean_inline_hook_impl(
    std::uint64_t target_va, std::uint64_t target_eprocess, std::uint32_t displaced_count)
{
    if (cr3_intercept::mmclean_hook::ctx.active)
    {
        // CPUID hook already installed (boot or previous attach).
        // Just re-arm with new EPROCESS target. No reinstall needed.
        cr3_intercept::cleanup_hook::target_eprocess = target_eprocess;
        cr3_intercept::cleanup_hook::armed = 1;
        return 1;
    }

    // CPUID mode: mov ecx, imm32; cpuid (7 bytes) — no hidden region, no stub filter.
    // Uses existing hypercall dispatch: reserved_data=10 handler does CR3 PFN matching.
    const auto result = ept_install_cpuid_hook(
        target_va, displaced_count, &cr3_intercept::mmclean_hook::ctx, mmclean_cpuid_rcx);

    if (result == 1)
    {
        cr3_intercept::cleanup_hook::target_eprocess = target_eprocess;
        cr3_intercept::cleanup_hook::armed = 1;
    }

    return result;
}

//=============================================================================
// MmClean hook setup — inline pre-check version (zero VMEXIT).
//=============================================================================
//
// 67-byte position-independent shellcode on ntoskrnl shadow code page:
//   - Load first 8 bytes of ImageFileName from EPROCESS ([RCX + IFN_OFFSET])
//   - OR with 0x2020... (case-insensitive ASCII)
//   - Compare with embedded target name qword
//   - Match → 14B abs JMP to compiled C++ handler in hidden region (PML4[hidden])
//   - No match → 14B abs JMP to trampoline (displaced prologue + JMP back)
//
// ALL data as immediates — zero memory reads from shadow page = zero self-read.
// Non-target processes: zero VMEXIT (JMP trampoline → original MmClean).
// Target process: zero VMEXIT (JMP hook_MmCleanProcessAddressSpace → compiled C++).
//
// At boot: installed with TARGET_NAME_QWORD=0 (dormant). Re-armed at attach
// when map_attachment_to_hidden_region() has been called and target name is set.
//
std::uint64_t setup_mmclean_precheck_hook_impl(
    std::uint64_t target_va, std::uint64_t target_eprocess, std::uint32_t displaced_count)
{
    auto& ctx = cr3_intercept::mmclean_hook::ctx;

    if (ctx.active)
    {
        // Re-arm: patch immediates in pre-check shellcode.
        auto* sc = static_cast<std::uint8_t*>(cr3_intercept::mmclean_hook::precheck_host_va);
        if (!sc) return 0;

        // Ensure attachment PE is mapped into hidden region for hidden_detour_va
        if (!cr3_intercept::attachment_mapping::mapped)
            map_attachment_to_hidden_region();

        // Abort re-arm if mapping failed — can't compute hidden_detour_va,
        // enabling the name match would JMP to address 0 → crash.
        if (!cr3_intercept::attachment_mapping::mapped)
            return 0;

        // 1. Patch IFN offset at [5..8]
        *reinterpret_cast<std::uint32_t*>(sc + 5) = cr3_intercept::mmclean_hook::imagefile_name_offset;

        // 2. Patch hidden_detour_va FIRST at [40..43] and [48..51].
        //    Must be valid BEFORE TARGET_NAME_QWORD is written, otherwise a concurrent
        //    VP executing MmClean could name-match and JMP to stale detour_va (0 at boot).
        const std::uint64_t detour_va = host_va_to_hidden_va(
            reinterpret_cast<std::uint64_t>(&hook_MmCleanProcessAddressSpace));
        *reinterpret_cast<std::uint32_t*>(sc + 40) = static_cast<std::uint32_t>(detour_va);
        *reinterpret_cast<std::uint32_t*>(sc + 48) = static_cast<std::uint32_t>(detour_va >> 32);

        serial::reinit();  // reclaim COM1 from VMX root (serial.sys may have reconfigured)
        serial::print("mmclean: detour_va="); serial::print_hex(detour_va); serial::println("");

        // 3. NOW patch TARGET_NAME_QWORD at [24..31] — enables name matching.
        //    Safe: detour_va is already valid above.
        //    Same OR logic as the shellcode: each byte |= 0x20 (case-insensitive ASCII).
        //    Null bytes → 0x20 (never matches real ImageFileName OR'd with 0x20).
        const char* name = cr3_intercept::cleanup_hook::target_process_name;
        std::uint8_t raw[8] = {};
        for (int i = 0; i < 8 && name[i]; i++)
            raw[i] = static_cast<std::uint8_t>(name[i]);
        for (int i = 0; i < 8; i++)
            raw[i] |= 0x20;
        std::uint64_t name_qword = 0;
        crt::copy_memory(&name_qword, raw, 8);
        *reinterpret_cast<std::uint64_t*>(sc + 24) = name_qword;

        cr3_intercept::cleanup_hook::target_eprocess = target_eprocess;
        cr3_intercept::cleanup_hook::armed = 1;

        serial::print("mmclean: precheck re-armed, name_qword="); serial::print_hex(name_qword); serial::println("");
        return 1;
    }

    serial::println("mmclean: setup_mmclean_precheck_hook_impl (first install)");

    // Pre-check uses 14B abs JMP at prologue — force minimum displaced_count.
    if (displaced_count < mmclean_displaced_count)
        displaced_count = mmclean_displaced_count;

    // shadow_code must be initialized by deferred init in Hook 2 (before enable_cr3_intercept).
    // Do NOT retry here — EPT-splitting pages in hook_cr3 while VPs are active causes double faults.
    if (!shadow_code::initialized)
    {
        serial::println("mmclean: shadow_code not initialized (deferred init failed?)");
        return 0xE000;
    }
    if (shadow_code::region_count == 0)
    {
        serial::println("mmclean: shadow_code initialized but 0 regions");
        return 0xE001; // init ran but found nothing
    }

    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 orig_cr3 = get_guest_cr3_for_translation();

    // 1. Translate target VA → PA, read original prologue
    const std::uint64_t target_pa = memory_manager::translate_guest_virtual_address(
        orig_cr3, slat_cr3, { .address = target_va });
    if (!target_pa) return 0xF2;

    const std::uint64_t page_off = target_pa & 0xFFF;
    const std::uint64_t pa_page = target_pa & ~0xFFFull;

    // Guard: 14B JMP must fit within the page
    if (page_off + 14 > 0x1000) return 0xF8;

    const auto* orig_page = static_cast<const std::uint8_t*>(
        memory_manager::map_guest_physical(slat_cr3, pa_page));
    if (!orig_page) return 0xF3;

    // 2. Allocate precheck (67B) and trampoline from shadow_code pool (any ntoskrnl .text page)
    constexpr std::uint32_t precheck_size = 67;

    void* precheck_host = nullptr;
    const std::uint64_t precheck_va = shadow_code::alloc(precheck_size, &precheck_host);
    if (!precheck_va) return 0xE100 | static_cast<std::uint8_t>(shadow_code::region_count);

    const std::uint64_t trampoline_va = shadow_code::alloc_trampoline(
        orig_page + page_off, displaced_count, target_va + displaced_count);
    if (!trampoline_va) return 0xE400 | static_cast<std::uint8_t>(shadow_code::region_count);

    // 3. Assemble 67-byte pre-check shellcode into shadow_code allocation
    //
    // Layout:
    //   [0]  push rax
    //   [1]  push rdx
    //   [2]  mov rax, [rcx + IFN_OFFSET]        ; 48 8B 81 [5..8]=disp32
    //   [9]  movabs rdx, 0x2020202020202020      ; 48 BA [11..18]=imm64
    //   [19] or rax, rdx                         ; 48 0B C2
    //   [22] movabs rdx, TARGET_NAME_QWORD       ; 48 BA [24..31]=imm64
    //   [32] cmp rax, rdx                        ; 48 3B C2
    //   [35] pop rdx
    //   [36] pop rax
    //   [37] jne .passthrough                    ; 75 0E (+14 → offset 53)
    //   [39] 14B abs JMP → hidden_detour_va      ; [40..43]=low32, [48..51]=high32
    //   [53] 14B abs JMP → trampoline_va         ; [54..57]=low32, [62..65]=high32
    //   Total: 67 bytes
    //
    auto* sc = static_cast<std::uint8_t*>(precheck_host);
    int pos = 0;

    sc[pos++] = 0x50; // push rax
    sc[pos++] = 0x52; // push rdx
    // mov rax, [rcx + IFN_OFFSET]
    sc[pos++] = 0x48; sc[pos++] = 0x8B; sc[pos++] = 0x81;
    *reinterpret_cast<std::uint32_t*>(sc + pos) = cr3_intercept::mmclean_hook::imagefile_name_offset;
    pos += 4; // pos = 9
    // movabs rdx, 0x2020202020202020
    sc[pos++] = 0x48; sc[pos++] = 0xBA;
    *reinterpret_cast<std::uint64_t*>(sc + pos) = 0x2020202020202020ull;
    pos += 8; // pos = 19
    // or rax, rdx
    sc[pos++] = 0x48; sc[pos++] = 0x0B; sc[pos++] = 0xC2; // pos = 22
    // movabs rdx, TARGET_NAME_QWORD — dormant: 0 (never matches OR'd name)
    sc[pos++] = 0x48; sc[pos++] = 0xBA;
    *reinterpret_cast<std::uint64_t*>(sc + pos) = 0; // dormant at boot
    pos += 8; // pos = 32
    // cmp rax, rdx
    sc[pos++] = 0x48; sc[pos++] = 0x3B; sc[pos++] = 0xC2; // pos = 35
    sc[pos++] = 0x5A; // pop rdx
    sc[pos++] = 0x58; // pop rax
    // jne .passthrough (+14 → offset 53)
    sc[pos++] = 0x75;
    sc[pos++] = 0x0E; // pos = 39

    // Match path: 14B abs JMP to hidden_detour_va (dormant: 0)
    build_abs_jmp(sc + pos, 0);
    pos += 14; // pos = 53

    // .passthrough: 14B abs JMP to trampoline_va
    build_abs_jmp(sc + pos, trampoline_va);
    pos += 14; // pos = 67

    serial::print("mmclean: precheck "); serial::print_dec(pos); serial::println("B assembled");

    // 4. Allocate shadow page for MmClean function itself (14B JMP at prologue)
    void* mmclean_shadow = heap_manager::allocate_page();
    if (!mmclean_shadow) return 0xF6;
    crt::copy_memory(mmclean_shadow, orig_page, 0x1000);

    // Write 14B absolute JMP at prologue → pre-check handler
    auto* prologue = static_cast<std::uint8_t*>(mmclean_shadow) + page_off;
    build_abs_jmp(prologue, precheck_va);

    // 5. EPT-split MmClean page: execute → shadow (--X), read/write → original
    const std::uint64_t shadow_pa = memory_manager::unmap_host_physical(mmclean_shadow);
    unhide_physical_page(slat_cr3, shadow_pa);

    if (slat::hook::add({ .address = target_pa }, { .address = shadow_pa }, 14) == 0)
    {
        heap_manager::free_page(mmclean_shadow);
        return 0xF7;
    }

    // shadow_code_page flag — only the 14B JMP is modified, but MmClean is stable kernel code.
    {
        slat::hook::entry_t* entry = slat::hook::entry_t::find(target_pa >> 12);
        if (entry) entry->set_shadow_code_page(1);
    }

    // 6. Fill context
    ctx.active = true;
    ctx.target_va = target_va;
    ctx.target_pa_page = pa_page;
    ctx.shadow_heap_va = mmclean_shadow;
    ctx.trampoline_va = trampoline_va;
    ctx.trampoline_hidden_slot = 0xFFFF;
    ctx.stub_pfn_offset = 0;
    ctx.displaced_count = displaced_count;

    // Store pre-check host VA for re-arm patching
    cr3_intercept::mmclean_hook::precheck_host_va = sc;

    cr3_intercept::cleanup_hook::target_eprocess = target_eprocess;

    serial::print("mmclean: precheck installed at "); serial::print_hex(precheck_va);
    serial::print(" trampoline="); serial::print_hex(trampoline_va); serial::println("");

    return 1;
}

// MmAccessFault hook setup — shadow code page version (no hidden memory dependency).
// Inline 44-byte shellcode checks PML4 index of faulting VA:
//   Match → swap CR3 to clone, return STATUS_SUCCESS (0)
//   No match → JMP to trampoline (displaced prologue + JMP back)
// Both handler and trampoline live in ntoskrnl shadow code pages (kernel VA, all processes).
//
// At boot: installed with clone_cr3=0 (dormant). Re-armed at attach with real values.
std::uint64_t setup_mmaf_inline_hook_impl(
    std::uint64_t target_va, std::uint64_t clone_cr3,
    std::uint32_t displaced_count, std::uint8_t hidden_pml4_index)
{
    // Always update runtime params (clone CR3 changes per-attach)
    cr3_intercept::mmaf_hook::clone_cr3_value = clone_cr3;
    cr3_intercept::mmaf_hook::hidden_pml4_index = hidden_pml4_index;

    if (cr3_intercept::mmaf_hook::ctx.active)
    {
        // Hook already installed — patch immediates in-place on shadow code page.
        // handler_host_va points to the 44-byte shellcode in shadow_code allocation.
        if (cr3_intercept::mmaf_hook::ctx.stub_pfn_offset != 0)
        {
            // stub_pfn_offset stores offset-from-shadow-page-start of the handler shellcode.
            // We use it to find the handler host VA and patch clone_cr3 + pml4_index.
            auto* handler = static_cast<std::uint8_t*>(cr3_intercept::mmaf_hook::ctx.shadow_heap_va);
            if (handler)
            {
                // Patch pml4_index at offset +11 (cmp al, imm8 operand)
                handler[11] = hidden_pml4_index;
                // Patch clone_cr3 at offset +18 (movabs rax, imm64 operand)
                *reinterpret_cast<std::uint64_t*>(handler + 18) = clone_cr3;
            }
        }
        return 1;
    }

    serial::reinit();  // reclaim COM1 from VMX root (serial.sys may have reconfigured)
    serial::println("mmaf: setup_mmaf_inline_hook_impl (shadow code version)");

    // shadow_code must be initialized by deferred init in Hook 2
    if (!shadow_code::initialized) return 0xE000;
    if (shadow_code::region_count == 0) return 0xE001;

    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 orig_cr3 = get_guest_cr3_for_translation();

    // 1. Translate target VA → PA, read original prologue
    const std::uint64_t target_pa = memory_manager::translate_guest_virtual_address(
        orig_cr3, slat_cr3, { .address = target_va });
    if (!target_pa) return 0xE1;

    const std::uint64_t page_off = target_pa & 0xFFF;
    const std::uint64_t pa_page = target_pa & ~0xFFFull;

    const auto* orig_page = static_cast<const std::uint8_t*>(
        memory_manager::map_guest_physical(slat_cr3, pa_page));
    if (!orig_page) return 0xE2;

    if (displaced_count < 14) return 0xE3; // need at least 14B for abs JMP

    // 2. Allocate trampoline in shadow code pages (displaced bytes + 14B JMP back)
    const std::uint64_t trampoline_va = shadow_code::alloc_trampoline(
        orig_page + page_off, displaced_count, target_va + displaced_count);
    if (!trampoline_va) return 0xE400 | static_cast<std::uint8_t>(shadow_code::region_count);

    // 3. Allocate 44-byte inline handler in shadow code pages
    void* handler_host = nullptr;
    const std::uint64_t handler_va = shadow_code::alloc(48, &handler_host);
    if (!handler_va || !handler_host) return 0xE5;

    // 4. Assemble 44-byte position-independent shellcode
    // Entry: RCX=FaultStatus, RDX=VirtualAddress, R8=PreviousMode, R9=TrapInformation
    auto* sc = static_cast<std::uint8_t*>(handler_host);
    int pos = 0;

    // push rax                            [50]
    sc[pos++] = 0x50;
    // mov rax, rdx                        [48 8B C2]
    sc[pos++] = 0x48; sc[pos++] = 0x8B; sc[pos++] = 0xC2;
    // shr rax, 39                         [48 C1 E8 27]
    sc[pos++] = 0x48; sc[pos++] = 0xC1; sc[pos++] = 0xE8; sc[pos++] = 0x27;
    // and al, 0xFF                        [24 FF]
    sc[pos++] = 0x24; sc[pos++] = 0xFF;
    // cmp al, HIDDEN_PML4_INDEX           [3C xx] — offset 12, patched
    sc[pos++] = 0x3C;
    const int pml4_idx_offset = pos;
    sc[pos++] = hidden_pml4_index;
    // pop rax                             [58]
    sc[pos++] = 0x58;
    // jne .passthrough                    [75 xx] — offset 14, rel8 patched below
    sc[pos++] = 0x75;
    const int jne_rel_offset = pos;
    sc[pos++] = 0x00; // placeholder

    // Match path: swap CR3 to clone, return STATUS_SUCCESS
    // push rax                            [50]
    sc[pos++] = 0x50;
    // movabs rax, CLONE_CR3_VALUE         [48 B8 xx*8] — offset 17, patched
    sc[pos++] = 0x48; sc[pos++] = 0xB8;
    const int clone_cr3_offset = pos;
    *reinterpret_cast<std::uint64_t*>(sc + pos) = clone_cr3;
    pos += 8;
    // mov cr3, rax                        [0F 22 D8]
    sc[pos++] = 0x0F; sc[pos++] = 0x22; sc[pos++] = 0xD8;
    // pop rax                             [58]
    sc[pos++] = 0x58;
    // xor eax, eax                        [33 C0]
    sc[pos++] = 0x33; sc[pos++] = 0xC0;
    // ret                                 [C3]
    sc[pos++] = 0xC3;

    // .passthrough: 14B absolute JMP to trampoline
    sc[jne_rel_offset] = static_cast<std::uint8_t>(pos - (jne_rel_offset + 1));
    // push low32                          [68 xx xx xx xx]
    sc[pos++] = 0x68;
    *reinterpret_cast<std::uint32_t*>(sc + pos) = static_cast<std::uint32_t>(trampoline_va);
    pos += 4;
    // mov [rsp+4], high32                 [C7 44 24 04 xx xx xx xx]
    sc[pos++] = 0xC7; sc[pos++] = 0x44; sc[pos++] = 0x24; sc[pos++] = 0x04;
    *reinterpret_cast<std::uint32_t*>(sc + pos) = static_cast<std::uint32_t>(trampoline_va >> 32);
    pos += 4;
    // ret                                 [C3]
    sc[pos++] = 0xC3;

    serial::print("mmaf: handler "); serial::print_dec(pos); serial::println("B assembled");

    // 5. Create shadow page for MmAccessFault function itself
    void* mmaf_shadow = heap_manager::allocate_page();
    if (!mmaf_shadow) return 0xE6;
    crt::copy_memory(mmaf_shadow, orig_page, 0x1000);

    // Write 14B absolute JMP at prologue → handler_va
    auto* prologue = static_cast<std::uint8_t*>(mmaf_shadow) + page_off;
    prologue[0] = 0x68; // push low32
    *reinterpret_cast<std::uint32_t*>(prologue + 1) = static_cast<std::uint32_t>(handler_va);
    prologue[5] = 0xC7; // mov [rsp+4], high32
    prologue[6] = 0x44;
    prologue[7] = 0x24;
    prologue[8] = 0x04;
    *reinterpret_cast<std::uint32_t*>(prologue + 9) = static_cast<std::uint32_t>(handler_va >> 32);
    prologue[13] = 0xC3; // ret

    // 6. EPT-split: execute → mmaf shadow (--X), read/write → original
    const std::uint64_t mmaf_shadow_pa = memory_manager::unmap_host_physical(mmaf_shadow);
    unhide_physical_page(slat_cr3, mmaf_shadow_pa);

    if (slat::hook::add({ .address = pa_page }, { .address = mmaf_shadow_pa }, 14) == 0)
    {
        heap_manager::free_page(mmaf_shadow);
        return 0xE7;
    }

    // 7. Fill context
    auto& ctx = cr3_intercept::mmaf_hook::ctx;
    ctx.active = true;
    ctx.target_va = target_va;
    ctx.target_pa_page = pa_page;
    ctx.shadow_heap_va = handler_host;  // points to handler shellcode for patching
    ctx.trampoline_va = trampoline_va;
    ctx.trampoline_hidden_slot = 0xFFFF; // not using hidden region
    ctx.stub_pfn_offset = 1; // nonzero signals "patchable" (actual patching uses handler_host)
    ctx.displaced_count = displaced_count;

    serial::print("mmaf: hook installed, handler="); serial::print_hex(handler_va);
    serial::print(" trampoline="); serial::print_hex(trampoline_va); serial::println("");

    return 1;
}

// Read 4KB from original page tables into a clone-visible buffer
std::uint64_t read_original_page_impl(const cr3& slat_cr3, std::uint64_t source_va, std::uint64_t dest_va)
{
    const cr3 original_cr3 = { .flags = cr3_intercept::target_original_cr3 };
    const cr3 clone_cr3 = { .address_of_page_directory = cr3_intercept::cloned_cr3_value >> 12 };

    // Translate source VA under original CR3
    const std::uint64_t src_gpa = memory_manager::translate_guest_virtual_address(
        original_cr3, slat_cr3, { .address = source_va });
    if (src_gpa == 0) return 0;

    // Translate dest VA under clone CR3
    const std::uint64_t dst_gpa = memory_manager::translate_guest_virtual_address(
        clone_cr3, slat_cr3, { .address = dest_va });
    if (dst_gpa == 0) return 0;

    const void* src = memory_manager::map_guest_physical(slat_cr3, src_gpa & ~0xFFFull);
    void* dst = memory_manager::map_guest_physical(slat_cr3, dst_gpa & ~0xFFFull);
    if (!src || !dst) return 0;

    crt::copy_memory(dst, src, 0x1000);
    return 1;
}

// Free all heap pages associated with the clone CR3:
// 1. Shadow leaf pages + cloned intermediate pages (via registry)
// 2. Hidden region (data pages, PT, PD, PDPT)
// 3. Cloned PML4 itself
void free_clone_pages()
{
    if (cr3_intercept::cloned_pml4_host_va == nullptr)
        return;

    // --- 1. Free all shadow leaf pages ---
    for (int i = 0; i < cr3_intercept::shadow_leaf_count; i++)
    {
        void* va = memory_manager::map_host_physical(cr3_intercept::shadow_leaves[i].shadow_pa);
        if (va) heap_manager::free_page(va);
    }

    // --- 2. Free all cloned PT pages ---
    for (int i = 0; i < cr3_intercept::shadow_pt_count; i++)
    {
        void* va = memory_manager::map_host_physical(cr3_intercept::shadow_pts[i].cloned_pa);
        if (va) heap_manager::free_page(va);
    }

    // --- 3. Free all cloned PD pages ---
    for (int i = 0; i < cr3_intercept::shadow_pd_count; i++)
    {
        void* va = memory_manager::map_host_physical(cr3_intercept::shadow_pds[i].cloned_pa);
        if (va) heap_manager::free_page(va);
    }

    // --- 4. Free all cloned PDPT pages ---
    for (int i = 0; i < cr3_intercept::shadow_pdpt_count; i++)
    {
        void* va = memory_manager::map_host_physical(cr3_intercept::shadow_pdpts[i].cloned_pa);
        if (va) heap_manager::free_page(va);
    }

    // --- 5. Reset registry counts ---
    cr3_intercept::shadow_pdpt_count = 0;
    cr3_intercept::shadow_pd_count = 0;
    cr3_intercept::shadow_pt_count = 0;
    cr3_intercept::shadow_leaf_count = 0;

    // --- 6. Free hidden region subtree (entirely heap-allocated) ---
    const cr3 slat_cr3 = slat::hyperv_cr3();

    if (cr3_intercept::reserved_pml4e_index < 512)
    {
        auto* clone_pml4 = static_cast<pml4e_64*>(cr3_intercept::cloned_pml4_host_va);
        const pml4e_64 pml4e = clone_pml4[cr3_intercept::reserved_pml4e_index];

        if (pml4e.present)
        {
            const std::uint64_t pdpt_gpa = pml4e.page_frame_number << 12;
            auto* pdpt = static_cast<pdpte_64*>(memory_manager::map_guest_physical(slat_cr3, pdpt_gpa));

            if (pdpt && pdpt[0].present)
            {
                const std::uint64_t pd_gpa = pdpt[0].page_frame_number << 12;
                auto* pd = static_cast<pde_64*>(memory_manager::map_guest_physical(slat_cr3, pd_gpa));

                if (pd && pd[0].present)
                {
                    const std::uint64_t pt_gpa = pd[0].page_frame_number << 12;
                    auto* pt = static_cast<pte_64*>(memory_manager::map_guest_physical(slat_cr3, pt_gpa));

                    if (pt)
                    {
                        // free all data pages in the hidden PT
                        // Skip attachment image pages (they are NOT heap-allocated)
                        const std::uint64_t att_base = cr3_intercept::attachment_mapping::image_base_pa;
                        const std::uint64_t att_end = att_base
                            + (static_cast<std::uint64_t>(cr3_intercept::attachment_mapping::image_page_count) << 12);

                        for (int i = 0; i < 512; i++)
                        {
                            if (pt[i].present)
                            {
                                const std::uint64_t page_pa = pt[i].page_frame_number << 12;
                                if (att_base != 0 && page_pa >= att_base && page_pa < att_end)
                                {
                                    pt[i].flags = 0; // clear mapping, don't free the image page
                                    continue;
                                }
                                void* data_va = memory_manager::map_host_physical(page_pa);
                                if (data_va) heap_manager::free_page(data_va);
                            }
                        }

                        // Reset attachment mapping state (will be remapped on next attach)
                        cr3_intercept::attachment_mapping::mapped = false;
                        cr3_intercept::attachment_mapping::hidden_base_va = 0;
                    }

                    // free PT page
                    void* pt_host = memory_manager::map_host_physical(pt_gpa);
                    if (pt_host) heap_manager::free_page(pt_host);
                }

                // free PD page
                void* pd_host = memory_manager::map_host_physical(pd_gpa);
                if (pd_host) heap_manager::free_page(pd_host);
            }

            // free PDPT page
            void* pdpt_host = memory_manager::map_host_physical(pdpt_gpa);
            if (pdpt_host) heap_manager::free_page(pdpt_host);
        }
    }

    // --- 7. Free the cloned PML4 itself ---
    heap_manager::free_page(cr3_intercept::cloned_pml4_host_va);
}

std::uint64_t operate_on_guest_physical_memory(const trap_frame_t* const trap_frame, const memory_operation_t operation)
{
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const std::uint64_t guest_buffer_virtual_address = trap_frame->r8;
    const std::uint64_t guest_physical_address = trap_frame->rdx;

    std::uint64_t size_left_to_copy = trap_frame->r9;

    std::uint64_t bytes_copied = 0;

    while (size_left_to_copy != 0)
    {
        std::uint64_t size_left_of_destination_slat_page = UINT64_MAX;
        std::uint64_t size_left_of_source_slat_page = UINT64_MAX;

        const std::uint64_t guest_buffer_physical_address = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = guest_buffer_virtual_address + bytes_copied });

        void* host_destination = memory_manager::map_guest_physical(slat_cr3, guest_buffer_physical_address, &size_left_of_destination_slat_page);
        void* host_source = memory_manager::map_guest_physical(slat_cr3, guest_physical_address + bytes_copied, &size_left_of_source_slat_page);

        if (size_left_of_destination_slat_page == UINT64_MAX || size_left_of_source_slat_page == UINT64_MAX)
        {
            break;
        }

        if (operation == memory_operation_t::write_operation)
        {
            crt::swap(host_source, host_destination);
        }

        const std::uint64_t size_left_of_slat_pages = crt::min(size_left_of_source_slat_page, size_left_of_destination_slat_page);

        const std::uint64_t copy_size = crt::min(size_left_to_copy, size_left_of_slat_pages);

        if (copy_size == 0)
        {
            break;
        }

        crt::copy_memory(host_destination, host_source, copy_size);

        size_left_to_copy -= copy_size;
        bytes_copied += copy_size;
    }

    return bytes_copied;
}

std::uint64_t operate_on_guest_virtual_memory(const trap_frame_t* const trap_frame, const memory_operation_t operation, const std::uint64_t address_of_page_directory)
{
    const cr3 guest_source_cr3 = { .address_of_page_directory = address_of_page_directory };

    const cr3 guest_destination_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const std::uint64_t guest_destination_virtual_address = trap_frame->rdx;
    const  std::uint64_t guest_source_virtual_address = trap_frame->r8;

    std::uint64_t size_left_to_read = trap_frame->r9;

    std::uint64_t bytes_copied = 0;

    while (size_left_to_read != 0)
    {
        std::uint64_t size_left_of_destination_virtual_page = UINT64_MAX;
        std::uint64_t size_left_of_destination_slat_page = UINT64_MAX;

        std::uint64_t size_left_of_source_virtual_page = UINT64_MAX;
        std::uint64_t size_left_of_source_slat_page = UINT64_MAX;

        const std::uint64_t guest_source_physical_address = memory_manager::translate_guest_virtual_address(guest_source_cr3, slat_cr3, { .address = guest_source_virtual_address + bytes_copied }, &size_left_of_source_virtual_page);
        const std::uint64_t guest_destination_physical_address = memory_manager::translate_guest_virtual_address(guest_destination_cr3, slat_cr3, { .address = guest_destination_virtual_address + bytes_copied }, &size_left_of_destination_virtual_page);

        if (size_left_of_destination_virtual_page == UINT64_MAX || size_left_of_source_virtual_page == UINT64_MAX)
        {
            break;
        }

        void* host_destination = memory_manager::map_guest_physical(slat_cr3, guest_destination_physical_address, &size_left_of_destination_slat_page);
        void* host_source = memory_manager::map_guest_physical(slat_cr3, guest_source_physical_address, &size_left_of_source_slat_page);

    	if (size_left_of_destination_slat_page == UINT64_MAX || size_left_of_source_slat_page == UINT64_MAX)
        {
            break;
        }

        if (operation == memory_operation_t::write_operation)
        {
            crt::swap(host_source, host_destination);
        }

        const std::uint64_t size_left_of_slat_pages = crt::min(size_left_of_source_slat_page, size_left_of_destination_slat_page);
        const std::uint64_t size_left_of_virtual_pages = crt::min(size_left_of_source_virtual_page, size_left_of_destination_virtual_page);

        const std::uint64_t size_left_of_pages = crt::min(size_left_of_slat_pages, size_left_of_virtual_pages);

        const std::uint64_t copy_size = crt::min(size_left_to_read, size_left_of_pages);

        if (copy_size == 0)
        {
            break;
        }

        crt::copy_memory(host_destination, host_source, copy_size);

        size_left_to_read -= copy_size;
        bytes_copied += copy_size;
    }

    return bytes_copied;
}

std::uint8_t copy_stack_data_from_log_exit(std::uint64_t* const stack_data, const std::uint64_t stack_data_count, const cr3 guest_cr3, const std::uint64_t rsp)
{
    if (rsp == 0)
    {
        return 0;
    }

    const cr3 slat_cr3 = slat::hyperv_cr3();

    std::uint64_t bytes_read = 0;
    std::uint64_t bytes_remaining = stack_data_count * sizeof(std::uint64_t);

    while (bytes_remaining != 0)
    {
        std::uint64_t virtual_size_left = 0;

        const std::uint64_t rsp_guest_physical_address = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = rsp + bytes_read }, &virtual_size_left);

        if (rsp_guest_physical_address == 0)
        {
            return 0;
        }

        std::uint64_t physical_size_left = 0;

        // rcx has just been pushed onto stack
        const auto rsp_mapped = static_cast<const std::uint64_t*>(memory_manager::map_guest_physical(slat_cr3, rsp_guest_physical_address, &physical_size_left));

        const std::uint64_t size_left_of_page = crt::min(physical_size_left, virtual_size_left);
        const std::uint64_t size_to_read = crt::min(bytes_remaining, size_left_of_page);

        if (size_to_read == 0)
        {
            return 0;
        }

        crt::copy_memory(reinterpret_cast<std::uint8_t*>(stack_data) + bytes_read, reinterpret_cast<const std::uint8_t*>(rsp_mapped) + bytes_read, size_to_read);

        bytes_remaining -= size_to_read;
        bytes_read += size_to_read;
    }

    return 1;
}

void do_stack_data_copy(trap_frame_log_t& trap_frame, const cr3 guest_cr3)
{
    constexpr std::uint64_t stack_data_count = trap_frame_log_stack_data_count + 1;

    std::uint64_t stack_data[stack_data_count];
    crt::set_memory(stack_data, 0, sizeof(stack_data));

    copy_stack_data_from_log_exit(&stack_data[0], stack_data_count, guest_cr3, trap_frame.rsp);

    crt::copy_memory(&trap_frame.stack_data, &stack_data[1], sizeof(trap_frame.stack_data));

    trap_frame.rcx = stack_data[0];
    trap_frame.rsp += 8; // get rid of the rcx value we push onto stack ourselves
}

void log_current_state(trap_frame_log_t trap_frame)
{
    cr3 guest_cr3 = arch::get_guest_cr3();

    do_stack_data_copy(trap_frame, guest_cr3);

    trap_frame.cr3 = guest_cr3.flags;
    trap_frame.rip = arch::get_guest_rip();

    logs::add_log(trap_frame);
}

std::uint64_t flush_logs(const trap_frame_t* const trap_frame)
{
    std::uint64_t stored_logs_count = logs::stored_log_index;

    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const std::uint64_t guest_virtual_address = trap_frame->rdx;
    const std::uint16_t count = static_cast<std::uint16_t>(trap_frame->r8);

    if (logs::flush(slat_cr3, guest_virtual_address, guest_cr3, count) == 0)
    {
        return -1;
    }

    return stored_logs_count;
}

// Shared cleanup: disables CR3 intercept, removes EPT hooks, frees clone pages, resets state.
// Called by disable_cr3_intercept and by MmCleanProcessAddressSpace hook on process death.
// Uses interlocked exchange on enabled to prevent concurrent entry from two VCPUs.
void hypercall::perform_process_cleanup()
{
    // Atomically claim cleanup: only one VCPU may proceed
    const char was_enabled = _InterlockedExchange8(
        reinterpret_cast<volatile char*>(&cr3_intercept::enabled), 0);
    if (!was_enabled) return;

    cr3_intercept::cleanup_hook::cleanup_performed_count++;

    // if current guest CR3 is the clone, restore original
    const cr3 current_guest_cr3 = arch::get_guest_cr3();

    if ((current_guest_cr3.flags & cr3_intercept::cr3_pfn_mask) == (cr3_intercept::cloned_cr3_value & cr3_intercept::cr3_pfn_mask))
    {
        arch::set_guest_cr3({ .flags = cr3_intercept::target_original_cr3 });
        arch::invalidate_vpid_current();
    }

    // flush SLAT on all VCPUs
    interrupts::set_all_nmi_ready();
    interrupts::send_nmi_all_but_self();

    // ── Permanent hooks (ring-1 model) ──────────────────────────────────
    // EPT hooks stay active even after process death.  MmClean, KiPageFault,
    // KiDispatchException, PsWatch, NtClose, etc. remain installed in the SLAT.
    // They become dormant: MmClean checks armed==0 → passthrough, KiPageFault
    // checks CR3 PFN → no match → passthrough, etc.
    //
    // Shadow pages, trampolines, hidden region, and clone PML4 are NOT freed —
    // hooks reference them.  On re-attach, state is re-armed with the new
    // target process info; hooks that are already installed are skipped.

    // disarm intercept state (hooks stay, intercept stops)
    cr3_intercept::target_original_cr3 = 0;
    cr3_intercept::target_user_cr3 = 0;
    cr3_intercept::cloned_cr3_value = 0;
    // NOTE: cloned_pml4_host_va, hidden_pt_host_va, reserved_pml4e_index kept —
    //       hooks and trampolines live in that memory.
    cr3_intercept::syscall_hijack_armed = 0;
    cr3_intercept::syscall_hijack_shellcode_va = 0;
    cr3_intercept::syscall_hijack_rip_offset = 0;

    // disarm cleanup hook (will be re-armed on next inject)
    cr3_intercept::cleanup_hook::armed = 0;
    cr3_intercept::cleanup_hook::target_eprocess = 0;
}

bool hypercall::process(const hypercall_info_t hypercall_info, trap_frame_t* const trap_frame)
{
    bool rip_redirected = false;

    switch (hypercall_info.call_type)
    {
    case hypercall_type_t::guest_physical_memory_operation:
    {
        const auto memory_operation = static_cast<memory_operation_t>(hypercall_info.call_reserved_data);

        trap_frame->rax = operate_on_guest_physical_memory(trap_frame, memory_operation);

        break;
    }
    case hypercall_type_t::guest_virtual_memory_operation:
    {
        const virt_memory_op_hypercall_info_t virt_memory_op_info = { .value = hypercall_info.value };

        const memory_operation_t memory_operation = virt_memory_op_info.memory_operation;
        const std::uint64_t address_of_page_directory = virt_memory_op_info.address_of_page_directory;

        trap_frame->rax = operate_on_guest_virtual_memory(trap_frame, memory_operation, address_of_page_directory);

        break;
    }
    case hypercall_type_t::translate_guest_virtual_address:
    {
        const virtual_address_t guest_virtual_address = { .address = trap_frame->rdx };

        const cr3 target_guest_cr3 = { .flags = trap_frame->r8 };
        const cr3 slat_cr3 = slat::hyperv_cr3();

        trap_frame->rax = memory_manager::translate_guest_virtual_address(target_guest_cr3, slat_cr3, guest_virtual_address);

        break;
    }
    case hypercall_type_t::read_guest_cr3:
    {
        if (hypercall_info.call_reserved_data == 1)
        {
            trap_frame->rax = cr3_intercept::cr3_exit_count;
        }
        else if (hypercall_info.call_reserved_data == 2)
        {
            trap_frame->rax = cr3_intercept::cr3_swap_count;
        }
        else if (hypercall_info.call_reserved_data == 3)
        {
            trap_frame->rax = cr3_intercept::cr3_last_seen;
        }
        else if (hypercall_info.call_reserved_data == 11)
        {
            trap_frame->rax = cr3_intercept::slat_violation_count;
        }
        else if (hypercall_info.call_reserved_data == 6)
        {
            // read mmaf_hit_count (MmAccessFault hook diagnostic)
            trap_frame->rax = cr3_intercept::mmaf_hit_count;
        }
        else if (hypercall_info.call_reserved_data == 37)
        {
            // read mmaf_hook total call count (stub filter fires for ALL processes)
            trap_frame->rax = cr3_intercept::mmaf_hook::total_count;
        }
        else if (hypercall_info.call_reserved_data == 7)
        {
            // check_and_clear_syscall_hijack: atomically disarm and return shellcode_va
            // RDX = original_rip (passed by ring-0 shellcode from TrapFrame.Rip)
            // Writes original_rip directly into the stub page at rip_offset (no usermode CPUID needed)
            cr3_intercept::hijack_cpuid_count++;

            const char was_armed = _InterlockedExchange8(
                reinterpret_cast<volatile char*>(&cr3_intercept::syscall_hijack_armed), 0);

            if (was_armed)
            {
                cr3_intercept::hijack_claimed_count++;

                // Write original_rip into the stub's jmp [rip+0] placeholder
                const std::uint64_t original_rip = trap_frame->rdx;
                const std::uint64_t target_va = cr3_intercept::syscall_hijack_shellcode_va
                    + cr3_intercept::syscall_hijack_rip_offset;

                const cr3 clone_cr3 = { .address_of_page_directory = cr3_intercept::cloned_cr3_value >> 12 };
                const cr3 slat_cr3 = slat::hyperv_cr3();

                const std::uint64_t target_gpa = memory_manager::translate_guest_virtual_address(
                    clone_cr3, slat_cr3, { .address = target_va });

                if (target_gpa != 0)
                {
                    auto* const host_ptr = static_cast<std::uint64_t*>(
                        memory_manager::map_guest_physical(slat_cr3, target_gpa));

                    if (host_ptr != nullptr)
                    {
                        *host_ptr = original_rip;
                    }
                }

                // Force clone CR3 so the thread returns to usermode with PML4[hidden]
                // accessible. Without this, Hyper-V can clear CR3 exiting between
                // filtered VMEXITs, causing a missed MOV CR3 swap → #PF on hidden
                // memory → process crash. This replaces the old MmAccessFault hook.
                if (cr3_intercept::enabled && cr3_intercept::cloned_cr3_value != 0)
                {
                    arch::set_guest_cr3({ .flags = cr3_intercept::cloned_cr3_value });
                    arch::invalidate_vpid_current();
                }

                trap_frame->rax = cr3_intercept::syscall_hijack_shellcode_va;
            }
            else
            {
                trap_frame->rax = 0;
            }
        }
        else if (hypercall_info.call_reserved_data == 8)
        {
            // arm_syscall_hijack: set shellcode VA, rip_offset, and arm
            cr3_intercept::syscall_hijack_shellcode_va = trap_frame->rdx;
            cr3_intercept::syscall_hijack_rip_offset = trap_frame->r8;
            cr3_intercept::hijack_cpuid_count = 0;
            cr3_intercept::hijack_claimed_count = 0;
            cr3_intercept::syscall_hijack_armed = 1;
            trap_frame->rax = 1;
        }
        else if (hypercall_info.call_reserved_data == 9)
        {
            // disarm_syscall_hijack
            cr3_intercept::syscall_hijack_armed = 0;
            cr3_intercept::syscall_hijack_shellcode_va = 0;
            cr3_intercept::syscall_hijack_rip_offset = 0;
            trap_frame->rax = 1;
        }
        else if (hypercall_info.call_reserved_data == 10)
        {
            // MmClean CPUID hook handler — process death detection (Option A).
            // Triggered by CPUID stub on MmClean shadow page (mov ecx, 0x5533A3D8; cpuid).
            // ALL processes calling MmClean on hook_cr3 hit this. Safe: CPUID → VMEXIT → here.
            // Non-target: passthrough via trampoline. Target: set cleanup_pending + trampoline.
            //
            // CRITICAL: rip_redirected = true — handler redirects RIP to CC trampoline.
            // Do NOT advance RIP normally (would land on dead NOPs after CPUID stub).

            cr3_intercept::cleanup_hook::hook_entry_count++;

            if (cr3_intercept::cleanup_hook::armed && cr3_intercept::enabled)
            {
                cr3_intercept::cleanup_hook::hook_hit_count++;

                const cr3 guest_cr3 = arch::get_guest_cr3();
                const std::uint64_t guest_pfn = guest_cr3.flags & cr3_intercept::cr3_pfn_mask;
                const std::uint64_t target_pfn = cr3_intercept::target_original_cr3 & cr3_intercept::cr3_pfn_mask;
                const std::uint64_t clone_pfn = cr3_intercept::cloned_cr3_value & cr3_intercept::cr3_pfn_mask;

                const bool is_target = (guest_pfn == target_pfn) ||
                    (guest_pfn == clone_pfn) ||
                    (cr3_intercept::target_user_cr3 != 0 &&
                     guest_pfn == (cr3_intercept::target_user_cr3 & cr3_intercept::cr3_pfn_mask));

                if (is_target)
                {
                    cr3_intercept::cleanup_hook::hook_match_count++;

                    const char was_armed = _InterlockedExchange8(
                        reinterpret_cast<volatile char*>(&cr3_intercept::cleanup_hook::armed), 0);
                    if (was_armed)
                    {
                        cr3_intercept::cleanup_hook::cleanup_pending = 1;
                    }
                }
            }

            // Redirect RIP to CC trampoline (displaced bytes + JMP back to MmClean+displaced_count).
            // Works for ALL processes: displaced bytes restore prologue, JMP back continues original MmClean.
            if (cr3_intercept::mmclean_hook::ctx.active &&
                cr3_intercept::mmclean_hook::ctx.trampoline_va != 0)
            {
                arch::set_guest_rip(cr3_intercept::mmclean_hook::ctx.trampoline_va);
                rip_redirected = true;
            }

            trap_frame->rax = cr3_intercept::cleanup_hook::cleanup_pending;
        }
        else if (hypercall_info.call_reserved_data == 12)
        {
            // read hijack_cpuid_count (total CPUID(7) calls received)
            trap_frame->rax = cr3_intercept::hijack_cpuid_count;
        }
        else if (hypercall_info.call_reserved_data == 13)
        {
            // read hijack_claimed_count (times was_armed==1 at CPUID(7))
            trap_frame->rax = cr3_intercept::hijack_claimed_count;
        }
        else if (hypercall_info.call_reserved_data == 14)
        {
            // read current armed state
            trap_frame->rax = cr3_intercept::syscall_hijack_armed;
        }
        else if (hypercall_info.call_reserved_data == 15)
        {
            // set_diag_watch_pfn: RDX = PFN to watch (0 = disable)
            cr3_intercept::diag_watch_pfn = trap_frame->rdx;
            cr3_intercept::diag_watch_pfn_exec_count = 0;
            cr3_intercept::diag_watch_pfn_rw_count = 0;
            trap_frame->rax = 1;
        }
        else if (hypercall_info.call_reserved_data == 16)
        {
            // read diag_watch_pfn_exec_count
            trap_frame->rax = cr3_intercept::diag_watch_pfn_exec_count;
        }
        else if (hypercall_info.call_reserved_data == 17)
        {
            // read diag_watch_pfn_rw_count
            trap_frame->rax = cr3_intercept::diag_watch_pfn_rw_count;
        }
        else if (hypercall_info.call_reserved_data == 18)
        {
            // read EPT PTE permissions for a given guest physical address
            // RDX = guest physical address, R8 = 0 for hyperv_cr3, 1 for hook_cr3
            const virtual_address_t gpa = { .address = trap_frame->rdx };
            const cr3 ept_cr3 = trap_frame->r8 == 0 ? slat::hyperv_cr3() : slat::hook_cr3();

            slat_pte* const pte = slat::get_pte(ept_cr3, gpa);

            if (pte != nullptr)
            {
                // Pack permissions + PFN into RAX:
                // bits [0]: read, [1]: write, [2]: execute, [3]: found
                // bits [51:12]: page_frame_number
                trap_frame->rax = (pte->page_frame_number << 12)
                    | (static_cast<std::uint64_t>(pte->read_access) << 0)
                    | (static_cast<std::uint64_t>(pte->write_access) << 1)
                    | (static_cast<std::uint64_t>(pte->execute_access) << 2)
                    | (1ull << 3); // found flag
            }
            else
            {
                trap_frame->rax = 0; // PTE not found
            }
        }
        else if (hypercall_info.call_reserved_data == 22)
        {
            // check_process_cleanup: called from ring-0 MmCleanProcessAddressSpace shellcode
            // RDX = dying EPROCESS VA
            //
            // DEFERRED CLEANUP: We do NOT call perform_process_cleanup() here because
            // the MmClean shellcode is still mid-execution on the shadow page. Removing
            // the EPT hook now would unmap the shadow page → guest resumes on original
            // page with wrong code → KMODE_EXCEPTION BSOD.
            // Instead, set cleanup_pending=1. Hook 2 (main.cpp) picks it up on the NEXT
            // VMEXIT when the shellcode has already finished and returned.
            const std::uint64_t dying_eprocess = trap_frame->rdx;

            if (cr3_intercept::cleanup_hook::armed &&
                dying_eprocess == cr3_intercept::cleanup_hook::target_eprocess &&
                cr3_intercept::enabled)
            {
                const char was_armed = _InterlockedExchange8(
                    reinterpret_cast<volatile char*>(&cr3_intercept::cleanup_hook::armed), 0);

                if (was_armed)
                {
                    cr3_intercept::cleanup_hook::cleanup_pending = 1;
                    trap_frame->rax = 1;
                }
                else
                {
                    trap_frame->rax = 0;
                }
            }
            else
            {
                trap_frame->rax = 0;
            }
        }
        else if (hypercall_info.call_reserved_data == 23)
        {
            // arm_process_cleanup: RDX = target EPROCESS, R8 = ntoskrnl base VA, R9 = guest VA of name string (16B)
            cr3_intercept::cleanup_hook::target_eprocess = trap_frame->rdx;

            // Resolve PsGetProcessImageFileName via PE export walk (like ring-1 LookupExport_ByName)
            if (trap_frame->r8 != 0)
            {
                cr3_intercept::cleanup_hook::ntoskrnl_base = trap_frame->r8;

                // Only resolve once — cached across re-arms
                if (cr3_intercept::cleanup_hook::fn_PsGetProcessImageFileName == 0)
                {
                    cr3_intercept::cleanup_hook::fn_PsGetProcessImageFileName =
                        resolve_kernel_export(trap_frame->r8, "PsGetProcessImageFileName");
                }
            }

            // Read target process name from guest memory
            if (trap_frame->r9 != 0)
            {
                const cr3 guest_cr3 = arch::get_guest_cr3();
                const cr3 slat_cr3 = slat::hyperv_cr3();
                const std::uint64_t name_pa = memory_manager::translate_guest_virtual_address(
                    guest_cr3, slat_cr3, { .address = trap_frame->r9 });
                if (name_pa != 0)
                {
                    const void* name_host = memory_manager::map_guest_physical(slat_cr3, name_pa);
                    if (name_host)
                    {
                        for (int i = 0; i < 15; i++)
                            cr3_intercept::cleanup_hook::target_process_name[i] =
                                static_cast<const char*>(name_host)[i];
                        cr3_intercept::cleanup_hook::target_process_name[15] = '\0';
                    }
                }
            }

            cr3_intercept::cleanup_hook::armed = 1;
            trap_frame->rax = cr3_intercept::cleanup_hook::fn_PsGetProcessImageFileName != 0 ? 1 : 0;
        }
        else if (hypercall_info.call_reserved_data == 28)
        {
            // read cleanup_performed_count: how many times perform_process_cleanup() fired
            trap_frame->rax = cr3_intercept::cleanup_hook::cleanup_performed_count;
        }
        else if (hypercall_info.call_reserved_data == 29)
        {
            // setup_mmclean_precheck_hook: RDX=target_va, R8=target_eprocess, R9=displaced_count
            // Pre-check version: 67B inline shellcode (zero VMEXIT), replaces CPUID stub.
            trap_frame->rax = setup_mmclean_precheck_hook_impl(
                trap_frame->rdx, trap_frame->r8,
                static_cast<std::uint32_t>(trap_frame->r9));
        }
        else if (hypercall_info.call_reserved_data == 31)
        {
            // disarm_mmclean_inline_hook (hook stays installed, becomes passthrough)
            if (!cr3_intercept::mmclean_hook::ctx.active)
            {
                trap_frame->rax = 0;
            }
            else
            {
                cr3_intercept::cleanup_hook::armed = 0;
                cr3_intercept::cleanup_hook::target_eprocess = 0;
                trap_frame->rax = 1;
            }
        }
        else if (hypercall_info.call_reserved_data == 32)
        {
            // Hook 3 (VMWRITE EPTP redirect) control + diagnostics
            // RDX: 1=activate, 0=deactivate, 2=read hook_cr3 count, 3=read hyperv_cr3 count, 4=read rebootstrap count
            const auto sub_cmd = trap_frame->rdx;
            if (sub_cmd == 1)
            {
                slat::activate_vmwrite_hook(true);
                trap_frame->rax = 1;
            }
            else if (sub_cmd == 0)
            {
                slat::activate_vmwrite_hook(false);
                trap_frame->rax = 1;
            }
            else if (sub_cmd == 2)
            {
                trap_frame->rax = static_cast<std::uint64_t>(hook3_on_hook_cr3_count);
            }
            else if (sub_cmd == 3)
            {
                trap_frame->rax = static_cast<std::uint64_t>(hook3_on_hyperv_cr3_count);
            }
            else if (sub_cmd == 4)
            {
                trap_frame->rax = static_cast<std::uint64_t>(hook3_rebootstrap_count);
            }
            else if (sub_cmd == 5)
            {
                trap_frame->rax = slat::read_vmwrite_hook_counter();
            }
            else if (sub_cmd == 6)
            {
                trap_frame->rax = slat::read_vmwrite_hook_slot1();
            }
            else if (sub_cmd == 7)
            {
                trap_frame->rax = slat::read_vmwrite_hook_slot2();
            }
            else if (sub_cmd == 9)
            {
                trap_frame->rax = slat::read_vmwrite_hook_cave_pa();
            }
            // Option B diagnostics (EPTP source table patch)
            else if (sub_cmd == 10) { trap_frame->rax = slat::optb_diag_bail; }
            else if (sub_cmd == 11) { trap_frame->rax = slat::optb_diag_per_vp; }
            else if (sub_cmd == 12) { trap_frame->rax = slat::optb_diag_ept_data; }
            else if (sub_cmd == 13) { trap_frame->rax = slat::optb_diag_count; }
            // Deep GS diagnostics
            else if (sub_cmd == 14) { trap_frame->rax = slat::optb_diag_gs_base; }
            else if (sub_cmd == 15) { trap_frame->rax = slat::optb_diag_manual_read; }
            else if (sub_cmd == 16) { trap_frame->rax = slat::optb_diag_gs_first_qword; }
            else if (sub_cmd == 17) { trap_frame->rax = slat::optb_diag_host_gs_base; }
            else if (sub_cmd == 8)
            {
                // Cave diagnostic: dump shellcode bytes + reverse-engineer function entry
                const std::uint64_t cave_pa = slat::read_vmwrite_hook_cave_pa();
                if (cave_pa == 0)
                {
                    trap_frame->rax = 0;
                }
                else
                {
                    const auto* cave = static_cast<const std::uint8_t*>(
                        memory_manager::map_host_physical(cave_pa));

                    serial::reinit();  // reclaim COM1 from VMX root (serial.sys may have reconfigured)

                    // 1. Dump SLOT1/SLOT2 from actual cave bytes
                    std::uint64_t slot1_in_cave = *reinterpret_cast<const std::uint64_t*>(cave + 4);
                    std::uint64_t slot2_in_cave = *reinterpret_cast<const std::uint64_t*>(cave + 39);
                    serial::print("[cavediag] SLOT1 (cave+4)="); serial::print_hex(slot1_in_cave); serial::println("");
                    serial::print("[cavediag] SLOT2 (cave+39)="); serial::print_hex(slot2_in_cave); serial::println("");

                    // 2. Dump first 73 bytes of shellcode
                    serial::print("[cavediag] shellcode: ");
                    for (int i = 0; i < 73; i++)
                    {
                        serial::print_byte_hex(cave[i]);
                        if (i == 11 || i == 16 || i == 28 || i == 36 || i == 46 || i == 52 || i == 54 || i == 61 || i == 67)
                            serial::print(" | ");
                        else
                            serial::print(" ");
                    }
                    serial::println("");

                    // 3. Reverse-engineer function entry from displaced jmp lazy_path
                    // The JMP rel32 at the function entry: func+5+rel32 = cave_va
                    // We can get cave_va from the displaced instructions' RIP-relative fixups.
                    // Displaced test at cave+55: test byte [rip+rel32], 1
                    // The rel32 at cave+57 was computed as: flag_target_va - (cave_va + 62)
                    // So cave_va = flag_target_va - rel32 - 62... but we don't know flag_target_va.
                    //
                    // Simpler: scan backward from cave for E9 XX XX XX XX where target = cave.
                    // The function entry has: E9 rel32 90 90 (7 bytes)
                    // rel32 = cave_va - (func_va + 5)
                    // So func_va = cave_va - rel32 - 5... but we need cave_va (host VA).
                    //
                    // Alternative: just dump the cave page to find the JMP pointing here.
                    // But let's use the approach: scan the page(s) before the cave for E9.
                    // Actually, the simplest: the cave is in hvix64 .text. The function could be
                    // anywhere. Let's just dump 7 bytes at a few candidate offsets.

                    // Report SLOT status
                    const bool slot1_ok = slot1_in_cave != 0;
                    const bool slot2_ok = slot2_in_cave != 0;
                    serial::print("[cavediag] SLOT1 "); serial::println(slot1_ok ? "SET" : "ZERO (inactive!)");
                    serial::print("[cavediag] SLOT2 "); serial::println(slot2_ok ? "SET" : "ZERO (no target!)");

                    // 4. Check first 2 bytes: should be 0x50 (push rax), 0x52 (push rdx)
                    const bool header_ok = (cave[0] == 0x50 && cave[1] == 0x52);
                    serial::print("[cavediag] header (50 52): ");
                    serial::print_byte_hex(cave[0]); serial::print(" ");
                    serial::print_byte_hex(cave[1]);
                    serial::println(header_ok ? " OK" : " MISMATCH!");

                    // Return combined status
                    trap_frame->rax = (header_ok ? 1 : 0) | (slot1_ok ? 2 : 0) | (slot2_ok ? 4 : 0);
                }
            }
            else
            {
                trap_frame->rax = 0;
            }
        }
        else if (hypercall_info.call_reserved_data == 33)
        {
            // sig_scan: RDX = guest VA of sig_scan_request_t
            // Returns: found VA in RAX (0 if not found)
            const cr3 slat_cr3 = slat::hyperv_cr3();
            const cr3 guest_cr3 = { .flags = cr3_intercept::target_original_cr3 };
            const std::uint64_t req_pa = memory_manager::translate_guest_virtual_address(
                guest_cr3, slat_cr3, { .address = trap_frame->rdx });

            if (!req_pa)
            {
                trap_frame->rax = 0;
            }
            else
            {
                const auto* page = static_cast<const std::uint8_t*>(
                    memory_manager::map_guest_physical(slat_cr3, req_pa & ~0xFFFull));
                const auto* req = reinterpret_cast<const sig_scan_request_t*>(
                    page + (req_pa & 0xFFF));

                std::uint64_t found = sig_scan_guest_pages(
                    req->scan_base_va, req->scan_size,
                    req->pattern, req->mask, req->pattern_len);

                // If resolve_call: match is an E8 CALL, resolve relative target
                if (found && req->resolve_call)
                {
                    // Read the 4-byte displacement after E8
                    const std::uint64_t disp_va = found + 1;
                    const std::uint64_t disp_pa = memory_manager::translate_guest_virtual_address(
                        guest_cr3, slat_cr3, { .address = disp_va });
                    if (disp_pa)
                    {
                        const auto* disp_page = static_cast<const std::uint8_t*>(
                            memory_manager::map_guest_physical(slat_cr3, disp_pa & ~0xFFFull));
                        const auto disp = *reinterpret_cast<const std::int32_t*>(
                            disp_page + (disp_pa & 0xFFF));
                        found = found + 5 + disp; // E8 xx xx xx xx → target = call_addr + 5 + disp
                    }
                    else
                    {
                        found = 0;
                    }
                }

                trap_frame->rax = found;
            }
        }
        else if (hypercall_info.call_reserved_data == 35)
        {
            // boot_hook_diag: returns packed boot hook state
            // RDX selects field: 0=packed_flags, 1=ntoskrnl_base, 2=fn_PsGetProcessImageFileName
            const std::uint64_t field = trap_frame->rdx;
            if (field == 0)
            {
                // bit 0: mmclean ctx.active
                // bit 1: armed
                // bit 2: fn_PsGetProcessImageFileName != 0
                // bit 3: hidden_pt_host_va != 0
                // bit 4: hidden_pml4e_flags != 0
                // bits 8..15: target_process_name[0]
                // bits 16..23: target_process_name[1..] (first 7 chars packed)
                std::uint64_t flags = 0;
                if (cr3_intercept::mmclean_hook::ctx.active) flags |= 1;
                if (cr3_intercept::cleanup_hook::armed) flags |= 2;
                if (cr3_intercept::cleanup_hook::fn_PsGetProcessImageFileName) flags |= 4;
                if (cr3_intercept::hidden_pt_host_va) flags |= 8;
                if (cr3_intercept::hidden_pml4e_flags) flags |= 16;
                // pack first 7 chars of target name into bits 8..63
                for (int i = 0; i < 7; i++)
                    flags |= static_cast<std::uint64_t>(
                        static_cast<std::uint8_t>(cr3_intercept::cleanup_hook::target_process_name[i]))
                        << (8 + i * 8);
                trap_frame->rax = flags;
            }
            else if (field == 1)
            {
                trap_frame->rax = cr3_intercept::cleanup_hook::ntoskrnl_base;
            }
            else if (field == 2)
            {
                trap_frame->rax = cr3_intercept::cleanup_hook::fn_PsGetProcessImageFileName;
            }
            else if (field == 3)
            {
                trap_frame->rax = cr3_intercept::cleanup_hook::hook_hit_count;
            }
            else if (field == 4)
            {
                trap_frame->rax = cr3_intercept::cleanup_hook::hook_match_count;
            }
            else if (field == 5)
            {
                trap_frame->rax = cr3_intercept::cleanup_hook::hook_entry_count;
            }
            else
            {
                trap_frame->rax = 0;
            }
        }
        else if (hypercall_info.call_reserved_data == 36)
        {
            // setup_mmaf_inline_hook: RDX=target_va, R8=clone_cr3, R9=packed(displaced|pml4_idx<<16)
            const std::uint32_t displaced = static_cast<std::uint32_t>(trap_frame->r9 & 0xFFFF);
            const std::uint8_t pml4_idx = static_cast<std::uint8_t>((trap_frame->r9 >> 16) & 0xFF);
            trap_frame->rax = setup_mmaf_inline_hook_impl(
                trap_frame->rdx, trap_frame->r8, displaced, pml4_idx);
        }
        else if (hypercall_info.call_reserved_data == 24)
        {
            // setup_exception_handler: RDX = kde_va (full 64-bit), R8 = packed_offsets
            // Direct hypercall — avoids relay encoding that truncates kernel VAs
            const cr3 slat_cr3 = slat::hyperv_cr3();
            trap_frame->rax = setup_exception_handler_impl(slat_cr3, trap_frame->rdx, trap_frame->r8);
        }
        else if (hypercall_info.call_reserved_data == 25)
        {
            // store_probe_stub_vas: RDX = copy_va, R8 = write_va
            // Called by controller after installing safe probe stubs
            cr3_intercept::exception_handler::probe_copy_va = trap_frame->rdx;
            cr3_intercept::exception_handler::probe_write_va = trap_frame->r8;
            trap_frame->rax = 1;
        }
        else if (hypercall_info.call_reserved_data == 26)
        {
            // setup_ki_page_fault_hook: RDX = kpf_va, R8 = packed_args
            const cr3 slat_cr3 = slat::hyperv_cr3();
            trap_frame->rax = setup_ki_page_fault_hook_impl(slat_cr3, trap_frame->rdx, trap_frame->r8);
        }
        else if (hypercall_info.call_reserved_data == 27)
        {
            // read_idt_handler: RDX = vector number → returns handler VA from guest IDT
            const std::uint8_t vector = static_cast<std::uint8_t>(trap_frame->rdx & 0xFF);
            const std::uint64_t idt_base = arch::get_guest_idtr_base();
            const std::uint64_t entry_va = idt_base + static_cast<std::uint64_t>(vector) * 16;

            // Translate IDT entry VA using current guest CR3
            const cr3 guest_cr3 = arch::get_guest_cr3();
            const cr3 slat_cr3 = slat::hyperv_cr3();
            const std::uint64_t entry_pa = memory_manager::translate_guest_virtual_address(
                guest_cr3, slat_cr3, { .address = entry_va });

            if (entry_pa == 0)
            {
                trap_frame->rax = 0;
            }
            else
            {
                const void* mapped = memory_manager::map_guest_physical(slat_cr3, entry_pa);
                if (mapped == nullptr)
                {
                    trap_frame->rax = 0;
                }
                else
                {
                    // IDT gate descriptor: offset[15:0] at +0, offset[31:16] at +6, offset[63:32] at +8
                    const auto* desc = static_cast<const std::uint8_t*>(mapped);
                    const std::uint64_t offset_low = *reinterpret_cast<const std::uint16_t*>(desc);
                    const std::uint64_t offset_mid = *reinterpret_cast<const std::uint16_t*>(desc + 6);
                    const std::uint64_t offset_high = *reinterpret_cast<const std::uint32_t*>(desc + 8);
                    trap_frame->rax = offset_low | (offset_mid << 16) | (offset_high << 32);
                }
            }
        }
        else if (hypercall_info.call_reserved_data == 21)
        {
            // exception_dispatch: KiDispatchException hook handler
            if (!cr3_intercept::exception_handler::active)
            {
                trap_frame->rax = 0;
            }
            else
            {
                namespace eh = cr3_intercept::exception_handler;
                const cr3 guest_cr3 = arch::get_guest_cr3();
                const cr3 slat_cr3 = slat::hyperv_cr3();
                const std::uint64_t ktf_va = trap_frame->r8; // KTRAP_FRAME ptr

                bool suppress = false;

                if (ktf_va != 0)
                {
                    // Read R10 first for quick magic check
                    std::uint64_t ktf_r10 = 0;
                    memory_manager::operate_on_guest_virtual_memory(
                        slat_cr3, &ktf_r10, ktf_va + eh::ktf_r10_offset,
                        guest_cr3, 8, memory_operation_t::read_operation);

                    if (ktf_r10 == 0x9EFABE87C1FE38E2ull)
                    {
                        // Range check: verify faulting RIP is in our probe stubs
                        std::uint64_t ktf_rip = 0;
                        memory_manager::operate_on_guest_virtual_memory(
                            slat_cr3, &ktf_rip, ktf_va + eh::ktf_rip_offset,
                            guest_cr3, 8, memory_operation_t::read_operation);

                        const bool in_copy = (eh::probe_copy_va != 0 &&
                            ktf_rip >= eh::probe_copy_va && ktf_rip < eh::probe_copy_va + 0x100);
                        const bool in_write = (eh::probe_write_va != 0 &&
                            ktf_rip >= eh::probe_write_va && ktf_rip < eh::probe_write_va + 0x100);

                        if (in_copy || in_write)
                        {
                            // Read RAX (instruction length) from KTRAP_FRAME
                            std::uint64_t ktf_rax = 0;
                            memory_manager::operate_on_guest_virtual_memory(
                                slat_cr3, &ktf_rax, ktf_va + eh::ktf_rax_offset,
                                guest_cr3, 8, memory_operation_t::read_operation);

                            // Advance faulting RIP past the faulting instruction
                            ktf_rip += (ktf_rax & 0xF);

                            // Write corrected RIP back
                            memory_manager::operate_on_guest_virtual_memory(
                                slat_cr3, &ktf_rip, ktf_va + eh::ktf_rip_offset,
                                guest_cr3, 8, memory_operation_t::write_operation);

                            // Signal to probe stub (R10 = 0x1337)
                            std::uint64_t signal = 0x1337;
                            memory_manager::operate_on_guest_virtual_memory(
                                slat_cr3, &signal, ktf_va + eh::ktf_r10_offset,
                                guest_cr3, 8, memory_operation_t::write_operation);

                            suppress = true;
                        }
                    }
                }

                if (suppress)
                {
                    // Suppress exception — return from KiDispatchException immediately
                    arch::set_guest_rip(eh::suppress_ret_va);
                }
                else
                {
                    // Passthrough — normal exception dispatch (don't touch RAX)
                    arch::set_guest_rip(eh::trampoline_va);
                }

                rip_redirected = true;
            }
        }
        else if (hypercall_info.call_reserved_data == 30)
        {
            // screenshot hook CPUID handler — called by kernel shellcode on NtGdiBitBlt/NtGdiStretchBlt
            const std::uint64_t sub_cmd = trap_frame->rdx;
            if (sub_cmd == 1) // blt_start
            {
                if (cr3_intercept::screenshot_hook::enabled && !cr3_intercept::screenshot_hook::blt_active)
                {
                    cr3_intercept::screenshot_hook::blt_ack = 0;
                    cr3_intercept::screenshot_hook::blt_active = 1;
                    cr3_intercept::screenshot_hook::blt_start_tsc = __rdtsc();
                    trap_frame->rax = 1;
                }
                else trap_frame->rax = 0;
            }
            else if (sub_cmd == 2) // blt_poll_ack
            {
                // Auto-timeout after ~2s (assuming ~3GHz TSC)
                if (cr3_intercept::screenshot_hook::blt_active &&
                    (__rdtsc() - cr3_intercept::screenshot_hook::blt_start_tsc) > 6'000'000'000ull)
                {
                    cr3_intercept::screenshot_hook::blt_ack = 1; // force ack on timeout
                }
                trap_frame->rax = cr3_intercept::screenshot_hook::blt_ack;
            }
            else if (sub_cmd == 3) // blt_clear
            {
                cr3_intercept::screenshot_hook::blt_active = 0;
                cr3_intercept::screenshot_hook::blt_ack = 0;
                trap_frame->rax = 1;
            }
            else if (sub_cmd == 4) // enable
            {
                cr3_intercept::screenshot_hook::enabled = 1;
                trap_frame->rax = 1;
            }
            else if (sub_cmd == 5) // disable + clear all
            {
                cr3_intercept::screenshot_hook::enabled = 0;
                cr3_intercept::screenshot_hook::blt_active = 0;
                cr3_intercept::screenshot_hook::blt_ack = 0;
                cr3_intercept::screenshot_hook::blt_start_tsc = 0;
                trap_frame->rax = 1;
            }
            else trap_frame->rax = 0;
        }
        else if (hypercall_info.call_reserved_data == 20)
        {
            // process_command: NtClose relay dispatcher
            // Encoding: RDX = (arg1 << 8) | cmd_byte
            //   KiSystemCall64 only saves RCX (via R10) and RDX to KTRAP_FRAME
            //   for syscalls with few args. R8/R9 are NOT saved reliably.
            //   So we pack cmd + arg1 into RDX. For 2-arg commands, arg2 is
            //   pre-stored via STORE_ARG (cmd 0xFE) call.
            // Per-VP storage: two threads on different LPs could race a shared static.
            // STORE_ARG on LP0 + STORE_ARG on LP1 + command on LP0 → wrong arg2.
            // NOTE: file-scope to avoid MSVC generating memset for function-local static init
            static std::uint64_t stored_relay_args[slat::mtf::max_contexts];
            const std::uint16_t relay_vpid = arch::get_current_vpid();
            const std::uint64_t raw_rdx = trap_frame->rdx;
            const std::uint64_t command_id = raw_rdx & 0xFF;
            const std::uint64_t arg1 = raw_rdx >> 8;
            const std::uint64_t arg2 = (relay_vpid < slat::mtf::max_contexts) ? stored_relay_args[relay_vpid] : 0;
            const cr3 slat_cr3_cmd = slat::hyperv_cr3();

            switch (command_id)
            {
            case 0: // ping
                trap_frame->rax = 0xC0DE;
                break;
            case 1: // shadow_guest_page(arg1=target_va)
                trap_frame->rax = shadow_guest_page_impl(slat_cr3_cmd, arg1);
                break;
            case 2: // unshadow_guest_page(arg1=target_va)
                trap_frame->rax = unshadow_guest_page_impl(slat_cr3_cmd, arg1);
                break;
            case 3: // read_original_page(arg1=source_va, arg2=dest_va)
                trap_frame->rax = read_original_page_impl(slat_cr3_cmd, arg1, arg2);
                break;
            case 4: // ept_hook_code(arg1=target_va, arg2=detour_va)
                trap_frame->rax = ept_hook_code_impl(slat_cr3_cmd, arg1, arg2);
                break;
            case 5: // ept_unhook_code(arg1=target_va)
                trap_frame->rax = ept_unhook_code_impl(slat_cr3_cmd, arg1);
                break;
            case 6: // alloc_hidden_page()
                trap_frame->rax = alloc_hidden_page_impl();
                break;
            case 7: // diag_ept_hook(arg1=target_va): re-translate VA, compare with hooked GPA, return diagnostic
            {
                // Returns packed result:
                //   bits [63:32] = diag_watch_pfn_exec_count (capped to 32 bits)
                //   bits [31:16] = diag_watch_pfn_rw_count (capped to 16 bits)
                //   bits [15:1]  = 0
                //   bit  [0]     = 1 if current GPA matches hooked GPA, 0 if mismatch
                const cr3 original_cr3 = { .flags = cr3_intercept::target_original_cr3 };
                const std::uint64_t current_pa = memory_manager::translate_guest_virtual_address(
                    original_cr3, slat_cr3_cmd, { .address = arg1 });
                const std::uint64_t current_pa_page = current_pa & ~0xFFFull;

                // Find the hooked GPA for this VA
                std::uint64_t gpa_match = 0;
                const auto* hook = cr3_intercept::find_usermode_ept_hook(current_pa_page);
                if (hook != nullptr)
                    gpa_match = 1;

                const std::uint64_t exec_count = cr3_intercept::diag_watch_pfn_exec_count;
                const std::uint64_t rw_count = cr3_intercept::diag_watch_pfn_rw_count;

                trap_frame->rax = ((exec_count & 0xFFFFFFFF) << 32)
                    | ((rw_count & 0xFFFF) << 16)
                    | gpa_match;
                break;
            }
            case 8: // diag_read_shadow(arg1=target_va): read first 8 bytes from shadow page at function offset
            {
                // Returns the first 8 bytes of the shadow page at the hooked offset
                // This lets the DLL verify the JMP bytes are present
                const cr3 original_cr3 = { .flags = cr3_intercept::target_original_cr3 };
                const std::uint64_t pa = memory_manager::translate_guest_virtual_address(
                    original_cr3, slat_cr3_cmd, { .address = arg1 });
                const std::uint64_t pa_page = pa & ~0xFFFull;
                const std::uint64_t offset = pa & 0xFFF;

                const auto* hook = cr3_intercept::find_usermode_ept_hook(pa_page);
                if (hook != nullptr && hook->shadow_heap_va != nullptr)
                {
                    const auto* shadow_bytes = static_cast<const std::uint8_t*>(hook->shadow_heap_va) + offset;
                    std::uint64_t result = 0;
                    crt::copy_memory(&result, shadow_bytes, 8);
                    trap_frame->rax = result;
                }
                else
                {
                    trap_frame->rax = 0;
                }
                break;
            }
            case 9: // diag_echo_args: return arg1 in low 32, arg2 in high 32 — tests KTRAP_FRAME offsets
            {
                // Pack: bits [63:32] = arg2 low 32 bits, bits [31:0] = arg1 low 32 bits
                trap_frame->rax = ((arg2 & 0xFFFFFFFF) << 32) | (arg1 & 0xFFFFFFFF);
                break;
            }
            case 10: // diag_translate_verbose(arg1=target_va): step-by-step page table walk diagnostic
            {
                // Returns packed result:
                //   bits [3:0]  = fail_level (0=cr3_not_set, 1=pml4_map, 2=pml4e_np, 3=pdpt_map, 4=pdpte_np,
                //                             5=pd_map, 6=pde_np, 7=pt_map, 8=pte_np, 0xF=success)
                //   bit  [4]    = large_page encountered
                //   bit  [5]    = heap_overlap (failing PA is in heap range)
                //   bits [7:6]  = reserved
                //   bits [63:8] = relevant PA >> 8 (GPA at failing level, or translated GPA on success)
                const cr3 original_cr3 = { .flags = cr3_intercept::target_original_cr3 };

                if (original_cr3.flags == 0)
                {
                    trap_frame->rax = 0; // fail_level=0: cr3 not set
                    break;
                }

                const std::uint64_t heap_base = heap_manager::initial_physical_base;
                const std::uint64_t heap_end = heap_base + heap_manager::initial_size;

                auto in_heap = [&](std::uint64_t pa) -> bool {
                    const std::uint64_t pa_page = pa & ~0xFFFull;
                    return pa_page >= heap_base && pa_page < heap_end;
                };

                const virtual_address_t va = { .address = arg1 };
                std::uint64_t result_pa = 0;
                std::uint64_t fail_level = 0;
                std::uint64_t large_page = 0;
                std::uint64_t heap_hit = 0;

                // Level 1: map PML4
                const std::uint64_t pml4_gpa = original_cr3.address_of_page_directory << 12;
                const auto pml4 = static_cast<const pml4e_64*>(
                    memory_manager::map_guest_physical(slat_cr3_cmd, pml4_gpa));
                if (pml4 == nullptr) {
                    fail_level = 1; result_pa = pml4_gpa;
                    heap_hit = in_heap(pml4_gpa) ? 1 : 0;
                } else {
                    const pml4e_64 pml4e = pml4[va.pml4_idx];
                    if (pml4e.present == 0) {
                        fail_level = 2; result_pa = pml4_gpa;
                    } else {
                        // Level 2: map PDPT
                        const std::uint64_t pdpt_gpa = pml4e.page_frame_number << 12;
                        const auto pdpt = static_cast<const pdpte_64*>(
                            memory_manager::map_guest_physical(slat_cr3_cmd, pdpt_gpa));
                        if (pdpt == nullptr) {
                            fail_level = 3; result_pa = pdpt_gpa;
                            heap_hit = in_heap(pdpt_gpa) ? 1 : 0;
                        } else {
                            const pdpte_64 pdpte = pdpt[va.pdpt_idx];
                            if (pdpte.present == 0) {
                                fail_level = 4; result_pa = pdpt_gpa;
                            } else if (pdpte.large_page == 1) {
                                fail_level = 0xF; large_page = 1;
                                const pdpte_1gb_64 lp = { .flags = pdpte.flags };
                                const std::uint64_t offset = (va.pd_idx << 21) + (va.pt_idx << 12) + va.offset;
                                result_pa = (lp.page_frame_number << 30) + offset;
                            } else {
                                // Level 3: map PD
                                const std::uint64_t pd_gpa = pdpte.page_frame_number << 12;
                                const auto pd = static_cast<const pde_64*>(
                                    memory_manager::map_guest_physical(slat_cr3_cmd, pd_gpa));
                                if (pd == nullptr) {
                                    fail_level = 5; result_pa = pd_gpa;
                                    heap_hit = in_heap(pd_gpa) ? 1 : 0;
                                } else {
                                    const pde_64 pde = pd[va.pd_idx];
                                    if (pde.present == 0) {
                                        fail_level = 6; result_pa = pd_gpa;
                                    } else if (pde.large_page == 1) {
                                        fail_level = 0xF; large_page = 1;
                                        const pde_2mb_64 lp = { .flags = pde.flags };
                                        const std::uint64_t offset = (va.pt_idx << 12) + va.offset;
                                        result_pa = (lp.page_frame_number << 21) + offset;
                                    } else {
                                        // Level 4: map PT
                                        const std::uint64_t pt_gpa = pde.page_frame_number << 12;
                                        const auto pt = static_cast<const pte_64*>(
                                            memory_manager::map_guest_physical(slat_cr3_cmd, pt_gpa));
                                        if (pt == nullptr) {
                                            fail_level = 7; result_pa = pt_gpa;
                                            heap_hit = in_heap(pt_gpa) ? 1 : 0;
                                        } else {
                                            const pte_64 pte = pt[va.pt_idx];
                                            if (pte.present == 0) {
                                                fail_level = 8; result_pa = pt_gpa;
                                            } else {
                                                fail_level = 0xF; // success
                                                result_pa = (pte.page_frame_number << 12) + va.offset;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Also check if the failing PA (page table page) is in heap range
                if (heap_hit == 0 && fail_level != 0xF && fail_level >= 2)
                    heap_hit = in_heap(result_pa) ? 1 : 0;

                trap_frame->rax = (result_pa & ~0xFFull) // bits [63:8] = PA >> 0 (aligned to 256)
                    | (heap_hit << 5)
                    | (large_page << 4)
                    | (fail_level & 0xF);
                break;
            }
            case 11: // diag_heap_info: return heap base and size for overlap checking
            {
                // arg1=0: return heap_base, arg1=1: return heap_end
                if (arg1 == 0)
                    trap_frame->rax = heap_manager::initial_physical_base;
                else
                    trap_frame->rax = heap_manager::initial_physical_base + heap_manager::initial_size;
                break;
            }
            case 0x0C: // screenshot_poll: return (blt_active << 1) | enabled
                trap_frame->rax = (static_cast<std::uint64_t>(cr3_intercept::screenshot_hook::blt_active) << 1)
                    | static_cast<std::uint64_t>(cr3_intercept::screenshot_hook::enabled);
                break;
            case 0x0D: // screenshot_ack: DLL acknowledged overlay hidden
                cr3_intercept::screenshot_hook::blt_ack = 1;
                trap_frame->rax = 1;
                break;
            case 0x0E: // screenshot_enable: enable screenshot hook feature
                cr3_intercept::screenshot_hook::enabled = 1;
                trap_frame->rax = 1;
                break;
            case 0x11: // get_probe_stub_va: arg1=0 → copy_va, arg1=1 → write_va
                if (arg1 == 0)
                    trap_frame->rax = cr3_intercept::exception_handler::probe_copy_va;
                else
                    trap_frame->rax = cr3_intercept::exception_handler::probe_write_va;
                break;
            case 0x0F: // screenshot_disable: disable and clear all screenshot hook state
                cr3_intercept::screenshot_hook::enabled = 0;
                cr3_intercept::screenshot_hook::blt_active = 0;
                cr3_intercept::screenshot_hook::blt_ack = 0;
                cr3_intercept::screenshot_hook::blt_start_tsc = 0;
                trap_frame->rax = 1;
                break;
            case 0xFE: // store_arg: pre-store arg1 for the next 2-arg command (per-VP)
                if (relay_vpid < slat::mtf::max_contexts)
                    stored_relay_args[relay_vpid] = arg1;
                trap_frame->rax = 1;
                break;
            default:
                trap_frame->rax = 0;
                break;
            }
        }
        else if (hypercall_info.call_reserved_data == 50)
        {
            // hookdiag: EPT hook diagnostic system.
            // RDX = field_index:
            //   0: hook_count | (shadow_code_initialized << 8) | (mmclean_active << 9) | (armed << 10)
            //   Per hook (base = 1 + hook_index * 8):
            //     +0: original_pfn
            //     +1: shadow_pfn (from hook_cr3 PTE) | (pte_read << 36) | (pte_write << 37) | (pte_exec << 38)
            //     +2: hook_byte_offset | (hook_byte_length << 12) | (shadow_code_page << 20) | (hook_byte_offset2 << 21) | (hook_byte_length2 << 33)
            //     +3: first 8 bytes of SHADOW page at hook_byte_offset
            //     +4: next 8 bytes of shadow (offset+8)
            //     +5: first 8 bytes of ORIGINAL page at hook_byte_offset
            //     +6: next 8 bytes of original (offset+8)
            //     +7: validation flags (bit 0=PTE is --X, bit 1=shadow!=original PFN, bit 2=shadow bytes differ from original)
            // Also dumps everything to serial when field=0 (full diagnostic pass).
            const std::uint64_t field = trap_frame->rdx;

            // Count hooks
            std::uint64_t hook_count = 0;
            slat::hook::entry_t* entries[32] = {};
            {
                auto* cur = slat::hook::used_hook_list_head;
                while (cur && hook_count < 32)
                {
                    entries[hook_count++] = cur;
                    cur = cur->next();
                }
            }

            if (field == 0)
            {
                // Field 0: summary + full serial dump
                serial::reinit();  // reclaim COM1 from VMX root (serial.sys may have reconfigured)
                serial::println("=== HOOKDIAG ===");
                serial::print("hook_count="); serial::print_dec(hook_count);
                serial::print(" shadow_code="); serial::print_dec(shadow_code::initialized ? 1 : 0);
                serial::print(" mmclean="); serial::print_dec(cr3_intercept::mmclean_hook::ctx.active ? 1 : 0);
                serial::print(" armed="); serial::print_dec(cr3_intercept::cleanup_hook::armed);
                serial::println("");

                for (std::uint64_t i = 0; i < hook_count; i++)
                {
                    const auto* e = entries[i];
                    const std::uint64_t orig_pfn = e->original_pfn();
                    const std::uint64_t off = e->hook_byte_offset();
                    const std::uint64_t len = e->hook_byte_length();

                    serial::print("--- Hook #"); serial::print_dec(i); serial::println(" ---");
                    serial::print("  original_pfn="); serial::print_hex(orig_pfn);
                    serial::print("  shadow_code_page="); serial::print_dec(e->shadow_code_page());
                    serial::print("  offset="); serial::print_hex(off);
                    serial::print("  length="); serial::print_dec(len); serial::println("");

                    // Read PTE from hook_cr3
                    const virtual_address_t gpa = { .address = orig_pfn << 12 };
                    slat_pte* pte = slat::get_pte(slat::hook_cr3(), gpa);
                    std::uint64_t shadow_pfn = 0;
                    std::uint8_t pte_r = 0, pte_w = 0, pte_x = 0;
                    if (pte)
                    {
                        shadow_pfn = pte->page_frame_number;
                        pte_r = pte->read_access;
                        pte_w = pte->write_access;
                        pte_x = pte->execute_access;
                    }
                    serial::print("  shadow_pfn="); serial::print_hex(shadow_pfn);
                    serial::print("  PTE: R="); serial::print_dec(pte_r);
                    serial::print(" W="); serial::print_dec(pte_w);
                    serial::print(" X="); serial::print_dec(pte_x);
                    const bool pte_ok = (pte_r == 0 && pte_w == 0 && pte_x == 1);
                    serial::print(pte_ok ? " [OK --X]" : " [FAIL expected --X]");
                    serial::println("");

                    // Map shadow and original pages, dump bytes at hook offset
                    const auto* shadow_page = static_cast<const std::uint8_t*>(
                        memory_manager::map_host_physical(shadow_pfn << 12));
                    const auto* original_page = static_cast<const std::uint8_t*>(
                        memory_manager::map_host_physical(orig_pfn << 12));

                    if (shadow_page && original_page && off < 0x1000)
                    {
                        const std::uint64_t dump_len = (off + 16 <= 0x1000) ? 16 : (0x1000 - off);
                        serial::print("  SHADOW : ");
                        for (std::uint64_t b = 0; b < dump_len; b++)
                        {
                            serial::print_byte_hex(shadow_page[off + b]);
                            serial::print(" ");
                        }
                        serial::println("");
                        serial::print("  ORIGINAL: ");
                        for (std::uint64_t b = 0; b < dump_len; b++)
                        {
                            serial::print_byte_hex(original_page[off + b]);
                            serial::print(" ");
                        }
                        serial::println("");

                        // Check if shadow differs from original at hook offset (should differ = our hook)
                        bool bytes_differ = false;
                        for (std::uint64_t b = 0; b < dump_len && !bytes_differ; b++)
                        {
                            if (shadow_page[off + b] != original_page[off + b])
                                bytes_differ = true;
                        }
                        serial::print("  bytes_differ="); serial::print_dec(bytes_differ ? 1 : 0);
                        serial::print(bytes_differ ? " [OK hook present]" : " [FAIL shadow == original, no hook?]");
                        serial::println("");
                    }
                }
                serial::println("=== END HOOKDIAG ===");

                trap_frame->rax = hook_count
                    | (static_cast<std::uint64_t>(shadow_code::initialized ? 1 : 0) << 8)
                    | (static_cast<std::uint64_t>(cr3_intercept::mmclean_hook::ctx.active ? 1 : 0) << 9)
                    | (static_cast<std::uint64_t>(cr3_intercept::cleanup_hook::armed) << 10);
            }
            else
            {
                // Per-hook field query
                const std::uint64_t hook_idx = (field - 1) / 8;
                const std::uint64_t sub_field = (field - 1) % 8;

                if (hook_idx >= hook_count)
                {
                    trap_frame->rax = 0;
                }
                else
                {
                    const auto* e = entries[hook_idx];
                    const std::uint64_t orig_pfn = e->original_pfn();
                    const std::uint64_t off = e->hook_byte_offset();

                    switch (sub_field)
                    {
                    case 0: // original_pfn
                        trap_frame->rax = orig_pfn;
                        break;
                    case 1: // shadow_pfn + PTE flags
                    {
                        const virtual_address_t gpa = { .address = orig_pfn << 12 };
                        slat_pte* pte = slat::get_pte(slat::hook_cr3(), gpa);
                        if (pte)
                            trap_frame->rax = pte->page_frame_number
                                | (static_cast<std::uint64_t>(pte->read_access) << 36)
                                | (static_cast<std::uint64_t>(pte->write_access) << 37)
                                | (static_cast<std::uint64_t>(pte->execute_access) << 38);
                        else
                            trap_frame->rax = 0;
                        break;
                    }
                    case 2: // hook metadata
                        trap_frame->rax = off
                            | (e->hook_byte_length() << 12)
                            | (e->shadow_code_page() << 20)
                            | (e->hook_byte_offset2() << 21)
                            | (e->hook_byte_length2() << 33);
                        break;
                    case 3: case 4: case 5: case 6:
                    {
                        // 3,4 = shadow bytes; 5,6 = original bytes
                        const bool is_shadow = (sub_field <= 4);
                        const std::uint64_t byte_off = off + ((sub_field == 4 || sub_field == 6) ? 8 : 0);
                        const std::uint64_t pfn = is_shadow ? 0 : orig_pfn;
                        const std::uint8_t* page = nullptr;
                        if (is_shadow)
                        {
                            const virtual_address_t gpa = { .address = orig_pfn << 12 };
                            slat_pte* pte = slat::get_pte(slat::hook_cr3(), gpa);
                            if (pte)
                                page = static_cast<const std::uint8_t*>(
                                    memory_manager::map_host_physical(pte->page_frame_number << 12));
                        }
                        else
                        {
                            page = static_cast<const std::uint8_t*>(
                                memory_manager::map_host_physical(orig_pfn << 12));
                        }
                        if (page && byte_off + 8 <= 0x1000)
                        {
                            std::uint64_t val = 0;
                            crt::copy_memory(&val, page + byte_off, 8);
                            trap_frame->rax = val;
                        }
                        else trap_frame->rax = 0;
                        break;
                    }
                    case 7: // validation flags
                    {
                        std::uint64_t flags = 0;
                        const virtual_address_t gpa = { .address = orig_pfn << 12 };
                        slat_pte* pte = slat::get_pte(slat::hook_cr3(), gpa);
                        if (pte)
                        {
                            if (pte->read_access == 0 && pte->write_access == 0 && pte->execute_access == 1)
                                flags |= 1; // PTE is --X
                            if (pte->page_frame_number != orig_pfn)
                                flags |= 2; // shadow != original PFN
                        }
                        // Check bytes differ
                        if (pte)
                        {
                            const auto* sp = static_cast<const std::uint8_t*>(
                                memory_manager::map_host_physical(pte->page_frame_number << 12));
                            const auto* op = static_cast<const std::uint8_t*>(
                                memory_manager::map_host_physical(orig_pfn << 12));
                            if (sp && op && off < 0x1000)
                            {
                                for (std::uint64_t b = 0; b < 16 && off + b < 0x1000; b++)
                                {
                                    if (sp[off + b] != op[off + b]) { flags |= 4; break; }
                                }
                            }
                        }
                        trap_frame->rax = flags;
                        break;
                    }
                    default:
                        trap_frame->rax = 0;
                        break;
                    }
                }
            }
        }
        else
        {
            const cr3 guest_cr3 = arch::get_guest_cr3();
            trap_frame->rax = guest_cr3.flags;
        }

        break;
    }
    case hypercall_type_t::add_slat_code_hook:
    {
        const virtual_address_t target_guest_physical_address = { .address = trap_frame->rdx };
        const virtual_address_t shadow_page_guest_physical_address = { .address = trap_frame->r8 };

        trap_frame->rax = slat::hook::add(target_guest_physical_address, shadow_page_guest_physical_address);

        break;
    }
    case hypercall_type_t::remove_slat_code_hook:
    {
        const virtual_address_t target_guest_physical_address = { .address = trap_frame->rdx };

        trap_frame->rax = slat::hook::remove(target_guest_physical_address);

        break;
    }
    case hypercall_type_t::hide_guest_physical_page:
    {
        const virtual_address_t target_guest_physical_address = { .address = trap_frame->rdx };

        trap_frame->rax = slat::hide_physical_page_from_guest(target_guest_physical_address);

        break;
    }
    case hypercall_type_t::log_current_state:
    {
        trap_frame_log_t trap_frame_log;

        crt::copy_memory(&trap_frame_log, trap_frame, sizeof(trap_frame_t));

        log_current_state(trap_frame_log);

        break;
    }
    case hypercall_type_t::flush_logs:
    {
        trap_frame->rax = flush_logs(trap_frame);

        break;
    }
    case hypercall_type_t::get_heap_free_page_count:
    {
        trap_frame->rax = heap_manager::get_free_page_count();

        break;
    }
    case hypercall_type_t::monitor_physical_page:
    {
        const virtual_address_t target_guest_physical_address = { .address = trap_frame->rdx };

        trap_frame->rax = slat::monitor::add(target_guest_physical_address);

        break;
    }
    case hypercall_type_t::unmonitor_physical_page:
    {
        const virtual_address_t target_guest_physical_address = { .address = trap_frame->rdx };

        trap_frame->rax = slat::monitor::remove(target_guest_physical_address);

        break;
    }
    case hypercall_type_t::write_guest_cr3:
    {
        // Used by MmAccessFault EPT hook shellcode + debug CLI (wcr3)
        cr3_intercept::mmaf_hit_count++;

        const cr3 new_guest_cr3 = { .flags = trap_frame->rdx };
        arch::set_guest_cr3(new_guest_cr3);
        arch::invalidate_vpid_current();
        trap_frame->rax = 1;
        break;
    }
    case hypercall_type_t::clone_guest_cr3:
    {
        if (hypercall_info.call_reserved_data == 1)
        {
            // setup_hidden_region: allocate PDPT + PD + PT, build hierarchy, insert into clone PML4
            const std::uint64_t pml4_index = trap_frame->rdx;

            // Block index 255 (attachment identity map) and kernel-half indices (256-511)
            if (pml4_index >= 256 || cr3_intercept::cloned_pml4_host_va == nullptr)
            {
                trap_frame->rax = 0;
                break;
            }

            // If boot already set up hidden region with same index, just return base VA
            if (cr3_intercept::hidden_pt_host_va != nullptr)
            {
                if (cr3_intercept::reserved_pml4e_index == pml4_index)
                {
                    // Ensure PML4E is written into clone (boot skipped this — no clone yet)
                    auto* const cloned_pml4 = static_cast<pml4e_64*>(cr3_intercept::cloned_pml4_host_va);
                    if (cr3_intercept::hidden_pml4e_flags != 0)
                        cloned_pml4[pml4_index].flags = cr3_intercept::hidden_pml4e_flags;

                    // Unhide boot-time PDPT/PD/PT pages in hook_cr3.
                    // These are heap pages allocated in setup_hidden_region_boot() before
                    // hook_cr3 existed. hide_heap_pages(hook_cr3) later hid them.
                    // Without this, guest CPU page walks through clone CR3 hit EPT
                    // violations on hidden intermediate pages → crash.
                    const cr3 hook = slat::hook_cr3();
                    if (hook.flags != 0)
                    {
                        const std::uint64_t pdpt_pa = cr3_intercept::hidden_pml4e_flags & 0xFFFFFFFFF000ull;
                        const auto* pdpt = static_cast<const pdpte_64*>(memory_manager::map_host_physical(pdpt_pa));
                        const std::uint64_t pd_pa = pdpt[0].page_frame_number << 12;
                        const auto* pd = static_cast<const pde_64*>(memory_manager::map_host_physical(pd_pa));
                        const std::uint64_t pt_pa = pd[0].page_frame_number << 12;

                        auto unhide_in_hook = [&](std::uint64_t pa) {
                            std::uint8_t ss = 0;
                            slat_pte* pte = slat::fork_get_pte(hook, slat::hyperv_cr3(), { .address = pa }, 1, &ss);
                            if (pte)
                            {
                                pte->page_frame_number = pa >> 12;
                                pte->read_access = 1;
                                pte->write_access = 1;
                                pte->execute_access = 1;
#ifdef _INTELMACHINE
                                pte->user_mode_execute = 1;
#endif
                            }
                        };
                        unhide_in_hook(pdpt_pa);
                        unhide_in_hook(pd_pa);
                        unhide_in_hook(pt_pa);

                        slat::flush_all_logical_processors_cache();
                    }

                    trap_frame->rax = pml4_index << 39;
                }
                else
                {
                    trap_frame->rax = 0;
                }
                break;
            }

            const cr3 hook = slat::hook_cr3();

            // allocate 3 pages: PDPT, PD, PT
            void* const pdpt_va = heap_manager::allocate_page();
            void* const pd_va = heap_manager::allocate_page();
            void* const pt_va = heap_manager::allocate_page();

            if (pdpt_va == nullptr || pd_va == nullptr || pt_va == nullptr)
            {
                if (pdpt_va) heap_manager::free_page(pdpt_va);
                if (pd_va) heap_manager::free_page(pd_va);
                if (pt_va) heap_manager::free_page(pt_va);
                trap_frame->rax = 0;
                break;
            }

            // zero all 3 pages
            crt::set_memory(pdpt_va, 0, 0x1000);
            crt::set_memory(pd_va, 0, 0x1000);
            crt::set_memory(pt_va, 0, 0x1000);

            // get physical addresses
            const std::uint64_t pdpt_pa = memory_manager::unmap_host_physical(pdpt_va);
            const std::uint64_t pd_pa = memory_manager::unmap_host_physical(pd_va);
            const std::uint64_t pt_pa = memory_manager::unmap_host_physical(pt_va);

            // DO NOT unhide in hyperv_cr3 — heap pages accessible via 2MB identity map.
            // Only unhide in hook_cr3 (our private EPT copy).
            auto unhide_hook = [&](std::uint64_t pa)
            {
                if (hook.flags != 0)
                {
                    std::uint8_t ss = 0;
                    slat_pte* const pte_hook = slat::fork_get_pte(hook, slat::hyperv_cr3(), { .address = pa }, 1, &ss);
                    if (pte_hook != nullptr)
                    {
                        pte_hook->page_frame_number = pa >> 12;
                        pte_hook->read_access = 1;
                        pte_hook->write_access = 1;
                        pte_hook->execute_access = 1;
#ifdef _INTELMACHINE
                        pte_hook->user_mode_execute = 1;
#endif
                    }
                }
            };

            unhide_hook(pdpt_pa);
            unhide_hook(pd_pa);
            unhide_hook(pt_pa);

            // build page table hierarchy: PDPT[0] -> PD, PD[0] -> PT
            // flags: present=1, write=1, supervisor=1 (usermode accessible) = 0x7
            auto* const pdpt = static_cast<pdpte_64*>(pdpt_va);
            pdpt[0].flags = (pd_pa & 0xFFFFFFFFF000ull) | 0x7;

            auto* const pd = static_cast<pde_64*>(pd_va);
            pd[0].flags = (pt_pa & 0xFFFFFFFFF000ull) | 0x7;

            // store state — set reserved index BEFORE writing PML4E to prevent
            // sync_page_tables on another VCPU from overwriting our entry
            cr3_intercept::reserved_pml4e_index = pml4_index;
            cr3_intercept::hidden_pt_host_va = pt_va;

            // set clone PML4[pml4_index] -> PDPT
            // Save for sync_page_tables BEFORE writing PML4E to avoid race with sync on another VCPU
            auto* const cloned_pml4 = static_cast<pml4e_64*>(cr3_intercept::cloned_pml4_host_va);
            cr3_intercept::hidden_pml4e_flags = (pdpt_pa & 0xFFFFFFFFF000ull) | 0x7;
            cloned_pml4[pml4_index].flags = cr3_intercept::hidden_pml4e_flags;

            slat::flush_all_logical_processors_cache();

            // return the base VA for this PML4 index
            trap_frame->rax = pml4_index << 39;

            break;
        }
        else if (hypercall_info.call_reserved_data == 2)
        {
            // map_hidden_page: allocate a data page, insert into PT[page_index]
            const std::uint64_t page_index = trap_frame->rdx;

            if (page_index >= 512 || cr3_intercept::hidden_pt_host_va == nullptr)
            {
                trap_frame->rax = 0;
                break;
            }

            // check if this PT slot is already mapped
            const auto* const pt_check = static_cast<const pte_64*>(cr3_intercept::hidden_pt_host_va);
            if (pt_check[page_index].present)
            {
                trap_frame->rax = 0;
                break;
            }

            const cr3 slat_cr3 = slat::hyperv_cr3();
            const cr3 hook = slat::hook_cr3();

            void* const data_page_va = heap_manager::allocate_page();

            if (data_page_va == nullptr)
            {
                trap_frame->rax = 0;
                break;
            }

            crt::set_memory(data_page_va, 0, 0x1000);

            const std::uint64_t data_pa = memory_manager::unmap_host_physical(data_page_va);

            // DO NOT unhide in hyperv_cr3 — accessible via 2MB identity map.
            // Only unhide in hook_cr3.
            if (hook.flags != 0)
            {
                std::uint8_t ss_4547 = 0;
                slat_pte* const pte_hook = slat::fork_get_pte(hook, slat::hyperv_cr3(), { .address = data_pa }, 1, &ss_4547);
                if (pte_hook != nullptr)
                {
                    pte_hook->page_frame_number = data_pa >> 12;
                    pte_hook->read_access = 1;
                    pte_hook->write_access = 1;
                    pte_hook->execute_access = 1;
#ifdef _INTELMACHINE
                    pte_hook->user_mode_execute = 1;
#endif
                }
            }

            // set PT[page_index] -> data page
            // flags: present=1, write=1, supervisor=1 (usermode accessible) = 0x7
            auto* const pt = static_cast<pte_64*>(cr3_intercept::hidden_pt_host_va);
            pt[page_index].flags = (data_pa & 0xFFFFFFFFF000ull) | 0x7;

            slat::flush_all_logical_processors_cache();

            // return the physical address of the data page
            trap_frame->rax = data_pa;

            break;
        }
        else if (hypercall_info.call_reserved_data == 3)
        {
            // set_user_cr3: register UserDTB PFN for MOV CR3 interception.
            // CR3 intercept swaps to clone (which has PML4[reserved_index]) atomically.
            cr3_intercept::target_user_cr3 = trap_frame->rdx;
            trap_frame->rax = 1;
            break;
        }
        else if (hypercall_info.call_reserved_data == 4)
        {
            // clear_user_cr3: stop intercepting UserDTB MOV CR3
            cr3_intercept::target_user_cr3 = 0;
            trap_frame->rax = 1;
            break;
        }
        else if (hypercall_info.call_reserved_data == 5)
        {
            // shadow_guest_page: remap a 4KB page under clone CR3
            // RDX = target guest VA
            // Returns: shadow page GPA on success, 0 on failure
            const cr3 slat_cr3 = slat::hyperv_cr3();
            trap_frame->rax = shadow_guest_page_impl(slat_cr3, trap_frame->rdx);
            break;
        }
        else if (hypercall_info.call_reserved_data == 6)
        {
            // unshadow_guest_page: restore original PFN for a shadowed page
            // RDX = target guest VA
            // Returns: 1 on success, 0 on failure
            const cr3 slat_cr3 = slat::hyperv_cr3();
            trap_frame->rax = unshadow_guest_page_impl(slat_cr3, trap_frame->rdx);
            break;
        }
        else if (hypercall_info.call_reserved_data == 38)
        {
            // WriteCloneVirtualMemory: external stealth write into clone CR3
            // RDX = dest_va (in target), R8 = source_va (in caller), R9 = size
            // Returns: bytes written
            trap_frame->rax = WriteCloneVirtualMemory_impl(trap_frame);
            break;
        }
        else if (hypercall_info.call_reserved_data == 39)
        {
            // ReadCloneVirtualMemory: read what the target sees via clone CR3
            // RDX = source_va (in target), R8 = dest_va (in caller), R9 = size
            // Returns: bytes read
            trap_frame->rax = ReadCloneVirtualMemory_impl(trap_frame);
            break;
        }

        // call_reserved_data == 0: existing clone behavior
        const cr3 target_cr3 = { .flags = trap_frame->rdx };
        const cr3 slat_cr3 = slat::hyperv_cr3();

        // allocate a page from heap for the cloned PML4
        void* const new_pml4_page = heap_manager::allocate_page();

        if (new_pml4_page == nullptr)
        {
            trap_frame->rax = 0;
            break;
        }

        const std::uint64_t new_pml4_hpa = memory_manager::unmap_host_physical(new_pml4_page);

        // map the target CR3's PML4 via guest physical memory
        const auto target_pml4 = static_cast<const std::uint8_t*>(
            memory_manager::map_guest_physical(slat_cr3, target_cr3.address_of_page_directory << 12));

        if (target_pml4 == nullptr)
        {
            heap_manager::free_page(new_pml4_page);
            trap_frame->rax = 0;
            break;
        }

        // copy all 512 PML4 entries
        crt::copy_memory(new_pml4_page, target_pml4, 0x1000);

        // DO NOT unhide in hyperv_cr3 — clone PML4 heap page is already accessible
        // via Hyper-V's 2MB identity-mapped EPT large pages. Splitting those pages
        // modifies hyperv_cr3's EPT structure → HyperGuard PAGE_HASH_MISMATCH.
        // Only unhide in hook_cr3 (our private EPT copy).
        const cr3 hook = slat::hook_cr3();

        if (hook.flags != 0)
        {
            std::uint8_t ss_4659 = 0;
            slat_pte* const pte_hook = slat::fork_get_pte(hook, slat::hyperv_cr3(), { .address = new_pml4_hpa }, 1, &ss_4659);

            if (pte_hook != nullptr)
            {
                pte_hook->page_frame_number = new_pml4_hpa >> 12;
            }
        }

        slat::flush_all_logical_processors_cache();

        // return the cloned CR3: same flags as target but with our new PML4 PFN
        cr3 cloned_cr3 = target_cr3;
        cloned_cr3.address_of_page_directory = new_pml4_hpa >> 12;

        trap_frame->rax = cloned_cr3.flags;

        break;
    }
    case hypercall_type_t::enable_cr3_intercept:
    {
        const std::uint64_t target_cr3_value = trap_frame->rdx;
        const std::uint64_t cloned_cr3_value = trap_frame->r8;

        const cr3 cloned = { .flags = cloned_cr3_value };
        const std::uint64_t cloned_pml4_hpa = cloned.address_of_page_directory << 12;

        cr3_intercept::cloned_pml4_host_va = memory_manager::map_host_physical(cloned_pml4_hpa);
        cr3_intercept::target_original_cr3 = target_cr3_value;
        cr3_intercept::cloned_cr3_value = cloned_cr3_value;

        // preserve reserved_pml4e_index if hidden region was already setup
        if (cr3_intercept::hidden_pt_host_va == nullptr)
            cr3_intercept::reserved_pml4e_index = 512;

        // initial sync of page tables
        cr3_intercept::sync_page_tables(target_cr3_value);

        // set enabled — CR3 load exiting swaps to clone atomically on MOV CR3
        cr3_intercept::enabled = 1;

        // flush SLAT on all VCPUs
        interrupts::set_all_nmi_ready();
        interrupts::send_nmi_all_but_self();

        // if current guest CR3 matches target, swap immediately
        const cr3 current_guest_cr3 = arch::get_guest_cr3();

        if ((current_guest_cr3.flags & cr3_intercept::cr3_pfn_mask) == (target_cr3_value & cr3_intercept::cr3_pfn_mask))
        {
            arch::set_guest_cr3({ .flags = cloned_cr3_value });
            arch::invalidate_vpid_current();
        }

        trap_frame->rax = 1;

        break;
    }
    case hypercall_type_t::disable_cr3_intercept:
    {
        // perform_process_cleanup() atomically checks enabled and returns early if already 0
        perform_process_cleanup();
        trap_frame->rax = 1;

        break;
    }
    default:
        break;
    }

    return rip_redirected;
}
