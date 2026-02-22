#include "hypercall.h"
#include "../memory_manager/memory_manager.h"
#include "../memory_manager/heap_manager.h"

#include "../slat/slat.h"
#include "../slat/cr3/cr3.h"
#include "../slat/cr3/pte.h"
#include "../slat/hook/hook.h"
#include "../slat/monitor/monitor.h"

#include "../arch/arch.h"
#include "../logs/logs.h"
#include "../crt/crt.h"
#include "../cr3_intercept.h"
#include "../interrupts/interrupts.h"

#include <ia32-doc/ia32.hpp>
#include <hypercall/hypercall_def.h>
#include <intrin.h>

//=============================================================================
// Shadow guest page helpers
//=============================================================================

// Set RWX on a physical page in both EPT roots (hyperv + hook)
void unhide_physical_page(const cr3& slat_cr3, std::uint64_t pa)
{
    auto set_rwx = [](slat_pte* pte, std::uint64_t pa) {
        if (!pte) return;
        pte->page_frame_number = pa >> 12;
        pte->read_access = 1;
        pte->write_access = 1;
        pte->execute_access = 1;
    };
    set_rwx(slat::get_pte(slat_cr3, { .address = pa }, 1), pa);
    const cr3 hook = slat::hook_cr3();
    if (hook.flags != 0)
        set_rwx(slat::get_pte(hook, { .address = pa }, 1), pa);
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

    // 4. Check not already hooked
    if (cr3_intercept::find_usermode_ept_hook(target_pa_page) != nullptr)
        return 0xE4;

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
    if (slat::hook::add({ .address = target_pa_page }, { .address = shadow_pa }) == 0)
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

    // 3. Get PA, unhide in EPT (RWX + user_mode_execute)
    const std::uint64_t data_pa = memory_manager::unmap_host_physical(page_va);
    const cr3 slat_cr3 = slat::hyperv_cr3();
    const cr3 hook = slat::hook_cr3();

    auto unhide_ume = [&](const cr3& ept_root) {
        slat_pte* const pte = slat::get_pte(ept_root, { .address = data_pa }, 1);
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
    };

    unhide_ume(slat_cr3);
    if (hook.flags != 0)
        unhide_ume(hook);

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
                        for (int i = 0; i < 512; i++)
                        {
                            if (pt[i].present)
                            {
                                void* data_va = memory_manager::map_host_physical(pt[i].page_frame_number << 12);
                                if (data_va) heap_manager::free_page(data_va);
                            }
                        }
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

    std::uint64_t stack_data[stack_data_count] = { };

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

void hypercall::process(const hypercall_info_t hypercall_info, trap_frame_t* const trap_frame)
{
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
        else if (hypercall_info.call_reserved_data == 4)
        {
            // enable enforce: force clone CR3 at every VM exit
            cr3_intercept::enforce_active = 1;

            // immediately swap if needed
            const cr3 current = arch::get_guest_cr3();
            if ((current.flags & cr3_intercept::cr3_pfn_mask) == (cr3_intercept::target_original_cr3 & cr3_intercept::cr3_pfn_mask))
            {
                arch::set_guest_cr3({ .flags = cr3_intercept::cloned_cr3_value });
                arch::invalidate_vpid_current();
            }

            trap_frame->rax = 1;
        }
        else if (hypercall_info.call_reserved_data == 5)
        {
            // disable enforce
            cr3_intercept::enforce_active = 0;
            trap_frame->rax = 1;
        }
        else if (hypercall_info.call_reserved_data == 6)
        {
            trap_frame->rax = cr3_intercept::mmaf_hit_count;
        }
        else if (hypercall_info.call_reserved_data == 11)
        {
            trap_frame->rax = cr3_intercept::slat_violation_count;
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
        else if (hypercall_info.call_reserved_data == 20)
        {
            // process_command: NtClose relay dispatcher
            // Encoding: RDX = (arg1 << 8) | cmd_byte
            //   KiSystemCall64 only saves RCX (via R10) and RDX to KTRAP_FRAME
            //   for syscalls with few args. R8/R9 are NOT saved reliably.
            //   So we pack cmd + arg1 into RDX. For 2-arg commands, arg2 is
            //   pre-stored via STORE_ARG (cmd 0xFE) call.
            static std::uint64_t stored_relay_arg = 0;
            const std::uint64_t raw_rdx = trap_frame->rdx;
            const std::uint64_t command_id = raw_rdx & 0xFF;
            const std::uint64_t arg1 = raw_rdx >> 8;
            const std::uint64_t arg2 = stored_relay_arg;
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
            case 0xFE: // store_arg: pre-store arg1 for the next 2-arg command
                stored_relay_arg = arg1;
                trap_frame->rax = 1;
                break;
            default:
                trap_frame->rax = 0;
                break;
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

            if (pml4_index >= 512 || cr3_intercept::cloned_pml4_host_va == nullptr || cr3_intercept::hidden_pt_host_va != nullptr)
            {
                trap_frame->rax = 0;
                break;
            }

            const cr3 slat_cr3 = slat::hyperv_cr3();
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

            // un-hide all 3 pages in EPT — must set RWX bits for guest access
            auto unhide = [&](std::uint64_t pa)
            {
                slat_pte* const pte = slat::get_pte(slat_cr3, { .address = pa }, 1);
                if (pte != nullptr)
                {
                    pte->page_frame_number = pa >> 12;
                    pte->read_access = 1;
                    pte->write_access = 1;
                    pte->execute_access = 1;
#ifdef _INTELMACHINE
                    pte->user_mode_execute = 1;
#endif
                }

                if (hook.flags != 0)
                {
                    slat_pte* const pte_hook = slat::get_pte(hook, { .address = pa }, 1);
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

            unhide(pdpt_pa);
            unhide(pd_pa);
            unhide(pt_pa);

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

            // un-hide in EPT — must set RWX bits for guest CPU access
            slat_pte* const pte_hyperv = slat::get_pte(slat_cr3, { .address = data_pa }, 1);
            if (pte_hyperv != nullptr)
            {
                pte_hyperv->page_frame_number = data_pa >> 12;
                pte_hyperv->read_access = 1;
                pte_hyperv->write_access = 1;
                pte_hyperv->execute_access = 1;
#ifdef _INTELMACHINE
                pte_hyperv->user_mode_execute = 1;
#endif
            }

            if (hook.flags != 0)
            {
                slat_pte* const pte_hook = slat::get_pte(hook, { .address = data_pa }, 1);
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
            // set_user_cr3: register UserDTB PFN for MOV CR3 interception only.
            // No PML4 patching — MmAccessFault EPT hook handles #PF on PML4[reserved_index].
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

        // un-hide this page in the hyperv EPT so the CPU page walker can access it
        // heap pages are identity-mapped (GPA == HPA) but hidden after init
        slat_pte* const pte_hyperv = slat::get_pte(slat_cr3, { .address = new_pml4_hpa }, 1);

        if (pte_hyperv != nullptr)
        {
            pte_hyperv->page_frame_number = new_pml4_hpa >> 12;
        }

        // also un-hide in hook EPT if it's been initialized
        const cr3 hook = slat::hook_cr3();

        if (hook.flags != 0)
        {
            slat_pte* const pte_hook = slat::get_pte(hook, { .address = new_pml4_hpa }, 1);

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

        // set enabled (no CR3 exiting — rely on MmAccessFault EPT hook for CR3 swap)
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
        if (cr3_intercept::enabled == 0)
        {
            trap_frame->rax = 0;
            break;
        }

        // disable intercept flag first (other VCPUs will see this immediately)
        cr3_intercept::enabled = 0;
        cr3_intercept::enforce_active = 0;

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

        // remove all usermode EPT hooks before freeing clone pages
        for (int i = 0; i < cr3_intercept::usermode_ept_hook_count; i++)
        {
            slat::hook::remove({ .address = cr3_intercept::usermode_ept_hooks[i].target_pa_page });
            heap_manager::free_page(cr3_intercept::usermode_ept_hooks[i].shadow_heap_va);
        }
        cr3_intercept::usermode_ept_hook_count = 0;

        // free all heap pages (hidden region, shadow pages, cloned PML4)
        free_clone_pages();

        // clear state
        cr3_intercept::target_original_cr3 = 0;
        cr3_intercept::target_user_cr3 = 0;
        cr3_intercept::cloned_cr3_value = 0;
        cr3_intercept::cloned_pml4_host_va = nullptr;
        cr3_intercept::hidden_pt_host_va = nullptr;
        cr3_intercept::reserved_pml4e_index = 512;
        cr3_intercept::shadow_pdpt_count = 0;
        cr3_intercept::shadow_pd_count = 0;
        cr3_intercept::shadow_pt_count = 0;
        cr3_intercept::shadow_leaf_count = 0;
        cr3_intercept::hidden_pml4e_flags = 0;
        cr3_intercept::syscall_hijack_armed = 0;
        cr3_intercept::syscall_hijack_shellcode_va = 0;
        cr3_intercept::syscall_hijack_rip_offset = 0;

        trap_frame->rax = 1;

        break;
    }
    default:
        break;
    }
}
