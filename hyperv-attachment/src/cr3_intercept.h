#pragma once
#include <cstdint>
#include <ia32-doc/ia32.hpp>
#include <structures/trap_frame.h>
#include "memory_manager/memory_manager.h"
#include "slat/slat.h"
#include "crt/crt.h"

namespace cr3_intercept
{
	// compare only PFN (bits 39:12), ignore PCID (bits 11:0) and reserved/noflush (bits 63:40)
	constexpr std::uint64_t cr3_pfn_mask = 0xFFFFFFFFF000ull;

	inline std::uint8_t enabled = 0;
	inline std::uint64_t cr3_exit_count = 0;
	inline std::uint64_t cr3_swap_count = 0;
	inline std::uint64_t cr3_last_seen = 0;
	inline std::uint64_t slat_violation_count = 0; // total EPT violations entering violation::process()
	inline std::uint64_t mmaf_hit_count = 0; // incremented each time write_guest_cr3 hypercall fires (from MmAccessFault hook)
	inline std::uint64_t target_original_cr3 = 0;
	inline std::uint64_t cloned_cr3_value = 0;
	inline void* cloned_pml4_host_va = nullptr;
	inline std::uint64_t reserved_pml4e_index = 0;
	inline void* hidden_pt_host_va = nullptr;
	inline std::uint64_t target_user_cr3 = 0; // UserDirectoryTableBase value

	// Shadow registry — tracks cloned intermediate pages and shadow leaves
	struct shadow_pdpt_t {
		std::uint16_t pml4_idx;
		std::uint64_t cloned_pa;
	};

	struct shadow_pd_t {
		std::uint16_t pml4_idx;
		std::uint16_t pdpt_idx;
		std::uint64_t cloned_pa;
	};

	struct shadow_pt_t {
		std::uint16_t pml4_idx;
		std::uint16_t pdpt_idx;
		std::uint16_t pd_idx;
		std::uint64_t cloned_pa;
	};

	struct shadow_leaf_t {
		std::uint16_t pml4_idx;
		std::uint16_t pdpt_idx;
		std::uint16_t pd_idx;
		std::uint16_t pt_idx;
		std::uint64_t shadow_pa;
		std::uint64_t saved_pte_flags;
	};

	constexpr int max_shadow_pdpts  = 8;
	constexpr int max_shadow_pds    = 32;
	constexpr int max_shadow_pts    = 64;
	constexpr int max_shadow_leaves = 256;

	inline shadow_pdpt_t shadow_pdpts[max_shadow_pdpts] = {};
	inline int shadow_pdpt_count = 0;

	inline shadow_pd_t shadow_pds[max_shadow_pds] = {};
	inline int shadow_pd_count = 0;

	inline shadow_pt_t shadow_pts[max_shadow_pts] = {};
	inline int shadow_pt_count = 0;

	inline shadow_leaf_t shadow_leaves[max_shadow_leaves] = {};
	inline int shadow_leaf_count = 0;

	inline std::uint64_t hidden_pml4e_flags = 0;

	inline shadow_pdpt_t* find_shadow_pdpt(std::uint16_t pml4_idx)
	{
		for (int i = 0; i < shadow_pdpt_count; i++)
			if (shadow_pdpts[i].pml4_idx == pml4_idx) return &shadow_pdpts[i];
		return nullptr;
	}

	inline shadow_pd_t* find_shadow_pd(std::uint16_t pml4_idx, std::uint16_t pdpt_idx)
	{
		for (int i = 0; i < shadow_pd_count; i++)
			if (shadow_pds[i].pml4_idx == pml4_idx && shadow_pds[i].pdpt_idx == pdpt_idx) return &shadow_pds[i];
		return nullptr;
	}

	inline shadow_pt_t* find_shadow_pt(std::uint16_t pml4_idx, std::uint16_t pdpt_idx, std::uint16_t pd_idx)
	{
		for (int i = 0; i < shadow_pt_count; i++)
			if (shadow_pts[i].pml4_idx == pml4_idx && shadow_pts[i].pdpt_idx == pdpt_idx && shadow_pts[i].pd_idx == pd_idx) return &shadow_pts[i];
		return nullptr;
	}

	inline shadow_leaf_t* find_shadow_leaf(std::uint16_t pml4_idx, std::uint16_t pdpt_idx, std::uint16_t pd_idx, std::uint16_t pt_idx)
	{
		for (int i = 0; i < shadow_leaf_count; i++)
			if (shadow_leaves[i].pml4_idx == pml4_idx && shadow_leaves[i].pdpt_idx == pdpt_idx && shadow_leaves[i].pd_idx == pd_idx && shadow_leaves[i].pt_idx == pt_idx) return &shadow_leaves[i];
		return nullptr;
	}

	inline void remove_shadow_pdpt(int index)
	{
		if (index < shadow_pdpt_count - 1) shadow_pdpts[index] = shadow_pdpts[shadow_pdpt_count - 1];
		shadow_pdpt_count--;
	}

	inline void remove_shadow_pd(int index)
	{
		if (index < shadow_pd_count - 1) shadow_pds[index] = shadow_pds[shadow_pd_count - 1];
		shadow_pd_count--;
	}

	inline void remove_shadow_pt(int index)
	{
		if (index < shadow_pt_count - 1) shadow_pts[index] = shadow_pts[shadow_pt_count - 1];
		shadow_pt_count--;
	}

	inline void remove_shadow_leaf(int index)
	{
		if (index < shadow_leaf_count - 1) shadow_leaves[index] = shadow_leaves[shadow_leaf_count - 1];
		shadow_leaf_count--;
	}

	// syscall exit hook hijack state
	inline std::uint8_t syscall_hijack_armed = 0;
	inline std::uint64_t syscall_hijack_shellcode_va = 0;
	inline std::uint64_t syscall_hijack_rip_offset = 0; // offset within stub where hypervisor writes original_rip
	inline std::uint64_t hijack_cpuid_count = 0; // total CPUID(7) calls received (diagnostic)
	inline std::uint64_t hijack_claimed_count = 0; // times was_armed==1 (diagnostic)

	// Usermode EPT hook registry — tracks shadow pages for relay commands 4/5
	struct usermode_ept_hook_t {
		std::uint64_t target_pa_page;  // page-aligned target PA (key for lookup)
		void* shadow_heap_va;          // host VA of shadow heap page (for freeing)
	};

	constexpr int max_usermode_ept_hooks = 16;
	inline usermode_ept_hook_t usermode_ept_hooks[max_usermode_ept_hooks] = {};
	inline int usermode_ept_hook_count = 0;

	inline usermode_ept_hook_t* find_usermode_ept_hook(std::uint64_t target_pa_page)
	{
		for (int i = 0; i < usermode_ept_hook_count; i++)
			if (usermode_ept_hooks[i].target_pa_page == target_pa_page) return &usermode_ept_hooks[i];
		return nullptr;
	}

	inline void remove_usermode_ept_hook(int index)
	{
		if (index < usermode_ept_hook_count - 1) usermode_ept_hooks[index] = usermode_ept_hooks[usermode_ept_hook_count - 1];
		usermode_ept_hook_count--;
	}

	// EPT violation diagnostic: track violations on a specific PFN
	inline std::uint64_t diag_watch_pfn = 0; // PFN to watch (0 = disabled)
	inline std::uint64_t diag_watch_pfn_exec_count = 0; // execute violations on watched PFN
	inline std::uint64_t diag_watch_pfn_rw_count = 0; // read/write violations on watched PFN

	// Screenshot hook state — anti-cheat GDI blit interception
	namespace screenshot_hook
	{
		inline volatile std::uint8_t enabled = 0;      // feature on/off
		inline volatile std::uint8_t blt_active = 0;   // screenshot in progress
		inline volatile std::uint8_t blt_ack = 0;      // DLL acknowledged (overlay hidden)
		inline volatile std::uint64_t blt_start_tsc = 0; // TSC at blt_start for timeout
	}

	// Process death auto-cleanup — MmCleanProcessAddressSpace hook state
	namespace cleanup_hook
	{
		inline volatile std::uint64_t target_eprocess = 0;
		inline volatile std::uint8_t armed = 0;
		inline volatile std::uint64_t cleanup_performed_count = 0;
		inline volatile std::uint8_t cleanup_pending = 0;
		inline volatile std::uint64_t hook_entry_count = 0;     // unconditional: hook code entered (any process)
		inline volatile std::uint64_t hook_hit_count = 0;       // armed path: fn_PsGetProcessImageFileName resolved
		inline volatile std::uint64_t hook_match_count = 0;     // name matches (cleanup triggered)

		// Name-based targeting (ring-1 style) — survives process restart
		inline char target_process_name[16] = {};
		inline std::uint64_t fn_PsGetProcessImageFileName = 0;  // resolved via PE export walk
		inline std::uint64_t ntoskrnl_base = 0;                 // set by hypercall 23
	}

	// Anti-recursion flag — ring-1 g_ExecutingEPTHook equivalent
	// Set to 1 when ANY compiled EPT hook function is executing in guest context.
	// Other hooks check this to avoid infinite recursion if hooked code calls another hooked function.
	inline volatile std::uint8_t g_executing_ept_hook = 0;

	// Generic EPT hook context — ring-1 HOOK_CONTEXT equivalent
	// Reusable for any inline EPT hook: MmClean, KiPageFault, KiDispatchException, etc.
	struct ept_hook_context_t
	{
		bool active = false;
		std::uint64_t target_va = 0;                           // guest VA of hooked function (pOriginalFunction)
		std::uint64_t target_pa_page = 0;                      // PA page for EPT removal
		void* shadow_heap_va = nullptr;                        // shadow page heap allocation
		std::uint64_t trampoline_va = 0;                       // guest VA of trampoline (calls original)
		std::uint64_t trampoline_hidden_slot = 0xFFFF;         // hidden PT slot for trampoline page
	};

	// Attachment image mapping into hidden region — makes compiled C++ code guest-executable
	namespace attachment_mapping
	{
		inline std::uint64_t image_base_pa = 0;     // attachment PE image base PA
		inline std::uint32_t image_page_count = 0;  // number of pages mapped
		inline std::uint64_t hidden_base_va = 0;    // VA of image base in hidden region
		inline bool mapped = false;
	}

	// MmCleanProcessAddressSpace inline EPT hook
	namespace mmclean_hook
	{
		inline ept_hook_context_t ctx;
	}

	// MmAccessFault compiled C++ EPT hook — safety net for hidden memory #PFs
	namespace mmaf_hook
	{
		inline ept_hook_context_t ctx;
		inline volatile std::uint64_t clone_cr3_value = 0;       // written by setup, read by guest hook
		inline volatile std::uint8_t hidden_pml4_index = 0;      // PML4 index of hidden region
		inline volatile std::uint64_t hit_count = 0;             // diagnostic: how many hidden memory faults caught
	}

	// KiDispatchException EPT hook — safe memory probes
	namespace exception_handler
	{
		inline bool active = false;
		inline std::uint64_t ki_dispatch_exception_va = 0;
		inline std::uint64_t trampoline_va = 0;
		inline std::uint64_t suppress_ret_va = 0;
		inline void* shadow_heap_va = nullptr;
		inline std::uint64_t target_pa_page = 0;
		inline std::uint32_t ktf_rax_offset = 0x30;
		inline std::uint32_t ktf_r10_offset = 0x58;
		inline std::uint32_t ktf_rip_offset = 0x168;
		inline std::uint64_t probe_copy_va = 0;   // TryCopyQword stub VA in hidden memory
		inline std::uint64_t probe_write_va = 0;   // TryWriteQword stub VA in hidden memory
		inline void* trampoline_shadow_heap_va = nullptr;  // separate trampoline page (null if on KDE page)
		inline std::uint64_t trampoline_pa_page = 0;       // PA page of separate trampoline (for EPT hook removal)
	}

	// KiPageFault inline EPT hook — safety net for hidden memory #PFs
	namespace page_fault_hook
	{
		inline bool active = false;
		inline std::uint64_t ki_page_fault_va = 0;
		inline void* shadow_heap_va = nullptr;
		inline std::uint64_t target_pa_page = 0;
		inline void* trampoline_shadow_heap_va = nullptr;
		inline std::uint64_t trampoline_pa_page = 0;
	}

	inline void sync_page_tables(const std::uint64_t new_original_cr3_value)
	{
		const cr3 new_original_cr3 = { .flags = new_original_cr3_value };
		const cr3 slat_cr3 = slat::hyperv_cr3();

		const auto original_pml4 = static_cast<const pml4e_64*>(
			memory_manager::map_guest_physical(slat_cr3, new_original_cr3.address_of_page_directory << 12));

		if (original_pml4 == nullptr)
		{
			return;
		}

		const auto cloned_pml4 = static_cast<pml4e_64*>(cloned_pml4_host_va);

		// Step 1: Full PML4 copy from original
		crt::copy_memory(cloned_pml4, original_pml4, 0x1000);

		// Step 2: Restore hidden region PML4E
		if (reserved_pml4e_index < 512 && hidden_pml4e_flags != 0)
			cloned_pml4[reserved_pml4e_index].flags = hidden_pml4e_flags;

		// Step 3: Re-apply shadow PDPTs and sync their content
		for (int i = 0; i < shadow_pdpt_count; i++)
		{
			const auto& reg = shadow_pdpts[i];
			const std::uint64_t orig_pdpt_gpa = original_pml4[reg.pml4_idx].page_frame_number << 12;
			cloned_pml4[reg.pml4_idx].page_frame_number = reg.cloned_pa >> 12;

			auto* cloned_pdpt = static_cast<pdpte_64*>(memory_manager::map_host_physical(reg.cloned_pa));
			const auto* orig_pdpt = static_cast<const pdpte_64*>(
				memory_manager::map_guest_physical(slat_cr3, orig_pdpt_gpa));
			if (cloned_pdpt && orig_pdpt)
				crt::copy_memory(cloned_pdpt, orig_pdpt, 0x1000);
		}

		// Step 4: Re-apply shadow PDs and sync their content
		for (int i = 0; i < shadow_pd_count; i++)
		{
			const auto& reg = shadow_pds[i];
			const shadow_pdpt_t* parent = find_shadow_pdpt(reg.pml4_idx);
			if (!parent) continue;

			auto* cloned_pdpt = static_cast<pdpte_64*>(memory_manager::map_host_physical(parent->cloned_pa));
			if (!cloned_pdpt) continue;

			const std::uint64_t orig_pd_gpa = cloned_pdpt[reg.pdpt_idx].page_frame_number << 12;
			cloned_pdpt[reg.pdpt_idx].page_frame_number = reg.cloned_pa >> 12;

			auto* cloned_pd = static_cast<pde_64*>(memory_manager::map_host_physical(reg.cloned_pa));
			const auto* orig_pd = static_cast<const pde_64*>(
				memory_manager::map_guest_physical(slat_cr3, orig_pd_gpa));
			if (cloned_pd && orig_pd)
				crt::copy_memory(cloned_pd, orig_pd, 0x1000);
		}

		// Step 5: Re-apply shadow PTs and sync their content
		for (int i = 0; i < shadow_pt_count; i++)
		{
			const auto& reg = shadow_pts[i];
			const shadow_pd_t* parent = find_shadow_pd(reg.pml4_idx, reg.pdpt_idx);
			if (!parent) continue;

			auto* cloned_pd = static_cast<pde_64*>(memory_manager::map_host_physical(parent->cloned_pa));
			if (!cloned_pd) continue;

			const std::uint64_t orig_pt_gpa = cloned_pd[reg.pd_idx].page_frame_number << 12;
			cloned_pd[reg.pd_idx].page_frame_number = reg.cloned_pa >> 12;

			auto* cloned_pt = static_cast<pte_64*>(memory_manager::map_host_physical(reg.cloned_pa));
			const auto* orig_pt = static_cast<const pte_64*>(
				memory_manager::map_guest_physical(slat_cr3, orig_pt_gpa));
			if (cloned_pt && orig_pt)
				crt::copy_memory(cloned_pt, orig_pt, 0x1000);
		}

		// Step 6: Re-apply shadow leaf PTEs
		for (int i = 0; i < shadow_leaf_count; i++)
		{
			const auto& leaf = shadow_leaves[i];
			const shadow_pt_t* parent = find_shadow_pt(leaf.pml4_idx, leaf.pdpt_idx, leaf.pd_idx);
			if (!parent) continue;

			auto* cloned_pt = static_cast<pte_64*>(memory_manager::map_host_physical(parent->cloned_pa));
			if (!cloned_pt) continue;

			cloned_pt[leaf.pt_idx].flags = leaf.saved_pte_flags;
		}

		target_original_cr3 = new_original_cr3_value;
	}

	inline std::uint64_t read_gpr(const trap_frame_t* const trap_frame, const std::uint64_t reg)
	{
		return reinterpret_cast<const std::uint64_t*>(trap_frame)[reg];
	}

	inline void write_gpr(trap_frame_t* const trap_frame, const std::uint64_t reg, const std::uint64_t value)
	{
		reinterpret_cast<std::uint64_t*>(trap_frame)[reg] = value;
	}
}
