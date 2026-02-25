#include "pte.h"
#include "fork_registry.h"

#include "../../memory_manager/memory_manager.h"
#include "../../memory_manager/heap_manager.h"

#include "../../structures/virtual_address.h"
#include "../../crt/crt.h"

slat_pml4e* slat::get_pml4e(const cr3 slat_cr3, const virtual_address_t guest_physical_address)
{
	const auto pml4 = static_cast<slat_pml4e*>(memory_manager::map_host_physical(slat_cr3.address_of_page_directory << 12));

	return &pml4[guest_physical_address.pml4_idx];
}

slat_pdpte* slat::get_pdpte(const slat_pml4e* const pml4e, const virtual_address_t guest_physical_address)
{
	const auto pdpt = static_cast<slat_pdpte*>(memory_manager::map_host_physical(pml4e->page_frame_number << 12));

	return &pdpt[guest_physical_address.pdpt_idx];
}

slat_pde* slat::get_pde(const slat_pdpte* const pdpte, const virtual_address_t guest_physical_address)
{
	const auto pd = static_cast<slat_pde*>(memory_manager::map_host_physical(pdpte->page_frame_number << 12));

	return &pd[guest_physical_address.pd_idx];
}

slat_pte* slat::get_pte(const slat_pde* const pde, const virtual_address_t guest_physical_address)
{
	const auto pt = static_cast<slat_pte*>(memory_manager::map_host_physical(pde->page_frame_number << 12));

	return &pt[guest_physical_address.pt_idx];
}

slat_pde* slat::get_pde(const cr3 slat_cr3, const virtual_address_t guest_physical_address,
	const std::uint8_t force_split_pages)
{
	const slat_pml4e* const pml4e = get_pml4e(slat_cr3, guest_physical_address);

	if (pml4e == nullptr)
	{
		return nullptr;
	}

	slat_pdpte* const pdpte = get_pdpte(pml4e, guest_physical_address);

	if (pdpte == nullptr)
	{
		return nullptr;
	}

	const auto large_pdpte = reinterpret_cast<slat_pdpte_1gb*>(pdpte);

	if (large_pdpte->large_page == 1 && (force_split_pages == 0 || split_1gb_pdpte(large_pdpte) == 0))
	{
		return nullptr;
	}

	return get_pde(pdpte, guest_physical_address);
}

slat_pte* slat::get_pte(const cr3 slat_cr3, const virtual_address_t guest_physical_address,
	const std::uint8_t force_split_pages, std::uint8_t* const paging_split_state)
{
	slat_pde* const pde = get_pde(slat_cr3, guest_physical_address, force_split_pages);

	if (pde == nullptr)
	{
		return nullptr;
	}

	const auto large_pde = reinterpret_cast<slat_pde_2mb*>(pde);

	if (large_pde->large_page == 1)
	{
		if (force_split_pages == 0 || split_2mb_pde(large_pde) == 0)
		{
			return nullptr;
		}

		if (paging_split_state != nullptr)
		{
			*paging_split_state = 1;
		}
	}

	return get_pte(pde, guest_physical_address);
}

std::uint8_t slat::split_2mb_pde(slat_pde_2mb* const large_pde)
{
	const auto pt = static_cast<slat_pte*>(heap_manager::allocate_page());

	if (pt == nullptr)
	{
		return 0;
	}

	for (std::uint64_t i = 0; i < 512; i++)
	{
		slat_pte* pte = &pt[i];

		pte->flags = 0;

#ifdef _INTELMACHINE
		pte->execute_access = large_pde->execute_access;
		pte->read_access = large_pde->read_access;
		pte->write_access = large_pde->write_access;
		pte->memory_type = large_pde->memory_type;
		pte->ignore_pat = large_pde->ignore_pat;
		pte->user_mode_execute = large_pde->user_mode_execute;
		pte->verify_guest_paging = large_pde->verify_guest_paging;
		pte->paging_write_access = large_pde->paging_write_access;
		pte->supervisor_shadow_stack = large_pde->supervisor_shadow_stack;
		pte->suppress_ve = large_pde->suppress_ve;
#else
		pte->execute_disable = large_pde->execute_disable;
		pte->present = large_pde->present;
		pte->write = large_pde->write;
		pte->global = large_pde->global;
		pte->pat = large_pde->pat;
		pte->protection_key = large_pde->protection_key;
		pte->page_level_write_through = large_pde->page_level_write_through;
		pte->page_level_cache_disable = large_pde->page_level_cache_disable;
		pte->supervisor = large_pde->supervisor;
#endif

		pte->accessed = large_pde->accessed;
		pte->dirty = large_pde->dirty;

		pte->page_frame_number = (large_pde->page_frame_number << 9) + i;
	}

	const std::uint64_t pt_physical_address = memory_manager::unmap_host_physical(pt);

	slat_pde new_pde = { };

	new_pde.page_frame_number = pt_physical_address >> 12;

#ifdef _INTELMACHINE
	new_pde.read_access = 1;
	new_pde.write_access = 1;
	new_pde.execute_access = 1;
	new_pde.user_mode_execute = 1;
#else
	new_pde.present = 1;
	new_pde.write = 1;
	new_pde.supervisor = 1;
#endif

	large_pde->flags = new_pde.flags;

	return 1;
}

std::uint8_t slat::split_1gb_pdpte(slat_pdpte_1gb* const large_pdpte)
{
	const auto pd = static_cast<slat_pde_2mb*>(heap_manager::allocate_page());

	if (pd == nullptr)
	{
		return 0;
	}

	for (std::uint64_t i = 0; i < 512; i++)
	{
		slat_pde_2mb* pde = &pd[i];

		pde->flags = 0;

#ifdef _INTELMACHINE
		pde->execute_access = large_pdpte->execute_access;
		pde->read_access = large_pdpte->read_access;
		pde->write_access = large_pdpte->write_access;
		pde->memory_type = large_pdpte->memory_type;
		pde->ignore_pat = large_pdpte->ignore_pat;
		pde->user_mode_execute = large_pdpte->user_mode_execute;
		pde->verify_guest_paging = large_pdpte->verify_guest_paging;
		pde->paging_write_access = large_pdpte->paging_write_access;
		pde->supervisor_shadow_stack = large_pdpte->supervisor_shadow_stack;
		pde->suppress_ve = large_pdpte->suppress_ve;
#else
		pde->execute_disable = large_pdpte->execute_disable;
		pde->present = large_pdpte->present;
		pde->write = large_pdpte->write;
		pde->global = large_pdpte->global;
		pde->pat = large_pdpte->pat;
		pde->protection_key = large_pdpte->protection_key;
		pde->page_level_write_through = large_pdpte->page_level_write_through;
		pde->page_level_cache_disable = large_pdpte->page_level_cache_disable;
		pde->supervisor = large_pdpte->supervisor;
#endif

		pde->accessed = large_pdpte->accessed;
		pde->dirty = large_pdpte->dirty;

		pde->page_frame_number = (large_pdpte->page_frame_number << 9) + i;
		pde->large_page = 1;
	}

	const std::uint64_t pd_physical_address = memory_manager::unmap_host_physical(pd);

	slat_pdpte new_pdpte = { .flags = 0 };

	new_pdpte.page_frame_number = pd_physical_address >> 12;

#ifdef _INTELMACHINE
	new_pdpte.read_access = 1;
	new_pdpte.write_access = 1;
	new_pdpte.execute_access = 1;
	new_pdpte.user_mode_execute = 1;
#else
	new_pdpte.present = 1;
	new_pdpte.write = 1;
	new_pdpte.supervisor = 1;
#endif

	large_pdpte->flags = new_pdpte.flags;

	return 1;
}

std::uint8_t slat::merge_4kb_pt(const cr3 slat_cr3, const virtual_address_t guest_physical_address)
{
	slat_pde* const pde = get_pde(slat_cr3, guest_physical_address);

	if (pde == nullptr)
	{
		return 0;
	}

	const auto large_pde = reinterpret_cast<slat_pde_2mb*>(pde);

	if (large_pde->large_page == 1)
	{
		return 1;
	}

	const std::uint64_t pt_physical_address = pde->page_frame_number << 12;

	slat_pte* const pte = get_pte(pde, guest_physical_address);

	slat_pde_2mb new_large_pde = { };

#ifdef _INTELMACHINE
	new_large_pde.execute_access = pte->execute_access;
	new_large_pde.read_access = pte->read_access;
	new_large_pde.write_access = pte->write_access;
	new_large_pde.memory_type = pte->memory_type;
	new_large_pde.ignore_pat = pte->ignore_pat;
	new_large_pde.user_mode_execute = pte->user_mode_execute;
	new_large_pde.verify_guest_paging = pte->verify_guest_paging;
	new_large_pde.paging_write_access = pte->paging_write_access;
	new_large_pde.supervisor_shadow_stack = pte->supervisor_shadow_stack;
	new_large_pde.suppress_ve = pte->suppress_ve;
#else
		new_large_pde.execute_disable = pte->execute_disable;
		new_large_pde.present = pte->present;
		new_large_pde.write = pte->write;
		new_large_pde.global = pte->global;
		new_large_pde.pat = pte->pat;
		new_large_pde.protection_key = pte->protection_key;
		new_large_pde.page_level_write_through = pte->page_level_write_through;
		new_large_pde.page_level_cache_disable = pte->page_level_cache_disable;
		new_large_pde.supervisor = pte->supervisor;
#endif

	new_large_pde.page_frame_number = pte->page_frame_number >> 9;
	new_large_pde.large_page = 1;

	*large_pde = new_large_pde;

	void* const pt_allocation_mapped = memory_manager::map_host_physical(pt_physical_address);

	heap_manager::free_page(pt_allocation_mapped);

	return 1;
}

std::uint8_t slat::is_pte_present(const void* const pte_in)
{
	if (!pte_in)
	{
		return 0;
	}

	const auto pte = static_cast<const slat_pte*>(pte_in);

#ifdef _INTELMACHINE
	return pte->read_access == 1;
#else
		return pte->present == 1;
#endif
}

std::uint8_t slat::is_pte_large(const void* const pte_in)
{
	if (!pte_in)
	{
		return 0;
	}

	const auto large_pte = static_cast<const slat_pde_2mb*>(pte_in);

	return large_pte->large_page;
}

slat_pte* slat::fork_get_pte(const cr3 hook_cr3_val, const cr3 hyperv_cr3_val, const virtual_address_t gpa, const std::uint8_t force_split, std::uint8_t* const paging_split_state)
{
#ifdef _INTELMACHINE
	// Walk hook_cr3 PML4
	slat_pml4e* const hook_pml4e = get_pml4e(hook_cr3_val, gpa);

	if (hook_pml4e == nullptr || is_pte_present(hook_pml4e) == 0)
	{
		return nullptr;
	}

	// Compare PDPT PFN with hyperv_cr3
	const slat_pml4e* const hyperv_pml4e = get_pml4e(hyperv_cr3_val, gpa);

	if (hyperv_pml4e == nullptr || is_pte_present(hyperv_pml4e) == 0)
	{
		return nullptr;
	}

	// Fork PDPT if shared
	if (hook_pml4e->page_frame_number == hyperv_pml4e->page_frame_number)
	{
		const auto shared_pdpt = static_cast<slat_pdpte*>(memory_manager::map_host_physical(hook_pml4e->page_frame_number << 12));
		const auto forked_pdpt = static_cast<slat_pdpte*>(heap_manager::allocate_page());

		if (forked_pdpt == nullptr)
		{
			return nullptr;
		}

		crt::copy_memory(forked_pdpt, shared_pdpt, sizeof(slat_pdpte) * 512);

		const std::uint64_t forked_pdpt_pfn = memory_manager::unmap_host_physical(forked_pdpt) >> 12;

		fork_registry::register_forked_pdpt(gpa.pml4_idx, forked_pdpt_pfn, hook_pml4e->page_frame_number);

		hook_pml4e->page_frame_number = forked_pdpt_pfn;
	}

	// Now walk the (possibly forked) PDPT
	slat_pdpte* const hook_pdpte = get_pdpte(hook_pml4e, gpa);

	if (hook_pdpte == nullptr || is_pte_present(hook_pdpte) == 0)
	{
		return nullptr;
	}

	// Split 1GB page if needed
	auto large_pdpte = reinterpret_cast<slat_pdpte_1gb*>(hook_pdpte);

	if (large_pdpte->large_page == 1)
	{
		if (force_split == 0 || split_1gb_pdpte(large_pdpte) == 0)
		{
			return nullptr;
		}

	}

	// Compare PD PFN with hyperv_cr3's PDPT entry
	const slat_pdpte* const hyperv_pdpte = get_pdpte(hyperv_pml4e, gpa);

	if (hook_pdpte->page_frame_number == hyperv_pdpte->page_frame_number)
	{
		const auto shared_pd = static_cast<slat_pde*>(memory_manager::map_host_physical(hook_pdpte->page_frame_number << 12));
		const auto forked_pd = static_cast<slat_pde*>(heap_manager::allocate_page());

		if (forked_pd == nullptr)
		{
			return nullptr;
		}

		crt::copy_memory(forked_pd, shared_pd, sizeof(slat_pde) * 512);

		const std::uint64_t forked_pd_pfn = memory_manager::unmap_host_physical(forked_pd) >> 12;

		fork_registry::register_forked_pd(gpa.pml4_idx, gpa.pdpt_idx, forked_pd_pfn, hook_pdpte->page_frame_number);

		hook_pdpte->page_frame_number = forked_pd_pfn;
	}

	// Now walk the (possibly forked) PD
	slat_pde* const hook_pde = get_pde(hook_pdpte, gpa);

	if (hook_pde == nullptr || is_pte_present(hook_pde) == 0)
	{
		return nullptr;
	}

	// Split 2MB page if needed
	auto large_pde = reinterpret_cast<slat_pde_2mb*>(hook_pde);

	if (large_pde->large_page == 1)
	{
		if (force_split == 0 || split_2mb_pde(large_pde) == 0)
		{
			return nullptr;
		}

		if (paging_split_state != nullptr)
		{
			*paging_split_state = 1;
		}
	}

	// Compare PT PFN with hyperv_cr3's PD entry (read-only walk, never force-split)
	const slat_pde* const hyperv_pde = get_pde(hyperv_cr3_val, gpa, 0);

	if (hyperv_pde != nullptr && hook_pde->page_frame_number == hyperv_pde->page_frame_number)
	{
		const auto shared_pt = static_cast<slat_pte*>(memory_manager::map_host_physical(hook_pde->page_frame_number << 12));
		const auto forked_pt = static_cast<slat_pte*>(heap_manager::allocate_page());

		if (forked_pt == nullptr)
		{
			return nullptr;
		}

		crt::copy_memory(forked_pt, shared_pt, sizeof(slat_pte) * 512);

		const std::uint64_t forked_pt_pfn = memory_manager::unmap_host_physical(forked_pt) >> 12;

		fork_registry::register_forked_pt(gpa.pml4_idx, gpa.pdpt_idx, gpa.pd_idx, forked_pt_pfn, hook_pde->page_frame_number);

		hook_pde->page_frame_number = forked_pt_pfn;
	}

	return get_pte(hook_pde, gpa);
#else
	// AMD: no fork needed, use standard path
	return get_pte(hook_cr3_val, gpa, force_split);
#endif
}

