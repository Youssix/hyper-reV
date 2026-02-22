#include "fork_registry.h"
#include "cr3.h"
#include "pte.h"
#include "../../memory_manager/memory_manager.h"
#include "../../crt/crt.h"
#include "../../structures/virtual_address.h"
#include "../slat_def.h"

namespace
{
	slat::fork_registry::forked_pdpt_t forked_pdpts[slat::fork_registry::max_forked_pdpts] = { };
	std::uint64_t forked_pdpt_count = 0;

	slat::fork_registry::forked_pd_t forked_pds[slat::fork_registry::max_forked_pds] = { };
	std::uint64_t forked_pd_count = 0;

	slat::fork_registry::forked_pt_t forked_pts[slat::fork_registry::max_forked_pts] = { };
	std::uint64_t forked_pt_count = 0;
}

slat::fork_registry::forked_pdpt_t* slat::fork_registry::find_forked_pdpt(const std::uint64_t pml4_idx)
{
	for (std::uint64_t i = 0; i < forked_pdpt_count; i++)
	{
		if (forked_pdpts[i].pml4_idx == pml4_idx)
		{
			return &forked_pdpts[i];
		}
	}

	return nullptr;
}

slat::fork_registry::forked_pd_t* slat::fork_registry::find_forked_pd(const std::uint64_t pml4_idx, const std::uint64_t pdpt_idx)
{
	for (std::uint64_t i = 0; i < forked_pd_count; i++)
	{
		if (forked_pds[i].pml4_idx == pml4_idx && forked_pds[i].pdpt_idx == pdpt_idx)
		{
			return &forked_pds[i];
		}
	}

	return nullptr;
}

slat::fork_registry::forked_pt_t* slat::fork_registry::find_forked_pt(const std::uint64_t pml4_idx, const std::uint64_t pdpt_idx, const std::uint64_t pd_idx)
{
	for (std::uint64_t i = 0; i < forked_pt_count; i++)
	{
		if (forked_pts[i].pml4_idx == pml4_idx && forked_pts[i].pdpt_idx == pdpt_idx && forked_pts[i].pd_idx == pd_idx)
		{
			return &forked_pts[i];
		}
	}

	return nullptr;
}

slat::fork_registry::forked_pdpt_t* slat::fork_registry::register_forked_pdpt(const std::uint64_t pml4_idx, const std::uint64_t forked_pfn, const std::uint64_t original_pfn)
{
	if (forked_pdpt_count >= max_forked_pdpts)
	{
		return nullptr;
	}

	forked_pdpt_t* const entry = &forked_pdpts[forked_pdpt_count++];

	entry->pml4_idx = pml4_idx;
	entry->forked_pfn = forked_pfn;
	entry->original_pfn = original_pfn;

	return entry;
}

slat::fork_registry::forked_pd_t* slat::fork_registry::register_forked_pd(const std::uint64_t pml4_idx, const std::uint64_t pdpt_idx, const std::uint64_t forked_pfn, const std::uint64_t original_pfn)
{
	if (forked_pd_count >= max_forked_pds)
	{
		return nullptr;
	}

	forked_pd_t* const entry = &forked_pds[forked_pd_count++];

	entry->pml4_idx = pml4_idx;
	entry->pdpt_idx = pdpt_idx;
	entry->forked_pfn = forked_pfn;
	entry->original_pfn = original_pfn;

	return entry;
}

slat::fork_registry::forked_pt_t* slat::fork_registry::register_forked_pt(const std::uint64_t pml4_idx, const std::uint64_t pdpt_idx, const std::uint64_t pd_idx, const std::uint64_t forked_pfn, const std::uint64_t original_pfn)
{
	if (forked_pt_count >= max_forked_pts)
	{
		return nullptr;
	}

	forked_pt_t* const entry = &forked_pts[forked_pt_count++];

	entry->pml4_idx = pml4_idx;
	entry->pdpt_idx = pdpt_idx;
	entry->pd_idx = pd_idx;
	entry->forked_pfn = forked_pfn;
	entry->original_pfn = original_pfn;

	return entry;
}

std::uint8_t slat::fork_registry::is_in_forked_region(const std::uint64_t pml4_idx, const std::uint64_t pdpt_idx, const std::uint64_t pd_idx)
{
	return find_forked_pt(pml4_idx, pdpt_idx, pd_idx) != nullptr;
}

void slat::fork_registry::sync_forked_entry(const std::uint64_t gpa)
{
	const virtual_address_t va = { .address = gpa };

	const forked_pt_t* const pt_entry = find_forked_pt(va.pml4_idx, va.pdpt_idx, va.pd_idx);

	if (pt_entry == nullptr)
	{
		return;
	}

	const auto original_pt = static_cast<slat_pte*>(memory_manager::map_host_physical(pt_entry->original_pfn << 12));
	const auto forked_pt = static_cast<slat_pte*>(memory_manager::map_host_physical(pt_entry->forked_pfn << 12));

	const slat_pte* const original_pte = &original_pt[va.pt_idx];
	slat_pte* const forked_pte = &forked_pt[va.pt_idx];

	const std::uint64_t saved_pfn = forked_pte->page_frame_number;
	const std::uint64_t saved_flags_low =
#ifdef _INTELMACHINE
		forked_pte->read_access | (forked_pte->write_access << 1) | (forked_pte->execute_access << 2);
#else
		0;
#endif

	forked_pte->flags = original_pte->flags;

	// If this PTE was modified by our hook (different PFN or permissions), restore our overrides
	if (saved_pfn != original_pte->page_frame_number)
	{
		forked_pte->page_frame_number = saved_pfn;

#ifdef _INTELMACHINE
		forked_pte->read_access = saved_flags_low & 1;
		forked_pte->write_access = (saved_flags_low >> 1) & 1;
		forked_pte->execute_access = (saved_flags_low >> 2) & 1;
#endif
	}
}
