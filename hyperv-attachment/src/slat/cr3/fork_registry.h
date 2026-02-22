#pragma once
#include <cstdint>

namespace slat::fork_registry
{
	constexpr std::uint64_t max_forked_pdpts = 16;
	constexpr std::uint64_t max_forked_pds = 64;
	constexpr std::uint64_t max_forked_pts = 128;

	struct forked_pdpt_t
	{
		std::uint64_t pml4_idx;
		std::uint64_t forked_pfn;
		std::uint64_t original_pfn;
	};

	struct forked_pd_t
	{
		std::uint64_t pml4_idx;
		std::uint64_t pdpt_idx;
		std::uint64_t forked_pfn;
		std::uint64_t original_pfn;
	};

	struct forked_pt_t
	{
		std::uint64_t pml4_idx;
		std::uint64_t pdpt_idx;
		std::uint64_t pd_idx;
		std::uint64_t forked_pfn;
		std::uint64_t original_pfn;
	};

	forked_pdpt_t* find_forked_pdpt(std::uint64_t pml4_idx);
	forked_pd_t* find_forked_pd(std::uint64_t pml4_idx, std::uint64_t pdpt_idx);
	forked_pt_t* find_forked_pt(std::uint64_t pml4_idx, std::uint64_t pdpt_idx, std::uint64_t pd_idx);

	forked_pdpt_t* register_forked_pdpt(std::uint64_t pml4_idx, std::uint64_t forked_pfn, std::uint64_t original_pfn);
	forked_pd_t* register_forked_pd(std::uint64_t pml4_idx, std::uint64_t pdpt_idx, std::uint64_t forked_pfn, std::uint64_t original_pfn);
	forked_pt_t* register_forked_pt(std::uint64_t pml4_idx, std::uint64_t pdpt_idx, std::uint64_t pd_idx, std::uint64_t forked_pfn, std::uint64_t original_pfn);

	std::uint8_t is_in_forked_region(std::uint64_t pml4_idx, std::uint64_t pdpt_idx, std::uint64_t pd_idx);

	void sync_forked_entry(std::uint64_t gpa);
}
