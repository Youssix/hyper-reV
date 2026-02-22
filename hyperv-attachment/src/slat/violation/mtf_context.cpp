#include "mtf_context.h"
#include "../cr3/cr3.h"
#include "../cr3/pte.h"
#include "../hook/hook_entry.h"
#include "../../arch/arch.h"
#include "../../memory_manager/memory_manager.h"
#include "../../crt/crt.h"
#include "../../structures/virtual_address.h"

namespace
{
	slat::mtf::context_t contexts[slat::mtf::max_contexts] = { };
}

void slat::mtf::set_up()
{
	crt::set_memory(contexts, 0, sizeof(contexts));
}

void slat::mtf::arm(const std::uint16_t vpid, const std::uint64_t gpa, slat_pte* const hook_pte, const std::uint64_t saved_flags)
{
	if (vpid >= max_contexts)
	{
		return;
	}

	context_t* const ctx = &contexts[vpid];

	ctx->pending_gpa = gpa;
	ctx->hook_pte = hook_pte;
	ctx->saved_pte_flags = saved_flags;
	ctx->active = 1;
}

std::uint8_t slat::mtf::process()
{
#ifdef _INTELMACHINE
	const std::uint16_t vpid = arch::get_current_vpid();

	if (vpid >= max_contexts)
	{
		return 0;
	}

	context_t* const ctx = &contexts[vpid];

	if (ctx->active == 0)
	{
		return 0;
	}

	// 1. Restore hook_cr3 PTE to R-- (remove temp write permission)
	if (ctx->hook_pte != nullptr)
	{
		ctx->hook_pte->flags = ctx->saved_pte_flags;
	}

	// 2. Disable MTF
	arch::disable_mtf();

	// 3. Sync shadow page: copy original -> shadow, preserving hook bytes
	const virtual_address_t gpa = { .address = ctx->pending_gpa };
	const std::uint64_t faulting_pfn = ctx->pending_gpa >> 12;

	const hook::entry_t* const hook_entry = hook::entry_t::find(faulting_pfn);

	if (hook_entry != nullptr)
	{
		// Get shadow page from hyperv_cr3 PTE (it points to shadow PFN)
		slat_pte* const hyperv_pte = get_pte(hyperv_cr3(), gpa);

		if (hyperv_pte != nullptr)
		{
			const std::uint64_t shadow_pfn = hyperv_pte->page_frame_number;
			const std::uint64_t original_pfn = hook_entry->original_pfn();

			auto shadow_page = static_cast<std::uint8_t*>(memory_manager::map_host_physical(shadow_pfn << 12));
			const auto original_page = static_cast<const std::uint8_t*>(memory_manager::map_host_physical(original_pfn << 12));

			const std::uint64_t hook_offset = hook_entry->hook_byte_offset();
			const std::uint64_t hook_length = hook_entry->hook_byte_length();

			if (hook_length > 0 && hook_offset + hook_length <= 0x1000)
			{
				// Copy bytes before hook region
				if (hook_offset > 0)
				{
					crt::copy_memory(shadow_page, original_page, hook_offset);
				}

				// Copy bytes after hook region
				const std::uint64_t after_offset = hook_offset + hook_length;
				const std::uint64_t after_size = 0x1000 - after_offset;

				if (after_size > 0)
				{
					crt::copy_memory(shadow_page + after_offset, original_page + after_offset, after_size);
				}
			}
			else
			{
				// hook_byte_length not set — save shadow's current content (contains hook patch),
				// copy entire original page, then restore the saved hook patch bytes.
				// The hook patch starts at hook_offset within the page.
				// Use a conservative 14-byte save (push+mov+ret detour size) if length is unknown.
				constexpr std::uint64_t default_patch_size = 14;
				const std::uint64_t save_offset = hook_offset;
				const std::uint64_t save_length = (save_offset + default_patch_size <= 0x1000) ? default_patch_size : (0x1000 - save_offset);

				std::uint8_t saved_hook_bytes[16] = { };

				if (save_length > 0 && save_length <= sizeof(saved_hook_bytes))
				{
					crt::copy_memory(saved_hook_bytes, shadow_page + save_offset, save_length);
				}

				// Copy entire original page to shadow
				crt::copy_memory(shadow_page, original_page, 0x1000);

				// Restore the hook patch bytes
				if (save_length > 0 && save_length <= sizeof(saved_hook_bytes))
				{
					crt::copy_memory(shadow_page + save_offset, saved_hook_bytes, save_length);
				}
			}
		}
	}

	// 4. Flush EPT cache
	flush_current_logical_processor_cache();

	// 5. Clear context
	ctx->active = 0;
	ctx->hook_pte = nullptr;
	ctx->pending_gpa = 0;
	ctx->saved_pte_flags = 0;

	return 1;
#else
	return 0;
#endif
}
