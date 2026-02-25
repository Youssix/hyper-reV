#include "cr3.h"

#include "../slat.h"
#include "../slat_def.h"
#include "deep_copy.h"
#include "pte.h"

#include "../../memory_manager/memory_manager.h"
#include "../../memory_manager/heap_manager.h"
#include "../../interrupts/interrupts.h"
#include "../../arch/arch.h"

#include <intrin.h>

#ifdef _INTELMACHINE
extern "C" void invalidate_ept_mappings(invept_type type, const invept_descriptor& descriptor);
#endif

namespace
{
	cr3 hook_slat_cr3 = { };
	slat_pml4e* hook_slat_pml4 = nullptr;

	cr3 hyperv_slat_cr3 = { };

	// Set to 1 AFTER set_up_hook_cr3() fully completes (PML4 copied, heap hidden, EPTP active).
	// Hook 2 checks this before bootstrapping other VPs to hook_cr3.
	// NOT the same as hook2_initialized — that's set at boot before any hook::add().
	volatile std::uint8_t hook_cr3_ready = 0;
}

cr3 slat::hyperv_cr3()
{
	return hyperv_slat_cr3;
}

cr3 slat::hook_cr3()
{
	return hook_slat_cr3;
}

cr3 slat::get_cr3()
{
	return arch::get_slat_cr3();
}

bool slat::is_hook_cr3_ready()
{
	return hook_cr3_ready != 0;
}

void slat::set_cr3(const cr3 slat_cr3)
{
	arch::set_slat_cr3(slat_cr3);

	flush_current_logical_processor_cache(1);
}

bool slat::is_our_eptp(const cr3 current_eptp)
{
	const std::uint64_t pml4 = current_eptp.address_of_page_directory;

	if (hyperv_slat_cr3.flags != 0 && pml4 == hyperv_slat_cr3.address_of_page_directory)
	{
		return true;
	}

	if (hook_slat_cr3.flags != 0 && pml4 == hook_slat_cr3.address_of_page_directory)
	{
		return true;
	}

	return false;
}

void slat::flush_current_logical_processor_cache(const std::uint8_t has_slat_cr3_changed)
{
#ifdef _INTELMACHINE
	(void)has_slat_cr3_changed;

	invalidate_ept_mappings(invept_type::invept_all_context, { });
#else
	vmcb_t* const vmcb = arch::get_vmcb();

	vmcb->control.tlb_control = tlb_control_t::flush_guest_tlb_entries;

	if (has_slat_cr3_changed == 1)
	{
		vmcb->control.clean.nested_paging = 0;
	}
#endif
}

void slat::flush_all_logical_processors_cache()
{
	flush_current_logical_processor_cache();

	interrupts::set_all_nmi_ready();
	interrupts::send_nmi_all_but_self();
}

void set_up_slat_cr3(cr3* const slat_cr3, slat_pml4e** const slat_pml4)
{
	*slat_pml4 = static_cast<slat_pml4e*>(heap_manager::allocate_page());

	crt::set_memory(*slat_pml4, 0, sizeof(slat_pml4e) * 512);

	const std::uint64_t pml4_physical_address = memory_manager::unmap_host_physical(*slat_pml4);

	*slat_cr3 = slat::hyperv_cr3();
	slat_cr3->address_of_page_directory = pml4_physical_address >> 12;
}

void slat::set_up_hyperv_cr3()
{
	hyperv_slat_cr3 = get_cr3();
}

void slat::update_hyperv_cr3(const cr3 new_eptp)
{
	hyperv_slat_cr3 = new_eptp;
}

void slat::sync_hook_pml4_from_hyperv()
{
	if (hook_slat_pml4 == nullptr)
		return;

	const slat_pml4e* const hyperv_pml4 = get_pml4e(slat::hyperv_cr3(), { });
	crt::copy_memory(hook_slat_pml4, hyperv_pml4, sizeof(slat_pml4e) * 512);

	// TODO (production): re-apply forked PDPT entries from fork_registry here
	// fork_registry tracks which PML4Es point to forked PDPTs — those must be
	// re-stamped after the bulk copy to avoid reverting our hook modifications.
}

void slat::set_up_hook_cr3()
{
	set_up_slat_cr3(&hook_slat_cr3, &hook_slat_pml4);

	const slat_pml4e* const hyperv_pml4 = get_pml4e(slat::hyperv_cr3(), { });

#ifdef _INTELMACHINE
	make_pml4_copy(hyperv_pml4, hook_slat_pml4, 0);
#else
	make_pml4_copy(hyperv_pml4, hook_slat_pml4, 1);
#endif

	// [DEFERRED] hide_heap_pages — commented out due to EPTP bounce perf issue.
	//
	// Context: ring-1 maps all physical memory RWX including its own UEFI allocations
	// (2MB + 80MB via AllocatePages). Guest can read their pages directly.
	// That's a weakness, not a design choice.
	//
	// For hyper-reV, 3 options to re-enable heap hiding:
	//
	// Option 1: Do nothing (like ring-1). Simple, no perf hit. But an AC scanning
	//   physical memory could find our structures. Moderate risk — need to know where to look.
	//
	// Option 2: VMWRITE hook (ring-1 style but better). Eliminates the bounce — VP stays
	//   on hook_cr3 permanently — no constant INVEPT — hide_heap_pages works without perf hit.
	//   This is the real long-term fix but requires hooking VMWRITE in HV's handler.
	//
	// Option 3: Re-bootstrap without INVEPT. hook_cr3's TLB entries survive the bounce
	//   (different EP4TA tags, not invalidated). Heap pages are forked (private to hook_cr3),
	//   HV can't modify them during bounce. So re-bootstrap could skip INVEPT — 4KB entries
	//   stay cached — no slowdown — hide_heap_pages works. Risky if HV modifies non-forked
	//   entries, but testable quickly.
	//
	// slat::hide_heap_pages(hook_cr3());

	// Do NOT bootstrap this VP immediately — caller may be usermode.exe (non-target process).
	// EPT hooks redirect to hidden region (PML4[hidden]), which only exists in the target
	// process's cloned CR3. Non-target processes on hook_cr3 would #PF → infinite recursion
	// → double fault (0x7F Arg1=8).
	//
	// Hook 1's re-bootstrap logic activates hook_cr3 ONLY when guest CR3 matches the target.
	_InterlockedExchange8(reinterpret_cast<volatile char*>(&hook_cr3_ready), 1);
}

