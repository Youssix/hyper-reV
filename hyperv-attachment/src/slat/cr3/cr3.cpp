#include "cr3.h"

#include "../slat.h"
#include "../slat_def.h"
#include "deep_copy.h"
#include "pte.h"

#include "../../memory_manager/memory_manager.h"
#include "../../memory_manager/heap_manager.h"
#include "../../interrupts/interrupts.h"
#include "../../arch/arch.h"
#include "../../logs/serial.h"

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

	// Hook 3: physical address of 73-byte shellcode in hvix64 .text code cave.
	// PATCH_SLOT_1 at cave+4:  hyperv_cr3 PFN (8 bytes, 0 = inactive)
	// PATCH_SLOT_2 at cave+39: hook_cr3 PFN << 12 (8 bytes)
	// NOTE: no in-cave counter — .text is read-only at runtime, writes fault.
	std::uint64_t vmwrite_hook_cave_physical_address = 0;

	// Hook 3 active flag. Checked by NMI handler to enforce hook_cr3 on all LPs.
	// With enlightened VMCS, HV writes EPTP to cache once → sub_358ABC never called again.
	// The shellcode alone can't fix VPs that are already cached on hyperv_cr3.
	// NMI broadcast + this flag forces every LP onto hook_cr3 at activation time.
	volatile std::uint8_t vmwrite_hook_active = 0;
}

// Per-LP dirty flags for lazy INVEPT. 1 = hook_cr3 EPT modified since last INVEPT on this LP.
volatile std::uint8_t slat::hook_cr3_ept_dirty[slat::max_logical_processors] = {};

// NMI action for EPTP source table: 0=none, 1=patch(hook_cr3), 2=restore(hyperv_cr3)
volatile std::uint8_t slat::eptp_table_nmi_action = 0;

// Deferred table patch flag
volatile std::uint8_t slat::eptp_table_patch_pending = 0;

// Option B diagnostics
volatile std::uint64_t slat::optb_diag_bail = 0;
volatile std::uint64_t slat::optb_diag_per_vp = 0;
volatile std::uint64_t slat::optb_diag_ept_data = 0;
volatile std::uint64_t slat::optb_diag_count = 0;
// Deep GS diagnostics
volatile std::uint64_t slat::optb_diag_gs_base = 0;
volatile std::uint64_t slat::optb_diag_manual_read = 0;
volatile std::uint64_t slat::optb_diag_gs_first_qword = 0;
volatile std::uint64_t slat::optb_diag_host_gs_base = 0;

void slat::mark_all_lps_dirty()
{
	for (std::uint16_t i = 0; i < max_logical_processors; i++)
	{
		hook_cr3_ept_dirty[i] = 1;
	}
}

// EPTP source table offsets (from IDA RE of HvGetEptPointer in hvix64.exe).
// per_vp + 0xCD8 → ptr to ept_data; ept_data + 0xBD0 → count; +0xBD8 → first entry; stride 0x138.
namespace eptp_table
{
	constexpr std::uint64_t ptr_offset     = 0xCD8;
	constexpr std::uint64_t count_offset   = 0xBD0;
	constexpr std::uint64_t first_offset   = 0xBD8;
	constexpr std::uint64_t entry_stride   = 0x138;
	constexpr std::uint32_t max_entries    = 16; // sanity cap
}

// Reset by activate_vmwrite_hook so each hook3 on/off cycle captures fresh diag.
static volatile long optb_diag_captured = 0;

void slat::patch_eptp_source_table(const bool use_hook_cr3)
{
	// Write-once diagnostics: only the first VP to call captures diag values.
	// Prevents NMI handler on VTL 1 VP from overwriting a good result.
	const bool capture_diag = (_InterlockedCompareExchange(&optb_diag_captured, 1, 0) == 0);

	const std::uint32_t gs_offset = arch::get_enlightened_gs_per_vp_offset();
	if (gs_offset == 0)
	{
		if (capture_diag) optb_diag_bail = 1;
		return;
	}

	// Read KERNEL_GS_BASE (MSR 0xC0000102) — the "other" GS from HV's SWAPGS pair.
	// After HV handler's 2x SWAPGS cycle, KERNEL_GS_BASE = HV per-VP GS base.
	// HOST_GS_BASE (= current GS) = per-processor struct (KPCR-like).
	// VALIDATED: KERNEL_GS_BASE = 0xFFFFCC... = canonical HV address, not guest garbage.
	// Safety: only dereference if canonical-high AND different from HOST_GS_BASE
	// (if equal → NMI arrived between the two SWAPGSes → wrong context).
	const std::uint64_t kernel_gs_base = __readmsr(0xC0000102); // IA32_KERNEL_GS_BASE
	const std::uint64_t host_gs_base = arch::vmread_host_gs_base(); // VMCS HOST_GS_BASE

	if (capture_diag)
	{
		optb_diag_gs_base = __readmsr(0xC0000101);       // IA32_GS_BASE (current)
		optb_diag_manual_read = kernel_gs_base;
		optb_diag_host_gs_base = host_gs_base;
	}

	// Try KERNEL_GS_BASE if it's canonical-high (bit 47 set → HV address, not user/guest)
	// and not equal to HOST_GS_BASE (would mean NMI between SWAPGSes).
	std::uint64_t per_vp = 0;
	const bool kgs_is_canonical_high = (kernel_gs_base >> 47) & 1; // bit 47 set = kernel/HV range
	const bool kgs_differs_from_host = (kernel_gs_base != host_gs_base);

	if (kernel_gs_base != 0 && kgs_is_canonical_high && kgs_differs_from_host)
	{
		per_vp = *reinterpret_cast<volatile std::uint64_t*>(kernel_gs_base + gs_offset);
		if (capture_diag) optb_diag_gs_first_qword = per_vp; // actual *(KERNEL_GS + offset)
	}

	// Fallback: try GS segment read (works if NMI arrived between SWAPGSes → GS = per_vp)
	if (per_vp == 0)
	{
		per_vp = __readgsqword(gs_offset);
		if (capture_diag && optb_diag_gs_first_qword == 0) optb_diag_gs_first_qword = per_vp;
	}

	if (capture_diag) optb_diag_per_vp = per_vp;
	if (per_vp == 0)
	{
		if (capture_diag) optb_diag_bail = 2;
		return;
	}

	const std::uint64_t ept_data = *reinterpret_cast<std::uint64_t*>(per_vp + eptp_table::ptr_offset);
	if (capture_diag) optb_diag_ept_data = ept_data;
	if (ept_data == 0)
	{
		if (capture_diag) optb_diag_bail = 3;
		return;
	}

	const std::uint32_t count = *reinterpret_cast<std::uint32_t*>(ept_data + eptp_table::count_offset);
	if (capture_diag) optb_diag_count = count;
	if (count == 0 || count > eptp_table::max_entries)
	{
		if (capture_diag) optb_diag_bail = 4;
		return;
	}

	if (capture_diag) optb_diag_bail = 5; // success

	const std::uint64_t pml4_pa = use_hook_cr3
		? (hook_slat_cr3.address_of_page_directory << 12)
		: (hyperv_slat_cr3.address_of_page_directory << 12);

	// Log once per enable cycle (first VP to run logs the table details)
	static volatile std::uint8_t logged_enable = 0;
	static volatile std::uint8_t logged_disable = 0;

	if (use_hook_cr3 && !logged_enable)
	{
		_InterlockedExchange8(reinterpret_cast<volatile char*>(&logged_enable), 1);
		logged_disable = 0;
		serial::print("[optB] patching EPTP source table: count=");
		serial::print_dec(count);
		serial::print(" ept_data=");
		serial::print_hex(ept_data);
		serial::print(" pml4_pa=");
		serial::print_hex(pml4_pa);
		serial::println("");
	}
	else if (!use_hook_cr3 && !logged_disable)
	{
		_InterlockedExchange8(reinterpret_cast<volatile char*>(&logged_disable), 1);
		logged_enable = 0;
		serial::print("[optB] restoring EPTP source table: count=");
		serial::print_dec(count);
		serial::println("");
	}

	for (std::uint32_t i = 0; i < count; i++)
	{
		auto* const entry = reinterpret_cast<volatile std::uint64_t*>(
			ept_data + eptp_table::first_offset + eptp_table::entry_stride * i);

		// Preserve EPTP metadata bits [11:0] (memory type, page-walk length, A/D enable).
		// Only replace PML4 PA in bits [51:12].
		const std::uint64_t current = *entry;
		const std::uint64_t metadata = current & 0xFFF;
		*entry = pml4_pa | metadata;
	}
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
	// Preserve current VMCS EPTP metadata bits [11:0] (memory type, page-walk-length, A/D).
	// Only replace PML4 PFN. Writing stale metadata can cause VM-entry failure → HYPERVISOR_ERROR.
	cr3 target = arch::get_slat_cr3();
	target.address_of_page_directory = slat_cr3.address_of_page_directory;
	arch::set_slat_cr3(target);

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

// Boot mode flag: suppress NMI broadcasts during boot-time EPT setup.
volatile std::uint8_t slat::suppress_nmi_broadcast = 0;

void slat::flush_all_logical_processors_cache()
{
	flush_current_logical_processor_cache();

	// During boot, skip NMI broadcast: no VP is on hook_cr3, so the TLB flush is
	// unnecessary. Lazy INVEPT (hook_cr3_ept_dirty) handles it when VPs switch later.
	// Sending NMIs during early boot causes guest NMI handler to fire unexpectedly
	// → potential bugcheck/freeze (no display driver loaded yet).
	if (suppress_nmi_broadcast)
	{
		mark_all_lps_dirty();
		return;
	}

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
	serial::println("[cr3] set_up_hook_cr3: START");

	set_up_slat_cr3(&hook_slat_cr3, &hook_slat_pml4);

	serial::print("[cr3] hook_cr3 PML4 PA=");
	serial::print_hex(hook_slat_cr3.address_of_page_directory << 12);
	serial::println("");

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
	// Hook 3 activation DEFERRED — do NOT activate here.
	// At this point, EPT hooks (MmClean) may already have shadow pages with JMPs to hidden memory,
	// but hidden region isn't mapped yet (only exists in target's clone CR3 after inject_dll).
	// Activating Hook 3 here would force ALL VPs on hook_cr3 → non-target processes hit shadow
	// → JMP to unmapped hidden VA → #PF → double fault (0x7F).
	// Hook 3 is activated via hypercall (reserved_data=32) after full inject flow completes.

	_InterlockedExchange8(reinterpret_cast<volatile char*>(&hook_cr3_ready), 1);
	serial::println("[cr3] set_up_hook_cr3: DONE, hook_cr3_ready=1");
}

void slat::set_vmwrite_hook_cave_pa(const std::uint64_t pa)
{
	vmwrite_hook_cave_physical_address = pa;
}

void slat::activate_vmwrite_hook(const bool enable)
{
	if (vmwrite_hook_cave_physical_address == 0)
		return;

	auto* const cave = static_cast<std::uint8_t*>(
		memory_manager::map_host_physical(vmwrite_hook_cave_physical_address));

	if (enable)
	{
		// Reset write-once diag flag so this cycle captures fresh values
		_InterlockedExchange(&optb_diag_captured, 0);

		serial::println("[hook3] activate_vmwrite_hook: ENABLING");
		serial::print("[hook3] hyperv_cr3 PFN="); serial::print_hex(hyperv_slat_cr3.address_of_page_directory); serial::println("");
		serial::print("[hook3] hook_cr3 PFN="); serial::print_hex(hook_slat_cr3.address_of_page_directory); serial::println("");

		// Dump dirty flag state before activation
		serial::print("[hook3] dirty flags: ");
		for (std::uint16_t i = 0; i < 8 && i < max_logical_processors; i++)
		{
			serial::print_dec(hook_cr3_ept_dirty[i]);
			serial::print(" ");
		}
		serial::println("");

		// CRITICAL: Write SLOT2 (replacement value) BEFORE SLOT1 (enable gate).
		// SLOT1 != 0 enables the hook. If SLOT1 is written first, another VP could see
		// SLOT1=active + SLOT2=0 → EPTP with PFN=0 → VM-entry failure → HYPERVISOR_ERROR.
		// With SLOT2 first, other VPs still see SLOT1=0 → passthrough (safe).

		// PATCH_SLOT_2 at cave+39: hook_cr3 physical address (PFN << 12) — replacement EPTP base
		*reinterpret_cast<std::uint64_t*>(cave + 39) = hook_slat_cr3.address_of_page_directory << 12;

		// PATCH_SLOT_1 at cave+4: hyperv_cr3 PFN — shellcode checks this to identify EPTP writes
		*reinterpret_cast<std::uint64_t*>(cave + 4) = hyperv_slat_cr3.address_of_page_directory;

		_InterlockedExchange8(reinterpret_cast<volatile char*>(&vmwrite_hook_active), 1);

		// [REMOVED] Option B: patch_eptp_source_table deferred via NMI.
		// No longer needed: HvSetEptPointer entry hook (shellcode) swaps PFN in [RCX]
		// before the function runs → HV writes hook_cr3 to enlightened VMCS page natively.
		// Both lazy cache (+0x270) and dirty bit (+0x338) are consistent.

		// Force ALL VPs onto hook_cr3. Safe now: all hooks use ntoskrnl shadow code pages
		// (kernel VA, accessible to all processes). No hidden memory dependency.
		// IMPORTANT: consume dirty flag for THIS LP before switching to hook_cr3.
		// Boot suppressed NMI broadcasts → dirty flags still set → stale TLB.
		{
			const auto vpid = arch::get_current_vpid();
			serial::print("[hook3] this VP vpid="); serial::print_dec(vpid);
			serial::print(" dirty="); serial::print_dec(vpid < max_logical_processors ? hook_cr3_ept_dirty[vpid] : 99);
			serial::println("");
			if (vpid < max_logical_processors && hook_cr3_ept_dirty[vpid])
			{
				serial::println("[hook3] consuming dirty flag for this VP (INVEPT)");
				hook_cr3_ept_dirty[vpid] = 0;
			}
		}
		set_cr3(hook_slat_cr3);
		// NOTE: set_cr3 already calls flush_current_logical_processor_cache(1) internally
		serial::println("[hook3] this VP on hook_cr3 + INVEPT done");

		// NMI broadcast: force every other LP onto hook_cr3 as well.
		// NMI handler checks vmwrite_hook_active and forces hook_cr3.
		interrupts::set_all_nmi_ready();
		interrupts::send_nmi_all_but_self();
		serial::println("[hook3] NMI broadcast sent, Hook 3 ACTIVE");
	}
	else
	{
		serial::println("[hook3] activate_vmwrite_hook: DISABLING");

		// Zero SLOT1 → shellcode's test rdx,rdx; jz .skip → passthrough
		*reinterpret_cast<std::uint64_t*>(cave + 4) = 0;

		_InterlockedExchange8(reinterpret_cast<volatile char*>(&vmwrite_hook_active), 0);

		// NMI broadcast: force VMEXITs on all VPs. With SLOT1=0, shellcode passes
		// through → next HvSetEptPointer call writes hyperv_cr3 → VPs drift back naturally.
		interrupts::set_all_nmi_ready();
		interrupts::send_nmi_all_but_self();

		serial::println("[hook3] Hook 3 DISABLED, VPs will drift back to hyperv_cr3");
	}
}

bool slat::is_vmwrite_hook_active()
{
	return vmwrite_hook_active != 0;
}

std::uint64_t slat::read_vmwrite_hook_counter()
{
	// No in-cave counter — .text is read-only at runtime, lock inc would fault.
	// Use Hook 2 diagnostic counters (hook3_on_hook_cr3_count etc.) instead.
	return 0;
}

std::uint64_t slat::read_vmwrite_hook_slot1()
{
	if (vmwrite_hook_cave_physical_address == 0)
		return 0;

	const auto* const cave = static_cast<const std::uint8_t*>(
		memory_manager::map_host_physical(vmwrite_hook_cave_physical_address));

	return *reinterpret_cast<const std::uint64_t*>(cave + 4);
}

std::uint64_t slat::read_vmwrite_hook_slot2()
{
	if (vmwrite_hook_cave_physical_address == 0)
		return 0;

	const auto* const cave = static_cast<const std::uint8_t*>(
		memory_manager::map_host_physical(vmwrite_hook_cave_physical_address));

	return *reinterpret_cast<const std::uint64_t*>(cave + 39);
}

std::uint64_t slat::read_vmwrite_hook_cave_pa()
{
	return vmwrite_hook_cave_physical_address;
}

