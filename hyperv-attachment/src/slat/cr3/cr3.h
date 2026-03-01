#pragma once
#include <ia32-doc/ia32.hpp>
#include <cstdint>

namespace slat
{
	cr3 hyperv_cr3();
	cr3 hook_cr3();

	cr3 get_cr3();
	void set_cr3(cr3 slat_cr3);

	// Check if an EPTP belongs to our VTL 0 context (hyperv_cr3 or hook_cr3 PML4)
	// Returns false for VTL 1 or unknown EPTPs — these must not be modified
	bool is_our_eptp(cr3 current_eptp);

	void flush_current_logical_processor_cache(std::uint8_t has_slat_cr3_changed = 0);
	void flush_all_logical_processors_cache();

	// Boot mode: suppress NMI broadcasts in flush_all_logical_processors_cache().
	// During boot, no VP is on hook_cr3 — broadcasting NMIs to flush EPT TLBs is
	// unnecessary AND harmful (guest receives unexpected NMIs → bugcheck with no display).
	// Lazy INVEPT flags (hook_cr3_ept_dirty) ensure TLBs are flushed when VPs switch later.
	extern volatile std::uint8_t suppress_nmi_broadcast;

	void set_up_hyperv_cr3();
	void set_up_hook_cr3();

	// ring-1 style: update saved hyperv EPTP if Hyper-V changed it (VTL transition, etc.)
	void update_hyperv_cr3(cr3 new_eptp);

	// True after set_up_hook_cr3() fully completes (PML4 copied, heap hidden).
	// Hook 2 must check this before bootstrapping VPs to hook_cr3.
	bool is_hook_cr3_ready();

	// Sync PML4 entries from hyperv_cr3 to hook_cr3.
	// Must be called after Hyper-V's handler modifies EPT while on hyperv_cr3,
	// before restoring hook_cr3 as the active EPTP.
	void sync_hook_pml4_from_hyperv();

	// Hook 3 (VMWRITE EPT_POINTER redirect): patches the code cave in hvix64 to
	// replace hyperv_cr3 PFN → hook_cr3 PFN so VP stays on hook_cr3 permanently.
	void set_vmwrite_hook_cave_pa(std::uint64_t pa);
	void activate_vmwrite_hook(bool enable);
	bool is_vmwrite_hook_active();
	std::uint64_t read_vmwrite_hook_counter();
	std::uint64_t read_vmwrite_hook_slot1();
	std::uint64_t read_vmwrite_hook_slot2();
	std::uint64_t read_vmwrite_hook_cave_pa();

	// Option B: Patch EPTP source table so HvGetEptPointer returns hook_cr3.
	// Must be called per-VP (reads gs:per_vp for current VP's table).
	// use_hook_cr3=true → write hook_cr3 PML4 PA; false → restore hyperv_cr3 PML4 PA.
	void patch_eptp_source_table(bool use_hook_cr3);

	// NMI action for EPTP source table: 0=none, 1=patch(hook_cr3), 2=restore(hyperv_cr3)
	extern volatile std::uint8_t eptp_table_nmi_action;

	// Deferred table patch: set by Hook 1 (bad GS context), consumed by Hook 2 (GS valid).
	// 1 = patch pending (hook_cr3), 0 = nothing pending.
	extern volatile std::uint8_t eptp_table_patch_pending;

	// Option B diagnostics (readable via hypercall sub_cmd 10-17)
	// bail_reason: 0=not called, 1=gs_offset=0, 2=per_vp=0, 3=ept_data=0, 4=bad count, 5=success
	extern volatile std::uint64_t optb_diag_bail;
	extern volatile std::uint64_t optb_diag_per_vp;
	extern volatile std::uint64_t optb_diag_ept_data;
	extern volatile std::uint64_t optb_diag_count;
	// Deep GS diagnostics (sub_cmd 14-17): understand WHY per_vp=0
	extern volatile std::uint64_t optb_diag_gs_base;         // 14: IA32_GS_BASE MSR value
	extern volatile std::uint64_t optb_diag_manual_read;     // 15: *(uint64*)(gs_base + gs_offset) direct ptr read
	extern volatile std::uint64_t optb_diag_gs_first_qword;  // 16: *(uint64*)(gs_base) first qword at GS base
	extern volatile std::uint64_t optb_diag_host_gs_base;    // 17: VMCS HOST_GS_BASE field

	// Lazy INVEPT: per-LP dirty flags for hook_cr3 EPT modifications.
	// When hook_cr3's EPT is modified (hook::add, fork, monitor, etc.),
	// mark all LPs dirty. Hook 1/2 only INVEPT on swap if this LP is dirty.
	constexpr std::uint16_t max_logical_processors = 256;
	extern volatile std::uint8_t hook_cr3_ept_dirty[max_logical_processors];
	void mark_all_lps_dirty();
} 
