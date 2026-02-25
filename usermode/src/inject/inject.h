#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <print>
#include <cstdint>

#include "../hypercall/hypercall.h"
#include "../system/system.h"
#include "../hook/hook.h"
#include "../hook/kernel_detour_holder.h"
#include <hypercall/hypercall_def.h>

namespace inject
{

// forward declare — full definition in the syscall exit hook section

//=============================================================================
// PE helpers
//=============================================================================

inline bool load_dll_file(const std::string& path, std::vector<uint8_t>& out_data)
{
	if (!std::filesystem::exists(path))
	{
		std::println("[-] DLL file not found: {}", path);
		return false;
	}

	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file.is_open()) return false;

	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);
	out_data.resize(size);
	return file.read(reinterpret_cast<char*>(out_data.data()), size).good();
}

inline PVOID rva_to_va(uintptr_t rva, PIMAGE_NT_HEADERS64 nt_headers, PVOID local_image)
{
	auto section = IMAGE_FIRST_SECTION(nt_headers);
	for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
	{
		if (rva >= section->VirtualAddress &&
		    rva < section->VirtualAddress + section->Misc.VirtualSize)
		{
			return (PUCHAR)local_image + section->PointerToRawData + (rva - section->VirtualAddress);
		}
	}
	return nullptr;
}

inline bool relocate_image(PVOID remote_base, PVOID local_image, PIMAGE_NT_HEADERS64 nt_headers)
{
	uintptr_t delta = (uintptr_t)remote_base - nt_headers->OptionalHeader.ImageBase;
	if (delta == 0) return true;

	if (!(nt_headers->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
		return false;

	auto reloc_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!reloc_dir->VirtualAddress || !reloc_dir->Size) return true;

	auto reloc_entry = (PIMAGE_BASE_RELOCATION)rva_to_va(reloc_dir->VirtualAddress, nt_headers, local_image);
	if (!reloc_entry) return true;

	uintptr_t reloc_end = (uintptr_t)reloc_entry + reloc_dir->Size;

	while ((uintptr_t)reloc_entry < reloc_end && reloc_entry->SizeOfBlock)
	{
		DWORD count = (reloc_entry->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD reloc_data = (PWORD)((uintptr_t)reloc_entry + sizeof(IMAGE_BASE_RELOCATION));

		for (DWORD i = 0; i < count; i++)
		{
			WORD type = reloc_data[i] >> 12;
			WORD offset = reloc_data[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_ABSOLUTE) continue;

			PVOID patch_addr = rva_to_va(reloc_entry->VirtualAddress + offset, nt_headers, local_image);
			if (!patch_addr) patch_addr = (PUCHAR)local_image + reloc_entry->VirtualAddress + offset;

			if (type == IMAGE_REL_BASED_HIGHLOW)
			{
				*(DWORD*)patch_addr += (DWORD)delta;
			}
			else if (type == IMAGE_REL_BASED_DIR64)
			{
				*(ULONG64*)patch_addr += delta;
			}
		}

		reloc_entry = (PIMAGE_BASE_RELOCATION)((uintptr_t)reloc_entry + reloc_entry->SizeOfBlock);
	}
	return true;
}

inline uintptr_t get_export_offset(const char* module_name, const char* func_name)
{
	HMODULE h_module = LoadLibraryExA(module_name, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!h_module) return 0;
	auto proc = (uintptr_t)GetProcAddress(h_module, func_name);
	FreeLibrary(h_module);
	if (proc == 0) return 0;
	return proc - (uintptr_t)h_module;
}

inline bool resolve_imports(PVOID local_image, PIMAGE_NT_HEADERS64 nt_headers)
{
	auto import_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (!import_dir->VirtualAddress || !import_dir->Size) return true;

	auto import_desc = (PIMAGE_IMPORT_DESCRIPTOR)rva_to_va(import_dir->VirtualAddress, nt_headers, local_image);
	if (!import_desc) return true;

	while (import_desc->Name)
	{
		auto module_name = (LPCSTR)rva_to_va(import_desc->Name, nt_headers, local_image);
		if (!module_name) break;

		uintptr_t module_base = (uintptr_t)LoadLibraryA(module_name);
		if (!module_base)
		{
			std::println("[-] Failed to load import module: {}", module_name);
			return false;
		}

		std::uint32_t module_import_count = 0;
		auto thunk = (PIMAGE_THUNK_DATA64)rva_to_va(import_desc->FirstThunk, nt_headers, local_image);
		while (thunk && thunk->u1.AddressOfData)
		{
			if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
			{
				uintptr_t offset = get_export_offset(module_name, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
				if (offset == 0)
				{
					std::println("[-] IMPORT FAIL: {}!Ordinal#{}", module_name, thunk->u1.Ordinal & 0xFFFF);
					return false;
				}
				thunk->u1.Function = module_base + offset;
			}
			else
			{
				auto import_by_name = (PIMAGE_IMPORT_BY_NAME)rva_to_va((uintptr_t)thunk->u1.AddressOfData, nt_headers, local_image);
				if (import_by_name)
				{
					uintptr_t offset = get_export_offset(module_name, import_by_name->Name);
					if (offset == 0)
					{
						std::println("[-] IMPORT FAIL: {}!{}", module_name, (const char*)import_by_name->Name);
						return false;
					}
					thunk->u1.Function = module_base + offset;
				}
			}
			module_import_count++;
			thunk++;
		}
		std::println("[+]   {} — {} imports @ base 0x{:X}", module_name, module_import_count, module_base);
		import_desc++;
	}
	return true;
}

// Write sections using physical addresses directly — bypasses clone CR3 guest page walk
// and avoids EPT 2MB split corruption issues during write_guest_virtual_memory.
inline bool write_sections(PVOID local_image, PIMAGE_NT_HEADERS64 nt_headers,
                           std::uint64_t hidden_base_va, std::uint64_t clone_cr3,
                           std::uint64_t image_size, std::uint64_t file_size,
                           const std::vector<std::uint64_t>& hidden_page_pas)
{
	auto section = IMAGE_FIRST_SECTION(nt_headers);
	for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
	{
		if (section->SizeOfRawData == 0) continue;

		// Validate source bounds against actual file size (prevents OOB read on malformed PE)
		if (section->PointerToRawData >= file_size)
			continue;

		// Cap write size to VirtualSize (if available) and SizeOfImage boundary
		std::uint64_t write_size = section->SizeOfRawData;
		if (write_size > file_size - section->PointerToRawData)
			write_size = file_size - section->PointerToRawData;
		if (section->Misc.VirtualSize != 0 && write_size > section->Misc.VirtualSize)
			write_size = section->Misc.VirtualSize;
		if (section->VirtualAddress + write_size > image_size)
			write_size = image_size - section->VirtualAddress;

		auto* src = reinterpret_cast<std::uint8_t*>(local_image) + section->PointerToRawData;

		// Write page by page using physical addresses — no clone CR3 translation needed.
		// This avoids the EPT 2MB page split corruption that causes write_guest_virtual_memory
		// to fail deterministically after N pages when hidden page PAs cross a 2MB EPT boundary.
		std::uint64_t total_written = 0;
		while (total_written < write_size)
		{
			std::uint64_t chunk = write_size - total_written;
			if (chunk > 0x1000) chunk = 0x1000;

			// Compute which hidden page and offset within it
			std::uint64_t dest_offset = section->VirtualAddress + total_written;
			std::uint64_t page_index = dest_offset / 0x1000;
			std::uint64_t page_off = dest_offset & 0xFFF;

			// Cap chunk to not cross a page boundary on destination
			if (page_off + chunk > 0x1000)
				chunk = 0x1000 - page_off;

			if (page_index >= hidden_page_pas.size() || hidden_page_pas[page_index] == 0)
			{
				std::println("[-] Section {:.8s}: page {} not mapped (VA 0x{:X})",
					(char*)section->Name, page_index, dest_offset);
				return false;
			}

			// Force source pages resident by touching them
			volatile std::uint8_t t = src[total_written];
			if (chunk > 1) t = src[total_written + chunk - 1];
			(void)t;

			std::uint64_t written = hypercall::write_guest_physical_memory(
				src + total_written, hidden_page_pas[page_index] + page_off, chunk);

			total_written += written;
			if (written != chunk)
			{
				std::println("[-] Failed to write section {:.8s} ({} / {} bytes, page {} PA 0x{:X}+0x{:X})",
					(char*)section->Name, total_written, write_size, page_index,
					hidden_page_pas[page_index], page_off);
				return false;
			}
		}
	}
	return true;
}

//=============================================================================
// Syscall Exit EPT Hook — trigger DllMain at exact syscall return point
// Hooks KiSystemServiceExit so the trap frame is modified at the moment
// the kernel is done, right before IRETQ/SYSRET. One-shot via CPUID hypercall.
//=============================================================================

// Hijack data struct in hidden memory — only used by DllMain shellcode (usermode)
// original_rip and armed are now handled entirely by the hypervisor (no hidden memory access from ring 0)
typedef struct _HIJACK_DATA {
	INT Status;              // 0=pending, 1=running, 2=done
	INT SubStatus;           // diagnostic: 0x10=pre-RtlAddFnTable, 0x11=pre-entry, 0x12=post-entry
	uintptr_t FnDllMain;
	HINSTANCE DllBase;
	uintptr_t DllMainResult; // return value from _DllMainCRTStartup (0=FALSE, 1=TRUE)
} HIJACK_DATA;

inline std::uint64_t target_pid = 0; // PID of injected process (for watchdog)

inline std::uint64_t ksse_hook_va = 0; // stored for removal
inline std::uint16_t ksse_shellcode_detour_offset = 0; // detour holder allocation for our shellcode

// Build the EPT hook shellcode for KiSystemServiceExit (runs in ring 0)
// Stored in the detour holder page (not in extra_assembled_bytes, to avoid
// displacing 100+ bytes of original code — which breaks RIP-relative fixups).
//
// CRITICAL: NO hidden memory (PML4[70]) access from ring 0!
// The CR3 may be the original (not clone) when this fires.
// PML4[70] only exists in the clone → accessing it under original CR3 = #PF BSOD.
//
// All data exchange with hypervisor via CPUID hypercall:
//   - original_rip passed to handler in RDX (handler saves it)
//   - shellcode_va returned in RAX (handler returns it)
//
// Flow:
//   1. EPROCESS check (kernel memory — always accessible) → mismatch → skip
//   2. Read TrapFrame.Rip (kernel memory — always accessible)
//   3. CPUID atomic claim: pass original_rip in RDX → get shellcode_va in RAX
//   4. Write shellcode_va to TrapFrame.Rip
inline std::vector<uint8_t> build_syscall_exit_hook(
	std::uint64_t target_eprocess,
	std::uint32_t kthread_process_offset,
	std::uint32_t kthread_trapframe_offset)
{
	std::vector<uint8_t> sc;
	sc.reserve(100);

	auto push_u8 = [&](uint8_t b) { sc.push_back(b); };
	auto push_u32 = [&](uint32_t v) {
		for (int i = 0; i < 4; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};
	auto push_u64 = [&](uint64_t v) {
		for (int i = 0; i < 8; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};

	// Build the check_and_clear hypercall info (reserved_data=7 under read_guest_cr3)
	hypercall_info_t hijack_call = {};
	hijack_call.primary_key = hypercall_primary_key;
	hijack_call.secondary_key = hypercall_secondary_key;
	hijack_call.call_type = hypercall_type_t::read_guest_cr3;
	hijack_call.call_reserved_data = 7;
	std::uint32_t hijack_call_value = static_cast<std::uint32_t>(hijack_call.value);

	// push rax, rcx, rdx, rbx
	push_u8(0x50); // push rax
	push_u8(0x51); // push rcx
	push_u8(0x52); // push rdx
	push_u8(0x53); // push rbx

	// === Stage 1: EPROCESS check (kernel memory, always accessible) ===

	// mov rax, gs:[0x188]  — KPCR.CurrentThread
	push_u8(0x65); push_u8(0x48); push_u8(0x8B); push_u8(0x04); push_u8(0x25);
	push_u8(0x88); push_u8(0x01); push_u8(0x00); push_u8(0x00);

	// mov rcx, [rax + kthread_process_offset]  — KTHREAD.Process → EPROCESS
	push_u8(0x48); push_u8(0x8B); push_u8(0x88);
	push_u32(kthread_process_offset);

	// movabs rdx, <target_eprocess>
	push_u8(0x48); push_u8(0xBA);
	push_u64(target_eprocess);

	// cmp rcx, rdx
	push_u8(0x48); push_u8(0x3B); push_u8(0xCA);

	// jne .skip
	push_u8(0x75);
	const std::size_t jne1_pos = sc.size();
	push_u8(0x00); // placeholder

	// === Stage 2: Read TrapFrame.Rip (kernel memory, always accessible) ===

	// mov rcx, [rax + kthread_trapframe_offset]  — TrapFrame ptr
	push_u8(0x48); push_u8(0x8B); push_u8(0x88);
	push_u32(kthread_trapframe_offset);

	// mov rdx, [rcx + 0x168]  — original TrapFrame.Rip → RDX (passed to CPUID handler)
	push_u8(0x48); push_u8(0x8B); push_u8(0x91);
	push_u32(0x168);

	// === Stage 3: CPUID atomic claim (one VMEXIT, happens once) ===
	// RDX = original_rip (handler saves it)
	// Handler returns shellcode_va in RAX (or 0 if not armed / already claimed)

	// mov ecx, <hijack_call_value>
	push_u8(0xB9);
	push_u32(hijack_call_value);

	// cpuid  — VMEXIT: handler reads RDX, atomically disarms, returns shellcode_va
	push_u8(0x0F); push_u8(0xA2);

	// test rax, rax  (0 = not armed or race lost)
	push_u8(0x48); push_u8(0x85); push_u8(0xC0);

	// jz .skip
	push_u8(0x74);
	const std::size_t jz_cpuid_pos = sc.size();
	push_u8(0x00); // placeholder

	// === Stage 4: Claimed! RAX = shellcode_va ===

	// Re-read CurrentThread → TrapFrame (CPUID handler didn't clobber RCX/RDX
	// but ECX was set to hijack_call_value, so re-read to be safe)
	// mov rcx, gs:[0x188]
	push_u8(0x65); push_u8(0x48); push_u8(0x8B); push_u8(0x0C); push_u8(0x25);
	push_u8(0x88); push_u8(0x01); push_u8(0x00); push_u8(0x00);

	// mov rcx, [rcx + kthread_trapframe_offset]  — TrapFrame ptr
	push_u8(0x48); push_u8(0x8B); push_u8(0x89);
	push_u32(kthread_trapframe_offset);

	// mov [rcx + 0x168], rax  — overwrite TrapFrame.Rip = shellcode_va
	push_u8(0x48); push_u8(0x89); push_u8(0x81);
	push_u32(0x168);

	// .skip:
	const std::size_t skip_pos = sc.size();

	// pop rbx, rdx, rcx, rax
	push_u8(0x5B); // pop rbx
	push_u8(0x5A); // pop rdx
	push_u8(0x59); // pop rcx
	push_u8(0x58); // pop rax

	// Patch jump offsets
	sc[jne1_pos] = static_cast<uint8_t>(skip_pos - (jne1_pos + 1));
	sc[jz_cpuid_pos] = static_cast<uint8_t>(skip_pos - (jz_cpuid_pos + 1));

	return sc;
}

// Build the NtClose relay shellcode — dual-mode ring-0 shellcode:
//   Hijack mode: same EPROCESS check + CPUID(7) atomic claim + TrapFrame.Rip overwrite
//   Relay mode:  magic handle check (TrapFrame.Rcx == 0xDEAD1337) → load command
//                params from TrapFrame registers → CPUID(20) → early RET with result in RAX
//                (short-circuits NtClose — no STATUS_INVALID_HANDLE overwrite)
//
// This replaces build_syscall_exit_hook for the NtClose hook. After DllMain completes,
// the NtClose hook stays alive for relay communication between DLL and hypervisor.
//
// KTRAP_FRAME offsets are resolved from PDB at startup (sys::offsets::ktrap_frame_*).
inline std::vector<uint8_t> build_ntclose_relay_shellcode(
	std::uint64_t target_eprocess,
	std::uint32_t kthread_process_offset,
	std::uint32_t kthread_trapframe_offset,
	std::uint32_t tf_rcx_off,   // KTRAP_FRAME.Rcx offset
	std::uint32_t tf_rdx_off,   // KTRAP_FRAME.Rdx offset
	std::uint32_t tf_r8_off,    // KTRAP_FRAME.R8  offset
	std::uint32_t tf_r9_off,    // KTRAP_FRAME.R9  offset
	std::uint32_t tf_rip_off)   // KTRAP_FRAME.Rip offset
{
	std::vector<uint8_t> sc;
	sc.reserve(180);

	auto push_u8 = [&](uint8_t b) { sc.push_back(b); };
	auto push_u32 = [&](uint32_t v) {
		for (int i = 0; i < 4; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};
	auto push_u64 = [&](uint64_t v) {
		for (int i = 0; i < 8; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};

	// Build CPUID leaf values for both modes
	hypercall_info_t hijack_call = {};
	hijack_call.primary_key = hypercall_primary_key;
	hijack_call.secondary_key = hypercall_secondary_key;
	hijack_call.call_type = hypercall_type_t::read_guest_cr3;
	hijack_call.call_reserved_data = 7; // check_and_clear_syscall_hijack
	std::uint32_t cpuid7_value = static_cast<std::uint32_t>(hijack_call.value);

	hypercall_info_t relay_call = {};
	relay_call.primary_key = hypercall_primary_key;
	relay_call.secondary_key = hypercall_secondary_key;
	relay_call.call_type = hypercall_type_t::read_guest_cr3;
	relay_call.call_reserved_data = 20; // process_command
	std::uint32_t cpuid20_value = static_cast<std::uint32_t>(relay_call.value);

	// === Save registers ===
	push_u8(0x50); // push rax
	push_u8(0x51); // push rcx
	push_u8(0x52); // push rdx
	push_u8(0x53); // push rbx

	// === Stage 1: EPROCESS check ===
	// mov rax, gs:[0x188]  — KPCR.CurrentThread
	push_u8(0x65); push_u8(0x48); push_u8(0x8B); push_u8(0x04); push_u8(0x25);
	push_u8(0x88); push_u8(0x01); push_u8(0x00); push_u8(0x00);

	// mov rcx, [rax + kthread_process_offset]
	push_u8(0x48); push_u8(0x8B); push_u8(0x88);
	push_u32(kthread_process_offset);

	// movabs rdx, <target_eprocess>
	push_u8(0x48); push_u8(0xBA);
	push_u64(target_eprocess);

	// cmp rcx, rdx
	push_u8(0x48); push_u8(0x3B); push_u8(0xCA);

	// jne .skip
	push_u8(0x75);
	const std::size_t jne_eprocess_pos = sc.size();
	push_u8(0x00); // placeholder

	// === Stage 2: Read TrapFrame ptr ===
	// mov rcx, [rax + kthread_trapframe_offset]
	push_u8(0x48); push_u8(0x8B); push_u8(0x88);
	push_u32(kthread_trapframe_offset);

	// === Stage 3: Check magic handle (TrapFrame.Rcx low32) ===
	// mov edx, [rcx + tf_rcx_off]   — TrapFrame.Rcx (NtClose first arg = handle)
	push_u8(0x8B); push_u8(0x91);
	push_u32(tf_rcx_off);

	// cmp edx, 0xDEAD1337
	push_u8(0x81); push_u8(0xFA);
	push_u32(0xDEAD1337);

	// je .relay_mode
	push_u8(0x74);
	const std::size_t je_relay_pos = sc.size();
	push_u8(0x00); // placeholder

	// ============================================================
	// HIJACK MODE — same as build_syscall_exit_hook CPUID(7) flow
	// ============================================================

	// mov rdx, [rcx + tf_rip_off]  — TrapFrame.Rip → RDX (passed to CPUID handler)
	push_u8(0x48); push_u8(0x8B); push_u8(0x91);
	push_u32(tf_rip_off);

	// mov ecx, <cpuid7_value>
	push_u8(0xB9);
	push_u32(cpuid7_value);

	// cpuid
	push_u8(0x0F); push_u8(0xA2);

	// test rax, rax  (0 = not armed, skip)
	push_u8(0x48); push_u8(0x85); push_u8(0xC0);

	// jz .skip
	push_u8(0x74);
	const std::size_t jz_cpuid7_pos = sc.size();
	push_u8(0x00); // placeholder

	// Claimed! RAX = shellcode_va. Re-read TrapFrame.
	// mov rcx, gs:[0x188]
	push_u8(0x65); push_u8(0x48); push_u8(0x8B); push_u8(0x0C); push_u8(0x25);
	push_u8(0x88); push_u8(0x01); push_u8(0x00); push_u8(0x00);

	// mov rcx, [rcx + kthread_trapframe_offset]
	push_u8(0x48); push_u8(0x8B); push_u8(0x89);
	push_u32(kthread_trapframe_offset);

	// mov [rcx + tf_rip_off], rax  — overwrite TrapFrame.Rip
	push_u8(0x48); push_u8(0x89); push_u8(0x81);
	push_u32(tf_rip_off);

	// jmp .skip
	push_u8(0xEB);
	const std::size_t jmp_skip_pos = sc.size();
	push_u8(0x00); // placeholder

	// ============================================================
	// RELAY MODE — load command params from TrapFrame, CPUID(20),
	//              then early RET to short-circuit NtClose.
	//              Result stays in RAX → system service dispatcher
	//              returns it to usermode.
	// ============================================================
	const std::size_t relay_mode_pos = sc.size();

	// rcx = TrapFrame ptr (still valid from stage 2)

	// mov rdx, [rcx + tf_rdx_off]   — TrapFrame.Rdx = command ID
	push_u8(0x48); push_u8(0x8B); push_u8(0x91);
	push_u32(tf_rdx_off);

	// mov r8, [rcx + tf_r8_off]    — TrapFrame.R8 = arg1
	push_u8(0x4C); push_u8(0x8B); push_u8(0x81);
	push_u32(tf_r8_off);

	// mov r9, [rcx + tf_r9_off]    — TrapFrame.R9 = arg2
	push_u8(0x4C); push_u8(0x8B); push_u8(0x89);
	push_u32(tf_r9_off);

	// mov ecx, <cpuid20_value>
	push_u8(0xB9);
	push_u32(cpuid20_value);

	// cpuid — VMEXIT → hypervisor dispatches process_command
	push_u8(0x0F); push_u8(0xA2);

	// RAX = command result from hypervisor.
	// Short-circuit NtClose: pop saved regs, skip saved rax, ret.
	// NtClose never executes → no STATUS_INVALID_HANDLE overwrite.
	// The system service dispatcher sees our RAX as NtClose's return value.
	push_u8(0x5B);                                     // pop rbx (restore)
	push_u8(0x5A);                                     // pop rdx (restore)
	push_u8(0x59);                                     // pop rcx (restore)
	push_u8(0x48); push_u8(0x83); push_u8(0xC4); push_u8(0x08); // add rsp, 8 (skip saved rax, keep result)
	push_u8(0xC3);                                     // ret → return to service dispatcher

	// .skip: (hijack mode + non-target fallthrough)
	const std::size_t skip_pos = sc.size();

	// pop rbx, rdx, rcx, rax
	push_u8(0x5B);
	push_u8(0x5A);
	push_u8(0x59);
	push_u8(0x58);

	// Patch jump offsets
	sc[jne_eprocess_pos] = static_cast<uint8_t>(skip_pos - (jne_eprocess_pos + 1));
	sc[je_relay_pos] = static_cast<uint8_t>(relay_mode_pos - (je_relay_pos + 1));
	sc[jz_cpuid7_pos] = static_cast<uint8_t>(skip_pos - (jz_cpuid7_pos + 1));
	sc[jmp_skip_pos] = static_cast<uint8_t>(skip_pos - (jmp_skip_pos + 1));

	return sc;
}

// Build the usermode DllMain shellcode (runs in user mode, hidden memory)
// Hypervisor writes original_rip directly into the stub's jmp placeholder
// during the CPUID(7) atomic claim — no usermode CPUID needed
inline std::vector<uint8_t> build_dllmain_shellcode(
	std::uint64_t dll_base, std::uint64_t entry_point_va,
	std::uint64_t data_va, std::uint16_t& out_rip_placeholder_offset,
	std::uint64_t rtl_add_fn_table_addr = 0,
	std::uint64_t pdata_va = 0,
	std::uint32_t pdata_entry_count = 0,
	bool skip_dllmain = false)
{
	std::vector<uint8_t> sc;
	sc.reserve(200);

	auto push_u8 = [&](uint8_t b) { sc.push_back(b); };
	auto push_u32 = [&](uint32_t v) {
		for (int i = 0; i < 4; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};
	auto push_u64 = [&](uint64_t v) {
		for (int i = 0; i < 8; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};

	// === Context save ===
	push_u8(0x9C);                   // pushfq
	push_u8(0x50);                   // push rax
	push_u8(0x51);                   // push rcx
	push_u8(0x52);                   // push rdx
	push_u8(0x53);                   // push rbx
	push_u8(0x6A); push_u8(0xFF);   // push -1 (rsp placeholder)
	push_u8(0x55);                   // push rbp
	push_u8(0x56);                   // push rsi
	push_u8(0x57);                   // push rdi
	push_u8(0x41); push_u8(0x50);   // push r8
	push_u8(0x41); push_u8(0x51);   // push r9
	push_u8(0x41); push_u8(0x52);   // push r10
	push_u8(0x41); push_u8(0x53);   // push r11
	push_u8(0x41); push_u8(0x54);   // push r12
	push_u8(0x41); push_u8(0x55);   // push r13
	push_u8(0x41); push_u8(0x56);   // push r14
	push_u8(0x41); push_u8(0x57);   // push r15

	// === Write Status = 1 (shellcode started, before DllMain) ===
	push_u8(0x48); push_u8(0xB9); push_u64(data_va);      // movabs rcx, data_va
	push_u8(0xC7); push_u8(0x01); push_u32(1);              // mov dword [rcx], 1

	if (!skip_dllmain)
	{
		// === Stack alignment ===
		push_u8(0x48); push_u8(0x89); push_u8(0xE3);           // mov rbx, rsp
		push_u8(0x48); push_u8(0x83); push_u8(0xE4); push_u8(0xF0); // and rsp, -16
		push_u8(0x48); push_u8(0x83); push_u8(0xEC); push_u8(0x30); // sub rsp, 0x30

		// SubStatus = 0x11 (about to call entry point)
		push_u8(0x48); push_u8(0xB9); push_u64(data_va);                  // movabs rcx, data_va
		push_u8(0xC7); push_u8(0x41); push_u8(0x04); push_u32(0x11);      // mov dword [rcx+4], 0x11

		// === Call _DllMainCRTStartup(hModule, DLL_PROCESS_ATTACH, NULL) ===
		push_u8(0x48); push_u8(0xB9); push_u64(dll_base);      // movabs rcx, dll_base (hModule)
		push_u8(0xBA); push_u32(1);                              // mov edx, 1 (DLL_PROCESS_ATTACH)
		push_u8(0x45); push_u8(0x33); push_u8(0xC0);           // xor r8d, r8d (lpReserved=NULL)
		push_u8(0x48); push_u8(0xB8); push_u64(entry_point_va); // movabs rax, entry_point
		push_u8(0xFF); push_u8(0xD0);                           // call rax

		// === Capture return value + SubStatus = 0x12 (entry returned) ===
		push_u8(0x48); push_u8(0xB9); push_u64(data_va);                  // movabs rcx, data_va
		push_u8(0x48); push_u8(0x89); push_u8(0x41); push_u8(0x18);      // mov [rcx+0x18], rax (DllMainResult @ offset 24)
		push_u8(0xC7); push_u8(0x41); push_u8(0x04); push_u32(0x12);      // mov dword [rcx+4], 0x12 (SubStatus: post-entry)
	}

	// === Write Status = 2 (DllMain completed / skipped) ===
	push_u8(0x48); push_u8(0xB9); push_u64(data_va);       // movabs rcx, data_va
	push_u8(0xC7); push_u8(0x01); push_u32(2);              // mov dword [rcx], 2

	// === Context restore ===
	if (!skip_dllmain)
	{
		push_u8(0x48); push_u8(0x89); push_u8(0xDC);       // mov rsp, rbx
	}

	push_u8(0x41); push_u8(0x5F);   // pop r15
	push_u8(0x41); push_u8(0x5E);   // pop r14
	push_u8(0x41); push_u8(0x5D);   // pop r13
	push_u8(0x41); push_u8(0x5C);   // pop r12
	push_u8(0x41); push_u8(0x5B);   // pop r11
	push_u8(0x41); push_u8(0x5A);   // pop r10
	push_u8(0x41); push_u8(0x59);   // pop r9
	push_u8(0x41); push_u8(0x58);   // pop r8
	push_u8(0x5F);                   // pop rdi
	push_u8(0x5E);                   // pop rsi
	push_u8(0x5D);                   // pop rbp
	push_u8(0x48); push_u8(0x83); push_u8(0xC4); push_u8(0x08); // add rsp, 8 (skip rsp placeholder)
	push_u8(0x5B);                   // pop rbx
	push_u8(0x5A);                   // pop rdx
	push_u8(0x59);                   // pop rcx
	push_u8(0x58);                   // pop rax
	push_u8(0x9D);                   // popfq

	// === Jump back to original RIP (written by hypervisor into stub during CPUID(7) claim) ===
	push_u8(0xFF); push_u8(0x25); push_u32(0x00000000);     // jmp [rip+0] — reads next 8 bytes as target
	out_rip_placeholder_offset = static_cast<std::uint16_t>(sc.size());
	push_u64(0);                                              // 8-byte placeholder (hypervisor fills this)

	return sc;
}

// Helper: build a 14-byte absolute jump (push low32 / mov [rsp+4], high32 / ret)
inline std::vector<std::uint8_t> build_abs_jmp(std::uint64_t target)
{
	std::vector<std::uint8_t> jmp;
	jmp.reserve(14);
	jmp.push_back(0x68); // push imm32 (low part)
	for (int i = 0; i < 4; i++) jmp.push_back(static_cast<uint8_t>(target >> (i * 8)));
	jmp.push_back(0xC7); jmp.push_back(0x44); jmp.push_back(0x24); jmp.push_back(0x04); // mov [rsp+4], imm32
	for (int i = 0; i < 4; i++) jmp.push_back(static_cast<uint8_t>(target >> (32 + i * 8)));
	jmp.push_back(0xC3); // ret
	return jmp;
}

// Install EPT hook on KiSystemServiceExit
// Strategy: store full shellcode in the detour holder page, use only a 14-byte
// trampoline as extra_assembled_bytes so only ~28 bytes of original code are
// displaced (instead of ~110, which would break RIP-relative instruction fixups).
//
// Flow: KiSystemServiceExit
//   → [14-byte jmp to shellcode in detour holder]  (extra_assembled_bytes)
//   → [our shellcode runs: EPROCESS check, TrapFrame.Rip overwrite]
//   → [14-byte jmp back to hook_va + 14]           (appended to shellcode)
//   → [14-byte jmp to detour holder original bytes] (add_kernel_hook's jmp_to_detour)
//   → [original displaced ~28 bytes + jmp back]     (normal detour)
inline bool install_syscall_exit_hook(std::uint64_t target_eprocess)
{
	if (sys::offsets::ki_system_service_exit_rva == 0)
	{
		std::println("[-] KiSystemServiceExit RVA not resolved");
		return false;
	}

	if (!sys::kernel::modules_list.contains("ntoskrnl.exe"))
	{
		std::println("[-] ntoskrnl.exe not in modules list");
		return false;
	}

	std::uint64_t ntoskrnl_base = sys::kernel::modules_list["ntoskrnl.exe"].base_address;
	std::uint64_t ksse_va = ntoskrnl_base + sys::offsets::ki_system_service_exit_rva;

	std::println("[+] KiSystemServiceExit VA: 0x{:X}", ksse_va);

	// 1. Build full ring-0 shellcode (NO hidden memory access)
	auto full_shellcode = build_syscall_exit_hook(
		target_eprocess,
		static_cast<std::uint32_t>(sys::offsets::kthread_process),
		static_cast<std::uint32_t>(sys::offsets::kthread_trap_frame));

	// Append 14-byte jmp back to ksse_va + 14 (past the trampoline, hits jmp_to_detour)
	auto return_jmp = build_abs_jmp(ksse_va + 14);
	full_shellcode.insert(full_shellcode.end(), return_jmp.begin(), return_jmp.end());

	std::println("[+] Syscall exit hook shellcode: {} bytes (with return jmp)", full_shellcode.size());

	// 2. Allocate space in detour holder for our shellcode
	void* sc_buffer = kernel_detour_holder::allocate_memory(
		static_cast<std::uint16_t>(full_shellcode.size()));

	if (sc_buffer == nullptr)
	{
		std::println("[-] Failed to allocate detour holder space for shellcode");
		return false;
	}

	ksse_shellcode_detour_offset = kernel_detour_holder::get_allocation_offset(sc_buffer);
	memcpy(sc_buffer, full_shellcode.data(), full_shellcode.size());

	std::uint64_t sc_kernel_va = hook::kernel_detour_holder_base + ksse_shellcode_detour_offset;

	std::println("[+] Shellcode in detour holder at offset 0x{:X} (kernel VA: 0x{:X})",
		ksse_shellcode_detour_offset, sc_kernel_va);

	// 3. Build trampoline: 14-byte jmp to our shellcode in detour holder
	auto trampoline = build_abs_jmp(sc_kernel_va);

	std::println("[+] Trampoline: {} bytes (only ~28 bytes of original code displaced)", trampoline.size());

	// 4. Install EPT hook with minimal displacement
	std::vector<std::uint8_t> post_original_bytes; // empty

	std::uint8_t status = hook::add_kernel_hook(ksse_va, trampoline, post_original_bytes);

	if (status == 1)
	{
		ksse_hook_va = ksse_va;
		std::println("[+] KiSystemServiceExit EPT hook installed at 0x{:X}", ksse_va);

		// Verify shadow page content at offset 0x710
		auto it = hook::kernel_hook_list.find(ksse_va);
		if (it != hook::kernel_hook_list.end())
		{
			std::uint8_t* shadow = static_cast<std::uint8_t*>(it->second.get_mapped_shadow_page());
			std::uint64_t off = ksse_va & 0xFFF;
			std::println("[+] Shadow page verify @ offset 0x{:X}: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
				off,
				shadow[off+0], shadow[off+1], shadow[off+2], shadow[off+3],
				shadow[off+4], shadow[off+5], shadow[off+6], shadow[off+7],
				shadow[off+8], shadow[off+9], shadow[off+10], shadow[off+11],
				shadow[off+12], shadow[off+13]);
			std::println("[+] (should be: 68 xx xx xx xx C7 44 24 04 xx xx xx xx C3 = abs jmp to detour holder shellcode)");
			std::println("[+] Shadow page owner={}, patched_bytes={}", (unsigned)it->second.is_shadow_page_owner, (unsigned)it->second.patched_byte_count);
		}

		return true;
	}

	// Cleanup on failure
	kernel_detour_holder::free_memory(sc_buffer);
	ksse_shellcode_detour_offset = 0;
	std::println("[-] Failed to install KiSystemServiceExit EPT hook");
	return false;
}

inline bool remove_syscall_exit_hook()
{
	if (ksse_hook_va == 0) return false;

	std::uint8_t status = hook::remove_kernel_hook(ksse_hook_va, 1);
	if (status == 1)
	{
		std::println("[+] KiSystemServiceExit EPT hook removed");
		ksse_hook_va = 0;

		// Free our shellcode allocation in detour holder
		if (ksse_shellcode_detour_offset != 0)
		{
			void* sc_alloc = kernel_detour_holder::get_allocation_from_offset(ksse_shellcode_detour_offset);
			kernel_detour_holder::free_memory(sc_alloc);
			ksse_shellcode_detour_offset = 0;
		}

		return true;
	}

	std::println("[-] Failed to remove KiSystemServiceExit EPT hook");
	return false;
}

//=============================================================================
// NtClose EPT Hook — alternative hijack trigger for processes that don't
// go through KiSystemServiceExit (fast-path sysret bypasses the slow path).
// NtClose is universally called by most processes including anti-cheats.
// Reuses the same EPROCESS check + CPUID(7) atomic claim shellcode.
//=============================================================================

inline std::uint64_t ntclose_hook_va = 0;
inline std::uint16_t ntclose_shellcode_detour_offset = 0;

inline bool install_ntclose_hook(std::uint64_t target_eprocess)
{
	if (sys::offsets::nt_close_rva == 0)
	{
		std::println("[-] NtClose RVA not resolved");
		return false;
	}

	if (!sys::kernel::modules_list.contains("ntoskrnl.exe"))
	{
		std::println("[-] ntoskrnl.exe not in modules list");
		return false;
	}

	std::uint64_t ntoskrnl_base = sys::kernel::modules_list["ntoskrnl.exe"].base_address;
	std::uint64_t ntclose_va = ntoskrnl_base + sys::offsets::nt_close_rva;

	std::println("[+] NtClose VA: 0x{:X}", ntclose_va);

	// Build dual-mode relay shellcode: hijack (CPUID 7) + relay (CPUID 20, magic handle)
	auto full_shellcode = build_ntclose_relay_shellcode(
		target_eprocess,
		static_cast<std::uint32_t>(sys::offsets::kthread_process),
		static_cast<std::uint32_t>(sys::offsets::kthread_trap_frame),
		static_cast<std::uint32_t>(sys::offsets::ktrap_frame_rcx),
		static_cast<std::uint32_t>(sys::offsets::ktrap_frame_rdx),
		static_cast<std::uint32_t>(sys::offsets::ktrap_frame_r8),
		static_cast<std::uint32_t>(sys::offsets::ktrap_frame_r9),
		static_cast<std::uint32_t>(sys::offsets::ktrap_frame_rip));

	// Append 14-byte jmp back to ntclose_va + 14 (past the trampoline, hits jmp_to_detour)
	auto return_jmp = build_abs_jmp(ntclose_va + 14);
	full_shellcode.insert(full_shellcode.end(), return_jmp.begin(), return_jmp.end());

	std::println("[+] NtClose relay shellcode: {} bytes (with return jmp)", full_shellcode.size());

	// Allocate space in detour holder
	void* sc_buffer = kernel_detour_holder::allocate_memory(
		static_cast<std::uint16_t>(full_shellcode.size()));

	if (sc_buffer == nullptr)
	{
		std::println("[-] Failed to allocate detour holder space for NtClose shellcode");
		return false;
	}

	ntclose_shellcode_detour_offset = kernel_detour_holder::get_allocation_offset(sc_buffer);
	memcpy(sc_buffer, full_shellcode.data(), full_shellcode.size());

	std::uint64_t sc_kernel_va = hook::kernel_detour_holder_base + ntclose_shellcode_detour_offset;

	std::println("[+] NtClose shellcode in detour holder at offset 0x{:X} (kernel VA: 0x{:X})",
		ntclose_shellcode_detour_offset, sc_kernel_va);

	// Build trampoline: 14-byte jmp to our shellcode
	auto trampoline = build_abs_jmp(sc_kernel_va);

	// Install EPT hook
	std::vector<std::uint8_t> post_original_bytes;

	std::uint8_t status = hook::add_kernel_hook(ntclose_va, trampoline, post_original_bytes);

	if (status == 1)
	{
		ntclose_hook_va = ntclose_va;
		std::println("[+] NtClose EPT hook installed at 0x{:X}", ntclose_va);

		// Verify shadow page content at NtClose offset
		auto it = hook::kernel_hook_list.find(ntclose_va);
		if (it != hook::kernel_hook_list.end())
		{
			std::uint8_t* shadow = static_cast<std::uint8_t*>(it->second.get_mapped_shadow_page());
			std::uint64_t off = ntclose_va & 0xFFF;
			std::println("[+] NtClose shadow page verify @ offset 0x{:X}: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
				off,
				shadow[off+0], shadow[off+1], shadow[off+2], shadow[off+3],
				shadow[off+4], shadow[off+5], shadow[off+6], shadow[off+7],
				shadow[off+8], shadow[off+9], shadow[off+10], shadow[off+11],
				shadow[off+12], shadow[off+13]);
			std::println("[+] NtClose (should be: 68 xx xx xx xx C7 44 24 04 xx xx xx xx C3 = abs jmp to shellcode)");
			std::println("[+] NtClose shadow owner={}, patched_bytes={}, pfn=0x{:X}",
				(unsigned)it->second.is_shadow_page_owner, (unsigned)it->second.patched_byte_count,
				(unsigned long long)it->second.original_page_pfn);

			// Also verify what the ORIGINAL NtClose bytes look like (read from kernel via hypercall)
			std::uint8_t orig_bytes[14] = {};
			hypercall::read_guest_virtual_memory(orig_bytes, ntclose_va, sys::current_cr3, 14);
			std::println("[+] NtClose original via read_gvm: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
				orig_bytes[0], orig_bytes[1], orig_bytes[2], orig_bytes[3],
				orig_bytes[4], orig_bytes[5], orig_bytes[6], orig_bytes[7],
				orig_bytes[8], orig_bytes[9], orig_bytes[10], orig_bytes[11],
				orig_bytes[12], orig_bytes[13]);
			std::println("[+] (read_gvm goes through EPT read path → should see ORIGINAL bytes if hook works, or shadow if read=1)");

			// Verify EPT PTE permissions directly from hypervisor
			std::uint64_t ntclose_gpa = hypercall::translate_guest_virtual_address(ntclose_va, sys::current_cr3);
			std::uint64_t hyperv_pte = hypercall::read_ept_pte(ntclose_gpa, 0); // hyperv_cr3
			std::uint64_t hook_pte = hypercall::read_ept_pte(ntclose_gpa, 1);   // hook_cr3

			auto decode_pte = [](std::uint64_t pte, const char* name) {
				if (pte & (1ull << 3)) // found flag
				{
					bool r = pte & 1, w = (pte >> 1) & 1, x = (pte >> 2) & 1;
					std::uint64_t pfn = pte >> 12;
					std::println("[+] EPT {} PTE: R={} W={} X={} PFN=0x{:X}",
						name, r ? 1 : 0, w ? 1 : 0, x ? 1 : 0, pfn);
				}
				else
				{
					std::println("[!] EPT {} PTE: NOT FOUND (raw=0x{:X})", name, pte);
				}
			};

			decode_pte(hyperv_pte, "hyperv_cr3");
			decode_pte(hook_pte, "hook_cr3");
			std::println("[+] Expected: hyperv_cr3 R=0 W=0 X=1 (shadow PFN), hook_cr3 R=1 W=1 X=0 (original PFN)");
		}

		return true;
	}

	kernel_detour_holder::free_memory(sc_buffer);
	ntclose_shellcode_detour_offset = 0;
	std::println("[-] Failed to install NtClose EPT hook");
	return false;
}

inline bool remove_ntclose_hook()
{
	if (ntclose_hook_va == 0) return false;

	std::uint8_t status = hook::remove_kernel_hook(ntclose_hook_va, 1);
	if (status == 1)
	{
		std::println("[+] NtClose EPT hook removed");
		ntclose_hook_va = 0;

		if (ntclose_shellcode_detour_offset != 0)
		{
			void* sc_alloc = kernel_detour_holder::get_allocation_from_offset(ntclose_shellcode_detour_offset);
			kernel_detour_holder::free_memory(sc_alloc);
			ntclose_shellcode_detour_offset = 0;
		}

		return true;
	}

	std::println("[-] Failed to remove NtClose EPT hook");
	return false;
}

// Main hijack function: installs EPT hook, arms hijack, waits for DllMain completion
inline bool hijack_thread(std::uint64_t clone_cr3, std::uint64_t target_cr3,
                          std::uint64_t target_eprocess,
                          std::uint64_t hidden_base_va, std::uint64_t dll_base,
                          DWORD entry_point_rva, std::uint64_t shellcode_page_index,
                          std::uint64_t shellcode_page_pa,
                          std::uint64_t rtl_add_fn_table_addr = 0,
                          std::uint64_t pdata_va = 0,
                          std::uint32_t pdata_entry_count = 0,
                          bool skip_dllmain = false)
{
	// 1. Shellcode + data layout on the last hidden page
	std::uint64_t shellcode_va = hidden_base_va + (shellcode_page_index * 0x1000);
	std::uint64_t entry_point_va = dll_base + entry_point_rva;

	// Data struct at offset 0x800 on the shellcode page
	std::uint64_t data_va = shellcode_va + 0x800;

	std::println("[+] Shellcode VA: 0x{:X}, Data VA: 0x{:X}", shellcode_va, data_va);
	std::println("[+] DLL entry point: 0x{:X}", entry_point_va);

	// 2. Build usermode DllMain shellcode (hypervisor writes original_rip to stub)
	std::uint16_t rip_placeholder_offset = 0;
	auto shellcode = build_dllmain_shellcode(dll_base, entry_point_va, data_va, rip_placeholder_offset,
		rtl_add_fn_table_addr, pdata_va, pdata_entry_count, skip_dllmain);
	std::println("[+] DllMain shellcode: {} bytes, rip_offset=0x{:X} (skip_dllmain={}, RtlAddFnTable=0x{:X}, pdata_entries={})",
		shellcode.size(), rip_placeholder_offset, skip_dllmain, rtl_add_fn_table_addr, pdata_entry_count);

	// 4. Prepare HIJACK_DATA
	HIJACK_DATA hijack_data = {};
	hijack_data.Status = 0;
	hijack_data.SubStatus = 0;
	hijack_data.FnDllMain = (uintptr_t)entry_point_va;
	hijack_data.DllBase = (HINSTANCE)dll_base;
	hijack_data.DllMainResult = 0;

	// 5. Write shellcode + data to hidden memory using physical addresses
	// (virtual memory ops through clone CR3 fail due to EPT 2MB page walk issues)
	std::uint64_t shellcode_pa = shellcode_page_pa; // PA of the shellcode page
	std::uint64_t data_pa = shellcode_page_pa + 0x800; // data struct at offset 0x800

	std::uint64_t written = hypercall::write_guest_physical_memory(
		shellcode.data(), shellcode_pa, shellcode.size());

	if (written != shellcode.size())
	{
		std::println("[-] Failed to write shellcode ({} / {} bytes)", written, shellcode.size());
		return false;
	}

	written = hypercall::write_guest_physical_memory(
		&hijack_data, data_pa, sizeof(hijack_data));

	if (written != sizeof(hijack_data))
	{
		std::println("[-] Failed to write HIJACK_DATA");
		return false;
	}

	// Verify shellcode was written (physical read)
	uint8_t verify[4] = {};
	hypercall::read_guest_physical_memory(verify, shellcode_pa, 4);
	std::println("[+] Shellcode verify: {:02X} {:02X} {:02X} {:02X} (expected 9C 50 51 52)",
		verify[0], verify[1], verify[2], verify[3]);

	// 6. Install EPT hooks for syscall hijack
	// KiSystemServiceExit (slow path — APCs, callbacks) + NtClose (fast path — universally called)
	// Both hooks use the same EPROCESS check + CPUID(7) atomic claim, so only one fires.
	if (!install_syscall_exit_hook(target_eprocess))
	{
		std::println("[!] WARNING: KiSystemServiceExit EPT hook failed (slow path unavailable)");
	}

	if (!install_ntclose_hook(target_eprocess))
	{
		std::println("[!] WARNING: NtClose EPT hook failed (fast path unavailable)");
	}

	if (ksse_hook_va == 0 && ntclose_hook_va == 0)
	{
		std::println("[-] Both syscall hooks failed — cannot hijack");
		return false;
	}

	// 7. Arm the hijack (hypervisor writes original_rip to stub at rip_placeholder_offset)
	hypercall::arm_syscall_hijack(shellcode_va, rip_placeholder_offset);
	std::println("[+] Syscall hijack armed with shellcode VA 0x{:X}, rip_offset=0x{:X}", shellcode_va, rip_placeholder_offset);

	// 7b. Set up EPT violation diagnostic watch on NtClose physical page
	if (ntclose_hook_va != 0)
	{
		std::uint64_t ntclose_phys = hypercall::translate_guest_virtual_address(ntclose_hook_va, sys::current_cr3);
		std::uint64_t ntclose_pfn = ntclose_phys >> 12;
		hypercall::set_diag_watch_pfn(ntclose_pfn);
		std::println("[+] Diagnostic: watching NtClose PFN 0x{:X} (phys 0x{:X}) for EPT violations", ntclose_pfn, ntclose_phys);
	}

	// 8. Print stats
	std::println("[+] CR3 stats: exits={} swaps={} ept_violations={}",
		hypercall::read_cr3_exit_count(), hypercall::read_cr3_swap_count(),
		hypercall::read_slat_violation_count());

	std::println("[+] Waiting for DllMain (target process will trigger on next syscall return)...");

	// 9. Poll for completion
	HIJACK_DATA remote_status = {};
	bool saw_status_1 = false;
	for (int attempt = 0; attempt < 600; attempt++)
	{
		Sleep(100);
		hypercall::read_guest_physical_memory(&remote_status, data_pa, sizeof(remote_status));

		if (remote_status.Status == 1 && !saw_status_1)
		{
			saw_status_1 = true;
			std::println("[+] CANARY HIT: Status=1 — shellcode is executing! (attempt {})", attempt);
		}

		if (remote_status.Status == 2)
		{
			std::println("[+] DllMain completed! (Status=2, SubStatus=0x{:X}, Result=0x{:X}, attempt {})",
				remote_status.SubStatus, remote_status.DllMainResult, attempt);
			if (remote_status.DllMainResult == 0)
				std::println("[!] WARNING: Entry point returned FALSE — CRT init may have failed");
			break;
		}

		if (attempt % 2 == 1)
		{
			// Check if MmClean cleanup fired (process died)
			std::uint64_t cleanup_count = hypercall::read_cleanup_count();
			if (cleanup_count > 0)
			{
				Beep(1000, 200); Beep(500, 200); // two-tone beep
				std::println("[!] *** MmCleanProcessAddressSpace TRIGGERED (count={}) — process died, hooks auto-cleaned ***", cleanup_count);
				break;
			}

			std::println("[*] Still waiting... Status={}, SubStatus=0x{:X}, swaps={}, cpuid7={}, claimed={}, armed={}, ept_viol={}, ntclose_exec={}, ntclose_rw={}",
				remote_status.Status,
				remote_status.SubStatus,
				hypercall::read_cr3_swap_count(),
				hypercall::read_hijack_cpuid_count(),
				hypercall::read_hijack_claimed_count(),
				hypercall::read_hijack_armed_state(),
				hypercall::read_slat_violation_count(),
				hypercall::read_diag_watch_exec_count(),
				hypercall::read_diag_watch_rw_count());
		}
	}

	// 10. Cleanup: remove KiSystemServiceExit hook, disarm hijack, stop watching
	// Keep NtClose hook alive for relay communication (DLL ↔ hypervisor via magic handle)
	remove_syscall_exit_hook();
	// remove_ntclose_hook();  — kept alive for relay mode
	hypercall::disarm_syscall_hijack();
	hypercall::set_diag_watch_pfn(0);

	if (remote_status.Status != 2)
	{
		std::println("[!] DllMain did not complete (Status={})", remote_status.Status);
		if (saw_status_1)
			std::println("[!] Status=1 was seen — shellcode ran, DllMain CRASHED");
		else
			std::println("[!] Status stayed 0 — EPT hook may not have fired");

		std::println("[+] Final: SubStatus=0x{:X}, DllMainResult=0x{:X}, swaps={} cpuid7={} claimed={} armed={} ept_viol={} ntclose_exec={} ntclose_rw={}",
			remote_status.SubStatus,
			remote_status.DllMainResult,
			hypercall::read_cr3_swap_count(),
			hypercall::read_hijack_cpuid_count(),
			hypercall::read_hijack_claimed_count(),
			hypercall::read_hijack_armed_state(),
			hypercall::read_slat_violation_count(),
			hypercall::read_diag_watch_exec_count(),
			hypercall::read_diag_watch_rw_count());
	}

	return remote_status.Status == 2;
}

//=============================================================================
// KiSystemCall64 Service Exit Hook — Instrumentation Callback Bypass
// Hooks "mov r10, [rbp+0xE8]" in the InstrumentationCallback check path
// of KiSystemCall64. When the sysret address at [rbp+0xE8] is in our
// hidden memory (PML4[70]), we set RAX = [rbp+0xE8] so that the next
// instruction "mov [rbp+0xE8], rax" writes back the ORIGINAL return
// address instead of the InstrumentationCallback pointer.
// Result: syscall returns directly to our code, callback is never invoked.
//=============================================================================

inline std::uint64_t ki_sc64se_hook_va = 0;
inline std::uint16_t ki_sc64se_shellcode_detour_offset = 0;
inline std::uint64_t ki_sc64se_target_eprocess = 0; // stored for CLI re-install

// Build the instrumentation callback bypass shellcode (runs in ring 0)
//
// Two-stage filter (iso ring-1.io):
//   1. EPROCESS check  — early-out for non-target processes (cheap, avoids PML4 math)
//   2. PML4 index check — only bypass callback for syscalls from hidden memory
//
// IMPORTANT: This shellcode includes the two displaced original instructions
// (mov r10, [rbp+disp] + mov [rbp+disp], rax) and returns to hook_va + 14,
// which is ORIGINAL code on the shadow page. This is necessary because external
// branches (jz/jne from InstrumentationCallback NULL check) jump to hook_va + 14.
// Using add_kernel_hook would put jmp_to_detour at offset 14 (28 bytes modified),
// and those branches would incorrectly execute the displaced mov instructions
// (writing RAX=0 to TrapFrame.Rip → BSOD).
//
// Flow:
//   if (KTHREAD.Process != target_eprocess) goto skip;  // not our process
//   if (PML4_INDEX([rbp+disp]) != hidden_pml4_index) goto skip;  // not hidden memory
//   RAX = [rbp+disp]   // bypass: overwrite callback ptr with original return addr
//   skip:
//   mov r10, [rbp+disp]    // displaced original
//   mov [rbp+disp], rax    // displaced original
//   jmp hook_va + 14       // back to original code (where jz/jne also land)
//
inline std::vector<uint8_t> build_ki_syscall64_service_exit_hook(
	std::uint64_t hook_va,
	std::int32_t frame_disp,
	std::uint8_t hidden_pml4_index,
	std::uint64_t target_eprocess,
	std::uint32_t kthread_process_offset)
{
	std::vector<uint8_t> sc;
	sc.reserve(120);

	auto push_u8 = [&](uint8_t b) { sc.push_back(b); };
	auto push_i32 = [&](int32_t v) {
		for (int i = 0; i < 4; i++) sc.push_back(static_cast<uint8_t>(static_cast<uint32_t>(v) >> (i * 8)));
	};
	auto push_u32 = [&](uint32_t v) {
		for (int i = 0; i < 4; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};
	auto push_u64 = [&](uint64_t v) {
		for (int i = 0; i < 8; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};

	// pushfq  — save RFLAGS (cmp modifies flags)
	push_u8(0x9C);

	// push rcx
	push_u8(0x51);

	// push rdx  — needed for EPROCESS comparison
	push_u8(0x52);

	// === Stage 1: EPROCESS check (early-out for non-target processes) ===

	// mov rcx, gs:[0x188]  — KPCR.CurrentThread
	push_u8(0x65); push_u8(0x48); push_u8(0x8B); push_u8(0x0C); push_u8(0x25);
	push_u8(0x88); push_u8(0x01); push_u8(0x00); push_u8(0x00);

	// mov rcx, [rcx + kthread_process_offset]  — KTHREAD.Process → EPROCESS
	push_u8(0x48); push_u8(0x8B); push_u8(0x89);
	push_u32(kthread_process_offset);

	// movabs rdx, <target_eprocess>
	push_u8(0x48); push_u8(0xBA);
	push_u64(target_eprocess);

	// cmp rcx, rdx
	push_u8(0x48); push_u8(0x3B); push_u8(0xCA);

	// jne .skip  — not our process, skip everything
	push_u8(0x75);
	const std::size_t jne_eprocess_pos = sc.size();
	push_u8(0x00); // placeholder

	// === Stage 2: PML4 index check (our process confirmed) ===

	// mov rcx, [rbp + frame_disp]  — load sysret return address
	push_u8(0x48); push_u8(0x8B); push_u8(0x8D);
	push_i32(frame_disp);

	// shr rcx, 39  — extract PML4 index (bits 47:39)
	push_u8(0x48); push_u8(0xC1); push_u8(0xE9); push_u8(0x27);

	// and ecx, 0x1FF  — mask to 9 bits
	push_u8(0x81); push_u8(0xE1); push_u8(0xFF); push_u8(0x01); push_u8(0x00); push_u8(0x00);

	// cmp ecx, <hidden_pml4_index>
	push_u8(0x83); push_u8(0xF9); push_u8(hidden_pml4_index);

	// jne .skip  — not from hidden memory
	push_u8(0x75);
	const std::size_t jne_pml4_pos = sc.size();
	push_u8(0x00); // placeholder

	// === Bypass: set RAX = original return address ===

	// mov rax, [rbp + frame_disp]
	push_u8(0x48); push_u8(0x8B); push_u8(0x85);
	push_i32(frame_disp);

	// .skip:
	const std::size_t skip_pos = sc.size();

	// Patch jne offsets
	sc[jne_eprocess_pos] = static_cast<uint8_t>(skip_pos - (jne_eprocess_pos + 1));
	sc[jne_pml4_pos] = static_cast<uint8_t>(skip_pos - (jne_pml4_pos + 1));

	// pop rdx
	push_u8(0x5A);

	// pop rcx
	push_u8(0x59);

	// popfq  — restore RFLAGS
	push_u8(0x9D);

	// === Displaced original instructions (from hook point) ===
	// mov r10, [rbp + frame_disp]   ; 4C 8B 95 + i32
	push_u8(0x4C); push_u8(0x8B); push_u8(0x95);
	push_i32(frame_disp);

	// mov [rbp + frame_disp], rax   ; 48 89 85 + i32
	push_u8(0x48); push_u8(0x89); push_u8(0x85);
	push_i32(frame_disp);

	// 14-byte abs jmp back to hook_va + 14 (original code, where jz/jne also land)
	auto return_jmp = build_abs_jmp(hook_va + 14);
	sc.insert(sc.end(), return_jmp.begin(), return_jmp.end());

	return sc;
}

// Shadow page management integrated with kernel_hook_list for multi-hook per page support.
// Only 14 bytes modified on the shadow page (trampoline at hook offset).
// Offset 14+ remains original code, so external jz/jne branches land safely.
// If another hook already owns a shadow for this page, reuses it (no new EPT registration).
inline bool install_ki_syscall64_service_exit_hook(std::uint64_t target_eprocess, std::uint64_t hidden_pml4_index = 70)
{
	if (sys::offsets::ki_system_call64_service_exit_rva == 0)
	{
		std::println("[-] KiSystemCall64 service exit RVA not resolved (pattern not found)");
		return false;
	}

	if (!sys::kernel::modules_list.contains("ntoskrnl.exe"))
	{
		std::println("[-] ntoskrnl.exe not in modules list");
		return false;
	}

	std::uint64_t ntoskrnl_base = sys::kernel::modules_list["ntoskrnl.exe"].base_address;
	std::uint64_t hook_va = ntoskrnl_base + sys::offsets::ki_system_call64_service_exit_rva;

	std::println("[+] KiSystemCall64 service exit hook VA: 0x{:X}", hook_va);

	// Store EPROCESS for CLI re-install
	ki_sc64se_target_eprocess = target_eprocess;

	// Build shellcode with EPROCESS + PML4 dual check (includes displaced instructions + return jmp)
	auto full_shellcode = build_ki_syscall64_service_exit_hook(
		hook_va,
		sys::offsets::ki_system_call64_service_exit_disp,
		static_cast<std::uint8_t>(hidden_pml4_index),
		target_eprocess,
		static_cast<std::uint32_t>(sys::offsets::kthread_process));

	std::println("[+] Callback bypass shellcode: {} bytes (frame_disp=0x{:X}, pml4_index={}, eprocess=0x{:X})",
		full_shellcode.size(), sys::offsets::ki_system_call64_service_exit_disp, hidden_pml4_index, target_eprocess);

	// Allocate shellcode in detour holder
	void* sc_buffer = kernel_detour_holder::allocate_memory(
		static_cast<std::uint16_t>(full_shellcode.size()));

	if (sc_buffer == nullptr)
	{
		std::println("[-] Failed to allocate detour holder space for callback bypass shellcode");
		return false;
	}

	ki_sc64se_shellcode_detour_offset = kernel_detour_holder::get_allocation_offset(sc_buffer);
	memcpy(sc_buffer, full_shellcode.data(), full_shellcode.size());

	std::uint64_t sc_kernel_va = hook::kernel_detour_holder_base + ki_sc64se_shellcode_detour_offset;

	std::println("[+] Shellcode in detour holder at offset 0x{:X} (kernel VA: 0x{:X})",
		ki_sc64se_shellcode_detour_offset, sc_kernel_va);

	// === Shadow page setup with same-page detection ===

	std::uint64_t hook_physical = hypercall::translate_guest_virtual_address(hook_va, sys::current_cr3);
	if (hook_physical == 0)
	{
		std::println("[-] Failed to translate hook VA to physical");
		kernel_detour_holder::free_memory(sc_buffer);
		ki_sc64se_shellcode_detour_offset = 0;
		return false;
	}

	std::uint64_t target_pfn = hook_physical >> 12;
	hook::kernel_hook_info_t* existing_hook = hook::find_hook_on_same_page(target_pfn);

	void* shadow_page = nullptr;
	bool is_owner = false;

	if (existing_hook != nullptr)
	{
		// Reuse existing shadow page (another hook already owns it)
		shadow_page = existing_hook->get_mapped_shadow_page();
		std::println("[+] Reusing existing shadow page from hook on same page (PFN: 0x{:X})", target_pfn);
	}
	else
	{
		// Allocate new shadow page
		shadow_page = sys::user::allocate_locked_memory(0x1000, PAGE_READWRITE);
		if (shadow_page == nullptr)
		{
			std::println("[-] Failed to allocate shadow page for callback bypass hook");
			kernel_detour_holder::free_memory(sc_buffer);
			ki_sc64se_shellcode_detour_offset = 0;
			return false;
		}

		std::uint64_t shadow_physical = hypercall::translate_guest_virtual_address(
			reinterpret_cast<std::uint64_t>(shadow_page), sys::current_cr3);
		if (shadow_physical == 0)
		{
			std::println("[-] Failed to translate shadow page to physical");
			sys::user::free_memory(shadow_page);
			kernel_detour_holder::free_memory(sc_buffer);
			ki_sc64se_shellcode_detour_offset = 0;
			return false;
		}

		// Copy original kernel page to shadow
		std::uint64_t page_base_va = hook_va & ~0xFFFull;
		hypercall::read_guest_virtual_memory(
			static_cast<std::uint8_t*>(shadow_page), page_base_va, sys::current_cr3, 0x1000);

		// Register EPT hook
		std::uint64_t hook_status = hypercall::add_slat_code_hook(hook_physical, shadow_physical);
		if (hook_status == 0)
		{
			std::println("[-] Failed to register EPT hook for callback bypass");
			sys::user::free_memory(shadow_page);
			kernel_detour_holder::free_memory(sc_buffer);
			ki_sc64se_shellcode_detour_offset = 0;
			return false;
		}

		is_owner = true;
	}

	// Save original shadow bytes before writing trampoline
	std::uint64_t page_offset = hook_va & 0xFFF;

	hook::saved_shadow_bytes[hook_va] = std::vector<std::uint8_t>(
		static_cast<std::uint8_t*>(shadow_page) + page_offset,
		static_cast<std::uint8_t*>(shadow_page) + page_offset + 14);

	// Write ONLY 14-byte trampoline at hook offset (rest stays original)
	auto trampoline = build_abs_jmp(sc_kernel_va);
	memcpy(static_cast<std::uint8_t*>(shadow_page) + page_offset, trampoline.data(), 14);

	std::println("[+] Shadow page: 14-byte trampoline at offset 0x{:X}, original code preserved at offset 0x{:X}+",
		page_offset, page_offset + 14);

	// Register in kernel_hook_list for same-page tracking
	hook::kernel_hook_info_t hook_info = { };
	hook_info.set_mapped_shadow_page(shadow_page);
	hook_info.original_page_pfn = target_pfn;
	hook_info.overflow_original_page_pfn = 0;
	hook_info.detour_holder_shadow_offset = 0; // manages own shellcode separately
	hook_info.is_shadow_page_owner = is_owner ? 1 : 0;
	hook_info.patched_byte_count = 14;

	hook::kernel_hook_list[hook_va] = hook_info;

	ki_sc64se_hook_va = hook_va;

	std::println("[+] InstrumentationCallback bypass hook installed at 0x{:X} (14 bytes, owner={})", hook_va, is_owner);
	return true;
}

inline bool remove_ki_syscall64_service_exit_hook()
{
	if (ki_sc64se_hook_va == 0)
	{
		std::println("[-] No InstrumentationCallback bypass hook to remove");
		return false;
	}

	if (hook::kernel_hook_list.contains(ki_sc64se_hook_va) == false)
	{
		std::println("[-] Callback bypass hook not found in kernel_hook_list");
		return false;
	}

	hook::kernel_hook_info_t hook_info = hook::kernel_hook_list[ki_sc64se_hook_va];

	// Check if another hook shares this physical page
	hook::kernel_hook_info_t* other_hook = hook::find_hook_on_same_page(hook_info.original_page_pfn, ki_sc64se_hook_va);

	if (other_hook != nullptr)
	{
		// Shared page: restore original bytes on shadow, skip EPT removal and shadow free
		auto saved_it = hook::saved_shadow_bytes.find(ki_sc64se_hook_va);

		if (saved_it != hook::saved_shadow_bytes.end())
		{
			std::uint64_t page_offset = ki_sc64se_hook_va & 0xFFF;
			std::uint8_t* shadow = static_cast<std::uint8_t*>(hook_info.get_mapped_shadow_page());
			memcpy(shadow + page_offset, saved_it->second.data(), saved_it->second.size());
			hook::saved_shadow_bytes.erase(saved_it);
		}

		// Transfer ownership if needed
		if (hook_info.is_shadow_page_owner == 1)
		{
			other_hook->is_shadow_page_owner = 1;
		}

		std::println("[+] Callback bypass removed from shared shadow page (ownership transferred: {})",
			hook_info.is_shadow_page_owner == 1);
	}
	else
	{
		// Sole hook on page: full teardown
		if (hypercall::remove_slat_code_hook(hook_info.original_page_pfn << 12) == 0)
		{
			std::println("[-] Failed to remove EPT hook for callback bypass");
			return false;
		}

		sys::user::free_memory(hook_info.get_mapped_shadow_page());
		hook::saved_shadow_bytes.erase(ki_sc64se_hook_va);
	}

	hook::kernel_hook_list.erase(ki_sc64se_hook_va);

	// Free shellcode allocation in detour holder
	if (ki_sc64se_shellcode_detour_offset != 0)
	{
		void* sc_alloc = kernel_detour_holder::get_allocation_from_offset(ki_sc64se_shellcode_detour_offset);
		kernel_detour_holder::free_memory(sc_alloc);
		ki_sc64se_shellcode_detour_offset = 0;
	}

	std::println("[+] InstrumentationCallback bypass hook removed");
	ki_sc64se_hook_va = 0;

	return true;
}

//=============================================================================
// Screenshot Hook — NtGdiBitBlt / NtGdiStretchBlt EPT hooks
// Anti-cheat GDI capture interception: shellcode signals hypervisor,
// spin-waits for DLL ack (overlay hidden), then proceeds to original function.
//=============================================================================

inline std::uint64_t bitblt_hook_va = 0;
inline std::uint64_t stretchblt_hook_va = 0;
inline std::uint16_t bitblt_shellcode_detour_offset = 0;
inline std::uint16_t stretchblt_shellcode_detour_offset = 0;

// Build the pre-hook shellcode for NtGdiBitBlt / NtGdiStretchBlt (runs in ring 0)
// Checks capture dimensions (width R9D > 150, height [rsp+0x28] > 150),
// then CPUID(30,1) to signal blt_start, spin-waits for DLL ack via CPUID(30,2),
// clears via CPUID(30,3). Falls through to original function via jmp back.
inline std::vector<uint8_t> build_blt_hook_shellcode()
{
	std::vector<uint8_t> sc;
	sc.reserve(100);

	auto push_u8 = [&](uint8_t b) { sc.push_back(b); };
	auto push_u32 = [&](uint32_t v) {
		for (int i = 0; i < 4; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};

	// Build CPUID leaf value for reserved_data=30
	hypercall_info_t blt_call = {};
	blt_call.primary_key = hypercall_primary_key;
	blt_call.secondary_key = hypercall_secondary_key;
	blt_call.call_type = hypercall_type_t::read_guest_cr3;
	blt_call.call_reserved_data = 30;
	std::uint32_t cpuid30_value = static_cast<std::uint32_t>(blt_call.value);

	// Save CPUID-clobbered registers (4 pushes = 32 bytes stack adjustment)
	push_u8(0x50); // push rax
	push_u8(0x51); // push rcx
	push_u8(0x52); // push rdx
	push_u8(0x53); // push rbx

	// Check width (R9D = cx param) > 150
	// cmp r9d, 150
	push_u8(0x41); push_u8(0x81); push_u8(0xF9);
	push_u32(150);

	// jle .skip
	push_u8(0x0F); push_u8(0x8E);
	const std::size_t jle_width_pos = sc.size();
	push_u32(0); // 32-bit rel offset placeholder

	// Check height: after 4 pushes (32 bytes), original [rsp+0x28] is at [rsp+0x48]
	// cmp dword [rsp+0x48], 150
	push_u8(0x81); push_u8(0x7C); push_u8(0x24); push_u8(0x48);
	push_u32(150);

	// jle .skip
	push_u8(0x0F); push_u8(0x8E);
	const std::size_t jle_height_pos = sc.size();
	push_u32(0); // 32-bit rel offset placeholder

	// === Signal blt_start: CPUID(magic_30, rdx=1) ===
	// mov ecx, <cpuid30_value>
	push_u8(0xB9);
	push_u32(cpuid30_value);

	// mov edx, 1
	push_u8(0xBA);
	push_u32(1);

	// cpuid
	push_u8(0x0F); push_u8(0xA2);

	// test eax, eax
	push_u8(0x85); push_u8(0xC0);

	// jz .skip (disabled or already active)
	push_u8(0x0F); push_u8(0x84);
	const std::size_t jz_disabled_pos = sc.size();
	push_u32(0); // placeholder

	// === Spin-wait for DLL ack (hypervisor handles TSC timeout) ===
	const std::size_t loop_pos = sc.size();

	// mov ecx, <cpuid30_value>
	push_u8(0xB9);
	push_u32(cpuid30_value);

	// mov edx, 2 (poll ack)
	push_u8(0xBA);
	push_u32(2);

	// cpuid
	push_u8(0x0F); push_u8(0xA2);

	// test eax, eax
	push_u8(0x85); push_u8(0xC0);

	// jnz .done (ack received)
	push_u8(0x75);
	const std::size_t jnz_done_pos = sc.size();
	push_u8(0x00); // placeholder

	// pause
	push_u8(0xF3); push_u8(0x90);

	// jmp .loop
	push_u8(0xEB);
	push_u8(static_cast<uint8_t>(loop_pos - (sc.size() + 1)));

	// .done:
	const std::size_t done_pos = sc.size();

	// Clear active flag: CPUID(magic_30, rdx=3)
	// mov ecx, <cpuid30_value>
	push_u8(0xB9);
	push_u32(cpuid30_value);

	// mov edx, 3
	push_u8(0xBA);
	push_u32(3);

	// cpuid
	push_u8(0x0F); push_u8(0xA2);

	// .skip:
	const std::size_t skip_pos = sc.size();

	// pop rbx, rdx, rcx, rax
	push_u8(0x5B);
	push_u8(0x5A);
	push_u8(0x59);
	push_u8(0x58);

	// Patch jump offsets (all near jumps use 32-bit displacement for safety)
	auto patch_rel32 = [&](std::size_t pos, std::size_t target) {
		std::int32_t offset = static_cast<std::int32_t>(target - (pos + 4));
		sc[pos + 0] = static_cast<uint8_t>(offset);
		sc[pos + 1] = static_cast<uint8_t>(offset >> 8);
		sc[pos + 2] = static_cast<uint8_t>(offset >> 16);
		sc[pos + 3] = static_cast<uint8_t>(offset >> 24);
	};

	patch_rel32(jle_width_pos, skip_pos);
	patch_rel32(jle_height_pos, skip_pos);
	patch_rel32(jz_disabled_pos, skip_pos);

	// Patch jnz .done (short jump)
	sc[jnz_done_pos] = static_cast<uint8_t>(done_pos - (jnz_done_pos + 1));

	return sc;
}

// Install EPT hooks on NtGdiBitBlt and NtGdiStretchBlt in win32kfull.sys
inline bool install_blt_hooks()
{
	if (!sys::kernel::modules_list.contains("win32kfull.sys"))
	{
		std::println("[-] win32kfull.sys not in modules list");
		return false;
	}

	const auto& w32k = sys::kernel::modules_list["win32kfull.sys"];

	auto install_one = [&](const char* name, std::uint64_t& hook_va_out, std::uint16_t& detour_offset_out) -> bool
	{
		auto it = w32k.exports.find(name);
		if (it == w32k.exports.end())
		{
			std::println("[-] {} not found in win32kfull.sys exports", name);
			return false;
		}

		std::uint64_t func_va = it->second;
		std::println("[+] {} VA: 0x{:X}", name, func_va);

		// Build shellcode
		auto full_shellcode = build_blt_hook_shellcode();

		// Append 14-byte jmp back to func_va + 14 (past trampoline, hits jmp_to_detour)
		auto return_jmp = build_abs_jmp(func_va + 14);
		full_shellcode.insert(full_shellcode.end(), return_jmp.begin(), return_jmp.end());

		std::println("[+] {} shellcode: {} bytes (with return jmp)", name, full_shellcode.size());

		// Allocate in detour holder
		void* sc_buffer = kernel_detour_holder::allocate_memory(
			static_cast<std::uint16_t>(full_shellcode.size()));

		if (sc_buffer == nullptr)
		{
			std::println("[-] Failed to allocate detour holder space for {} shellcode", name);
			return false;
		}

		detour_offset_out = kernel_detour_holder::get_allocation_offset(sc_buffer);
		memcpy(sc_buffer, full_shellcode.data(), full_shellcode.size());

		std::uint64_t sc_kernel_va = hook::kernel_detour_holder_base + detour_offset_out;

		std::println("[+] {} shellcode in detour holder at offset 0x{:X} (kernel VA: 0x{:X})",
			name, detour_offset_out, sc_kernel_va);

		// Build trampoline: 14-byte jmp to our shellcode
		auto trampoline = build_abs_jmp(sc_kernel_va);

		// Install EPT hook
		std::vector<std::uint8_t> post_original_bytes;
		std::uint8_t status = hook::add_kernel_hook(func_va, trampoline, post_original_bytes);

		if (status == 1)
		{
			hook_va_out = func_va;
			std::println("[+] {} EPT hook installed at 0x{:X}", name, func_va);
			return true;
		}

		kernel_detour_holder::free_memory(sc_buffer);
		detour_offset_out = 0;
		std::println("[-] Failed to install {} EPT hook", name);
		return false;
	};

	bool ok1 = install_one("NtGdiBitBlt", bitblt_hook_va, bitblt_shellcode_detour_offset);
	bool ok2 = install_one("NtGdiStretchBlt", stretchblt_hook_va, stretchblt_shellcode_detour_offset);

	if (!ok1 && !ok2)
	{
		std::println("[-] Both BLT hooks failed");
		return false;
	}

	std::println("[+] BLT hooks installed: NtGdiBitBlt={} NtGdiStretchBlt={}",
		ok1 ? "OK" : "FAIL", ok2 ? "OK" : "FAIL");
	return true;
}

inline bool remove_blt_hooks()
{
	auto remove_one = [](const char* name, std::uint64_t& hook_va, std::uint16_t& detour_offset) -> bool
	{
		if (hook_va == 0) return false;

		std::uint8_t status = hook::remove_kernel_hook(hook_va, 1);
		if (status == 1)
		{
			std::println("[+] {} EPT hook removed", name);
			hook_va = 0;

			if (detour_offset != 0)
			{
				void* sc_alloc = kernel_detour_holder::get_allocation_from_offset(detour_offset);
				kernel_detour_holder::free_memory(sc_alloc);
				detour_offset = 0;
			}

			return true;
		}

		std::println("[-] Failed to remove {} EPT hook", name);
		return false;
	};

	bool r1 = remove_one("NtGdiBitBlt", bitblt_hook_va, bitblt_shellcode_detour_offset);
	bool r2 = remove_one("NtGdiStretchBlt", stretchblt_hook_va, stretchblt_shellcode_detour_offset);

	return r1 || r2;
}

//=============================================================================
// Forward declaration (defined later in this file)
inline std::uint32_t find_instruction_boundary(const std::uint8_t* code, std::uint32_t min_bytes);

// MmCleanProcessAddressSpace Hook — Process Death Auto-Cleanup (ring-1 style)
// Compiled C++ hook function via ept_install_hook. Zero CPUID, zero VMEXIT.
// Resolution: PDB first, then sig scan fallback.
//=============================================================================

inline std::uint64_t mmclean_hook_va = 0;

// IDA-style signature: hex bytes with '?' wildcards, space-separated
// Parser converts to pattern+mask arrays at runtime
struct ida_sig_t
{
	std::uint8_t pattern[64]{};
	char mask[64]{};
	std::uint32_t len = 0;
	bool resolve_call = false; // true = pattern matches E8 CALL, resolve target

	constexpr ida_sig_t() = default;

	ida_sig_t(const char* ida_string, bool resolve = false) : resolve_call(resolve)
	{
		const char* p = ida_string;
		while (*p && len < 64)
		{
			while (*p == ' ') p++;
			if (!*p) break;
			if (*p == '?')
			{
				pattern[len] = 0;
				mask[len] = '?';
				len++;
				p++;
				while (*p == '?') p++;
			}
			else
			{
				auto hex_val = [](char c) -> std::uint8_t {
					if (c >= '0' && c <= '9') return c - '0';
					if (c >= 'A' && c <= 'F') return c - 'A' + 10;
					if (c >= 'a' && c <= 'f') return c - 'a' + 10;
					return 0;
				};
				pattern[len] = (hex_val(p[0]) << 4) | hex_val(p[1]);
				mask[len] = 'x';
				len++;
				p += 2;
			}
		}
	}
};

// MmCleanProcessAddressSpace prologue signature (Win11 23H2)
inline const ida_sig_t mmclean_sig(
	"4C 8B DC 49 89 5B ? 49 89 6B ? 49 89 73 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? 48 8B 91"
);

inline std::uint64_t find_mmclean_va()
{
	if (!sys::kernel::modules_list.contains("ntoskrnl.exe"))
		return 0;

	const auto& ntoskrnl = sys::kernel::modules_list["ntoskrnl.exe"];

	// Method 1: PDB
	if (sys::offsets::mm_clean_process_address_space_rva != 0)
	{
		std::uint64_t va = ntoskrnl.base_address + sys::offsets::mm_clean_process_address_space_rva;
		std::println("[+] MmCleanProcessAddressSpace via PDB: 0x{:X}", va);
		return va;
	}

	// Method 2: Sig scan (ring-1 IDASignatureScan style)
	if (mmclean_sig.len > 0)
	{
		std::println("[*] PDB failed, trying sig scan...");
		std::uint64_t va = hypercall::sig_scan_kernel(
			ntoskrnl.base_address, ntoskrnl.size,
			mmclean_sig.pattern, mmclean_sig.mask, mmclean_sig.len,
			mmclean_sig.resolve_call);
		if (va)
		{
			std::println("[+] MmCleanProcessAddressSpace via sig scan: 0x{:X}", va);
			return va;
		}
		std::println("[-] Sig scan failed — no match in ntoskrnl");
	}

	std::println("[-] MmCleanProcessAddressSpace not found (PDB failed, no sig)");
	return 0;
}

inline bool install_mmclean_hook(std::uint64_t target_eprocess)
{
	std::uint64_t mmclean_va = find_mmclean_va();
	if (!mmclean_va)
		return false;

	// Read prologue and find instruction boundary >= 14 (shadow page JMP size)
	constexpr std::uint32_t min_displaced = 14;
	std::uint8_t prologue[200]{};
	hypercall::read_guest_virtual_memory(prologue, mmclean_va, sys::current_cr3, 200);

	std::uint32_t displaced = find_instruction_boundary(prologue, min_displaced);
	if (displaced == 0 || displaced > 200)
	{
		std::println("[-] Failed to find instruction boundary >= {} at MmClean 0x{:X}", min_displaced, mmclean_va);
		std::print("    Prologue: ");
		for (int i = 0; i < 40; i++)
			std::print("{:02X} ", prologue[i]);
		std::println("");
		return false;
	}

	std::println("[+] Displacing {} bytes for 14-byte JMP redirect", displaced);

	std::uint64_t result = hypercall::setup_mmclean_inline_hook(mmclean_va, target_eprocess, displaced);
	if (result != 1)
	{
		std::println("[-] setup_mmclean_inline_hook failed: 0x{:X}", result);
		return false;
	}

	mmclean_hook_va = mmclean_va;
	std::println("[+] MmCleanProcessAddressSpace EPT hook installed (EPROCESS=0x{:X})", target_eprocess);
	return true;
}

inline bool remove_mmclean_hook()
{
	if (mmclean_hook_va == 0)
	{
		std::println("[-] No MmCleanProcessAddressSpace hook to remove");
		return false;
	}

	std::uint64_t result = hypercall::remove_mmclean_inline_hook();
	if (result == 1)
	{
		std::println("[+] MmCleanProcessAddressSpace inline EPT hook removed");
		mmclean_hook_va = 0;
		return true;
	}

	std::println("[-] Failed to remove MmClean inline hook: 0x{:X}", result);
	return false;
}

//=============================================================================
// MmAccessFault Compiled C++ EPT Hook — Safety Net for Hidden Memory #PFs
// Replaces old CPUID-based shellcode approach. Uses ept_install_hook infrastructure
// (14B JMP → compiled C++ function in hidden region). Zero VMEXIT for non-hidden faults.
//=============================================================================

inline std::uint64_t mmaf_cpp_hook_va = 0;

inline bool install_mmaf_cpp_hook(std::uint64_t clone_cr3, std::uint64_t hidden_pml4_index = 70)
{
	if (sys::offsets::mm_access_fault_rva == 0)
	{
		std::println("[-] MmAccessFault RVA not resolved (PDB failed?)");
		return false;
	}

	if (!sys::kernel::modules_list.contains("ntoskrnl.exe"))
	{
		std::println("[-] ntoskrnl.exe not in modules list");
		return false;
	}

	std::uint64_t ntoskrnl_base = sys::kernel::modules_list["ntoskrnl.exe"].base_address;
	std::uint64_t mmaf_va = ntoskrnl_base + sys::offsets::mm_access_fault_rva;

	std::println("[+] MmAccessFault VA: 0x{:X} (C++ EPT hook)", mmaf_va);

	// Read prologue and find instruction boundary >= 14 (shadow page JMP size)
	constexpr std::uint32_t min_displaced = 14;
	std::uint8_t prologue[200]{};
	hypercall::read_guest_virtual_memory(prologue, mmaf_va, sys::current_cr3, 200);

	std::uint32_t displaced = find_instruction_boundary(prologue, min_displaced);
	if (displaced == 0 || displaced > 200)
	{
		std::println("[-] Failed to find instruction boundary >= {} at MmAccessFault 0x{:X}", min_displaced, mmaf_va);
		std::print("    Prologue: ");
		for (int i = 0; i < 40; i++)
			std::print("{:02X} ", prologue[i]);
		std::println("");
		return false;
	}

	std::println("[+] Displacing {} bytes for 14-byte JMP redirect", displaced);

	std::uint64_t result = hypercall::setup_mmaf_inline_hook(
		mmaf_va, clone_cr3, displaced, static_cast<std::uint8_t>(hidden_pml4_index));
	if (result != 1)
	{
		std::println("[-] setup_mmaf_inline_hook failed: 0x{:X}", result);
		return false;
	}

	mmaf_cpp_hook_va = mmaf_va;
	std::println("[+] MmAccessFault C++ EPT hook installed at 0x{:X}", mmaf_va);
	return true;
}

//=============================================================================
// PsWatchWorkingSet Hook — Suppress Working Set Monitoring for Hidden Memory
// Prevents GetWsChangesEx/QueryWorkingSetEx from revealing pages in PML4[hidden].
// Pure inline PML4 index check — no VMEXIT, no hypervisor handler needed.
//=============================================================================

inline std::uint64_t pswatch_hook_va = 0;
inline std::uint16_t pswatch_shellcode_detour_offset = 0;

// Build PsWatchWorkingSet inline check shellcode (~52 bytes)
// PsWatchWorkingSet(Status=RCX, PcValue=RDX, Va=R8)
// If PML4 index of PcValue or Va matches hidden_pml4_index → suppress (ret)
// Otherwise → passthrough (jmp pswatch_va + 14)
inline std::vector<std::uint8_t> build_pswatch_shellcode(
	std::uint64_t pswatch_va,
	std::uint8_t hidden_pml4_index)
{
	std::vector<std::uint8_t> sc;
	sc.reserve(64);

	auto push_u8 = [&](uint8_t b) { sc.push_back(b); };
	auto push_u32 = [&](uint32_t v) {
		for (int i = 0; i < 4; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};

	// push rax                ; 1B — save scratch
	push_u8(0x50);

	// mov rax, rdx            ; 3B — PcValue
	push_u8(0x48); push_u8(0x8B); push_u8(0xC2);
	// shr rax, 39             ; 4B — extract PML4 index
	push_u8(0x48); push_u8(0xC1); push_u8(0xE8); push_u8(39);
	// and eax, 0x1FF          ; 5B — mask 9 bits
	push_u8(0x25); push_u32(0x1FF);
	// cmp eax, <hidden_index> ; 3B
	push_u8(0x83); push_u8(0xF8); push_u8(hidden_pml4_index);
	// je .suppress            ; 2B (short jump, patched below)
	push_u8(0x74);
	std::size_t je1_offset = sc.size();
	push_u8(0x00); // placeholder

	// mov rax, r8             ; 3B — Va
	push_u8(0x4C); push_u8(0x89); push_u8(0xC0);
	// shr rax, 39             ; 4B
	push_u8(0x48); push_u8(0xC1); push_u8(0xE8); push_u8(39);
	// and eax, 0x1FF          ; 5B
	push_u8(0x25); push_u32(0x1FF);
	// cmp eax, <hidden_index> ; 3B
	push_u8(0x83); push_u8(0xF8); push_u8(hidden_pml4_index);
	// je .suppress            ; 2B
	push_u8(0x74);
	std::size_t je2_offset = sc.size();
	push_u8(0x00); // placeholder

	// .passthrough:
	// pop rax                 ; 1B
	push_u8(0x58);
	// jmp pswatch_va + 14     ; 14B absolute jump
	auto passthrough_jmp = build_abs_jmp(pswatch_va + 14);
	sc.insert(sc.end(), passthrough_jmp.begin(), passthrough_jmp.end());

	// .suppress:
	std::size_t suppress_offset = sc.size();
	// pop rax                 ; 1B
	push_u8(0x58);
	// ret                     ; 1B — drop call silently
	push_u8(0xC3);

	// Patch je targets (relative to byte after je instruction)
	sc[je1_offset] = static_cast<uint8_t>(suppress_offset - (je1_offset + 1));
	sc[je2_offset] = static_cast<uint8_t>(suppress_offset - (je2_offset + 1));

	return sc;
}

inline bool install_pswatch_hook(std::uint64_t hidden_pml4_index = 70)
{
	if (sys::offsets::ps_watch_working_set_rva == 0)
	{
		std::println("[-] PsWatchWorkingSet RVA not resolved (PDB failed?)");
		return false;
	}

	if (!sys::kernel::modules_list.contains("ntoskrnl.exe"))
	{
		std::println("[-] ntoskrnl.exe not in modules list");
		return false;
	}

	std::uint64_t ntoskrnl_base = sys::kernel::modules_list["ntoskrnl.exe"].base_address;
	std::uint64_t pswatch_va = ntoskrnl_base + sys::offsets::ps_watch_working_set_rva;

	std::println("[+] PsWatchWorkingSet VA: 0x{:X}", pswatch_va);

	// 1. Build shellcode
	auto full_shellcode = build_pswatch_shellcode(pswatch_va, static_cast<std::uint8_t>(hidden_pml4_index));

	std::println("[+] PsWatchWorkingSet shellcode: {} bytes", full_shellcode.size());

	// 2. Allocate in detour holder
	void* sc_buffer = kernel_detour_holder::allocate_memory(
		static_cast<std::uint16_t>(full_shellcode.size()));

	if (sc_buffer == nullptr)
	{
		std::println("[-] Failed to allocate detour holder space for PsWatch shellcode");
		return false;
	}

	pswatch_shellcode_detour_offset = kernel_detour_holder::get_allocation_offset(sc_buffer);
	memcpy(sc_buffer, full_shellcode.data(), full_shellcode.size());

	std::uint64_t sc_kernel_va = hook::kernel_detour_holder_base + pswatch_shellcode_detour_offset;

	std::println("[+] PsWatch shellcode in detour holder at offset 0x{:X} (kernel VA: 0x{:X})",
		pswatch_shellcode_detour_offset, sc_kernel_va);

	// 3. Build trampoline: 14-byte jmp to our shellcode
	auto trampoline = build_abs_jmp(sc_kernel_va);

	// 4. Install EPT hook
	std::vector<std::uint8_t> post_original_bytes;
	std::uint8_t status = hook::add_kernel_hook(pswatch_va, trampoline, post_original_bytes);

	if (status == 1)
	{
		pswatch_hook_va = pswatch_va;
		std::println("[+] PsWatchWorkingSet EPT hook installed at 0x{:X}", pswatch_va);
		return true;
	}

	kernel_detour_holder::free_memory(sc_buffer);
	pswatch_shellcode_detour_offset = 0;
	std::println("[-] Failed to install PsWatchWorkingSet EPT hook");
	return false;
}

inline bool remove_pswatch_hook()
{
	if (pswatch_hook_va == 0)
	{
		std::println("[-] No PsWatchWorkingSet hook to remove");
		return false;
	}

	std::uint8_t status = hook::remove_kernel_hook(pswatch_hook_va, 1);

	if (status == 1)
	{
		std::println("[+] PsWatchWorkingSet EPT hook removed");
		pswatch_hook_va = 0;

		if (pswatch_shellcode_detour_offset != 0)
		{
			void* sc_alloc = kernel_detour_holder::get_allocation_from_offset(pswatch_shellcode_detour_offset);
			kernel_detour_holder::free_memory(sc_alloc);
			pswatch_shellcode_detour_offset = 0;
		}

		return true;
	}

	std::println("[-] Failed to remove PsWatchWorkingSet EPT hook");
	return false;
}

//=============================================================================
// MmAccessFault EPT Hook (reference implementation — NOT installed by default)
// Intercepts page faults on hidden memory (PML4[hidden]) and swaps CR3 to clone
// so the faulting instruction retries under the clone where hidden pages exist.
//
// NOTE: This was the original safety net before KiPageFault inline hook replaced it.
// Kept for comparison and as a fallback option. Key difference vs KiPageFault:
//   - MMAF: causes VMEXIT for every page fault system-wide (EPT execute violation)
//     + additional CPUID VMEXIT on hidden-memory path = ~30K VMEXITs/sec overhead
//   - KiPageFault: zero VMEXITs for non-target processes (inline handler on shadow page)
//     + 1 VMEXIT per page fault for target process only (handled in Hook 1 fast path)
//   - MMAF was removed because anti-cheat deep kernel stacks + CPUID VMEXIT overhead
//     caused double faults (BSOD 0x7F) and excessive VMEXIT load
//=============================================================================

inline std::uint64_t mmaf_hook_va = 0;
inline std::uint16_t mmaf_shellcode_detour_offset = 0;

// Build MmAccessFault check shellcode (runs in detour holder)
// Flow: trampoline (14B on shadow page) → this shellcode in detour holder
//   Hidden path: CPUID swap → return STATUS_SUCCESS to caller
//   Not-hidden path: jmp back to mmaf_va+14 → displaced original bytes
inline std::vector<std::uint8_t> build_mmaf_shellcode(
	std::uint64_t mmaf_va,
	std::uint32_t hypercall_value,
	std::uint64_t clone_cr3,
	std::uint64_t hidden_pml4_index)
{
	std::vector<std::uint8_t> sc;
	sc.reserve(80);

	auto push_u8 = [&](uint8_t b) { sc.push_back(b); };
	auto push_u32 = [&](uint32_t v) {
		for (int i = 0; i < 4; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};
	auto push_u64 = [&](uint64_t v) {
		for (int i = 0; i < 8; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};

	// push rax
	push_u8(0x50);
	// push rbx (CPUID clobbers EBX)
	push_u8(0x53);
	// mov rax, rdx  -- RDX = faulting virtual address (MmAccessFault param 2)
	push_u8(0x48); push_u8(0x8B); push_u8(0xC2);
	// shr rax, 39  -- extract PML4 index
	push_u8(0x48); push_u8(0xC1); push_u8(0xE8); push_u8(0x27);
	// and eax, 0x1FF  -- mask to 9 bits
	push_u8(0x25); push_u8(0xFF); push_u8(0x01); push_u8(0x00); push_u8(0x00);
	// cmp eax, <pml4_index>
	push_u8(0x83); push_u8(0xF8); push_u8(static_cast<uint8_t>(hidden_pml4_index));
	// jne .not_hidden
	push_u8(0x75);
	const std::size_t jne_pos = sc.size();
	push_u8(0x00); // placeholder

	// --- hidden path: CPUID swap + return STATUS_SUCCESS ---
	const std::size_t hidden_start = sc.size();

	// mov ecx, <hypercall_value>
	push_u8(0xB9); push_u32(hypercall_value);
	// movabs rdx, <clone_cr3>
	push_u8(0x48); push_u8(0xBA); push_u64(clone_cr3);
	// cpuid -- VMEXIT: writes clone_cr3 to guest CR3
	push_u8(0x0F); push_u8(0xA2);
	// pop rbx
	push_u8(0x5B);
	// pop rax
	push_u8(0x58);
	// xor eax, eax  -- STATUS_SUCCESS
	push_u8(0x33); push_u8(0xC0);
	// ret  -- return to MmAccessFault's caller
	push_u8(0xC3);

	// patch jne offset
	sc[jne_pos] = static_cast<uint8_t>(sc.size() - hidden_start);

	// --- .not_hidden: restore regs, jmp back to mmaf_va+14 ---
	// pop rbx
	push_u8(0x5B);
	// pop rax
	push_u8(0x58);

	// 14-byte absolute jmp back to mmaf_va + 14 (past the trampoline, hits displaced bytes)
	auto return_jmp = build_abs_jmp(mmaf_va + 14);
	sc.insert(sc.end(), return_jmp.begin(), return_jmp.end());

	return sc;
}

inline bool install_mmaf_hook(std::uint64_t clone_cr3, std::uint64_t hidden_pml4_index = 70)
{
	if (sys::offsets::mm_access_fault_rva == 0)
	{
		std::println("[-] MmAccessFault RVA not resolved (PDB failed?)");
		return false;
	}

	if (!sys::kernel::modules_list.contains("ntoskrnl.exe"))
	{
		std::println("[-] ntoskrnl.exe not in modules list");
		return false;
	}

	std::uint64_t ntoskrnl_base = sys::kernel::modules_list["ntoskrnl.exe"].base_address;
	std::uint64_t mmaf_va = ntoskrnl_base + sys::offsets::mm_access_fault_rva;

	std::println("[+] MmAccessFault VA: 0x{:X}", mmaf_va);

	// Build hypercall_info for write_guest_cr3
	hypercall_info_t call_info = {};
	call_info.primary_key = hypercall_primary_key;
	call_info.secondary_key = hypercall_secondary_key;
	call_info.call_type = hypercall_type_t::write_guest_cr3;
	call_info.call_reserved_data = 0;

	std::uint32_t hypercall_value = static_cast<std::uint32_t>(call_info.value);

	// 1. Build full shellcode (runs in detour holder)
	auto full_shellcode = build_mmaf_shellcode(mmaf_va, hypercall_value, clone_cr3, hidden_pml4_index);

	std::println("[+] MmAccessFault shellcode: {} bytes, clone_cr3=0x{:X}",
		full_shellcode.size(), clone_cr3);

	// 2. Allocate space in detour holder
	void* sc_buffer = kernel_detour_holder::allocate_memory(
		static_cast<std::uint16_t>(full_shellcode.size()));

	if (sc_buffer == nullptr)
	{
		std::println("[-] Failed to allocate detour holder space for MmAccessFault shellcode");
		return false;
	}

	mmaf_shellcode_detour_offset = kernel_detour_holder::get_allocation_offset(sc_buffer);
	memcpy(sc_buffer, full_shellcode.data(), full_shellcode.size());

	std::uint64_t sc_kernel_va = hook::kernel_detour_holder_base + mmaf_shellcode_detour_offset;

	std::println("[+] MmAccessFault shellcode in detour holder at offset 0x{:X} (kernel VA: 0x{:X})",
		mmaf_shellcode_detour_offset, sc_kernel_va);

	// 3. Build trampoline: 14-byte jmp to our shellcode in detour holder
	auto trampoline = build_abs_jmp(sc_kernel_va);

	// 4. Install EPT hook
	std::vector<std::uint8_t> post_original_bytes; // empty

	std::uint8_t status = hook::add_kernel_hook(mmaf_va, trampoline, post_original_bytes);

	if (status == 1)
	{
		mmaf_hook_va = mmaf_va;
		std::println("[+] MmAccessFault EPT hook installed at 0x{:X}", mmaf_va);
		return true;
	}

	// Cleanup on failure
	kernel_detour_holder::free_memory(sc_buffer);
	mmaf_shellcode_detour_offset = 0;
	std::println("[-] Failed to install MmAccessFault EPT hook");
	return false;
}

inline bool remove_mmaf_hook()
{
	if (mmaf_hook_va == 0)
	{
		std::println("[-] No MmAccessFault hook to remove");
		return false;
	}

	std::uint8_t status = hook::remove_kernel_hook(mmaf_hook_va, 1);

	if (status == 1)
	{
		std::println("[+] MmAccessFault EPT hook removed");
		mmaf_hook_va = 0;

		if (mmaf_shellcode_detour_offset != 0)
		{
			void* sc_alloc = kernel_detour_holder::get_allocation_from_offset(mmaf_shellcode_detour_offset);
			kernel_detour_holder::free_memory(sc_alloc);
			mmaf_shellcode_detour_offset = 0;
		}

		return true;
	}

	std::println("[-] Failed to remove MmAccessFault EPT hook");
	return false;
}

//=============================================================================
// KiDispatchException EPT hook — safe memory probes for injected DLL
//=============================================================================

// Build TryCopyQword shellcode: bool TryCopyQword(void* src, void* dst)
// Sets magic R10, attempts read, checks if R10 was changed to 0x1337 (fault suppressed).
// Returns 1 on success, 0 on fault.
inline std::vector<uint8_t> build_try_copy_qword_stub()
{
	std::vector<uint8_t> sc;
	sc.reserve(48);

	auto push_u8 = [&](uint8_t b) { sc.push_back(b); };
	auto push_u32 = [&](uint32_t v) {
		for (int i = 0; i < 4; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};
	auto push_u64 = [&](uint64_t v) {
		for (int i = 0; i < 8; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};

	// mov r10, 0x9EFABE87C1FE38E2  ; magic marker (10 bytes)
	push_u8(0x49); push_u8(0xBA);
	push_u64(0x9EFABE87C1FE38E2ull);

	// mov eax, 3                   ; instruction length of next insn (mov rax,[rcx] = 3 bytes)
	push_u8(0xB8); push_u32(3);

	// mov rax, [rcx]               ; may fault (48 8B 01) — 3 bytes
	push_u8(0x48); push_u8(0x8B); push_u8(0x01);

	// mov [rdx], rax               ; store result
	push_u8(0x48); push_u8(0x89); push_u8(0x02);

	// xor eax, eax                 ; eax = 0 (default: fail)
	push_u8(0x31); push_u8(0xC0);

	// cmp r10, 0x1337              ; was R10 changed to failure signal?
	push_u8(0x49); push_u8(0x81); push_u8(0xFA);
	push_u32(0x1337);

	// jz .fail                     ; if R10 == 0x1337, fault was suppressed → fail
	push_u8(0x74); push_u8(0x05);

	// mov eax, 1                   ; success
	push_u8(0xB8); push_u32(1);

	// .fail:
	// xor r10d, r10d               ; clear magic
	push_u8(0x45); push_u8(0x31); push_u8(0xD2);

	// ret
	push_u8(0xC3);

	return sc;
}

// Build TryWriteQword shellcode: bool TryWriteQword(void* dst, uint64_t value)
// Same pattern as TryCopyQword but writes value to dst.
inline std::vector<uint8_t> build_try_write_qword_stub()
{
	std::vector<uint8_t> sc;
	sc.reserve(48);

	auto push_u8 = [&](uint8_t b) { sc.push_back(b); };
	auto push_u32 = [&](uint32_t v) {
		for (int i = 0; i < 4; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};
	auto push_u64 = [&](uint64_t v) {
		for (int i = 0; i < 8; i++) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
	};

	// mov r10, 0x9EFABE87C1FE38E2  ; magic marker
	push_u8(0x49); push_u8(0xBA);
	push_u64(0x9EFABE87C1FE38E2ull);

	// mov eax, 3                   ; instruction length of next insn (mov [rcx],rdx = 3 bytes)
	push_u8(0xB8); push_u32(3);

	// mov [rcx], rdx               ; may fault (48 89 11) — 3 bytes
	push_u8(0x48); push_u8(0x89); push_u8(0x11);

	// xor eax, eax                 ; eax = 0 (default: fail)
	push_u8(0x31); push_u8(0xC0);

	// cmp r10, 0x1337              ; was R10 changed?
	push_u8(0x49); push_u8(0x81); push_u8(0xFA);
	push_u32(0x1337);

	// jz .fail
	push_u8(0x74); push_u8(0x05);

	// mov eax, 1                   ; success
	push_u8(0xB8); push_u32(1);

	// .fail:
	// xor r10d, r10d               ; clear magic
	push_u8(0x45); push_u8(0x31); push_u8(0xD2);

	// ret
	push_u8(0xC3);

	return sc;
}

// Instruction length decoder for x86-64 prologue instructions.
// Returns total bytes for the first N instructions that sum to >= min_bytes.
// Returns 0 on failure (unknown opcode).
// Handles: segment prefixes (GS/FS), REX, two-byte opcodes (0F),
//          push/pop, mov, lea, alu, swapgs, mov CR, etc.
inline std::uint32_t find_instruction_boundary(const std::uint8_t* code, std::uint32_t min_bytes)
{
	std::uint32_t total = 0;

	while (total < min_bytes)
	{
		const std::uint8_t* p = code + total;
		std::uint32_t len = 0;
		std::uint32_t skip = 0;

		// Skip prefixes: segment (ES/CS/SS/DS/FS/GS), LOCK, operand-size (66), REP/REPNE (F2/F3)
		while (p[skip] == 0x26 || p[skip] == 0x2E || p[skip] == 0x36 ||
		       p[skip] == 0x3E || p[skip] == 0x64 || p[skip] == 0x65 ||
		       p[skip] == 0xF0 || p[skip] == 0x66 || p[skip] == 0xF2 ||
		       p[skip] == 0xF3)
			skip++;

		// REX prefix
		bool has_rex = (p[skip] >= 0x40 && p[skip] <= 0x4F);
		const std::uint8_t* op = has_rex ? p + skip + 1 : p + skip;
		std::uint32_t prefix_len = skip + (has_rex ? 1 : 0);

		// Helper: compute extra bytes from ModRM addressing mode
		auto modrm_extra = [&](std::uint32_t modrm_off) -> std::uint32_t {
			std::uint8_t modrm = op[modrm_off];
			std::uint8_t mod = modrm >> 6;
			std::uint8_t rm = modrm & 7;
			if (mod == 3) return 0;
			std::uint32_t extra = 0;
			if (mod == 0) {
				if (rm == 5) extra = 4; // [rip+disp32]
				else if (rm == 4) {
					extra = 1; // SIB
					if ((op[modrm_off + 1] & 7) == 5) extra += 4; // SIB.base=5 → disp32
				}
			} else if (mod == 1) {
				extra = 1; // disp8
				if (rm == 4) extra += 1; // SIB
			} else { // mod == 2
				extra = 4; // disp32
				if (rm == 4) extra += 1; // SIB
			}
			return extra;
		};

		switch (op[0])
		{
		case 0x50: case 0x51: case 0x52: case 0x53: // push reg
		case 0x54: case 0x55: case 0x56: case 0x57:
		case 0x58: case 0x59: case 0x5A: case 0x5B: // pop reg
		case 0x5C: case 0x5D: case 0x5E: case 0x5F:
		case 0x90: // nop
		case 0xC3: // ret
		case 0xCC: // int3
		case 0xFC: // cld
		case 0xFB: // sti
		case 0xFA: // cli
		case 0x9C: // pushfq
		case 0x9D: // popfq
		case 0xC9: // leave
		case 0xF8: // clc
		case 0xF9: // stc
		case 0x99: // cdq/cqo
			len = prefix_len + 1;
			break;
		case 0x83: // alu r/m, imm8
			len = prefix_len + 2 + modrm_extra(1) + 1;
			break;
		case 0x81: // alu r/m, imm32
			len = prefix_len + 2 + modrm_extra(1) + 4;
			break;
		case 0x80: // alu r/m8, imm8
			len = prefix_len + 2 + modrm_extra(1) + 1;
			break;
		case 0xC7: // mov r/m, imm32
			len = prefix_len + 2 + modrm_extra(1) + 4;
			break;
		case 0xC6: // mov r/m8, imm8
			len = prefix_len + 2 + modrm_extra(1) + 1;
			break;
		case 0x89: case 0x8B: // mov r/m, r  or  mov r, r/m
		case 0x8D: // lea
		case 0x85: case 0x84: // test
		case 0x87: // xchg
		case 0x39: case 0x3B: // cmp
		case 0x38: case 0x3A: // cmp r/m8
		case 0x31: case 0x33: // xor
		case 0x29: case 0x2B: // sub
		case 0x01: case 0x03: // add
		case 0x09: case 0x0B: // or
		case 0x21: case 0x23: // and
		case 0x88: case 0x8A: // mov r/m8
		case 0x86: // xchg r/m8, r8
		case 0x00: case 0x02: // add r/m8
		case 0x08: case 0x0A: // or r/m8
		case 0x18: case 0x1A: // sbb r/m8
		case 0x10: case 0x12: // adc r/m8
		case 0x28: case 0x2A: // sub r/m8
		case 0x30: case 0x32: // xor r/m8
		case 0x19: case 0x1B: // sbb
		case 0x11: case 0x13: // adc
		case 0x63: // movsxd
		case 0x8F: // pop r/m
			len = prefix_len + 2 + modrm_extra(1);
			break;
		case 0xB8: case 0xB9: case 0xBA: case 0xBB: // mov reg, imm32/64
		case 0xBC: case 0xBD: case 0xBE: case 0xBF:
			len = prefix_len + 1 + (has_rex && (p[skip] & 0x08) ? 8 : 4);
			break;
		case 0xB0: case 0xB1: case 0xB2: case 0xB3: // mov reg8, imm8
		case 0xB4: case 0xB5: case 0xB6: case 0xB7:
			len = prefix_len + 2;
			break;
		case 0x70: case 0x71: case 0x72: case 0x73: // Jcc rel8
		case 0x74: case 0x75: case 0x76: case 0x77:
		case 0x78: case 0x79: case 0x7A: case 0x7B:
		case 0x7C: case 0x7D: case 0x7E: case 0x7F:
		case 0xEB: // jmp rel8
			len = prefix_len + 2;
			break;
		case 0xE9: // jmp rel32
		case 0xE8: // call rel32
			len = prefix_len + 5;
			break;
		case 0xA8: // test al, imm8
		case 0x3C: // cmp al, imm8
		case 0x2C: // sub al, imm8
		case 0x24: // and al, imm8
		case 0x0C: // or al, imm8
		case 0x34: // xor al, imm8
		case 0x04: // add al, imm8
		case 0x14: // adc al, imm8
		case 0x1C: // sbb al, imm8
		case 0x6A: // push imm8
			len = prefix_len + 2;
			break;
		case 0xA9: // test rax, imm32
		case 0x3D: // cmp rax, imm32
		case 0x2D: // sub rax, imm32
		case 0x25: // and rax, imm32
		case 0x0D: // or rax, imm32
		case 0x35: // xor rax, imm32
		case 0x05: // add rax, imm32
		case 0x15: // adc rax, imm32
		case 0x1D: // sbb rax, imm32
		case 0x68: // push imm32
			len = prefix_len + 5;
			break;
		case 0xD1: // shift r/m, 1
		case 0xD3: // shift r/m, cl
		case 0xD0: // shift r/m8, 1
		case 0xD2: // shift r/m8, cl
		case 0xFF: // group 5: inc/dec/call/jmp/push r/m
		case 0xFE: // group 4: inc/dec r/m8
			len = prefix_len + 2 + modrm_extra(1);
			break;
		case 0xC1: // shift r/m, imm8
		case 0xC0: // shift r/m8, imm8
			len = prefix_len + 2 + modrm_extra(1) + 1;
			break;
		case 0xF6: // group 3 r/m8: test(imm8)/not/neg/mul/div
		{
			std::uint8_t reg = (op[1] >> 3) & 7;
			std::uint32_t imm = (reg == 0 || reg == 1) ? 1 : 0;
			len = prefix_len + 2 + modrm_extra(1) + imm;
			break;
		}
		case 0xF7: // group 3 r/m: test(imm32)/not/neg/mul/div
		{
			std::uint8_t reg = (op[1] >> 3) & 7;
			std::uint32_t imm = (reg == 0 || reg == 1) ? 4 : 0;
			len = prefix_len + 2 + modrm_extra(1) + imm;
			break;
		}
		case 0x69: // imul r, r/m, imm32
			len = prefix_len + 2 + modrm_extra(1) + 4;
			break;
		case 0x6B: // imul r, r/m, imm8
			len = prefix_len + 2 + modrm_extra(1) + 1;
			break;
		case 0x0F: // Two-byte opcodes
			switch (op[1])
			{
			case 0x01: // system instructions
				if (op[2] == 0xF8) len = prefix_len + 3; // swapgs
				else return 0;
				break;
			case 0x20: case 0x22: // mov CR
				len = prefix_len + 3;
				break;
			case 0xAE: // LFENCE/SFENCE/MFENCE/LDMXCSR/STMXCSR
			case 0x1F: // multi-byte NOP
			case 0xB6: case 0xB7: // movzx
			case 0xBE: case 0xBF: // movsx
			case 0x28: case 0x29: // movaps
			case 0x10: case 0x11: // movups
			case 0x57: // xorps
			case 0x56: // orps
			case 0x54: // andps
			case 0x2E: case 0x2F: // ucomiss/comiss
			case 0x40: case 0x41: case 0x42: case 0x43: // cmovcc
			case 0x44: case 0x45: case 0x46: case 0x47:
			case 0x48: case 0x49: case 0x4A: case 0x4B:
			case 0x4C: case 0x4D: case 0x4E: case 0x4F:
			case 0xAF: // imul r, r/m
			case 0xA3: // bt r/m, r
			case 0xAB: // bts r/m, r
			case 0xB3: // btr r/m, r
			case 0xBB: // btc r/m, r
			case 0xBC: // bsf
			case 0xBD: // bsr
			case 0x6E: // movd xmm, r/m32
			case 0x7E: // movd r/m32, xmm
			case 0x6F: // movdqa/movdqu
			case 0x7F: // movdqa/movdqu store
			case 0xEF: // pxor
			case 0xD6: // movq store
				len = prefix_len + 3 + modrm_extra(2);
				break;
			case 0xBA: // bt/bts/btr/btc r/m, imm8
				len = prefix_len + 3 + modrm_extra(2) + 1;
				break;
			case 0x80: case 0x81: case 0x82: case 0x83: // Jcc rel32
			case 0x84: case 0x85: case 0x86: case 0x87:
			case 0x88: case 0x89: case 0x8A: case 0x8B:
			case 0x8C: case 0x8D: case 0x8E: case 0x8F:
				len = prefix_len + 6;
				break;
			case 0x90: case 0x91: case 0x92: case 0x93: // SETcc r/m8
			case 0x94: case 0x95: case 0x96: case 0x97:
			case 0x98: case 0x99: case 0x9A: case 0x9B:
			case 0x9C: case 0x9D: case 0x9E: case 0x9F:
				len = prefix_len + 3 + modrm_extra(2);
				break;
			default:
				return 0;
			}
			break;
		default:
			return 0; // unknown opcode
		}

		if (len == 0) return 0;
		total += len;
	}

	return total;
}

// Install KiPageFault inline EPT hook — zero-VMEXIT safety net for hidden memory #PFs.
// The inline handler runs entirely on the shadow page (no VMEXIT):
//   1. Check CR2 PML4 index == hidden_pml4_index (5 cycles)
//   2. Check CR3 PFN matches target process (15 cycles)
//   3. If match: MOV CR3 clone + IRETQ (retry faulting instruction)
//   4. Else: JMP trampoline → original KiPageFault prologue
// Must be called after enable_cr3_intercept and set_user_cr3.
inline bool install_page_fault_hook(std::uint8_t hidden_pml4_index)
{
	if (!sys::kernel::modules_list.contains("ntoskrnl.exe"))
	{
		std::println("[-] ntoskrnl.exe not in modules list");
		return false;
	}

	std::uint64_t ntoskrnl_base = sys::kernel::modules_list["ntoskrnl.exe"].base_address;

	// Read IDT #0E (page fault) handler VA — this is the actual ISR entry point
	std::uint64_t hook_va = hypercall::read_idt_handler(0x0E);

	if (hook_va != 0)
	{
		std::println("[+] IDT #0E handler VA: 0x{:X}", hook_va);

		if (sys::offsets::ki_page_fault_rva != 0)
		{
			std::uint64_t kpf_va = ntoskrnl_base + sys::offsets::ki_page_fault_rva;
			if (hook_va == kpf_va)
				std::println("[*] IDT entry == PDB KiPageFault (direct IDT handler)");
			else
				std::println("[*] IDT entry differs from PDB KiPageFault (0x{:X}) — using IDT entry", kpf_va);
		}
	}
	else if (sys::offsets::ki_page_fault_rva != 0)
	{
		// Fallback to PDB symbol if IDT read failed
		hook_va = ntoskrnl_base + sys::offsets::ki_page_fault_rva;
		std::println("[*] IDT read failed, falling back to PDB KiPageFault VA: 0x{:X}", hook_va);
	}
	else
	{
		std::println("[-] Neither IDT read nor PDB KiPageFault available");
		return false;
	}

	// Read prologue bytes to find instruction boundary >= 28 (inline handler size)
	// Only ~28-30 bytes displaced = standard prologue (push/sub/lea), zero RIP-relative risk
	constexpr std::uint32_t min_displaced = 28;
	std::uint8_t prologue[200] = {};
	hypercall::read_guest_virtual_memory(prologue, hook_va, sys::current_cr3, 200);

	std::uint32_t displaced = find_instruction_boundary(prologue, min_displaced);
	if (displaced == 0 || displaced > 200)
	{
		std::println("[-] Failed to find instruction boundary >= {} at 0x{:X}", min_displaced, hook_va);
		std::println("[*] Bytes 0-15:  {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
			prologue[0], prologue[1], prologue[2], prologue[3],
			prologue[4], prologue[5], prologue[6], prologue[7],
			prologue[8], prologue[9], prologue[10], prologue[11],
			prologue[12], prologue[13], prologue[14], prologue[15]);
		std::println("[*] Bytes 16-31: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
			prologue[16], prologue[17], prologue[18], prologue[19],
			prologue[20], prologue[21], prologue[22], prologue[23],
			prologue[24], prologue[25], prologue[26], prologue[27],
			prologue[28], prologue[29], prologue[30], prologue[31]);
		std::uint32_t partial = find_instruction_boundary(prologue, 1);
		std::uint32_t prev = 0;
		while (partial != 0 && partial < min_displaced) {
			prev = partial;
			partial = find_instruction_boundary(prologue, partial + 1);
		}
		if (partial == 0)
			std::println("[*] Decoder fails at offset {} (opcode 0x{:02X})", prev, prologue[prev]);
		return false;
	}

	std::println("[+] Displacing {} bytes for 28-byte inline handler at 0x{:X}", displaced, hook_va);

	// Dump displaced prologue bytes for trampoline verification
	std::println("[*] KPF prologue (displaced {} bytes):", displaced);
	for (std::uint32_t b = 0; b < displaced && b < 48; b += 16)
	{
		std::uint32_t end = (b + 16 < displaced) ? b + 16 : displaced;
		std::string hex;
		for (std::uint32_t j = b; j < end; j++)
		{
			char tmp[4];
			std::snprintf(tmp, sizeof(tmp), "%02X ", prologue[j]);
			hex += tmp;
		}
		std::println("[*]   +{:02X}: {}", b, hex);
	}

	// Decode each instruction for verification
	std::uint32_t off = 0;
	int insn_idx = 0;
	while (off < displaced)
	{
		std::uint32_t insn_len = find_instruction_boundary(prologue + off, 1);
		if (insn_len == 0) break;
		std::string hex;
		for (std::uint32_t j = off; j < off + insn_len; j++)
		{
			char tmp[4];
			std::snprintf(tmp, sizeof(tmp), "%02X ", prologue[j]);
			hex += tmp;
		}
		std::println("[*]   insn[{}] @+{:02X} ({}B): {}", insn_idx, off, insn_len, hex);
		off += insn_len;
		insn_idx++;
	}

	std::uint64_t result = hypercall::setup_ki_page_fault_hook(hook_va, displaced, hidden_pml4_index);
	if (result != 1)
	{
		std::println("[-] setup_ki_page_fault_hook failed: 0x{:X}", result);
		return false;
	}

	std::println("[+] KiPageFault inline EPT hook installed — hidden memory #PFs handled with zero VMEXITs");
	return true;
}

// Install KiDispatchException EPT hook for safe memory probes.
// Called after DLL is loaded and relay is active.
inline bool install_exception_handler_hook()
{
	if (sys::offsets::ki_dispatch_exception_rva == 0)
	{
		std::println("[-] KiDispatchException RVA not resolved");
		return false;
	}

	if (!sys::kernel::modules_list.contains("ntoskrnl.exe"))
	{
		std::println("[-] ntoskrnl.exe not in modules list");
		return false;
	}

	std::uint64_t ntoskrnl_base = sys::kernel::modules_list["ntoskrnl.exe"].base_address;
	std::uint64_t kde_va = ntoskrnl_base + sys::offsets::ki_dispatch_exception_rva;

	std::println("[+] KiDispatchException VA: 0x{:X}", kde_va);

	// Read first 32 bytes to find instruction boundary >= 10
	// (10 bytes: push rcx + mov ecx + cpuid + pop rcx + ret)
	std::uint8_t code[32] = {};
	hypercall::read_guest_virtual_memory(code, kde_va, sys::current_cr3, 32);

	std::uint32_t displaced = find_instruction_boundary(code, 10);
	if (displaced == 0 || displaced > 32)
	{
		std::println("[-] Failed to find instruction boundary >= 10 in KiDispatchException prologue");
		std::println("[*] First 16 bytes: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
			code[0], code[1], code[2], code[3], code[4], code[5], code[6], code[7],
			code[8], code[9], code[10], code[11], code[12], code[13], code[14], code[15]);
		return false;
	}

	std::println("[+] KiDispatchException: displacing {} bytes for 10-byte CPUID stub", displaced);

	std::uint64_t result = hypercall::setup_exception_handler(kde_va, displaced);
	if (result != 1)
	{
		std::println("[-] setup_exception_handler failed: 0x{:X}", result);
		return false;
	}

	std::println("[+] KiDispatchException EPT hook installed — safe memory probes active");
	return true;
}

// Allocate a hidden page and write safe probe stubs into it.
// Uses an existing hidden page slot (must be called after setup_hidden_region + map_hidden_page).
// page_index: index of the hidden PT slot to use for probe stubs.
// Returns a pair of VAs: {try_copy_qword_va, try_write_qword_va}, or {0,0} on failure.
inline std::pair<std::uint64_t, std::uint64_t> install_safe_probe_stubs(
	std::uint64_t clone_cr3, std::uint64_t hidden_base_va, std::uint64_t page_index)
{
	// Map a new hidden page for the stubs
	std::uint64_t page_pa = hypercall::map_hidden_page(page_index);
	if (page_pa == 0)
	{
		std::println("[-] Failed to map hidden page {} for safe probe stubs", page_index);
		return {0, 0};
	}

	std::uint64_t page_va = hidden_base_va + (page_index * 0x1000);
	std::println("[+] Safe probe stub page VA: 0x{:X}", page_va);

	// Build stubs
	auto copy_stub = build_try_copy_qword_stub();
	auto write_stub = build_try_write_qword_stub();

	// Write TryCopyQword at offset 0 (physical write — clone CR3 VA ops broken)
	std::uint64_t copy_va = page_va;
	hypercall::write_guest_physical_memory(copy_stub.data(), page_pa, copy_stub.size());

	// Write TryWriteQword at offset 0x100 (well-separated)
	std::uint64_t write_va = page_va + 0x100;
	hypercall::write_guest_physical_memory(write_stub.data(), page_pa + 0x100, write_stub.size());

	std::println("[+] TryCopyQword at 0x{:X} ({} bytes), TryWriteQword at 0x{:X} ({} bytes)",
		copy_va, copy_stub.size(), write_va, write_stub.size());

	return {copy_va, write_va};
}

//=============================================================================
// Main injection entry point
//=============================================================================

inline bool inject_dll(const std::string& dll_path, const std::string& process_name)
{
	// cleanup any stale CR3 intercept from previous run
	hypercall::disable_cr3_intercept();

	// 1. Find target process
	auto process = sys::process::find_process_by_name(process_name);
	if (!process.has_value())
	{
		std::println("[-] Process '{}' not found", process_name);
		return false;
	}

	std::println("[+] Found {} (PID: {}, CR3: 0x{:X}, EPROCESS: 0x{:X})",
		process->name, process->pid, process->cr3, process->eprocess);

	// 2. Clone CR3
	std::uint64_t cloned_cr3 = hypercall::clone_guest_cr3(process->cr3);
	if (cloned_cr3 == 0)
	{
		std::println("[-] Failed to clone CR3");
		return false;
	}

	std::println("[+] Cloned CR3: 0x{:X}", cloned_cr3);

	// 3. Enable CR3 intercept
	std::uint64_t icr3_result = hypercall::enable_cr3_intercept(process->cr3, cloned_cr3);
	if (icr3_result == 0)
	{
		std::println("[-] Failed to enable CR3 intercept");
		return false;
	}

	std::println("[+] CR3 intercept enabled");

	// 4. Load DLL from disk
	// NOTE: From this point on, any failure must go through cleanup_partial_injection
	// to disable CR3 intercept + remove any hooks installed so far.
	// Leaving cr3_intercept::enabled without cleanup causes SECURE_KERNEL_ERROR
	// (VTL1 detects unknown clone CR3 in VTL0's VMCS during integrity checks).

	// Declare variables before first goto to avoid C2362 (jumping over initialization)
	PIMAGE_DOS_HEADER dos_header = nullptr;
	PIMAGE_NT_HEADERS64 nt_headers = nullptr;
	DWORD entry_point_rva = 0;
	SIZE_T image_size = 0;
	std::uint64_t pages_needed = 0;
	std::uint64_t shellcode_page = 0;
	std::uint64_t probe_stubs_page = 0;
	std::uint64_t total_pages = 0;
	std::uint64_t hidden_pml4_index = 70;
	std::uint64_t hidden_base_va = 0;
	std::uint64_t user_dtb = 0;
	bool dllmain_result = false;
	char target_name_buf[16] = {};
	std::vector<std::uint64_t> hidden_page_pas; // PA for each hidden page (for physical writes)

	std::vector<uint8_t> dll_image;
	if (!load_dll_file(dll_path, dll_image))
	{
		std::println("[-] Failed to load DLL: {}", dll_path);
		goto cleanup_partial_injection;
	}

	dos_header = (PIMAGE_DOS_HEADER)dll_image.data();
	nt_headers = (PIMAGE_NT_HEADERS64)(dll_image.data() + dos_header->e_lfanew);

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		std::println("[-] Invalid PE signature");
		goto cleanup_partial_injection;
	}

	entry_point_rva = nt_headers->OptionalHeader.AddressOfEntryPoint;
	image_size = nt_headers->OptionalHeader.SizeOfImage;
	pages_needed = (image_size + 0xFFF) / 0x1000;
	shellcode_page = pages_needed; // one extra page for shellcode
	probe_stubs_page = pages_needed + 1; // one more for safe probe stubs
	total_pages = pages_needed + 2;

	std::println("[+] DLL: {} bytes, {} pages + 1 shellcode + 1 probe stubs", image_size, pages_needed);

	// 5. Setup hidden region (PML4[70])
	hidden_base_va = hypercall::setup_hidden_region(70);
	if (hidden_base_va == 0)
	{
		std::println("[-] Failed to setup hidden region");
		goto cleanup_partial_injection;
	}

	std::println("[+] Hidden region at VA 0x{:X}", hidden_base_va);

	// 6. Map image + shellcode pages — store PAs for direct physical writes.
	// Do NOT map probe_stubs_page here: install_safe_probe_stubs maps it itself.
	// Double-mapping causes map_hidden_page to fail (PT entry already present).
	{
		const std::uint64_t pages_to_map = pages_needed + 1; // image + shellcode only
		hidden_page_pas.resize(pages_to_map, 0);
		for (std::uint64_t i = 0; i < pages_to_map; i++)
		{
			std::uint64_t page_pa = hypercall::map_hidden_page(i);
			if (page_pa == 0)
			{
				std::println("[-] Failed to map hidden page {}", i);
				goto cleanup_partial_injection;
			}
			hidden_page_pas[i] = page_pa;
		}

		std::println("[+] Mapped {} pages ({} image + 1 shellcode, probe stubs deferred)",
			pages_to_map, pages_needed);
	}

	// 6b. Register UserDirectoryTableBase for CR3 write interception (KPTI fix)
	// KPTI: kernel exit writes UserDTB to CR3. Without intercepting this,
	// the CR3 swap to clone is undone. Now the hypervisor intercepts both PFNs.
	if (sys::offsets::kprocess_user_directory_table_base != 0)
	{
		hypercall::read_guest_virtual_memory(&user_dtb,
			process->eprocess + sys::offsets::kprocess_user_directory_table_base,
			sys::current_cr3, 8);

		if (user_dtb != 0)
		{
			std::println("[+] UserDirectoryTableBase: 0x{:X} (offset 0x{:X})", user_dtb, sys::offsets::kprocess_user_directory_table_base);
			std::uint64_t result = hypercall::set_user_cr3(user_dtb);
			if (result)
				std::println("[+] Registered UserDTB PFN for CR3 interception");
			else
				std::println("[!] WARNING: Failed to register UserDTB");
		}
		else
		{
			std::println("[!] WARNING: UserDirectoryTableBase is 0 (KPTI disabled?)");
		}
	}
	else
	{
		std::println("[!] WARNING: UserDirectoryTableBase offset not resolved from PDB — KPTI interception disabled");
	}

	// 6c. KiPageFault inline EPT hook — DISABLED for bisect testing.
	// Per-VMEXIT CR3 swap alone should handle context switches. Re-enable after
	// confirming CR3 swap works without freeze.
	// if (install_page_fault_hook(static_cast<std::uint8_t>(hidden_pml4_index)))
	// {
	//     std::println("[+] Hidden memory #PF safety net active (zero-VMEXIT inline handler)");
	// }
	std::println("[*] KiPageFault disabled (bisect) — per-VMEXIT CR3 swap is the only safety net");

	// 7. Relocate image
	if (!relocate_image((PVOID)hidden_base_va, dll_image.data(), nt_headers))
	{
		std::println("[-] Failed to relocate image");
		goto cleanup_partial_injection;
	}

	std::println("[+] Relocations applied (delta: 0x{:X})",
		hidden_base_va - nt_headers->OptionalHeader.ImageBase);

	// 8. Resolve imports
	if (!resolve_imports(dll_image.data(), nt_headers))
	{
		std::println("[-] Failed to resolve imports");
		goto cleanup_partial_injection;
	}

	std::println("[+] Imports resolved");

	// 9. Zero-fill entire image area, then write PE header + sections
	// CRITICAL: PE loader zeroes the full SizeOfImage before mapping sections.
	// Without this, BSS (zero-initialized globals) and section gaps contain
	// stale heap data. CRT globals like __scrt_current_native_startup_state
	// need to be 0 — garbage values cause _DllMainCRTStartup to return FALSE.
	// Zero-fill and write using physical addresses — bypasses clone CR3 page walk
	// to avoid EPT 2MB split corruption in write_guest_virtual_memory.
	{
		std::vector<uint8_t> zero_page(0x1000, 0);
		for (std::uint64_t i = 0; i < pages_needed; i++)
		{
			hypercall::write_guest_physical_memory(
				zero_page.data(), hidden_page_pas[i], 0x1000);
		}
		std::println("[+] Zero-filled {} image pages (BSS/section gaps clean)", pages_needed);
	}

	{
		DWORD headers_size = nt_headers->OptionalHeader.SizeOfHeaders;
		std::uint64_t total_hdr = 0;
		while (total_hdr < headers_size)
		{
			std::uint64_t page_idx = total_hdr / 0x1000;
			std::uint64_t page_off = total_hdr & 0xFFF;
			std::uint64_t chunk = headers_size - total_hdr;
			if (page_off + chunk > 0x1000) chunk = 0x1000 - page_off;

			hypercall::write_guest_physical_memory(
				dll_image.data() + total_hdr, hidden_page_pas[page_idx] + page_off, chunk);
			total_hdr += chunk;
		}
		std::println("[+] PE header written: {} / {} bytes", total_hdr, headers_size);
	}

	if (!write_sections(dll_image.data(), nt_headers, hidden_base_va, cloned_cr3, image_size, dll_image.size(), hidden_page_pas))
	{
		std::println("[-] Failed to write sections");
		goto cleanup_partial_injection;
	}

	std::println("[+] Sections written to hidden memory");

	// 10. Verify hidden memory was written correctly using physical reads
	// (virtual memory ops through clone CR3 fail due to EPT 2MB page walk issues)
	{
	std::uint16_t verify_mz = 0;
	hypercall::read_guest_physical_memory(&verify_mz, hidden_page_pas[0], 2);
	std::println("[+] Hidden base via phys read: 0x{:X} (should be 0x5A4D = MZ)", verify_mz);

	// Also verify first section (.text)
	{
		auto first_section = IMAGE_FIRST_SECTION(nt_headers);
		if (first_section->SizeOfRawData > 0)
		{
			std::uint64_t text_page_idx = first_section->VirtualAddress / 0x1000;
			std::uint64_t text_page_off = first_section->VirtualAddress & 0xFFF;
			std::uint8_t text_verify[16] = {};
			if (text_page_idx < hidden_page_pas.size() && hidden_page_pas[text_page_idx] != 0)
			{
				hypercall::read_guest_physical_memory(text_verify,
					hidden_page_pas[text_page_idx] + text_page_off, 16);
			}
			std::uint64_t text_va = hidden_base_va + first_section->VirtualAddress;
			std::println("[+] .text section at 0x{:X}: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
				text_va, text_verify[0], text_verify[1], text_verify[2], text_verify[3],
				text_verify[4], text_verify[5], text_verify[6], text_verify[7]);
		}
	}
	}

	// 11. MmAccessFault C++ EPT hook — DISABLED (catch-22: lives in hidden memory PML4[70],
	// so if CR3 is original and a #PF hits hidden memory, MmAccessFault hook jumps to hidden
	// region → #PF again → double fault → BSOD). KiPageFault inline hook + per-VMEXIT CR3
	// swap cover the gap without this circular dependency.
	// if (install_mmaf_cpp_hook(cloned_cr3, hidden_pml4_index))
	// {
	//     std::println("[+] MmAccessFault C++ EPT hook installed (safety net active)");
	// }
	std::println("[*] MmAccessFault disabled — KiPageFault + per-VMEXIT CR3 swap are the active safety nets");

	// 12. Install InstrumentationCallback bypass hook BEFORE hijack_thread
	// With multi-hook per page support, callback bypass and KiSystemServiceExit
	// can coexist on the same shadow page (0x42F000). Callback bypass creates
	// the shadow page (owner), KiSSE reuses it during hijack_thread.
	// This means DllMain executes with callback bypass already active.
	if (sys::offsets::ki_system_call64_service_exit_rva != 0)
	{
		if (install_ki_syscall64_service_exit_hook(process->eprocess, hidden_pml4_index))
		{
			std::println("[+] InstrumentationCallback bypass active — will protect DllMain syscalls");
		}
		else
		{
			std::println("[!] WARNING: InstrumentationCallback bypass hook failed (callbacks may intercept our syscalls)");
		}
	}
	else
	{
		std::println("[!] WARNING: KiSystemCall64 service exit pattern not found — no callback bypass");
	}

	// 12b. MmClean hook — essential for auto-cleanup on process death (prevents orphaned hooks)
	if (mmclean_hook_va == 0)
	{
		if (install_mmclean_hook(process->eprocess))
			std::println("[+] Process death cleanup hook installed");
		else
			std::println("[!] WARNING: MmCleanProcessAddressSpace hook failed — manual cleanup required on crash");
	}
	else
	{
		std::println("[+] MmCleanProcessAddressSpace hook already installed (reusing)");
	}
	// Arm with name-based matching (ring-1 style) — survives process restart
	// Pass ntoskrnl base → hypervisor resolves PsGetProcessImageFileName via PE export walk
	for (size_t i = 0; i < process->name.size() && i < 15; i++)
		target_name_buf[i] = process->name[i];
	{
		const auto& ntoskrnl = sys::kernel::modules_list["ntoskrnl.exe"];
		hypercall::arm_process_cleanup(process->eprocess, ntoskrnl.base_address, target_name_buf);
		std::println("[+] Process cleanup armed for '{}' (ntoskrnl=0x{:X})", process->name, ntoskrnl.base_address);
	}

	// 12b2. PsWatch/KDE hooks — disabled (minimal mode)
	// if (install_pswatch_hook(hidden_pml4_index)) ...
	// if (install_exception_handler_hook()) ...
	std::println("[*] PsWatch/KDE hooks disabled (minimal mode)");

	// 13. Print stats before trigger
	std::println("[+] CR3 stats before trigger: exits={} swaps={} ept_violations={}",
		hypercall::read_cr3_exit_count(), hypercall::read_cr3_swap_count(),
		hypercall::read_slat_violation_count());

	// 14. Call DllMain via syscall hijack (trap frame RIP overwrite)
	// KiSSE hook will share the same shadow page as callback bypass (multi-hook per page).
	// hijack_thread installs KiSSE (non-owner on shared page), waits for DllMain, then removes it.
	// Callback bypass remains active throughout.
	dllmain_result = hijack_thread(
		cloned_cr3, process->cr3, process->eprocess,
		hidden_base_va, hidden_base_va, entry_point_rva, shellcode_page,
		hidden_page_pas[shellcode_page],
		0, 0, 0, // RtlAddFunctionTable disabled (detectable by EAC via RtlpDynamicFunctionTable)
		true /* skip_dllmain — TEMP: testing MmClean cleanup on process kill */);

	std::println("[+] ept_violations after trigger: {}", hypercall::read_slat_violation_count());

	if (dllmain_result)
	{
		std::println("[+] Injection complete - DLL running in hidden memory at 0x{:X}", hidden_base_va);
		std::println("[+] NtClose relay active (magic handle: 0xDEAD1337)");
	}
	else
	{
		std::println("[-] DllMain execution failed or timed out");
	}

	// DLL is persistent (runs threads, hooks PresentThread) — keep infrastructure active:
	//   - CR3 intercept: swaps to clone on MOV CR3 (context switch)
	//   - InstrumentationCallback bypass: protects hidden memory syscalls
	//   - UserDTB interception: handles KPTI user/kernel DTB swap
	// Only the KiSSE hook was removed inside hijack_thread() after DllMain returned.
	if (!dllmain_result)
	{
		// DllMain failed — tear down everything
		if (ntclose_hook_va != 0)
		{
			remove_ntclose_hook();
			std::println("[*] NtClose hook removed");
		}
		if (ki_sc64se_hook_va != 0)
		{
			remove_ki_syscall64_service_exit_hook();
			std::println("[*] InstrumentationCallback bypass hook removed");
		}
		if (pswatch_hook_va != 0)
		{
			remove_pswatch_hook();
			std::println("[*] PsWatchWorkingSet hook removed");
		}
		if (mmclean_hook_va != 0)
		{
			remove_mmclean_hook();
			std::println("[*] MmCleanProcessAddressSpace hook removed");
		}
		if (user_dtb != 0)
		{
			hypercall::clear_user_cr3();
			std::println("[*] UserDTB interception cleared");
		}
		std::println("[*] Disabling CR3 intercept...");
		hypercall::disable_cr3_intercept();
	}
	else
	{
		target_pid = process->pid;
		std::println("[+] DLL persistent — CR3 intercept + callback bypass hooks remain active");
	}

	return dllmain_result;

	// Cleanup for early failures AFTER enable_cr3_intercept (step 3).
	// Without this, cr3_intercept::enabled stays 1 with clone CR3 active,
	// causing VTL1 integrity check failure → SECURE_KERNEL_ERROR after minutes.
cleanup_partial_injection:
	std::println("[*] Cleaning up partial injection state...");
	// Remove any hooks installed before the failure point
	if (mmaf_hook_va != 0) { remove_mmaf_hook(); std::println("[*] Removed orphaned MMAF hook"); }
	if (ki_sc64se_hook_va != 0) { remove_ki_syscall64_service_exit_hook(); std::println("[*] Removed orphaned InstrCallback hook"); }
	if (ntclose_hook_va != 0) { remove_ntclose_hook(); std::println("[*] Removed orphaned NtClose hook"); }
	hypercall::clear_user_cr3(); // safe even if never set
	std::println("[*] Disabling CR3 intercept...");
	hypercall::disable_cr3_intercept();
	return false;
}

//=============================================================================
// Uninject: tear down all hooks and restore clean state
//=============================================================================

inline void uninject()
{
	std::println("[*] Tearing down injection infrastructure...");

	// 1. Disarm any pending syscall hijack
	hypercall::disarm_syscall_hijack();

	// 2. Remove KiSystemServiceExit hook (if still active)
	if (ksse_hook_va != 0)
	{
		remove_syscall_exit_hook();
		std::println("[+] KiSystemServiceExit hook removed");
	}

	// 2b. Remove NtClose hook (if still active)
	if (ntclose_hook_va != 0)
	{
		remove_ntclose_hook();
		std::println("[+] NtClose hook removed");
	}

	// 2c. Remove BLT screenshot hooks (if still active)
	if (bitblt_hook_va != 0 || stretchblt_hook_va != 0)
	{
		remove_blt_hooks();
		std::println("[+] Screenshot hooks removed");
	}

	// 2d. Remove PsWatchWorkingSet hook (if still active)
	if (pswatch_hook_va != 0)
	{
		remove_pswatch_hook();
		std::println("[+] PsWatchWorkingSet hook removed");
	}

	// 2e. Remove MmCleanProcessAddressSpace hook (if still active)
	if (mmclean_hook_va != 0)
	{
		remove_mmclean_hook();
		std::println("[+] MmCleanProcessAddressSpace hook removed");
	}

	// 3. Remove InstrumentationCallback bypass hook
	if (ki_sc64se_hook_va != 0)
	{
		remove_ki_syscall64_service_exit_hook();
		std::println("[+] InstrumentationCallback bypass hook removed");
	}
	else
	{
		std::println("[*] InstrumentationCallback bypass hook not active");
	}

	// 4. Remove MmAccessFault hook (if active)
	if (mmaf_hook_va != 0)
	{
		remove_mmaf_hook();
		std::println("[+] MmAccessFault hook removed");
	}

	// 5. Clear UserDTB interception
	hypercall::clear_user_cr3();
	std::println("[+] UserDTB interception cleared");

	// 6. Disable CR3 intercept (frees clone pages + resets state)
	hypercall::disable_cr3_intercept();
	std::println("[+] CR3 intercept disabled");

	// 7. Clear target PID
	target_pid = 0;

	// 8. Print final stats
	std::println("[+] Final stats: exits={} swaps={} ept_violations={}",
		hypercall::read_cr3_exit_count(), hypercall::read_cr3_swap_count(),
		hypercall::read_slat_violation_count());

	std::println("[+] Clean state restored — safe to reinject or exit");
}

} // namespace inject
