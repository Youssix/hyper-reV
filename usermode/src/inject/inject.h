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
#include <hypercall/hypercall_def.h>

namespace inject
{

//=============================================================================
// DllMain Shellcode (from PhysInj GameInjector.h)
//=============================================================================
static BYTE g_RemoteCallDllMain[92] = {
	0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24,
	0x20, 0x83, 0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48,
	0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B,
	0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
};
static const DWORD g_ShellDataOffset = 0x6;

typedef struct _DLLMAIN_STRUCT {
	INT Status;
	uintptr_t FnDllMain;
	HINSTANCE DllBase;
} DLLMAIN_STRUCT, *PDLLMAIN_STRUCT;

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
	uintptr_t offset = (uintptr_t)GetProcAddress(h_module, func_name) - (uintptr_t)h_module;
	FreeLibrary(h_module);
	return offset;
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

		auto thunk = (PIMAGE_THUNK_DATA64)rva_to_va(import_desc->FirstThunk, nt_headers, local_image);
		while (thunk && thunk->u1.AddressOfData)
		{
			if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
			{
				thunk->u1.Function = module_base + get_export_offset(module_name, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
			}
			else
			{
				auto import_by_name = (PIMAGE_IMPORT_BY_NAME)rva_to_va((uintptr_t)thunk->u1.AddressOfData, nt_headers, local_image);
				if (import_by_name)
				{
					thunk->u1.Function = module_base + get_export_offset(module_name, import_by_name->Name);
				}
			}
			thunk++;
		}
		import_desc++;
	}
	return true;
}

inline bool write_sections(PVOID local_image, PIMAGE_NT_HEADERS64 nt_headers,
                           std::uint64_t hidden_base_va, std::uint64_t clone_cr3)
{
	auto section = IMAGE_FIRST_SECTION(nt_headers);
	for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
	{
		if (section->SizeOfRawData == 0) continue;

		PVOID src = (PVOID)((uintptr_t)local_image + section->PointerToRawData);
		std::uint64_t dst_va = hidden_base_va + section->VirtualAddress;

		std::uint64_t bytes_written = hypercall::write_guest_virtual_memory(
			src, dst_va, clone_cr3, section->SizeOfRawData);

		if (bytes_written != section->SizeOfRawData)
		{
			std::println("[-] Failed to write section {:.8s} ({} / {} bytes)",
				(char*)section->Name, bytes_written, section->SizeOfRawData);
			return false;
		}
	}
	return true;
}

//=============================================================================
// KCT Hijack - trigger DllMain via KernelCallbackTable
//=============================================================================

inline HWND find_target_window(DWORD target_pid)
{
	struct EnumData { DWORD pid; HWND hwnd; };
	EnumData data = { target_pid, nullptr };

	EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
		auto* data = (EnumData*)lParam;
		DWORD window_pid = 0;
		GetWindowThreadProcessId(hwnd, &window_pid);
		if (window_pid == data->pid && IsWindowVisible(hwnd))
		{
			data->hwnd = hwnd;
			return FALSE;
		}
		return TRUE;
	}, (LPARAM)&data);

	return data.hwnd;
}

inline bool call_dll_main(std::uint64_t clone_cr3, std::uint64_t target_cr3,
                          std::uint64_t target_eprocess, std::uint64_t target_pid,
                          std::uint64_t hidden_base_va, std::uint64_t dll_base,
                          DWORD entry_point_rva, std::uint64_t shellcode_page_index)
{
	// shellcode VA = hidden_base + shellcode_page * 0x1000
	std::uint64_t shellcode_va = hidden_base_va + (shellcode_page_index * 0x1000);
	std::uint64_t data_va = shellcode_va + sizeof(g_RemoteCallDllMain);

	// prepare local shellcode buffer
	SIZE_T shellcode_total = sizeof(g_RemoteCallDllMain) + sizeof(DLLMAIN_STRUCT);
	std::vector<BYTE> local_shellcode(shellcode_total, 0);

	memcpy(local_shellcode.data(), g_RemoteCallDllMain, sizeof(g_RemoteCallDllMain));

	// patch shellcode: data pointer at offset 0x6
	*(uintptr_t*)(local_shellcode.data() + g_ShellDataOffset) = data_va;

	// fill DLLMAIN_STRUCT
	auto main_struct = (PDLLMAIN_STRUCT)(local_shellcode.data() + sizeof(g_RemoteCallDllMain));
	main_struct->Status = 0;
	main_struct->DllBase = (HINSTANCE)dll_base;
	main_struct->FnDllMain = dll_base + entry_point_rva;

	// write shellcode + struct to hidden memory
	std::uint64_t bytes_written = hypercall::write_guest_virtual_memory(
		local_shellcode.data(), shellcode_va, clone_cr3, shellcode_total);

	if (bytes_written != shellcode_total)
	{
		std::println("[-] Failed to write shellcode to hidden memory");
		return false;
	}

	std::println("[+] Shellcode at 0x{:X}, data at 0x{:X}", shellcode_va, data_va);

	// read EPROCESS.Peb
	std::uint64_t peb_addr = 0;
	hypercall::read_guest_virtual_memory(&peb_addr,
		target_eprocess + sys::offsets::eprocess_peb,
		sys::current_cr3, 8);

	if (peb_addr == 0)
	{
		std::println("[-] Failed to read PEB address from EPROCESS");
		return false;
	}

	std::println("[+] PEB: 0x{:X}", peb_addr);

	// read PEB.KernelCallbackTable (using target's CR3 since PEB is in target's userspace)
	std::uint64_t kct_addr = 0;
	hypercall::read_guest_virtual_memory(&kct_addr,
		peb_addr + sys::offsets::peb_kernel_callback_table,
		clone_cr3, 8);

	if (kct_addr == 0)
	{
		std::println("[-] Failed to read KernelCallbackTable from PEB");
		return false;
	}

	std::println("[+] KernelCallbackTable: 0x{:X}", kct_addr);

	// dump first 4 KCT entries to check which index is __fnCOPYDATA
	std::uint64_t kct_entries[4] = {};
	hypercall::read_guest_virtual_memory(kct_entries, kct_addr, clone_cr3, sizeof(kct_entries));
	std::println("[+] KCT[0]: 0x{:X}", kct_entries[0]);
	std::println("[+] KCT[1]: 0x{:X}", kct_entries[1]);
	std::println("[+] KCT[2]: 0x{:X}", kct_entries[2]);
	std::println("[+] KCT[3]: 0x{:X}", kct_entries[3]);

	// read original __fnCOPYDATA (first entry in KCT)
	std::uint64_t original_fn_copydata = kct_entries[0];

	std::println("[+] Original __fnCOPYDATA (KCT[0]): 0x{:X}", original_fn_copydata);

	// patch __fnCOPYDATA → our shellcode VA
	hypercall::write_guest_virtual_memory(
		&shellcode_va, kct_addr, clone_cr3, 8);

	// verify KCT patch by reading back
	std::uint64_t kct_verify = 0;
	hypercall::read_guest_virtual_memory(&kct_verify, kct_addr, clone_cr3, 8);
	std::println("[+] KCT patched: __fnCOPYDATA = 0x{:X} (expected 0x{:X}) {}",
		kct_verify, shellcode_va, kct_verify == shellcode_va ? "OK" : "MISMATCH!");

	// verify shellcode is readable from hidden memory
	BYTE shellcode_verify[4] = {};
	hypercall::read_guest_virtual_memory(shellcode_verify, shellcode_va, clone_cr3, 4);
	std::println("[+] Shellcode verify: first 4 bytes = {:02X} {:02X} {:02X} {:02X} (expected 48 83 EC 38)",
		shellcode_verify[0], shellcode_verify[1], shellcode_verify[2], shellcode_verify[3]);

	// find target window and trigger
	HWND hwnd = find_target_window(static_cast<DWORD>(target_pid));
	std::println("[+] Target HWND: 0x{:X}", (std::uint64_t)hwnd);

	if (hwnd)
	{
		COPYDATASTRUCT cds = {};
		WCHAR msg[] = L"X";
		cds.dwData = 1;
		cds.cbData = sizeof(msg);
		cds.lpData = msg;

		// enable enforce: force clone CR3 at every VM exit during callback
		hypercall::enable_cr3_enforce();
		std::println("[+] CR3 enforce enabled");

		LRESULT send_result = SendMessageW(hwnd, WM_COPYDATA, (WPARAM)hwnd, (LPARAM)&cds);
		std::println("[+] SendMessageW returned: {}", (long long)send_result);

		// immediate status check (before disabling enforce)
		DLLMAIN_STRUCT immediate_status = {};
		hypercall::read_guest_virtual_memory(&immediate_status, data_va, clone_cr3, sizeof(DLLMAIN_STRUCT));
		std::println("[+] Immediate status after SendMessage: Status={}", immediate_status.Status);

		// disable enforce
		hypercall::disable_cr3_enforce();
		std::println("[+] CR3 enforce disabled");

		// CR3 stats after trigger
		std::println("[+] CR3 stats after trigger: exits={} swaps={} last_seen=0x{:X}",
			hypercall::read_cr3_exit_count(), hypercall::read_cr3_swap_count(), hypercall::read_cr3_last_seen());
	}
	else
	{
		std::println("[-] No visible window found for PID {}", target_pid);
		// restore KCT before returning
		hypercall::write_guest_virtual_memory(
			&original_fn_copydata, kct_addr, clone_cr3, 8);
		return false;
	}

	// poll for completion
	DLLMAIN_STRUCT remote_status = {};
	for (int attempt = 0; attempt < 50; attempt++)
	{
		Sleep(100);
		hypercall::read_guest_virtual_memory(&remote_status, data_va, clone_cr3, sizeof(DLLMAIN_STRUCT));

		if (remote_status.Status == 2)
		{
			std::println("[+] DllMain executed successfully (Status=2)");
			break;
		}
	}

	if (remote_status.Status != 2)
	{
		std::println("[!] DllMain may not have executed (Status={})", remote_status.Status);
	}

	// restore original __fnCOPYDATA
	hypercall::write_guest_virtual_memory(
		&original_fn_copydata, kct_addr, clone_cr3, 8);

	std::println("[+] KCT restored");

	return remote_status.Status == 2;
}

//=============================================================================
// MmAccessFault EPT Hook
// Intercepts page faults on hidden memory (PML4[70]) and swaps CR3 to clone
// so the faulting instruction retries under the clone where hidden pages exist.
//=============================================================================

inline std::uint64_t mmaf_hook_va = 0; // stored for removal

inline bool install_mmaf_hook(std::uint64_t clone_cr3, std::uint64_t hidden_pml4_index = 70)
{
	// compute MmAccessFault VA from RVA + ntoskrnl base
	if (sys::offsets::mm_access_fault_rva == 0)
	{
		std::println("[-] MmAccessFault RVA not resolved (PDB failed?)");
		return false;
	}

	if (sys::kernel::modules_list.contains("ntoskrnl.exe") == false)
	{
		std::println("[-] ntoskrnl.exe not in modules list");
		return false;
	}

	std::uint64_t ntoskrnl_base = sys::kernel::modules_list["ntoskrnl.exe"].base_address;
	std::uint64_t mmaf_va = ntoskrnl_base + sys::offsets::mm_access_fault_rva;

	std::println("[+] MmAccessFault VA: 0x{:X}", mmaf_va);

	// build hypercall_info for write_guest_cr3
	hypercall_info_t call_info = {};
	call_info.primary_key = hypercall_primary_key;
	call_info.secondary_key = hypercall_secondary_key;
	call_info.call_type = hypercall_type_t::write_guest_cr3;
	call_info.call_reserved_data = 0;

	std::uint32_t hypercall_value = static_cast<std::uint32_t>(call_info.value);

	// build extra_assembled_bytes for the MmAccessFault EPT hook
	// MmAccessFault(ULONG FaultCode /*RCX*/, PVOID Address /*RDX*/, ...)
	//
	// Logic:
	//   if ((RDX >> 39) & 0x1FF) == hidden_pml4_index:
	//       write_guest_cr3(clone_cr3) via CPUID hypercall
	//       return STATUS_SUCCESS (0)
	//   else:
	//       fall through to original MmAccessFault
	//
	// Shellcode:
	//   push rax                          ; 50
	//   mov rax, rdx                      ; 48 8B C2
	//   shr rax, 39                       ; 48 C1 E8 27
	//   and eax, 0x1FF                    ; 25 FF 01 00 00
	//   cmp eax, <pml4_index>             ; 83 F8 XX
	//   jne .not_hidden (+23)             ; 75 17
	//   push rbx                          ; 53
	//   mov ecx, <hypercall_info_32>      ; B9 XX XX XX XX
	//   movabs rdx, <clone_cr3_64>        ; 48 BA XX XX XX XX XX XX XX XX
	//   cpuid                             ; 0F A2
	//   pop rbx                           ; 5B
	//   pop rax                           ; 58
	//   xor eax, eax                      ; 33 C0
	//   ret                               ; C3
	// .not_hidden:
	//   pop rax                           ; 58

	std::vector<std::uint8_t> shellcode;
	shellcode.reserve(42);

	// push rax
	shellcode.push_back(0x50);
	// mov rax, rdx
	shellcode.push_back(0x48); shellcode.push_back(0x8B); shellcode.push_back(0xC2);
	// shr rax, 39
	shellcode.push_back(0x48); shellcode.push_back(0xC1); shellcode.push_back(0xE8); shellcode.push_back(0x27);
	// and eax, 0x1FF
	shellcode.push_back(0x25); shellcode.push_back(0xFF); shellcode.push_back(0x01); shellcode.push_back(0x00); shellcode.push_back(0x00);
	// cmp eax, <pml4_index>
	shellcode.push_back(0x83); shellcode.push_back(0xF8); shellcode.push_back(static_cast<std::uint8_t>(hidden_pml4_index));
	// jne +23 (.not_hidden)
	shellcode.push_back(0x75); shellcode.push_back(0x17);

	// --- hidden path (23 bytes) ---
	// push rbx
	shellcode.push_back(0x53);
	// mov ecx, <hypercall_value>
	shellcode.push_back(0xB9);
	shellcode.push_back(static_cast<std::uint8_t>(hypercall_value >>  0));
	shellcode.push_back(static_cast<std::uint8_t>(hypercall_value >>  8));
	shellcode.push_back(static_cast<std::uint8_t>(hypercall_value >> 16));
	shellcode.push_back(static_cast<std::uint8_t>(hypercall_value >> 24));
	// movabs rdx, <clone_cr3>
	shellcode.push_back(0x48); shellcode.push_back(0xBA);
	for (int i = 0; i < 8; i++)
		shellcode.push_back(static_cast<std::uint8_t>(clone_cr3 >> (i * 8)));
	// cpuid
	shellcode.push_back(0x0F); shellcode.push_back(0xA2);
	// pop rbx
	shellcode.push_back(0x5B);
	// pop rax
	shellcode.push_back(0x58);
	// xor eax, eax
	shellcode.push_back(0x33); shellcode.push_back(0xC0);
	// ret
	shellcode.push_back(0xC3);

	// --- .not_hidden ---
	// pop rax
	shellcode.push_back(0x58);

	std::println("[+] MmAccessFault hook shellcode: {} bytes, clone_cr3=0x{:X}, hypercall=0x{:08X}",
		shellcode.size(), clone_cr3, hypercall_value);

	std::vector<std::uint8_t> post_original_bytes; // empty

	std::uint8_t status = hook::add_kernel_hook(mmaf_va, shellcode, post_original_bytes);

	if (status == 1)
	{
		mmaf_hook_va = mmaf_va;
		std::println("[+] MmAccessFault EPT hook installed at 0x{:X}", mmaf_va);
		return true;
	}

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
		return true;
	}

	std::println("[-] Failed to remove MmAccessFault EPT hook");
	return false;
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
	std::vector<uint8_t> dll_image;
	if (!load_dll_file(dll_path, dll_image))
	{
		std::println("[-] Failed to load DLL: {}", dll_path);
		return false;
	}

	auto dos_header = (PIMAGE_DOS_HEADER)dll_image.data();
	auto nt_headers = (PIMAGE_NT_HEADERS64)(dll_image.data() + dos_header->e_lfanew);

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		std::println("[-] Invalid PE signature");
		return false;
	}

	DWORD entry_point_rva = nt_headers->OptionalHeader.AddressOfEntryPoint;
	SIZE_T image_size = nt_headers->OptionalHeader.SizeOfImage;
	std::uint64_t pages_needed = (image_size + 0xFFF) / 0x1000;
	std::uint64_t shellcode_page = pages_needed; // one extra page for shellcode
	std::uint64_t total_pages = pages_needed + 1;

	std::println("[+] DLL: {} bytes, {} pages + 1 shellcode page", image_size, pages_needed);

	// 5. Setup hidden region (PML4[70])
	constexpr std::uint64_t hidden_pml4_index = 70;
	std::uint64_t hidden_base_va = hypercall::setup_hidden_region(hidden_pml4_index);
	if (hidden_base_va == 0)
	{
		std::println("[-] Failed to setup hidden region");
		return false;
	}

	std::println("[+] Hidden region at VA 0x{:X}", hidden_base_va);

	// 6. Map all needed pages
	for (std::uint64_t i = 0; i < total_pages; i++)
	{
		std::uint64_t result = hypercall::map_hidden_page(i);
		if (result == 0)
		{
			std::println("[-] Failed to map hidden page {}", i);
			return false;
		}
	}

	std::println("[+] Mapped {} hidden pages", total_pages);

	// 7. Relocate image
	if (!relocate_image((PVOID)hidden_base_va, dll_image.data(), nt_headers))
	{
		std::println("[-] Failed to relocate image");
		return false;
	}

	std::println("[+] Relocations applied (delta: 0x{:X})",
		hidden_base_va - nt_headers->OptionalHeader.ImageBase);

	// 8. Resolve imports
	if (!resolve_imports(dll_image.data(), nt_headers))
	{
		std::println("[-] Failed to resolve imports");
		return false;
	}

	std::println("[+] Imports resolved");

	// 9. Write PE header + sections to hidden memory
	{
		DWORD headers_size = nt_headers->OptionalHeader.SizeOfHeaders;
		std::uint64_t hdr_written = hypercall::write_guest_virtual_memory(
			dll_image.data(), hidden_base_va, cloned_cr3, headers_size);
		std::println("[+] PE header written: {} / {} bytes", hdr_written, headers_size);
	}

	if (!write_sections(dll_image.data(), nt_headers, hidden_base_va, cloned_cr3))
	{
		std::println("[-] Failed to write sections");
		return false;
	}

	std::println("[+] Sections written to hidden memory");

	// 10. Verify hidden memory is accessible under clone CR3 but NOT under original
	std::uint16_t verify_mz = 0;
	hypercall::read_guest_virtual_memory(&verify_mz, hidden_base_va, cloned_cr3, 2);
	std::uint64_t verify_orig = 0;
	std::uint64_t orig_read = hypercall::read_guest_virtual_memory(&verify_orig, hidden_base_va, process->cr3, 8);
	std::println("[+] Hidden base via clone: 0x{:X} (should be 0x5A4D = MZ)", verify_mz);
	std::println("[+] Hidden base via original: {} bytes read (should be 0 = unmapped)", orig_read);

	// Also verify first section (.text)
	auto first_section = IMAGE_FIRST_SECTION(nt_headers);
	if (first_section->SizeOfRawData > 0)
	{
		std::uint64_t text_va = hidden_base_va + first_section->VirtualAddress;
		std::uint8_t text_verify[16] = {};
		hypercall::read_guest_virtual_memory(text_verify, text_va, cloned_cr3, 16);
		std::println("[+] .text section at 0x{:X}: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
			text_va, text_verify[0], text_verify[1], text_verify[2], text_verify[3],
			text_verify[4], text_verify[5], text_verify[6], text_verify[7]);
	}

	// 11. Print CR3 stats before trigger
	std::println("[+] CR3 stats before trigger: exits={} swaps={} last_seen=0x{:X}",
		hypercall::read_cr3_exit_count(), hypercall::read_cr3_swap_count(), hypercall::read_cr3_last_seen());

	// 12. Call DllMain via KCT hijack
	bool dllmain_result = call_dll_main(
		cloned_cr3, process->cr3, process->eprocess, process->pid,
		hidden_base_va, hidden_base_va, entry_point_rva, shellcode_page);

	if (dllmain_result)
	{
		std::println("[+] Injection complete - DLL running in hidden memory at 0x{:X}", hidden_base_va);
	}
	else
	{
		std::println("[-] DllMain execution failed or timed out");
		std::println("[*] Disabling CR3 intercept to avoid overhead...");
		hypercall::disable_cr3_intercept();
	}

	return dllmain_result;
}

} // namespace inject
