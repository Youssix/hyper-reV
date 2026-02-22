# Deobfuscation and Analysis of Ring-1.io

**Authors:** IDontCode, noahware, Eggsy, AVX — back.engineering
**Date:** February 4, 2026
**Source:** https://back.engineering/blog/04/02/2026/
**Files:** https://github.com/backengineering/ring-1.io

---

## Introduction

The integrity of online video games is locked in a perpetual cat-and-mouse battle between anti-cheat developers and cheat engineers. Over the years, we've witnessed the rise of increasingly sophisticated evasion tactics, often outpacing those in the antivirus and red-team communities. In this article, we'll dissect the inner workings of a prominent cheat provider, ring-1.io.

As part of this research, we partially deobfuscated multiple Themida-protected binaries used by ring-1.io, including its UEFI bootloader implant. Several critical functions were recovered to enable static analysis of the implant's behavior. This work provides visibility into mechanisms that are intentionally designed to resist inspection, including virtualization-assisted hooks, execution redirection, and kernel manipulation techniques.

Ring-1.io has drawn significant attention in recent years, as major game studios like Bungie and Ubisoft pursue legal action to dismantle it, yet it endures despite settlements and ongoing cases that recently uncovered a $12 million Bitcoin stash and new defendants in 2025. This raises a critical question: When lawsuits fail, what's the next step? That's where our reverse engineering services come in, tailored for precisely these challenges. Join us for a deep dive into the technical intricacies of ring-1.io.

- https://www.courtlistener.com/docket/67656565/bungie-inc-v-fisher/
- https://www.courtlistener.com/docket/60084066/bungie-inc-v-thorpe/

---

## Table of Contents

1. Loader
2. Bootloader Implant
3. Injection Into Hyper-V
   - Mapping Into Hyper-V
   - SLAT Logic
4. Guest Physical Memory Redirection
   - EPT Violation Handling
   - MTF Handling
5. VMEXIT Hooks
6. Implant Communication
   - Guest User-Mode → Guest Kernel Implant Communication
   - Kernel Implant → VMX Root Communication
7. Process Injection - Overview
   - Cloning Target Game Page Tables
   - Insertion of Malicious Page Table Entries
   - Loading of Malicious Page Table
   - Call to Hypervisor For Loading Page Tables
   - Hiding Malicious Page Tables
   - Hiding Memory Contents Through EPT
8. EPT Hooks
   - Inline Hook (Relocation) EPT Hook
   - Shellcode-Based (Full-Context) EPT Inline Hook
9. All Hooks
10. Possible Detections
11. Conclusion

---

## 1. Loader

The loader serves as the initial user-mode executable in ring-1.io's cheat deployment pipeline. Designed for evasion, each loader instance has a unique file hash and self-deletes after execution. This forces customers to redownload a fresh loader with a different filename and hash upon each use, mitigating risks from persistent Windows artifacts such as prefetch files, shim cache entries, and other forensic traces that could be used to flag entire batches of players who have executed the loader.

Communication with ring-1.io's backend occurs over HTTPS, authenticated via JWT (JSON Web Tokens) for session validation. The loader leverages libcurl as its HTTP client library. To enhance security, HTTP response bodies are encrypted using a custom symmetric scheme: the first 16 bytes of the payload act as the decryption key for the subsequent encrypted data.

Once a user authenticates and selects the desired cheats, the loader mounts the EFI system partition and replaces `bootmgfw.efi` and `bootx64.efi` on disk with modified versions. For each selected cheat, an additional section is appended to the bootloader implant. These section(s) contain the user's JWT token, the target process name, and the encrypted game cheat binary. On the next system boot, the modified `bootmgfw.efi` or `bootx64.efi` executes before the operating system loads, giving the implant full control over the boot process. The bootloader's entry point is detoured to an appended section called `.trp`.

**These modifications inherently violate Secure Boot integrity. As such ring-1 does not support secure boot.**

---

## 2. Bootloader Implant

The bootkit is protected with Themida and implements several security mechanisms that execute prior to the original entry point. The virtual machine components are compressed and multiple sections are encrypted. During Themida boot execution, the entry point decompresses the VM components and decrypts the protected sections.

Upon execution of the real entry point, the implant immediately restores the original `bootmgfw.efi` and `bootx64.efi` binaries on the EFI system partition. It then manipulates the last modification time of these files and parent folders in an attempt to evade detection.

### Anti-Forensics: Timestamp Spoofing

```c
EFI_STATUS UpdateTimestampsRecursive(
    IN EFI_FILE_PROTOCOL *Root,
    IN CHAR16 *Path,
    IN EFI_FILE_INFO *OriginalFileInfo,
    IN EFI_BOOT_SERVICES *BootServices)
{
    // Walk up the directory tree, spoofing timestamps on each level
    // Uses timestamps from bootmgr.efi (original Microsoft file)
    // Covers: CreateTime, LastAccessTime, ModificationTime
}
```

### Anti-VM Checks

After restoring boot files, the implant performs anti-virtualization timing checks combining CPUID (forced vm-exiting instruction) with RDTSC/RDTSCP measurements. If virtualization is detected, the implant induces a system crash.

### SetVirtualAddressMap Hook

If no virtualization is detected, the implant hooks `SetVirtualAddressMap` by replacing the function pointer in the `EFI_RUNTIME_SERVICES` table. This hook intercepts the firmware-to-OS handoff when `winload` finalizes the kernel's virtual address space.

```c
RuntimeServices = (*EfiSystemTable_0)->RuntimeServices;
SetVirtualAddressMap = (__int64)RuntimeServices->SetVirtualAddressMap;
RuntimeServices->SetVirtualAddressMap = (VOID *)hook_SetVirtualAddressMap;
```

### Boot Chain Hook Sequence

In `hook_SetVirtualAddressMap`:
1. Captures return address, walks backward to find `winload` image base (MZ header scan)
2. Scans winload for signature: `48 8B 0D ? ? ? ? 48 85 C9 75` → hvloader base address
3. Scans hvloader for signature: `E8 ? ? ? ? E8 ? ? ? ? 80 3D` → `hv_launch` thunk
4. Hooks `hv_launch` to intercept Hyper-V launch

```c
// Deobfuscated hook installation
InstallHook(
    &g_p1C_0x140e46c3e,
    SwitchContextScanResult + *(int *)(SwitchContextScanResult + 1) + 5,
    (unsigned __int64)hook_hv_launch);
```

---

## 3. Injection Into Hyper-V

### hvloader.dll!hv_launch

```c
void __fastcall hvloader_hv_launch(
    std::uint64_t hyperv_cr3,
    std::uint8_t* hyperv_entry_point,
    std::uint8_t* entry_point_gadget,
    std::uint64_t guest_kernel_cr3)
{
    __writecr3(guest_kernel_cr3);
    __asm { jmp entry_point_gadget }
}
```

In this detour, the attacker:
- Maps the implant into Hyper-V AND the guest kernel
- Hooks Hyper-V's VMEXIT entry and handler

**Key insight:** Ring-1 patches only the final Hyper-V image (protected by SLAT), not the unprotected copies. This should prevent guest-side integrity checks. However, **ring-1's insecure SLAT implementation identity-maps all guest physical memory including host memory**, making this protection redundant.

### Hyper-V Signatures Scanned

| Signature | Purpose |
|-----------|---------|
| `65 8B 14 25 ? ? ? ? 48 8D 0D ? ? ? ? 44` | GS offset for logical processor ID |
| `C7 44 24 ? ? ? ? ? 48 89 4C 24 ? 48 8B 4C 24` | VMEXIT entry point |
| `E8 ? ? ? ? E9 ? ? ? ? 74 0D` | VMEXIT logic handler |

### Mapping Into Hyper-V

The implant is mapped into both guest kernel and host Hyper-V page tables:

```c
// For each page of the implant:
current_cr3 = __readcr3();
guest_pte = *AllocatePageTableEntry_RecursiveSetup(
    current_cr3, current_offset + r1implant_base_address, 0, 0, 0)
    & 0xFFFFFFFFF000LL;

hyperv_pte = AllocatePageTableEntry_RecursiveSetup(
    hyperv_cr3, current_offset + r1implant_base_address, 0, 0, 0);

// Map same physical page in both address spaces
*hyperv_pte = (*hyperv_pte & 0x7FFF000000000FFCLL) + guest_pte + 3;
```

### SLAT Logic

Each logical processor creates its own unique EPTP (identity map of all guest physical memory) in the first VMEXIT. These EPT mappings are **not shared** between processors — no synchronization needed.

**Detection vectors:**
- Malicious EPTPs don't reflect Hyper-V's original EPTP state
- On HVCI systems: identity maps with RWX violate W^X enforcement
- Host Hyper-V memory is exposed to guest (insecure SLAT)

---

## 4. Guest Physical Memory Redirection

### EPT Violation Handling

When an EPT-based memory redirection is placed:
- **Execute**: Page shows shadow (hooked) content, permissions `--X`
- **Read**: EPT violation → switch to original page, permissions `RW-`
- **Write**: EPT violation → switch to original page, permissions `RWX`, set MTF flag

#### Execute Violation
```c
if ((exit_qualification & 4) != 0) {
    *ept_pte = (ept_hook_info->shadow_page_index & 0xFFFFFFFFF000LL)
             + (*ept_pte & 0xFFFF000000000FF8uLL) + 4; // --X
    return 1;
}
```

#### Read Violation (with self-read detection)
```c
if ((exit_qualification & 1) != 0) {
    if ((guest_linear_address ^ guest_rip) > 0xFFF) {
        // Self-read: set R-X to avoid infinite loop
        *ept_pte = readable_pte_permissions | 5;
        set_monitor_trap_flag();
    } else {
        *ept_pte = readable_pte_permissions | 1; // R-- only
    }
}
```

#### Write Violation
```c
if ((exit_qualification & 2) != 0) {
    *ept_pte = (guest_physical_address & 0xFFFFFFFFF000LL)
             + (*ept_pte & 0xFFFF000000000FF8uLL) + 7; // RWX
    get_logical_processor_state()[61] = 1; // signal write sync needed
}
```

### MTF Handling

After read/write violations, the MTF handler:
1. Reverts permissions back to `--X` (execute-only shadow page)
2. For writes: **propagates write content to shadow page** (anti-tamper)

```c
// Write synchronization: copy modified bytes from original to shadow
if (get_logical_processor_state()[61]) {
    original_page = map_guest_physical_to_host_virtual(hook->original_page_index);
    shadow_page = map_guest_physical_to_host_virtual(hook->shadow_page_index);
    for (i = 0; i != 4096; i += 2) {
        // Bitmap-based selective copy
        if (!_bittest64(&hook->Unknown[8 * (i >> 6)], i & 0x3E))
            shadow_page[i] = original_page[i];
    }
}
```

**Why MTF write sync matters:** Without it, an AC could write known bytes to a hooked page, execute them, and compare expected vs actual results. With sync, the shadow always matches writes.

---

## 5. VMEXIT Hooks

### Two hooks on Hyper-V's VMEXIT routine:

1. **Entry point hook**: Intercepts BEFORE Hyper-V saves guest state → can VMRESUME cleanly
2. **Processing hook**: Intercepts AFTER Hyper-V processes the exit → ensures malicious EPTP is always restored

The processing hook:
- Loads original Hyper-V EPTP before calling original handler (prevents Hyper-V from modifying malicious EPTP)
- Restores malicious EPTP after handler returns (guest always executes under attacker's EPTP)

---

## 6. Implant Communication

### 6.1 Guest User-Mode → Guest Kernel (NtClose EPT Hook)

The kernel implant is accessed via an EPT hook on `ntoskrnl.exe!NtClose`.

```c
__int64 __fastcall hook_NtClose(__int64 rcx0, ...) {
    // Validate: must be from usermode (SegCs == 0x33), IRQL == 0
    if (!TrapFrame || TrapFrame->SegCs != 0x33 || KeGetCurrentIrql())
        return NtClosePtr(rcx0, ...);

    // Check magic value
    if (rcx0 != 0x19283EF938AB49EFLL)
        return NtClose(rcx0, ...);

    // Validate RIP is in expected range
    if (CheckAddressInRange(pContext, TrapFrame->Rip))
        return KernelImplantHandleRequest(a2, a3, a4);
}
```

**User-mode syscall stub:**
```asm
KernelImplantRequest proc near
    mov     r8, 19283EF938AB49EFh  ; magic value
    mov     edx, 4
    mov     ecx, 0Fh               ; NtClose syscall ID (0xF on all Win10/11)
    call    syscall_wrapper
KernelImplantRequest endp
```

### KernelImplantHandleRequest — Command Dispatch

| Command | Handler |
|---------|---------|
| CMD_CREATE_EPT_HOOK (0) | CreateEptHook_InThreadContext |
| CMD_REMOVE_EPT_HOOK (1) | RemoveEptHook_InThreadContext |
| CMD_CHECK_HOOKABLE (2) | CheckHookable_Vmcall |
| CMD_PROCESS_PATH (3) | ProcessPath_ConvertLowercase_AddToList_PS |
| CMD_CONVERT_STRING (4) | ConvertStringToStdString_AndProcess |
| CMD_INSTALL_EPT_HOOK_WITH_CONTEXT (5) | InstallEptHook_WithThreadContext |
| CMD_REMOVE_EPT_HOOK_VALIDATED (6) | RemoveEptHook_WithThreadContext_ValidatePointer |
| CMD_HANDLE_DEVICE_IO (7) | HandleDeviceIoRequest_WithRetries |
| 8 | ThreadCreation_ResolveExports_AllocateWithTracking |
| 0xB | Unknown_Handler |
| 0xC | InitializeDiskFilters_WithMultipleRetries |
| 0xE | Execute_MemcopyInThreadContext |
| 0xF | ValidateAddress_MmIsAddressValid_ReturnStatus |
| 0x10 | CopyGlobalBuffer_77Bytes |
| 0x11 | WriteBackGlobalBuffer_Offset49 |
| 0x17 | DecryptAndProcessSection_ToBuffer |
| 0x18 | LazyImport_ResolveExport_Simple |
| 0x19 | ExecuteCallback_Function2F190_4Params |
| 0x1A-0x1C | TimeDivision calculations, ProcessDataWithMutex |
| 0x20 | CopyGlobalData_WithMutex_24ByteBlocks |
| 0x21 | CreateThreadWithStringBuffers_InMutex |
| 0x22 | MutexProtected_FreeAndMove_CallOffset60E0 |

### 6.2 Kernel Implant → VMX Root (VMCALL)

```c
__int64 __fastcall vmcall_handler(__int64 trap_frame) {
    // Check magic value
    if (*(_QWORD *)(dereference_pointer(trap_frame) + 0x78) == 0xDEADBEEFDEADBEEFuLL
        && check_address_range(implant_info, get_guest_rip(trap_frame)))
    {
        switch (code) {
            case 0: update_epte_and_invept(trap_frame); break;
            case 1: write_guest_cr3(trap_frame); break;
            case 2: read_guest_cr3(trap_frame); break;
            case 4: copy_guest_physical_memory(trap_frame); break;
        }
    }
}
```

**VMX Root operations (minimal set):**
- Read guest CR3
- Write guest CR3
- Copy guest physical memory
- Update EPT page table entry

---

## 7. Process Injection

### Overview

1. Clone target process's PML4 → "malicious page tables"
2. Insert DLL page table entries into the clone
3. Hook `MmAccessFault` to intercept page faults
4. When DLL executes under original PT → page fault → hook loads malicious CR3
5. Hide malicious CR3 via CR3 read/write interception

### 7.1 Cloning Page Tables

```c
// Allocate new PML4
*process_context_pml4 = Allocate_AlignedMemory(4096, 0x1000u);
// Copy current PML4
memmove(*process_context_pml4, GuestVA_To_HostPA(current_cr3 & 0xFFFFFFFFF000LL), 0x1000u);
// Get physical address of copy
copy_cr3 = GuestCR3_TranslateVA_To_PA(pml4_copy) & 0xFFFFFFFFF000LL;
```

### 7.2 Inserting DLL PTEs

```c
for each page:
    pte = AllocatePageTableEntry_RecursiveSetup(copy_pml4, virtual_addr, 1, ...);
    *pte = (physical_address & 0xFFFFFFFFF000LL)
         + (*pte & 0x7FFF000000000FF8LL)
         + 7; // supervisor, write, present (NX cleared)
    invlpg(virtual_addr);
```

### 7.3 Loading Malicious CR3 via MmAccessFault Hook

When DLL code page faults under original CR3:
```asm
call    get_process_context
call    get_process_copy_cr3     ; returns malicious CR3
mov     ecx, 1                   ; VMCALL code: write_guest_cr3
mov     rdx, rax                 ; malicious CR3
call    execute_vmcall_hypercall
```

### 7.4 CR3 Read Spoofing

```c
// If guest reads CR3 and it matches malicious CR3:
if (((guest_cr3 ^ get_process_copy_cr3(ctx)) & 0xFFFFFFFFF000LL) == 0) {
    guest_cr3 = get_process_original_cr3(ctx); // return spoofed clean value
}
```

### 7.5 CR3 Write Synchronization

On every CR3 write to the game process, sync the malicious PML4 with the new real PML4:

```c
char sync_page_tables(process_context, original_pml4_mapped) {
    for (index = 0; index < 512; index++) {
        if (index != reserved_pml4e) { // skip attacker's PML4E
            if (copy_pml4[index] != original_pml4[index]) {
                copy_pml4[index] = original_pml4[index];
                has_updated = 1;
            }
        }
    }
    return has_updated;
}
```

### 7.6 Hiding DLL Memory via EPT

```c
shadow_page = get_or_allocate_shadow_page(hook, section_va);
memmove(shadow_page, section_va, 0x1000u);
memset(section_va, 0xCE, 0x1000u); // DETECTABLE PATTERN!
```

---

## 8. EPT Hooks

### 8.1 Inline Hook (Relocation)

1. EPT hook on target code page (shadow page)
2. First instructions replaced with JMP to detour
3. Overwritten instructions copied to trampoline
4. Detour executes original instructions from trampoline
5. Control returns past the JMP

### 8.2 Full-Context EPT Hook

For arbitrary instruction boundaries (not just function entry):

1. 14-byte absolute JMP at hook site
2. Redirects to shellcode stub
3. Stub saves ALL registers + RFLAGS + FPU/SSE state (FXSAVE)
4. Calls detour with full context
5. Restores everything
6. Executes relocated instructions
7. Resumes at instruction after hook

**Magic value in shellcode:** `0x1E38EDFF2301EEBC` (replaced with actual callback address)

---

## 9. All Hooks

### Complete Hook List

| Hook Target | Purpose |
|------------|---------|
| **IopCreateFile** | File operation interception |
| **IopXxxControlFile** | Device I/O control interception |
| **PsWatchWorkingSet** | Suppress working set notifications for cheat memory |
| **MmAccessFault** | Handle page faults for DLL injection (CR3 swap) |
| **MiProcessLoaderEntry** | Module load interception |
| **NtGdiBitBlt** | Screenshot interception |
| **NtGdiStretchBlt** | Screenshot interception |
| **NtDCompositionBeginFrame** | Composition frame interception |
| **DpiDxgkDdiQueryDeviceDescriptor** | GPU descriptor spoofing |
| **MmProtectVirtualMemory** | Memory protection interception |
| **NtQueryValueKey** | Registry value spoofing |
| **NtOpenKey** | Registry key interception |
| **MmCleanProcessAddressSpace** | Process cleanup interception |
| **ReadPartitionTable** | Disk partition spoofing |
| **IofCallDriver** | I/O request interception |
| **IofCompleteRequest** | I/O completion interception |
| **classnpnp!ClassGlobalDispatch** | Storage class driver interception |
| **partmgr!PmReadPartitionTable** | Partition manager spoofing |
| **NdisReadConfiguration** | Network config spoofing |
| **NdisMSetMiniportAttributes** | Network adapter spoofing |
| **NsiGetAllParameters** | Network parameter spoofing |
| **NsiEnumerateObjectsAllParametersEx** | Network enumeration spoofing |
| **KiDispatchException** | Exception suppression for implant faults |
| **KiSystemCall64_ServiceExit** | Instrumentation callback bypass |
| **VrpIoctlDeviceDispatch** | Device dispatch interception |

### nvlddmkm.sys (Nvidia Driver) Hooks

Signature scans:
- `81 BB 10 06 01 00 D2 6A C6 A7`
- `BA D2 6A C6 A7`

Purpose: Intercept GID validation (magic `0xA7C66AD2` = PMU_SHA1_GID_SIGNATURE) for UUID/serial generation spoofing.

### Hook_KiDispatchException (Exception Handler)

Gracefully handles memory access faults from the implant:

```c
// Magic value in r10 signals implant operation
if (IsAddressInModuleRange(implant, FaultingRIP)
    && pTrapFrame->R10 == 0x9EFABE87C1FE38E2uLL) {
    pTrapFrame->Rip += pTrapFrame->Rax & 0xF; // skip faulting instruction
    pTrapFrame->R10 = 0x1337LL; // signal failure to caller
    return ContinueExecution;
}
```

Helper stub pattern:
```asm
TryCopyQword proc
    mov     r10, 9EFABE87C1FE38E2h  ; magic
    mov     eax, 3                    ; instruction size
    mov     rax, [rcx]               ; potentially faulting read
    mov     [rdx], rax
    mov     eax, 0                    ; success
    cmp     r10, 1337h               ; was it faulted?
    jz      failed
    mov     eax, 1
failed:
    xor     r10, r10
    retn
TryCopyQword endp
```

### hook_KiSystemCall64_ServiceExit (Instrumentation Callback Bypass)

Signature: `4C 8B 95 E8 ? ? ? 48 89 85 E8`

Prevents instrumentation callbacks from being invoked on syscalls originating from the cheat:

```c
if (IsAddressInProtectedRegions(ctx, *(_QWORD *)(SavedRbp + 0xE8))) {
    pHookContext->Rax = *(_QWORD *)(SavedRbp + 0xE8); // preserve original return
}
```

### hook_NtGdiBitBlt / hook_NtGdiStretchBlt (Screenshot Interception)

- Ignores blits < 151px in either dimension
- Forwards blit parameters to user-mode via shared comm block
- Waits up to 2000ms for user-mode acknowledgment before proceeding

### hook_PsWatchWorkingSet

Suppresses working set notifications if the faulting address or instruction pointer falls within the cheat's memory region.

---

## 10. Possible Detections

### 1. Shadow PML4E Scan
The implant's `sync_page_tables` copies every PML4E except the reserved one. Detection: execute under the cloned CR3, probe PML4E-backed ranges for mappings with no VAD. Or: clear accessed bits, flush TLB, access memory, check if accessed bit toggled in real (not shadow) page tables.

### 2. Intel Processor Trace (IPT) Analysis
IP packets contain addresses within the cheat DLL's VA range (no legitimate mapping in real PTs). PIP packets reveal the cloned CR3 value.

### 3. Physical Memory 0xCE Page Scan
Shadow pages are filled with `0xCE`. Scan physical memory for entirely 0xCE-filled pages not backed by memory manager.

### 4. EFI Runtime Region Execution Analysis
Mark all EFI runtime code as NX, incrementally re-enable. Each page fault identifies an actively executing EFI page. Analyze contents since implant code is called more frequently than normal EFI code.

### 5. Hyper-V Memory Exposure
Ring-1's SLAT identity-maps all guest physical memory including host Hyper-V memory. On legitimate VBS/HVCI: host pages are SLAT-protected. Test by patching Hyper-V's CPUID vendor string — if it reflects in guest, SLAT is broken.

### 6. RWX Anomaly Under HVCI
HVCI enforces W^X in EPT. Ring-1 rebuilds per-processor EPTPs as identity maps with RWX. This should never be possible on HVCI.

---

## 11. Conclusion

Key takeaway: deliberate separation of responsibilities across privilege boundaries:
- Guest user-mode: entry point only
- Guest kernel: Windows API access
- VMX root: minimal privileged operations, isolated from guest

Secure Boot would prevent this attack chain when correctly enforced. The explicit requirement to disable Secure Boot demonstrates how usability tradeoffs undermine platform defenses.

---

## Quick Reference — Magic Values

| Value | Usage |
|-------|-------|
| `0x19283EF938AB49EF` | NtClose magic (user→kernel comm) |
| `0xDEADBEEFDEADBEEF` | VMCALL magic (kernel→VMX root comm) |
| `0x9EFABE87C1FE38E2` | KiDispatchException magic (fault handler) |
| `0x1E38EDFF2301EEBC` | EPT hook shellcode placeholder |
| `0x1337` | Fault signal return value |
| `0xCE` | Shadow page fill byte (DETECTABLE) |
| `0xA7C66AD2` | PMU_SHA1_GID_SIGNATURE (nvlddmkm) |

## Quick Reference — Signatures

| Signature | Target |
|-----------|--------|
| `48 8B 0D ? ? ? ? 48 85 C9 75` | hvloader base in winload |
| `E8 ? ? ? ? E8 ? ? ? ? 80 3D` | hv_launch thunk in hvloader |
| `65 8B 14 25 ? ? ? ? 48 8D 0D ? ? ? ? 44` | GS processor ID in Hyper-V |
| `C7 44 24 ? ? ? ? ? 48 89 4C 24 ? 48 8B 4C 24` | VMEXIT entry in Hyper-V |
| `E8 ? ? ? ? E9 ? ? ? ? 74 0D` | VMEXIT handler in Hyper-V |
| `4C 8B 95 E8 ? ? ? 48 89 85 E8` | KiSystemCall64 service exit |
| `81 BB 10 06 01 00 D2 6A C6 A7` | nvlddmkm GID validation |
| `BA D2 6A C6 A7` | nvlddmkm GID validation (alt) |
