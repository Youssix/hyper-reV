// =============================================================================
// ring-1.io — hook_MiProcessLoaderEntry reverse engineering pseudocode
// =============================================================================
//
// MiProcessLoaderEntry is an internal ntoskrnl function called every time a
// kernel module (driver) is loaded or unloaded. ring-1.io hooks it via EPT
// (shadow page) to intercept ALL driver loads without using the detectable
// PsSetLoadImageNotifyRoutine callback.
//
// Parameters:
//   a1 = KLDR_DATA_TABLE_ENTRY* (loader entry for the module)
//        +0x30 (48)  = DllBase (void*)
//        +0x40 (64)  = SizeOfImage (ULONG)
//        +0x58 (88)  = BaseDllName.Length (USHORT, in bytes)
//        +0x60 (96)  = BaseDllName.Buffer (PWCH)
//   a2 = operation: 0 = unload, 1 = load
//
// All string constants are XOR-encrypted at rest with key:
//   { 0x1ECEACECD73CD2B3, 0xF7422BB1E10B1A60 }
// Decrypted inline via _mm_xor_ps before use, then discarded on stack.
//
// Source: bootloader-implant-deobfuscated.bin @ 0x14000C510 (size: 0x32D7)
// =============================================================================

#include <ntdef.h>

// ---------------------------------------------------------------------------
// Forward declarations (other EPT hooks installed by this handler)
// ---------------------------------------------------------------------------
extern "C" __int64 hook_NtDCompositionBeginFrame(...);
extern "C" __int64 hook_NtGdiStretchBlt(...);
extern "C" __int64 hook_NtGdiBitBlt(...);
extern "C" __int64 hook_DpiDxgkDdiQueryDeviceDescriptor(...);
extern "C" __int64 hook_NdisReadConfiguration(...);
extern "C" __int64 hook_NdisMSetMiniportAttributes(...);
extern "C" __int64 hook_NsiGetAllParameters(...);
extern "C" __int64 hook_NsiEnumerateObjectsAllParametersEx(...);
extern "C" __int64 hook_classnpnp_ClassGlobalDispatch(...);
extern "C" __int64 hook_partmgr_PmReadPartitionTable(...);
extern "C" __int64 hook_VrpIoctlDeviceDispatch(...);
extern "C" __int64 hook_Wrapper_CallSmallFunction277F0(...);
extern "C" __int64 hook_IofCallDriver(...);
extern "C" __int64 hook_IofCompleteRequest(...);

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
static bool     g_ExecutingEPTHook;         // = 1 while inside any EPT hook
static bool     g_bSpooferEnabled;          // HWID spoofer feature toggle
static int      g_DriverEnumInitState;      // once-init sentinel (-1 = done)
static int      g_DisplayDriverInitState;   // once-init for display driver enum

// Module tracking (PrepareImageStructure fills a 0x40-byte struct):
//   +0x00 = DllBase
//   +0x20 = mapped image info (base + size for sig scans)
struct module_info_t {
    void*       dll_base;           // +0x00
    uint32_t    size_of_image;      // +0x08
    char        _pad[0x18];
    void*       mapped_base;        // +0x20  (for IDASignatureScan)
    uint64_t    mapped_size;        // +0x28
};

static module_info_t* g_pNtoskrnlModule;    // resolved elsewhere (boot)
static module_info_t* g_pHalModule;         // hal.dll
static module_info_t* g_pVgkModule;         // vgk.sys (Vanguard anti-cheat)
static module_info_t* g_pWin32kBaseModule;  // win32kbase.sys
static module_info_t* g_pWin32kFullModule;  // win32kfull.sys
static module_info_t* g_pDxgkrnlModule;     // dxgkrnl.sys
static module_info_t* g_pNvidiaModule;      // nvlddmkm.sys
static module_info_t* g_pKbdClassModule;    // kbdclass.sys
static module_info_t* g_pMouseHidModule;    // mouhid.sys
static module_info_t* g_pMouseClassModule;  // mouclass.sys
static module_info_t* g_pClassPnpModule;    // classpnp.sys
static module_info_t* g_pPartMgrModule;     // partmgr.sys
static module_info_t* g_pStorPortModule;    // storport.sys
static module_info_t* g_pNetIoModule;       // netio.sys
static module_info_t* g_pTcpIpModule;       // tcpip.sys
static module_info_t* g_pNduModule;         // ndu.sys
static module_info_t* g_pEacModule;         // EasyAntiCheat*.sys
static module_info_t* g_pHalModule2;        // hal.dll (second ref for spoofer)

// Loaded driver registry (mutex-protected vector):
//   Each entry = { DllBase, SizeOfImage, lowercase_name } (40 bytes)
static mutex_t          g_DriverListMutex;
static vector<driver_entry_t> g_DriverList; // xmmword_1402DF908

// EPT hook contexts (HOOK_CONTEXT = 0x140-byte struct per hook site)
static HOOK_CONTEXT  HookContext_MiProcessLoaderEntry;  // this hook itself
static HOOK_CONTEXT  HookContext_NtDCompositionBeginFrame;
static HOOK_CONTEXT  HookContext_NtGdiBitBlt;
static HOOK_CONTEXT* g_HookContext_NtGdiStretchBlt;     // heap-allocated
static HOOK_CONTEXT* g_HookContext_DxgkFn1;             // DxgkDdiQueryDeviceDescriptor
static HOOK_CONTEXT* g_HookContext_ClassPnpFn;          // ClassGlobalDispatch
static HOOK_CONTEXT* g_HookContext_PartMgrFn;           // PmReadPartitionTable
// ... + NdisRead, NdisSetMiniport, NsiGetAll, NsiEnum, VrpIoctl, etc.

// Original function pointer (saved by EptInstallHook trampoline mechanism)
static __int64 (*original_MiProcessLoaderEntry)(__int64 entry, unsigned int operation);


// =============================================================================
// One-time initialization (called on first driver load via MutexedInit)
// =============================================================================
//
// InstallEptHooks_InitProcAddress_WithShellcode @ 0x14000F850
//
// Resolves ntoskrnl exports and installs core I/O hooks:
//
static void InstallEptHooks_InitProcAddress_WithShellcode()
{
    // 1. Acquire driver enumeration lock
    // ExAcquireResourceExclusiveLite(&g_DriverEnumResource) (resolved by XOR name)
    auto ExAcquireResource = LookupExport(g_pNtoskrnlModule, XOR("ExAcquireResourceExclusiveLite"));
    ExAcquireResource(&g_DriverEnumResource);

    if (!g_bSpooferEnabled)
        return;

    // 2. Hook IofCompleteRequest — intercepts I/O request completion
    //    Purpose: inspect completed IRPs for spoofer results, clean up injected
    //    completion routines (magic 0x4C7053FA36C6A164 in allocated context)
    auto IofCompleteRequest_addr = LookupExport(g_pNtoskrnlModule, XOR("IofCompleteRequest"));
    EptInstallHook(&HookContext_IofCompleteRequest, IofCompleteRequest_addr,
                   hook_IofCompleteRequest, /*trampoline=*/false);

    // 3. Hook IofCallDriver — intercepts I/O request dispatch
    //    Purpose: intercept IRP_MJ_DEVICE_CONTROL (0x0E) and IRP_MJ_INTERNAL_DEVICE_CONTROL (0x0F)
    //    for storage/disk/network spoofer. Checks IO_STACK_LOCATION.MajorFunction.
    //    Uses shellcode relocation: patches magic 0x1E38EDFF2301EEBC with hook_IofCallDriver address
    auto IofCallDriver_addr = LookupExport(g_pNtoskrnlModule, XOR("IofCallDriver"));
    if (!IsHookAlreadyInstalled(&HookContext_IofCallDriver)) {
        auto ctx = (HOOK_CONTEXT*)malloc(0x140);
        InitializeHookContext(ctx);

        // Copy shellcode template, patch magic address placeholder
        uint8_t shellcode[...];
        memcpy(shellcode, &EPT_Hook_Shellcode_Stub, shellcode_size);
        for (size_t i = 0; i < shellcode_size; i++) {
            if (*(uint64_t*)&shellcode[i] == 0x1E38EDFF2301EEBC)
                *(uint64_t*)&shellcode[i] = (uint64_t)hook_IofCallDriver;
        }

        EptInstallHook_WithRelocation(ctx, IofCallDriver_addr, shellcode, shellcode_size,
                                      /*unused=*/0, /*broadcast=*/true);
    }
}


// =============================================================================
// EptInstallHook — Core EPT hook installer
// =============================================================================
//
// @ 0x140024390
//
// Creates an EPT-based inline hook:
//   1. Validates target address
//   2. Builds 14-byte absolute jump (push low32 + mov [rsp+4], high32 + ret)
//   3. Optionally allocates trampoline near target for calling original
//   4. Calls RelocateCodeForHook_Wrapper to:
//      - Allocate shadow page (EPT split)
//      - Copy original page content to shadow
//      - Write 14-byte jump on shadow page
//   5. Broadcasts to all CPUs (IPI) to flush EPT TLB
//
static bool EptInstallHook(HOOK_CONTEXT* ctx, void* target, void* detour, bool alloc_trampoline)
{
    if (ctx->original_function || !IsAddressValid(target))
        return false;

    ctx->original_function = target;

    // Build absolute jump: push low32; mov dword [rsp+4], high32; ret
    uint8_t jump_stub[14];
    BuildAbsoluteJump_14Bytes(jump_stub, detour);
    ctx->patch_size = 14;

    if (alloc_trampoline) {
        // Allocate executable memory within ±2GB of target for trampoline
        void* trampoline = AllocateExecutableMemory_NearTarget(target, 14);
        // Register trampoline in hook manager's list
        if (trampoline && ctx->hook_manager)
            ctx->hook_manager->trampoline_list.push_back(trampoline);
    }

    // Save original bytes, create EPT shadow page, write jump stub
    if (!RelocateCodeForHook(target, ctx->patch_size))
        return false;

    memcpy(ctx->saved_original_bytes, target, ctx->patch_size);
    EptApplyPatchToShadowPages(target, jump_stub, ctx->patch_size);

    // IPI broadcast: flush EPT on all logical processors
    BroadcastToAllCpus(FlushEptForHook, ctx);

    return true;
}


// =============================================================================
// MAIN HOOK: hook_MiProcessLoaderEntry
// =============================================================================
//
// @ 0x14000C510 (size: 0x32D7 = 13,015 bytes)
//
__int64 __fastcall hook_MiProcessLoaderEntry(
    __int64 loader_entry,   // KLDR_DATA_TABLE_ENTRY*
    unsigned int operation  // 0=unload, 1=load
)
{
    auto original = original_MiProcessLoaderEntry;

    // -------------------------------------------------------------------------
    // [1] Mark EPT hook context active (anti-recursion / TEB-based checks)
    // -------------------------------------------------------------------------
    g_ExecutingEPTHook = 1;

    // -------------------------------------------------------------------------
    // [2] One-time initialization: resolve exports + install IofCallDriver/IofCompleteRequest hooks
    //     Uses MutexedInitialization (InterlockedCompareExchange-based once-init)
    // -------------------------------------------------------------------------
    if (g_DriverEnumInitState != -1 /*0xFFFFFFFF*/) {
        MutexedInitialization(&g_DriverEnumInitState,
                              InstallEptHooks_InitProcAddress_WithShellcode);
    }

    // -------------------------------------------------------------------------
    // [3] Call original MiProcessLoaderEntry — let the real load/unload proceed
    // -------------------------------------------------------------------------
    __int64 result = original(loader_entry, operation);

    if (!loader_entry)
        return result;

    // -------------------------------------------------------------------------
    // [4] Handle unload (operation == 0): remove module from tracked driver list
    // -------------------------------------------------------------------------
    if (operation == 0) {
        void* dll_base = *(void**)(loader_entry + 0x30);  // DllBase

        MutexLock(&g_DriverListMutex);
        // Linear scan: find entry with matching DllBase, shift-remove
        for (auto it = g_DriverList.begin(); it != g_DriverList.end(); ++it) {
            if (it->dll_base == dll_base) {
                g_DriverList.erase(it);
                break;
            }
        }
        MutexUnlock(&g_DriverListMutex);

        return result;
    }

    // =========================================================================
    // [5] Handle load (operation == 1): identify module, install targeted hooks
    // =========================================================================

    // --- Extract module name from KLDR_DATA_TABLE_ENTRY ---
    // BaseDllName is UNICODE_STRING at offset +0x58
    uint16_t name_length_bytes = *(uint16_t*)(loader_entry + 88);    // +0x58
    wchar_t* name_buffer       = *(wchar_t**)(loader_entry + 96);    // +0x60
    size_t   name_char_count   = name_length_bytes / 2;

    // Convert UNICODE to ASCII lowercase (SSE2 _mm_packus_epi16 fast path for >=32 chars)
    char module_name_lower[256];
    UnicodeToAsciiLowercase(name_buffer, name_char_count, module_name_lower);

    // -------------------------------------------------------------------------
    // [5a] If operation == 1 (load): register in driver list
    // -------------------------------------------------------------------------
    if (operation == 1) {
        driver_entry_t entry;
        entry.dll_base      = *(void**)(loader_entry + 0x30);
        entry.size_of_image = *(uint32_t*)(loader_entry + 0x40);
        entry.name          = module_name_lower;  // std::string copy

        MutexLock(&g_DriverListMutex);
        g_DriverList.push_back(entry);
        MutexUnlock(&g_DriverListMutex);
    }

    // =====================================================================
    // [6] Module-specific hook installation
    //     Each block: XOR-decrypt target name -> compare -> install hook
    // =====================================================================

    // -----------------------------------------------------------------
    // hal.dll — Hardware Abstraction Layer
    // -----------------------------------------------------------------
    // Just tracks the module info, no EPT hook installed here.
    // Used later by spoofer (HalQueryBusSlots, etc.)
    if (strstr(module_name_lower, XOR("hal.dll"))) {
        g_pHalModule = new module_info_t;
        PrepareImageStructure(g_pHalModule, *(void**)(loader_entry + 0x30), 0);
    }

    // -----------------------------------------------------------------
    // vgk.sys — Vanguard Anti-Cheat (Riot Games)
    // -----------------------------------------------------------------
    // Tracks the module for awareness; no hook installed directly.
    // Other hooks (MmAccessFault, PsWatchWorkingSet) check if VGK is loaded
    // to adapt their behavior.
    if (strstr(module_name_lower, XOR("vgk.sys"))) {
        g_pVgkModule = new module_info_t;
        PrepareImageStructure(g_pVgkModule, *(void**)(loader_entry + 0x30), 0);
    }

    // -----------------------------------------------------------------
    // win32kbase.sys — Win32k Base Driver
    // -----------------------------------------------------------------
    // Hooks NtDCompositionBeginFrame (DirectComposition / DWM rendering)
    // Purpose: intercept DWM frame begin for overlay/screenshot bypass
    if (strstr(module_name_lower, XOR("win32kbase.sys"))) {
        g_pWin32kBaseModule = new module_info_t;
        PrepareImageStructure(g_pWin32kBaseModule, *(void**)(loader_entry + 0x30), 0);

        // Resolve export by XOR-decrypted name, then install EPT hook
        void* NtDCompositionBeginFrame_addr = LookupExport(
            g_pWin32kBaseModule, XOR("NtDCompositionBeginFrame"));

        EptInstallHook(&HookContext_NtDCompositionBeginFrame,
                       NtDCompositionBeginFrame_addr,
                       hook_NtDCompositionBeginFrame,
                       /*trampoline=*/true);
    }

    // -----------------------------------------------------------------
    // win32kfull.sys — Win32k Full Driver
    // -----------------------------------------------------------------
    // Hooks NtGdiStretchBlt and NtGdiBitBlt
    // Purpose: intercept GDI screenshot/BitBlt operations
    //          (anti-screenshot / overlay rendering bypass)
    if (strstr(module_name_lower, XOR("win32kfull.sys"))) {
        g_pWin32kFullModule = new module_info_t;
        PrepareImageStructure(g_pWin32kFullModule, *(void**)(loader_entry + 0x30), 0);

        // NtGdiStretchBlt hook
        void* NtGdiStretchBlt_addr = LookupExport(
            g_pWin32kFullModule, XOR("NtGdiStretchBlt"));
        EptInstallHook(g_HookContext_NtGdiStretchBlt,
                       NtGdiStretchBlt_addr,
                       hook_NtGdiStretchBlt,
                       /*trampoline=*/true);

        // NtGdiBitBlt hook
        void* NtGdiBitBlt_addr = LookupExport(
            g_pWin32kFullModule, XOR("NtGdiBitBlt"));
        EptInstallHook(&HookContext_NtGdiBitBlt,
                       NtGdiBitBlt_addr,
                       hook_NtGdiBitBlt,
                       /*trampoline=*/true);
    }

    // -----------------------------------------------------------------
    // dxgkrnl.sys — DirectX Graphics Kernel
    // -----------------------------------------------------------------
    // [A] Triggers display driver enumeration (EnumerateDiskDevices_SendCommand)
    // [B] If spoofer enabled: sig-scan for DxgkDdiQueryDeviceDescriptor
    //     Purpose: GPU HWID spoofing (intercepts adapter descriptor queries)
    if (strstr(module_name_lower, XOR("dxgkrnl.sys"))) {
        g_pDxgkrnlModule = new module_info_t;
        PrepareImageStructure(g_pDxgkrnlModule, *(void**)(loader_entry + 0x30), 0);

        // [A] One-time display driver initialization
        if (g_DisplayDriverInitState != -1) {
            MutexedInitialization(&g_DisplayDriverInitState,
                                  EnumerateDiskDevices_SendCommand);
        }

        // [B] GPU spoofer hook (conditional)
        if (g_bSpooferEnabled) {
            // Sig scan inside dxgkrnl.sys .text section
            // Pattern resolves to a CALL instruction -> target = DxgkDdiQueryDeviceDescriptor
            void* sig_match = IDASignatureScan(
                &g_pDxgkrnlModule->mapped_base,
                XOR("E8 ?? ?? ?? ?? ..."));  // actual encrypted pattern

            void* target = nullptr;
            if (sig_match)
                target = ResolveRelativeCall(sig_match);  // sig + *(int*)(sig+1) + 5

            EptInstallHook(g_HookContext_DxgkFn1, target,
                           hook_DpiDxgkDdiQueryDeviceDescriptor,
                           /*trampoline=*/true);
        }
    }

    // -----------------------------------------------------------------
    // nvlddmkm.sys — NVIDIA Display Driver (first check)
    // -----------------------------------------------------------------
    // If spoofer enabled: sig-scan for NVIDIA-internal function
    // Purpose: GPU serial/HWID spoofing in NVIDIA driver
    // Tries two different signatures (version compat)
    if (strstr(module_name_lower, XOR("nvlddmkm.sys"))) {
        g_pNvidiaModule = new module_info_t;
        PrepareImageStructure(g_pNvidiaModule, *(void**)(loader_entry + 0x30), 0);

        if (g_bSpooferEnabled) {
            void* match = IDASignatureScan(&g_pNvidiaModule->mapped_base, XOR("pattern1"));
            if (!match)
                match = IDASignatureScan(&g_pNvidiaModule->mapped_base, XOR("pattern2"));
            if (match)
                SwapObjectStates_WithPolymorphicCleanup(match);
        }
    }

    // -----------------------------------------------------------------
    // kbdclass.sys — Keyboard Class Driver
    // -----------------------------------------------------------------
    // Sig-scan for keyboard read dispatch function.
    // Installs a TIMED callback (20s delay) to hook keyboard read path.
    // Purpose: keyboard input interception (keylogger / input redirection)
    //
    // The timed delay avoids hooking before the driver stack is fully initialized.
    if (strstr(module_name_lower, XOR("kbdclass.sys"))) {
        g_pKbdClassModule = new module_info_t;
        PrepareImageStructure(g_pKbdClassModule, *(void**)(loader_entry + 0x30), 0);

        // Sig scan -> resolve CALL target -> schedule timed hook installation
        void* sig = IDASignatureScan(&g_pKbdClassModule->mapped_base, XOR("E8 ?? ..."));
        if (sig) {
            void* target = ResolveRelativeCall(sig, /*offset=*/8);
            InsertTimedEntry(/*delay_ms=*/20000, {vtable_keyboard, target});
        }
    }

    // -----------------------------------------------------------------
    // mouhid.sys — Mouse HID Minidriver
    // -----------------------------------------------------------------
    // Sig-scan for internal HID function.
    // Pattern: "E8 ? ? ? ? 48 8B D7" -> CALL to mouse read handler
    // Installs a TIMED callback (10s delay)
    // Purpose: mouse input interception
    if (strstr(module_name_lower, XOR("mouhid.sys"))) {
        g_pMouseHidModule = new module_info_t;
        PrepareImageStructure(g_pMouseHidModule, *(void**)(loader_entry + 0x30), 0);

        // First sig: find CALL to target function
        void* sig1 = IDASignatureScan(&g_pMouseHidModule->mapped_base,
                                       XOR("E8 ? ? ? ? 48 8B D7"));
        if (sig1) {
            void* fn = ResolveRelativeCall(sig1);
            Helper_CalculateNegativeOffset(&g_pMouseHidModule->mapped_base, fn);

            // Second sig: find delayed hook target
            // Pattern: "33 D2 FF 15 ? ? ? ?" -> xor edx,edx; call [rip+xxx]
            void* sig2 = IDASignatureScan(&g_pMouseHidModule->mapped_base,
                                           XOR("33 D2 FF 15 ? ? ? ?"));

            InsertTimedEntry(/*delay_ms=*/10000, {vtable_mouse_hid, sig2 + 8});
        }
    }

    // -----------------------------------------------------------------
    // mouclass.sys — Mouse Class Driver
    // -----------------------------------------------------------------
    // Sig-scan for MouseClassRead dispatch function.
    // Also finds MouseClassServiceCallback via second sig.
    // Installs a TIMED callback (20s delay) for class-level mouse hook.
    // Purpose: class-level mouse input interception
    if (strstr(module_name_lower, XOR("mouclass.sys"))) {
        g_pMouseClassModule = new module_info_t;
        PrepareImageStructure(g_pMouseClassModule, *(void**)(loader_entry + 0x30), 0);

        // Sig scan: multi-byte pattern to find MouseClassRead
        void* sig = IDASignatureScan(&g_pMouseClassModule->mapped_base,
                                      XOR("48 8D 05 ?? ?? ?? ?? 48 89 83 ..."));
        if (sig) {
            void* MouseClassRead = ResolveRipRelative(sig, /*rip_offset=*/3);
            g_MouseReadHookAddr = MouseClassRead;
            Helper_CalculateNegativeOffset(&g_pMouseClassModule->mapped_base, MouseClassRead);

            // Second sig for MouseClassServiceCallback
            void* sig2 = IDASignatureScan(&g_pMouseClassModule->mapped_base,
                                           XOR("pattern2"));
            if (sig2)
                InsertTimedEntry(/*delay_ms=*/20000, {vtable_mouse_class, sig2});
        }
    }

    // -----------------------------------------------------------------
    // classpnp.sys — SCSI Class Plug-and-Play Driver
    // -----------------------------------------------------------------
    // [SPOOFER ONLY] Sig-scan for ClassGlobalDispatch
    // Purpose: intercepts SCSI class-level I/O dispatch
    //          Used for disk serial / volume ID spoofing
    if (g_bSpooferEnabled && strstr(module_name_lower, XOR("classpnp.sys"))) {
        g_pClassPnpModule = new module_info_t;
        PrepareImageStructure(g_pClassPnpModule, *(void**)(loader_entry + 0x30), 0);

        void* ClassGlobalDispatch = IDASignatureScan(
            &g_pClassPnpModule->mapped_base, XOR("classpnp_dispatch_sig"));

        EptInstallHook(g_HookContext_ClassPnpFn, ClassGlobalDispatch,
                       hook_classnpnp_ClassGlobalDispatch,
                       /*trampoline=*/false);
    }

    // -----------------------------------------------------------------
    // nvlddmkm.sys — NVIDIA Driver (second check, different hooks)
    // -----------------------------------------------------------------
    // [SPOOFER ONLY] If this is nvlddmkm.sys AND it wasn't already handled above:
    //   Hook VrpIoctlDeviceDispatch — NVIDIA IOCTL handler
    //   Hook another small internal function
    //   Purpose: spoof NVIDIA GPU responses to IOCTL queries (GPU ID, serial)
    if (g_bSpooferEnabled && strcmp(module_name_lower, XOR("nvlddmkm.sys")) == 0) {
        auto nvidia_module = new module_info_t;
        PrepareImageStructure(nvidia_module, *(void**)(loader_entry + 0x30), 0);

        // Sig scan #1: VrpIoctlDeviceDispatch
        // Pattern: "48 8D 05 ? ? ? ? 48 89 83 E0 00 00 00"
        void* sig1 = IDASignatureScan(&nvidia_module->mapped_base, XOR("vrp_ioctl_sig"));
        void* VrpIoctl = sig1 ? ResolveRipRelative(sig1, 3) : nullptr;
        EptInstallHook(&HookCtx_VrpIoctl, VrpIoctl,
                       hook_VrpIoctlDeviceDispatch, /*trampoline=*/false);

        // Sig scan #2: small wrapper function (same pattern, different match)
        void* sig2 = IDASignatureScan(&nvidia_module->mapped_base, XOR("wrapper_sig"));
        void* wrapper = sig2 ? ResolveRipRelative(sig2, 3) : nullptr;
        EptInstallHook(&HookCtx_Wrapper, wrapper,
                       hook_Wrapper_CallSmallFunction277F0, /*trampoline=*/false);
    }

    // -----------------------------------------------------------------
    // partmgr.sys — Partition Manager
    // -----------------------------------------------------------------
    // [SPOOFER ONLY] Sig-scan for PmReadPartitionTable
    // Purpose: spoof disk partition table data (partition GUID / serial)
    if (g_bSpooferEnabled && strcmp(module_name_lower, XOR("partmgr.sys")) == 0) {
        g_pPartMgrModule = new module_info_t;
        PrepareImageStructure(g_pPartMgrModule, *(void**)(loader_entry + 0x30), 0);

        void* sig = IDASignatureScan(&g_pPartMgrModule->mapped_base,
                                      XOR("partmgr_read_partition_sig"));
        void* PmReadPartitionTable = sig ? ResolveRelativeCall(sig) : nullptr;

        EptInstallHook(g_HookContext_PartMgrFn, PmReadPartitionTable,
                       hook_partmgr_PmReadPartitionTable,
                       /*trampoline=*/false);
    }

    // -----------------------------------------------------------------
    // storport.sys — Storage Port Driver
    // -----------------------------------------------------------------
    // [SPOOFER ONLY] Hooks NdisReadConfiguration + NdisMSetMiniportAttributes
    //                (these are NDIS functions exported by storport!)
    // Purpose: spoof storage miniport attributes (disk serial, model string)
    //          NdisReadConfiguration → intercept registry reads for adapter config
    //          NdisMSetMiniportAttributes → intercept miniport attribute registration
    if (strstr(module_name_lower, XOR("storport.sys"))) {
        g_pStorPortModule = new module_info_t;
        PrepareImageStructure(g_pStorPortModule, *(void**)(loader_entry + 0x30), 0);

        if (g_bSpooferEnabled) {
            void* NdisReadConfig = LookupExport(g_pStorPortModule,
                                                 XOR("NdisReadConfiguration"));
            EptInstallHook(&HookCtx_NdisRead, NdisReadConfig,
                           hook_NdisReadConfiguration, /*trampoline=*/false);

            void* NdisMSetMiniport = LookupExport(g_pStorPortModule,
                                                    XOR("NdisMSetMiniportAttributes"));
            EptInstallHook(&HookCtx_NdisMiniport, NdisMSetMiniport,
                           hook_NdisMSetMiniportAttributes, /*trampoline=*/false);
        }
    }

    // -----------------------------------------------------------------
    // netio.sys — Network I/O Subsystem
    // -----------------------------------------------------------------
    // [SPOOFER ONLY] Hooks NsiGetAllParameters + NsiEnumerateObjectsAllParametersEx
    // Purpose: spoof network adapter MAC address / interface GUID
    //   NsiGetAllParameters → called by iphlpapi for GetAdaptersInfo etc.
    //   NsiEnumerateObjectsAllParametersEx → called for enumerating all NICs
    //
    // hook_NsiGetAllParameters: if result >= 0 && ObjectIndex == 20 (NPI_MS_NDIS_MODULEID):
    //   XorDecryptString_MersenneTwister on the output buffer (MAC randomization)
    if (strstr(module_name_lower, XOR("netio.sys"))) {
        g_pNetIoModule = new module_info_t;
        PrepareImageStructure(g_pNetIoModule, *(void**)(loader_entry + 0x30), 0);

        if (g_bSpooferEnabled) {
            void* NsiGetAll = LookupExport(g_pNetIoModule,
                                            XOR("NsiGetAllParameters"));
            EptInstallHook(&HookCtx_NsiGet, NsiGetAll,
                           hook_NsiGetAllParameters, /*trampoline=*/false);

            void* NsiEnum = LookupExport(g_pNetIoModule,
                                          XOR("NsiEnumerateObjectsAllParametersEx"));
            EptInstallHook(&HookCtx_NsiEnum, NsiEnum,
                           hook_NsiEnumerateObjectsAllParametersEx, /*trampoline=*/false);
        }
    }

    // -----------------------------------------------------------------
    // tcpip.sys — TCP/IP Protocol Driver
    // -----------------------------------------------------------------
    // Just tracks the module (no hook). Used by other hooks that need
    // to resolve TCP/IP internals for network spoofer.
    if (strstr(module_name_lower, XOR("tcpip.sys"))) {
        g_pTcpIpModule = new module_info_t;
        PrepareImageStructure(g_pTcpIpModule, *(void**)(loader_entry + 0x30), 0);
    }

    // -----------------------------------------------------------------
    // ndu.sys — Windows Network Data Usage Monitor
    // -----------------------------------------------------------------
    // Just tracks the module. NDU queries network stats; tracking it
    // prevents unexpected interactions with spoofed network data.
    if (strstr(module_name_lower, XOR("ndu.sys"))) {
        g_pNduModule = new module_info_t;
        PrepareImageStructure(g_pNduModule, *(void**)(loader_entry + 0x30), 0);
    }

    // -----------------------------------------------------------------
    // EasyAntiCheat*.sys — EAC Kernel Module
    // -----------------------------------------------------------------
    // Tracks the module. Previous instance freed if re-loaded.
    // Other hooks adapt behavior based on EAC presence.
    if (strstr(module_name_lower, XOR("easyanticheat"))) {
        if (g_pEacModule) {
            Cleanup_FreeInstructionContext(g_pEacModule);
            free(g_pEacModule);
        }
        g_pEacModule = new module_info_t;
        PrepareImageStructure(g_pEacModule, *(void**)(loader_entry + 0x30), 0);
    }

    // -----------------------------------------------------------------
    // hal.dll — Hardware Abstraction Layer (second reference)
    // -----------------------------------------------------------------
    // Duplicate tracking for HAL (separate global for spoofer subsystem)
    if (strstr(module_name_lower, XOR("hal.dll"))) {
        if (g_pHalModule2) {
            Cleanup_FreeInstructionContext(g_pHalModule2);
            free(g_pHalModule2);
        }
        g_pHalModule2 = new module_info_t;
        PrepareImageStructure(g_pHalModule2, *(void**)(loader_entry + 0x30), 0);
    }

    return result;
}


// =============================================================================
// INITIALIZATION + CLEANUP
// =============================================================================

// Called at boot to initialize the hook context
// @ 0x140010E30
static void Initialize_MiProcessLoaderEntry()
{
    g_pF_cleanup = nullptr;         // some cleanup function pointer
    PhysPageShadowInit(&HookContext_MiProcessLoaderEntry);
}

// Called on teardown
// @ 0x14000C500
static void Cleanup_MiProcessLoaderEntry()
{
    PhysPageShadowDestructor(&HookContext_MiProcessLoaderEntry);
}


// =============================================================================
// SUMMARY — Total hooks installed from MiProcessLoaderEntry
// =============================================================================
//
// UNCONDITIONAL (always installed):
//   1. IofCallDriver          — I/O dispatch interception (shellcode-based EPT hook)
//   2. IofCompleteRequest     — I/O completion interception
//   3. NtDCompositionBeginFrame — DWM composition frame hook
//   4. NtGdiStretchBlt        — GDI StretchBlt interception
//   5. NtGdiBitBlt            — GDI BitBlt interception
//
// CONDITIONAL (g_bSpooferEnabled):
//   6.  DxgkDdiQueryDeviceDescriptor — GPU descriptor spoof (dxgkrnl)
//   7.  NVIDIA internal fn           — GPU object state swap (nvlddmkm)
//   8.  VrpIoctlDeviceDispatch       — NVIDIA IOCTL spoof (nvlddmkm)
//   9.  Small wrapper fn             — NVIDIA secondary hook (nvlddmkm)
//   10. ClassGlobalDispatch          — SCSI class dispatch spoof (classpnp)
//   11. PmReadPartitionTable         — Disk partition spoof (partmgr)
//   12. NdisReadConfiguration        — Storage registry spoof (storport)
//   13. NdisMSetMiniportAttributes   — Miniport attribute spoof (storport)
//   14. NsiGetAllParameters          — Network param spoof (netio)
//   15. NsiEnumerateObjectsAllParametersEx — Network enum spoof (netio)
//
// TIMED CALLBACKS (deferred hook installation):
//   16. Keyboard read dispatch  — kbdclass.sys (20s delay)
//   17. Mouse HID handler       — mouhid.sys (10s delay)
//   18. Mouse class read        — mouclass.sys (20s delay)
//
// MODULE TRACKING ONLY (no hook, stored for other hooks to reference):
//   - hal.dll, vgk.sys, tcpip.sys, ndu.sys, EasyAntiCheat*.sys
//
// =============================================================================
// KEY DESIGN NOTES:
//
// 1. WHY MiProcessLoaderEntry instead of PsSetLoadImageNotifyRoutine?
//    -> Notify routines are registered in PspLoadImageNotifyRoutine array
//    -> Anti-cheats enumerate this array to detect all registered callbacks
//    -> Hooking the internal MiProcessLoaderEntry is invisible to this scan
//
// 2. XOR string encryption prevents static signature scanning of the binary.
//    Every module name and export name is encrypted with the same XOR key
//    and decrypted on the stack immediately before use.
//
// 3. The one-time init pattern (MutexedInitialization) uses interlocked
//    compare-exchange: first thread to enter does the init, others spin-wait.
//
// 4. EPT hooks create a shadow copy of the target page where the JMP stub
//    is written. The original page remains untouched in physical memory.
//    Execute permission points to shadow (with hook), read/write to original.
//    This makes the hooks invisible to integrity checks reading the code.
//
// 5. IofCallDriver uses a special shellcode-based hook (EptInstallHook_WithRelocation)
//    rather than a simple 14-byte jump, because IofCallDriver is a high-frequency
//    very short function — the shellcode is more efficient than the standard
//    EPT violation path.
// =============================================================================
