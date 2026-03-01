#include "hvloader.h"

#include "../bootmgfw/bootmgfw.h"
#include "../hooks/hooks.h"
#include "../image/image.h"
#include "../structures/virtual_address.h"
#include "../memory_manager/memory_manager.h"
#include "../hyperv_attachment/hyperv_attachment.h"
#include "../winload/winload.h"

hook_data_t hvloader_launch_hv_hook_data = { 0 };
hook_data_t hv_vmexit_hook_data = { 0 };

UINT64 vmwrite_hook_cave_pa = 0;
// Packed enlightened VMCS offsets from HvSetEptPointer sig scan:
// [31:0] = gs:???? per-VP struct offset, [47:32] = EPTP cache offset, [63:48] = clean_fields offset
UINT64 enlightened_vmcs_offsets = 0;

typedef void(*hvloader_launch_hv_t)(cr3 a1, virtual_address_t a2, UINT64 a3, UINT64 a4);

void set_up_identity_map(pml4e_64* pml4e)
{
    pdpte_1gb_64* pdpt = (pdpte_1gb_64*)pdpt_physical_allocation;

    pml4e->flags = 0;
    pml4e->page_frame_number = pdpt_physical_allocation >> 12;
    pml4e->present = 1;
    pml4e->write = 1;

    for (UINT64 i = 0; i < 512; i++)
    {
        pdpte_1gb_64* pdpte = &pdpt[i];

        pdpte->flags = 0;
        pdpte->page_frame_number = i;
        pdpte->present = 1;
        pdpte->write = 1;
        pdpte->large_page = 1;
    }
}

void load_identity_map_into_hyperv_cr3(cr3 identity_map_cr3, cr3 hyperv_cr3, pml4e_64 identity_map_pml4e, pml4e_64* initial_hyperv_pml4e)
{
    AsmWriteCr3(identity_map_cr3.flags);

    pml4e_64* hyperv_pml4 = (pml4e_64*)(hyperv_cr3.address_of_page_directory << 12);

    *initial_hyperv_pml4e = hyperv_pml4[0];

    hyperv_pml4[0] = identity_map_pml4e;
    hyperv_pml4[255] = identity_map_pml4e;
}

void restore_initial_hyperv_pml4e(cr3 identity_map_cr3, cr3 hyperv_cr3, pml4e_64 initial_hyperv_pml4e)
{
    AsmWriteCr3(identity_map_cr3.flags);

    pml4e_64* hyperv_pml4 = (pml4e_64*)(hyperv_cr3.address_of_page_directory << 12);

    hyperv_pml4[0] = initial_hyperv_pml4e;
}

// must have identity map in 0th pml4e
UINT8 is_page_executable(cr3 cr3_to_search, virtual_address_t page)
{
    pml4e_64* pml4 = (pml4e_64*)(cr3_to_search.address_of_page_directory << 12);
    pml4e_64 pml4e = pml4[page.pml4_idx];

    if (pml4e.present == 0 || pml4e.execute_disable == 1)
    {
        return 0;
    }

    pdpte_64* pdpt = (pdpte_64*)(pml4e.page_frame_number << 12);
    pdpte_64 pdpte = pdpt[page.pdpt_idx];

    if (pdpte.present == 0 || pdpte.execute_disable == 1)
    {
        return 0;
    }

    if (pdpte.large_page == 1)
    {
        return 1;
    }

    pde_64* pd = (pde_64*)(pdpte.page_frame_number << 12);
    pde_64 pde = pd[page.pd_idx];

    if (pde.present == 0 || pde.execute_disable == 1)
    {
        return 0;
    }

    if (pde.large_page == 1)
    {
        return 1;
    }

    pte_64* pt = (pte_64*)(pde.page_frame_number << 12);
    pte_64 pte = pt[page.pt_idx];

    if (pte.present == 0 || pte.execute_disable == 1)
    {
        return 0;
    }

    return 1;
}

UINT64 find_hyperv_text_base(cr3 hyperv_cr3, virtual_address_t entry_point)
{
    virtual_address_t text_address = entry_point;

    while (is_page_executable(hyperv_cr3, text_address) == 1)
    {
        text_address.address -= 0x1000;
    }

    return text_address.address + 0x1000;
}

UINT64 find_hyperv_text_end(cr3 hyperv_cr3, virtual_address_t entry_point)
{
    virtual_address_t text_address = entry_point;

    while (is_page_executable(hyperv_cr3, text_address) == 1)
    {
        text_address.address += 0x1000;
    }

    return text_address.address - 0x1000;
}

UINT64 get_physical_address_from_va(cr3 cr3_to_search, UINT64 va)
{
    virtual_address_t vaddr = { .address = va };
    pml4e_64* pml4 = (pml4e_64*)(cr3_to_search.address_of_page_directory << 12);
    pml4e_64 pml4e = pml4[vaddr.pml4_idx];

    if (pml4e.present == 0)
        return 0;

    pdpte_64* pdpt = (pdpte_64*)(pml4e.page_frame_number << 12);
    pdpte_64 pdpte = pdpt[vaddr.pdpt_idx];

    if (pdpte.present == 0)
        return 0;

    if (pdpte.large_page == 1)
        return (pdpte.page_frame_number << 30) | (va & 0x3FFFFFFFull);

    pde_64* pd = (pde_64*)(pdpte.page_frame_number << 12);
    pde_64 pde = pd[vaddr.pd_idx];

    if (pde.present == 0)
        return 0;

    if (pde.large_page == 1)
        return (pde.page_frame_number << 21) | (va & 0x1FFFFFull);

    pte_64* pt = (pte_64*)(pde.page_frame_number << 12);
    pte_64 pte = pt[vaddr.pt_idx];

    if (pte.present == 0)
        return 0;

    return (pte.page_frame_number << 12) | (va & 0xFFFull);
}

void build_entry_trampoline(CHAR8* code_cave, CHAR8* entry_point_address)
{
    // Copy 18 displaced bytes (3 complete instructions) from the entry point
    mm_copy_memory(code_cave, entry_point_address, 18);

    // Build 14-byte JMP back to entry_point + 18
    // push low32; mov [rsp+4], high32; ret
    parted_address_t return_address = { .value = (UINT64)(entry_point_address + 18) };

    UINT8 jmp_back[14] = {
        0x68, 0x00, 0x00, 0x00, 0x00,                          // push low32
        0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,       // mov [rsp+4], high32
        0xC3                                                     // ret
    };

    *(UINT32*)(&jmp_back[1]) = return_address.u.low_part;
    *(UINT32*)(&jmp_back[9]) = return_address.u.high_part;

    mm_copy_memory(code_cave + 18, jmp_back, sizeof(jmp_back));
}

void hook_entry_point(CHAR8* entry_point_address, UINT8* detour_target)
{
    // Write 14-byte JMP at entry point -> detour_target (attachment's ASM stub)
    // push low32; mov [rsp+4], high32; ret
    parted_address_t target = { .value = (UINT64)detour_target };

    UINT8 hook_bytes[14] = {
        0x68, 0x00, 0x00, 0x00, 0x00,                          // push low32
        0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,       // mov [rsp+4], high32
        0xC3                                                     // ret
    };

    *(UINT32*)(&hook_bytes[1]) = target.u.low_part;
    *(UINT32*)(&hook_bytes[9]) = target.u.high_part;

    mm_copy_memory(entry_point_address, hook_bytes, sizeof(hook_bytes));
}

void set_up_hyperv_hooks(cr3 hyperv_cr3, virtual_address_t entry_point)
{
    AsmWriteCr3(hyperv_cr3.flags);

    UINT64 hyperv_text_base = find_hyperv_text_base(hyperv_cr3, entry_point);
    UINT64 hyperv_text_end = find_hyperv_text_end(hyperv_cr3, entry_point);
    UINT64 hyperv_text_size = hyperv_text_end - hyperv_text_base;

    if (hyperv_text_base != 0)
    {
        UINT8* hyperv_attachment_entry_point = NULL;

        EFI_STATUS status = hyperv_attachment_get_relocated_entry_point(&hyperv_attachment_entry_point);

        if (status == EFI_SUCCESS)
        {
            CHAR8* code_ref_to_vmexit_handler = NULL;

            UINT8 is_intel = 0;

            // search for AMD's vmexit handler
            status = scan_image(&code_ref_to_vmexit_handler, (CHAR8*)hyperv_text_base, hyperv_text_size, "\xE8\x00\x00\x00\x00\x48\x89\x04\x24\xE9", "x????xxxxx");

            if (status == EFI_NOT_FOUND)
            {
                // search for Intel's vmexit handler
                status = scan_image(&code_ref_to_vmexit_handler, (CHAR8*)hyperv_text_base, hyperv_text_size, "\xE8\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x74", "x????x????x");

                is_intel = 1;
            }

            if (status == EFI_SUCCESS)
            {
                INT32 original_vmexit_handler_rva = *(INT32*)(code_ref_to_vmexit_handler + 1);
                CHAR8* original_vmexit_handler = (code_ref_to_vmexit_handler + 5) + original_vmexit_handler_rva;

                UINT8* hyperv_attachment_detours[2] = { NULL, NULL };

                CHAR8* get_vmcb_gadget = NULL;

                if (is_intel == 0)
                {
                    status = scan_image(&get_vmcb_gadget, (CHAR8*)hyperv_text_base, hyperv_text_size, "\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00\x48\x8B\x81\x00\x00\x00\x00\x48\x8B", "xxxxx????xxx????xxx????xx");

                    if (status != EFI_SUCCESS)
                    {
                        return;
                    }
                }

                UINT64 heap_physical_base = hyperv_attachment_heap_allocation_base;
                UINT64 heap_physical_usable_base = hyperv_attachment_heap_allocation_usable_base;
                UINT64 heap_total_size = hyperv_attachment_heap_allocation_size;

                // Intel: scan for VMEXIT entry point and find second code cave for trampoline
                UINT64 vmexit_entry_trampoline = 0;
                CHAR8* vmexit_entry_point = NULL;

                if (is_intel == 1)
                {
                    status = scan_image(&vmexit_entry_point, (CHAR8*)hyperv_text_base, hyperv_text_size,
                        "\xC7\x44\x24\x00\x00\x00\x00\x00\x48\x89\x4C\x24\x00\x48\x8B\x4C\x24",
                        "xxx?????xxxx?xxx?");

                    if (status == EFI_SUCCESS)
                    {
                        // Find a code cave large enough for the entry trampoline (32 bytes = 18 displaced + 14 JMP back)
                        CHAR8* code_cave_2 = NULL;

                        status = scan_image(&code_cave_2, (CHAR8*)hyperv_text_base, hyperv_text_size,
                            "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
                            "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

                        if (status == EFI_SUCCESS)
                        {
                            build_entry_trampoline(code_cave_2, vmexit_entry_point);
                            vmexit_entry_trampoline = (UINT64)code_cave_2;
                        }
                    }

                    // Hook 3: VMWRITE EPT_POINTER redirect
                    // Intercepts the ONLY function in hvix64 that writes EPTP to VMCS/cache.
                    // When active (patch slots filled), replaces hyperv_cr3 PFN → hook_cr3 PFN
                    // so VP stays on hook_cr3 permanently — no more EPTP bounce.
                    // Installed BEFORE entry_point so cave PA is available to pass to attachment.
                    {
                        CHAR8* vmwrite_eptp_func = NULL;

                        status = scan_image(&vmwrite_eptp_func, (CHAR8*)hyperv_text_base, hyperv_text_size,
                            "\xF6\x05\x00\x00\x00\x00\x00\x74\x00\x65\x48\x8B\x14\x25\x00\x00\x00\x00"
                            "\x48\x8B\x01\x0F\xBA\xB2\x00\x00\x00\x00\x00\x48\x89\x82\x00\x00\x00\x00"
                            "\xC3\xCC\xBA\x00\x00\x00\x00\x0F\x79\x11\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
                            "\xCC\xCC\x48\x89\x5C\x24",
                            "xx?????x?xxxxx????xxxxxx?????xxx????xxx????xxxxxxxxxxxxxxxxx");

                        if (status == EFI_SUCCESS)
                        {
                            // Extract enlightened VMCS offsets from HvSetEptPointer sig match:
                            // +14: gs:???? (per-VP ptr), +24: btr [rdx+????] (clean_fields), +32: mov [rdx+????] (EPTP cache)
                            UINT32 gs_per_vp_off    = *(UINT32*)(vmwrite_eptp_func + 14);
                            UINT32 eptp_cache_off   = *(UINT32*)(vmwrite_eptp_func + 32);
                            UINT32 clean_fields_off = *(UINT32*)(vmwrite_eptp_func + 24);
                            enlightened_vmcs_offsets = (UINT64)gs_per_vp_off
                                | ((UINT64)(eptp_cache_off & 0xFFFF) << 32)
                                | ((UINT64)(clean_fields_off & 0xFFFF) << 48);

                            // Find a code cave (80+ CC bytes) for Hook 3 shellcode (73 bytes)
                            CHAR8* hook3_cave = NULL;

                            status = scan_image(&hook3_cave, (CHAR8*)hyperv_text_base, hyperv_text_size,
                                "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
                                "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
                                "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
                                "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
                                "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                                "xxxxxxxxxxxxxxxx");

                            if (status == EFI_SUCCESS)
                            {
                                UINT64 cave_va = (UINT64)hook3_cave;

                                // Parse displaced instruction's RIP-relative target
                                // Original: test byte ptr [rip+rel32], 1 at vmwrite_eptp_func
                                INT32 original_rel32 = *(INT32*)(vmwrite_eptp_func + 2);
                                UINT64 flag_target_va = (UINT64)(vmwrite_eptp_func + 7) + original_rel32;

                                // Parse original jz to find both branch targets
                                UINT8 jz_rel8 = *(UINT8*)(vmwrite_eptp_func + 8);
                                UINT64 direct_vmwrite_va = (UINT64)(vmwrite_eptp_func + 9) + jz_rel8;
                                UINT64 lazy_cache_va = (UINT64)(vmwrite_eptp_func + 9);

                                // 73-byte shellcode: PFN check + EPTP replace + displaced test/jz/jmp
                                // PATCH_SLOT_1 at cave+4:  hyperv_cr3 PFN (8 bytes, initially 0 = inactive)
                                // PATCH_SLOT_2 at cave+39: hook_cr3 PFN << 12 (8 bytes, initially 0)
                                // NOTE: no lock inc counter — .text is read-only at runtime, writes fault.
                                UINT8 shellcode[73] = {
                                    0x50,                                           // [0]     push rax
                                    0x52,                                           // [1]     push rdx
                                    0x48, 0xBA, 0,0,0,0, 0,0,0,0,                  // [2-11]  movabs rdx, SLOT1
                                    0x48, 0x85, 0xD2,                               // [12-14] test rdx, rdx
                                    0x74, 0x24,                                     // [15-16] jz .skip (→ 53)
                                    0x48, 0x8B, 0x01,                               // [17-19] mov rax, [rcx]
                                    0x48, 0xC1, 0xE8, 0x0C,                         // [20-23] shr rax, 12
                                    0x48, 0x39, 0xD0,                               // [24-26] cmp rax, rdx
                                    0x75, 0x18,                                     // [27-28] jne .skip (→ 53)
                                    0x48, 0x8B, 0x01,                               // [29-31] mov rax, [rcx]
                                    0x25, 0xFF, 0x0F, 0x00, 0x00,                   // [32-36] and eax, 0FFFh
                                    0x48, 0xBA, 0,0,0,0, 0,0,0,0,                  // [37-46] movabs rdx, SLOT2
                                    0x48, 0x09, 0xD0,                               // [47-49] or rax, rdx
                                    0x48, 0x89, 0x01,                               // [50-52] mov [rcx], rax
                                    0x5A,                                           // [53]    .skip: pop rdx
                                    0x58,                                           // [54]    pop rax
                                    0xF6, 0x05, 0,0,0,0, 0x01,                     // [55-61] test byte [rip+XX], 1
                                    0x0F, 0x84, 0,0,0,0,                           // [62-67] jz direct_path
                                    0xE9, 0,0,0,0,                                 // [68-72] jmp lazy_path
                                };

                                // Verify jz/jne skip targets:
                                // jz at [15]: IP after = 17, target = 53, rel8 = 53-17 = 36 = 0x24 ✓
                                // jne at [27]: IP after = 29, target = 53, rel8 = 53-29 = 24 = 0x18 ✓

                                // Fixup: displaced test byte ptr [rip+XX], 1
                                // Instruction at offset 55, 7 bytes long, RIP after = 62
                                *(INT32*)(&shellcode[57]) = (INT32)(flag_target_va - (cave_va + 62));

                                // Fixup: jz → direct VMWRITE path
                                // Instruction at offset 62, 6 bytes long, RIP after = 68
                                *(INT32*)(&shellcode[64]) = (INT32)(direct_vmwrite_va - (cave_va + 68));

                                // Fixup: jmp → lazy cache path
                                // Instruction at offset 68, 5 bytes long, RIP after = 73
                                *(INT32*)(&shellcode[69]) = (INT32)(lazy_cache_va - (cave_va + 73));

                                // Write shellcode to code cave
                                mm_copy_memory((UINT8*)hook3_cave, shellcode, sizeof(shellcode));

                                // Patch function entry: JMP rel32 + 2 NOP (replaces 7-byte test instruction)
                                UINT8 jmp_patch[7] = { 0xE9, 0,0,0,0, 0x90, 0x90 };
                                *(INT32*)(&jmp_patch[1]) = (INT32)(cave_va - ((UINT64)vmwrite_eptp_func + 5));
                                mm_copy_memory((UINT8*)vmwrite_eptp_func, jmp_patch, sizeof(jmp_patch));

                                // Physical address of code cave → attachment patches SLOT1/SLOT2 at runtime
                                vmwrite_hook_cave_pa = get_physical_address_from_va(hyperv_cr3, cave_va);
                            }
                        }
                    }
                }

                hyperv_attachment_invoke_entry_point(hyperv_attachment_detours, hyperv_attachment_entry_point, original_vmexit_handler, heap_physical_base, heap_physical_usable_base, heap_total_size, uefi_boot_physical_base_address, uefi_boot_image_size, get_vmcb_gadget, vmexit_entry_trampoline, vmwrite_hook_cave_pa, enlightened_vmcs_offsets);

                // Hook 2: processing hook on the CALL to vmexit handler (existing mechanism)
                CHAR8* code_cave = NULL;

                status = scan_image(&code_cave, (CHAR8*)hyperv_text_base, hyperv_text_size, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC", "xxxxxxxxxxxxxxxx");

                if (status == EFI_SUCCESS)
                {
                    status = hook_create(&hv_vmexit_hook_data, code_cave, hyperv_attachment_detours[0]);

                    if (status == EFI_SUCCESS)
                    {
                        hook_enable(&hv_vmexit_hook_data);

                        UINT32 new_call_rva = (UINT32)(code_cave - (code_ref_to_vmexit_handler + 5));

                        mm_copy_memory(code_ref_to_vmexit_handler + 1, (UINT8*)&new_call_rva, sizeof(new_call_rva));
                    }
                }

                // Hook 1: entry point hook (Intel only, fast path)
                if (is_intel == 1 && vmexit_entry_trampoline != 0 && vmexit_entry_point != NULL && hyperv_attachment_detours[1] != NULL)
                {
                    hook_entry_point(vmexit_entry_point, hyperv_attachment_detours[1]);
                }
            }
        }
    }
}

void hvloader_launch_hv_detour(cr3 hyperv_cr3, virtual_address_t hyperv_entry_point, UINT64 jmp_gadget, UINT64 kernel_cr3)
{
    hook_disable(&hvloader_launch_hv_hook_data);

    pml4e_64* virtual_pml4 = (pml4e_64*)pml4_physical_allocation;

    set_up_identity_map(&virtual_pml4[0]);

    UINT64 original_cr3 = AsmReadCr3();

    cr3 identity_map_cr3 = { .address_of_page_directory = pml4_physical_allocation >> 12 };

    pml4e_64 initial_hyperv_pml4e = { 0 };

    load_identity_map_into_hyperv_cr3(identity_map_cr3, hyperv_cr3, virtual_pml4[0], &initial_hyperv_pml4e);

    set_up_hyperv_hooks(hyperv_cr3, hyperv_entry_point);

    restore_initial_hyperv_pml4e(identity_map_cr3, hyperv_cr3, initial_hyperv_pml4e);

    AsmWriteCr3(original_cr3);

    hvloader_launch_hv_t original_subroutine = (hvloader_launch_hv_t)hvloader_launch_hv_hook_data.hooked_subroutine_address;

    original_subroutine(hyperv_cr3, hyperv_entry_point, jmp_gadget, kernel_cr3);
}

EFI_STATUS hvloader_place_hooks(UINT64 image_base, UINT64 image_size)
{
    CHAR8* hvloader_launch_hv = NULL;

    EFI_STATUS status = scan_image(&hvloader_launch_hv, (CHAR8*)image_base, image_size, "\x48\x53\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x00\x48\x89\x25", "xxxxxxxxxxxxxxxx?xxx");

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    status = hook_create(&hvloader_launch_hv_hook_data, hvloader_launch_hv, (void*)hvloader_launch_hv_detour);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    return hook_enable(&hvloader_launch_hv_hook_data);
}
