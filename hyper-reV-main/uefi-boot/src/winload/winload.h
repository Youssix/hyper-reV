#pragma once
#include <Library/UefiLib.h>
#include <ia32-doc/ia32_compact.h>

extern UINT64 pml4_physical_allocation;
extern UINT64 pdpt_physical_allocation;

EFI_STATUS winload_place_hooks(UINT64 image_base, UINT64 image_size);
