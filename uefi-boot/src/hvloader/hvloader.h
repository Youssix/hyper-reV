#pragma once
#include <Library/UefiLib.h>

extern UINT64 vmwrite_hook_cave_pa;

EFI_STATUS hvloader_place_hooks(UINT64 image_base, UINT64 image_size);
