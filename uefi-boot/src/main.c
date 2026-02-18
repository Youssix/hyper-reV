#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include "bootmgfw/bootmgfw.h"
#include "hyperv_attachment/hyperv_attachment.h"

const UINT8 _gDriverUnloadImageCount = 1;
const UINT32 _gUefiDriverRevision = 0x200;
CHAR8* gEfiCallerBaseName = "hyper-reV";

EFI_STATUS
EFIAPI
UefiUnload(
    IN EFI_HANDLE image_handle
)
{
    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiMain(
    IN EFI_HANDLE image_handle,
    IN EFI_SYSTEM_TABLE* system_table
)
{
    Print(L"\n");
    Print(L"  ______              _   _             _                    \n");
    Print(L" |___  /             | | | |           | |     __ _  __ _   \n");
    Print(L"    / / ___ _ __ ___ | |_| | ___   ___ | | __ / _` |/ _` | \n");
    Print(L"   / / / _ | '__/ _ \\|  _  |/ _ \\ / _ \\| |/ /| (_| | (_| | \n");
    Print(L"  / /_|  __| | | (_) | | | | (_) | (_) |   <  \\__, |\\__, | \n");
    Print(L" /_____|\\__|_|  \\___/\\_| |_/\\___/ \\___/|_|\\_\\ |___/ |___/ \n");
    Print(L"\n");

    EFI_HANDLE device_handle = NULL;

    EFI_STATUS status = bootmgfw_restore_original_file(&device_handle);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    status = hyperv_attachment_set_up();

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    return bootmgfw_run_original_image(image_handle, device_handle);
}
