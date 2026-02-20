@echo off
setlocal

set build_directory=%~dp0build\x64\Release\

mountvol Z: /S

set boot_directory=Z:\EFI\Microsoft\Boot\

if exist "%boot_directory%bootmgfw.original.efi" (
    echo hyper-reV already scheduled, updating bootloader + hyperv-attachment.dll...
) else (
    attrib -s %boot_directory%bootmgfw.efi
    move %boot_directory%bootmgfw.efi %boot_directory%bootmgfw.original.efi

    bcdedit /set hypervisorlaunchtype auto

    echo hyper-reV first install, original bootmgfw.efi backed up.
)

copy /Y "%build_directory%uefi-boot.efi" "%boot_directory%bootmgfw.efi"
copy /Y "%build_directory%hyperv-attachment.dll" "%boot_directory%"

echo updated. reboot to apply.

endlocal
pause