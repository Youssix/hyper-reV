@echo off
setlocal

set build_directory=%~dp0build\x64\Release\

mountvol Z: /S

set boot_directory=Z:\EFI\Microsoft\Boot\

if exist "%boot_directory%bootmgfw.original.efi" (
    echo hyper-reV already scheduled, updating hyperv-attachment.dll...
    copy /Y "%build_directory%hyperv-attachment.dll" "%boot_directory%"
    echo updated. reboot to apply.
) else (
    attrib -s %boot_directory%bootmgfw.efi
    move %boot_directory%bootmgfw.efi %boot_directory%bootmgfw.original.efi

    copy /Y %~dp0uefi-boot.efi %boot_directory%bootmgfw.efi
    copy /Y "%build_directory%hyperv-attachment.dll" "%boot_directory%"

    bcdedit /set hypervisorlaunchtype auto

    echo hyper-reV will load at next boot
)

endlocal
pause