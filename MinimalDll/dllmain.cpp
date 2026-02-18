// Minimal DLL - NO CRT, NO imports
// Entry point directly returns TRUE
// Used to validate injection mechanism independently of DLL complexity

#include <windows.h>

// Raw entry point - no CRT initialization
BOOL WINAPI _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        // Do absolutely nothing - just return TRUE
        // If Status=2 after injection, the mechanism works
    }

    return TRUE;
}
