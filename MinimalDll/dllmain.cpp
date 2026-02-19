// Minimal DLL for injection validation
// Raw entry point - no CRT initialization

#include <windows.h>

BOOL WINAPI _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        // 1. File proof (zero UI dependency)
        HANDLE h = CreateFileA("C:\\injected.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (h != INVALID_HANDLE_VALUE)
        {
            WriteFile(h, "pwned\r\n", 7, NULL, NULL);
            CloseHandle(h);
        }

        // 2. DebugView proof (kernel32 only, open DebugView to see)
        OutputDebugStringA("[PhysInj] DLL injected successfully!\n");

        // 3. MessageBox (needs user32 + GUI thread)
        MessageBoxA(NULL, "DLL Injected!", "PhysInj", MB_OK | MB_ICONINFORMATION);
    }

    return TRUE;
}
