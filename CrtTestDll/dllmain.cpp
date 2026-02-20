// CRT Test DLL — diagnostic version
// Overrides _initterm_e to log results to in-memory buffer (read via hypervisor)
// Also tries file output as fallback

#include <windows.h>

typedef int (__cdecl* _PIFV)(void);
typedef void (__cdecl* _PVFV)(void);

//=============================================================================
// In-memory diagnostic buffer — inject tool reads this from hidden memory
// Marker: 0xD1A6D1A6 at start, so inject tool can find it
//=============================================================================

#pragma section(".diag", read, write)
__declspec(allocate(".diag")) volatile unsigned int g_diag_marker = 0xD1A6D1A6;
__declspec(allocate(".diag")) volatile int g_diag_phase = 0;        // 1=initterm_e entered, 2=initterm entered, 3=DllMain entered
__declspec(allocate(".diag")) volatile int g_diag_total = 0;        // total initializers
__declspec(allocate(".diag")) volatile int g_diag_failed_idx = -1;  // which index failed (-1=none)
__declspec(allocate(".diag")) volatile int g_diag_failed_ret = 0;   // failed return value
__declspec(allocate(".diag")) volatile int g_diag_last_err = 0;     // GetLastError at failure
__declspec(allocate(".diag")) volatile unsigned long long g_diag_failed_fn = 0; // address of failed fn
__declspec(allocate(".diag")) volatile int g_diag_results[32] = {}; // per-initializer: 1=OK, -ret=FAIL, 0=null/skipped

//=============================================================================
// Also try file output (best-effort)
//=============================================================================

static HANDLE try_open_diag_file()
{
    // Try several paths in order
    HANDLE h;
    h = CreateFileA("C:\\Users\\yo\\Documents\\crt_diag.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) return h;
    h = CreateFileA("C:\\Users\\Public\\crt_diag.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) return h;
    h = CreateFileA("C:\\crt_diag.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) return h;
    h = CreateFileA("crt_diag.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    return h; // might be INVALID_HANDLE_VALUE
}

static void diag_write(HANDLE hFile, const char* msg)
{
    if (hFile == INVALID_HANDLE_VALUE) return;
    DWORD len = 0;
    while (msg[len]) len++;
    DWORD written;
    WriteFile(hFile, msg, len, &written, NULL);
}

static void int_to_str(int val, char* buf)
{
    if (val == 0) { buf[0] = '0'; buf[1] = '\0'; return; }
    int neg = 0;
    unsigned int uval;
    if (val < 0) { neg = 1; uval = (unsigned int)(-(long long)val); } else { uval = (unsigned int)val; }
    char tmp[12]; int i = 0;
    while (uval > 0) { tmp[i++] = '0' + (uval % 10); uval /= 10; }
    int j = 0;
    if (neg) buf[j++] = '-';
    while (i > 0) buf[j++] = tmp[--i];
    buf[j] = '\0';
}

static void u64_to_hex(unsigned long long val, char* buf)
{
    const char hex[] = "0123456789ABCDEF";
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 15; i >= 0; i--)
        buf[2 + (15 - i)] = hex[(val >> (i * 4)) & 0xF];
    buf[18] = '\0';
}

//=============================================================================
// Override _initterm_e — linker prefers OBJ over LIB
//=============================================================================

extern "C" int __cdecl _initterm_e(_PIFV* pfbegin, _PIFV* pfend)
{
    g_diag_phase = 1;

    HANDLE hFile = try_open_diag_file();
    char numbuf[20];

    int total = (int)(pfend - pfbegin);
    g_diag_total = total;

    diag_write(hFile, "=== _initterm_e ===\r\nTotal: ");
    int_to_str(total, numbuf); diag_write(hFile, numbuf);
    diag_write(hFile, "\r\n");

    int index = 0;
    for (_PIFV* pfn = pfbegin; pfn < pfend; ++pfn, ++index)
    {
        if (*pfn == nullptr)
        {
            if (index < 32) g_diag_results[index] = 0;
            continue;
        }

        diag_write(hFile, "[");
        int_to_str(index, numbuf); diag_write(hFile, numbuf);
        diag_write(hFile, "] ");
        u64_to_hex((unsigned long long)*pfn, numbuf); diag_write(hFile, numbuf);
        diag_write(hFile, " -> ");
        if (hFile != INVALID_HANDLE_VALUE) FlushFileBuffers(hFile);

        int ret = (**pfn)();

        if (index < 32)
            g_diag_results[index] = (ret == 0) ? 1 : -(ret);

        if (ret != 0)
        {
            g_diag_failed_idx = index;
            g_diag_failed_ret = ret;
            g_diag_last_err = (int)GetLastError();
            g_diag_failed_fn = (unsigned long long)*pfn;

            diag_write(hFile, "FAIL ret=");
            int_to_str(ret, numbuf); diag_write(hFile, numbuf);
            diag_write(hFile, " GLE=");
            int_to_str(g_diag_last_err, numbuf); diag_write(hFile, numbuf);
            diag_write(hFile, "\r\n");
            if (hFile != INVALID_HANDLE_VALUE) { FlushFileBuffers(hFile); CloseHandle(hFile); }
            return ret;
        }

        diag_write(hFile, "OK\r\n");
    }

    diag_write(hFile, "\r\nAll passed!\r\n");
    if (hFile != INVALID_HANDLE_VALUE) { FlushFileBuffers(hFile); CloseHandle(hFile); }
    return 0;
}

//=============================================================================
// Override _initterm
//=============================================================================

extern "C" void __cdecl _initterm(_PVFV* pfbegin, _PVFV* pfend)
{
    g_diag_phase = 2;
    for (_PVFV* pfn = pfbegin; pfn < pfend; ++pfn)
    {
        if (*pfn) (**pfn)();
    }
}

//=============================================================================
// DllMain
//=============================================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL; (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        g_diag_phase = 3;
        MessageBoxA(NULL, "CRT DLL Injected!", "CrtTest", MB_OK | MB_ICONINFORMATION);
    }
    return TRUE;
}
