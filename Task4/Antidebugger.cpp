// antidebug_checkpoint.c
// Implements the 8 Check Point anti-debug techniques verbatim (x86 MSVC).
// Build (Developer Command Prompt, x86 target, Release):
//   cl /O2 /EHsc /nologo antidebug_checkpoint.c

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

typedef DWORD(WINAPI* TCsrGetProcessId)(VOID);

bool c1(void);
bool c2(void);
bool c3(void);
bool c4(void);
bool c5(void);
bool c6(void);
bool c7(void);
bool c8(void);
void print_flag(void);

static bool CheckForSpecificByte(BYTE cByte, PVOID pMemory, SIZE_T nMemorySize)
{
    PBYTE pBytes = (PBYTE)pMemory;
    SIZE_T i = 0;

    for (;; ++i) {
        if ((nMemorySize > 0 && i >= nMemorySize) ||
            (nMemorySize == 0 && pBytes[i] == 0xC3))
            break;

        if (pBytes[i] == cByte)
            return true;
    }
    return false;
}


// PEB BeingDebugged

bool c1(void)
{
    BYTE flag = 0;
    __asm {
        mov eax, fs: [0x30]
        mov al, [eax + 2]
        mov flag, al
    }
    return flag == 0;
}

// Software BP

bool c2(void)
{
    PVOID functionsToCheck[] = {
        (PVOID)c1,
        (PVOID)c3,
        (PVOID)c4
    };
    size_t n = sizeof(functionsToCheck) / sizeof(functionsToCheck[0]);

    for (size_t j = 0; j < n; ++j) {
        if (CheckForSpecificByte(0xCC, functionsToCheck[j], 0)) {
            return false;
        }
    }
    return true;
}


// GetLocalTime

bool c3(void)
{
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetLocalTime(&stStart);
    for (volatile int i = 0; i < 500000; ++i) { }
    GetLocalTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return true; 
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return true;

    uiStart.LowPart = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;


    const unsigned long long qwNativeElapsed = 10000000ULL;
    if ((uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed)
        return false;

    return true;
}

// OpenProcess

bool c4(void)
{
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) return true;

    TCsrGetProcessId pfn = (TCsrGetProcessId)GetProcAddress(hNtdll, "CsrGetProcessId");
    if (!pfn) {
        FreeLibrary(hNtdll);
        return true;
    }

    DWORD pid = pfn();
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (h) {
        CloseHandle(h);
        FreeLibrary(hNtdll);
        return false;
    }

    FreeLibrary(hNtdll);
    return true;
}


// Hiding control flow 

LONG WINAPI cp_seh_handler(PEXCEPTION_POINTERS info)
{
    info->ContextRecord->Eip += 3;
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool c5(void)
{
    bool ok = true;
    SetUnhandledExceptionFilter(cp_seh_handler);

    __asm {
        int 3
        jmp done_label
    }

    ok = false;

done_label:
    return ok == false;
}


 // ICE

bool c6(void)
{
    __try {
        __asm __emit 0xF1
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
}

// BlockInput()

bool c7(void)
{
    BOOL r1 = BlockInput(TRUE);
    BOOL r2 = BlockInput(TRUE);
    BlockInput(FALSE);
    return !(r1 && r2);
}

// FindWindow

bool c8(void)
{
    const char* dbg[] = {
        "OLLYDBG",
        "WinDbgFrameClass",
        "ID",
        "ObsidianGUI",
        "Rock Debugger",
        "Qt5QWindowIcon",
        "Zeta Debugger"
    };
    for (int i = 0; i < 7; ++i) {
        if (FindWindowA(dbg[i], NULL))
            return false;
    }
    return true;
}

void print_flag(void)
{
    unsigned char p1[] = { 0x9F, 0x8A, 0x8F, 0x99, 0xCB };
    unsigned char p2[] = { 0xF2, 0xE6, 0xE3, 0xEE, 0xA7 };
    unsigned char p3[] = { 0x01, 0x1A, 0x1B, 0x06, 0x02 };
    unsigned char p4[] = { 0xD5, 0xC2, 0xCF, 0xC6, 0xDD };

    char out[32];
    int k = 0;
    for (int i = 0; i < 5; ++i) out[k++] = (char)((p1[i] ^ 0xF9) - 1);
    for (int i = 0; i < 5; ++i) out[k++] = (char)(p2[i] ^ 0xA3);
    for (int i = 0; i < 5; ++i) out[k++] = (char)(p4[i] ^ p3[i]);
    out[k] = '\0';
    printf("%s\n", out);
}

int main(void)
{
    int passed = 0;
    if (c1()) ++passed;
    if (c2()) ++passed;
    if (c3()) ++passed;
    if (c4()) ++passed;
    if (c5()) ++passed;
    if (c6()) ++passed;
    if (c7()) ++passed;
    if (c8()) ++passed;

    printf("%d/8 checks passed\n", passed);
    if (passed == 8) print_flag();

    (void)getchar();
    return 0;
}
