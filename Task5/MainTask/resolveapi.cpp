#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <shlwapi.h>
#include <string.h>
#pragma comment(lib, "Shlwapi.lib")

int cmpUnicodeStr(WCHAR substr[], WCHAR mystr[]) {
    _wcslwr_s(substr, MAX_PATH);
    _wcslwr_s(mystr, MAX_PATH);

    int result = 0;
    if (StrStrW(mystr, substr) != NULL) {
        result = 1;
    }

    return result;
}

typedef UINT(CALLBACK* fnMessageBoxA)(
    HWND   hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT   uType
    );

HMODULE myGetModuleHandle(LPCWSTR lModuleName) {
    PEB* pPeb = (PEB*)__readgsqword(0x60);

    PEB_LDR_DATA* Ldr = pPeb->Ldr;
    LIST_ENTRY* ModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

    WCHAR mystr[MAX_PATH] = { 0 };
    WCHAR substr[MAX_PATH] = { 0 };
    for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {
        LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

        memset(mystr, 0, MAX_PATH * sizeof(WCHAR));
        memset(substr, 0, MAX_PATH * sizeof(WCHAR));
        wcscpy_s(mystr, MAX_PATH, pEntry->FullDllName.Buffer);
        wcscpy_s(substr, MAX_PATH, lModuleName);
        if (cmpUnicodeStr(substr, mystr)) {
            return (HMODULE)pEntry->DllBase;
        }
    }
    return NULL;
}

FARPROC myGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        if (strcmp(lpProcName, (const char*)hModule + addressOfNames[i]) == 0) {
            return (FARPROC)((BYTE*)hModule + addressOfFunctions[addressOfNameOrdinals[i]]);
        }
    }

    return NULL;
}

int main(int argc, char* argv[]) {
    HMODULE mod = myGetModuleHandle(L"user32.dll");
    if (NULL == mod) {
        return -2;
    }
    else {
        printf("dc");
    }

    fnMessageBoxA myMessageBoxA = (fnMessageBoxA)myGetProcAddress(mod, "MessageBoxA");
    myMessageBoxA(NULL, "asm la gi", ".....", MB_OK);
    return 0;
}