# Task 5: Resolve API

### Yêu cầu
> #### Tìm hiểu và code chương trình thực hiện resolve windows api và gọi messagebox, lưu ý tất cả các hàm winapi phải thực hiện resolve, code cả c và asm (giải thích rõ ràng ý tưởng, code)

## Resolve API
- Resolve API là kĩ thuật mà chương trình không import API trực tiếp mà tự tìm địa chỉ của API.

Ý tưởng:
Sử dụng `GetModuleHandleA` để lấy địa chỉ của dll.

Ex: 
```cpp!
 HMODULE kernel32dll  = GetModuleHandleA("kernel32.dll");
```
Sau đó dùng `GetProcAddress` để resolve

Ex:
```cpp!
myIsDebuggerPresent  = GetProcAddress(kernel32dll, "IsDebuggerPresent");
```
### GetModuleHandleA
Vậy `GetModuleHandleA` hoạt động như thế nào? 
1. Truy cập PEB của process
2. Xác định `InMemoryOrderModuleList` trong cấu trúc Ldr của PEB 
3. Lặp qua danh sách liên kết của các module đã được load
4. So sánh base name của từng module với tên module mong muốn
5. Nếu tìm thấy trùng khớp, trả về địa chỉ base (đóng vai trò như handle) của module đó


Code ([nguồn](https://cocomelonc.github.io/malware/2023/04/08/malware-av-evasion-15.html))
```clike
HMODULE myGetModuleHandle(LPCWSTR lModuleName) {

    PEB* pPeb = (PEB*)__readgsqword(0x60);
// Lấy model đc load vào process
    PEB_LDR_DATA* Ldr = pPeb->Ldr;
    LIST_ENTRY* ModuleList = &Ldr->InMemoryOrderModuleList;

    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

    WCHAR mystr[MAX_PATH] = { 0 };
    WCHAR substr[MAX_PATH] = { 0 };
    for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {
 // lấy address của LDR_DATA_TABLE_ENTRY hiện tại
        LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));
// check xem cái có phải dll mình cần 
        memset(mystr, 0, MAX_PATH * sizeof(WCHAR));
        memset(substr, 0, MAX_PATH * sizeof(WCHAR));
        wcscpy(mystr, pEntry->FullDllName.Buffer);
        wcscpy(substr, lModuleName);
        if (cmpUnicodeStr(substr, mystr)) {
            return (HMODULE)pEntry->DllBase;
        }
    }

    printf("failed to get a handle to %ls\n", lModuleName);
    return NULL;
}
```
### GetProcAddress
`GetProcAddress` là 1 hàm Windows API lấy địa chỉ của 1 function đã đc xuất ra hoặc 1 biến từ dll nhất định. Đây nó đc sử dụng để load function từ dll trong runtime 

```cpp!
FARPROC GetProcAddress(
  HMODULE hModule,
  LPCSTR  lpProcName
);
```
- `hModule` - Là handle của DLL module, chứa functions hoặc biến. Function `LoadLibrary` trả lại handle này 
- `lpProcName` - Tên function hoặc biến dưới dạng chuỗi kết thúc bằng ký tự null, hoặc giá trị thứ tự của function. Nếu tham số này là một giá trị thứ tự, nó phải nằm trong low-order, và high-order word phải bằng không.
```cpp
FARPROC myGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader ->e_lfanew);
  PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + 
  ntHeaders ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

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
```
1. Lấy header của DOZ và NT:
-- Đổi base address của `hModule` thành pointer `PIMAGE_DOS_HEADER` và sử dụng nó để xác định address của cấu trúc `PIMAGE_NT_HEADERS` bằng cách cộng `e_lfanew` field vào base address
2. Tìm export directory:
-- Sử dụng `OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress` từ cấu trúc `PIMAGE_NT_HEADERS`để tìm cấu trúc `PIMAGE_EXPORT_DIRECTORY`
3. Lấy pointer tới export table:
-- Lấy pointer đến các table `AddressOfFunctions`, `AddressOfNameOrdinals` và `AddressOfNames` bằng cách sử dụng các trường tương ứng của cấu trúc `PIMAGE_EXPORT_DIRECTORY` và base address của module.
4. Lặp, tìm các tên:
-- Lặp qua `AddressOfNames` tối đa `NumberOfNames` lần, và so sánh từng tên function với tên function cần có (lpProcName) bằng hàm `strcmp`.
5. Tìm địa chỉ function: 
-- Nếu tên hàm khớp, tìm ordinal của function bằng cách tra cứu bảng `AddressOfNameOrdinals`, và sử dụng số đó để tra cứu bảng `AddressOfFunctions`. Tính toán address của function bằng cách cộng base address của module với virtual address (RVA) của function.

Kết hợp cả 2 đoạn lại
```cpp
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
```
Đây là bản ASM
```asm
global main

extern ExitProcess

section .data
    kernel32_str db "KERNEL32.DLL", 0
    getproc_str  db "GetProcAddress", 0
    msgbox_str   db "MessageBoxA", 0
    user32_str   db "USER32.DLL", 0
    loadlib_str db "LoadLibraryA", 0
    text db "haaha..", 0
    caption db ".", 0

section .bss
    kernel32_base resq 1
    getproc_addr  resq 1
    msgbox_addr   resq 1
    loadlib_addr resq 1
    user32_base  resq 1
section .text

; p.biệt hoa và thường 

strcmp:
.cmp:
    mov al, [rdi] 
    mov cl, [rsi]  
    cmp al, cl
    jne .noteq
    test al, al
    je .eq
    inc rdi
    inc rsi
    jmp .cmp
.eq:
    xor rax, rax
    ret
.noteq:
    mov rax, 1
    ret


; lấy kernel32 base qua PEB

get_kernel32:
    mov rax, [gs:0x60]        ; PEB
    mov rax, [rax + 0x18]     ; PEB->Ldr
    mov rax, [rax + 0x20]     ; InMemoryOrderModuleList
    mov rax, [rax]            ; ntdll
    mov rax, [rax]            ; kernel32
    mov rax, [rax + 0x20]     ; DllBase
    ret

.next:
    mov rbx, [rbx]            
    mov rcx, [rbx + 0x50]     ; BaseDllName 
    mov rax, [rbx + 0x20]     ; DllBase
    ret


; export table
resolve_export:
    push rbx  
    push rsi 
    push rdi 
    push r12 
    push r13 
    push r14 
    push r15

    mov rbx, rcx              ; module base

    mov eax, [rbx + 0x3C]
    add rax, rbx              ; PE header

    mov eax, [rax + 0x88]     ; export table RVA
    add rax, rbx

    mov r12d, [rax + 0x18]    ; NumberOfNames
    mov r13d, [rax + 0x20]    ; AddressOfNames
    add r13, rbx

    mov r14d, [rax + 0x24]    ; AddressOfNameOrdinals
    add r14, rbx

    mov r15d, [rax + 0x1C]    ; AddressOfFunctions
    add r15, rbx

.loop:
    test r12d, r12d              ; test nếu NumberOfNames == 0
    jz .notfound                

    dec r12d                     ; index-- 

    mov esi, [r13 + r12*4]       ; lấy RVA của tên function từ mảng AddressOfNames 
    add rsi, rbx                 ; chuyển RVA thành VA

    mov rdi, rdx                 ; rdi = tên của function mình muốn
    call strcmp                  ; cmp tên export vs tên đó
    cmp rax, 0                   
    jne .loop                    
   ; nếu thấy 
    movzx eax, word [r14 + r12*2] ; lấy ordinal index từ AddressOfNameOrdinals
    mov eax, [r15 + rax*4]        ; lấy function RVA từ AddressOfFunctions
    add rax, rbx                 ; chuyển RVA → VA 
    jmp .done                    

.notfound:
    xor rax, rax               
.done:
    ; hồi phục lại registers
    pop r15 
    pop r14 
    pop r13 
    pop r12 
    pop rdi 
    pop rsi 
    pop rbx 
    ret      ; rax = function pointer


main:
    sub rsp, 40

    ; lấy kernel32 base
    call get_kernel32
    mov [rel kernel32_base], rax

    ; resolve GetProcAddress
    mov rcx, rax
    mov rdx, getproc_str
    call resolve_export
    mov [rel getproc_addr], rax

    ; resolve LoadLibraryA
    mov rcx, [rel kernel32_base]
    mov rdx, loadlib_str            
    call resolve_export
    mov [rel loadlib_addr], rax

    ; call LoadLibraryA
    lea rcx, [rel user32_str]        
    call [rel loadlib_addr]
    mov [rel user32_base], rax

    ; resolve MessageBoxA 
    mov rcx, rax
    mov rdx, msgbox_str
    call resolve_export
    mov [rel msgbox_addr], rax

    ; call MessageBoxA
    xor rcx, rcx
    lea rdx, [rel text]
    lea r8,  [rel caption]
    xor r9, r9
    call [rel msgbox_addr]
exit:
    xor rcx, rcx
    call ExitProcess
```

# Sub task
### VEH
Mới vào chương trình dẫn mình đến đoạn này 
```asm 
.text:00007FF6D2862540 push    rsi
.text:00007FF6D2862541 sub     rsp, 20h
.text:00007FF6D2862545 call    sub_7FF6D28611F0
.text:00007FF6D286254A mov     cs:dword_7FF6D2865108, 0
.text:00007FF6D2862554 mov     ecx, 0C11AD5C5h
.text:00007FF6D2862559 mov     edx, 145370BBh
.text:00007FF6D286255E call    sub_7FF6D2861000
.text:00007FF6D2862563 lea     rdx, sub_7FF6D28611A0
.text:00007FF6D286256A mov     ecx, 1
.text:00007FF6D286256F call    rax
.text:00007FF6D2862571 mov     cs:dword_7FF6D286510C, 0
.text:00007FF6D286257B mov     r8, 0FFFFFFFFE3B9876Ah
.text:00007FF6D2862582 mov     r9, 29CDD463h
.text:00007FF6D2862589 xor     rax, rax
.text:00007FF6D286258C div     rax
.text:00007FF6D286258C ; ---------------------------------------------------------------------------
.text:00007FF6D286258F db 0E9h
.text:00007FF6D2862590 db  48h ; H
.text:00007FF6D2862591 db  89h
.text:00007FF6D2862592 db 0C6h
.text:00007FF6D2862593 ; ---------------------------------------------------------------------------
.text:00007FF6D2862593 mov     ecx, 0FFFFFFF6h
.text:00007FF6D2862598 call    rax
.text:00007FF6D286259A mov     cs:qword_7FF6D28650F8, rax
.text:00007FF6D28625A1 mov     ecx, 0FFFFFFF5h
.text:00007FF6D28625A6 call    rsi
.text:00007FF6D28625A8 mov     cs:qword_7FF6D2865100, rax
.text:00007FF6D28625AF mov     cs:dword_7FF6D2865110, 0
.text:00007FF6D28625B9 add     rsp, 20h
.text:00007FF6D28625BD pop     rsi
.text:00007FF6D28625BE retn
.text:00007FF6D28625BE sub_7FF6D2862540 endp ; sp-analysis failed
```
Ở đoạn này 
```asm
.text:00007FF6D2862554 mov     ecx, 0C11AD5C5h
.text:00007FF6D2862559 mov     edx, 145370BBh
.text:00007FF6D286255E call    sub_7FF6D2861000
.text:00007FF6D2862563 lea     rdx, sub_7FF6D28611A0
.text:00007FF6D286256A mov     ecx, 1
.text:00007FF6D286256F call    rax
```
Chương trình thực hiện call API resolver và call resolved API `ntdll_RtlAddVectoredExceptionHandler` là API mà đoạn code đã call, vậy chương trình đã cài exception handler
Tiếp theo 
```asm 
mov r8, 0FFFFFFFFE3B9876Ah
mov r9, 29CDD463h
xor rax, rax
div rax
```
Chương trình `div rax` trong khi rax = 0, vì vậy sẽ tạo lỗi `divide by zero exception` và kích hoạt `AddVectoredExceptionHandler` thế nên flow sẽ được tiếp tục trong `sub_7FF6D28611A0`
```cpp
__int64 __fastcall sub_7FF6D28611A0(__int64 a1)
{
  *(_QWORD *)(*(_QWORD *)(a1 + 8) + 120LL) = sub_7FF6D2861000(
                                               *(_DWORD *)(*(_QWORD *)(a1 + 8) + 184LL),
                                               *(_DWORD *)(*(_QWORD *)(a1 + 8) + 192LL));
  *(_QWORD *)(*(_QWORD *)(a1 + 8) + 248LL) += 4LL;
  return 0xFFFFFFFFLL;
}
```
Theo như các chuyên gia phân tích thì ở đây chương trình thực hiện 
```asm
mov r8, func_hash
mov r9, module_hash
xor rax, rax
div rax
```
CPU sẽ bị lỗi `integer division by zero exception` lỗi này cũng được kích hoạt bởi `div rax` ban nãy. Sau đó win sẽ gọi tự exception handler 

Tiếp theo, `div rax` có bytes là `48 F7 F0` nhưng tác giả lại thêm 1 byte `E9` nữa

Vậy logic là `div rax` chia 0 = lỗi -> exception -> exception handler -> `rax` = API call

Vậy mình sẽ ngồi mò hết đống API này :sob:

Những API mà mình tìm được là

```
LoadLibraryW
memset
memcmp
memcpy
WriteFile
ReadFile
CryptReleaseContext
CryptDestroyKey
CryptImportKey
CryptAcquireContextA
CryptSetKeyParam
CryptEncrypt
GetLastError
```

Hàm `sub_7FF6D6F31640` là nơi tạo key/thuật toán
![{42E2AF04-24D7-46BA-B963-B2ED6841F67E}](https://hackmd.io/_uploads/S1LNr2Iqbg.png)
Sau khi giải xong nó sẽ tự xóa key.
![{E9382D77-F4C5-4DF7-A61F-0210D72141C8}](https://hackmd.io/_uploads/ByKh06Lq-g.png)
Ở khúc này mình có 1 doạn loop, loop hết ta được một url (https://www.youtube.com/watch?v=dQw4w9WgXcQ)

Nếu chúng ta chạy xuống chút nữa thì ct sẽ xóa nó ;/
![{99C7BDBC-9ACC-4A68-BFD0-5570CF34F319}](https://hackmd.io/_uploads/B1ktkRU5Zx.png)

Ở khúc này 
![{EBF6EF3C-0CE8-457F-9F79-417BCECE72C2}](https://hackmd.io/_uploads/ByrnoALq-g.png)
Ct có gọi `CryptSetKeyParam` và số byte của nó là 16 từ 1 -> 16 vậy đây là Initialization Vector
Tiếp theo mình phát hiện đoạn này
![{0F1D9638-1661-478A-B91E-69C25EABC01B}](https://hackmd.io/_uploads/H1mopAL5Zg.png)
Nó có gọi `sub_7FF6D6F319A0` là AES, có length là 32 và nó có resolve memcmp `memcmp(encrypted_output, this, 32)` vậy `unk_7FF6D6F35000` là ciphertext của chúng ta
```py
#from gpt with luv
import hashlib
from Crypto.Cipher import AES

url   = b"https://www.youtube.com/watch?v=dQw4w9WgXcQ"
key   = hashlib.sha256(url).digest()
IV    = bytes(range(1, 17)) 
ciphertext    = bytes.fromhex("e560440942c4bbdef6a12d93d91d1372af8d4cf7a79f1fb999689cb8c24c4f85")

cipher = AES.new(key, AES.MODE_CBC, IV)
pt     = cipher.decrypt(ciphertext)
#padding (1 byte of 0x01)
flag   = pt[:-pt[-1]]
print(flag)
```
![{398AFA2A-1308-4D1A-A064-D8812AFDEE35}](https://hackmd.io/_uploads/rk48lJDcbg.png)


### Wannaflag
Vào main
```ccp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // esi
  HANDLE FileA; // esi
  DWORD v5; // esi
  DWORD v6; // edi
  DWORD v7; // eax
  DWORD v8; // edx
  DWORD v9; // esi
  CHAR *v10; // edi
  DWORD v11; // ecx
  int result; // eax
  DWORD NumberOfBytesRead; // [esp+10h] [ebp-808h] BYREF
  _BYTE v14[192]; // [esp+18h] [ebp-800h] BYREF
  int v15; // [esp+D8h] [ebp-740h] BYREF
  int v16; // [esp+DCh] [ebp-73Ch]
  int v17; // [esp+E0h] [ebp-738h]
  int v18; // [esp+E4h] [ebp-734h]
  int v19; // [esp+E8h] [ebp-730h]
  int v20; // [esp+ECh] [ebp-72Ch]
  int v21; // [esp+F0h] [ebp-728h]
  int i; // [esp+F4h] [ebp-724h]
  CHAR Filename[264]; // [esp+F8h] [ebp-720h] BYREF
  CHAR Buffer[1024]; // [esp+308h] [ebp-510h] BYREF
  CHAR FileName[268]; // [esp+708h] [ebp-110h] BYREF

  memset(Buffer, 0, sizeof(Buffer));
  GetModuleFileNameA(0, Filename, 0x104u);
  if ( IsDebuggerPresent() )
    goto LABEL_24;
  v3 = strrchr(Filename, 92);
  if ( IsDebuggerPresent() )
    goto LABEL_24;
  if ( v3 )
    v3[1] = 0;
  sub_231360(FileName, 0x104u, "%s%s", (char)Filename);
  FileA = CreateFileA(FileName, 0x80000000, 0, 0, 3u, 0, 0);
  if ( IsDebuggerPresent() )
    goto LABEL_24;
  if ( FileA != (HANDLE)-1 && ReadFile(FileA, Buffer, 0x400u, &NumberOfBytesRead, 0) )
  {
    CloseHandle(FileA);
    v5 = 16 - (NumberOfBytesRead & 0xF);
    if ( !IsDebuggerPresent() )
    {
      v6 = 0;
      if ( v5 )
      {
        v6 = v5;
        memset(&Buffer[NumberOfBytesRead], v5, v5);
      }
      v7 = v6 + NumberOfBytesRead;
      NumberOfBytesRead = v7;
      if ( v7 >= 0x400 )
        __report_rangecheckfailure();
      Buffer[v7] = 0;
      v15 = -1448796403;
      v16 = -2133891425;
      v17 = 1676089180;
      v18 = -1110616710;
      v19 = -426315469;
      v20 = 1338778897;
      v21 = -1038548038;
      i = -738310864;
      AES_key_expansion(v14, &v15);
      if ( !IsDebuggerPresent() )
      {
        v8 = NumberOfBytesRead;
        v9 = NumberOfBytesRead >> 4;
        if ( NumberOfBytesRead >> 4 )
        {
          v10 = Buffer;
          do
          {
            AES_encrypt(v10, v14);
            v10 += 16;
            --v9;
          }
          while ( v9 );
          v8 = NumberOfBytesRead;
        }
        v11 = 0;
        v15 = 1029662604;
        v16 = 837762801;
        v17 = -682434832;
        v18 = -1806848824;
        v19 = -524838890;
        v20 = 220915250;
        v21 = -1681108108;
        for ( i = 982145798; v11 < v8; ++v11 )
          Buffer[v11] ^= *((_BYTE *)&v15 + (int)v11 % 32);
        if ( !IsDebuggerPresent() && !IsDebuggerPresent() && !IsDebuggerPresent() )
        {
          result = (int)Buffer;
          MEMORY[0] = 0;
          return result;
        }
      }
    }
LABEL_24:
    ExitProcess(0xFFFFFFFF);
  }
  return 1;
}
```
Đầu tiên mình thấy được chương trình đang mã hóa file `fl4g_f0r_y0u.txt` 2 lần 
Lần 1 
```cpp
      v7 = v6 + NumberOfBytesRead;
      NumberOfBytesRead = v7;
      if ( v7 >= 1024 )
        __report_rangecheckfailure();
      Buffer[v7] = 0;
      v15 = -1448796403;
      v16 = -2133891425;
      v17 = 1676089180;
      v18 = -1110616710;
      v19 = -426315469;
      v20 = 1338778897;
      v21 = -1038548038;
      i = -738310864;
      sub_231000(v14, &v15);
```
Trong `sub_231000` có thêm 1 đoạn mã hóa như vậy nữa
```cpp
v2 = *a2 ^ 0x42;
  v3 = (_BYTE *)a1;
  v4 = a2[13] ^ 0x4D;
  v5 = a2[14] ^ 0x58;
  v3[13] = v4;
  *v3 = v2;
  v6 = a2[1] ^ 0x4D;
  v3[14] = v5;
  v3[1] = v6;
  v7 = a2[15];
  v3[2] = a2[2] ^ 0x58;
  v3[3] = a2[3] ^ 0x63;
  v3[4] = a2[4] ^ 0x42;
  v3[5] = a2[5] ^ 0x4D;
  v3[6] = a2[6] ^ 0x58;
  v3[7] = a2[7] ^ 0x63;
  v3[8] = a2[8] ^ 0x42;
  v3[9] = a2[9] ^ 0x4D;
  v3[10] = a2[10] ^ 0x58;
  v3[11] = a2[11] ^ 0x63;
  v3[12] = a2[12] ^ 0x42;
  result = v3 + 13;
  v3[15] = v7 ^ 0x63;
  LOBYTE(a1) = 4;
  v11 = 4;
  do
  {
    v9 = v4;
    v10 = *(result - 1);
    v12 = result[1];
    v13 = result[2];
    if ( (a1 & 3) == 0 )
    {
      v12 = byte_237138[v13];
      v13 = byte_237138[v10];
      v10 = byte_237138[v4] ^ byte_237338[v11 >> 2];
      v9 = byte_237138[(unsigned __int8)result[1]];
    }
    result[3] = v10 ^ *(result - 13);
    v4 = v9 ^ *(result - 12);
    result[4] = v4;
    result[5] = v12 ^ *(result - 11);
    result[6] = v13 ^ *(result - 10);
    result += 4;
    a1 = v11 + 1;
    v11 = a1;
  }
  while ( a1 < 0x2C );
  return result;
}
```
Và `sub_231140` 
```cpp
  v2 = a1;
  v33 = a1;
  v3 = a2 - (_DWORD)a1;
  v4 = 4;
  do
  {
    v5 = 4;
    do
    {
      *a1 ^= a1[v3];
      ++a1;
      --v5;
    }
    while ( v5 );
    --v4;
  }
  while ( v4 );
  for ( i = 1; ; ++i )
  {
    v6 = v2;
    v7 = 4;
    do
    {
      v8 = v6;
      v9 = 4;
      do
      {
        v10 = *v8;
        v8 += 4;
        *(v8 - 4) = byte_237138[v10];
        --v9;
      }
      while ( v9 );
      ++v6;
      --v7;
    }
    while ( v7 );
    v11 = v2[1];
    v2[1] = v2[5];
    v2[5] = v2[9];
    v2[9] = v2[13];
    v12 = v2[10];
    v2[13] = v11;
    v13 = v2[2];
    v2[2] = v12;
    v14 = v2[14];
    v2[10] = v13;
    v15 = v2[6];
    v2[6] = v14;
    v16 = v2[15];
    v2[14] = v15;
    v17 = v2[3];
    v2[3] = v16;
    v2[15] = v2[11];
    result = v2[7];
    v2[11] = result;
    v2[7] = v17;
    if ( i == 10 )
      break;
    v19 = v2 + 2;
    v20 = 4;
    do
    {
      v21 = v19[1];
      v19 += 4;
      v22 = *(v19 - 4);
      v23 = *(v19 - 5);
      v35 = *(v19 - 6);
      v24 = v23 ^ v35 ^ v22 ^ v21;
      *(v19 - 6) = v24 ^ v35 ^ (2 * (v23 ^ v35)) ^ (27 * ((unsigned __int8)(v23 ^ v35) >> 7));
      *(v19 - 5) = v24 ^ v23 ^ (2 * (v22 ^ v23)) ^ (27 * ((unsigned __int8)(v22 ^ v23) >> 7));
      *(v19 - 4) = v24 ^ v22 ^ (2 * (v22 ^ v21)) ^ (27 * ((unsigned __int8)(v22 ^ v21) >> 7));
      *(v19 - 3) = v24 ^ v21 ^ (2 * (v21 ^ v35)) ^ (27 * ((unsigned __int8)(v21 ^ v35) >> 7));
      --v20;
    }
    while ( v20 );
    v25 = 4;
    v2 = v33;
    v26 = v33;
    v27 = (char *)(a2 + 16 * i);
    do
    {
      v28 = 4;
      do
      {
        v29 = *v27++;
        *v26++ ^= v29;
        --v28;
      }
      while ( v28 );
      --v25;
    }
    while ( v25 );
  }
  v30 = 4;
  v31 = (_BYTE *)(a2 + 160);
  do
  {
    v32 = 4;
    do
    {
      LOBYTE(result) = *v31++;
      *v2++ ^= result;
      --v32;
    }
    while ( v32 );
    --v30;
  }
  while ( v30 );
  return result;
}
```
Lần 2
```cpp
v8 = NumberOfBytesRead;
        }
        v11 = 0;
        v15 = 1029662604;
        v16 = 837762801;
        v17 = -682434832;
        v18 = -1806848824;
        v19 = -524838890;
        v20 = 220915250;
        v21 = -1681108108;
        for ( i = 982145798; v11 < v8; ++v11 )
          Buffer[v11] ^= *((_BYTE *)&v15 + (int)v11 % 32);
```
Nghĩ rằng có thể tạo solver luôn, nhưng ở phần asm nó có một đoạn code như vậy nhìn khá là lạ

![{73819804-0EFE-459C-B4E2-F384FB705113}](https://hackmd.io/_uploads/HkfwKDcqZx.png)

nên mình sẽ patch `IsDebuggerPresent` và vào xem nó làm gì

![image](https://hackmd.io/_uploads/ByHLiPc9-g.png)
Khi  xuống `mov [ecx], ecx` thanh ecx của mình là 0 nên ct sẽ ghi vào NULL và tạo exception

Và ở TLSCallBack
```cpp
PVOID __stdcall TlsCallback_0(int a1, int a2, int a3)
{
  return AddVectoredExceptionHandler(1u, Handler);
}
```
Mình thấy handler đã được đăng kí trước, vậy thì khi dính exception của `mov [ecx], ecx` flow sẽ tiếp tục ở `Handler`
```cpp
LONG __stdcall Handler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
  PCONTEXT ContextRecord; // ecx
  PCONTEXT *p_ContextRecord; // edi
  DWORD Edx; // eax
  unsigned int Ebx; // esi
  unsigned int v6; // eax
  DWORD Eax; // edx
  DWORD *p_Eax; // ebx
  unsigned int v9; // ecx
  DWORD v10; // ebx
  struct _EXCEPTION_POINTERS *ExceptionInfoa; // [esp+Ch] [ebp+8h]

  if ( ExceptionInfo->ExceptionRecord->ExceptionCode == -1073741819 )
  {
    ContextRecord = ExceptionInfo->ContextRecord;
    p_ContextRecord = &ExceptionInfo->ContextRecord;
    Edx = ContextRecord->Edx;
    Ebx = ContextRecord->Ebx;
    switch ( Edx )
    {
      case 0u:
        *(_BYTE *)(ContextRecord->Eax + Ebx) ^= 0xDu;
        (*p_ContextRecord)->Eip += 3;
        return -1;
      case 1u:
        *(_BYTE *)(ContextRecord->Eax + Ebx) += 37;
        (*p_ContextRecord)->Eip += 4;
        return -1;
      case 2u:
        *(_BYTE *)(ContextRecord->Eax + Ebx) -= 37;
        (*p_ContextRecord)->Eip += 5;
        return -1;
      case 3u:
        *(_BYTE *)(ContextRecord->Eax + Ebx) ^= 0x25u;
        (*p_ContextRecord)->Eip += 3;
        return -1;
      case 4u:
        *(_BYTE *)(ContextRecord->Eax + Ebx) += 13;
        (*p_ContextRecord)->Eip += 4;
        return -1;
      case 5u:
        *(_BYTE *)(ContextRecord->Eax + Ebx) -= 13;
        (*p_ContextRecord)->Eip += 5;
        return -1;
    }
    if ( Edx != 6 )
      return -1;
    v6 = 0;
    if ( !Ebx )
      goto LABEL_30;
    if ( Ebx < 8 )
      goto LABEL_29;
    Eax = ContextRecord->Eax;
    ExceptionInfoa = (struct _EXCEPTION_POINTERS *)(Eax + Ebx - 1);
    p_Eax = &ContextRecord->Eax;
    if ( Eax <= (unsigned int)p_ContextRecord && ExceptionInfoa >= (struct _EXCEPTION_POINTERS *)p_ContextRecord )
      goto LABEL_29;
    if ( Eax <= (unsigned int)p_Eax && ExceptionInfoa >= (struct _EXCEPTION_POINTERS *)p_Eax )
      goto LABEL_29;
    if ( Ebx >= 0x40 )
    {
      v9 = ContextRecord->Ebx & 0x3F;
      do
      {
        *(__m128i *)(Eax + v6) = _mm_andnot_si128(*(__m128i *)(Eax + v6), (__m128i)xmmword_237390);
        *(__m128i *)(Eax + v6 + 16) = _mm_andnot_si128(*(__m128i *)(Eax + v6 + 16), (__m128i)xmmword_237390);
        *(__m128i *)(Eax + v6 + 32) = _mm_andnot_si128(*(__m128i *)(Eax + v6 + 32), (__m128i)xmmword_237390);
        *(__m128i *)(Eax + v6 + 48) = _mm_andnot_si128(*(__m128i *)(Eax + v6 + 48), (__m128i)xmmword_237390);
        v6 += 64;
      }
      while ( v6 < Ebx - v9 );
      if ( v9 < 8 )
      {
LABEL_28:
        while ( v6 < Ebx )
        {
LABEL_29:
          *(_BYTE *)((*p_ContextRecord)->Eax + v6) = ~*(_BYTE *)((*p_ContextRecord)->Eax + v6);
          ++v6;
        }
LABEL_30:
        (*p_ContextRecord)->Eip += 4;
        return -1;
      }
      ContextRecord = *p_ContextRecord;
    }
    v10 = ContextRecord->Eax;
    do
    {
      *(_QWORD *)(v10 + v6) = _mm_andnot_si128(_mm_loadl_epi64((const __m128i *)(v10 + v6)), (__m128i)xmmword_237390).m128i_u64[0];
      v6 += 8;
    }
    while ( v6 < Ebx - (Ebx & 7) );
    goto LABEL_28;
  }
  return 0;
}
```
<img width="621" height="45" alt="{42131C75-C83F-4426-868A-1C636407BA88}" src="https://github.com/user-attachments/assets/1ddd40a9-3f69-49fc-85fe-d70221e51a08" />

Trong `ExceptionInfo` có chứa thông tin của `ExceptionRecord` và `ContextInfo`. 
<img width="1776" height="44" alt="{99834936-D848-4F16-965A-16532F70CEFF}" src="https://github.com/user-attachments/assets/3a5192e1-a4f9-4a82-905e-05f08696b613" />
`ContextRecord` thì nó đang chứa opcode của handler

`





















`TCP1P{wh4t_4_r3v3rs3_3ng1neEr!_76ad1fea}`





