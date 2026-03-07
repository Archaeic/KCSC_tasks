# Task 4: Anti-debugger

### Yêu cầu
> ## Trình bày cách hiểu về anti-debug
>
> Trang này (https://anti-debug.checkpoint.com/) có cung cấp hiểu biết về nhiều kỹ thuật anti debug, chia làm 8 mục lớn (debug flags, object handles, ...).
> Tìm hiểu về mấy cái kỹ thuật trong này, ít nhất 2 kỹ thuật trên mỗi mục rồi báo cáo lại.
> Code 1 cái chương trình chống debug, ở mỗi mục bạn chọn ít nhất 1 kỹ thuật bạn đã viết, cho vào cái chương trình đó.



# Lý Thuyết
## Debug Flags
### 1. Win32 API
### NtQueryInformationProcess()
Đây là một native API của window trong `ntdll.dll`, nhưng không như `IsDebuggerPresent()`, khi được gọi nó thực hiện syscall và chuyển sang kernel.

Syntax:
```cpp
__kernel_entry NTSTATUS NtQueryInformationProcess(
  [in]            HANDLE           ProcessHandle,
  [in]            PROCESSINFOCLASS ProcessInformationClass,
  [out]           PVOID            ProcessInformation,
  [in]            ULONG            ProcessInformationLength,
  [out, optional] PULONG           ReturnLength
);
```
Trong đó tham số `ProcessInformationClass` quyết định loại trạng thái của tiến trình được truy vấn, đồng thời xác định kiểu và ý nghĩa của dữ liệu được kernel ghi vào vùng nhớ đầu ra `ProcessInformation`
Tóm lại `NtQueryInformationProcess()` là một hàm cho phép chương trình hỏi kernel và do `ProcessInformationClass` quyết định.
#### ProcessDebugPort
Nếu bị đang debug thì trả về giá trị DWORD là 0xFFFFFFFF (--1)
Syntax: 
```asm
 lea rcx, [dwReturned]
    push rcx    ; ReturnLength
    mov r9d, 4  ; ProcessInformationLength
    lea r8, [dwProcessDebugPort] 
                ; ProcessInformation
    mov edx, 7  ; ProcessInformationClass
    mov rcx, -1 ; ProcessHandle
    call NtQueryInformationProcess
    cmp dword ptr [dwProcessDebugPort], -1
    jz being_debugged
    ...
being_debugged:
    mov ecx, -1
    call ExitProcess
```
#### ProcessDebugFlags

Nếu giá trị trả về bằng 0 thì nó đang bị debugged
Syntax:
```asm
   lea rcx, [dwReturned]
    push rcx     ; ReturnLength
    mov r9d, 4   ; ProcessInformationLength
    lea r8, [dwProcessDebugFlags] 
                 ; ProcessInformation
    mov edx, 1Fh ; ProcessInformationClass
    mov rcx, -1  ; ProcessHandle
    call NtQueryInformationProcess
    cmp dword ptr [dwProcessDebugFlags], 0
    jz being_debugged
    ...
being_debugged:
    mov ecx, -1
    call ExitProcess
```
Khi quá trình debug bắt đầu, kernel sẽ tạo ra một đối tượng nội bộ gọi là Debug Object.
Có thể truy vấn giá trị handle của đối tượng này bằng cách sử dụng lớp thông tin là `ProcessDebugObjectHandle`.
```asm
    lea rcx, [dwReturned]
    push rcx     ; ReturnLength
    mov r9d, 4   ; ProcessInformationLength
    lea r8, [hProcessDebugObject] 
                 ; ProcessInformation
    mov edx, 1Eh ; ProcessInformationClass
    mov rcx, -1  ; ProcessHandle
    call NtQueryInformationProcess
    cmp dword ptr [hProcessDebugObject], 0
    jnz being_debugged
    ...
being_debugged:
    mov ecx, -1
    call ExitProcess
```
Để bypass thì mình phải "hook" hàm và chỉnh các giá trị trả về trong buffer kết quả như sau:
- 0 (hoặc bất kỳ giá trị nào khác -1) trong trường hợp `ProcessDebugPort`.
Giá trị khác 0 trong trường hợp `ProcessDebugFlags`.
- 0 trong trường hợp `ProcessDebugObjectHandle`.

### 2. Manual checks
chương trình tự đọc trực tiếp các cấu trúc nội bộ trong bộ nhớ thay vì dùng API 
### PEB!BeingDebugged Flag
Cái này hoạt động giống `IsDebuggerPresent()` nhưng cách làm khác thôi.
```asm
    mov rax, gs:[60h]         ; PEB
    cmp byte ptr [rax+2], 0   ; so sánh BeingDebugged
    jne being_debugged
```
Nếu BeingDebugged !=0 thì đang bị debug, để bypass chỉnh flag = 0.

## Object Handles
Kĩ thuật này sử dụng handle của kernel object để phát hiện debugger. Nó còn có thể làm một số hàm WinAPI hoạt động khác đi khi đang bị debug
Ngoài ra, khi quá trình debug bắt đầu, hệ điều hành sẽ tạo ra một số kernel object đặc biệt.

### OpenProcess()
Một số debugger có thể bị phát hiện bằng cách sử dụng hàm `kernel32!OpenProcess()` trong process `csrss.exe`.
`Call OpenProcess` chỉ thành công khi:
Users thuộc Administrators và process có debug privilege
```cpp
typedef DWORD (WINAPI *TCsrGetProcessId)(VOID);

bool Check()
{   
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll)
        return false;
    
    TCsrGetProcessId pfnCsrGetProcessId = (TCsrGetProcessId)GetProcAddress(hNtdll, "CsrGetProcessId");
    if (!pfnCsrGetProcessId)
        return false;

    HANDLE hCsr = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pfnCsrGetProcessId()); // Nếu có debugger, mở process thường sẽ thất bại do debugger can thiệp vào handle/quyền
    if (hCsr != NULL)
    {
        CloseHandle(hCsr); // Mở được, không có debugger
        return true;
    }        
    else
        return false;  // Mở không được, có debugger
}
```

### LoadLibrary()

Khi một file được load vào không gian nhớ của một process bằng `kernel32!LoadLibraryA/W`, nếu process đang bị debug, `LOAD_DLL_DEBUG_EVENT` sẽ xảy ra
Handle của file vừa được load sẽ được lưu trong cấu trúc `LOAD_DLL_DEBUG_INFO.` Do đó, debugger có thể đọc thông tin debug từ file này.
NẾU handle này không được debugger đóng, file đó sẽ không thể được mở với chế độ truy cập độc quyền.
Để check có debugger hay không, ta có thể load bất kỳ file nào bằng `kernel32!LoadLibraryA()` và sau đó thử mở file đó bằng `kernel32!CreateFileA()`. Nếu `call kernel32!CreateFileA()` fail, thì có debugger.
Code: 
```cpp
bool Check()
{
    CHAR szBuffer[] = { "C:\\Windows\\System32\\calc.exe" }; //exe đc load vào
    LoadLibraryA(szBuffer); //nếu đang bị debug, debugger nhận handle của file
    return INVALID_HANDLE_VALUE == CreateFileA(szBuffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    //đầu tiên là check, nếu không mở được file = có debugger, và ngược lại
}
```
cái này nói chung là nó trick debugger bằng cách nhận handle của file, xong debugger quên đóng handle, sau đó check bằng `CreateFile` nếu còn giữ handle thì mở file không được

Để vô hiệu hóa thì debug thủ công chương trình cho tới khi gặp đoạn check, sau đó bỏ qua nó, ví dụ:
- patch bằng NOP
- thay đổi instruction
- hoặc chỉnh ZF sau khi phép kiểm tra được thực hiện
## Exceptions
Cố tình gây ra exception để xác minh xem hành vi tiếp theo có khác đi so với tiến trình chạy không có debugger hay không.

### UnhandledExceptionFilter()
Nếu một exception được được kích hoạt và không có handler đc đăng kí, thì `kernel32!UnhandledExceptionFilter()` được gọi. Mình có thể dùng `kernel32!SetUnhandledExceptionFilter()` để đăng kí exception filter đặc biệt chưa được handle. Nhưng nếu chương trình được debugged thì cái filter không được gọi và exception sẽ được pass tới debugger 
Vì vậy, nếu exception filter chưa được handle mà được đăng kí và cái quyền điều khiển được truyền tới nó, thì chương trình không có debugger
Code: 
```asm
include 'win32ax.inc'

.code

start:
        jmp begin

not_debugged:
        invoke  MessageBox,HWND_DESKTOP,"Not Debugged","",MB_OK
        invoke  ExitProcess,0

begin:
        invoke SetUnhandledExceptionFilter, not_debugged
        int  3
        jmp  being_debugged

being_debugged:
        invoke  MessageBox,HWND_DESKTOP,"Debugged","",MB_OK
        invoke  ExitProcess,0

.end start
```
### Hiding Control Flow with Exception Handlers
Nó không phải detect debugger mà là giấu control flow của chương trình
Chúng ta đăng kí một exception handler, từ đó nâng cái exception khác lên sau đó được truyền qua handler rồi nó cứ tiếp diễn như vậy cho đến khi handler dẫn tới chỗ mình cần giấu 
Code (Structured)
```cpp
#include <Windows.h>

void MaliciousEntry()
{
    // ...
}

void Trampoline2()
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        MaliciousEntry(); // payload
    }
}

void Trampoline1()
{
    __try 
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Trampoline2();
    }
}

int main(void)
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    {
        Trampoline1();
    }

    return 0;
}
```
Để bypass `UnhandledExceptionFilter()`, chỉ cần NOP các cái checks
Còn Hiding Control Flow, chúng ta phải trace đến payload
## Timing
Khi chạy dưới debugger, thì có một sự delay giữa các lệnh và lúc thực thi. Mình có thể đo sự delay này giữa một vài đoạn của code và so sánh với delay thực sự

### GetLocalTime()
```cpp
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetLocalTime(&stStart);
    // ... some work
    GetLocalTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return false;
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return false;

    uiStart.LowPart  = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart    = ftEnd.dwLowDateTime;
    uiEnd.HighPart   = ftEnd.dwHighDateTime;
    return (uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed;
}
```
Thì khi mình dùng debugger chương trình sẽ chạy lâu hơn khi mình chỉ việc chạy chương trình, vì thế  nó sẽ so sánh thời gian khi mình dùng debugger để chạy code này với thời gian thật sự khi mình chạy code này mà không có debugger, trường hợp này nó sẽ lấy thời gian của hệ thống để so sánh

### QueryPerformanceCounter()
```cpp
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    LARGE_INTEGER liStart, liEnd;
    QueryPerformanceCounter(&liStart);
    // ... some work
    QueryPerformanceCounter(&liEnd);
    return (liEnd.QuadPart - liStart.QuadPart) > qwNativeElapsed;
}
```
Lấy số đếm để so sánh, khi chạy debugger thì debugger sẽ gặp breakpoint, exception, v.v, con số này bắt nguồn từ `QueryPerformanceCounter()` và sẽ tăng dần qua thời gian, nếu nó cao hơn mức bình thường thì sẽ bị nghi là có debugger
Để patch thì trong lúc debug, mình có thể NOP các lệnh này và đặt lại kết quả của các checks
## Process Memory
Kiểm tra bộ nhớ để: detect debugger, hoặc can thiệp debugger
### Breakpoint
Kiểm tra bộ nhớ và kiếm các software breakpoint trong code, hoặc kiểm tra các thanh ghi để xác định xem các hardware breakpoint có được đặt hay không.
### Software Breakpoints (INT3)
Xác định machine code của một số hàm xem có byte 0xCC hay không, byte 0xCC đại diện cho lệnh `INT 3`.
Nhưng cách này tạo khá nhiều false positive
Code: 
```cpp
bool CheckForSpecificByte(BYTE cByte, PVOID pMemory, SIZE_T nMemorySize = 0)
{
    PBYTE pBytes = (PBYTE)pMemory; 
    for (SIZE_T i = 0; ; i++)
    {
        // Break on RET (0xC3) if we don't know the function's size
        if (((nMemorySize > 0) && (i >= nMemorySize)) ||
            ((nMemorySize == 0) && (pBytes[i] == 0xC3)))
            break;

        if (pBytes[i] == cByte) // Nếu gặp byte cần tìm, phát hiện software breakpoint
            return true;
    }
    return false;
}

bool IsDebugged()
{
    PVOID functionsToCheck[] = {
        &Function1,
        &Function2,
        &Function3,
    };
    for (auto funcAddr : functionsToCheck)
    {
        if (CheckForSpecificByte(0xCC, funcAddr)) // check xem có byte 0xCC ko
            return true; // phát hiện debugger
    }
    return false;
}
```
### Hardware Breakpoints
Thanh ghi debug DR0, DR1, DR2 và DR3 có thể được lấy từ context của thread. Nếu chúng chứa giá trị khác 0, nghĩa là process đang chạy dưới debugger và hardware breakpoint đc đặt.
Code:
```cpp
bool IsDebugged()
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT));
    //lấy các thanh ghi debug trong CONTEXT 
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; 
    
    if(!GetThreadContext(GetCurrentThread(), &ctx)) // Lấy context của thread hiện tại
        return false;
         // Nếu bất kỳ DR nào khác 0 sẽ bị nghi có debugger
    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}
```
## Assembly instructions

### INT3
Lệnh INT3 là một lệnh ngắt được sử dụng như software breakpoint. Khi không có debugger, sau khi đến lệnh INT3, một exception `EXCEPTION_BREAKPOINT` (0x80000003) và một exception handler sẽ được gọi. Nếu có debugger, control flow sẽ không được chuyển tới exception handler.
```cpp
bool IsDebugged()
{
    __try
    {
        __asm int 3; //software bp
        return true; // handle ko chạy, ko bị dbg
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
```
Ngoài ra còn có dạng dài của lệnh INT3 (opcode CD 03).
Khi exception `EXCEPTION_BREAKPOINT` xảy ra, Windows giảm thanh ghi EIP về vị trí của opcode 0xCC và chuyển control tới exception handler. Trong TH dạng dài của lệnh INT3, EIP sẽ trỏ tới giữa instruction (tức byte 0x03). Do đó, EIP cần được chỉnh trong exception handler nếu ta muốn tiếp tục execute sau lệnh INT3 nếu ko, rất có thể gặp `EXCEPTION_ACCESS_VIOLATION`. Nếu ko muốn, đừng sửa EIP.
```cpp
bool g_bDebugged = false;

int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{
    g_bDebugged = code != EXCEPTION_BREAKPOINT;
    return EXCEPTION_EXECUTE_HANDLER;
}

bool IsDebugged()
{
    __try
    {
        __asm __emit(0xCD);
        __asm __emit(0x03);
    }
    __except (filter(GetExceptionCode(), GetExceptionInformation()))
    {
        return g_bDebugged;
    }
}
```

### ICE
thực thi lệnh `ICE` để tạo `EXCEPTION_SINGLE_STEP`. Nếu trình debug đang trace, debugger xử lý exception như single-step và handler nội bộ sẽ không chạy nên ta biết có debugger. Nếu không trace, handler chạy.
```cpp
bool IsDebugged()
{
    __try
    {
        __asm __emit 0xF1;
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
```
Để bypass các check sau đây là patch bằng NOP.
Đối với kỹ thuật chống trace thay vì patch, ta có thể một breakpoint tại đoạn mã nằm sau phép kiểm tra và chạy chương trình cho đến breakpoint đó.

## Direct debugger interaction
cho phép process quản lý một giao diện người dùng hoặc tương tác với process cha của nó để phát hiện các sự không đồng đều của một process đang bị debug.
### Self-debugging
Có ít nhất ba hàm có thể được dùng để attach, đóng vai debugger vào process đang chạy:
- kernel32!DebugActiveProcess()
- ntdll!DbgUiDebugActiveProcess()
- ntdll!NtDebugActiveProcess()

Vì chỉ có một debugger có thể được gắn vào một process cùng lúc, việc attach không thành công vào process có thể chỉ ra sự hiện diện của một debugger khác.
Ở đoạn code dưới, ta chạy instance thứ hai của tiến trình, instance này cố gắng attach debugger vào tiến trình cha của nó (instance thứ nhất). Nếu `kenel32!DebugActiveProcess() `kết thúc không thành công, ta set một event được tạo bởi instance đầu. Nếu event được set, instance đầu hiểu rằng có  debugger.
```cpp
#define EVENT_SELFDBG_EVENT_NAME L"SelfDebugging"

bool IsDebugged()
{
    WCHAR wszFilePath[MAX_PATH], wszCmdLine[MAX_PATH];
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    HANDLE hDbgEvent;

    hDbgEvent = CreateEventW(NULL, FALSE, FALSE, EVENT_SELFDBG_EVENT_NAME); //instance 1
    if (!hDbgEvent)
        return false;

    if (!GetModuleFileNameW(NULL, wszFilePath, _countof(wszFilePath)))
        return false;

    swprintf_s(wszCmdLine, L"%s %d", wszFilePath, GetCurrentProcessId());
    if (CreateProcessW(NULL, wszCmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) // instance 2
    {
            // chờ instance con kt
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
            // kt event
        return WAIT_OBJECT_0 == WaitForSingleObject(hDbgEvent, 0);
    }

    return false;
}

bool EnableDebugPrivilege() 
{
    bool bResult = false;
    HANDLE hToken = NULL;
    DWORD ec = 0;

    do
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
            break;

        TOKEN_PRIVILEGES tp; 
        tp.PrivilegeCount = 1;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
            break;

        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if( !AdjustTokenPrivileges( hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
            break;

        bResult = true;
    }
    while (0);

    if (hToken) 
        CloseHandle(hToken);

    return bResult;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {        
        if (IsDebugged())
            ExitProcess(0);
    }
    else
    {
             // Đây là instance thứ hai: argv[1] chứa PID của process cha cần attach
        DWORD dwParentPid = atoi(argv[1]);
        HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, EVENT_SELFDBG_EVENT_NAME);
        if (hEvent && EnableDebugPrivilege()) // Thử attach như debugger đến process cha
        {
            if (FALSE == DebugActiveProcess(dwParentPid))
                SetEvent(hEvent); 
            else
                DebugActiveProcessStop(dwParentPid); 
        }
        ExitProcess(0);
    }
    
    // ...
    
    return 0;
}
```

### Blockinput()
Hàm user32!BlockInput() có thể chặn hết chuột và bàn phím, đây là một cách khá hiệu quả để vô hiệu hóa một debugger. Call này cần quyền admin
Mình cũng có thể xem thử có tool nào có thể hook `user32!BlockInput()` hoặc những call anti-debug khác.
Hàm này chỉ cho phép chặn input một lần. Call lần 2 sẽ trả false
Nếu hàm trả về true bất kì input nào, điều đó chứng tỏ có gì đó đang hook.
Code: 
```cpp
bool IsHooked ()
{
    BOOL bFirstResult = false, bSecondResult = false;

    __try
    {
        bFirstResult = BlockInput(true);
        bSecondResult = BlockInput(true);
    }
    __finally
    {
        BlockInput(false); // Mở lại input 
    }  
    return bFirstResult && bSecondResult; // Nếu cả hai lần đều trả true, có điều bất thường
}
```
Để bypass, NOP hết hàm call nào sú sú

## Misc
### FindWindow()
Tìm tên/lớp cửa sổ đặc trưng của các disassembler (OllyDbg, WinDbg,…). Nếu thấy một trong các lớp đó, rất có khả năng debugger đang chạy.
```cpp
const std::vector<std::string> vWindowClasses = {
    "antidbg",
    "ID",               // Immunity Debugger
    "ntdll.dll",        
    "ObsidianGUI",
    "OLLYDBG",
    "Rock Debugger",
    "SunAwtFrame",
    "Qt5QWindowIcon",
    "WinDbgFrameClass", // WinDbg
    "Zeta Debugger",
};

bool IsDebugged()
{
    for (auto &sWndClass : vWindowClasses) // Duyệt danh sách các lớp nghi ngờ
    {
        if (NULL != FindWindowA(sWndClass.c_str(), NULL)) // Nếu tồn tại lớp tương ứng, đang bị debug
            return true;
    }
    return false;
}
```
### DbgPrint()
Các hàm debug như `ntdll!DbgPrint()` và `kernel32!OutputDebugStringW()` gây ra exception `DBG_PRINTEXCEPTION_C` (0x40010006). Nếu ct được execute với một debugger đang được attach, thì debugger sẽ xử lý exception này. Nhưng nếu không có debugger, và có một exception handler được đăng ký, exception này sẽ bị bắt bởi exception handler.
phát hiện debugger bằng cách kiểm tra xem exception `DBG_PRINTEXCEPTION_C` bị debugger xử lý hay bị handler của chương trình xử lý.
Code: 
```cpp
bool IsDebugged()
{
    __try
    {
        RaiseException(DBG_PRINTEXCEPTION_C, 0, 0, 0);
    }
    __except(GetExceptionCode() == DBG_PRINTEXCEPTION_C)
    {
        return false;
    }

    return true;
}
```
Muốn bypass thì NOP các check anti 
# Code
Ở đây mình sẽ dùng 8 kĩ thuật sau:
PEB!BeingDebugged Flag, Software Breakpoints (INT3), GetLocalTime(), OpenProcess(), Hiding Control Flow with Exception Handlers, ICE, Blockinput(), FindWindow().


# Sub task
## Antidebug 1

TLScallback:

<img width="832" height="443" alt="{9ADFACDA-ED39-4295-A738-9D8DCF6A4664}" src="https://github.com/user-attachments/assets/2997749a-c6e4-4d0e-9e8f-68b2406c98d4" />

chương trình gọi hai hàm nhìn khá là lạ nên mình chạy qua hết hai hàm đấy để xem có gì.

<img width="1051" height="96" alt="{9AAD4F9A-BCCC-427A-ADCD-A90764F4C35E}" src="https://github.com/user-attachments/assets/9bba9a3d-1f76-4cf3-8fac-a37b58df7c17" />

mình có thể thấy EAX trả về khi chạy hết 2 hàm là  `ZwQueryInformationProcess`. Đây là kĩ thuật API resolver, thay vì gọi hàm bằng tên thì nó giấu hàm đó đi và gọi bằng hashes.

<img width="882" height="125" alt="{0521E24F-2522-4A9A-A0E4-CDEB21303212}" src="https://github.com/user-attachments/assets/52509de4-de7a-426f-b9d0-544065ae0ac4" />

qua call đầu chúng ta có thể biết `7B3FA1C0` là hash của module `ntdll.dll` và `5A3BB3B0` là hash của function `ZwQueryInformationProcess`

<img width="481" height="97" alt="{BF566858-6D7A-42C1-BA58-AAFF86588675}" src="https://github.com/user-attachments/assets/7d754832-2e5f-4bc9-ab2b-a7565f0d336f" />

khi bị debug thì thay đổi data unk_505018 + 10

main:

```cpp
LRESULT __stdcall sub_91350(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
  const CHAR *v5; // [esp-Ch] [ebp-258h]
  DWORD pdwDataLen; // [esp+0h] [ebp-24Ch] BYREF
  tagPAINTSTRUCT Paint; // [esp+4h] [ebp-248h] BYREF
  _OWORD v8[2]; // [esp+44h] [ebp-208h] BYREF
  __int128 v9; // [esp+64h] [ebp-1E8h]
  CHAR v10[208]; // [esp+74h] [ebp-1D8h] BYREF
  CHAR String[260]; // [esp+144h] [ebp-108h] BYREF

  v8[0] = xmmword_938D0;
  v8[1] = xmmword_938E0;
  v9 = xmmword_938F0;
  memset(v10, 0, sizeof(v10));
  pdwDataLen = 48;
  if ( Msg <= 0xF )
  {
    switch ( Msg )
    {
      case 0xFu:
        BeginPaint(hWnd, &Paint);
        EndPaint(hWnd, &Paint);
        return 0;
      case 1u:
        sub_912F0(hWnd);
        return 0;
      case 2u:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
  }
  if ( Msg != 273 )
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
  switch ( (unsigned __int16)wParam )
  {
    case 4u:
      GetWindowTextA(::hWnd, String, 256);
      if ( sub_91B40(String) )
      {
        sub_91000((BYTE *)String, &pdwDataLen);
        if ( pdwDataLen >= 0x2E )
        {
          BYTE14(v9) = 0;
          MessageBoxA(0, (LPCSTR)v8, "OK", 0);
          return 0;
        }
        v5 = "Wrong";
      }
      else
      {
        v5 = "Wrong check fail";
      }
      MessageBoxA(0, "oh, no", v5, 0);
      return 0;
    case 0x68u:
      DialogBoxParamW(hInstance, (LPCWSTR)0x67, hWnd, DialogFunc, 0);
      return 0;
    case 0x69u:
      DestroyWindow(hWnd);
      return 0;
    default:
      return DefWindowProcW(hWnd, 0x111u, wParam, lParam);
  }
}
```
Nhìn qua thì chương trình đang check ở `sub_91B40`
```cpp
char __thiscall check(const char *this)
{
  bool v2; // cl
  int v3; // esi
  int v4; // ecx
  char v5; // bl
  char v6; // cl
  int v7; // eax
  char v8; // al
  int v9; // eax
  void (__stdcall *v10)(_DWORD); // eax
  char result; // al
  char v12; // bl
  int v13; // eax
  unsigned __int8 v14; // cl
  int v15; // eax
  int v16; // eax
  void (__stdcall *v17)(_DWORD); // eax
  void (__stdcall *v18)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD); // [esp-4h] [ebp-25Ch] BYREF
  void (__stdcall *v19)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD); // [esp+10h] [ebp-248h]
  int v20; // [esp+14h] [ebp-244h]
  void (__stdcall *v21)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD); // [esp+18h] [ebp-240h]
  char v22; // [esp+1Fh] [ebp-239h]
  char v23[556]; // [esp+20h] [ebp-238h] BYREF
  int v24; // [esp+24Ch] [ebp-Ch]

  if ( strlen(this) < 0x26 )
    return 0;
  sub_501FD0(v23, byte_50501C[(unsigned __int8)byte_50501C[0] / 0xCu]);
  v2 = v22;
  v3 = 0;
  while ( 2 )
  {
    switch ( dword_5032C8[v3] )
    {
      case 1:
        v4 = dword_503360[v3];
        v5 = this[dword_5033F8[v3]];
        v22 = NtCurrentPeb()->NtGlobalFlag & 0x70;
        v6 = sub_502050(v4);
        v7 = v24;
        if ( v24 >= 256 )
          v7 = 0;
        v24 = v7 + 1;
        v2 = byte_50329F[v7 + 1] == (char)(v5 ^ v6);
        goto LABEL_9;
      case 2:
        v8 = sub_501600((int)v23, this[dword_5033F8[v3]], dword_503360[v3]);
        goto LABEL_8;
      case 3:
        v8 = sub_5016C0(dword_503360[v3]);
        goto LABEL_8;
      case 4:
        v8 = sub_501760(dword_503360[v3]);
        goto LABEL_8;
      case 5:
        v8 = sub_501950(dword_503360[v3]);
        goto LABEL_8;
      case 6:
        v8 = sub_501AA0(dword_503360[v3]);
LABEL_8:
        v2 = v8;
        goto LABEL_9;
      case 7:
        v20 = dword_503360[v3];
        v12 = this[dword_5033F8[v3]];
        v13 = sub_501DF0(2067767744);
        v19 = (void (__stdcall *)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD))sub_501F10(v13, 1513862064);
        v21 = 0;
        v18 = v19;
        v19(-1, 31, &v18, 4, 0);
        v21 = v18;
        v14 = sub_502050(v20);
        v15 = v24;
        if ( v24 >= 256 )
          v15 = 0;
        v24 = v15 + 1;
        if ( byte_50329F[v15 + 1] != (v14 ^ (unsigned __int8)v12) )
          goto LABEL_20;
        v2 = 1;
        goto LABEL_10;
      default:
LABEL_9:
        if ( !v2 )
        {
LABEL_20:
          v16 = sub_501DF0(38312619);
          v17 = (void (__stdcall *)(_DWORD))sub_501F10(v16, 838910877);
          v17(0);
          byte_5055B8 = 0;
          return 0;
        }
LABEL_10:
        if ( ++v3 < 38 )
          continue;
        v9 = sub_501DF0(38312619);
        v10 = (void (__stdcall *)(_DWORD))sub_501F10(v9, 838910877);
        v10(0);
        byte_5055B8 = 0;
        result = 1;
        break;
    }
    return result;
  }
}
```
chương trình đang thực hiện switch case theo `dword_5032C8`

tiếp tục phân tích theo từng cases, mỗi case đều có antidebug

`CASE 1`

ở đây input của mình vẫn đang được lưu ở edi

<img width="501" height="560" alt="{A1B94610-E1EF-4DF0-A9CC-6C43331BD916}" src="https://github.com/user-attachments/assets/15eb6731-b213-4696-a2c6-c42cd369b015" />

khi bị debug `GlobalFlag` sẽ được set giá trị là `0x70`, và luồng đúng sẽ theo bên phải. Khi qua luồng phải thì giá trị ở dl được set là 0

<img width="582" height="108" alt="{A2338FEF-97FC-4D25-83DF-0BBA9237B557}" src="https://github.com/user-attachments/assets/7f9c7c51-dde0-464a-a707-56a970015aa0" />

ở đây nó xor rồi so sánh với `byte_50329F` (cipher)


`CASE 2`

cái này cũng dùng resolver API giống bên TLS rồi h mình xem case 2 nó gọi cái j

<img width="491" height="121" alt="{1BE6564C-F60B-4CDF-9055-C5974A3A9782}" src="https://github.com/user-attachments/assets/7d2bc76c-4004-4334-96fe-6504580bdcc9" />

sau solver sẽ là hàm `GetVersion` lấy version của OS của mình. Sau khi set cho luồng đi nó đúng, mình có thể thấy nó giống luồng ở case 1

<img width="817" height="447" alt="{C87B98B1-412E-4514-B004-1F64108273FA}" src="https://github.com/user-attachments/assets/97c0b881-fb9f-482b-ad5a-2d09b9d0eb64" />


`CASE 3`

Case 3 nó giống case 2. Tuy nhiên mình có để ý là 

<img width="576" height="247" alt="{4C3758BF-44DC-41BF-82BD-B1E71E6A4A9B}" src="https://github.com/user-attachments/assets/8e335f94-16d7-46fd-8c85-3e147065e77e" />
<img width="507" height="228" alt="{4DE0711C-E374-46AB-A952-0A162F9C216E}" src="https://github.com/user-attachments/assets/d7b15ca8-f9f6-4010-a153-fefed2ed3c8b" />

giữa case 2 và case 3 nó có làm cái gì đó với con số kia, thì nó là heap flag, nó sẽ lấy flags hoặc forceflag. Trong TH này case 2 đang lấy flag và case 3 là forceflag
cả ở cả case 2 và case 3 dl đang là 1

`CASE 4`

Case 4 sau khi mình debug thì có những cái này 

<img width="407" height="336" alt="{6C22BABB-512A-4BB6-A544-3785E73E60E5}" src="https://github.com/user-attachments/assets/5c09f6d6-bda7-4662-a370-07c9ebc34023" />

ct sẽ đúng khi flow nó vào đây 

<img width="1071" height="373" alt="{7B683A1D-6B06-4E3C-8B7F-C5A42B418961}" src="https://github.com/user-attachments/assets/edfb7da5-cab2-4634-b9a8-64d3891dbfec" />

dl ở đây sẽ là 0

`CASE 5`

<img width="739" height="350" alt="{8B38EA76-98C9-4186-AF67-F1CBAA844F56}" src="https://github.com/user-attachments/assets/05145785-5d97-4965-8426-0f734494032e" />

dùng process để xem có đang bị debug không, dl của mình ở đây đang là 0

`CASE 6`

<img width="1222" height="178" alt="{4A508A9A-C614-42A0-957A-600CE4BE4FF3}" src="https://github.com/user-attachments/assets/9fbf735f-2df3-4412-8373-7e8da175e046" />

```cpp
bool __fastcall sub_931AA0(int a1, char a2, int a3)
{
  int v5; // eax
  int (__stdcall *v6)(int); // esi
  char v7; // bl
  char v8; // al
  char v9; // al

  v5 = sub_931DF0(38312619);
  v6 = (int (__stdcall *)(int))sub_931F10(v5, 838910877);
  v7 = v6(1);
  v8 = v6(1);
  if ( byte_9355B8 )
  {
    if ( v7 == v8 )
      goto LABEL_3;
  }
  else if ( v7 != v8 )
  {
LABEL_3:
    v9 = sub_932050(a3);
    byte_9355B8 = 1;
    goto LABEL_6;
  }
  v9 = sub_932050(a3);
LABEL_6:
  if ( *(int *)(a1 + 556) >= 256 )
    *(_DWORD *)(a1 + 556) = 0;
  return byte_93329F[++*(_DWORD *)(a1 + 556)] == (char)(a2 ^ v9);
}
``` 
bypass: 

```cpp
bool __fastcall sub_931AA0(int a1, char a2, int a3)
{
  int v5; // eax
  int (__stdcall *v6)(int); // esi
  char v7; // bl
  char v8; // al
  char v9; // al

  v5 = sub_931DF0(38312619);
  v6 = (int (__stdcall *)(int))sub_931F10(v5, 838910877);
  v7 = v6(1);
  v8 = v6(1);
  v9 = sub_932050(a3);

  if ( *(int *)(a1 + 556) >= 256 )
    *(_DWORD *)(a1 + 556) = 0;
  return byte_93329F[++*(_DWORD *)(a1 + 556)] == (char)(a2 ^ v9);
}
```
dl của chúng ta sẽ là 1

`CASE 7`

<img width="1333" height="154" alt="{14E349A3-90E3-46BE-B2B3-08C4B50EC960}" src="https://github.com/user-attachments/assets/f652e7b2-5f86-4660-add1-ff7580386bf6" />

`NtQueryInformationProcess` tiếp, sau khi bypass dl của chúng ta là 1

sau tất cả các cases, chương trình chủ yếu là đang lấy cái này

<img width="858" height="427" alt="{8D2F1640-0210-47DA-B1A4-C36C000A390A}" src="https://github.com/user-attachments/assets/30770f54-a327-44f4-af47-763056302d3f" />

xor vs input và so sánh với byte_93329F giờ mình mô phỏng lại mấy cái cases trên 


```cpp
#include<stdio.h>
 
#define _DWORD unsigned __int32
#define _WORD unsigned __int16

char sub_932050(char a1, unsigned __int8 *a2, int a3)
{
  int v4; // esi
  char v6; // bl
  int v7; // ecx
  unsigned __int16 v8; // dx
  unsigned int v9; // edx
  char v10; // cl
  unsigned int v11; // edx
  unsigned __int8 v12; // al
  bool v13; // zf
  unsigned __int8 *v14; // ecx
  int v15; // esi
  char v16; // dl
  int v18; // [esp+14h] [ebp+8h]

  v4 = a3 - 1;
  v18 = 171;
  v6 = 0;
  do
  {
    if ( v4 <= 5 )
    {
      if ( *(_DWORD *)&a2[4 * v4 + 16] )
        v8 = *(_WORD *)&a2[4 * v4 + 16];
      else
        v8 = *(_WORD *)&a2[4 * v4];
      v7 = (v8 >> 1) | (unsigned __int16)(((unsigned __int16)(32 * v8) ^ (v8 ^ (unsigned __int16)(4 * (v8 ^ (2 * v8)))) & 0xFFE0) << 10);
      *(_DWORD *)&a2[4 * v4 + 16] = v7;
    }
    else
    {
      v7 = 0;
    }
    v9 = v7 & 0x7FF;
    v10 = v7 & 7;
    v11 = v9 >> 3;
    if ( a1 )
      v12 = a2[v11 + 44];
    else
      v12 = ~a2[v11 + 44];
    v13 = v18-- == 1;
    a2[v11 + 44] = v12 ^ (1 << v10);
  }
  while ( !v13 );
  v14 = a2 + 46;
  v15 = 64;
  do
  {
    v16 = *(v14 - 2);
    v14 += 4;
    v6 ^= *(v14 - 4) ^ *(v14 - 3) ^ *(v14 - 5) ^ v16;
    --v15;
  }
  while ( v15 );
  return v6;
}
 
int main(){
 	unsigned __int32 dword_9333F8[] = {9, 18, 15, 3, 4, 23, 6, 7, 8, 22, 10, 11, 33, 13, 14, 27, 16, 37, 17, 19, 20, 21, 5, 34, 24, 25, 26, 2, 12, 29, 30, 31, 32, 28, 0, 35, 36, 1};
	unsigned __int32 dword_933360[] = {1, 3, 1, 1, 2, 1, 3, 1, 2, 2, 4, 4, 1, 3, 4, 4, 4, 1, 2, 1, 4, 1, 4, 3, 1, 2, 4, 4, 2, 2, 1, 3, 4, 2, 1, 2, 2, 3};
	unsigned __int8 v23[] = {54,236,0,0,54,237,0,0,54,187,0,0,54,140,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,95,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
	unsigned __int8 byte_93329F[] = {14,235,243,246,209,107,167,143,61,145,133,43,134,167,107,219,123,110,137,137,24,149,103,202,95,226,84,14,211,62,32,90,126,212,184,16,194,183,0,0};
	unsigned __int32 dword_9332C8[] = {6, 1, 7, 1, 3, 2, 4, 3, 6, 3, 7, 6, 1, 4, 7, 4, 1, 5, 7, 6, 7, 5, 6, 4, 5, 1, 7, 5, 2, 3, 1, 2, 3, 2, 1, 6, 2, 4};
 
 	unsigned char tmp;
  	unsigned char flag[40];
 
	for(int i=0;i<38;i++){
		switch(dword_9332C8[i]){
			case 1:
				tmp = sub_932050(0,v23,dword_933360[i]);
				flag[dword_9333F8[i]] = byte_93329F[i]^tmp;
				break;
			case 2:
				tmp = sub_932050(1,v23,dword_933360[i]);
				flag[dword_9333F8[i]] = byte_93329F[i]^tmp;
				break;
			case 3:
				tmp = sub_932050(1,v23,dword_933360[i]);
				flag[dword_9333F8[i]] = byte_93329F[i]^tmp;
				break;
			case 4:
				tmp = sub_932050(0,v23,dword_933360[i]);
				flag[dword_9333F8[i]] = byte_93329F[i]^tmp;
				break;
			case 5:
				tmp = sub_932050(0,v23,dword_933360[i]);
				flag[dword_9333F8[i]] = byte_93329F[i]^tmp;
				break;
			case 6:
				tmp = sub_932050(1,v23,dword_933360[i]);
				flag[dword_9333F8[i]] = byte_93329F[i]^tmp;
				break;
			case 7:
				tmp = sub_932050(1,v23,dword_933360[i]);
				flag[dword_9333F8[i]] = byte_93329F[i]^tmp;
				break;
			default:
				break;
				
		}
	}
	printf("%s",flag);
	return 1;
} 
```
`I_10v3-y0U__wh3n Y0u=c411..M3 Senor1t4`

## checker

Main
```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+0h] [ebp-10h]
  int v5; // [esp+0h] [ebp-10h]
  unsigned __int8 i; // [esp+Fh] [ebp-1h]

  sub_401050("Enter Your Flag: ", v4);
  sub_4010C0("%s", (char)byte_404630);
  v5 = &byte_404630[strlen(byte_404630) + 1] - (char *)&unk_404631;
  if ( v5 != 32 )
  {
    sub_401050("Wrong Length!!!\n", v5);
    exit(0);
  }
  sub_401750(byte_404630);
  sub_401990(byte_404630);
  sub_401CD0(byte_404630);
  for ( i = 0; i < 0x20u; ++i )
  {
    if ( byte_404630[i] != byte_4042A8[i] )
    {
      sub_401050("Wrong Flag!!!\n", 32);
      exit(0);
    }
  }
  sub_401050("Correct :3\n", 32);
  return 0;
}
```
nhìn qua thì bài này đang biến đổi thông qua 3 hàm `sub_401750`, `sub_401990`, `sub_401CD0` rồi check với `byte_4042A8`.
đầu tiên là phép xor
```cpp
unsigned __int8 __cdecl xor(int a1)
{
  unsigned __int8 result; // al
  unsigned __int8 mm; // [esp+2h] [ebp-Ah]
  unsigned __int8 kk; // [esp+3h] [ebp-9h]
  unsigned __int8 jj; // [esp+4h] [ebp-8h]
  unsigned __int8 n; // [esp+5h] [ebp-7h]
  unsigned __int8 m; // [esp+6h] [ebp-6h]
  unsigned __int8 k; // [esp+7h] [ebp-5h]
  unsigned __int8 i; // [esp+8h] [ebp-4h]
  unsigned __int8 nn; // [esp+9h] [ebp-3h]
  unsigned __int8 ii; // [esp+Ah] [ebp-2h]
  unsigned __int8 j; // [esp+Bh] [ebp-1h]

  for ( i = 0; i < 0x20u; ++i )
    *(_BYTE *)(a1 + i) ^= 0xABu;
  for ( j = 0; j < 0x20u; ++j )
    *(_BYTE *)(a1 + j) ^= j - 85;
  for ( k = 0; k < 0x20u; k += 4 )
    *(_DWORD *)(a1 + k) ^= 0xC0FEBEEF;
  for ( m = 0; m < 0x20u; m += 4 )
    *(_DWORD *)(a1 + m) ^= 0xDEADBABE;
  for ( n = 0; n < 0x20u; ++n )
    *(_BYTE *)(a1 + n) ^= 0xCDu;
  for ( ii = 0; ii < 0x20u; ++ii )
    *(_BYTE *)(a1 + ii) ^= ii - 51;
  for ( jj = 0; jj < 0x20u; jj += 4 )
    *(_DWORD *)(a1 + jj) ^= 0xC0FEBABE;
  for ( kk = 0; kk < 0x20u; kk += 4 )
    *(_DWORD *)(a1 + kk) ^= 0xDEADBEEF;
  for ( mm = 0; ; ++mm )
  {
    result = mm;
    if ( mm >= 0x20u )
      break;
    *(_BYTE *)(a1 + mm) ^= 0xEFu;
  }
  for ( nn = 0; nn < 0x20u; ++nn )
  {
    *(_BYTE *)(a1 + nn) ^= nn - 17;
    result = nn + 1;
  }
  return result;
}
```
Thứ hai là RC4
```cpp
int __cdecl rc4(int a1)
{
  char v2; // [esp+4h] [ebp-4h]
  unsigned __int8 i; // [esp+5h] [ebp-3h]
  unsigned __int8 v4; // [esp+6h] [ebp-2h]
  unsigned __int8 v5; // [esp+7h] [ebp-1h]

  v5 = 0;
  v4 = 0;
  for ( i = 0; i < 0x20u; ++i )
  {
    v4 += byte_5A41A8[++v5];
    v2 = byte_5A41A8[v5];
    byte_5A41A8[v5] = byte_5A41A8[v4];
    byte_5A41A8[v4] = v2;
    *(_BYTE *)(a1 + i) ^= byte_5A41A8[((unsigned __int8)byte_5A41A8[v4] + (unsigned __int8)byte_5A41A8[v5]) % 256];
  }
  return sub_5A12B0();
}
```
Mà ở trong này có 1 chỗ đc gọi trong TLScallback

<img width="863" height="132" alt="{248E3EEA-1983-46AB-B883-A5F5A59280EB}" src="https://github.com/user-attachments/assets/43ff4132-2fbe-428f-9a7d-8e2d334db91b" />

Nhảy vào TLScallback
```cpp
NTSTATUS __stdcall TlsCallback_0(int a1, int a2, int a3)
{
  NTSTATUS result; // eax
  ULONG NtGlobalFlag; // [esp+8h] [ebp-Ch]
  int ProcessInformation; // [esp+Ch] [ebp-8h] BYREF

  NtGlobalFlag = NtCurrentPeb()->NtGlobalFlag;
  ProcessInformation = 0;
  result = NtQueryInformationProcess((HANDLE)0xFFFFFFFF, ProcessDebugPort, &ProcessInformation, 4u, 0);
  if ( !result && ProcessInformation )
  {
    result = NtGlobalFlag & 0x70;
    if ( (NtGlobalFlag & 0x70) != 0 )
      qmemcpy(&byte_7D41A8, &unk_7D40A8, 0x100u);
  }
  return result;
}
```
ở đây nó đang kiểm tra rằng nếu đang bị debug thì sao chép `unk_7D40A8` sang `byte_7D41A8`
sau khi bypass mình có
byte_7D41A8 ={137,205,50,65,154,124,229,81,241,194,161,118,150,89,95,122,79,71,136,112,76,99,40,164,33,144,234,0,9,176,143,22,58,141,62,159,139,230,116,51,64,162,168,57,42,54,199,91,240,180,215,135,222,247,74,138,119,48,117,175,148,90,223,103,72,221,82,147,163,47,254,166,3,217,75,197,93,98,23,102,198,30,228,202,70,25,214,146,120,236,181,77,244,242,123,39,140,49,169,59,18,170,115,157,5,233,182,171,11,8,151,126,186,158,32,37,113,56,128,14,100,235,226,204,250,206,173,68,97,246,255,105,208,19,153,253,218,107,60,34,86,110,178,69,38,127,248,12,188,27,109,196,66,216,132,114,179,142,67,29,185,92,190,94,83,131,203,133,149,155,174,232,21,183,213,227,191,207,108,211,195,193,20,13,1,225,201,63,239,24,104,167,224,200,44,134,31,245,251,106,219,84,212,187,210,73,55,35,209,238,45,172,96,78,231,121,28,177,152,15,111,2,125,10,237,165,160,6,85,36,88,192,189,145,43,243,46,156,7,220,249,41,53,4,129,87,130,184,80,61,101,17,52,252,16,26};

trước khi qua AES thì mình thấy cuối RC4 có ret thêm 1 hàm nữa nên mình vào xem
```cpp
int sub_5A12B0()
{
  DWORD CurrentProcessId; // eax
  DWORD v2; // [esp+10h] [ebp-288h]
  int v3; // [esp+1Ch] [ebp-27Ch]
  int v4; // [esp+20h] [ebp-278h]
  int v5; // [esp+24h] [ebp-274h]
  HANDLE hSnapshot; // [esp+28h] [ebp-270h]
  unsigned __int8 v7; // [esp+57h] [ebp-241h]
  PROCESSENTRY32W pe; // [esp+5Ch] [ebp-23Ch] BYREF
  DWORD flOldProtect; // [esp+288h] [ebp-10h] BYREF
  _BYTE Src[6]; // [esp+28Ch] [ebp-Ch] BYREF

  v7 = 0;
  GetCurrentProcessId();
  CurrentProcessId = GetCurrentProcessId();
  v2 = sub_5A11F0(CurrentProcessId);
  memset(&pe, 0, sizeof(pe));
  pe.dwSize = 556;
  hSnapshot = CreateToolhelp32Snapshot(2u, 0);
  if ( Process32FirstW(hSnapshot, &pe) )
  {
    while ( 1 )
    {
      if ( pe.th32ProcessID == v2 )
      {
        v5 = wcscmp(pe.szExeFile, (const unsigned __int16 *)sub_5A1180((int)aFlagchecker4Ex));
        if ( v5 )
          v5 = v5 < 0 ? -1 : 1;
        if ( v5 )
        {
          v4 = wcscmp(pe.szExeFile, (const unsigned __int16 *)sub_5A1180((int)aCmdExe));
          if ( v4 )
            v4 = v4 < 0 ? -1 : 1;
          if ( v4 )
          {
            v3 = wcscmp(pe.szExeFile, (const unsigned __int16 *)sub_5A1180((int)aExplorerExe));
            if ( v3 )
              v3 = v3 < 0 ? -1 : 1;
            if ( v3 )
              break;
          }
        }
      }
      if ( !Process32NextW(hSnapshot, &pe) )
        goto LABEL_14;
    }
    v7 = 1;
  }
LABEL_14:
  if ( !v7 )
  {
    v7 = 0;
    Src[0] = 0x68;
    Src[5] = 0xC3;
    *(_DWORD *)&Src[1] = sub_5A1A80;
    VirtualProtect(aes, 6u, 0x40u, &flOldProtect);
    memcpy(aes, Src, 6u);
  }
  CloseHandle(hSnapshot);
  return v7;
}
```
Nó đang check xem là process ID có đang khớp với 3 cái tên `flagchecker4.exe`, `cmd.exe` và `explorer.exe` không. Nếu khớp thì v7= 0, xuống label14 khi v7= 0
```cpp
LABEL_14:
  if ( !v7 )
  {
    v7 = 0;
    Src[0] = 0x68;
    Src[5] = 0xC3;
    *(_DWORD *)&Src[1] = sub_5A1A80;
    VirtualProtect(aes, 6u, 0x40u, &flOldProtect);
    memcpy(aes, Src, 6u);
  }
  CloseHandle(hSnapshot);
  return v7;
}
```
`0x68` và `0xC3` là opcode của asm thực hiện lệnh push và ret. Vậy ở đây đang thực hiên push `sub_7D1A80` vào stack và ret tức nó sẽ là `jmp sub_7D1A80` thế thì 
`sub_7D1A80` mới chính là AES của mình.
```cpp
int __usercall sub_5A1A80@<eax>(int a1@<ebp>, const void *a2)
{
  int result; // eax
  unsigned __int8 k; // [esp-47h] [ebp-53h]
  unsigned __int8 j; // [esp-46h] [ebp-52h]
  unsigned __int8 jj; // [esp-45h] [ebp-51h]
  unsigned __int8 ii; // [esp-44h] [ebp-50h]
  unsigned __int8 n; // [esp-43h] [ebp-4Fh]
  unsigned __int8 m; // [esp-42h] [ebp-4Eh]
  unsigned __int8 i; // [esp-41h] [ebp-4Dh]
  __int128 v10; // [esp-40h] [ebp-4Ch] BYREF
  _BYTE v11[36]; // [esp-24h] [ebp-30h] BYREF
  int v12; // [esp+0h] [ebp-Ch]
  void *v13; // [esp+4h] [ebp-8h]
  void *retaddr; // [esp+Ch] [ebp+0h]

  v12 = a1;
  v13 = retaddr;
  qmemcpy(v11, a2, 0x20u);
  for ( i = 0; i < 0x20u; ++i )
    v11[i] = (-120 - i) ^ i;
  for ( j = 0; j < 0x20u; ++j )
    v11[j] = sub_5A16B0(136, v11[j]);
  v10 = xmmword_5A3180;
  for ( k = 0; k < 0x58u; ++k )
  {
    sub_5A1630(v11, &v10);
    sub_5A1630(&v11[16], &v10);
  }
  for ( m = 0; m < 0x20u; ++m )
    *((_BYTE *)a2 + m) = sub_5A1720(*((_BYTE *)a2 + m), m & 7);
  for ( n = 0; n < 0x20u; ++n )
    *((_BYTE *)a2 + n) ^= v11[n];
  for ( ii = 0; ii < 0x20u; ++ii )
    *((_BYTE *)a2 + ii) = sub_5A1720(*((_BYTE *)a2 + ii), 8 - (ii & 7));
  for ( jj = 0; ; ++jj )
  {
    result = jj;
    if ( jj >= 0x20u )
      break;
    *((_BYTE *)a2 + jj) ^= -1 - v11[jj];
  }
  return result;
}
``` 
Giờ giải thôi
```py
flag = [0x9c, 0x87, 0x9c, 0x6e, 0x64, 0x27, 0x3b, 0x78, 0x71, 0x53, 0x2b, 0x6d, 0xd4, 0x0e, 0x82, 0x22, 0x5d, 0xc4, 0xe2, 0xe8, 0x07, 0xb9, 0x85, 0xa7, 0x49, 0x9a, 0x6d, 0xd4, 0xfc, 0x64, 0xba, 0x02]
m = [0x89, 0xcd, 0x32, 0x41, 0x9a, 0x7c, 0xe5, 0x51, 0xf1, 0xc2, 0xa1, 0x76, 0x96, 0x59, 0x5f, 0x7a, 0x4f, 0x47, 0x88, 0x70, 0x4c, 0x63, 0x28, 0xa4, 0x21, 0x90, 0xea, 0x00, 0x09, 0xb0, 0x8f, 0x16, 0x3a, 0x8d, 0x3e, 0x9f, 0x8b, 0xe6, 0x74, 0x33, 0x40, 0xa2, 0xa8, 0x39, 0x2a, 0x36, 0xc7, 0x5b, 0xf0, 0xb4, 0xd7, 0x87, 0xde, 0xf7, 0x4a, 0x8a, 0x77, 0x30, 0x75, 0xaf, 0x94, 0x5a, 0xdf, 0x67, 0x48, 0xdd, 0x52, 0x93, 0xa3, 0x2f, 0xfe, 0xa6, 0x03, 0xd9, 0x4b, 0xc5, 0x5d, 0x62, 0x17, 0x66, 0xc6, 0x1e, 0xe4, 0xca, 0x46, 0x19, 0xd6, 0x92, 0x78, 0xec, 0xb5, 0x4d, 0xf4, 0xf2, 0x7b, 0x27, 0x8c, 0x31, 0xa9, 0x3b, 0x12, 0xaa, 0x73, 0x9d, 0x05, 0xe9, 0xb6, 0xab, 0x0b, 0x08, 0x97, 0x7e, 0xba, 0x9e, 0x20, 0x25, 0x71, 0x38, 0x80, 0x0e, 0x64, 0xeb, 0xe2, 0xcc, 0xfa, 0xce, 0xad, 0x44, 0x61, 0xf6, 0xff, 0x69, 0xd0, 0x13, 0x99, 0xfd, 0xda, 0x6b, 0x3c, 0x22, 0x56, 0x6e, 0xb2, 0x45, 0x26, 0x7f, 0xf8, 0x0c, 0xbc, 0x1b, 0x6d, 0xc4, 0x42, 0xd8, 0x84, 0x72, 0xb3, 0x8e, 0x43, 0x1d, 0xb9, 0x5c, 0xbe, 0x5e, 0x53, 0x83, 0xcb, 0x85, 0x95, 0x9b, 0xae, 0xe8, 0x15, 0xb7, 0xd5, 0xe3, 0xbf, 0xcf, 0x6c, 0xd3, 0xc3, 0xc1, 0x14, 0x0d, 0x01, 0xe1, 0xc9, 0x3f, 0xef, 0x18, 0x68, 0xa7, 0xe0, 0xc8, 0x2c, 0x86, 0x1f, 0xf5, 0xfb, 0x6a, 0xdb, 0x54, 0xd4, 0xbb, 0xd2, 0x49, 0x37, 0x23, 0xd1, 0xee, 0x2d, 0xac, 0x60, 0x4e, 0xe7, 0x79, 0x1c, 0xb1, 0x98, 0x0f, 0x6f, 0x02, 0x7d, 0x0a, 0xed, 0xa5, 0xa0, 0x06, 0x55, 0x24, 0x58, 0xc0, 0xbd, 0x91, 0x2b, 0xf3, 0x2e, 0x9c, 0x07, 0xdc, 0xf9, 0x29, 0x35, 0x04, 0x81, 0x57, 0x82, 0xb8, 0x50, 0x3d, 0x65, 0x11, 0x34, 0xfc, 0x10, 0x1a]
v9 = [0xa4, 0xa9, 0x01, 0xff, 0x22, 0xd3, 0xa3, 0x06, 0xde, 0x2c, 0x17, 0x81, 0xa6, 0x70, 0xa6, 0xe6, 0x7b, 0xb6, 0x47, 0x02, 0x7b, 0x8d, 0x2c, 0x0c, 0x4a, 0x17, 0x21, 0x91, 0x60, 0x72, 0x08, 0xe4]

def ROR_8bit(a1, a2):
    return ((a1 >> a2) | (a1 << (8 - a2))) & 0xff

if __name__ == '__main__':
    for i in range(0x20):
        flag[i] ^= (0xff - v9[i])
    for i in range(0x20):
        flag[i] = ROR_8bit(flag[i], 8 - (i & 7))
    for i in range(0x20):
        flag[i] ^= v9[i]
    for i in range(0x20):
        flag[i] = ROR_8bit(flag[i], i & 7)

    v4, v5 = 0, 0
    for i in range(0x20):
        v5 += 1
        v4 = (v4 + m[v5]) & 0xff
        m[v4], m[v5] = m[v5], m[v4]
        flag[i] ^= m[(m[v4] + m[v5]) & 0xff]

    for i in range(0x20):
        flag[i] ^= (i + 0xEF) & 0xFF
    for i in range(0x20):
        flag[i] ^= 0xEF
    for i in range(0, 0x20, 4):
        flag[i] ^= 0xEF
        flag[i + 1] ^= 0xBE
        flag[i + 2] ^= 0xAD
        flag[i + 3] ^= 0xDE
    for i in range(0, 0x20, 4):
        flag[i] ^= 0xBE
        flag[i + 1] ^= 0xBA
        flag[i + 2] ^= 0xFE
        flag[i + 3] ^= 0xC0
    for i in range(0x20):
        flag[i] ^= (i + 0xCD) & 0xFF
    for i in range(0x20):
        flag[i] ^= 0xCD
    for i in range(0, 0x20, 4):
        flag[i] ^= 0xBE
        flag[i + 1] ^= 0xBA
        flag[i + 2] ^= 0xAD
        flag[i + 3] ^= 0xDE
    for i in range(0, 0x20, 4):
        flag[i] ^= 0xEF
        flag[i + 1] ^= 0xBE
        flag[i + 2] ^= 0xFE
        flag[i + 3] ^= 0xC0
    for i in range(0x20):
        flag[i] ^= (i + 0xAB) & 0xFF
    for i in range(0x20):
        flag[i] ^= 0xAB

    for i in range(0x20):
        print(end = chr(flag[i]))
```
`KCSC{6r347!!!y0u_4r3_w1nn3r:333}`

## antidebug 3

vào main thì nó sẽ trông như này 

<img width="686" height="695" alt="{68B38145-01CB-4B97-9A19-11FC6F2963CF}" src="https://github.com/user-attachments/assets/c878362b-73cb-4a38-8c0b-0b6a5047b822" />

Đầu tiên thì ct làm các phép tính toán với `0DEADBEEF`, cộng trừ nhân sao cho giữ nguyên var_4 = 0 sau đó idiv sẽ lấy 0 chia 0, trong khi đó 0 chia 0 sẽ không được nên nó sẽ tạo lỗi exception. `unhandled_exception_filter` sẽ bị bắt và nó dẫn vào `TopLevelExceptionFilter`

<img width="884" height="459" alt="{6B7A71ED-8E62-4371-88B0-8E97296F3F6C}" src="https://github.com/user-attachments/assets/beed7ea8-fbed-45dc-8cb1-7da799730488" />

nhập flag > đưa vào `byte_404640` và thêm cái `unk_404560` 

Khi mình chạy thử nó ra được cái console như vậy

<img width="464" height="134" alt="{A6356545-4A4E-4D84-AB0A-76F95B4C46F8}" src="https://github.com/user-attachments/assets/dba3d041-9b17-4c78-9575-83e859834510" />

mà trong main mình chưa thấy status nên tìm string thử và ra cái này 

```cpp
int sub_401100()
{
  int result; // eax
  char v1[4]; // [esp+0h] [ebp-Ch]
  int i; // [esp+4h] [ebp-8h]

  *(_DWORD *)v1 = 0;
  for ( i = 0; i < 100; ++i )
  {
    if ( byte_404640[i] == byte_404118[i] )
      ++*(_DWORD *)v1;
  }
  result = sub_401050("Status: %d/100\n", *(_DWORD *)v1);
  if ( *(_DWORD *)v1 == 100 )
    return sub_401050("You got it! flag: kcsc{%s}", byte_404560);
  return result;
}
```
nó đang dùng `byte_404640` để so sánh với `byte_404118`

<img width="416" height="374" alt="{FF5F0116-0EAC-48D7-9349-B1CA383CC446}" src="https://github.com/user-attachments/assets/be5111c0-076f-46ae-8d05-42bce58a4985" />

okay ra lại bên `TopLevelExceptionFilter`

<img width="872" height="473" alt="{91CFCA21-9227-4661-9DB0-909F4F247664}" src="https://github.com/user-attachments/assets/e982c767-c915-4649-9d04-994d90001506" />

Thì thấy `NtGlobalFlag` đoạn này nếu ko có debugger thì xor với 0CDh 

<img width="792" height="459" alt="{9E35C626-905C-46EC-8CB9-E8FCC8BA6C6D}" src="https://github.com/user-attachments/assets/555a5a2b-756e-4724-888c-d476ec43c46e" />

nhảy xuống đây thì bị dính 1 cái antidebug nữa PEB khi nó đang bật thì xor 1 với 0AB = 0AA <img width="172" height="47" alt="{EFD8BE3D-BB04-499E-AA17-3EF118A14ECB}" src="https://github.com/user-attachments/assets/589bdc63-03c8-462a-96f6-d292131ef5b2" />
sửa cờ lại thành 0 để bypass

Giờ f7 vào `sub_631400`
```cpp
int sub_631400()
{
  unsigned int v1; // [esp+4h] [ebp-8h]
  unsigned int i; // [esp+8h] [ebp-4h]

  v1 = (char *)sub_6313F0 - (char *)&loc_631330 - 16;
  for ( i = 0; i < v1 && (*((unsigned __int8 *)&loc_631330 + i) ^ 0x55) != 0x99; ++i )
    ;
  return v1 - i + 48879;
}
```
cái này nó là int3 0x99 ^ 0x55 = 0xCC. Chỉnh cờ thành 0 để bypass 
Xuống cái tiếp theo

<img width="915" height="337" alt="{BADDC6AF-0FCB-401C-85D4-FD3EB6DFD366}" src="https://github.com/user-attachments/assets/b015688b-2bec-4878-8172-67becc6df36d" />

nó chỉ là phép xor thôi. Lấy 17 bytes r cho vào thử..

```py
enc = [0x74, 0x6F, 0x69, 0x35, 0x4F, 0x65, 0x6D, 0x32, 0x32, 0x79, 0x42, 0x32, 0x71, 0x55, 0x68, 0x31, 0x6F, 0x5F]
res = ''.join(chr(b ^ 1) for b in enc)
print(res) #unh4Ndl33xC3pTi0n_
```
vậy là đúng đc 1 phần 

<img width="397" height="95" alt="{A60CBE7A-8F84-415A-9583-8CAE2BE4DF8B}" src="https://github.com/user-attachments/assets/3a9398b1-6a31-4748-87a7-7cbf624fba17" />

trace tiếp thì thấy phần này 

<img width="923" height="389" alt="{2028B9F8-206D-4EFE-8F06-9838B6CE6366}" src="https://github.com/user-attachments/assets/9451a95c-d51d-4ca5-a995-3880c78b2c9c" />

xor 8 kí tự tiếp theo với 0AB

```cpp
enc = [0xDB, 0xCE, 0xC9, 0xEF, 0xCE, 0xC9, 0xFE]
res = ''.join(chr(b ^ 0xAB) for b in enc)
print(res) #pebDebU9
```
Tiếp

<img width="736" height="403" alt="{FD2150C5-6E1F-4C8C-AEB9-266D7E3A441C}" src="https://github.com/user-attachments/assets/6b69d60f-c6ed-4107-9fd6-fafe4edc3930" />

```py
enc = [0x10, 0x27, 0xBC, 0x09, 0x0E, 0x17, 0xBA, 0x4D, 0x18, 0x0F, 0xBE, 0xAB]
k = 0xCD

out = ''
for i, b in enumerate(enc):
    key = (k + i) & 0xFF
    tmp = b ^ key
    out += chr((tmp ^ 1) >> 1)

print(out) #nt9lob4Lfl49
```
next

<img width="1258" height="273" alt="{E1B0EE3C-E751-46FB-A1BD-D0CD44E07581}" src="https://github.com/user-attachments/assets/181ccd1c-02f2-43b7-91a5-7f2b13d4bb46" />

xor 18 kí tự với 0xBEEF

```
enc = [0x9C, 0x8E, 0xA9, 0x89, 0x98, 0x8A, 0x9D, 0x8D, 0xD7, 0xCC, 0xDC, 0x8A, 0xA4, 0xCE, 0xDF, 0x8F, 0x81, 0x89]
key = 0xBEEF
out = b""
for i in range(0, len(enc), 2):
    word = enc[i] | (enc[i+1] << 8)
    out += (word ^ key).to_bytes(2, "little")
print(out.decode("ascii")) #s0F7w4r38r34Kp01n7
```

next

<img width="1304" height="460" alt="{F6AFFF50-0C0A-4F26-91A5-9DAC542A4F72}" src="https://github.com/user-attachments/assets/2eec8a2f-3f68-4d49-b25b-b6ee38928860" />

nó là ROR

```py
enc = [0x69, 0x37, 0x1D, 0x46, 0x46]  

out = ''
for i, b in enumerate(enc):
    dec = ((b << i) | (b >> (8 - i))) & 0xFF
    out += chr(dec)
print(out) #int2d
```

tiếp

<img width="1344" height="313" alt="{656B1407-1B7D-4D83-B102-EB34D0B4B30E}" src="https://github.com/user-attachments/assets/a185e114-57f9-4070-8d4b-95cf20178153" />

int3 và nó xor với `0EFC00CFEh`

```py 
enc  = [0x5E, 0x7D, 0x8A, 0xF3]
key  = [0x37, 0x13, 0xFE, 0xC0]
out  = ''.join(chr(a ^ b) for a, b in zip(enc, key))
print(out) #int3
```

cái cuối dùng hết bytes

<img width="1231" height="294" alt="{4D567649-B749-4C90-B1A9-883BF87224DA}" src="https://github.com/user-attachments/assets/84de9ddf-2e40-4a98-b1e9-1549ee57a674" />

i=1: arr[1] = arr[1] ^ arr[0]         
i=2: arr[2] = arr[2] ^ arr[1]_mới  

dùng giá trị đã bị ghi đè

```py
enc = [0x59, 0x01, 0x57, 0x67, 0x06, 0x41, 0x78, 0x01, 0x65, 0x2D, 0x7B, 0x0E, 0x57, 0x03, 0x68, 0x5D, 0x07, 0x69, 0x23, 0x55, 0x37, 0x60, 0x14, 0x7E, 0x1D, 0x2F, 0x62, 0x5F, 0x62, 0x5F]

out = bytearray(enc)
for i in range(len(out) - 1, 0, -1):
    out[i] ^= out[i-1]
print(out.decode("ascii")) #YXV0aG9ydHVuYTk5ZnJvbWtjc2M===
```

ghép hết lại 

<img width="1489" height="144" alt="{81F960D7-4F86-464E-9035-95CCD016A51A}" src="https://github.com/user-attachments/assets/0bbeec84-cbba-49b8-9d92-8ac0e722f519" />










