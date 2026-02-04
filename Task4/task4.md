# Task 4: Anti-debugger

### Yêu cầu
:::info
Trình bày cách hiểu về anti debug
Trang này (https://anti-debug.checkpoint.com/) có cung cấp hiểu biết về nhiều kỹ thuật anti debug, chia làm 8 mục lớn (debug flags, object handles, ...). Tìm hiểu về mấy cái kỹ thuật trong này, ít nhất 2 kỹ thuật trên mỗi mục rồi báo cáo lại.
Code 1 cái chương trình chống debug, ở mỗi mục bạn chọn ít nhất 1 kỹ thuật bạn đã viết, cho vào cái chương trình đó.
:::

# Lý Thuyết
## Debug Flags
### 1. Win32 API
### NtQueryInformationProcess()
Đây là một native API của window trong `ntdll.dll`, nhưng không như `IsDebuggerPresent()`, khi được gọi nó thực hiện syscall và chuyển sang kernel.

Syntax:
```cpp!
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
```asm!
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
```asm!
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
```cpp!
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
```cpp!
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
```asm!
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
```cpp!
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
```cpp!
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
```cpp!
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
```cpp!
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
```cpp!
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
```cpp!
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
```cpp!
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
```cpp!
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
```cpp!
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
```cpp!
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
```cpp!
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
```cpp!
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
