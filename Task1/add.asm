.386
.model flat, stdcall
option casemap:none

include \masm32\include\kernel32.inc
include \masm32\include\msvcrt.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\msvcrt.lib

.data
    msg1 db "Nhap so thu 1 : ", 0
    msg2 db "Nhap so thu 2 : ", 0
    msg3 db "kq = %I64u", 13, 10, 0
    fmt  db "%I64u", 0 ;I64u giong llu

    m dq 0   ;khai bao bien giong kieu 'int m' trong c, kq= 64bit
    n dq 0
    kq dq 0

.code
start:
     
    ;nhap so 1
    push offset msg1 ;lay dia chi msg1 roi day msg1 len stack
    call crt_printf  ;goi ham in
    add esp, 4       ;don stack, 1 push 4 byte

    push offset m    ;day dia chi m len stack
    push offset fmt  ;push dia chi fmt tuong tu voi scanf trong c
    call crt_scanf   ;goi ham nhap
    add esp, 8       ;don stack, 2 push 8 byte
    
    ;nhap so 2
    push offset msg2
    call crt_printf
    add esp, 4

    push offset n
    push offset fmt
    call crt_scanf
    add esp, 8

    ;cong
    mov eax, dword ptr [m]     ;lay m sang eax (lo)
    mov edx, dword ptr [m+4]   ;lay m nhung lay bat dau tu dia chi m+4 (hi)

    add eax, dword ptr [n]     ;eax = m.lo + n.lo
    adc edx, dword ptr [n+4]   ;edx = m.hi + n.hi + cf

    ;luu ket qua
    mov dword ptr [kq], eax    ;lo
    mov dword ptr [kq+4], edx  ;hi

    ;in kq
    push dword ptr [kq+4] ;push hi
    push dword ptr [kq]   ;push lo
    push offset msg3      ;push kq 
    call crt_printf       ;goi ham print
    add esp, 12           ;don stack, 12 boi vi push 3 lan 4x3

    push 0
    call ExitProcess
end start
