# Task 1: Assembly 101

Nguồn học: [1](https://www.youtube.com/watch?v=bhTGgzRsn1k&t=3416s), [2](https://adminvietnam.org/kien-thuc-co-ban-ve-assembly/4463/)
## 1. Lý thuyết 

#### Registers

EAX: thanh ghi tích lũy. Thường được dùng trong nhập xuất và các lệnh tính toán số học.                                                                            
EBX: thanh ghi cơ sở. Thường được dùng để đánh dấu địa chỉ, lưu địa chỉ bắt đầu của 1 mảng.                                                                        
ECX: thanh ghi đếm. Thường được dùng trong vòng lặp, đếm số lần lặp.                                                                                               
EDX: thanh ghi dữ liệu. Thường được sử dụng trong nhập xuất dữ liệu như EAX.                                                                                    
EIP và IP: trỏ tới địa chỉ chứa lệnh tiếp theo sẽ được thực thi.                                                                                                
ESP và SP: trỏ tới đỉnh hiện thời của stack.                                                                                                                       
EBP và BP: thường dùng để tham chiếu đến các biến tham số sử dụng trong chương trình con.   

#### Instructions
các lệnh cơ bản:

`mov eax, 0x1` ; eax = 0x1                                                                                                                                         
`cmp eax, ebx` ; so sánh eax ebx                                                                                                                                   
`test eax, ebx`; thử eax ebx                                                                                                                                     
`jne`      ; nhảy nếu không bằng                                                                                                                                   
`je`         ; nhảy nếu bằng
`jump`         ; nhảy tới địa chỉ                                                                                                                                  
`add eax, ebx` ; eax = eax + ebx                                                                                                                                   
`sub eax, ebx` ; eax = eax - ebx                                                                                                                                
`inc eax`      ; eax = eax + 1                                                                                                                                    
`dec eax`      ; eax = eax -1                                                                                                                                     
`imul eax, 0x3`; eax = eax * 0x3                                                                                                                                
`idiv eax, 0x6`; eax = eax / 0x6                                                                                                                                
`and eax, 0x1` ; eax = eax & 0x1                                                                                                                                
`or eax, 0x1`  ; eax = eax | 0x1                                                                                                                                
`xor eax, 0x1` ; eax = eax ^ 0x1                                                                                                                                
`not eax `    ; eax = ~eax                                                                                                                                         
`shl eax, 0x1` ; eax = eax << 0x1 (nhân 2)                                                                                                                        
`shr eax, 0x1` ; eax = eax >> 0x1 (chia 2)                                                                                                                        

ngoài ra còn có các **flags** như:

![image](https://hackmd.io/_uploads/S1tFOg3EWl.png)

#### Stack

Stack hoạt động trên nguyên tắc LIFO(last in, first out), tức cái nào vào sau thì ra trước.                                                                        
ESP (Stack Pointer): Trỏ đến đỉnh ngăn xếp hiện tại.                                                                                                            
EBP (Base Pointer): Trỏ đến đáy của khung ngăn xếp hiện tại trong các hàm, giúp quản lý các tham số và biến cục bộ của hàm.                                        
push: push sẽ đẩy một giá trị vào stack, khi push thì ESP = ESP - 0x4 (đối với 64-bit sẽ là 0x8)                                                                   
pop: pop sẽ lấy giá trị trên cùng của stack ra, khi pop thì ESP = ESP + 0x4                                                                                        
vì vậy càng lên cao, địa chỉ sẽ càng giảm và ngược lại.                                                                                                            
#### Endianess
Endianness là cách sắp xếp thứ tự byte                                                                                                                             
vd: 0A0B0C0D                                                                                                                                                    
Little endian sẽ sắp xếp như sau: 0D 0C 0B 0A                                                                                                                    
Big endian sẽ sắp xếp như sau: 0A 0B 0C 0D                                                                                                                        


#### Calling convention

Quy ước chung: 

![image](https://hackmd.io/_uploads/ryRmv7CEZg.png)



**Cdecl**
Cho chương trình mẫu:
```c 
#include<stdio.h>

int sum(int a, int b){
    return a + b;
}

int main(){
    int c;
    c = sum(3, 6);
    return 0;
}
```
cho lên IDA thì đây là dạng của call cdecl

![image](https://hackmd.io/_uploads/Syy0zXh4Wg.png)


chương trình thực hiện mov 2 giá trị vào stack theo nguyên tắc ngược lại rồi sau đó gọi hàm sum

![image](https://hackmd.io/_uploads/SybzXX2N-l.png)

vào hàm sum 

![image](https://hackmd.io/_uploads/ry6TVQhNbx.png)

thì ta có thể thấy nó đang push giá trị `_main+22` vào stack

![image](https://hackmd.io/_uploads/ByoISQnV-x.png)

vào `_main+22` thì nó dẫn tới cái này thì nó nghĩa là địa chỉ của lệnh kế tiếp sau call sum                                                                        
vậy thì cách hoạt động của nó theo thứ tự như sau:                                                                                                                
B1: `push ebp` để lưu ebp vào stack                                                                                                                                
B2: `move ebp, esp`, di chuyển esp vào ebp => thiết lập stack mới                                                                                                
B3: `pop ebp` lấy lại ebp cũ                                                                                                                                     
B4: `ret` trở về hàm call                                                                                                                                        

***Stdcall***

__stdcall chủ yếu được API Windows sử dụng và nhỏ gọn hơn __cdecl một chút, nhưng thực chất thì em thấy 2 cái này cũng tựa nhau.

Ngoài ra còn có nhiều calling conventions:`__fastcall`, `__clrcall`, `__thiscall` và `__vectorcall`. Một số cái lỗi thời như `__pascal`, `__fortran`, `__syscall`.

## 2. Code chương trình asm


#### Task: Chương trình asm: cộng 2 số tự nhiên lớn (tràn thanh ghi, số hạng trong đoạn [0, 2^64 - 1] với 32 bit, [0, 2^128 - 1] với 64 bit)
- Cho phép nhập 2 số (Thêm msg ví dụ: "Nhập số thứ nhất: ")
- Tính cộng
- In kết quả

muốn ra đc 64 bit trong với 32 bit thì mình cộng 2 phần 32 bit lại

IDE em sử dụng là MASM32 ([tutorial](https://www.youtube.com/watch?v=uJgkKhQa4kM))

```
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

```
<img width="382" height="299" alt="image" src="https://github.com/user-attachments/assets/d1c47e4a-59d7-4152-a333-ef74fcbe2b2e" />



Bổ sung thêm: không được dùng lib, cộng nhớ                                                                                                                        
ps: không dùng lib nên e sang nasm luôn e dùng masm vì nó có call sẵn cho dễ thở 😔

```
section .data
    msg1    db "Nhap so thu 1: "   ; nhập số thứ nhất
    len1    equ $ - msg1           ; độ dài

    msg2    db "Nhap so thu 2: "   
    len2    equ $ - msg2         

    msgkq   db "KQ: "        
    lenkq   equ $ - msgkq         

section .bss
    num1    resb 100               ; buffer chứa số 1
    num2    resb 100               
    buf     resb 101               

section .text
global _start
_start:

;in nhập chữ 1
    mov rax, 1                     ; syscall 1 = write
    mov rdi, 1                     ; fd = 1 = stdout
    mov rsi, msg1                  ; địa chỉ chuỗi cần in
    mov rdx, len1                  ; số byte cần in
    syscall                        ; gọi kernel

;đọc số 1
    xor rax, rax                   ; rax = 0 = syscall read
    xor rdi, edi                   ; fd = 0 → stdin
    mov rsi, num1                  ; buffer nhận dữ liệu
    mov rdx, 100                   ; đọc tối đa 100 byte
    syscall                        ; rax = số byte đọc được

    dec rax                        ; bỏ '\n'
    mov r12, rax                   ; r12 = độ dài số 1

;in nhập chữ 2
    mov rax, 1                    
    mov rdi, 1                   
    mov rsi, msg2                  
    mov rdx, len2               
    syscall

;đọc số 2
    xor rax, rax                 
    xor rdi, rdi                  
    mov rsi, num2                
    mov rdx, 100                
    syscall

    dec rax                  
    mov r13, rax                   ; r13 = độ dài số 2

    lea rsi, [r12-1]               ; rsi = chữ số cuối của num1
    lea rdi, [r13-1]               ; rdi = chữ số cuối của num2
    xor r10, r10                   ; r10 = nhớ = 0
    xor rcx, rcx                   ; rcx = kq

;loop

.add:
    xor rax, rax                   ; rax = 0
    add rax, r10d                  ; cộng nhớ từ loop trước
    xor r10, r10                   ; xóa nhớ cũ

    cmp rsi, 0                     ; còn num1 không?
    jl .n1                         ; nếu hết bỏ qua
    movzx rdx, byte [num1+rsi]     ; lấy ký tự ASCII
    sub rdx, '0'                   ; chuyển chữ qua số
    add rax, rdx                   ; cộng vào tổng
    dec rsi                        ; lùi sang chữ số tiếp theo

.n1:
    cmp rdi, 0                   
    jl .calc                       ; nếu hết sang calc
    movzx rdx, byte [num2+rdi]     
    sub edx, '0'                  
    add eax, edx                  
    dec rdi                      

.calc:
    xor rdx, rdx                   ; chuẩn bị chia
    mov rbx, 10                    ; chia cho 10
    div rbx                        ; rax = thương, rdx = dư

    mov r10, rax                   ; lưu nhớ cho vòng sau
    add dl, '0'                  
    push rdx                       ; đẩy vào stack
    inc rcx                        ; tăng

    cmp rsi, 0                     ; so sánh num1 
    jge .add                       ; jump if greater
    cmp rdi, 0                     ; so sánh num2
    jge .add
    test r10, r10                  ; ktra còn nhớ k
    jnz .add

;pop

    mov rbx, buf                   ; rbx = đầu buffer kết quả
    mov r14, rcx                   ; r14 = độ dài kết quả

.pop:

    pop rax                        ; lấy chữ số đúng thứ tự
    mov [rbx], al                  ; ghi vào buffer
    inc rbx                        ; sang ô tiếp theo
    loop .pop                      ; lặp rcx lần

;in kq
    mov rax, 1                     ; write
    mov rdi, 1                     ; stdout
    mov rsi, msgkq                 ; "Tong la:"
    mov rdx, lenkq
    syscall

    mov rax, 1                     ; write
    mov rdi, 1
    mov rsi, buf                   ; kết quả
    mov rdx, r14                   ; độ dài 
    syscall

;thoát
    mov rax, 60                    ; syscall exit
    xor rdi, edi                   ; exit code = 0
    syscall
```
chạy thử
<img width="494" height="72" alt="image" src="https://github.com/user-attachments/assets/dbe7ac41-195c-43c7-907d-ced9260005d3" />





