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




