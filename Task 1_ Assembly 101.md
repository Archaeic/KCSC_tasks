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

## Code chương trình asm

```
Task: Chương trình asm: cộng 2 số tự nhiên lớn (tràn thanh ghi, số hạng trong đoạn [0, 2^64 - 1] với 32 bit, [0, 2^128 - 1] với 64 bit)
- Cho phép nhập 2 số (Thêm msg ví dụ: "Nhập số thứ nhất: ")
- Tính cộng
- In kết quả
```
Bài này mình sẽ dùng cờ CF, cờ này được sử dụng để lưu trữ trạng thái dư ra của phép tính toán, nếu kết quả của phép tính toán vượt quá kích thước của thanh ghi thì bit CF sẽ được thiết lập thành 1.

Bản chất của tràn số 
vd: max là 10 thì mỗi thanh ghi max nó là 10, lo= 10, khi mà add thêm 1 vào thì lo= 0 (vì đã max rồi), và chuyển sang thanh ghi thứ hai hi= 1

IDE em sử dụng là MASM32 ([tutorial](https://www.youtube.com/watch?v=uJgkKhQa4kM))

```
include \masm32\include\masm32rt.inc


.data
m   dd 0 ;khai báo biến giống như kiểu 'int m' trong c
n   dd 0 
lo  dd 0
hi  dd 0

.code
start: ;bắt đầu ct
    invoke AllocConsole ;tạo console để nhìn
    
    ;nhập
    mov m, sval(input("nhap so thu nhat = ")) ;input("...") nhập số vào, còn sval là chuyển số đó sang 32 bit, rồi mov m để lưu nó vào m
    mov n, sval(input("nhap so thu hai = ")) 

    ;cộng
    mov eax, m ;đưa m vào eax
    add eax, n ;cộng n vào eax, tức eax = m + n 
    mov lo, eax ;lưu eax = m + n vào lo

    mov edx, 0
    adc edx, 0        ; adc thì giống lệnh add nhưng có thêm carry flag, tức edx = edx + 0 + CF
    mov hi, edx       ; lưu hi

    ;in kết quả
    print chr$("hi = ") ;in ra 'hi='
    print str$(hi) ;in ra hi
    print chr$(13,10) ;xuống dòng
    print chr$("lo = ")
    print str$(lo)
    print chr$(13,10)
    inkey ;cho nhập số
    
    exit ;thóat ct
    
end start ;kết thúc ct     
```
