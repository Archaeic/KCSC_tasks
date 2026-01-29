# Task 3

`Viết WU 3 bài và giải CTF của knightCTF và MtaCTF`

## Bài chính
### 1. F81E37E841D0B2C1D5738A7D60FD98BE

[file](Task3/F81E37E841D0B2C1D5738A7D60FD98BE)

#### Main
``` c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int i; // esi
  int j; // edi
  _BYTE *v5; // esi
  int v6; // ecx
  _BYTE v8[24]; // [esp+0h] [ebp-28h] BYREF
  __int16 v9; // [esp+18h] [ebp-10h]
  _BYTE v10[8]; // [esp+1Ch] [ebp-Ch] BYREF

  qmemcpy(v8, "bdnpQai|nufimnug`n{Fafhr", sizeof(v8));
  v9 = 1111;
  sub_401020("Guest your flag. The flag will be of the form flag{[a-zA-Z0-9]+}\n");
  sub_401020("Enter your key:");
  for ( i = 0; i < 5; ++i )
    sub_401050("%hhd", &v10[i]);
  for ( j = 0; j < 26; j += 2 )
  {
    v5 = &v8[j];
    *v5 ^= v10[j % 5u];
    v6 = j;
    v5[1] ^= v10[v6 - 5 * ((unsigned int)&v5[1 - (_DWORD)v8] / 5) + 1];
  }
  sub_401020("flag is : %s\n");
  return 0;
}
```

Đoạn này là đoạn chính của cả chương trình 
``` c
    v5 = &v8[j];
    *v5 ^= v10[j % 5u];
    v6 = j;
    v5[1] ^= v10[v6 - 5 * ((unsigned int)&v5[1 - (_DWORD)v8] / 5) + 1];
```
từ đoạn code ta có: 
`v5 = v8[j]`                                                                                                                                                        
`v8[j] ^= v10[j % 5]`                                                                                                                                        
`v6 =j`
vậy  `v8[j+1] ^= (j + 1) - 5 * ((j + 1) / 5)` => `v8[j+1] ^= v10[(j + 1) % 5]`                                                                                      
nói chung là đoạn code đánh lừa mình chỗ này thôi `v5[1] ^= v10[v6 - 5 * ((unsigned int)&v5[1 - (_DWORD)v8] / 5) + 1];`                                             
v8 = bdnpQai|nufimnug`n{Fafhr
v10 = key (flag{[a-zA-Z0-9]+})
rồi mình xor 5 ký tự đầu với nhau thôi
```py
enc   = b"bdnpQ"
plain = b"flag{"
key = [enc[i] ^ plain[i]
for i in range(5)]
print(key)
```

<img width="199" height="41" alt="image" src="https://github.com/user-attachments/assets/5d29f696-b198-43ac-a1ac-2169ca87ad36" />                                             
<img width="794" height="79" alt="image" src="https://github.com/user-attachments/assets/024156d2-2cbd-4e93-8b34-181bd489217e" />


### 2. ezjunk



Đầu tiên thì bài này rất là so với em, nó không cho decomplie, giấu flag rất kĩ, có thêm cả antidebugger. Nhưng theo cái tên "junk" nghĩa là rác vậy nên nó sẽ có điều gì đó liên quan tới code thừa, nặng làm IDA không thể phân biệt và chạy được. 
VD: 

<img width="504" height="250" alt="image" src="https://github.com/user-attachments/assets/7132d504-2aed-4a0f-8b59-f1cb3fbd4d65" />

vậy mục đầu tiên chúng ta phải patch chương trình.

<img width="1081" height="647" alt="image" src="https://github.com/user-attachments/assets/29af0b23-59b6-44b2-8fc7-3653097c863d" />

Đầu tiên, mình sẽ vào `sub_401CC0` trước để xem thử function đó là thật hay không.

<img width="435" height="258" alt="image" src="https://github.com/user-attachments/assets/e205f7f1-570c-423b-9f5c-6e6bdb52fac9" />

function là thật nhưng mà nó có return thêm một function nữa nên mình sẽ tiếp tục trace theo cái function đó.

<img width="550" height="369" alt="image" src="https://github.com/user-attachments/assets/74471042-c353-470f-a9b2-b85afcc5f650" />

và mình nhận thấy cái function `sub_401C50` gọi `sub_401510` 

<img width="512" height="99" alt="image" src="https://github.com/user-attachments/assets/47cda9c4-070f-4466-8778-63a540a3a90d" />

thì mình thấy một lệnh lạ đó là onexit(), nó làm gì? Đơn giản là nó đăng kí 1 hàm mà sau khi chương trình sắp kết thúc thì nó gọi lại rồi mới kết thúc. Vậy vấn đề đang nằm ở `sub_401C50`.

<img width="705" height="216" alt="image" src="https://github.com/user-attachments/assets/1c3673ee-3108-4214-a5e6-7087cccd24be" />

Vậy chúng ta có thể thấy được có hai function sẽ được thực thi nữa đó là `sub_401550` và `sub_4016BC` khi vào cả hai func đó thì mình decompile không được, nên nó khá giống  `main` của mình. Vậy mình sẽ bắt đầu patch  `main` trước

Nhưng mà patch ở đâu? Patch ở những chỗ không có nghĩa, gọi lung tung khiến IDA bị rối.
Vậy mình sẽ patch ở sau `call sub_401CC0` (vì nó là function thật) dùng lệnh của IDApy:
```py
import ida_bytes

start = 0x401A12
end   = 0x401A3D

for ea in range(start, end + 1):
    ida_bytes.patch_byte(ea, 0x90)
```
tại sao lại `end = 0x401A3D` ? rõ là nó chỉ đến `0x401A26` thôi mà? khi mình patch đến thì nó lại sinh ra nhiều lệnh giả hơn nữa. Và mình có chú ý là nó cứ call đến cái pointer không tồn tại khi mình jump tới nó. Và mình cũng đã lưu ý một điều nữa là patch thì phải patch luôn cùng một lúc nếu không chương trình sẽ bị lỗi (

<img width="826" height="264" alt="image" src="https://github.com/user-attachments/assets/6dfbdd3a-06ef-433c-b849-d7267a04b59d" />

nếu chúng ta patch tới `0x401A3D` decompiler sẽ xuất hiện:
```c 
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char Str[32]; // [rsp+20h] [rbp-60h] BYREF
  char v5; // [rsp+40h] [rbp-40h] BYREF
  _BYTE v6[25]; // [rsp+41h] [rbp-3Fh] BYREF
  unsigned int *v7; // [rsp+60h] [rbp-20h]
  unsigned int *v8; // [rsp+68h] [rbp-18h]
  int k; // [rsp+74h] [rbp-Ch]
  int j; // [rsp+78h] [rbp-8h]
  int i; // [rsp+7Ch] [rbp-4h]

  sub_401CC0(argc, argv, envp);
  v5 = 4;
  qmemcpy(v6, "85p6<17p6?\"=1$p9#p4c3$6+-", sizeof(v6));
  qmemcpy(Str, " <51#5p9> %$p)?%\"p6<17jZ", 24);
  for ( i = 0; i < strlen(Str); ++i )
    putchar(Str[i] ^ 0x50);
  gets(&unk_408040);
  for ( j = 0; j <= 7; j += 2 )
    sub_401917(
      (char *)&unk_408040 + 4 * j,
      *v7,
      *v8,
      (char *)off_404350 + 400,
      *(_QWORD *)Str,
      *(_QWORD *)&Str[8],
      *(_QWORD *)&Str[16]);
  if ( (unsigned int)sub_401663(&unk_404360, &unk_408040) )
    exit(0);
  for ( k = 0; k < strlen(&v5); ++k )
    putchar(v6[k - 1] ^ 0x50);
  return 0;
}
```
trước khi phân tích main thì mình thấy còn vài func đặc biệt mà nó không cho decompile (sus) nên mình đã patch nó hết 

ở `sub_4016BC` khi mở graph lên thì mình thấy nó phần này nó không có sự kết nối nào hết.. nên mình đã patch nó..

<img width="902" height="617" alt="image" src="https://github.com/user-attachments/assets/271d2715-11c8-469c-b775-073988d8fff1" />

```py 
import ida_bytes

start = 0x4016BC
end   = 0x401785

for ea in range(start, end + 1):
    ida_bytes.patch_byte(ea, 0x90)
```
```c 
size_t sub_4016BC()
{
  unsigned int v0; // ecx
  size_t result; // rax
  _DWORD v2[8]; // [rsp+20h] [rbp-60h]
  char Str[36]; // [rsp+40h] [rbp-40h] BYREF
  int k; // [rsp+64h] [rbp-1Ch]
  int j; // [rsp+68h] [rbp-18h]
  int i; // [rsp+6Ch] [rbp-14h]

  v1[0] = 0xB6DDB3A9;
  v1[1] = 0x36162C23;
  v1[2] = 0x1889FABF;
  v1[3] = 0x6CE4E73B;
  v1[4] = 0xA5AF8FC;
  v1[5] = 0x21FF8415;
  v1[6] = 0x44859557;
  v1[7] = 0x2DC227B7;
  for ( i = 0; i <= 7; ++i )
  {
    for ( j = 0; j <= 31; ++j )
    {
      if ( dword_408040[i] < 0 )
      {
        dword_408040[i] *= 2;
        v0 = dword_408040[i] ^ 0x84A6972F;
      }
      else
      {
        v0 = 2 * dword_408040[i];
      }
      dword_408040[i] = v0;
    }
    if ( v2[i] != dword_408040[i] )
      exit(0);
  }
  for ( k = 0; ; ++k )
  {
    result = strlen(Str);
    if ( k >= result )
      break;
    putchar(Str[k] ^ 0x50);
  }
  return result;
}
```
cũng hên là mình trúng:p
`sub_401550`

<img width="663" height="86" alt="image" src="https://github.com/user-attachments/assets/da7cd8ec-95ab-4e65-8746-d1dcae482ff4" />

nó cũng như hàm main, nên mình đã patch nó. Ở đoạn này mình bấm "U" thay vì dùng IDApy vì [cái này](https://hex-rays.com/blog/igors-tip-of-the-week-147-fixing-stack-frame-is-too-big) 
```c
char *sub_401550()
{
  char *result; // rax
  CHAR LibFileName[8]; // [rsp+20h] [rbp-10h] BYREF
  _DWORD v2[2]; // [rsp+28h] [rbp-8h] BYREF

  LibFileName[0] = 126;
  LibFileName[1] = 127;
  LibFileName[2] = 20;
  LibFileName[3] = 14;
  LibFileName[4] = 99;
  LibFileName[5] = 19;
  LibFileName[6] = 4;
  LibFileName[7] = 22;
  strcpy((char *)v2, "~4<<");
  BYTE1(v2[1]) = 0;
  HIWORD(v2[1]) = 0;
  while ( v2[1] <= 11 )
    LibFileName[v2[1]++] ^= 0x50u;
  LoadLibraryA(LibFileName);
  if ( IsDebuggerPresent() )
  {
    *((_DWORD *)off_404350 + 100) ^= 0x44u;
    result = (char *)off_404350 + 412;
    *((_DWORD *)off_404350 + 103) ^= 0x33u;
  }
  else
  {
    *((_DWORD *)off_404350 + 101) ^= 0x44u;
    result = (char *)off_404350 + 408;
    *((_DWORD *)off_404350 + 102) ^= 0x33u;
  }
  return result;
}
```
Tóm tắt lại cách chạy của chương trình:
1. Main
- String bị XOR với 0x50
- Biến đổi input bằng `sub_401917`
- `sub_401663` để check
2. sub_4016BC
- chạy 32 vòng dịch LFSR, dịch trái 1 bit, nếu bit cao nhất = 1 thì xor với 0x84A6972F
3. sub_401550
- Nếu có debugger thì nó chạy sang key sai

Giờ mình vào `sub_401917`
```c
_DWORD *__fastcall sub_401917(unsigned int *a1, unsigned int sum, int delta, __int64 key)
{
  _DWORD *result; // rax
  int i; // [rsp+4h] [rbp-Ch]
  unsigned int v6; // [rsp+8h] [rbp-8h]
  unsigned int v7; // [rsp+Ch] [rbp-4h]

  v7 = *a1;
  v6 = a1[1];
  for ( i = 0; i <= 31; ++i )
  {
    v7 += (v6 + ((16 * v6) ^ (v6 >> 5))) ^ (*(_DWORD *)(4LL * (sum & 3) + key) + sum) ^ 0x44;
    v6 += (v7 + ((32 * v7) ^ (v7 >> 6))) ^ (*(_DWORD *)(4LL * ((sum >> 11) & 3) + key) + sum) ^ 0x33;
    sum -= delta;
  }
  *a1 = v7;
  result = a1 + 1;
  a1[1] = v6;
  return result;
}
```
đây là thuật toán [XTEA](https://en.wikipedia.org/wiki/XTEA) 
vậy giờ mình sẽ debug để tìm key, sum và delta, và muốn tìm key thì phải nop anti-debugger

<img width="1078" height="392" alt="image" src="https://github.com/user-attachments/assets/0d82b3a7-25a4-4e5f-b9ae-ac88164b5d04" />

chỉ cần đổi JZ thành JNZ để nhảy sang nhánh đúng, và đây là key

<img width="432" height="275" alt="image" src="https://github.com/user-attachments/assets/e57a4fcd-35d6-49c5-93cc-d4ab9522559e" />

chạy tới xtea thì đây là sum và delta

<img width="436" height="104" alt="image" src="https://github.com/user-attachments/assets/4f375a8f-4903-4a62-9754-ab35c33da577" />
<img width="310" height="97" alt="image" src="https://github.com/user-attachments/assets/f482d99d-685c-42cd-81d6-59c32075cd1d" />

và đây là code solve: 
```py
flag = [0xB6DDB3A9, 0x36162C23, 0x1889FABF, 0x6CE4E73B, 0xA5AF8FC, 0x21FF8415, 0x44859557, 0x2DC227B7]

sum = 0xE8017300
delta = 0xFF58F981
key = [0x5454, 0x4602, 0x4477, 0x5E5E]

for i in range(8):
    for _ in range(32):
        v0 = flag[i]
        if ((v0 & 1) == 1):
            v0 ^= 0x84A6972F
            v0 = v0 >> 1
            v0 |= 0x80000000
        else:
            v0 = v0 >> 1
        flag[i] = v0
for i in range(0, 7, 2):
    v6 = flag[i+1]
    v7 = flag[i]
    for _ in range(32):
        sum = sum + 0x100000000 - delta
        sum &= 0xFFFFFFFF
    for _ in range(32):
        sum += delta
        sum &= 0xFFFFFFFF
        v6 = v6 + 0x100000000 - (((v7 + ((v7 << 5) ^ (v7 >> 6))) ^ (key[(sum>>11)&3]+sum) ^ 0x33) & 0xFFFFFFFF)
        v6 &= 0xFFFFFFFF
        v7 = v7 + 0x100000000 - (((v6 + ((v6 << 4) ^ (v6 >> 5))) ^ (key[sum&3]+sum) ^ 0x44) & 0xFFFFFFFF)
        v7 &= 0xFFFFFFFF
    flag[i+1] = v6
    flag[i] = v7

res = b"".join(x.to_bytes(4, "little") for x in flag)
print(res.decode("ascii"))
```
<img width="333" height="36" alt="image" src="https://github.com/user-attachments/assets/9c3b217b-f72d-46c9-b798-184275e2a590" />

### 3. no-main

Ở bài này chúng ta không có hàm main, thay vào đó là một đống functions. Việc đầu tiên mình làm là tìm string để xem có manh mối gì không

<img width="1532" height="322" alt="image" src="https://github.com/user-attachments/assets/c5aa87f1-b37f-4605-b0c7-7d4ebd68c714" />

đầu tiên, mình có thể thấy `libc_start_main` và hai cái `.init_array`, `.finit_array`

<img width="741" height="635" alt="image" src="https://github.com/user-attachments/assets/595a2afc-8c49-4d8e-a9a3-14efd80920d1" />

Để tìm hiểu thêm sâu hơn về init và finit các bạn có thể tham khảo link [này](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html) 
Nhưng tóm gọn lại thì                                                                                                                                              
init là constructor, nó được gọi trước khi main() bắt đầu và được gọi bởi `libc_start_main`                                                                        
finit là destructor, nó gọi sau main() và được thực hiện cùng lúc với exit, nó để dọn dẹp constructor   

Nhưng ở bài này, chúng ta không có main() và cả `libc_start_main`  của chúng ta bị NOP vậy tức là init và finit không theo trình tự như trên
tiếp theo vào phần `input`

```c
signed __int64 sub_4013DC()
{
  signed __int64 v0; // rax
  int i; // [rsp+1Ch] [rbp-4h]

  v0 = sys_open("./input", 0, (int)"./input");
  if ( (int)v0 < 0 )
    exit(-1);
  for ( i = 0; i <= 255; ++i )
    buf[i] = 0;
  return sys_read(v0, buf, 0xFCu);
}
```
thì hàm này đọc input bằng file input, dùng lệnh này để tạo file input
```
echo -n "CyKor{Sorry_for_the_prank_but_wasn\'t_it_fun?_e071a0b358c7a6c4e4}" > input
```
Rồi sau đó mình debug, mình có thể thấy nó gọi `sub_40258D`, func này input sẽ là tên file (a1) và tên cần tìm (a2) sau đó so sánh với nhau.

Ở đợt call `sub_40258D` thứ nhất

init_array được gọi và nó đang chỉ tới `sub_40155A`

<img width="811" height="278" alt="image" src="https://github.com/user-attachments/assets/5e2911c5-871b-43aa-8782-c6a08ec1e047" />

Chạy qua đợt call `sub_40258D` thứ hai

finit_array được gọi và nó đang chỉ tới `sub_4013DC`, tức là func input của mình

<img width="1255" height="302" alt="image" src="https://github.com/user-attachments/assets/eba1cf09-12c7-46a7-a72b-5e857a6758c8" />

TUY NHIÊN khi xuống call rbx đầu tiên, thì nó lại gọi `sub_4013DC` cho dù nó là finit

<img width="786" height="292" alt="image" src="https://github.com/user-attachments/assets/957b322d-5f9c-4350-a62f-a9cd645d2ce4" />

và ở đợt call rbx thứ 2 nó gọi `sub_40155A`

<img width="882" height="297" alt="image" src="https://github.com/user-attachments/assets/08929746-34e7-4dbc-a2db-50f822502a53" />

vậy init và finit ở đây nó chả liên quan gì hết, nó chỉ đang đánh lừa 😭😭

vậy có thể nói finit ở đây được gọi trước init.

Qua `sub_40155A`, chương trình call rất nhiều functions và mỗi functions nó như vậy.

<img width="821" height="620" alt="image" src="https://github.com/user-attachments/assets/8ce231c2-5c14-407a-872e-98eb2d16609f" />

và vì em không biết deobfus kiểu gì nên lướt từng function

Bắt đầu từ hàm sú đầu tiên em tìm được `sub_4027C7`

hàm này để check lens và truyền buf cho sub_4022B1

<img width="796" height="300" alt="image" src="https://github.com/user-attachments/assets/1f192d9b-fceb-4c69-a0fc-6233f8a5a234" />


`sub_4022B1`
```c
void __fastcall __noreturn encrypt(_QWORD *a1)
{
  __int64 v1; // [rsp+10h] [rbp-60h] BYREF
  __int64 v2; // [rsp+18h] [rbp-58h]
  __int64 v3; // [rsp+20h] [rbp-50h]
  __int64 v4; // [rsp+28h] [rbp-48h]
  __int64 v5; // [rsp+30h] [rbp-40h]
  __int64 v6; // [rsp+38h] [rbp-38h]
  __int64 v7; // [rsp+40h] [rbp-30h]
  __int64 v8; // [rsp+48h] [rbp-28h]
  __int64 v9; // [rsp+50h] [rbp-20h]
  __int64 v10; // [rsp+58h] [rbp-18h]
  _QWORD *v11; // [rsp+68h] [rbp-8h]

  v11 = a1;
  v1 = 0;
  v2 = 0;
  v3 = 0;
  v4 = 0;
  v5 = 0;
  v6 = 0;
  v7 = 0;
  v8 = 0;
  v9 = 0;
  v10 = 0;
  v1 = a1[1] + *a1 + a1[2];
  v2 = a1[4] + a1[3] + a1[5];
  v3 = (a1[7] + a1[6]) ^ *a1;
  v4 = a1[2] ^ a1[1] ^ a1[3];
  v5 = a1[5] ^ a1[4] ^ a1[6];
  v6 = a1[7] - *a1 - a1[1];
  v7 = (a1[4] + a1[5]) ^ (a1[2] + a1[3]) ^ a1[1] ^ a1[6];
  v8 = a1[5] - a1[2] + a1[3];
  v9 = a1[1] - a1[3] + a1[5] + a1[7];
  v10 = a1[6] ^ a1[5] ^ (a1[7] + *a1);
  validator(&v1);
}
```
hàm này encrypt rồi call `sub_402128`(validator)                                                                                                                            
`sub_402128`
```c
void __fastcall __noreturn validator(_QWORD *a1)
{
  if ( *a1 != 0x3D275D492E2A5429LL )
    exit(-1);
  if ( a1[1] != 0xF81C2E3328F84344LL )
    exit(-1);
  if ( a1[2] != 0x8F3FE115AA2DBB2BLL )
    exit(-1);
  if ( a1[3] != 0x50644262757E456DLL )
    exit(-1);
  if ( a1[4] != 0xB7C393329797A24LL )
    exit(-1);
  if ( a1[5] != 0xAE6E7A5B94717582LL )
    exit(-1);
  if ( a1[6] != 0x6536450F5A1B3745LL )
    exit(-1);
  if ( a1[7] != 0x2A465263556B6C5DLL )
    exit(-1);
  if ( a1[8] != 0xB25FDA858CBBE9A4LL )
    exit(-1);
  if ( a1[9] != 0xB88FB0CA8FDFCE2DLL )
    exit(-1);
  exit(0);
}
```
dùng z3 

```py 
from z3 import *

target = [
    0x3D275D492E2A5429,
    0xF81C2E3328F84344,
    0x8F3FE115AA2DBB2B,
    0x50644262757E456D,
    0x0B7C393329797A24,
    0xAE6E7A5B94717582,
    0x6536450F5A1B3745,
    0x2A465263556B6C5D,
    0xB25FDA858CBBE9A4,
    0xB88FB0CA8FDFCE2D,
]

a = [BitVec(f'a{i}', 64) for i in range(8)]
s = Solver()

s.add(a[1] + a[0] + a[2] == target[0])
s.add(a[4] + a[3] + a[5] == target[1])
s.add((a[7] + a[6]) ^ a[0] == target[2])
s.add(a[2] ^ a[1] ^ a[3] == target[3])
s.add(a[5] ^ a[4] ^ a[6] == target[4])
s.add(a[7] - a[0] - a[1] == target[5])
s.add((a[4] + a[5]) ^ (a[2] + a[3]) ^ a[1] ^ a[6] == target[6])
s.add(a[5] - a[2] + a[3] == target[7])
s.add(a[1] - a[3] + a[5] + a[7] == target[8])
s.add(a[6] ^ a[5] ^ (a[7] + a[0]) == target[9])

for i in range(8):
    for j in range(8):
        b = Extract(j*8 + 7, j*8, a[i])
        s.add(b >= 0x20, b <= 0x7E)

assert s.check() == sat
m = s.model()

flag = b''
for i in range(8):
    q = m[a[i]].as_long()
    flag += q.to_bytes(8, 'little')

print(flag.decode())
```
output:

<img width="647" height="30" alt="image" src="https://github.com/user-attachments/assets/e2d4be76-6396-4a6e-acf6-e87c1ea03b5f" />


## Bài phụ

### 1. easy_peasy (kctf)

#### Main
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  size_t v3; // rax
  char *v4; // rax
  size_t v5; // rax
  size_t v6; // rax
  int v7; // r12d
  size_t v8; // rax
  char *v10; // rdi
  __int64 v11; // rcx
  __int64 v12; // r14
  size_t v13; // rax
  char *v14; // rdi
  __int64 i; // rcx
  __int64 v16; // r13
  size_t v17; // rax
  char *v18; // [rsp+0h] [rbp-358h]
  __int64 v19; // [rsp+0h] [rbp-358h]
  char s1[48]; // [rsp+20h] [rbp-338h] BYREF
  char v21[64]; // [rsp+50h] [rbp-308h] BYREF
  char v22[128]; // [rsp+90h] [rbp-2C8h] BYREF
  char s[5]; // [rsp+110h] [rbp-248h] BYREF
  _BYTE v24[5]; // [rsp+115h] [rbp-243h] BYREF
  _BYTE v25[246]; // [rsp+11Ah] [rbp-23Eh] BYREF
  char v26; // [rsp+210h] [rbp-148h] BYREF
  unsigned __int64 v27; // [rsp+318h] [rbp-40h]

  v27 = __readfsqword(0x28u);
  puts("========================================");
  puts("   E4sy P3asy - KnightCTF 2026");
  puts("========================================");
  puts("[*] Enter the flag to prove your worth!");
  puts("");
  printf("flag> ");
  if ( fgets(s, 256, stdin) )
  {
    v3 = strlen(s);
    if ( v3 )
    {
      v4 = &v22[v3 + 127];
      do
      {
        if ( *v4 != 10 && *v4 != 13 )
          break;
        *v4-- = 0;
      }
      while ( &v4[1LL - (_QWORD)s] );
    }
    v5 = strlen(s);
    sub_1660(s, v5, &v26);
    if ( (unsigned int)sub_1760(s, "GoogleCTF{") )
    {
      if ( (unsigned int)sub_17A0(s) )
      {
        v6 = strlen(s);
        if ( v6 - 11 <= 0xFF )
        {
          qmemcpy(&v26, v25, v6 - 11);
          v10 = v21;
          v25[v6 + 235] = 0;
          v11 = 16;
          v18 = v21;
          while ( v11 )
          {
            *(_DWORD *)v10 = 0;
            v10 += 4;
            --v11;
          }
          strcpy(v21, "G00gleCTF_s@lt_2026");
          if ( v6 == 24 )
          {
            v12 = 0;
            while ( 1 )
            {
              snprintf(v22, 0x80u, "%s%zu%c", v18, v12, (unsigned int)*(&v26 + v12), v18);
              v13 = strlen(v22);
              sub_1660(v22, v13, s1);
              if ( strcmp(s1, off_3D60[v12]) )
                break;
              if ( ++v12 == 13 )
              {
                puts("[!] Interesting... but that's a decoy flag from a different universe.");
                puts("[!] You're in KnightCTF, not GoogleCTF :)");
                puts("Try again!");
                return 0;
              }
            }
          }
        }
      }
    }
    if ( (unsigned int)sub_1760(s, (char *)"CTF{") || (v7 = sub_1760(s, "FLAG{")) != 0 )
    {
      puts("[?] Format looks suspicious... but not quite.");
      puts("Try again!");
    }
    else
    {
      if ( (unsigned int)sub_1760(s, "KCTF{") )
      {
        if ( (unsigned int)sub_17A0(s) )
        {
          v8 = strlen(s);
          if ( v8 - 6 <= 0xFF )
          {
            qmemcpy(&v26, v24, v8 - 6);
            v14 = v21;
            v25[v8 + 240] = 0;
            for ( i = 16; i; --i )
            {
              *(_DWORD *)v14 = v7;
              v14 += 4;
            }
            qmemcpy(v21, "KnightCTF_2026_s@lt", 19);
            if ( v8 == 29 )
            {
              v16 = 0;
              snprintf(v22, 0x80u, "%s%zu%c", v21, 0, (unsigned int)v26);
              while ( 1 )
              {
                v17 = strlen(v22);
                sub_1660(v22, v17, s1);
                if ( strcmp(s1, off_3CA0[v16]) )
                  break;
                if ( ++v16 == 23 )
                {
                  puts("Good job! You got it!");
                  return 0;
                }
                snprintf(v22, 0x80u, "%s%zu%c", v19, v16, (unsigned int)*(&v26 + v16), v19);
              }
            }
          }
        }
      }
      puts("Try again!");
    }
  }
  return 0;
}
```
Có thể thấy được bài này có nhiều fake flag nhưng mình chỉ cần quan tâm ở đoạn này.

```c
      if ( (unsigned int)sub_1760(s, "KCTF{") )
      {
        if ( (unsigned int)sub_17A0(s) )
        {
          v8 = strlen(s);
          if ( v8 - 6 <= 0xFF )
          {
            qmemcpy(&v26, v24, v8 - 6);
            v14 = v21;
            v25[v8 + 240] = 0;
            for ( i = 16; i; --i )
            {
              *(_DWORD *)v14 = v7;
              v14 += 4;
            }
            qmemcpy(v21, "KnightCTF_2026_s@lt", 19);
            if ( v8 == 29 )
            {
              v16 = 0;
              snprintf(v22, 0x80u, "%s%zu%c", v21, 0, (unsigned int)v26);
              while ( 1 )
              {
                v17 = strlen(v22);
                sub_1660(v22, v17, s1);
                if ( strcmp(s1, off_3CA0[v16]) )
                  break;
                if ( ++v16 == 23 )
                {
                  puts("Good job! You got it!");
                  return 0;
                }
                snprintf(v22, 0x80u, "%s%zu%c", v19, v16, (unsigned int)*(&v26 + v16), v19);
```


<img width="237" height="64" alt="image" src="https://github.com/user-attachments/assets/af747266-bdc1-4b5b-b1af-1bc4cf3504b4" />

đoạn này là check len, biết len == 29 mà vì v8 -6 nên flag sẽ lag KCTF{23 bytes}

nhưng khi mình vào off_3CA0 thì mình thấy md5 nên mình sẽ brute force;p

<img width="729" height="507" alt="image" src="https://github.com/user-attachments/assets/344442f4-832a-4079-9f7f-0495a42d3199" />


```py 
import hashlib

targets = [
    "781011edfb2127ee5ff82b06bb1d2959",
    "4cf891e0ddadbcaae8e8c2dc8bb15ea0",
    "d06d0cbe140d0a1de7410b0b888f22b4",
    "d44c9a9b9f9d1c28d0904d6a2ee3e109",
    "e20ab37bee9d2a1f9ca3d914b0e98f09",
    "d0beea4ce1c12190db64d10a82b96ef8",
    "ac87da74d381d253820bcf4e5f19fcea",
    "ce3f3a34a04ba5e5142f5db272b6cb1f",
    "13843aca227ef709694bbfe4e5a32203",
    "ca19a4c4eb435cb44d74c1e589e51a10",
    "19edec8e46bdf97e3018569c0a60baa3",
    "972e078458ce3cb6e32f795ff4972718",
    "071824f6039981e9c57725453e005beb",
    "66cd6098426b0e69e30e7fa360310728",
    "f78d152df5d277d0ab7d25fb7d1841f3",
    "dba3a36431c4aaf593566f7421abaa22",
    "8820bbdad85ebee06632c379231cfb6b",
    "722bc7cde7d548b81c5996519e1b0f0f",
    "c2862c390c830eb3c740ade576d64773",
    "94da978fe383b341f9588f9bab246774",
    "bea3bb724dbd1704cf45aea8e73c01e1",
    "ade2289739760fa27fd4f7d4ffbc722d",
    "3cd0538114fe416b32cdd814e2ee57b3"
]

salt = b"KnightCTF_2026_s@lt"
payload = []

for i, target in enumerate(targets):
    for b in range(256):
        data = salt + str(i).encode() + bytes([b])
        if hashlib.md5(data).hexdigest() == target:
            payload.append(chr(b))
            break

flag = "KCTF{" + "".join(payload) + "}"
print(flag)
```
<img width="308" height="39" alt="image" src="https://github.com/user-attachments/assets/6f05d8be-aad8-48ba-bbcc-3432763c95c7" />

<img width="485" height="160" alt="image" src="https://github.com/user-attachments/assets/12944dc0-a2f5-49c7-b94e-6d048bc2a883" />

### 2. rem3

#### main 
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  size_t v3; // rax
  _BYTE v5[58]; // [rsp+0h] [rbp-158h] BYREF
  char s[16]; // [rsp+40h] [rbp-118h] BYREF
  unsigned __int64 v7; // [rsp+148h] [rbp-10h]

  v7 = __readfsqword(0x28u);
  puts("=== KCTF Reverse Challenge ===");
  printf("Enter flag: ");
  if ( fgets(s, 256, stdin) )
  {
    v3 = strcspn(s, "\r\n");
    s[v3] = 0;
    if ( v3 != 29 )
      goto LABEL_7;
    sub_1380();
    if ( !memcmp(s, "KCTF{str1ngs_lie_dont_trust!}", 0x1Du) )
    {
      puts("Congrats — you got a flag! But... not sure you'll get points for it :)");
      puts("KCTF{str1ngs_lie_dont_trust!}");
      return 0;
    }
    if ( sub_1470(s) == 0xE76FA3DABA5D6F3ALL )
    {
      puts("Congrats — you got a flag! But... not sure you'll get points for it :)");
      puts("KCTF{hash_passes_but_fake!!!}");
      return 0;
    }
    *(__m128i *)v5 = _mm_load_si128((const __m128i *)s);
    *(__m128i *)&v5[13] = _mm_loadu_si128((const __m128i *)&s[13]);
    ((void (__fastcall *)(_BYTE *))sub_14C0)(v5);
    if ( (unsigned int)sub_1400(v5, &unk_2160, &unk_2150, &unk_2140) )
    {
      puts("Success! Real flag accepted.");
      return 0;
    }
    if ( (unsigned int)sub_1400(v5, &unk_2130, &unk_2120, &unk_2110) )
    {
      puts("Congrats — you got a flag! But... not sure you'll get points for it :)");
      puts("KCTF{fake_flag_for_reversers}");
    }
    else
    {
LABEL_7:
      puts("Failed!");
    }
    return 0;
  }
  return 1;
}
```
lại fake flags nhưng đây là chộ mình cần phân tích
```c
}
    *(__m128i *)v5 = _mm_load_si128((const __m128i *)s);
    *(__m128i *)&v5[13] = _mm_loadu_si128((const __m128i *)&s[13]);
    ((void (__fastcall *)(_BYTE *))sub_14C0)(v5);
    if ( (unsigned int)sub_1400(v5, &unk_2160, &unk_2150, &unk_2140) )
    {
      puts("Success! Real flag accepted.");
      return 0;
```
vào `sub_14C0`
```c
char __fastcall sub_14C0(__int64 a1)
{
  int v2; // r8d
  int v3; // edi
  int v4; // esi
  __int64 i; // rdx
  int v6; // eax
  int v7; // ecx
  int v8; // eax

  v2 = 0;
  v3 = 0;
  v4 = -61;
  for ( i = 0; i != 29; ++i )
  {
    v6 = v3 + (0x2F910ED35CA71942uLL >> (8 * ((unsigned __int8)i & 7u)));
    v3 += 29;
    LOBYTE(v6) = __ROL1__(*(_BYTE *)(a1 + i) ^ v6, 0x6A124DE908B17733uLL >> ((8 * i + 16) & 0x38));
    v7 = v2 ^ (0x6A124DE908B17733uLL >> (8 * ((unsigned __int8)i & 7u)));
    v2 += 17;
    v8 = v7 ^ (v4 + v6);
    LOBYTE(v8) = __ROR1__(v8, v4);
    LOBYTE(v7) = (8 * i + 24) & 0x38;
    *(_BYTE *)(a1 + i) = v8;
    v4 += v8 + ((0x2F910ED35CA71942uLL >> v7) ^ 0xFFFFFFA5);
  }
  return v8;
}
```
đây là ROR và ROL và nó lấy byte từ `unk_2160`, `unk_2150`, `unk_2140`.                                                                                                      
solve
```py
def ROL(x, r):
    r &= 7
    return ((x << r) | (x >> (8 - r))) & 0xFF

def ROR(x, r):
    r &= 7
    return ((x >> r) | (x << (8 - r))) & 0xFF

a1 = list(bytes.fromhex(
    "DC 6B BB 4D FD 25 E4 7E C3 26 "
    "F5 72 AB 96 FC 8D 55 10 93 C1 "
    "FD 81 46 5B 7E 33 83 8F 2F"
))
v2 = 0
v3 = 0
v4 = -61
out = []
for i in range(29):
    v8 = a1[i]
    v8 = ROL(v8, v4)
    rot = (0x6A124DE908B17733 >> ((8 * i + 16) & 0x38)) & 7
    v7 = (v2 ^ (0x6A124DE908B17733 >> (8 * (i & 7)))) & 0xFF
    v2 += 17
    v6 = ((v7 ^ v8) - (v4 & 0xFF)) & 0xFF
    base = (v3 + (0x2F910ED35CA71942 >> (8 * (i & 7)))) & 0xFF
    inp = base ^ ROR(v6, rot)
    out.append(inp)
    v3 += 29
    v7 = (8 * i + 24) & 0x38
    v4 += a1[i] + ((0x2F910ED35CA71942 >> v7) ^ 0xFFFFFFA5)

print(bytes(out).decode())
```

<img width="313" height="37" alt="image" src="https://github.com/user-attachments/assets/ef2e5df3-cbcb-498a-8c0e-a2f2f63ee220" />

<img width="566" height="81" alt="image" src="https://github.com/user-attachments/assets/2f444dd0-26f9-4160-ac6b-82a6efe3db7a" />

### ez-enc

<img width="981" height="511" alt="image" src="https://github.com/user-attachments/assets/737150e1-a229-40ad-b70f-5825d22e2214" />

nó có rất nhiều file nên mình sẽ phân tích từng file, đầu tiên mình xem file số 0 thử

#### main
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 v3; // rax
  __int64 v4; // rcx
  const char *v5; // rcx
  __int64 v7; // [rsp+20h] [rbp-28h] BYREF
  __int16 v8; // [rsp+28h] [rbp-20h]

  v7 = 0;
  v8 = 0;
  printf("password: ");
  sub_140001064("%8s", (const char *)&v7);
  v3 = -1;
  v4 = 0;
  do
    ++v3;
  while ( *((_BYTE *)&v7 + v3) );
  if ( v3 <= 8 )
  {
    do
    {
      *((_BYTE *)&v7 + v4) ^= word_140028A80[v4];
      ++v4;
    }
    while ( v4 < 8 );
    v5 = "Correct\n";
    if ( v7 != qword_140028A88 )
      v5 = "Wrong\n";
    printf(v5, "Wrong\n");
  }
  else
  {
    printf("Wrong\n");
  }
  return 0;
}
```
chương trình nó chỉ đang xor `word_140028A80` với `qword_140028A88` thôi ;v
solve
```py
key = [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]
ex  = [0x47, 0x7c, 0x21, 0x69, 0x74, 0x5c, 0x20, 0x56]

password = []
for i in range(8):
    password.append(ex[i] ^ key[i])

print(bytes(password).decode())
```

<img width="267" height="52" alt="image" src="https://github.com/user-attachments/assets/7f477dfd-1c6d-4bde-82fe-4e9598dfa5f0" />

vậy giờ mình solve tất cả các file vì nó đều giống nhau cả, và đây là thứ mình có được.
```
0 Vm0xeM1G
1 bFdiRmRW
2 V0doVVlt
3 czFWRll3
4 YUVOamJG
5 WnpWbTVr
6 V0ZKc2NI
7 bFhhMXBQ
8 VkcxS1Iy
9 TkZhRmRp
10 V0ZKeVZt
11 cEdZV05y
12 TlZkYVJs
13 Wk9WbXhW
14 ZUZacVJs
15 WmxSMUpJ
16 Vm10V1dH
17 SkhhRlJW
18 YkZKWFZs
19 WmtXR05G
20 WkZSTlZt
21 d3pWREZh
22 WVdKR1Ns
23 VldhemxY
24 WVdzMWNW
25 UldSVGxR
26 VVQwOQ==
```
`Vm0xeM1GbFdiRmRWV0doVVltczFWRll3YUVOamJGWnpWbTVrV0ZKc2NIbFhhMXBQVkcxS1IyTkZhRmRpV0ZKeVZtcEdZV05yTlZkYVJsWk9WbXhWZUZacVJsWmxSMUpJVm10V1dHSkhhRlJWYkZKWFZsWmtXR05GWkZSTlZtd3pWREZhWVdKR1NsVldhemxYWVdzMWNWUldSVGxRVVQwOQ==` 
nó là base64 nhưng mà em giải mã nó, nó cũng không ra flag thật, dù em đã test hết rồi và nó ra correct hết.









