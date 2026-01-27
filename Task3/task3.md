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

mình có thể thấy `libc_start_main` và hai cái `.init_array`, `.finit_array`

<img width="741" height="635" alt="image" src="https://github.com/user-attachments/assets/595a2afc-8c49-4d8e-a9a3-14efd80920d1" />

Để tìm hiểu thêm sâu hơn về init và finit các bạn có thể tham khảo link [này](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html) 
Nhưng tóm gọn lại thì                                                                                                                                              
init là constructor, nó được gọi trước khi main() bắt đầu và được gọi bởi `libc_start_main`                                                                        
finit là destructor, nó gọi sau main() và được thực hiện cùng lúc với exit, nó để dọn dẹp constructor                                                              

<img width="1919" height="313" alt="image" src="https://github.com/user-attachments/assets/400b75d9-e5dd-4c52-aef1-6904d2a054e5" />

vào `sub_40155A`    
chương trình call rất nhiều functions và mỗi functions nó như vậy.

<img width="821" height="620" alt="image" src="https://github.com/user-attachments/assets/8ce231c2-5c14-407a-872e-98eb2d16609f" />

và vì em không biết deobfus kiểu gì nên lướt từng function

Bắt đầu từ hàm sú đầu tiên em tìm được `sub_4013DC`

```c
void __noreturn lenght()
{
  int v0; // r13d
  int i; // r12d

  v0 = 0;
  for ( i = 0; i <= 251 && buf[i]; ++i )
    ++v0;
  if ( v0 != 64 )
    exit(-1);
  encrypt(buf);
}
```
hàm này để check lens và call sub_4022B1(encrypt)

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




còn upd thêm...

    














