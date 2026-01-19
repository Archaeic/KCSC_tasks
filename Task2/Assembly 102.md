# Task 2

1. Chương trình asm: thuật toán mã hóa RC4                                                                                                                        
Chạy được và phải đúng
Input: Plain Text + Key                                                                                                                                            
Output: Hex                                                                                                                                                        
Giải thích code rõ ràng
  
3. Write up challenge EZsudocu + hidden


## Code 

[RC4](Task2/rc4.asm)

<img width="364" height="94" alt="image" src="https://github.com/user-attachments/assets/866a5ffb-5fdf-466c-86d8-ffe50b85ea8d" />


## Write up

### EZsudoku
chạy thử: 

<img width="326" height="268" alt="image" src="https://github.com/user-attachments/assets/67dfb23b-6ee6-4bff-948e-5a554ce02b3c" />

trước hết có sudoku thì cứ giải thử rồi để đó :)

dùng script có [sẵn](https://www.geeksforgeeks.org/dsa/sudoku-backtracking-7/) 

<img width="197" height="282" alt="image" src="https://github.com/user-attachments/assets/746d2057-e3fd-496e-b79b-212567bff759" />

#### Chương trình : 
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // eax
  unsigned int v5; // esi
  unsigned int v6; // kr00_4
  void **v7; // ecx
  int v8; // edx
  size_t v9; // edi
  void **v10; // esi
  void **v11; // eax
  __int128 v12; // xmm0
  __int64 v13; // xmm1_8
  void *v14; // ecx
  void *v15; // ecx
  void *v16; // ecx
  int v18; // [esp+20h] [ebp-1B4h]
  void *v19[4]; // [esp+28h] [ebp-1ACh] BYREF
  int v20; // [esp+38h] [ebp-19Ch]
  unsigned int v21; // [esp+3Ch] [ebp-198h]
  __int64 v22; // [esp+40h] [ebp-194h]
  void *Src; // [esp+48h] [ebp-18Ch]
  size_t Size; // [esp+4Ch] [ebp-188h]
  void *Block[4]; // [esp+50h] [ebp-184h] BYREF
  size_t v26[2]; // [esp+60h] [ebp-174h]
  _OWORD v27[20]; // [esp+68h] [ebp-16Ch] BYREF
  int v28; // [esp+1A8h] [ebp-2Ch]
  char v29[24]; // [esp+1ACh] [ebp-28h] BYREF
  int v30; // [esp+1D0h] [ebp-4h]

  v28 = 0;
  strcpy(v29, ";e!kazw^e<i6]4o\\l[Wh4d7");
  v27[0] = xmmword_2801E0;
  v27[1] = 0;
  v27[2] = xmmword_280260;
  v27[3] = xmmword_2801C0;
  v27[4] = xmmword_280270;
  v27[5] = xmmword_280250;
  v27[6] = xmmword_280190;
  v27[7] = xmmword_2801B0;
  v27[8] = xmmword_2801D0;
  v27[9] = 0;
  v27[10] = xmmword_280230;
  v27[11] = 0;
  v27[12] = xmmword_280180;
  v27[13] = xmmword_2801A0;
  v27[14] = xmmword_280180;
  v27[15] = xmmword_280240;
  v27[16] = xmmword_280220;
  v27[17] = xmmword_280200;
  v27[18] = xmmword_2801F0;
  v27[19] = xmmword_280210;
  v3 = sub_2540B0(&dword_283F50, "This is your challenge: ");
  sub_254370(v3);
  sub_251D60(v27);
  v4 = sub_2540B0(&dword_283F50, "...and here is your flag: ");
  sub_254370(v4);
  v26[0] = 0;
  v26[1] = 15;
  LOBYTE(Block[0]) = 0;
  sub_252F30(Block, (void *)&::Src, 0);
  v5 = 0;
  v30 = 0;
  HIDWORD(v22) = 0;
  v6 = strlen(v29);
  if ( v6 )
  {
    do
    {
      v20 = 0;
      v21 = 15;
      LOBYTE(v19[0]) = 0;
      sub_252DF0(v19, 1u, v29[v5] ^ *((_BYTE *)v27 + 40 * ((int)v5 % 9)));
      LOBYTE(v30) = 1;
      v7 = Block;
      if ( v26[1] >= 0x10 )
        v7 = (void **)Block[0];
      v8 = v20;
      v9 = v26[0];
      Src = v7;
      if ( v26[0] > v21 - v20 )
      {
        LOBYTE(v18) = 0;
        v11 = (void **)sub_255370(v19, v26[0], v18, (int)v7, (int)v7, v26[0]);
      }
      else
      {
        v10 = v19;
        v20 += v26[0];
        if ( v21 >= 0x10 )
          v10 = (void **)v19[0];
        if ( (void **)((char *)v7 + v26[0]) <= v10 || v7 > (void **)((char *)v10 + v8) )
        {
          Size = v26[0];
        }
        else if ( v10 > v7 )
        {
          Size = (char *)v10 - (char *)v7;
        }
        else
        {
          Size = 0;
        }
        memmove_0((char *)v10 + v26[0], v10, v8 + 1);
        memmove(v10, Src, Size);
        memmove((char *)v10 + Size, (char *)Src + Size + v9, v9 - Size);
        v5 = HIDWORD(v22);
        v11 = v19;
      }
      v12 = *(_OWORD *)v11;
      v13 = *((_QWORD *)v11 + 2);
      v11[4] = 0;
      v11[5] = (void *)15;
      *(_BYTE *)v11 = 0;
      v22 = v13;
      if ( v26[1] >= 0x10 )
      {
        v14 = Block[0];
        if ( v26[1] + 1 >= 0x1000 )
        {
          v14 = (void *)*((_DWORD *)Block[0] - 1);
          if ( (unsigned int)((char *)Block[0] - (char *)v14 - 4) > 0x1F )
            goto LABEL_29;
        }
        sub_257991(v14);
        v13 = v22;
      }
      LOBYTE(v30) = 0;
      *(_QWORD *)v26 = v13;
      *(_OWORD *)Block = v12;
      if ( v21 >= 0x10 )
      {
        v15 = v19[0];
        if ( v21 + 1 >= 0x1000 )
        {
          v15 = (void *)*((_DWORD *)v19[0] - 1);
          if ( (unsigned int)((char *)v19[0] - (char *)v15 - 4) > 0x1F )
            goto LABEL_29;
        }
        sub_257991(v15);
      }
      HIDWORD(v22) = ++v5;
    }
    while ( v5 < v6 );
  }
  sub_2550E0(v26[0]);
  if ( v26[1] >= 0x10 )
  {
    v16 = Block[0];
    if ( v26[1] + 1 >= 0x1000 )
    {
      v16 = (void *)*((_DWORD *)Block[0] - 1);
      if ( (unsigned int)((char *)Block[0] - (char *)v16 - 4) > 0x1F )
LABEL_29:
        _invalid_parameter_noinfo_noreturn();
    }
    sub_257991(v16);
  }
  return 0;
}
```

này nó hardcode vào luôn :d
`strcpy(v29, ";e!kazw^e<i6]4o\\l[Wh4d7");`

đây là dòng tạo flag

`sub_252DF0(v19, 1u, v29[v5] ^ *((_BYTE *)v27 + 40 * ((int)v5 % 9)));`

v29 thực hiện XOR với v27, v27 sẽ là 9 byte của sudoku.  `((int)v5 % 9))` , ở đây `%9` là để loop key 9 lần để XOR tại cái string mã hóa nó dài hơn key 
code giải 
```py
chall = b";e!kazw^e<i6]4o\l[Wh4d7"

key =[8, 4, 5, 2, 4, 9, 3, 1, 2]

out = bytes(chall[i] ^ key[i % 9]
    for i in range(len(chall)))
print(out.decode())
```
mình đã thử hết 9 byte của tất cả các hàng, cột, xong tới đường chéo mới ra được flag 

<img width="259" height="38" alt="image" src="https://github.com/user-attachments/assets/3b7151c3-f081-4b62-bfcf-e355be5c1e06" />

### hidden

#### Chương trình
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned __int64 i; // [rsp+18h] [rbp-58h]
  char *s; // [rsp+20h] [rbp-50h]
  size_t n; // [rsp+28h] [rbp-48h]
  unsigned int *dest; // [rsp+38h] [rbp-38h]
  char v8[24]; // [rsp+40h] [rbp-30h] BYREF
  unsigned __int64 v9; // [rsp+58h] [rbp-18h]

  v9 = __readfsqword(0x28u);
  strcpy(v8, "AlpacaHackRound8");
  if ( a1 > 1 )
  {
    s = a2[1];
    n = strlen(s);
    dest = (unsigned int *)calloc((n + 3) >> 2, 4u);
    memcpy(dest, s, n);
    for ( i = 0; i < (n + 3) >> 2; ++i )
      dest[i] = sub_1272(dest[i], v8);
    if ( !memcmp(dest, &unk_4040, 4 * qword_4020) )
      puts("congratz");
    else
      puts("wrong");
    return 0;
  }
  else
  {
    printf("usage: %s <input>\n", *a2);
    return 0;
  }
}
```

ở đây chương trình thực hiện copy input vào dest, nhưng ở đây nó đang đọc input theo 32-bit và nó gom input mỗi 4 kí tự. Sau đó mã hóa nó ở `dest[i] = sub_1272(dest[i], v8);` 
vào `sub_1272`
```c 
__int64 __fastcall sub_1272(unsigned int a1, _DWORD *a2)
{
  sub_124F((unsigned int)(__ROL4__(*a2, 5) + __ROR4__(a2[1], 3)));
  sub_122C((unsigned int)(__ROR4__(a2[2], 3) - __ROL4__(a2[3], 5)));
  sub_1209(a1);
  *a2 ^= __ROR4__(0, 13);
  a2[1] ^= __ROR4__(0, 15);
  a2[2] ^= __ROL4__(0, 13);
  a2[3] ^= __ROL4__(0, 11);
  return 0;
}
```

nhưng khi chuyển sang view asm thì nó bị thiếu rất nhiều code                                                                                                      
vd: 

<img width="1234" height="257" alt="image" src="https://github.com/user-attachments/assets/e6308e1c-d867-48c5-b6cb-b0cef1d1901c" />

<img width="1231" height="593" alt="image" src="https://github.com/user-attachments/assets/81d1e37d-123a-4e0f-a2c9-94c60f6282f9" />

đây là dạng bài anti decompile vậy thì giờ mình dịch từng đoạn asm bị thiếu ra


cho input là a 

<img width="367" height="58" alt="image" src="https://github.com/user-attachments/assets/bc7f9338-8a56-4f07-8a1f-c4860cd4562d" />

khi nhảy vào `sub_1272` thì ta có thể thấy input được lưu vào `var_14`

<img width="1519" height="384" alt="image" src="https://github.com/user-attachments/assets/612babcf-27ae-4d46-8618-10d63676dbd2" />

và key được lưu trong `var_20`

<img width="754" height="281" alt="image" src="https://github.com/user-attachments/assets/5f043f6e-17ac-42bc-ad5d-24396649c263" />


<img width="306" height="117" alt="image" src="https://github.com/user-attachments/assets/7b659ed1-f194-47fa-b46a-750abce8005e" />

pseudo code: 
```
eax ^= in (var_14)
eax ^= t0 (var_c)
eax ^= t1 (var_8)
eax = sub_1209
out = eax

out = var_14 (input) ^ var_c ^ var_8
if eax & 1 
   jump to loc_136E
else qua nhánh còn lại
```

còn khúc này thì bị mất nhánh bên trái 

<img width="1377" height="650" alt="image" src="https://github.com/user-attachments/assets/e1fcdb8b-9f9b-45ea-b833-257f5131d2f5" />

còn đây là từ k[0] chuyển sang k[1], nó đọc xong 4 byte của k[0] rồi nó sang tiếp 4 byte của k[1]

<img width="403" height="422" alt="image" src="https://github.com/user-attachments/assets/52ce99d3-d4c5-4f24-b666-7601764ca8de" />

thì đoạn này có pseudo code rồi, và nhánh trái thì chả khác nhánh phải có điều nó bị đảo ROR và ROL

<img width="1096" height="525" alt="image" src="https://github.com/user-attachments/assets/4a50b5d9-1d76-42a7-926a-d3583f58ef6d" />

vậy nên ta có pseudo của nhánh trái 

```py
if c & 1:
        k0 ^= rol(v2, 11)
        k1 ^= rol(v2, 13)
        k2 ^= ror(v1, 15)
        k3 ^= ror(v1, 13)
     else:
        k0 ^= ror(v2, 13)
        k1 ^= ror(v2, 15)
        k2 ^= rol(v1, 13)
        k3 ^= rol(v1, 11)
```

kết hợp cả hai ta được đoạn psuedo code của sub_1272

``` py
 v1 = (rol(k0, 5) + ror(k1, 3))
 v2 = (ror(k2, 3) - rol(k3, 5))
    p  = ( c ^ v1 ^ v2 )
     if c & 1:
        k0 ^= rol(v2, 11)
        k1 ^= rol(v2, 13)
        k2 ^= ror(v1, 15)
        k3 ^= ror(v1, 13)
     else:
        k0 ^= ror(v2, 13)
        k1 ^= ror(v2, 15)
        k2 ^= rol(v1, 13)
        k3 ^= rol(v1, 11)
```
bây giờ mình ra lại main phân tích tiếp , `if ( !memcmp(dest, &unk_4040, 4 * qword_4020) )` ở đoạn này nó đang so sánh dist với unk và check len với qword 
đúng thì in congratz sai thì in wrong                                                                                                                              
qword = 1Bh = 27                                                                                                                                                 
unk = [DC 86 1A 9A DD 93 9B 35 D3 74 DA EE E8 5A 3C C5 1C 64 33 47 D2 3B 28 F3 CC 5A 48 8B 74 0C 4B 87 38 D6 80 40 51 E6 4A 27 A1 73 52 0F 93 06 54 3D 65 13 FB C8 65 AF D2 67 B3 09 EF 7D 23 A6 76 E5 13 10 13 FF 34 8D AE D0 9C 2C 4D F3 A1 BC 46 2F 98 87 B6 57 1A A2 17 F1 F0 E5 B0 BA 9B 6D B5 A7 AC 6A 5E AC E8 F6 90 D8 B0 A2 99 91]                                                                                                                                                            
và đây là solver 
```py
import struct

hex = "DC 86 1A 9A DD 93 9B 35 D3 74 DA EE E8 5A 3C C5 1C 64 33 47 D2 3B 28 F3 CC 5A 48 8B 74 0C 4B 87 38 D6 80 40 51 E6 4A 27 A1 73 52 0F 93 06 54 3D 65 13 FB C8 65 AF D2 67 B3 09 EF 7D 23 A6 76 E5 13 10 13 FF 34 8D AE D0 9C 2C 4D F3 A1 BC 46 2F 98 87 B6 57 1A A2 17 F1 F0 E5 B0 BA 9B 6D B5 A7 AC 6A 5E AC E8 F6 90 D8 B0 A2 99 91"

def rol(x, r):
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

def ror(x, r) :
    return ((x >> r) | (x << (32 - r))) & 0xFFFFFFFF

ct = struct.unpack("<27I", bytes.fromhex(hex))
k = list(struct.unpack("<4I", b"AlpacaHackRound8"))
out = bytearray()

for c in ct:
    v1 = (rol(k[0], 5) + ror(k[1], 3)) & 0xFFFFFFFF
    v2 = (ror(k[2], 3) - rol(k[3], 5)) & 0xFFFFFFFF
    pt = (c ^ v1 ^ v2) & 0xFFFFFFFF
    out += struct.pack("<I", pt)

    if c & 1:
        k[0] ^= rol(v2, 11)
        k[1] ^= rol(v2, 13)
        k[2] ^= ror(v1, 15)
        k[3] ^= ror(v1, 13)
    else:
        k[0] ^= ror(v2, 13)
        k[1] ^= ror(v2, 15)
        k[2] ^= rol(v1, 13)
        k[3] ^= rol(v1, 11)

print(out.rstrip(b"\x00").decode())
```
<img width="1071" height="38" alt="image" src="https://github.com/user-attachments/assets/96e9cc62-09dc-477b-afb6-b1f3b9a12930" />
<img width="1450" height="73" alt="image" src="https://github.com/user-attachments/assets/947237d0-19fe-4dcd-b06c-2263833866f9" />















