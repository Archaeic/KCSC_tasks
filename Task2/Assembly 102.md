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












