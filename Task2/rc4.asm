section .data
    msg_pt db "plaintext: "
    msg_pt_len equ $-msg_pt

    msg_k db "key: "
    msg_k_len equ $-msg_k

    hexchars db "0123456789ABCDEF"
    nl db 10
	
section .bss
    plaintext resb 256
    keybuf    resb 256
    cipher    resb 256
    hexout    resb 512
    Sbox      resb 256

    pt_len  resd 1
    key_len resd 1

section .text
global _start

_start:
; plaintext
    mov eax, 4
    mov ebx, 1
    mov ecx, msg_pt
    mov edx, msg_pt_len
    int 0x80

    mov ecx, plaintext
    mov edx, 256
    call rl
    mov [pt_len], eax
    test eax, eax
    jz exit

; key
    mov eax, 4
    mov ebx, 1
    mov ecx, msg_k
    mov edx, msg_k_len
    int 0x80

    mov ecx, keybuf
    mov edx, 256
    call rl
    mov [key_len], eax
    test eax, eax
    jz exit

; bẻ sbox
    xor eax, eax	; eax = 0
    mov ecx, 256	; ecx = 256 
    mov edi, Sbox	; edi trỏ tới Sbox
.initS:
    mov [edi], al	; Sbox[i] = i (al)
    inc al		; al++
    inc edi		; edi++
    loop .initS		; lặp 256 lần


; ksa 
    xor ecx, ecx        ; i=0
    xor ebx, ebx        ; j=0
    mov esi, [key_len]  ; es= key_len

.ksa:
    mov al, [Sbox + ecx] ; al = Sbox[i]
    add bl, al           ; j += Sbox[i]

    mov eax, ecx
    xor edx, edx
    div esi                     ; edx = i % key_len
    mov al, [keybuf + edx]	; al = key[i % key_len]
    add bl, al                  ; j += key[i % key_len]

    mov dl, [Sbox + ecx]	; dl = Sbox[i]
    mov dh, [Sbox + ebx]        ; dh = Sbox[j]
    mov [Sbox + ecx], dh        ; swap S[i] = S[j]
    mov [Sbox + ebx], dl        ; swap S[j] = S[i]

    inc ecx		; i++
    cmp ecx, 256
    jl .ksa		; nếu i < 256 thì tt

; prga
    xor ecx, ecx        
    xor ebx, ebx       
    xor edi, edi	; edi=0
    mov esi, [pt_len]	; esi = pt_len

.prga:
    cmp edi, esi     
    jge .prga_done      

    inc cl			; i = (i + 1) & 255 
    mov al, [Sbox + ecx]	; al = S[i]
    add bl, al                  ; j = (j + S[i]) & 255

    mov dl, [Sbox + ecx]	; dl = S[i]
    mov dh, [Sbox + ebx]        ; dh = S[j]
    mov [Sbox + ecx], dh        ; swap S[i] = S[j]
    mov [Sbox + ebx], dl        ; swap S[j] = S[i]

    mov al, [Sbox + ecx]        ; S[i] sau swap
    mov dl, [Sbox + ebx]        ; S[j] sau swap
    movzx eax, al	   	; eax = al 0 extended
    add al, dl                  ; t = (mới S[i] + mới S[j]) & 255
    and eax, 0FFh                           
    mov dl, [Sbox + eax]        ; keystream byte = S[t]

    mov al, [plaintext + edi]   ; lấy một byte plaintext
    xor al, dl                  ; xor keystream vs cipher
    mov [cipher + edi], al      ; lưu cipher byte

    inc edi 		
    jmp .prga         

.prga_done:

; chuyển cipher sang hex
    xor ecx, ecx			

.hex:
    cmp ecx, [pt_len]          
    jge .hex_done           

    mov al, [cipher + ecx]	; al = cipher[i]
    mov edx, ecx
    shl edx, 1                  ; edx = i * 2 

    movzx eax, al 		; eax = al 0 extended
    shr eax, 4                  ; dịch phải 4bit
    mov bl, [hexchars + eax]    ; vd: eax= 10 => bl = "A"
    mov [hexout + edx], bl      ; ghi ký tự hex thứ 1

    mov al, [cipher + ecx]      ; reload
    movzx eax, al
    and eax, 0Fh                ; edx & 0Fh
    mov bl, [hexchars + eax]    ; ghi ký tự hex 2
    mov [hexout + edx + 1], bl  ; lưu

    inc ecx                     ; i++
    jmp .hex                    

.hex_done:

; print hex
    mov eax, 4
    mov ebx, 1
    mov ecx, hexout
    mov edx, [pt_len]
    shl edx, 1
    int 0x80

    mov eax, 4
    mov ebx, 1
    mov ecx, nl
    mov edx, 1
    int 0x80 

exit:
    mov eax, 1
    xor ebx, ebx
    int 0x80

rl:
; tách dòng (?)
    mov eax, 3         
    mov ebx, 0 
    mov edx, 256         
    int 0x80        

    ; kiểm tra
    test eax, eax       ; eax = 0 ?
    jz .ret   

    ; xử lý "\n"
    mov esi, eax        ; esi = bytes_read
    dec esi             ; esi = index byte cuối (len - 1)

    cmp byte [ecx + esi], 10   ; byte cuối có phải "\n"?
    jne .no_nl                  ; nếu không có "\n" thì bỏ qua

    ; có "\n"
    mov byte [ecx + esi], 0    ; ghi đè "\n"
    mov eax, esi               ; length = len - 1
    ret

.no_nl:
    mov byte [ecx + eax], 0    ; buffer[len] = '\0', eax = bytes_read
    ret

.ret:
    xor eax, eax
    ret
