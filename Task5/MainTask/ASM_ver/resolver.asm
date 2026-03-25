global main

extern ExitProcess

section .data
    kernel32_str db "KERNEL32.DLL", 0
    getproc_str  db "GetProcAddress", 0
    msgbox_str   db "MessageBoxA", 0
    user32_str   db "USER32.DLL", 0
    loadlib_str db "LoadLibraryA", 0
    text db "haaha..", 0
    caption db ".", 0

section .bss
    kernel32_base resq 1
    getproc_addr  resq 1
    msgbox_addr   resq 1
    loadlib_addr resq 1
    user32_base  resq 1
section .text

; p.biệt hoa và thường 

strcmp:
.cmp:
    mov al, [rdi] 
    mov cl, [rsi]  
    cmp al, cl
    jne .noteq
    test al, al
    je .eq
    inc rdi
    inc rsi
    jmp .cmp
.eq:
    xor rax, rax
    ret
.noteq:
    mov rax, 1
    ret


; lấy kernel32 base qua PEB

get_kernel32:
    mov rax, [gs:0x60]        ; PEB
    mov rax, [rax + 0x18]     ; PEB->Ldr
    mov rax, [rax + 0x20]     ; InMemoryOrderModuleList
    mov rax, [rax]            ; ntdll
    mov rax, [rax]            ; kernel32
    mov rax, [rax + 0x20]     ; DllBase
    ret

.next:
    mov rbx, [rbx]            
    mov rcx, [rbx + 0x50]     ; BaseDllName 
    mov rax, [rbx + 0x20]     ; DllBase
    ret


; export table
resolve_export:
    push rbx  
    push rsi 
    push rdi 
    push r12 
    push r13 
    push r14 
    push r15

    mov rbx, rcx              ; module base

    mov eax, [rbx + 0x3C]
    add rax, rbx              ; PE header

    mov eax, [rax + 0x88]     ; export table RVA
    add rax, rbx

    mov r12d, [rax + 0x18]    ; NumberOfNames
    mov r13d, [rax + 0x20]    ; AddressOfNames
    add r13, rbx

    mov r14d, [rax + 0x24]    ; AddressOfNameOrdinals
    add r14, rbx

    mov r15d, [rax + 0x1C]    ; AddressOfFunctions
    add r15, rbx

.loop:
    test r12d, r12d              ; test nếu NumberOfNames == 0
    jz .notfound                

    dec r12d                     ; index-- 

    mov esi, [r13 + r12*4]       ; lấy RVA của tên function từ mảng AddressOfNames 
    add rsi, rbx                 ; chuyển RVA thành VA

    mov rdi, rdx                 ; rdi = tên của function mình muốn
    call strcmp                  ; cmp tên export vs tên đó
    cmp rax, 0                   
    jne .loop                    
   ; nếu thấy 
    movzx eax, word [r14 + r12*2] ; lấy ordinal index từ AddressOfNameOrdinals
    mov eax, [r15 + rax*4]        ; lấy function RVA từ AddressOfFunctions
    add rax, rbx                 ; chuyển RVA → VA 
    jmp .done                    

.notfound:
    xor rax, rax               
.done:
    ; hồi phục lại registers
    pop r15 
    pop r14 
    pop r13 
    pop r12 
    pop rdi 
    pop rsi 
    pop rbx 
    ret      ; rax = function pointer


main:
    sub rsp, 40

    ; lấy kernel32 base
    call get_kernel32
    mov [rel kernel32_base], rax

    ; resolve GetProcAddress
    mov rcx, rax
    mov rdx, getproc_str
    call resolve_export
    mov [rel getproc_addr], rax

    ; resolve LoadLibraryA
    mov rcx, [rel kernel32_base]
    mov rdx, loadlib_str            
    call resolve_export
    mov [rel loadlib_addr], rax

    ; call LoadLibraryA
    lea rcx, [rel user32_str]        
    call [rel loadlib_addr]
    mov [rel user32_base], rax

    ; resolve MessageBoxA 
    mov rcx, rax
    mov rdx, msgbox_str
    call resolve_export
    mov [rel msgbox_addr], rax

    ; call MessageBoxA
    xor rcx, rcx
    lea rdx, [rel text]
    lea r8,  [rel caption]
    xor r9, r9
    call [rel msgbox_addr]
exit:
    xor rcx, rcx
    call ExitProcess
