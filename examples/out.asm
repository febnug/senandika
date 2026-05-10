bits 64
global _start

section .text

%define XOR_KEY 0x22

_start:
    jmp short get_payload

decoder:
    pop rsi
    sub rsp, 6 + 8
    mov rdi, rsp
    xor ecx, ecx
    mov cl, 6

.decode:
    lodsb
    xor al, 0x22
    stosb
    loop .decode

    xor eax, eax
    mov al, 1
    xor edi, edi
    mov dil, 1
    mov rsi, rsp
    xor edx, edx
    mov dl, 6
    syscall

    xor eax, eax
    mov al, 60
    xor edi, edi
    syscall

get_payload:
    call decoder
payload:
    db 0x44, 0x47, 0x40, 0x4c, 0x57, 0x45
