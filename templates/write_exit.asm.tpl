bits 64
global _start

section .text

{{KEY_DEFINE}}

_start:
    jmp short get_payload

decoder:
    pop rsi
    sub rsp, {{MSG_LEN}} + 8
    mov rdi, rsp
    xor ecx, ecx
    mov cl, {{MSG_LEN}}

.decode:
    lodsb
{{XOR_LINE}}
    stosb
    loop .decode

    xor eax, eax
    mov al, 1
    xor edi, edi
    mov dil, 1
    mov rsi, rsp
    xor edx, edx
    mov dl, {{MSG_LEN}}
    syscall

    xor eax, eax
    mov al, 60
    xor edi, edi
    syscall

get_payload:
    call decoder
payload:
    db {{MSG_BYTES}}
