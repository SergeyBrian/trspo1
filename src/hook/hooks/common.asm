includelib kernel32.lib

TlsGetValue  PROTO :DWORD
TlsSetValue  PROTO :DWORD, :DWORD
SetLastError PROTO :DWORD
GetLastError PROTO

.code
PUBLIC common_hook
PUBLIC hook_end

SAVE_REGS MACRO
    push   rcx
    push   rdx
    push   rbx
    push   rbp
    push   rsi
    push   rdi
    push   r8
    push   r9
    push   r12
    push   r13
    push   r14
    push   r15
    sub    rsp,40h
    movups XMMWORD PTR [rsp],xmm0
    movups XMMWORD PTR [rsp+10h],xmm1
    movups XMMWORD PTR [rsp+20h],xmm2
    movups XMMWORD PTR [rsp+30h],xmm3
ENDM

RESTORE_REGS MACRO
    movups xmm0,XMMWORD PTR [rsp]
    movups xmm1,XMMWORD PTR [rsp+10h]
    movups xmm2,XMMWORD PTR [rsp+20h]
    movups xmm3,XMMWORD PTR [rsp+30h]
    add    rsp,40h
    pop    r15
    pop    r14
    pop    r13
    pop    r12
    pop    r9
    pop    r8
    pop    rdi
    pop    rsi
    pop    rbp
    pop    rbx
    pop    rdx
    pop    rcx
ENDM

; r11 -> main hook
; rax -> trampoline
; stack -> tls idx
common_hook PROC
    pop r10 ; get tls idx
    push r11 ; store main hook addr
    push rax ; store trampoline

    SAVE_REGS

    mov     rcx, r10
    call    TlsGetValue
    push rax
    test    rax, rax
    jnz     skip_hook

    mov     rdx, 1
    call    TlsSetValue

skip_hook:

    pop     r10 ; is hook active

    RESTORE_REGS

    pop r11 ; r11 <- trampoline

    ; if tls flag is set, main hook will be skipped
    test r10, r10
    jnz trampoline

    pop r11 ; r11 <- main hook
    jmp r11

    ret

trampoline:
    pop r10 ; clear stack. r11 is still trampoline
    jmp r11
common_hook ENDP


; r11 -> tls idx
hook_end PROC
    SAVE_REGS
    
    call GetLastError
    push rax

    mov rcx, r11
    xor rdx, rdx

    call TlsSetValue

    pop rcx
    call SetLastError

    RESTORE_REGS

    ret
hook_end ENDP

END
