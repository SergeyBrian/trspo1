.intel_syntax noprefix
.globl common_hook
.type  common_hook, @function
.globl hook_end
.type  hook_end, @function


.macro SAVE_REGS
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    sub  rsp, 0x40
    movdqu [rsp+0x00], xmm0
    movdqu [rsp+0x10], xmm1
    movdqu [rsp+0x20], xmm2
    movdqu [rsp+0x30], xmm3
.endm

.macro RESTORE_REGS
    movdqu xmm0, [rsp+0x00]
    movdqu xmm1, [rsp+0x10]
    movdqu xmm2, [rsp+0x20]
    movdqu xmm3, [rsp+0x30]
    add  rsp, 0x40

    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rbp
    pop  rbx
    pop  rdx
pop  rcx
    pop  rax
.endm

common_hook:
    pop rax
    jmp r11

hook_end:
    ret
