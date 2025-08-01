EXTERNDEF C trampoline_ptr:DWORD
EXTERNDEF C 

.code

UniversalHook proc
    push rcx
    push rdx
    push r8
    push r9

    call HookFunction

    pop r9
    pop r8
    pop rdx
    pop rcx

    mov rax, qword ptr [trampoline_ptr]
    jmp rax
UniversalHook endp

end 
