#ifndef H_HOOK_HOOKS_COMMON_H
#define H_HOOK_HOOKS_COMMON_H

#include "hook/manager/manager.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstring>
#include <cstdint>

namespace hooks::common {
template <typename T>
void *make_hook(const char *func_name, T info, void (*handler)(T *)) {
    uint8_t data[] = {
        /*
            0:  50                      push   rax
            1:  51                      push   rcx
            2:  52                      push   rdx
            3:  53                      push   rbx
            4:  55                      push   rbp
            5:  56                      push   rsi
            6:  57                      push   rdi
            7:  41 50                   push   r8
            9:  41 51                   push   r9
            b:  41 52                   push   r10
            d:  41 53                   push   r11
            f:  41 54                   push   r12
            11: 41 55                   push   r13
            13: 41 56                   push   r14
            15: 41 57                   push   r15
            17: 48 83 ec 40             sub    rsp,0x40
            1b: 0f 11 04 24             movups XMMWORD PTR [rsp],xmm0
            1f: 0f 11 4c 24 10          movups XMMWORD PTR [rsp+0x10],xmm1
            24: 0f 11 54 24 20          movups XMMWORD PTR [rsp+0x20],xmm2
            29: 0f 11 5c 24 30          movups XMMWORD PTR [rsp+0x30],xmm3
            2e: 48 b9 00 00 00 00 00    movabs rcx,0x0
            35: 00 00 00
            38: 48 ba 00 00 00 00 00    movabs rdx,0x0
            3f: 00 00 00
            42: 48 b8 00 00 00 00 00    movabs rax,0x0
            49: 00 00 00
            4c: ff d2                   call   rdx
            4e: 0f 10 04 24             movups xmm0,XMMWORD PTR [rsp]
            52: 0f 10 4c 24 10          movups xmm1,XMMWORD PTR [rsp+0x10]
            57: 0f 10 54 24 20          movups xmm2,XMMWORD PTR [rsp+0x20]
            5c: 0f 10 5c 24 30          movups xmm3,XMMWORD PTR [rsp+0x30]
            61: 48 83 c4 40             add    rsp,0x40
            65: 41 5f                   pop    r15
            67: 41 5e                   pop    r14
            69: 41 5d                   pop    r13
            6b: 41 5c                   pop    r12
            6d: 41 5b                   pop    r11
            6f: 41 5a                   pop    r10
            71: 41 59                   pop    r9
            73: 41 58                   pop    r8
            75: 5f                      pop    rdi
            76: 5e                      pop    rsi
            77: 5d                      pop    rbp
            78: 5b                      pop    rbx
            79: 5a                      pop    rdx
            7a: 59                      pop    rcx
            7b: 58                      pop    rax
            7c: ff 25 06 00 00 00       jmp    QWORD PTR [rip+0x0]
        */
        0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41,
        0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48,
        0x83, 0xEC, 0x40, 0x0F, 0x11, 0x04, 0x24, 0x0F, 0x11, 0x4C, 0x24, 0x10,
        0x0F, 0x11, 0x54, 0x24, 0x20, 0x0F, 0x11, 0x5C, 0x24, 0x30, 0x48, 0xB9,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xBA, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xD2, 0x0F, 0x10, 0x04, 0x24, 0x0F, 0x10,
        0x4C, 0x24, 0x10, 0x0F, 0x10, 0x54, 0x24, 0x20, 0x0F, 0x10, 0x5C, 0x24,
        0x30, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41,
        0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5D,
        0x5B, 0x5A, 0x59, 0x58, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    };

    auto orig = HookManager::Instance()->get_trampoline<void *>(func_name);

    size_t bufSize = sizeof(data) + sizeof(orig) + sizeof(info);

    void *buf = VirtualAlloc(nullptr, bufSize, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    void *res = buf;
    auto meta = reinterpret_cast<T *>(buf);
    buf = meta + 1;
    void *code = buf;

    std::memcpy(meta, &info, sizeof(info));

    auto addr = reinterpret_cast<uint64_t>(meta);
    std::memcpy(data + 0x2e + 2, &addr, sizeof(addr));
    addr = reinterpret_cast<uint64_t>(handler);
    std::memcpy(data + 0x38 + 2, &addr, sizeof(addr));

    std::memcpy(buf, data, sizeof(data));
    buf = reinterpret_cast<uint8_t *>(buf) + sizeof(data);

    *reinterpret_cast<uint64_t *>(buf) = reinterpret_cast<uint64_t>(orig);

    DWORD tmp{};
    VirtualProtect(res, bufSize, PAGE_EXECUTE_READ, &tmp);
    return code;
}
}  // namespace hooks::common

#endif
