#include "hook/patch/common.h"
#include "patch.h"
#include <stdexcept>

#include "hook/manager/manager.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <capstone/capstone.h>

#include <iostream>
#include "common.h"

extern "C" {
void common_hook();
void hook_end();
}

void HookPatch::patch() {
    std::cout << "[*] patch() begin\n";
    DWORD tmp{};
    VirtualProtect(reinterpret_cast<LPVOID>(target_ptr), 32,
                   PAGE_EXECUTE_READWRITE, &tmp);

    uint8_t data[sizeof(common::jmp_shell)]{};
    uint8_t simple_jmp[sizeof(common::simple_jmp_shell)]{};
    uint8_t post_trampoline[sizeof(common::post_trampoline_shell)]{};

    memcpy(data, common::jmp_shell, sizeof(data));
    memcpy(simple_jmp, common::simple_jmp_shell, sizeof(simple_jmp));
    memcpy(post_trampoline, common::post_trampoline_shell,
           sizeof(post_trampoline));

    patch_size = adjust_patch_size(sizeof(data));
    if (patch_size < sizeof(simple_jmp)) {
        throw std::runtime_error("patch failed: not enough space");
    }

    auto idx = HookManager::Instance()->get_tls_idx();

    // setup post hook
    auto addr = reinterpret_cast<uint64_t>(&hook_end);
    memcpy(post_trampoline + 0x7 + 2, &addr, sizeof(addr));
    memcpy(post_trampoline + 3, &idx, sizeof(idx));
    memcpy(trampoline, post_trampoline, sizeof(post_trampoline));
    void *tramp_code =
        reinterpret_cast<uint8_t *>(trampoline) + sizeof(post_trampoline);

    // SAVE OLD BYTES
    old_bytes.resize(patch_size);
    memcpy(old_bytes.data(), reinterpret_cast<uint8_t *>(target_ptr),
           patch_size);

    // MOVE OLD BYTES TO TRAMPOLINE
    memcpy(tramp_code, old_bytes.data(), old_bytes.size());

    // (simple) JMP BACK TO AFTER OLD BYTES
    addr = reinterpret_cast<uint64_t>(reinterpret_cast<uint8_t *>(target_ptr) +
                                      patch_size);

    // r10
    memcpy(simple_jmp + 2, &addr, sizeof(addr));
    memcpy(reinterpret_cast<uint8_t *>(tramp_code) + patch_size, simple_jmp,
           sizeof(simple_jmp));

    // ==== TRAMPOLINE SETUP DONE ====

    // SETUP JMP TO common_hook (r10)
    addr = reinterpret_cast<uint64_t>(&common_hook);
    memcpy(data + 2, &addr, sizeof(addr));

    // SETUP main hook (r11)
    addr = reinterpret_cast<uint64_t>(hook_ptr);
    memcpy(data + 0xa + 2, &addr, sizeof(addr));

    // SETUP trampoline addr (rax)
    addr = reinterpret_cast<uint64_t>(trampoline);
    memcpy(data + 0x14 + 2, &addr, sizeof(addr));

    // SETUP tls idx (push)
    memcpy(data + 0x1e + 1, &idx, sizeof(idx));

    void *pre_trampoline = reinterpret_cast<uint8_t *>(tramp_code) +
                           sizeof(simple_jmp) + patch_size;

    memcpy(pre_trampoline, data, sizeof(data));

    // ==== SECOND TRAMPOLINE SETUP DONE ====

    addr = reinterpret_cast<uint64_t>(pre_trampoline);
    memcpy(simple_jmp + 2, &addr, sizeof(addr));
    memcpy(target_ptr, simple_jmp, sizeof(simple_jmp));

    VirtualProtect(reinterpret_cast<LPVOID>(target_ptr), 32, tmp, &tmp);
    VirtualProtect(reinterpret_cast<LPVOID>(trampoline), 1024,
                   PAGE_EXECUTE_READ, &tmp);
    std::cout << "[+] patch() done.\n";
}

void HookPatch::unpatch() {
    DWORD tmp{};
    VirtualProtect(reinterpret_cast<LPVOID>(target_ptr), 32,
                   PAGE_EXECUTE_READWRITE, &tmp);

    memcpy(target_ptr, old_bytes.data(), old_bytes.size());
    VirtualFree(trampoline, 0, MEM_RELEASE);

    VirtualProtect(reinterpret_cast<LPVOID>(target_ptr), 32, tmp, &tmp);
    std::cout << "[+] Hook removed\n";
}

void *unstub(void *ptr) {
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cout << "cs_open failed\n";
        return nullptr;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insn = nullptr;
    const size_t count =
        cs_disasm(handle, static_cast<const uint8_t *>(ptr), 16,
                  reinterpret_cast<uint64_t>(ptr), 1, &insn);

    if (!count) {
        cs_close(&handle);
        std::cout << "cs_disasm failed\n";
        return nullptr;
    }
    std::cout << "cs_disasm (" << count << ")\n";

    uint64_t target = 0;
    const cs_x86 &x86 = insn->detail->x86;

    if (insn->id == X86_INS_JMP && x86.op_count > 0) {
        const cs_x86_op &op = x86.operands[0];

        switch (op.type) {
            case X86_OP_IMM:
                target = static_cast<uint64_t>(op.imm);
                break;

            case X86_OP_MEM: {
                uint64_t addr = 0;

                if (op.mem.base == X86_REG_RIP) {
                    addr = insn->address + insn->size + op.mem.disp;
                } else if (op.mem.base == X86_REG_INVALID) {
                    addr = static_cast<uint64_t>(op.mem.disp);
                }

                if (addr) target = *reinterpret_cast<uint64_t *>(addr);
                break;
            }

            default:
                std::cout << "bad instruction\n";
                break;
        }
    } else {
        std::cout << "very bad instruction\n";
        std::cout << insn->mnemonic << " " << insn->op_str << "\n";
    }

    cs_free(insn, count);
    cs_close(&handle);

    return target ? reinterpret_cast<void *>(target) : nullptr;
}
