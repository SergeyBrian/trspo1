#include "patch.h"
#include <stdexcept>
#include "hook/manager/manager.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <capstone/capstone.h>

#include <iostream>

void *unstub(void *ptr);

extern "C" {
void common_hook();
void hook_end();
}

HookPatch::HookPatch(void *target, void *hook) : HookPatch() {
    setup(target, hook);
}

HookPatch::~HookPatch() { unpatch(); }

size_t HookPatch::adjust_patch_size(size_t min_size) const {
    csh h{};
    cs_insn *insn{};
    size_t res{};

    std::cout << "[*] adjust_patch_size min_size=" << min_size << "\n";
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) {
        std::cout << "[!] Capstone failed" << std::endl;
        return 0;
    }

    std::cout << "[+] cs_open done\n";

    cs_option(h, CS_OPT_DETAIL, CS_OPT_OFF);
    size_t count =
        cs_disasm(h, reinterpret_cast<uint8_t *>(this->target_ptr), 32,
                  reinterpret_cast<uint64_t>(this->target_ptr), 0, &insn);
    auto tmp = insn;
    std::cout << "[+] cs_disasm done (" << count << ")\n";
    while (count && insn && res < min_size) {
        res += insn->size;
        insn++;
        count--;
    }
    std::cout << "[+] loop done (" << res << ")\n";

    cs_free(tmp, count);
    cs_close(&h);
    std::cout << "[+] capstone done\n";

    return res;
}

void HookPatch::patch() {
    std::cout << "[*] patch() begin\n";
    DWORD tmp{};
    VirtualProtect(reinterpret_cast<LPVOID>(target_ptr), 32,
                   PAGE_EXECUTE_READWRITE, &tmp);

    uint8_t data[] = {
        /*
            0:  49 ba 00 00 00 00 00    movabs r10,0x0
            7:  00 00 00
            a:  49 bb 00 00 00 00 00    movabs r11,0x0
            11: 00 00 00
            14: 48 b8 00 00 00 00 00    movabs rax,0x0
            1b: 00 00 00
            1e: 68 00 00 00 00          push   0x0
            23: 41 ff e2                jmp    r10
        */
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x68, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE2,
    };

    uint8_t simple_jmp[] = {
        /*
            0:  49 ba 00 00 00 00 00    movabs r10,0x0
            7:  00 00 00
            a:  41 ff e2                jmp    r10
        */
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x41, 0xFF, 0xE2,
    };

    uint8_t post_trampoline[] = {
        /*
            0:  49 c7 c3 00 00 00 00    mov    r11,0x0
            7:  49 ba 00 00 00 00 00    movabs r10,0x0
            e:  00 00 00
            11: 41 ff d2                call   r10
        */
        0x49, 0xC7, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x49, 0xBA, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xD2,
    };

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

HookPatch::HookPatch() {
    hook_ptr = nullptr;
    target_ptr = nullptr;
    trampoline = VirtualAlloc(nullptr, 1024, MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
}

void HookPatch::setup(void *target, void *hook) {
    hook_ptr = hook;
    target_ptr = unstub(target);
    if (!target_ptr) {
        throw std::runtime_error("failed to find target function address");
    }
    patch();
}
