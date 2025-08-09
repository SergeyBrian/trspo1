#include "patch.h"

#include <cerrno>
#include <cstdlib>
#include <stdexcept>
#include <iostream>

#include <capstone/capstone.h>
#include <sys/mman.h>

#include "hook/manager/manager.h"
#include "common.h"

extern "C" {
void common_hook();
void hook_end();
}

void print_ptr(void *p) {
    static const size_t ps = sysconf(_SC_PAGE_SIZE);
    auto ptr = reinterpret_cast<uint64_t>(p);
    fprintf(stdout, "0x%lx (%%16 = %lu; %%8 = %lu; %%%lu = %lu)\n", ptr,
            ptr % 16, ptr % 8, ps, ptr % ps);
}

void HookPatch::patch() {
    uint64_t addr{};
    static const size_t ps = sysconf(_SC_PAGE_SIZE);

    std::cout << "[+] patch() begin\n";

    uint8_t data[sizeof(common::jmp_shell)]{};
    uint8_t simple_jmp[sizeof(common::simple_jmp_shell)]{};
    uint8_t post_trampoline[sizeof(common::post_trampoline_shell)]{};

    memcpy(data, common::jmp_shell, sizeof(data));
    memcpy(simple_jmp, common::simple_jmp_shell, sizeof(simple_jmp));
    memcpy(post_trampoline, common::post_trampoline_shell,
           sizeof(post_trampoline));

    patch_size = adjust_patch_size(sizeof(simple_jmp));
    fprintf(stdout, "[+] calculated patch_size = %zu (min %zu)\n", patch_size,
            sizeof(simple_jmp));

    std::cout << "[+] target_ptr = ";
    print_ptr(target_ptr);
    if (mprotect(get_page(target_ptr), patch_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC)) {
        fprintf(stdout, "[!] mprotect failed! (%d)\n", errno);
        throw std::runtime_error(strerror(errno));
    }
    std::cout << "[+] mprotect done\n";

    auto idx = HookManager::Instance()->get_tls_idx();
    std::cout << "[+] tls idx: " << idx << "\n";

    // setup post hook
    addr = reinterpret_cast<uint64_t>(&hook_end);
    memcpy(post_trampoline + 0x7 + 2, &addr, sizeof(addr));
    memcpy(post_trampoline + 3, &idx, sizeof(idx));
    memcpy(trampoline, post_trampoline, sizeof(post_trampoline));
    void *tramp_code =
        reinterpret_cast<uint8_t *>(trampoline) + sizeof(post_trampoline);

    // SAVE OLD BYTES
    old_bytes.resize(patch_size);
    memcpy(old_bytes.data(), reinterpret_cast<uint8_t *>(target_ptr),
           patch_size);

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

    std::cout << "[*] before overwirte\n";
    memcpy(target_ptr, simple_jmp, sizeof(simple_jmp));

    std::cout << "[+] target_ptr overwirte done\n";

    if (mprotect(get_page(target_ptr), patch_size, PROT_READ | PROT_EXEC)) {
        fprintf(stdout, "[!] mprotect failed! (%d)\n", errno);
        throw std::runtime_error(strerror(errno));
    }
    std::cout << "[+] mprotect done\n";

    std::cout << "[+] patch() done\n";
}

void HookPatch::unpatch() {}

void *unstub(void *ptr) {
    if (*reinterpret_cast<uint8_t *>(ptr) != 0xF3) {
        fprintf(stdout, "[!] First instruction is not endbr64.\n");
        return nullptr;
    }
    return reinterpret_cast<uint8_t *>(ptr) + 0x4;
}
