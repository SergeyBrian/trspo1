#include "patch.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <capstone/capstone.h>

#include <iostream>

HookPatch::HookPatch(void *target, void *hook)
    : target_ptr(target), hook_ptr(hook) {
    patch();
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
          0:  48 b8 00 00 00 00 00    movabs rax,0x0
          7:  00 00 00
          a:  ff e0                   jmp    rax
        */
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0,
    };

    patch_size = adjust_patch_size(sizeof(data));
    if (patch_size < sizeof(data)) {
        throw std::runtime_error("patch failed: not enough space");
    }
    std::cout << "[*] patch_size = " << patch_size << "\n";

    old_bytes.resize(patch_size);
    memcpy(old_bytes.data(), target_ptr, patch_size);

    trampoline = VirtualAlloc(nullptr, sizeof(data) + patch_size,
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    std::cout << "trampoline addr: " << std::hex << trampoline << "\n"
              << std::dec;
    memcpy(trampoline, old_bytes.data(), old_bytes.size());

    auto addr = reinterpret_cast<uint64_t>(target_ptr) + patch_size;
    memcpy(data + 2, &addr, sizeof(addr));
    memcpy(reinterpret_cast<uint8_t *>(trampoline) + patch_size, data,
           sizeof(data));

    std::cout << std::hex;
    for (const auto &c : data) {
        std::cout << "0x" << static_cast<uint64_t>(c) << " ";
    }
    std::cout << "\n" << std::dec;

    std::cout << "hook_ptr addr: " << std::hex << hook_ptr << "\n" << std::dec;
    addr = reinterpret_cast<uint64_t>(hook_ptr);
    memcpy(data + 2, &addr, sizeof(addr));
    memcpy(target_ptr, data, sizeof(data));

    VirtualProtect(reinterpret_cast<LPVOID>(target_ptr), 32, tmp, &tmp);
    std::cout << "[+] Hook added\n";
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
