#include "patch.h"
#include <stdexcept>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#include <iostream>
#include <capstone/capstone.h>

void *unstub(void *ptr);

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
    size_t count = cs_disasm(
        h, reinterpret_cast<uint8_t *>(this->target_ptr), min_size * 2,
        reinterpret_cast<uint64_t>(this->target_ptr), 0, &insn);
    auto tmp = insn;
    std::cout << "[+] cs_disasm done (count: " << count << ")\n";
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

HookPatch::HookPatch() {
    hook_ptr = nullptr;
    target_ptr = nullptr;
#ifdef _WIN32
    trampoline = VirtualAlloc(nullptr, 1024, MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
#else
    trampoline = mmap(NULL, 1024, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
}

void HookPatch::setup(void *target, void *hook) {
    hook_ptr = hook;
    target_ptr = unstub(target);
    if (!target_ptr) {
        throw std::runtime_error("failed to find target function address");
    }
    patch();
}
