#include <dlfcn.h>
#include <unistd.h>
#include <cstdio>
#include "utils.h"

void *get_func_ptr(const std::string &lib_name, const std::string &func_name) {
    void *h = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
    if (!h) {
        fprintf(stderr, "[!] dlopen libc failed\n");
        return nullptr;
    }

    void *sym = dlsym(h, func_name.c_str());
    if (!sym) {
        fprintf(stderr, "[!] dlsym failed (%s)\n", func_name.c_str());
        return nullptr;
    }

    Dl_info info{};
    if (!dladdr(sym, &info) || !info.dli_fbase || !info.dli_fname) {
        fprintf(stderr, "[!] dladdr failed (%s)\n", func_name.c_str());
        return nullptr;
    }

    uint64_t local_addr = reinterpret_cast<uint64_t>(sym);

    return reinterpret_cast<void *>(local_addr);
}

TlsKey alloc_tls() { return 0; }

void *get_page(void *p) {
    static const size_t ps = sysconf(_SC_PAGE_SIZE);
    auto ptr = reinterpret_cast<uint64_t>(p);
    uint64_t offset = ptr % ps;
    return reinterpret_cast<void *>(ptr - offset);
}
