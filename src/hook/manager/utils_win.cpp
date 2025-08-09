#include "utils.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdexcept>

void *get_func_ptr(const std::string &lib_name, const std::string &func_name) {
    HMODULE h = LoadLibraryA(lib_name.c_str());
    if (!h) {
        throw std::runtime_error("LoadLibraryA failed");
    }

    void *target =
        reinterpret_cast<void *>(GetProcAddress(h, func_name.c_str()));
    if (!target) {
        throw std::runtime_error("GetProcAddress failed");
    }

    return target;
}

TlsKey alloc_tls() {
    TlsKey tls_idx = TlsAlloc();
    TlsSetValue(tls_idx, 0);

    return tls_idx;
}

void *get_page(void *p) { return p; }
