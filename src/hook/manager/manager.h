#ifndef H_HOOK_MANAGER_H
#define H_HOOK_MANAGER_H

#include "hook/patch/patch.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
using TlsKey = DWORD;
#else
#include <pthread.h>

using TlsKey = pthread_key_t;
#endif

#include <unordered_map>
#include <string>
#include <memory>
#include <iostream>

class HookManager {
public:
    static HookManager *Instance();
    void add_patch(const std::string &lib_name, const std::string &func_name,
                   void *hook_func);
    void remove_patch(const std::string &func_name);

    template <typename T>
    T get_trampoline(const std::string &func_name) {
        if (patches.contains(func_name)) {
            std::cout << "[+] Found trampoline (" << func_name << ")\n";
            return patches.at(func_name)->get_trampoline<T>();
        }

        std::cout << "[!] Not found (" << func_name << ")\n";

        patches[func_name] = std::make_unique<HookPatch>();

        return patches.at(func_name)->get_trampoline<T>();
    }

    TlsKey get_tls_idx() { return tls_idx; }

    HookManager(const HookManager &) = delete;
    HookManager &operator=(const HookManager &) = delete;

private:
    HookManager();
    std::unordered_map<std::string, std::unique_ptr<HookPatch>> patches;

    TlsKey tls_idx;
};

#endif
