#include "manager.h"
#include <stdexcept>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void HookManager::AddPatch(const std::string &lib_name,
                           const std::string &func_name, void *hook_func) {
    HMODULE h = LoadLibraryA(lib_name.c_str());
    if (!h) {
        throw std::runtime_error("LoadLibraryA failed");
    }

    void *target =
        reinterpret_cast<void *>(GetProcAddress(h, func_name.c_str()));
    if (!target) {
        throw std::runtime_error("GetProcAddress failed");
    }

    patches[func_name] =
        std::move(std::make_unique<HookPatch>(target, hook_func));
}

void HookManager::RemovePatch(std::string func_name) {
    patches.erase(func_name);
}

HookManager *HookManager::Instance() {
    static HookManager instance;

    return &instance;
}
