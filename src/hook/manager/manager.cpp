#include "manager.h"
#include <stdexcept>

#include "utils.h"

void HookManager::add_patch(const std::string &lib_name,
                            const std::string &func_name, void *hook_func) {
    void *target = get_func_ptr(lib_name, func_name);
    if (!target) {
        throw std::runtime_error("Function not found");
    }

    if (patches.contains(func_name)) {
        patches.at(func_name)->setup(target, hook_func);
    } else {
        patches[func_name] =
            std::move(std::make_unique<HookPatch>(target, hook_func));
    }
}

void HookManager::remove_patch(const std::string &func_name) {
    patches.erase(func_name);
}

HookManager *HookManager::Instance() {
    static HookManager instance;

    return &instance;
}

HookManager::HookManager() { tls_idx = alloc_tls(); }
