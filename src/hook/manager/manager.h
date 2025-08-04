#ifndef H_HOOK_MANAGER_H
#define H_HOOK_MANAGER_H

#include "hook/patch/patch.h"

#include <stdexcept>
#include <unordered_map>
#include <string>
#include <memory>

class HookManager {
public:
    static HookManager *Instance();
    void add_patch(const std::string &lib_name, const std::string &func_name,
                   void *hook_func);
    void remove_patch(const std::string &func_name);

    template <typename T>
    T get_trampoline(const std::string &func_name) {
        if (!patches.contains(func_name))
            throw std::runtime_error("patch not found");

        return patches.at(func_name)->get_trampoline<T>();
    }

    HookManager(const HookManager &) = delete;
    HookManager &operator=(const HookManager &) = delete;

private:
    HookManager() = default;
    std::unordered_map<std::string, std::unique_ptr<HookPatch>> patches;
};

#endif
