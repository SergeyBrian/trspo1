#ifndef H_HOOK_MANAGER_H
#define H_HOOK_MANAGER_H

#include "hook/patch/patch.h"

#include <unordered_map>
#include <string>
#include <memory>

class HookManager {
public:
    static HookManager *Instance();
    void AddPatch(const std::string &lib_name, const std::string &func_name,
                  void *hook_func);
    void RemovePatch(std::string func_name);

    HookManager(const HookManager &) = delete;
    HookManager &operator=(const HookManager &) = delete;

private:
    HookManager() = default;
    std::unordered_map<std::string, std::unique_ptr<HookPatch>> patches;
};

#endif
