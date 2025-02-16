#include "hook_manager.hpp"

void HookManager::AddPatch(std::string lib_name, std::string func_name,
                           void *hook_func) {
  patches[func_name] = std::move(std::make_unique<HookPatch>(
      lib_name.c_str(), func_name.c_str(), hook_func));
}

void HookManager::RemovePatch(std::string func_name) {
  patches.erase(func_name);
}
