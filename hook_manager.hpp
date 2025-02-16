#ifndef HOOK_MANAGER_HPP
#define HOOK_MANAGER_HPP

#include <map>
#include <memory>
#include <string>

#include "patch.hpp"

class HookManager {
public:
  void AddPatch(std::string lib_name, std::string func_name, void *hook_func);
  void RemovePatch(std::string func_name);

private:
  std::map<std::string, std::unique_ptr<HookPatch>> patches;
};

#endif
