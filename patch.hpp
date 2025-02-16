#ifndef PATCH_HPP
#define PATCH_HPP

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>

class HookPatch {
public:
  HookPatch(const char *lib_name, const char *func_name, const void *hook_func);
  ~HookPatch();

  HookPatch(const HookPatch &) = delete;

private:
  void *address{};
  void *hook_func{};
  HMODULE lib_handle{};
  uint8_t old_bytes[15];
};

#endif
