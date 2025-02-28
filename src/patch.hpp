#ifndef PATCH_HPP
#define PATCH_HPP

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace hook {
class HookPatch {
public:
    HookPatch(const char *lib_name, const char *func_name,
              const void *hook_func);
    ~HookPatch();

    HookPatch(const HookPatch &) = delete;

private:
    void *address{};
    void *hook_func{};
    HMODULE lib_handle{};
    void *trampoline{};
    size_t old_bytes_count{};
};
}  // namespace hook

#endif
