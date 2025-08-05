#ifndef H_HOOK_PATCH_H
#define H_HOOK_PATCH_H

#include <vector>

class HookPatch {
public:
    template <typename T>
    T get_trampoline() {
        return reinterpret_cast<T>(trampoline);
    }
    void setup(void *target, void *hook);

    HookPatch();
    HookPatch(void *target, void *hook);
    ~HookPatch();

private:
    void patch();
    void unpatch();

    void *target_ptr;
    void *hook_ptr;
    void *trampoline{};

    size_t patch_size{};
    std::vector<uint8_t> old_bytes{};

    size_t adjust_patch_size(size_t min_size) const;
};

#endif
