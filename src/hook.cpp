#include "hook.hpp"
#include <cstdio>

extern "C" {
void save_ctx(void);
void restore_ctx(void);
}

namespace hook {
void Hook() {
    save_ctx();
    printf("[+] Hook triggered!\n");
    restore_ctx();
}
}  // namespace hook
