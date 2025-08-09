#include "filter.h"

#include <cstring>

#include "hook/manager/manager.h"

namespace hooks::filter {
static std::string hidden_str;
void SetHideStrig(const std::string &s) { hidden_str = s; }

bool is_allowed(const char *s) {
    if (hidden_str.empty()) return true;

    return !strcmp(s, hidden_str.c_str());
}

FILE *filter_fopen(const char *__restrict __filename,
                   const char *__restrict __modes) {
    puts("filter_fopen begin.");
    puts(__filename);
    if (is_allowed(__filename)) {
        puts("block.");
        return nullptr;
    }

    puts("allow.");
    return HookManager::Instance()->get_trampoline<decltype(&filter_fopen)>(
        "fopen")(__filename, __modes);
}

void *fopen() { return reinterpret_cast<void *>(&filter_fopen); }
}  // namespace hooks::filter
