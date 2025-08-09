#include "logger.h"

#include <algorithm>
#include <cstdio>
#include <iostream>

#include "hook/hooks/common.h"

namespace {
struct LoggerInfo {
    char func_name[PATH_MAX]{};
};
}  // namespace

extern "C" {
static void logger_call(LoggerInfo *l) {
    char line[PATH_MAX * 2]{};
    std::sprintf(line, "Call to %s detected!\n", l->func_name);
    puts(line);
}
}

namespace hooks::logger {
void *Logger(const char *func_name) {
    std::cout << "[*] Constructing Logger('" << func_name << "')\n";

    ::LoggerInfo info{};

    std::memcpy(info.func_name, func_name,
                std::min(PATH_MAX, int(strlen(func_name))));

    void *buf = common::make_hook(func_name, info, &logger_call);

    std::cout << "[+] Done Logger('" << func_name << "')\n";
    return buf;
}
}  // namespace hooks::logger
