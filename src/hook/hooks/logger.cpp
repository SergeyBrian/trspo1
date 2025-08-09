#include "logger.h"
#include <cstdio>
#include "hook/hooks/common.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>

namespace hooks::logger {
struct LoggerInfo {
    char func_name[MAX_PATH]{};
};

extern "C" {
static void logger_call(LoggerInfo *l) {
    char line[MAX_PATH]{};
    std::sprintf(line, "Call to %s detected!\n", l->func_name);
    DWORD written;
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), line, strlen(line), &written,
                  NULL);
}
}
void *Logger(const char *func_name) {
    std::cout << "[*] Constructing Logger('" << func_name << "')\n";

    LoggerInfo info{};

    std::memcpy(info.func_name, func_name, min(MAX_PATH, strlen(func_name)));

    void *buf = common::make_hook(func_name, info, &logger_call);

    std::cout << "[+] Done Logger('" << func_name << "')\n";
    return buf;
}
}  // namespace hooks::logger
