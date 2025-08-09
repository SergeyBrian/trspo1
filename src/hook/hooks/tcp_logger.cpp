#include "tcp_logger.h"
#include <cstdio>
#include "hook/hooks/common.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>

#include "common/include/proto.h"

namespace hooks::tcp_logger {
struct LoggerInfo {
    char func_name[MAX_PATH]{};
    io::IStream *s;
};

extern "C" {
static void logger_call(LoggerInfo *l) {
    char line[MAX_PATH * 2]{};
    std::sprintf(line, "Call to %s detected!", l->func_name);
    proto::send_log(l->s, line);
}
}

void *Logger(const char *func_name, io::IStream *s) {
    std::cout << "[*] Constructing Logger('" << func_name << "')\n";

    LoggerInfo info{{}, s};

    std::memcpy(info.func_name, func_name, min(MAX_PATH, strlen(func_name)));

    void *buf = common::make_hook(func_name, info, &logger_call);

    std::cout << "[+] Done Logger('" << func_name << "')\n";
    return buf;
}
}  // namespace hooks::tcp_logger
