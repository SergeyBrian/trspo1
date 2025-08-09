#include "tcp_logger.h"
#include <algorithm>
#include <cstdio>
#include "hook/hooks/common.h"

#include <iostream>

#include "common/include/proto.h"

#define MAX_PATH 260

namespace hooks::tcp_logger {
struct TcpLoggerInfo {
    char func_name[MAX_PATH]{};
    io::IStream *s;
};

extern "C" {
static void logger_call(TcpLoggerInfo *l) {
    std::cout << "info: " << std::hex << reinterpret_cast<uint64_t>(l) << "\n"
              << std::dec;
    char line[MAX_PATH * 2]{};
    std::sprintf(line, "Call to %s detected!", l->func_name);
    puts(line);
    proto::send_log(l->s, line);
}
}

void *Logger(const char *func_name, io::IStream *s) {
    std::cout << "[*] Constructing Logger('" << func_name << "')" << std::hex
              << "0x" << reinterpret_cast<uint64_t>(s) << std::dec << "\n";

    TcpLoggerInfo info{{}, s};

    std::memcpy(info.func_name, func_name,
                std::min(MAX_PATH, static_cast<int>(strlen(func_name))));

    void *buf = common::make_hook(func_name, info, &logger_call);

    std::cout << "[+] Done Logger('" << func_name << "')\n";
    return buf;
}
}  // namespace hooks::tcp_logger
