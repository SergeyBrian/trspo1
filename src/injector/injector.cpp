#include "injector.hpp"

#include <iostream>
#include <cstring>
#include <thread>

#include "common/include/tcp.h"
#include "common/include/proto.h"

#include "utils.h"

#ifdef _WIN32
static const char *dll_name = "hook";
#else
static const char *dll_name = "libhook.so";
#endif

namespace injector {
bool server(const Config &config) {
    auto listener = net::TcpListener::bind("127.0.0.1", "6969");
    if (!listener) {
        std::cout << "[!] Failed to bind to tcp socket\n";
        return 1;
    }

    auto stream = listener->accept();
    if (!stream) {
        std::cout << "[!] Accept failed\n";
        return 1;
    }
    std::cout << "[+] Successfully connected\n";

    proto::Mode mode{};
    std::string s{};

    if (config.hide_file_name) {
        mode = proto::Mode::Filter;
        s = config.hide_file_name;
    } else {
        mode = proto::Mode::Log;
        s = config.func_name;
    }

    auto cfg = proto::Config{mode, s};

    proto::send_config(stream.get(), cfg);

    while (true) {
        auto log = proto::recv_log(stream.get());
        if (!log) {
            std::cout << "[*] Connection closed!\n";
            break;
        }
        std::cout << "[+] Msg: " << *log << "\n";
    }

    stream->close();
    listener->close();
    return 0;
}

bool inject(const Config &config) {
    std::string dll_full_path = get_full_path(dll_name);
    int64_t pid = config.pid;

    if (dll_full_path.empty()) {
        std::cout << "[!] can't resolve lib path\n";
        return 1;
    }

    if (!config.pid) {
        if (!strlen(config.process_name)) {
            std::cout << "[!] Please specify pid or process name\n";
            return 1;
        }
        pid = get_pid_by_name(config.process_name);
        if (!pid) {
            std::cout << "[!] Process not found\n";
            return 1;
        }
    }

    std::cout << "[*] Pid: " << pid << "\n";

    std::thread t([&] {
        bool ok = server(config);
        std::cout << "server finished, ok=" << std::boolalpha << ok << "\n";
    });

    auto thread = ::inject(pid, dll_full_path);

    ::wait(thread);
    t.join();

    return 0;
}
}  // namespace injector
