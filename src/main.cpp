#include <cstring>
#include <cstdint>
#include <iostream>

#include "injector/injector.hpp"

enum class Arg : uint8_t {
    Unknown,
    Pid,
    Name,
    Func,
    Hide,
};

int main(int argc, char **argv) {
    injector::Config config{};
    Arg cur_arg{};

    if (argc <= 1) {
        std::cout << "[!] Not enough arguments.\n";
        std::cout << "Usage: " << argv[0]
                  << " {-name | -pid} {-func | -hide}\n";
        exit(1);
    }

    for (int i = 1; i < argc; i++) {
        switch (cur_arg) {
            case Arg::Unknown:
                if (!(i % 2)) {
                    std::cout << "[!] Unknown arg '" << argv[i] << "'\n";
                    return 1;
                }
                break;
            case Arg::Pid:
                config.pid = std::atoi(argv[i]);
                cur_arg = Arg::Unknown;
                continue;
            case Arg::Name:
                config.process_name = argv[i];
                cur_arg = Arg::Unknown;
                continue;
            case Arg::Func:
                config.func_name = argv[i];
                cur_arg = Arg::Unknown;
                continue;
            case Arg::Hide:
                config.hide_file_name = argv[i];
                cur_arg = Arg::Unknown;
                continue;
        }

        if (!strcmp(argv[i], "-pid")) {
            cur_arg = Arg::Pid;
            continue;
        } else if (!strcmp(argv[i], "-name")) {
            cur_arg = Arg::Name;
            continue;
        } else if (!strcmp(argv[i], "-func")) {
            cur_arg = Arg::Func;
            continue;
        } else if (!strcmp(argv[i], "-hide")) {
            cur_arg = Arg::Hide;
            continue;
        }
    }

    if (injector::inject(config)) {
        std::cout << "[!] Injection failed :(\n";
        return 2;
    }

    return 0;
}
