#ifndef INJECTOR_HPP
#define INJECTOR_HPP

#include <cstdint>

namespace injector {
struct Config {
    int64_t pid;
    const char *process_name;
    const char *func_name;
    const char *hide_file_name;
};

bool inject(const Config &config);
}  // namespace injector

#endif
