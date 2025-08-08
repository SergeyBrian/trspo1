#ifndef H_INJECTOR_UTILS_H
#define H_INJECTOR_UTILS_H

#include <string>
#include <cstdint>

uint64_t get_pid_by_name(const char *name);
std::string get_full_path(const std::string &base);
void *inject(int64_t pid, const std::string &lib);
void wait(void *t);

#endif
