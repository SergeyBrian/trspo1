#include "filter.h"

#include <iostream>
#include <cstdarg>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <sys/types.h>
#include <cstring>

#include "hook/manager/manager.h"

namespace hooks::filter {
static std::string hidden_str;
void SetHideStrig(const std::string &s) { hidden_str = s; }

bool is_allowed(const char *s) {
    if (hidden_str.empty()) return true;

    return !strcmp(s, hidden_str.c_str());
}

template <class Fn>
static Fn tramp(const char *name) {
    return HookManager::Instance()->get_trampoline<Fn>(name);
}

static void safe_log(const char *msg) { ::write(2, msg, strlen(msg)); }

FILE *filter_fopen(const char *__restrict filename,
                   const char *__restrict modes) {
    std::cout << "[!] fopen: " << filename << "\n";
    if (is_allowed(filename)) {
        std::cout << "    -> block\n";
        errno = EACCES;
        return nullptr;
    }
    std::cout << "    -> allow\n";
    using fn_t = FILE *(*)(const char *, const char *);
    return tramp<fn_t>("fopen")(filename, modes);
}

void *fopen() { return reinterpret_cast<void *>(&filter_fopen); }

FILE *filter_fopen64(const char *__restrict filename,
                     const char *__restrict modes) {
    std::cout << "[!] fopen64: " << filename << "\n";
    if (is_allowed(filename)) {
        std::cout << "    -> block\n";
        errno = EACCES;
        return nullptr;
    }
    std::cout << "    -> allow\n";
    using fn_t = FILE *(*)(const char *, const char *);
    return tramp<fn_t>("fopen64")(filename, modes);
}
void *fopen64() { return reinterpret_cast<void *>(&filter_fopen64); }

int filter_open(const char *pathname, int flags, ...) {
    // достанем mode при O_CREAT
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    std::cout << "[!] open: " << pathname << " flags=0x" << std::hex << flags
              << std::dec << "\n";
    if (is_allowed(pathname)) {
        std::cout << "    -> block\n";
        errno = EACCES;
        return -1;
    }
    std::cout << "    -> allow\n";

    using fn_t = int (*)(const char *, int, ...);
    auto orig = tramp<fn_t>("open");
    if (flags & O_CREAT) return orig(pathname, flags, mode);
    return orig(pathname, flags);
}
void *open() { return reinterpret_cast<void *>(&filter_open); }

int filter_open64(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    std::cout << "[!] open64: " << pathname << " flags=0x" << std::hex << flags
              << std::dec << "\n";
    if (is_allowed(pathname)) {
        std::cout << "    -> block\n";
        errno = EACCES;
        return -1;
    }
    std::cout << "    -> allow\n";

    using fn_t = int (*)(const char *, int, ...);
    auto orig = tramp<fn_t>("open64");
    if (flags & O_CREAT) return orig(pathname, flags, mode);
    return orig(pathname, flags);
}
void *open64() { return reinterpret_cast<void *>(&filter_open64); }

int filter_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    std::cout << "[!] openat: dirfd=" << dirfd << " path=" << pathname
              << " flags=0x" << std::hex << flags << std::dec << "\n";

    if (is_allowed(pathname)) {
        std::cout << "    -> block\n";
        errno = EACCES;
        return -1;
    }
    std::cout << "    -> allow\n";

    using fn_t = int (*)(int, const char *, int, ...);
    auto orig = tramp<fn_t>("openat");
    if (flags & O_CREAT) return orig(dirfd, pathname, flags, mode);
    return orig(dirfd, pathname, flags);
}
void *openat() { return reinterpret_cast<void *>(&filter_openat); }

int filter_openat64(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    std::cout << "[!] openat64: dirfd=" << dirfd << " path=" << pathname
              << " flags=0x" << std::hex << flags << std::dec << "\n";

    if (is_allowed(pathname)) {
        std::cout << "    -> block\n";
        errno = EACCES;
        return -1;
    }
    std::cout << "    -> allow\n";

    using fn_t = int (*)(int, const char *, int, ...);
    auto orig = tramp<fn_t>("openat64");
    if (flags & O_CREAT) return orig(dirfd, pathname, flags, mode);
    return orig(dirfd, pathname, flags);
}
void *openat64() { return reinterpret_cast<void *>(&filter_openat64); }

int filter_creat(const char *pathname, mode_t mode) {
    std::cout << "[!] creat: " << pathname << " mode=0" << std::oct << mode
              << std::dec << "\n";
    if (is_allowed(pathname)) {
        std::cout << "    -> block\n";
        errno = EACCES;
        return -1;
    }
    std::cout << "    -> allow\n";
    using fn_t = int (*)(const char *, mode_t);
    return tramp<fn_t>("creat")(pathname, mode);
}
void *creat() { return reinterpret_cast<void *>(&filter_creat); }

int filter_creat64(const char *pathname, mode_t mode) {
    std::cout << "[!] creat64: " << pathname << " mode=0" << std::oct << mode
              << std::dec << "\n";
    if (is_allowed(pathname)) {
        std::cout << "    -> block\n";
        errno = EACCES;
        return -1;
    }
    std::cout << "    -> allow\n";
    using fn_t = int (*)(const char *, mode_t);
    return tramp<fn_t>("creat64")(pathname, mode);
}
void *creat64() { return reinterpret_cast<void *>(&filter_creat64); }
}  // namespace hooks::filter
