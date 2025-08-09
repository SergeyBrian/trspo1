#ifndef H_HOOK_HOOKS_FILTER_H
#define H_HOOK_HOOKS_FILTER_H

#include <string>

namespace hooks::filter {
void SetHideStrig(const std::string &filter);
#ifdef _WIN32
void *CreateFileA();
void *FindNextFileA();
void *FindFirstFileA();
void *CreateFileW();
void *FindNextFileW();
void *FindFirstFileW();
#else
void *fopen();
void *fopen64();
void *open();
void *open64();
void *openat();
void *openat64();
void *creat();
void *creat64();
#endif
}  // namespace hooks::filter

#endif
