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
#endif
}  // namespace hooks::filter

#endif
