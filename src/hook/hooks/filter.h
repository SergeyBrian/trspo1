#ifndef H_HOOK_HOOKS_FILTER_H
#define H_HOOK_HOOKS_FILTER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>

namespace hooks::filter {
void SetHideStrig(const std::string &filter);
void *CreateFileA();
void *FindNextFileA();
void *FindFirstFileA();
void *CreateFileW();
void *FindNextFileW();
void *FindFirstFileW();
}  // namespace hooks::filter

#endif
