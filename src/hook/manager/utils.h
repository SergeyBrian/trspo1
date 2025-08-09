#ifndef H_SRC_HOOK_MANAGER_UTILS_H
#define H_SRC_HOOK_MANAGER_UTILS_H

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
using TlsKey = DWORD;
#else
#include <pthread.h>

using TlsKey = pthread_key_t;
#endif

#include <string>

void *get_func_ptr(const std::string &lib_name, const std::string &func_name);
TlsKey alloc_tls();
void *get_page(void *p);

#endif  // H_SRC_HOOK_MANAGER_UTILS_H
