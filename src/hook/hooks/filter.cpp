#include "filter.h"

#include <iostream>

#include "hook/manager/manager.h"

namespace hooks::filter {
static std::string hidden_str;

bool is_allowed(const char *s) {
    if (hidden_str.empty()) return true;

    char hidden[MAX_PATH]{};
    char requested[MAX_PATH]{};

    GetFullPathNameA(hidden_str.c_str(), MAX_PATH, hidden, nullptr);
    GetFullPathNameA(s, MAX_PATH, requested, nullptr);

    return strcmp(hidden, requested);
}

bool is_wallowed(const wchar_t *s) {
    if (hidden_str.empty()) return true;

    wchar_t hidden[MAX_PATH]{};
    wchar_t requested[MAX_PATH]{};

    GetFullPathNameW(std::wstring(hidden_str.begin(), hidden_str.end()).c_str(),
                     MAX_PATH, hidden, nullptr);
    GetFullPathNameW(s, MAX_PATH, requested, nullptr);

    return wcscmp(hidden, requested);
}

HANDLE
WINAPI
filter_CreateFileA(_In_ LPCSTR lpFileName, _In_ DWORD dwDesiredAccess,
                   _In_ DWORD dwShareMode,
                   _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                   _In_ DWORD dwCreationDisposition,
                   _In_ DWORD dwFlagsAndAttributes,
                   _In_opt_ HANDLE hTemplateFile) {
    std::cout << "[*] filter_CreateFileA begin (" << lpFileName << ")\n";

    std::cout << "[*] filter_CreateFileA end. ";
    if (!is_allowed(lpFileName)) {
        std::cout << "block\n";
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    std::cout << "allow\n";
    return HookManager::Instance()
        ->get_trampoline<decltype(&filter_CreateFileA)>("CreateFileA")(
            lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
            dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI filter_FindNextFileA(_In_ HANDLE hFindFile,
                                 _Out_ LPWIN32_FIND_DATAA lpFindFileData) {
    std::cout << "[*] filter_FindNextFileA begin (" << lpFindFileData->cFileName
              << ")\n";
    auto orig =
        HookManager::Instance()
            ->get_trampoline<decltype(&filter_FindNextFileA)>("FindNextFileA");
    bool res{};
    std::cout << "[*] filter_CreateFileA end. ";

    if (!is_allowed(lpFindFileData->cFileName)) {
        std::cout << "block\n";
        return false;
    }
    std::cout << "allow\n";
    return orig(hFindFile, lpFindFileData);
}

HANDLE
WINAPI
filter_FindFirstFileA(_In_ LPCSTR lpFileName,
                      _Out_ LPWIN32_FIND_DATAA lpFindFileData) {
    std::cout << "[*] filter_FindFirstFileA begin (" << lpFileName << ")\n";
    auto orig = HookManager::Instance()
                    ->get_trampoline<decltype(&filter_FindFirstFileA)>(
                        "FindFirstFileA");
    std::cout << "[*] filter_CreateFileA end. ";
    if (!is_allowed(lpFileName)) {
        std::cout << "block\n";
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    HANDLE res = orig(lpFileName, lpFindFileData);
    if (!is_allowed(lpFindFileData->cFileName)) {
        std::cout << "block\n";
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    std::cout << "allow\n";

    return res;
}

HANDLE
WINAPI
filter_CreateFileW(_In_ LPCWSTR lpFileName, _In_ DWORD dwDesiredAccess,
                   _In_ DWORD dwShareMode,
                   _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                   _In_ DWORD dwCreationDisposition,
                   _In_ DWORD dwFlagsAndAttributes,
                   _In_opt_ HANDLE hTemplateFile) {
    std::wcout << "[*] filter_CreateFileW begin (" << lpFileName << ")\n";

    std::cout << "[*] filter_CreateFileW end. ";
    if (!is_wallowed(lpFileName)) {
        std::cout << "block\n";
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    std::cout << "allow\n";
    return HookManager::Instance()
        ->get_trampoline<decltype(&filter_CreateFileW)>("CreateFileW")(
            lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
            dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI filter_FindNextFileW(_In_ HANDLE hFindFile,
                                 _Out_ LPWIN32_FIND_DATAW lpFindFileData) {
    std::wcout << "[*] filter_FindNextFileW begin ("
               << lpFindFileData->cFileName << ")\n";
    auto orig =
        HookManager::Instance()
            ->get_trampoline<decltype(&filter_FindNextFileW)>("FindNextFileW");
    bool res{};
    std::cout << "[*] filter_CreateFileW end. ";

    if (!is_wallowed(lpFindFileData->cFileName)) {
        std::cout << "block\n";
        return false;
    }
    std::cout << "allow\n";
    return orig(hFindFile, lpFindFileData);
}

HANDLE
WINAPI
filter_FindFirstFileW(_In_ LPCSTR lpFileName,
                      _Out_ LPWIN32_FIND_DATAA lpFindFileData) {
    std::cout << "[*] filter_FindFirstFileW begin (" << lpFileName << ")\n";
    auto orig = HookManager::Instance()
                    ->get_trampoline<decltype(&filter_FindFirstFileW)>(
                        "FindFirstFileW");
    std::cout << "[*] filter_CreateFileW end. ";
    if (!is_allowed(lpFileName)) {
        std::cout << "block\n";
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    HANDLE res = orig(lpFileName, lpFindFileData);
    if (!is_allowed(lpFindFileData->cFileName)) {
        std::cout << "block\n";
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    std::cout << "allow\n";

    return res;
}

void SetHideStrig(const std::string &s) { hidden_str = s; }

void *CreateFileA() { return reinterpret_cast<void *>(&filter_CreateFileA); }
void *FindNextFileA() {
    return reinterpret_cast<void *>(&filter_FindNextFileA);
}
void *FindFirstFileA() {
    return reinterpret_cast<void *>(&filter_FindFirstFileA);
}
void *CreateFileW() { return reinterpret_cast<void *>(&filter_CreateFileW); }
void *FindNextFileW() {
    return reinterpret_cast<void *>(&filter_FindNextFileW);
}
void *FindFirstFileW() {
    return reinterpret_cast<void *>(&filter_FindFirstFileW);
}
}  // namespace hooks::filter
