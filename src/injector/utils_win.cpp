#ifdef _WIN32
#include "utils.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <iostream>
#include <cstring>

uint64_t get_pid_by_name(const char *name) {
    uint64_t pid{};
    WCHAR name[MAX_PATH];
    size_t tmp;
    mbstowcs_s(&tmp, name, name, strlen(name));
    std::wcout << "[*] Name: " << name << "\n";

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cout << "[!] CreateToolhelp32Snapshot failed\n";
        return 0;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnapshot, &pe)) {
        std::cout << "[!] Process32FirstW failed\n";
        return 0;
    }
    do {
        if (_wcsicmp(pe.szExeFile, name) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnapshot, &pe));
    CloseHandle(hSnapshot);
    return pid;
}

std::string get_full_path(const std::string &base) {
    char fullPath[MAX_PATH] = {0};

    DWORD result =
        SearchPathA(nullptr, base.c_str(), ".dll", MAX_PATH, fullPath, nullptr);

    if (result == 0) {
        std::cerr << "[!] Can't find " << base << ".dll" << std::endl;
        return "";
    }

    return std::string(fullPath);
}

void *inject(int64_t pid, const std::string &lib) {
    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        false, pid);
    if (!proc) {
        std::cout << "[!] Failed to open proccess with pid " << pid << "\n";
        return nullptr;
    }

    auto new_mem = VirtualAllocEx(proc, nullptr, lib.size() + 1, MEM_COMMIT,
                                  PAGE_READWRITE);
    if (!new_mem) {
        std::cout << "[!] Failed to allocate memory :(\n"
                  << GetLastError() << "\n";
        return nullptr;
    }

    SIZE_T tmp{};
    if (!WriteProcessMemory(proc, new_mem, lib.c_str(), lib.size() + 1, &tmp)) {
        std::cout << "[!] Failed to write memory\n" << GetLastError() << "\n";
        return nullptr;
    }

    LPVOID loadLibrary = (LPVOID)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibrary) {
        std::cout << "[!] GetProcAddress failed\n" << GetLastError() << "\n";
        return nullptr;
    }
    auto thread = CreateRemoteThread(
        proc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary),
        new_mem, 0, nullptr);
    if (!thread) {
        std::cout << "[!] Failed to create thread\n" << GetLastError() << "\n";
        return nullptr;
    }

    return thread;
}

void wait(void *t) { WaitForSingleObject(t, INFINITE); }
#endif
