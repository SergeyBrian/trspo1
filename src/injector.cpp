#include "injector.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>

static const char *dll_name = "hook";

namespace injector {
std::string get_dll_full_path() {
    char fullPath[MAX_PATH] = {0};

    DWORD result =
        SearchPathA(nullptr, dll_name, ".dll", MAX_PATH, fullPath, nullptr);

    if (result == 0) {
        std::cerr << "[!] Can't find " << dll_name << ".dll" << std::endl;
        return "";
    }

    return std::string(fullPath);
}

bool inject(const Config &config) {
    std::string dll_full_path = get_dll_full_path();
    std::cout << dll_full_path << "\n";
    std::cout << "[*] Pid: " << config.pid << "\n";

    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        false, config.pid);
    if (!proc) {
        std::cout << "[!] Failed to open proccess with pid " << config.pid
                  << "\n";
        std::cout << GetLastError() << "\n";
        return 1;
    }

    auto new_mem = VirtualAllocEx(proc, nullptr, dll_full_path.size() + 1,
                                  MEM_COMMIT, PAGE_READWRITE);
    if (!new_mem) {
        std::cout << "[!] Failed to allocate memory :(\n"
                  << GetLastError() << "\n";
        return 1;
    }

    SIZE_T tmp{};
    if (!WriteProcessMemory(proc, new_mem, dll_full_path.c_str(),
                            dll_full_path.size() + 1, &tmp)) {
        std::cout << "[!] Failed to write memory\n" << GetLastError() << "\n";
        return 1;
    }

    LPVOID loadLibrary = (LPVOID)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibrary) {
        std::cout << "[!] GetProcAddress failed\n" << GetLastError() << "\n";
        return 1;
    }
    auto thread = CreateRemoteThread(
        proc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary),
        new_mem, 0, nullptr);
    if (!thread) {
        std::cout << "[!] Failed to create thread\n" << GetLastError() << "\n";
        return 1;
    }

    std::cout << "Success\n";

    WaitForSingleObject(thread, INFINITE);

    return 0;
}
}  // namespace injector
