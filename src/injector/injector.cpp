#include "injector.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <iostream>

#include "common/include/tcp.h"
#include "common/include/proto.h"

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
    int64_t pid = config.pid;

    if (!config.pid) {
        if (!strlen(config.process_name)) {
            std::cout << "[!] Please specify pid or process name\n";
            return 1;
        }
        WCHAR name[MAX_PATH];
        size_t tmp;
        mbstowcs_s(&tmp, name, config.process_name,
                   strlen(config.process_name));
        std::wcout << "[*] Name: " << name << "\n";

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            std::cout << "[!] CreateToolhelp32Snapshot failed\n";
            return 1;
        }

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (!Process32FirstW(hSnapshot, &pe)) {
            std::cout << "[!] Process32FirstW failed\n";
            return 1;
        }
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
        CloseHandle(hSnapshot);
    }

    std::cout << "[*] Pid: " << pid << "\n";

    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        false, pid);
    if (!proc) {
        std::cout << "[!] Failed to open proccess with pid " << pid << "\n";
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

    auto listener = net::TcpListener::bind("127.0.0.1", "6969");
    if (!listener) {
        std::cout << "[!] Failed to bind to tcp socket\n";
        return 1;
    }

    auto stream = listener->accept();
    if (!stream) {
        std::cout << "[!] Accept failed\n";
        return 1;
    }
    std::cout << "[+] Successfully connected\n";

    proto::Mode mode{};
    std::string s{};

    if (config.hide_file_name) {
        mode = proto::Mode::Filter;
        s = config.hide_file_name;
    } else {
        mode = proto::Mode::Log;
        s = config.func_name;
    }

    auto cfg = proto::Config{mode, s};

    proto::send_config(stream.get(), cfg);

    while (true) {
        auto log = proto::recv_log(stream.get());
        if (!log) {
            std::cout << "[*] Connection closed!\n";
            break;
        }
        std::cout << "[+] Msg: " << *log << "\n";
    }

    stream->close();
    listener->close();

    WaitForSingleObject(thread, INFINITE);

    return 0;
}
}  // namespace injector
