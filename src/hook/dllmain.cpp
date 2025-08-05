#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>

#include "common/include/tcp.h"
#include "common/include/proto.h"

#include "hook/manager/manager.h"
#include "hook/hooks/tcp_logger.h"
#include "hook/hooks/filter.h"

void OpenConsole() {
    AllocConsole();
    freopen_s((FILE **)stdout, "CONOUT$", "w", stdout);
    std::cout << "Hello" << std::endl;
}

DWORD WINAPI Main(LPVOID) {
    auto mngr = HookManager::Instance();
    auto stream = net::TcpStream::connect("127.0.0.1", "6969");
    if (!stream) {
        return 1;
    }

    auto cfg = proto::recv_config(stream.get());
    if (!cfg) return 1;

    proto::send_log(stream.get(), "Hello from dll");

    switch (cfg->mode) {
        case proto::Mode::Filter:
            hooks::filter::SetHideStrig(cfg->name);
            /*mngr->add_patch("kernel32.dll", "CreateFileA",*/
            /*                hooks::filter::CreateFileA());*/
            /*mngr->add_patch("kernel32.dll", "FindNextFileA",*/
            /*                hooks::filter::FindNextFileA());*/
            /*mngr->add_patch("kernel32.dll", "FindFirstFileA",*/
            /*                hooks::filter::FindFirstFileA());*/
            mngr->add_patch("kernel32.dll", "CreateFileW",
                            hooks::filter::CreateFileW());
            /*mngr->add_patch("kernel32.dll", "FindNextFileW",*/
            /*                hooks::filter::FindNextFileW());*/
            /*mngr->add_patch("kernel32.dll", "FindFirstFileW",*/
            /*                hooks::filter::FindFirstFileW());*/
            break;
        case proto::Mode::Log:
            mngr->add_patch(
                "kernel32.dll", cfg->name,
                hooks::tcp_logger::Logger(cfg->name.c_str(), stream.get()));
            break;
    }

    Sleep(INFINITE);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        OpenConsole();
        CreateThread(NULL, 0, Main, NULL, 0, NULL);
    }
    return TRUE;
}
