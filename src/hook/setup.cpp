#include "setup.h"

#include "manager/manager.h"
#include "common/include/tcp.h"
#include "common/include/proto.h"

#include "hooks/filter.h"
#include "hooks/tcp_logger.h"

void setup() {
    std::cout << "[+] setup()\n";
    auto mngr = HookManager::Instance();
    auto stream = net::TcpStream::connect("127.0.0.1", "6969");
    if (!stream) {
        std::cout << "[!] tcp connect failed\n";
        return;
    }
    std::cout << "[+] tcp connect success. waiting for config\n";

    auto cfg = proto::recv_config(stream.get());
    if (!cfg) {
        std::cout << "[!] failed to recv config\n";
        return;
    }
    std::cout << "[+] config received! Mode: "
              << (cfg->mode == proto::Mode::Filter ? "Filter" : "Log")
              << " Name: " << cfg->name << "\n";

    proto::send_log(stream.get(), "Hello from dll");

    switch (cfg->mode) {
        case proto::Mode::Filter:
            hooks::filter::SetHideStrig(cfg->name);
#ifdef _WIN32
            mngr->add_patch("kernel32.dll", "CreateFileA",
                            hooks::filter::CreateFileA());
            mngr->add_patch("kernel32.dll", "FindNextFileA",
                            hooks::filter::FindNextFileA());
            mngr->add_patch("kernel32.dll", "FindFirstFileA",
                            hooks::filter::FindFirstFileA());
            mngr->add_patch("kernel32.dll", "CreateFileW",
                            hooks::filter::CreateFileW());
            mngr->add_patch("kernel32.dll", "FindNextFileW",
                            hooks::filter::FindNextFileW());
            mngr->add_patch("kernel32.dll", "FindFirstFileW",
                            hooks::filter::FindFirstFileW());
#else
            mngr->add_patch("libc.so.6", "fopen", hooks::filter::fopen());
            mngr->add_patch("libc.so.6", "fopen64", hooks::filter::fopen64());
            mngr->add_patch("libc.so.6", "open", hooks::filter::open());
            mngr->add_patch("libc.so.6", "open64", hooks::filter::open64());
            mngr->add_patch("libc.so.6", "openat", hooks::filter::openat());
            mngr->add_patch("libc.so.6", "openat64", hooks::filter::openat64());
            mngr->add_patch("libc.so.6", "creat", hooks::filter::creat());
            mngr->add_patch("libc.so.6", "creat64", hooks::filter::creat64());
            mngr->add_patch("libc.so.6", "__libc_open", hooks::filter::open());
            mngr->add_patch("libc.so.6", "__libc_open64",
                            hooks::filter::open64());
            mngr->add_patch("libc.so.6", "__open", hooks::filter::open());
            mngr->add_patch("libc.so.6", "__open64", hooks::filter::open64());
            mngr->add_patch("libc.so.6", "__openat", hooks::filter::openat());
            mngr->add_patch("libc.so.6", "__openat64",
                            hooks::filter::openat64());
            mngr->add_patch("libglib-2.0.so.0", "g_open",
                            hooks::filter::open());
            mngr->add_patch("libglib-2.0.so.0", "g_creat",
                            hooks::filter::creat());
            mngr->add_patch("libglib-2.0.so.0", "g_fopen",
                            hooks::filter::fopen());
#endif
            break;
        case proto::Mode::Log:
#ifdef _WIN32
            mngr->add_patch(
                "kernel32.dll", cfg->name,
                hooks::tcp_logger::Logger(cfg->name.c_str(), stream.get()));
#else
            mngr->add_patch(
                "libc.so.6", cfg->name,
                hooks::tcp_logger::Logger(cfg->name.c_str(), stream.get()));
#endif
            break;
    }

    while (true) {
    }
}
