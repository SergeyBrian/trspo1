#include "setup.h"

#include "manager/manager.h"
#include "common/include/tcp.h"
#include "common/include/proto.h"

#include "hooks/filter.h"
#include "hooks/tcp_logger.h"

void setup() {
    auto mngr = HookManager::Instance();
    auto stream = net::TcpStream::connect("127.0.0.1", "6969");
    if (!stream) {
        return;
    }

    auto cfg = proto::recv_config(stream.get());
    if (!cfg) return;

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
}
