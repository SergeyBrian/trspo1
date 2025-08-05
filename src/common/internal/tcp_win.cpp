#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <mutex>
#include <string>
#include <string_view>
#include <memory>
#include <algorithm>
#include <iostream>
#include "common/include/tcp.h"

namespace {
std::once_flag g_wsa_once;
void ensure_wsa() {
    std::call_once(g_wsa_once, [] {
        WSADATA wsa{};
        int r = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (r != 0) {
            std::cerr << "WSAStartup failed: " << r << "\n";
            std::abort();
        }
    });
}
}  // namespace

namespace net {

struct TcpStream::Impl {
    SOCKET s = INVALID_SOCKET;
    ~Impl() {
        if (s != INVALID_SOCKET) ::closesocket(s);
    }
};

struct TcpListener::Impl {
    SOCKET s = INVALID_SOCKET;
    ~Impl() {
        if (s != INVALID_SOCKET) ::closesocket(s);
    }
};

TcpStream::~TcpStream() {
    if (pimpl_) delete pimpl_;
}
TcpStream::TcpStream(TcpStream &&o) noexcept { std::swap(pimpl_, o.pimpl_); }
TcpStream &TcpStream::operator=(TcpStream &&o) noexcept {
    std::swap(pimpl_, o.pimpl_);
    return *this;
}
TcpStream::TcpStream(Impl *impl) { pimpl_ = impl; }

std::unique_ptr<TcpStream> TcpStream::connect(std::string_view host,
                                              std::string_view port) {
    ensure_wsa();
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo *res = nullptr;
    if (::getaddrinfo(std::string(host).c_str(), std::string(port).c_str(),
                      &hints, &res) != 0)
        return nullptr;

    SOCKET s = INVALID_SOCKET;
    for (auto *p = res; p; p = p->ai_next) {
        s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        if (::connect(s, p->ai_addr, int(p->ai_addrlen)) == 0) {
            break;
        }
        ::closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (s == INVALID_SOCKET) return nullptr;

    auto tp = std::make_unique<TcpStream>();
    tp->pimpl_ = new Impl{s};
    return tp;
}

bool TcpStream::write(const std::uint8_t *data, std::size_t len) {
    if (!pimpl_ || pimpl_->s == INVALID_SOCKET) return false;
    std::size_t sent = 0;
    while (sent < len) {
        int n = ::send(pimpl_->s, reinterpret_cast<const char *>(data + sent),
                       (int)std::min<std::size_t>(len - sent, 1 << 30), 0);
        if (n == SOCKET_ERROR || n == 0) return false;
        sent += (std::size_t)n;
    }
    return true;
}
bool TcpStream::read(std::uint8_t *data, std::size_t len) {
    if (!pimpl_ || pimpl_->s == INVALID_SOCKET) return false;
    std::size_t recvd = 0;
    while (recvd < len) {
        int n = ::recv(pimpl_->s, reinterpret_cast<char *>(data + recvd),
                       (int)std::min<std::size_t>(len - recvd, 1 << 30), 0);
        if (n == SOCKET_ERROR || n == 0) return false;
        recvd += (std::size_t)n;
    }
    return true;
}
void TcpStream::close() {
    if (pimpl_ && pimpl_->s != INVALID_SOCKET) {
        ::closesocket(pimpl_->s);
        pimpl_->s = INVALID_SOCKET;
    }
}

TcpListener::~TcpListener() {
    if (pimpl_) delete pimpl_;
}
TcpListener::TcpListener(TcpListener &&o) noexcept {
    std::swap(pimpl_, o.pimpl_);
}
TcpListener &TcpListener::operator=(TcpListener &&o) noexcept {
    std::swap(pimpl_, o.pimpl_);
    return *this;
}

std::unique_ptr<TcpListener> TcpListener::bind(std::string_view bind_ip,
                                               std::string_view port) {
    ensure_wsa();
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    addrinfo *res = nullptr;
    if (::getaddrinfo(std::string(bind_ip).c_str(), std::string(port).c_str(),
                      &hints, &res) != 0)
        return nullptr;

    SOCKET s = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        return nullptr;
    }

    BOOL yes = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char *>(&yes), sizeof(yes));

    if (::bind(s, res->ai_addr, int(res->ai_addrlen)) == SOCKET_ERROR) {
        ::closesocket(s);
        freeaddrinfo(res);
        return nullptr;
    }
    freeaddrinfo(res);
    if (::listen(s, SOMAXCONN) == SOCKET_ERROR) {
        ::closesocket(s);
        return nullptr;
    }

    auto lst = std::make_unique<TcpListener>();
    lst->pimpl_ = new Impl{s};
    return lst;
}

std::unique_ptr<TcpStream> TcpListener::accept() {
    if (!pimpl_ || pimpl_->s == INVALID_SOCKET) return nullptr;
    SOCKET c = ::accept(pimpl_->s, nullptr, nullptr);
    if (c == INVALID_SOCKET) return nullptr;
    auto tp = std::make_unique<TcpStream>();
    tp->pimpl_ = new TcpStream::Impl{c};
    return tp;
}

void TcpListener::close() {
    if (pimpl_ && pimpl_->s != INVALID_SOCKET) {
        ::closesocket(pimpl_->s);
        pimpl_->s = INVALID_SOCKET;
    }
}

}  // namespace net
#endif
