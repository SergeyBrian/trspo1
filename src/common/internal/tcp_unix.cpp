#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include <string>
#include <string_view>
#include <memory>
#include <algorithm>
#include "common/include/tcp.h"

namespace {
inline void ensure_wsa() {}
}  // namespace

namespace net {

struct TcpStream::Impl {
    int s = -1;
    ~Impl() {
        if (s != -1) ::close(s);
    }
};

struct TcpListener::Impl {
    int s = -1;
    ~Impl() {
        if (s != -1) ::close(s);
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

    int s = -1;
    for (auto *p = res; p; p = p->ai_next) {
        s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == -1) continue;
        if (::connect(s, p->ai_addr, int(p->ai_addrlen)) == 0) {
            break;
        }
        ::close(s);
        s = -1;
    }
    freeaddrinfo(res);
    if (s == -1) return nullptr;

    auto tp = std::make_unique<TcpStream>();
    tp->pimpl_ = new Impl{s};
    return tp;
}

bool TcpStream::write(const std::uint8_t *data, std::size_t len) {
    if (!pimpl_ || pimpl_->s == -1) return false;
    std::size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(
            pimpl_->s, reinterpret_cast<const char *>(data + sent),
            (size_t)std::min<std::size_t>(len - sent, size_t(1) << 30), 0);
        if (n <= 0) return false;
        sent += (std::size_t)n;
    }
    return true;
}
bool TcpStream::read(std::uint8_t *data, std::size_t len) {
    if (!pimpl_ || pimpl_->s == -1) return false;
    std::size_t recvd = 0;
    while (recvd < len) {
        ssize_t n = ::recv(
            pimpl_->s, reinterpret_cast<char *>(data + recvd),
            (size_t)std::min<std::size_t>(len - recvd, size_t(1) << 30), 0);
        if (n <= 0) return false;
        recvd += (std::size_t)n;
    }
    return true;
}
void TcpStream::close() {
    if (pimpl_ && pimpl_->s != -1) {
        ::close(pimpl_->s);
        pimpl_->s = -1;
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

    int s = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == -1) {
        freeaddrinfo(res);
        return nullptr;
    }

    int yes = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const void *>(&yes), sizeof(yes));

    if (::bind(s, res->ai_addr, int(res->ai_addrlen)) == -1) {
        ::close(s);
        freeaddrinfo(res);
        return nullptr;
    }
    freeaddrinfo(res);
    if (::listen(s, SOMAXCONN) == -1) {
        ::close(s);
        return nullptr;
    }

    auto lst = std::make_unique<TcpListener>();
    lst->pimpl_ = new Impl{s};
    return lst;
}

std::unique_ptr<TcpStream> TcpListener::accept() {
    if (!pimpl_ || pimpl_->s == -1) return nullptr;
    int c = ::accept(pimpl_->s, nullptr, nullptr);
    if (c == -1) return nullptr;
    auto tp = std::make_unique<TcpStream>();
    tp->pimpl_ = new TcpStream::Impl{c};
    return tp;
}

void TcpListener::close() {
    if (pimpl_ && pimpl_->s != -1) {
        ::close(pimpl_->s);
        pimpl_->s = -1;
    }
}

}  // namespace net
