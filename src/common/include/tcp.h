#ifndef H_COMMON_INCLUDE_TCP_H
#define H_COMMON_INCLUDE_TCP_H

#include <memory>
#include <string_view>
#include <cstdint>

#include "io.h"

namespace net {
class TcpStream : public io::IStream {
public:
    TcpStream() = default;
    ~TcpStream() override;

    TcpStream(const TcpStream &) = delete;
    TcpStream &operator=(const TcpStream &) = delete;
    TcpStream(TcpStream &&) noexcept;
    TcpStream &operator=(TcpStream &&) noexcept;

    static std::unique_ptr<TcpStream> connect(std::string_view host,
                                              std::string_view port);

    bool write(const std::uint8_t *data, std::size_t len) override;
    bool read(std::uint8_t *data, std::size_t len) override;
    void close() override;

private:
    struct Impl;
    Impl *pimpl_ = nullptr;
    friend class TcpListener;
    explicit TcpStream(Impl *impl);
};

class TcpListener {
public:
    TcpListener() = default;
    ~TcpListener();

    TcpListener(const TcpListener &) = delete;
    TcpListener &operator=(const TcpListener &) = delete;
    TcpListener(TcpListener &&) noexcept;
    TcpListener &operator=(TcpListener &&) noexcept;

    static std::unique_ptr<TcpListener> bind(std::string_view bind_ip,
                                             std::string_view port);

    std::unique_ptr<TcpStream> accept();

    void close();

private:
    struct Impl;
    Impl *pimpl_ = nullptr;
};
}  // namespace net

#endif
