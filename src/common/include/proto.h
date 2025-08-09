#ifndef H_COMMON_INCLUDE_PROTO_H
#define H_COMMON_INCLUDE_PROTO_H

#include <cstdint>
#include <optional>
#include <string>
#include <iostream>

#include "io.h"

namespace proto {
enum class MsgType : uint8_t {
    Config = 0x01,
    Log,
};

enum class Mode : uint8_t {
    Filter = 0x01,
    Log,
};

struct Config {
    Mode mode;
    std::string name;
};

inline constexpr std::uint32_t MAX_STR = 260;
inline bool write_u8(io::IStream *s, std::uint8_t v) { return s->write(&v, 1); }
inline bool read_u8(io::IStream *s, std::uint8_t &v) { return s->read(&v, 1); }
inline bool write_u32_be(io::IStream *s, std::uint32_t v) {
    std::uint8_t buf[4]{static_cast<std::uint8_t>((v >> 24) & 0xFF),
                        static_cast<std::uint8_t>((v >> 16) & 0xFF),
                        static_cast<std::uint8_t>((v >> 8) & 0xFF),
                        static_cast<std::uint8_t>(v & 0xFF)};
    return s->write(buf, 4);
}
inline bool read_u32_be(io::IStream *s, std::uint32_t &v) {
    std::uint8_t buf[4];
    if (!s->read(buf, 4)) return false;
    v = (std::uint32_t(buf[0]) << 24) | (std::uint32_t(buf[1]) << 16) |
        (std::uint32_t(buf[2]) << 8) | (std::uint32_t(buf[3]));
    return true;
}
inline bool write_string(io::IStream *s, std::string_view sv) {
    if (sv.size() > 0xFFFFFFFFu) return false;
    if (!write_u32_be(s, static_cast<std::uint32_t>(sv.size()))) return false;
    if (sv.empty()) return true;
    return s->write(reinterpret_cast<const std::uint8_t *>(sv.data()),
                    sv.size());
}
inline std::optional<std::string> read_string(io::IStream *s) {
    std::uint32_t len{};
    if (!read_u32_be(s, len)) return std::nullopt;
    if (len > MAX_STR) return std::nullopt;
    std::string out(len, '\0');
    if (len && !s->read(reinterpret_cast<std::uint8_t *>(&out[0]), len))
        return std::nullopt;
    return out;
}

inline bool send_config(io::IStream *s, const Config &cfg) {
    return write_u8(s, static_cast<std::uint8_t>(MsgType::Config)) &&
           write_u8(s, static_cast<std::uint8_t>(cfg.mode)) &&
           write_string(s, cfg.name);
}

inline std::optional<Config> recv_config(io::IStream *s) {
    std::uint8_t t{};
    if (!read_u8(s, t)) return std::nullopt;
    if (t != static_cast<std::uint8_t>(MsgType::Config)) return std::nullopt;
    std::uint8_t m{};
    if (!read_u8(s, m)) return std::nullopt;
    auto name = read_string(s);
    if (!name) return std::nullopt;
    return Config{static_cast<Mode>(m), *name};
}

inline bool send_log(io::IStream *s, std::string_view msg) {
    std::cout << "[*] Sending log into 0x" << std::hex
              << reinterpret_cast<uint64_t>(s) << "\n";
    return write_u8(s, static_cast<std::uint8_t>(MsgType::Log)) &&
           write_string(s, msg);
}
inline std::optional<std::string> recv_log(io::IStream *s) {
    std::uint8_t t{};
    if (!read_u8(s, t)) return std::nullopt;
    if (t != static_cast<std::uint8_t>(MsgType::Log)) return std::nullopt;
    return read_string(s);
}
}  // namespace proto

#endif
