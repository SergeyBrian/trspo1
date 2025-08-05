#ifndef H_COMMON_INCLUDE_IO_H
#define H_COMMON_INCLUDE_IO_H

#include <cstddef>
#include <cstdint>

namespace io {
struct IStream {
    virtual ~IStream() = default;
    virtual bool write(const std::uint8_t *data, std::size_t len) = 0;
    virtual bool read(std::uint8_t *data, std::size_t len) = 0;
    virtual void close() = 0;
};
}  // namespace io

#endif
