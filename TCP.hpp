#pragma once
#include <cstdint>
#include "core/Packet.hpp"

namespace decode {

struct TCPHeader {
    std::uint16_t srcPort{0};
    std::uint16_t dstPort{0};
    std::uint32_t seq{0};
    std::uint32_t ack{0};
    std::uint8_t dataOffsetBytes{20};
    std::uint8_t flags{0};
};

inline bool parse_tcp(core::ByteSpan bytes, TCPHeader &out, core::ByteSpan &payload) {
    if (bytes.size() < 20) return false;
    out.srcPort = static_cast<std::uint16_t>((bytes[0] << 8) | bytes[1]);
    out.dstPort = static_cast<std::uint16_t>((bytes[2] << 8) | bytes[3]);
    out.seq = (static_cast<std::uint32_t>(bytes[4]) << 24) |
              (static_cast<std::uint32_t>(bytes[5]) << 16) |
              (static_cast<std::uint32_t>(bytes[6]) << 8)  |
               static_cast<std::uint32_t>(bytes[7]);
    out.ack = (static_cast<std::uint32_t>(bytes[8]) << 24) |
              (static_cast<std::uint32_t>(bytes[9]) << 16) |
              (static_cast<std::uint32_t>(bytes[10]) << 8)  |
               static_cast<std::uint32_t>(bytes[11]);
    std::uint8_t dataOffset = (bytes[12] >> 4) & 0x0F;
    out.dataOffsetBytes = static_cast<std::uint8_t>(dataOffset * 4);
    out.flags = bytes[13];
    if (out.dataOffsetBytes < 20 || bytes.size() < out.dataOffsetBytes) return false;
    payload = bytes.subspan(out.dataOffsetBytes);
    return true;
}

} // namespace decode
