#pragma once
#include <cstdint>
#include <algorithm>
#include "core/Packet.hpp"

namespace decode {

struct IPv4Header {
    std::uint8_t version{4};
    std::uint8_t ihl_bytes{20};
    std::uint16_t totalLength{0};
    std::uint8_t protocol{0};
    std::uint8_t ttl{0};
    std::uint32_t src{0};
    std::uint32_t dst{0};
};

inline bool parse_ipv4(core::ByteSpan bytes, IPv4Header &out, core::ByteSpan &payload) {
    if (bytes.size() < 20) return false;
    std::uint8_t vihl = bytes[0];
    out.version = vihl >> 4;
    std::uint8_t ihl_words = vihl & 0x0F;
    out.ihl_bytes = static_cast<std::uint8_t>(ihl_words * 4);
    if (out.version != 4 || out.ihl_bytes < 20 || bytes.size() < out.ihl_bytes) return false;
    out.totalLength = static_cast<std::uint16_t>((bytes[2] << 8) | bytes[3]);
    out.ttl = bytes[8];
    out.protocol = bytes[9];
    out.src = (static_cast<std::uint32_t>(bytes[12]) << 24) |
              (static_cast<std::uint32_t>(bytes[13]) << 16) |
              (static_cast<std::uint32_t>(bytes[14]) << 8)  |
               static_cast<std::uint32_t>(bytes[15]);
    out.dst = (static_cast<std::uint32_t>(bytes[16]) << 24) |
              (static_cast<std::uint32_t>(bytes[17]) << 16) |
              (static_cast<std::uint32_t>(bytes[18]) << 8)  |
               static_cast<std::uint32_t>(bytes[19]);

    std::size_t total = out.totalLength ? std::min<std::size_t>(out.totalLength, bytes.size()) : bytes.size();
    if (total < out.ihl_bytes) return false;
    payload = bytes.subspan(out.ihl_bytes, total - out.ihl_bytes);
    return true;
}

} // namespace decode
