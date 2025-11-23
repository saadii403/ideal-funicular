#pragma once
#include <cstdint>
#include "core/Packet.hpp"

namespace decode {

struct EthernetHeader {
    std::uint8_t dst[6]{};
    std::uint8_t src[6]{};
    std::uint16_t ethertype{0};
};

inline bool parse_ethernet(core::ByteSpan bytes, EthernetHeader &out, core::ByteSpan &payload) {
    if (bytes.size() < 14) return false;
    for (int i = 0; i < 6; ++i) out.dst[i] = bytes[i];
    for (int i = 0; i < 6; ++i) out.src[i] = bytes[6 + i];
    out.ethertype = static_cast<std::uint16_t>((bytes[12] << 8) | bytes[13]);
    payload = bytes.subspan(14);
    return true;
}

} // namespace decode
