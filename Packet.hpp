#pragma once
#include <cstdint>
#include <vector>
#include <chrono>
#include <span>

namespace core {
    enum class LinkType : uint16_t { None = 0, Ethernet = 1 };

    struct Packet {
        std::chrono::steady_clock::time_point ts{};
        std::vector<std::uint8_t> bytes{};
        LinkType link{LinkType::Ethernet};
    };

    using ByteSpan = std::span<const std::uint8_t>;
}
