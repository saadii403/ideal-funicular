#pragma once
#include <cstdint>
#include <chrono>
#include <functional>
#include <string>
#include "core/dsa/LRUCache.hpp"

namespace flow {

struct FlowKey {
    std::uint32_t src{}; // IPv4
    std::uint32_t dst{};
    std::uint16_t sport{};
    std::uint16_t dport{};
    std::uint8_t proto{};

    bool operator==(const FlowKey& o) const {
        return src==o.src && dst==o.dst && sport==o.sport && dport==o.dport && proto==o.proto;
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const noexcept {
        std::size_t h = 1469598103934665603ull;
        auto mix = [&](std::uint64_t v){ h ^= v; h *= 1099511628211ull; };
        mix(k.src); mix(k.dst); mix((k.sport<<16)|k.dport); mix(k.proto);
        return h;
    }
};

struct FlowEntry {
    std::chrono::steady_clock::time_point lastSeen{};
    std::uint64_t packets{0};
    std::uint64_t bytes{0};
};

class FlowTable {
public:
    explicit FlowTable(std::size_t capacity)
        : cache_(capacity) {}

    FlowEntry& touch(const FlowKey& k, std::chrono::steady_clock::time_point now) {
        auto& e = cache_.get_or_create(k, [](){ return FlowEntry{}; });
        e.lastSeen = now;
        ++e.packets;
        return e;
    }

private:
    core::dsa::LRUCache<FlowKey, FlowEntry, FlowKeyHash> cache_;
};

} // namespace flow
