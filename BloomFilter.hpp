#pragma once
#include <cstdint>
#include <functional>
#include <string_view>
#include <vector>

namespace core { namespace dsa {

class BloomFilter {
public:
    BloomFilter(std::size_t bit_count = 8192, std::size_t hashes = 3)
        : bits_((bit_count + 63) / 64), mask_((bit_count + 63) / 64 * 64 - 1), k_(hashes) {}

    void add(std::string_view s) {
        auto h1 = splitmix64_hash(s, 0x9E3779B97F4A7C15ull);
        auto h2 = splitmix64_hash(s, 0xBF58476D1CE4E5B9ull);
        for (std::size_t i = 0; i < k_; ++i) set_bit((h1 + i * h2) & mask_);
    }

    bool possibly_contains(std::string_view s) const {
        auto h1 = splitmix64_hash(s, 0x9E3779B97F4A7C15ull);
        auto h2 = splitmix64_hash(s, 0xBF58476D1CE4E5B9ull);
        for (std::size_t i = 0; i < k_; ++i) if (!test_bit((h1 + i * h2) & mask_)) return false;
        return true;
    }

private:
    static uint64_t splitmix64(uint64_t x) {
        x += 0x9e3779b97f4a7c15ull;
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
        return x ^ (x >> 31);
    }

    static uint64_t splitmix64_hash(std::string_view s, uint64_t seed) {
        uint64_t h = seed;
        for (unsigned char c : s) h = splitmix64(h ^ c);
        return h;
    }

    void set_bit(std::size_t i) {
        bits_[i >> 6] |= (uint64_t{1} << (i & 63));
    }
    bool test_bit(std::size_t i) const {
        return (bits_[i >> 6] & (uint64_t{1} << (i & 63))) != 0;
    }

    std::vector<uint64_t> bits_;
    std::size_t mask_;
    std::size_t k_;
};

}} // namespace core::dsa
