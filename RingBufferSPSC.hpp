#pragma once
#include <array>
#include <atomic>
#include <cstddef>
#include <utility>

namespace core { namespace dsa {

template <typename T, std::size_t Capacity>
class RingBufferSPSC {
public:
    RingBufferSPSC() : head_(0), tail_(0) {}

    bool try_push(const T &v) {
        auto next = increment(head_.load(std::memory_order_relaxed));
        if (next == tail_.load(std::memory_order_acquire)) return false; // full
        storage_[head_.load(std::memory_order_relaxed)] = v;
        head_.store(next, std::memory_order_release);
        return true;
    }

    bool try_push(T &&v) {
        auto next = increment(head_.load(std::memory_order_relaxed));
        if (next == tail_.load(std::memory_order_acquire)) return false; // full
        storage_[head_.load(std::memory_order_relaxed)] = std::move(v);
        head_.store(next, std::memory_order_release);
        return true;
    }

    bool try_pop(T &out) {
        auto tail = tail_.load(std::memory_order_relaxed);
        if (tail == head_.load(std::memory_order_acquire)) return false; // empty
        out = std::move(storage_[tail]);
        tail_.store(increment(tail), std::memory_order_release);
        return true;
    }

    bool empty() const {
        return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
    }

    bool full() const {
        auto next = increment(head_.load(std::memory_order_acquire));
        return next == tail_.load(std::memory_order_acquire);
    }

private:
    static constexpr std::size_t capacity_plus_one = Capacity + 1; // one slot is unused

    static std::size_t increment(std::size_t v) {
        return (v + 1) % capacity_plus_one;
    }

    std::array<T, capacity_plus_one> storage_{};
    std::atomic<std::size_t> head_;
    std::atomic<std::size_t> tail_;
};

}} // namespace core::dsa
