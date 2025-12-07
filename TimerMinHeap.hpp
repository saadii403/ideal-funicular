#pragma once
#include <chrono>
#include <cstdint>
#include <queue>
#include <vector>

namespace core { namespace dsa {

struct TimerItem {
    std::chrono::steady_clock::time_point when{};
    std::uint64_t id{};
    bool operator>(const TimerItem& other) const { return when > other.when; }
};

class TimerMinHeap {
public:
    void push(TimerItem t) { heap_.push(std::move(t)); }

    bool peek(TimerItem& out) const {
        if (heap_.empty()) return false;
        out = heap_.top();
        return true;
    }

    bool pop(TimerItem& out) {
        if (heap_.empty()) return false;
        out = heap_.top();
        heap_.pop();
        return true;
    }

    bool empty() const { return heap_.empty(); }

private:
    std::priority_queue<TimerItem, std::vector<TimerItem>, std::greater<TimerItem>> heap_{};
};

}} // namespace core::dsa
