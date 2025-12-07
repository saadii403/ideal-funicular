#pragma once
#include <atomic>
#include <memory>
#include <optional>

namespace core { namespace dsa {

template <typename T>
class QueueMPSC {
    struct Node {
        std::atomic<Node*> next{nullptr};
        T value;
        explicit Node(T&& v) : value(std::move(v)) {}
        explicit Node(const T& v) : value(v) {}
    };

public:
    QueueMPSC() {
        Node* stub = new Node(T{});
        head_.store(stub, std::memory_order_relaxed);
        tail_ = stub;
    }

    ~QueueMPSC() {
        T tmp{};
        while (try_pop(tmp)) {}
        Node* t = tail_;
        delete t;
    }

    bool try_push(const T& v) { return enqueue(Node(v)); }
    bool try_push(T&& v) { return enqueue(Node(std::move(v))); }

    bool try_pop(T& out) {
        Node* tail = tail_;
        Node* next = tail->next.load(std::memory_order_acquire);
        if (!next) return false;
        out = std::move(next->value);
        tail_ = next;
        delete tail;
        return true;
    }

private:
    bool enqueue(Node n) {
        Node* node = new Node(std::move(n.value));
        node->next.store(nullptr, std::memory_order_relaxed);
        Node* prev = head_.exchange(node, std::memory_order_acq_rel);
        prev->next.store(node, std::memory_order_release);
        return true;
    }

    std::atomic<Node*> head_{nullptr};
    Node* tail_{nullptr}; // single consumer only
};

}} // namespace core::dsa
