#pragma once
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

namespace core { namespace dsa {

class Trie {
    struct Node {
        bool terminal{false};
        std::unordered_map<char, std::unique_ptr<Node>> next;
    };

public:
    void insert(std::string_view s) {
        Node* cur = root_.get();
        for (char ch : s) {
            auto &ptr = cur->next[ch];
            if (!ptr) ptr = std::make_unique<Node>();
            cur = ptr.get();
        }
        cur->terminal = true;
    }

    bool match_prefix(std::string_view s) const {
        const Node* cur = root_.get();
        for (char ch : s) {
            auto it = cur->next.find(ch);
            if (it == cur->next.end()) return false;
            cur = it->second.get();
            if (cur->terminal) return true;
        }
        return cur && cur->terminal;
    }

private:
    std::unique_ptr<Node> root_ = std::make_unique<Node>();
};

}} // namespace core::dsa
