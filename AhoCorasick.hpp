#pragma once
#include <queue>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <memory>

namespace core { namespace dsa {

struct AhoCorasickMatch {
    std::size_t position;
    std::size_t pattern_id;
    std::size_t length;
};

class AhoCorasick {
    struct Node {
        std::unordered_map<char, std::unique_ptr<Node>> children;
        Node* failure{nullptr};
        std::vector<std::size_t> output; // pattern IDs that end at this node
        bool is_root{false};
    };

public:
    AhoCorasick() : root_(std::make_unique<Node>()) {
        root_->is_root = true;
        root_->failure = root_.get();
    }

    // Add pattern and return its ID
    std::size_t add_pattern(std::string_view pattern) {
        std::size_t pattern_id = patterns_.size();
        patterns_.emplace_back(pattern);
        
        Node* current = root_.get();
        for (char c : pattern) {
            if (current->children.find(c) == current->children.end()) {
                current->children[c] = std::make_unique<Node>();
            }
            current = current->children[c].get();
        }
        current->output.push_back(pattern_id);
        
        built_ = false; // Need to rebuild failure links
        return pattern_id;
    }

    // Build failure links (call after adding all patterns)
    void build() {
        if (built_) return;
        
        // BFS to build failure links
        std::queue<Node*> queue;
        
        // Initialize first level
        for (auto& [c, child] : root_->children) {
            child->failure = root_.get();
            queue.push(child.get());
        }
        
        while (!queue.empty()) {
            Node* current = queue.front();
            queue.pop();
            
            for (auto& [c, child] : current->children) {
                queue.push(child.get());
                
                // Find failure link
                Node* failure = current->failure;
                while (failure != root_.get() && failure->children.find(c) == failure->children.end()) {
                    failure = failure->failure;
                }
                
                if (failure->children.find(c) != failure->children.end() && failure->children[c].get() != child.get()) {
                    child->failure = failure->children[c].get();
                } else {
                    child->failure = root_.get();
                }
                
                // Merge output from failure link
                for (std::size_t pattern_id : child->failure->output) {
                    child->output.push_back(pattern_id);
                }
            }
        }
        
        built_ = true;
    }

    // Search for all patterns in text
    std::vector<AhoCorasickMatch> search(std::string_view text) {
        if (!built_) build();
        
        std::vector<AhoCorasickMatch> matches;
        Node* current = root_.get();
        
        for (std::size_t i = 0; i < text.size(); ++i) {
            char c = text[i];
            
            // Follow failure links until we find a match or reach root
            while (current != root_.get() && current->children.find(c) == current->children.end()) {
                current = current->failure;
            }
            
            if (current->children.find(c) != current->children.end()) {
                current = current->children[c].get();
            }
            
            // Report all patterns that end at this position
            for (std::size_t pattern_id : current->output) {
                matches.push_back({
                    i + 1 - patterns_[pattern_id].size(), // start position
                    pattern_id,
                    patterns_[pattern_id].size()
                });
            }
        }
        
        return matches;
    }

    const std::string& get_pattern(std::size_t pattern_id) const {
        return patterns_[pattern_id];
    }

    std::size_t pattern_count() const { return patterns_.size(); }

private:
    std::unique_ptr<Node> root_;
    std::vector<std::string> patterns_;
    bool built_{false};
};

}} // namespace core::dsa
