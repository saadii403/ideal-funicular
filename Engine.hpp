#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <cstring>
#include <unordered_map>
#include "core/Packet.hpp"
#include "core/dsa/AhoCorasick.hpp"
#include "core/dsa/BloomFilter.hpp"
#include "detect/Rule.hpp"
#include "flow/FlowTable.hpp"

namespace detect {

struct MatchResult {
    Rule rule;
    std::size_t position;
    std::string context;
};

class Engine {
public:
    Engine() : bloom_(16384, 4), built_(false) {}

    void addRule(Rule r) {
        if (!r.payload_pattern.empty()) {
            std::size_t pattern_id = aho_corasick_.add_pattern(r.payload_pattern);
            pattern_to_rule_[pattern_id] = rules_.size();
            bloom_.add(r.payload_pattern);
        }
        rules_.emplace_back(std::move(r));
        built_ = false;
    }

    void build() {
        if (!built_) {
            aho_corasick_.build();
            built_ = true;
        }
    }

    std::vector<MatchResult> match(core::ByteSpan payload, const flow::FlowKey* flow_key = nullptr) {
        if (!built_) build();
        
        std::vector<MatchResult> results;
        
        // Convert to string_view for processing
        std::string_view payload_str(reinterpret_cast<const char*>(payload.data()), payload.size());
        
        // Bloom filter prefilter
        bool bloom_match = false;
        for (const auto& rule : rules_) {
            if (!rule.payload_pattern.empty() && bloom_.possibly_contains(rule.payload_pattern)) {
                bloom_match = true;
                break;
            }
        }
        
        if (!bloom_match) return results;
        
        // Aho-Corasick multi-pattern matching
        auto matches = aho_corasick_.search(payload_str);
        
        for (const auto& match : matches) {
            auto it = pattern_to_rule_.find(match.pattern_id);
            if (it != pattern_to_rule_.end()) {
                const Rule& rule = rules_[it->second];
                
                // Apply additional filters
                if (flow_key && !check_flow_filters(rule, *flow_key)) {
                    continue;
                }
                
                MatchResult result;
                result.rule = rule;
                result.position = match.position;
                result.context = extract_context(payload_str, match.position, match.length);
                results.push_back(std::move(result));
            }
        }
        
        return results;
    }

    std::size_t rule_count() const { return rules_.size(); }
    
private:
    bool check_flow_filters(const Rule& rule, const flow::FlowKey& flow_key) {
        // Add IP/port filtering logic here
        (void)rule; (void)flow_key;
        return true;
    }
    
    std::string extract_context(std::string_view payload, std::size_t pos, std::size_t len) {
        std::size_t start = pos > 10 ? pos - 10 : 0;
        std::size_t end = std::min(pos + len + 10, payload.size());
        return std::string(payload.substr(start, end - start));
    }

    std::vector<Rule> rules_;
    core::dsa::AhoCorasick aho_corasick_;
    core::dsa::BloomFilter bloom_;
    std::unordered_map<std::size_t, std::size_t> pattern_to_rule_;
    bool built_;
};

} // namespace detect
