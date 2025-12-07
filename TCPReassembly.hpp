#pragma once
#include <map>
#include <vector>
#include <cstdint>
#include <chrono>
#include "core/Packet.hpp"

namespace flow {

struct TCPSegment {
    std::uint32_t seq{0};
    std::vector<std::uint8_t> data{};
    std::chrono::steady_clock::time_point timestamp{};
};

class TCPStream {
public:
    void add_segment(std::uint32_t seq, core::ByteSpan data, std::chrono::steady_clock::time_point ts) {
        if (data.empty()) return;
        
        TCPSegment segment;
        segment.seq = seq;
        segment.data.assign(data.begin(), data.end());
        segment.timestamp = ts;
        
        segments_[seq] = std::move(segment);
        
        // Try to reassemble
        reassemble();
        
        // Clean old segments
        cleanup_old_segments(ts);
    }
    
    std::vector<std::uint8_t> get_reassembled_data() {
        return reassembled_data_;
    }
    
    bool has_new_data() const {
        return has_new_data_;
    }
    
    void mark_data_consumed() {
        has_new_data_ = false;
    }
    
    void set_initial_seq(std::uint32_t seq) {
        if (!initial_seq_set_) {
            next_expected_seq_ = seq;
            initial_seq_set_ = true;
        }
    }

private:
    void reassemble() {
        if (!initial_seq_set_) return;
        
        bool added_data = false;
        
        while (true) {
            auto it = segments_.find(next_expected_seq_);
            if (it == segments_.end()) break;
            
            const auto& segment = it->second;
            reassembled_data_.insert(reassembled_data_.end(), 
                                   segment.data.begin(), segment.data.end());
            next_expected_seq_ += static_cast<std::uint32_t>(segment.data.size());
            segments_.erase(it);
            added_data = true;
        }
        
        if (added_data) {
            has_new_data_ = true;
            
            // Limit reassembled data size
            if (reassembled_data_.size() > max_reassembled_size_) {
                std::size_t excess = reassembled_data_.size() - max_reassembled_size_;
                reassembled_data_.erase(reassembled_data_.begin(), 
                                      reassembled_data_.begin() + excess);
            }
        }
    }
    
    void cleanup_old_segments(std::chrono::steady_clock::time_point now) {
        auto cutoff = now - std::chrono::seconds(30); // 30 second timeout
        
        auto it = segments_.begin();
        while (it != segments_.end()) {
            if (it->second.timestamp < cutoff) {
                it = segments_.erase(it);
            } else {
                ++it;
            }
        }
    }

    std::map<std::uint32_t, TCPSegment> segments_;
    std::vector<std::uint8_t> reassembled_data_;
    std::uint32_t next_expected_seq_{0};
    bool initial_seq_set_{false};
    bool has_new_data_{false};
    static constexpr std::size_t max_reassembled_size_ = 1024 * 1024; // 1MB limit
};

class TCPReassembly {
public:
    TCPStream& get_stream(const FlowKey& key) {
        return streams_[key];
    }
    
    void cleanup_old_streams(std::chrono::steady_clock::time_point cutoff) {
        // This is a simplified cleanup - in practice, you'd track last activity per stream
        (void)cutoff;
    }

private:
    std::map<FlowKey, TCPStream> streams_;
};

} // namespace flow
