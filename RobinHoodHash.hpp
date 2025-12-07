#pragma once
#include <vector>
#include <functional>
#include <optional>

namespace core { namespace dsa {

template <typename Key, typename Value, typename Hash = std::hash<Key>>
class RobinHoodHash {
    struct Entry {
        Key key{};
        Value value{};
        std::size_t psl{0}; // probe sequence length
        bool occupied{false};
    };

public:
    explicit RobinHoodHash(std::size_t capacity = 1024) 
        : capacity_(next_power_of_2(capacity)), mask_(capacity_ - 1) {
        table_.resize(capacity_);
    }

    bool insert(const Key& key, const Value& value) {
        if (size_ >= capacity_ * 0.75) { // Load factor threshold
            if (!resize()) return false;
        }

        std::size_t hash = hasher_(key);
        std::size_t pos = hash & mask_;
        std::size_t psl = 0;
        
        Entry to_insert{key, value, psl, true};

        while (true) {
            if (!table_[pos].occupied) {
                table_[pos] = to_insert;
                ++size_;
                return true;
            }

            if (table_[pos].key == key) {
                table_[pos].value = value; // Update existing
                return true;
            }

            // Robin Hood: if current entry has lower PSL, evict it
            if (table_[pos].psl < to_insert.psl) {
                std::swap(table_[pos], to_insert);
            }

            pos = (pos + 1) & mask_;
            ++to_insert.psl;
            
            if (to_insert.psl > capacity_) return false; // Prevent infinite loop
        }
    }

    std::optional<Value> find(const Key& key) const {
        std::size_t hash = hasher_(key);
        std::size_t pos = hash & mask_;
        std::size_t psl = 0;

        while (table_[pos].occupied && psl <= table_[pos].psl) {
            if (table_[pos].key == key) {
                return table_[pos].value;
            }
            pos = (pos + 1) & mask_;
            ++psl;
        }

        return std::nullopt;
    }

    bool erase(const Key& key) {
        std::size_t hash = hasher_(key);
        std::size_t pos = hash & mask_;
        std::size_t psl = 0;

        while (table_[pos].occupied && psl <= table_[pos].psl) {
            if (table_[pos].key == key) {
                // Found the key, now shift back entries
                table_[pos].occupied = false;
                --size_;
                
                std::size_t next_pos = (pos + 1) & mask_;
                while (table_[next_pos].occupied && table_[next_pos].psl > 0) {
                    table_[pos] = table_[next_pos];
                    --table_[pos].psl;
                    table_[next_pos].occupied = false;
                    pos = next_pos;
                    next_pos = (pos + 1) & mask_;
                }
                return true;
            }
            pos = (pos + 1) & mask_;
            ++psl;
        }

        return false;
    }

    std::size_t size() const { return size_; }
    std::size_t capacity() const { return capacity_; }
    double load_factor() const { return static_cast<double>(size_) / capacity_; }

private:
    bool resize() {
        auto old_table = std::move(table_);
        std::size_t old_size = size_;
        
        capacity_ *= 2;
        mask_ = capacity_ - 1;
        table_.clear();
        table_.resize(capacity_);
        size_ = 0;

        for (const auto& entry : old_table) {
            if (entry.occupied) {
                if (!insert(entry.key, entry.value)) {
                    return false;
                }
            }
        }

        return true;
    }

    static std::size_t next_power_of_2(std::size_t n) {
        if (n <= 1) return 1;
        --n;
        n |= n >> 1;
        n |= n >> 2;
        n |= n >> 4;
        n |= n >> 8;
        n |= n >> 16;
        n |= n >> 32;
        return ++n;
    }

    std::vector<Entry> table_;
    std::size_t capacity_;
    std::size_t mask_;
    std::size_t size_{0};
    Hash hasher_;
};

}} // namespace core::dsa
