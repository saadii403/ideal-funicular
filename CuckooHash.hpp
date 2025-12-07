#pragma once
#include <array>
#include <functional>
#include <optional>
#include <vector>

namespace core { namespace dsa {

template <typename Key, typename Value, typename Hash1 = std::hash<Key>, typename Hash2 = std::hash<Key>>
class CuckooHash {
    static constexpr std::size_t MAX_ITERATIONS = 8;
    
    struct Entry {
        Key key{};
        Value value{};
        bool occupied{false};
    };

public:
    explicit CuckooHash(std::size_t capacity = 1024) 
        : capacity_(next_power_of_2(capacity)), mask_(capacity_ - 1) {
        table1_.resize(capacity_);
        table2_.resize(capacity_);
    }

    bool insert(const Key& key, const Value& value) {
        if (find(key)) return false; // Key already exists
        
        return insert_internal(key, value, 0);
    }

    std::optional<Value> find(const Key& key) const {
        std::size_t h1 = hash1_(key) & mask_;
        if (table1_[h1].occupied && table1_[h1].key == key) {
            return table1_[h1].value;
        }
        
        std::size_t h2 = hash2_(key) & mask_;
        if (table2_[h2].occupied && table2_[h2].key == key) {
            return table2_[h2].value;
        }
        
        return std::nullopt;
    }

    bool erase(const Key& key) {
        std::size_t h1 = hash1_(key) & mask_;
        if (table1_[h1].occupied && table1_[h1].key == key) {
            table1_[h1].occupied = false;
            --size_;
            return true;
        }
        
        std::size_t h2 = hash2_(key) & mask_;
        if (table2_[h2].occupied && table2_[h2].key == key) {
            table2_[h2].occupied = false;
            --size_;
            return true;
        }
        
        return false;
    }

    std::size_t size() const { return size_; }
    std::size_t capacity() const { return capacity_; }
    double load_factor() const { return static_cast<double>(size_) / capacity_; }

private:
    bool insert_internal(Key key, Value value, std::size_t iteration) {
        if (iteration >= MAX_ITERATIONS) {
            return rehash() && insert_internal(key, value, 0);
        }
        
        // Try table1
        std::size_t h1 = hash1_(key) & mask_;
        if (!table1_[h1].occupied) {
            table1_[h1] = {key, value, true};
            ++size_;
            return true;
        }
        
        // Evict from table1 and try table2
        std::swap(key, table1_[h1].key);
        std::swap(value, table1_[h1].value);
        
        std::size_t h2 = hash2_(key) & mask_;
        if (!table2_[h2].occupied) {
            table2_[h2] = {key, value, true};
            ++size_;
            return true;
        }
        
        // Evict from table2 and recurse
        std::swap(key, table2_[h2].key);
        std::swap(value, table2_[h2].value);
        
        return insert_internal(key, value, iteration + 1);
    }

    bool rehash() {
        auto old_table1 = std::move(table1_);
        auto old_table2 = std::move(table2_);
        std::size_t old_size = size_;
        
        capacity_ *= 2;
        mask_ = capacity_ - 1;
        table1_.clear();
        table1_.resize(capacity_);
        table2_.clear();
        table2_.resize(capacity_);
        size_ = 0;
        
        // Reinsert all elements
        for (const auto& entry : old_table1) {
            if (entry.occupied && !insert_internal(entry.key, entry.value, 0)) {
                return false;
            }
        }
        for (const auto& entry : old_table2) {
            if (entry.occupied && !insert_internal(entry.key, entry.value, 0)) {
                return false;
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

    std::vector<Entry> table1_;
    std::vector<Entry> table2_;
    std::size_t capacity_;
    std::size_t mask_;
    std::size_t size_{0};
    Hash1 hash1_;
    Hash2 hash2_;
};

}} // namespace core::dsa
