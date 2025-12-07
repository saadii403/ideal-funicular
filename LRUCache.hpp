#pragma once
#include <list>
#include <unordered_map>
#include <utility>

namespace core { namespace dsa {

template <typename Key, typename T, typename Hash = std::hash<Key>, typename KeyEq = std::equal_to<Key>>
class LRUCache {
public:
    explicit LRUCache(std::size_t capacity) : capacity_(capacity) {}

    template <typename Factory>
    T& get_or_create(const Key& key, Factory factory) {
        auto it = map_.find(key);
        if (it != map_.end()) {
            touch(it);
            return it->second.value;
        }
        if (map_.size() >= capacity_) evict_one();
        order_.push_front(key);
        auto [mi, ok] = map_.emplace(key, Entry{factory(), order_.begin()});
        (void)ok;
        return mi->second.value;
    }

    bool contains(const Key& key) const { return map_.find(key) != map_.end(); }

private:
    struct Entry {
        T value;
        typename std::list<Key>::iterator it;
    };

    void touch(typename std::unordered_map<Key, Entry, Hash, KeyEq>::iterator it) {
        order_.splice(order_.begin(), order_, it->second.it);
        it->second.it = order_.begin();
    }

    void evict_one() {
        const Key& k = order_.back();
        map_.erase(k);
        order_.pop_back();
    }

    std::size_t capacity_;
    std::list<Key> order_{};
    std::unordered_map<Key, Entry, Hash, KeyEq> map_{};
};

}} // namespace core::dsa
