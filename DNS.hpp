#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "core/Packet.hpp"

namespace decode {

struct DNSHeader {
    std::uint16_t id{0};
    std::uint16_t flags{0};
    std::uint16_t questions{0};
    std::uint16_t answers{0};
    std::uint16_t authority{0};
    std::uint16_t additional{0};
};

struct DNSQuestion {
    std::string name{};
    std::uint16_t type{0};
    std::uint16_t class_{0};
};

inline bool parse_dns(core::ByteSpan bytes, DNSHeader &header, std::vector<DNSQuestion> &questions) {
    if (bytes.size() < 12) return false;
    
    header.id = (bytes[0] << 8) | bytes[1];
    header.flags = (bytes[2] << 8) | bytes[3];
    header.questions = (bytes[4] << 8) | bytes[5];
    header.answers = (bytes[6] << 8) | bytes[7];
    header.authority = (bytes[8] << 8) | bytes[9];
    header.additional = (bytes[10] << 8) | bytes[11];
    
    // Parse questions (simplified)
    std::size_t offset = 12;
    for (std::uint16_t i = 0; i < header.questions && offset < bytes.size(); ++i) {
        DNSQuestion q;
        
        // Parse name (simplified - doesn't handle compression)
        while (offset < bytes.size() && bytes[offset] != 0) {
            std::uint8_t len = bytes[offset++];
            if (offset + len > bytes.size()) return false;
            
            if (!q.name.empty()) q.name += ".";
            q.name.append(reinterpret_cast<const char*>(&bytes[offset]), len);
            offset += len;
        }
        if (offset >= bytes.size()) return false;
        offset++; // skip null terminator
        
        if (offset + 4 > bytes.size()) return false;
        q.type = (bytes[offset] << 8) | bytes[offset + 1];
        q.class_ = (bytes[offset + 2] << 8) | bytes[offset + 3];
        offset += 4;
        
        questions.push_back(std::move(q));
    }
    
    return true;
}

} // namespace decode
