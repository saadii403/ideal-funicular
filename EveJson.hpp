#pragma once
#include <cstdint>
#include <string>
#include <sstream>
#include "flow/FlowTable.hpp"
#include "detect/Rule.hpp"

namespace output {

inline std::string ipv4_to_string(std::uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << '.'
        << ((ip >> 16) & 0xFF) << '.'
        << ((ip >> 8) & 0xFF) << '.'
        << (ip & 0xFF);
    return oss.str();
}

inline std::string make_eve_alert_line(const detect::Rule& rule, const flow::FlowKey& k) {
    std::ostringstream oss;
    oss << "{\"timestamp\":\"now\",";
    oss << "\"event_type\":\"alert\",";
    oss << "\"alert\":{\"signature_id\":" << rule.id << ",\"signature\":\"" << rule.message << "\"},";
    oss << "\"src_ip\":\"" << ipv4_to_string(k.src) << "\",";
    oss << "\"src_port\":" << k.sport << ",";
    oss << "\"dest_ip\":\"" << ipv4_to_string(k.dst) << "\",";
    oss << "\"dest_port\":" << k.dport << "}";
    return oss.str();
}

} // namespace output
