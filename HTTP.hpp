#pragma once
#include <string>
#include <unordered_map>
#include <string_view>
#include "core/Packet.hpp"

namespace decode {

struct HTTPRequest {
    std::string method{};
    std::string uri{};
    std::string version{};
    std::unordered_map<std::string, std::string> headers{};
    std::string body{};
};

struct HTTPResponse {
    std::string version{};
    int status_code{0};
    std::string reason{};
    std::unordered_map<std::string, std::string> headers{};
    std::string body{};
};

inline bool parse_http_request(core::ByteSpan data, HTTPRequest& req) {
    std::string_view text(reinterpret_cast<const char*>(data.data()), data.size());
    
    // Find end of headers
    auto header_end = text.find("\r\n\r\n");
    if (header_end == std::string_view::npos) return false;
    
    std::string_view headers_section = text.substr(0, header_end);
    std::string_view body_section = text.substr(header_end + 4);
    
    // Parse request line
    auto first_line_end = headers_section.find("\r\n");
    if (first_line_end == std::string_view::npos) return false;
    
    std::string_view request_line = headers_section.substr(0, first_line_end);
    
    // Parse method, URI, version
    auto first_space = request_line.find(' ');
    if (first_space == std::string_view::npos) return false;
    
    req.method = request_line.substr(0, first_space);
    
    auto second_space = request_line.find(' ', first_space + 1);
    if (second_space == std::string_view::npos) return false;
    
    req.uri = request_line.substr(first_space + 1, second_space - first_space - 1);
    req.version = request_line.substr(second_space + 1);
    
    // Parse headers
    std::string_view remaining_headers = headers_section.substr(first_line_end + 2);
    std::size_t pos = 0;
    
    while (pos < remaining_headers.size()) {
        auto line_end = remaining_headers.find("\r\n", pos);
        if (line_end == std::string_view::npos) break;
        
        std::string_view header_line = remaining_headers.substr(pos, line_end - pos);
        auto colon_pos = header_line.find(':');
        
        if (colon_pos != std::string_view::npos) {
            std::string key(header_line.substr(0, colon_pos));
            std::string value(header_line.substr(colon_pos + 1));
            
            // Trim whitespace
            while (!value.empty() && value[0] == ' ') value.erase(0, 1);
            while (!value.empty() && value.back() == ' ') value.pop_back();
            
            req.headers[key] = value;
        }
        
        pos = line_end + 2;
    }
    
    req.body = body_section;
    return true;
}

inline bool is_http_traffic(core::ByteSpan payload) {
    if (payload.size() < 16) return false;
    
    std::string_view text(reinterpret_cast<const char*>(payload.data()), 
                         std::min<std::size_t>(payload.size(), 16));
    
    return text.starts_with("GET ") || text.starts_with("POST ") || 
           text.starts_with("PUT ") || text.starts_with("DELETE ") ||
           text.starts_with("HEAD ") || text.starts_with("OPTIONS ") ||
           text.starts_with("HTTP/");
}

} // namespace decode
