#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include "detect/Rule.hpp"

namespace config {

struct IdsConfig {
    std::string capture_mode{"simulation"}; // simulation, npcap, windivert
    std::string interface_name{};
    std::string windivert_filter{"true"};
    std::size_t ring_buffer_size{1024};
    std::size_t flow_table_size{8192};
    std::size_t worker_threads{1};
    std::vector<std::string> rule_files{};
    bool enable_stats{true};
    int stats_interval_seconds{5};
};

// Simple JSON-like config parser (basic implementation)
inline bool load_config(const std::string& filename, IdsConfig& config) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Cannot open config file: " << filename << std::endl;
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // Remove whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);
        
        if (line.empty() || line[0] == '#') continue;
        
        auto colon_pos = line.find(':');
        if (colon_pos == std::string::npos) continue;
        
        std::string key = line.substr(0, colon_pos);
        std::string value = line.substr(colon_pos + 1);
        
        // Remove quotes and whitespace from value
        value.erase(0, value.find_first_not_of(" \t\""));
        value.erase(value.find_last_not_of(" \t\",") + 1);
        
        if (key == "capture_mode") config.capture_mode = value;
        else if (key == "interface_name") config.interface_name = value;
        else if (key == "windivert_filter") config.windivert_filter = value;
        else if (key == "ring_buffer_size") config.ring_buffer_size = std::stoull(value);
        else if (key == "flow_table_size") config.flow_table_size = std::stoull(value);
        else if (key == "worker_threads") config.worker_threads = std::stoull(value);
        else if (key == "enable_stats") config.enable_stats = (value == "true");
        else if (key == "stats_interval_seconds") config.stats_interval_seconds = std::stoi(value);
    }
    
    return true;
}

inline std::vector<detect::Rule> load_rules(const std::string& filename) {
    std::vector<detect::Rule> rules;
    std::ifstream file(filename);
    
    if (!file.is_open()) {
        std::cerr << "Cannot open rules file: " << filename << std::endl;
        return rules;
    }
    
    std::string line;
    int rule_id = 1;
    
    while (std::getline(file, line)) {
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);
        
        if (line.empty() || line[0] == '#') continue;
        
        // Simple rule format: message|pattern
        auto pipe_pos = line.find('|');
        if (pipe_pos != std::string::npos) {
            std::string message = line.substr(0, pipe_pos);
            std::string pattern = line.substr(pipe_pos + 1);
            
            detect::Rule rule;
            rule.id = rule_id++;
            rule.message = message;
            rule.payload_pattern = pattern;
            
            rules.push_back(std::move(rule));
        }
    }
    
    std::cout << "Loaded " << rules.size() << " rules from " << filename << std::endl;
    return rules;
}

} // namespace config
