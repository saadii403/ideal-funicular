#pragma once
#include <string>

namespace detect {

struct Rule {
    int id{0};
    std::string message{};
    std::string payload_pattern{}; // naive content match for demo
};

} // namespace detect
