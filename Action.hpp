#pragma once
#include <string>

namespace ips {

enum class Decision { Pass, Drop };

inline void apply(Decision d) {
    (void)d; // placeholder for WinDivert/WFP integration
}

} // namespace ips
