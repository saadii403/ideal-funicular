#include "FirewallManager.h"
#include <cstdlib>
#include <iostream>

void FirewallManager::blockIP(const std::string& ip) {
    if (blockedIPs.count(ip) > 0) {
        return; // Already blocked
    }

    std::string cmd = "netsh advfirewall firewall add rule name=\"IDS_Block_" + ip +
                      "\" dir=in action=block remoteip=" + ip + " >nul 2>&1";
    int result = std::system(cmd.c_str());

    if (result == 0) {
        std::cout << "[Firewall] Blocked IP: " << ip << "\n";
        blockedIPs.insert(ip);
    } else {
        std::cerr << "[Firewall] Failed to block IP: " << ip << "\n";
    }
}

bool FirewallManager::isBlocked(const std::string& ip) const {
    return blockedIPs.count(ip) > 0;
}