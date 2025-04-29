#ifndef FIREWALL_MANAGER_H
#define FIREWALL_MANAGER_H

#include <string>
#include <unordered_set>

class FirewallManager {
public:
    void blockIP(const std::string& ip);
    bool isBlocked(const std::string& ip) const;

private:
    std::unordered_set<std::string> blockedIPs;
};

#endif // FIREWALL_MANAGER_H
