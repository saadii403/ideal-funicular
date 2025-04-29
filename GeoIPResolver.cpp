#include "GeoIPResolver.h"

GeoIPResolver::GeoIPResolver() {
    loadStaticData();
}

void GeoIPResolver::loadStaticData() {
    // Lightweight IP-to-Country mappings
    ipToCountry["192.168"] = "Private Network";
    ipToCountry["10.0"] = "Private Network";
    ipToCountry["172.16"] = "Private Network";
    ipToCountry["203.0"] = "China";
    ipToCountry["198.51"] = "USA";
    ipToCountry["8.8"] = "USA";
    ipToCountry["5.62"] = "Germany";
}

std::string GeoIPResolver::getCountry(const std::string& ip) const {
    size_t firstDot = ip.find('.');
    if (firstDot == std::string::npos) return "Unknown";

    size_t secondDot = ip.find('.', firstDot + 1);
    if (secondDot == std::string::npos) return "Unknown";

    std::string prefix = ip.substr(0, secondDot);  // e.g., "192.168"
    if (ipToCountry.count(prefix)) {
        return ipToCountry.at(prefix);
    }
    return "Unknown";
}