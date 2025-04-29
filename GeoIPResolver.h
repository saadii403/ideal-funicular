#ifndef GEOIP_RESOLVER_H
#define GEOIP_RESOLVER_H

#include <string>
#include <unordered_map>

class GeoIPResolver {
public:
    GeoIPResolver();
    std::string getCountry(const std::string& ip) const;

private:
    std::unordered_map<std::string, std::string> ipToCountry;
    void loadStaticData();
};

#endif // GEOIP_RESOLVER_H