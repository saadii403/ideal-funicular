#ifndef ANOMALY_ANALYZER_H
#define ANOMALY_ANALYZER_H

#include "Analyzer.h"
#include "AlertManager.h"
#include "FirewallManager.h"
#include "GeoIPResolver.h"
#include <map>
#include <set>

class AnomalyAnalyzer : public Analyzer {
public:
    AnomalyAnalyzer(AlertManager& alertMgr, FirewallManager& fwMgr);

    void analyze(const Packet& packet) override;
    std::string getName() const override;

private:
    AlertManager& alertManager;
    FirewallManager& firewallManager;
    GeoIPResolver geoResolver;

    std::map<std::string, int> packetCount;
    std::map<std::string, std::set<int>> portsAccessed;
    const int floodThreshold = 10;
    const int portScanThreshold = 5;
    const int largePacketSize = 1500;

    void detectFlood(const Packet& packet);
    void detectPortScan(const Packet& packet);
    void detectLargePacket(const Packet& packet);
};

#endif // ANOMALY_ANALYZER_H