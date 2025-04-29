#ifndef IDS_H
#define IDS_H

#include "Packet.h"
#include "Analyzer.h"
#include "AlertManager.h"
#include "FirewallManager.h"

#include <pcap.h>
#include <vector>
#include <memory>
#include <string>

class IDS {
public:
    IDS();

    void addAnalyzer(std::unique_ptr<Analyzer> analyzer);
    void analyzePacket(const Packet& packet);
    void loadPcapFile(const std::string& filename);
    void startLiveCapture(const std::string& interfaceName);

    void showAlerts() const;
    void clearAlerts();

private:
    std::vector<std::unique_ptr<Analyzer>> analyzers;
    AlertManager alertManager;
    FirewallManager firewall;

    void parsePcapPacket(const struct pcap_pkthdr* header, const u_char* data);
    void handleDetectedThreat(const Packet& packet);
};

#endif // IDS_H