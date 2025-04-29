#include "AnomalyAnalyzer.h"
#include <chrono>

AnomalyAnalyzer::AnomalyAnalyzer(AlertManager& alertMgr, FirewallManager& fwMgr)
    : alertManager(alertMgr), firewallManager(fwMgr) {}

void AnomalyAnalyzer::analyze(const Packet& packet) {
    detectFlood(packet);
    detectPortScan(packet);
    detectLargePacket(packet);
}

void AnomalyAnalyzer::detectFlood(const Packet& packet) {
    std::string ip = packet.getSourceIP();
    std::string country = geoResolver.getCountry(ip);

    ++packetCount[ip];

    if (packetCount[ip] > floodThreshold) {
        alertManager.logAlert(Alert(
            "Anomaly Detected",
            "Possible packet flood from IP: " + ip + " (" + country + ")",
            packet.getTimestamp()
        ));

        if (!firewallManager.isBlocked(ip)) {
            firewallManager.blockIP(ip);
        }

        packetCount[ip] = 0;
    }
}

void AnomalyAnalyzer::detectPortScan(const Packet& packet) {
    std::string ip = packet.getSourceIP();
    std::string country = geoResolver.getCountry(ip);

    portsAccessed[ip].insert(packet.getDestinationPort());

    if (portsAccessed[ip].size() > portScanThreshold) {
        alertManager.logAlert(Alert(
            "Anomaly Detected",
            "Possible port scanning by IP: " + ip + " (" + country + ")",
            packet.getTimestamp()
        ));

        if (!firewallManager.isBlocked(ip)) {
            firewallManager.blockIP(ip);
        }

        portsAccessed[ip].clear();
    }
}

void AnomalyAnalyzer::detectLargePacket(const Packet& packet) {
    std::string ip = packet.getSourceIP();
    std::string country = geoResolver.getCountry(ip);

    if (packet.getLength() > largePacketSize) {
        alertManager.logAlert(Alert(
            "Anomaly Detected",
            "Large packet detected from IP: " + ip + " (" + country + ")",
            packet.getTimestamp()
        ));

        if (!firewallManager.isBlocked(ip)) {
            firewallManager.blockIP(ip);
        }
    }
}

std::string AnomalyAnalyzer::getName() const {
    return "Anomaly-Based Analyzer (Smart)";
}