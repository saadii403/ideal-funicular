#include "SignatureAnalyzer.h"
#include <chrono>

SignatureAnalyzer::SignatureAnalyzer(AlertManager& alertMgr, FirewallManager& fwMgr)
    : alertManager(alertMgr), firewallManager(fwMgr) {
    loadSignatures();
}

void SignatureAnalyzer::loadSignatures() {
    blacklistedIPs = {
        "192.168.100.66",
        "10.0.0.23",
        "203.0.113.77"
    };

    suspiciousPorts = { 23, 135, 445, 1433, 3389 };
}

void SignatureAnalyzer::analyze(const Packet& packet) {
    std::string country = geoResolver.getCountry(packet.getSourceIP());

    if (blacklistedIPs.count(packet.getSourceIP()) > 0) {
        alertManager.logAlert(Alert(
            "Signature Match",
            "Blacklisted IP detected: " + packet.getSourceIP() + " (" + country + ")",
            packet.getTimestamp()
        ));

        if (!firewallManager.isBlocked(packet.getSourceIP())) {
            firewallManager.blockIP(packet.getSourceIP());
        }
    }

    if (suspiciousPorts.count(packet.getDestinationPort()) > 0) {
        alertManager.logAlert(Alert(
            "Signature Match",
            "Suspicious port access: " + std::to_string(packet.getDestinationPort()) +
            " by IP: " + packet.getSourceIP() + " (" + country + ")",
            packet.getTimestamp()
        ));
    }
}

std::string SignatureAnalyzer::getName() const {
    return "Signature-Based Analyzer";
}