#ifndef SIGNATURE_ANALYZER_H
#define SIGNATURE_ANALYZER_H

#include "Analyzer.h"
#include "AlertManager.h"
#include "FirewallManager.h"
#include "GeoIPResolver.h"
#include <unordered_set>

class SignatureAnalyzer : public Analyzer {
public:
    SignatureAnalyzer(AlertManager& alertMgr, FirewallManager& fwMgr);

    void analyze(const Packet& packet) override;
    std::string getName() const override;

private:
    AlertManager& alertManager;
    FirewallManager& firewallManager;
    GeoIPResolver geoResolver;

    std::unordered_set<std::string> blacklistedIPs;
    std::unordered_set<int> suspiciousPorts;

    void loadSignatures();
};

#endif // SIGNATURE_ANALYZER_H