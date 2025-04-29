#include "IDS.h"
#include "SignatureAnalyzer.h"
#include "AnomalyAnalyzer.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>

void IDS::parsePcapPacket(const struct pcap_pkthdr* header, const u_char* data) {
    if (header->caplen < 34) return; // Not enough data for IP headers

    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];

    snprintf(srcIP, sizeof(srcIP), "%u.%u.%u.%u", data[26], data[27], data[28], data[29]);
    snprintf(dstIP, sizeof(dstIP), "%u.%u.%u.%u", data[30], data[31], data[32], data[33]);

    int srcPort = (data[34] << 8) + data[35];
    int dstPort = (data[36] << 8) + data[37];

    std::string protocol = (data[23] == 6) ? "TCP" : (data[23] == 17) ? "UDP" : "OTHER";

    auto timestamp = std::chrono::system_clock::from_time_t(header->ts.tv_sec);

    Packet packet(srcIP, dstIP, srcPort, dstPort, protocol, timestamp, header->len);
    analyzePacket(packet);
}

IDS::IDS() {
    // Add upgraded analyzers
    addAnalyzer(std::make_unique<SignatureAnalyzer>(alertManager, firewall));
    addAnalyzer(std::make_unique<AnomalyAnalyzer>(alertManager, firewall));
}

void IDS::addAnalyzer(std::unique_ptr<Analyzer> analyzer) {
    analyzers.push_back(std::move(analyzer));
}

void IDS::analyzePacket(const Packet& packet) {
    for (const auto& analyzer : analyzers) {
        analyzer->analyze(packet);
    }
}

void IDS::loadPcapFile(const std::string& filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);
    if (!handle) {
        std::cerr << "[Error] Failed to open PCAP file: " << errbuf << "\n";
        return;
    }

    const u_char* packetData;
    struct pcap_pkthdr* packetHeader;
    int result;

    while ((result = pcap_next_ex(handle, &packetHeader, &packetData)) >= 0) {
        parsePcapPacket(packetHeader, packetData);
    }

    pcap_close(handle);
}

void IDS::startLiveCapture(const std::string& interfaceName) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interfaceName.c_str(), 65536, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "[Error] Live capture failed: " << errbuf << "\n";
        return;
    }

    std::cout << "[*] Starting live packet capture...\n";
    const u_char* packetData;
    struct pcap_pkthdr* packetHeader;

    while (true) {
        int result = pcap_next_ex(handle, &packetHeader, &packetData);
        if (result == 1) {
            parsePcapPacket(packetHeader, packetData);
        } else if (result == -1) {
            std::cerr << "[Error] Capture error: " << pcap_geterr(handle) << "\n";
            break;
        }
    }

    pcap_close(handle);
}

void IDS::showAlerts() const {
    alertManager.showAlerts();
}

void IDS::clearAlerts() {
    alertManager.clearAlerts();
}