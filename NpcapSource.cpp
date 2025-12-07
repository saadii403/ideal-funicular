#include "capture/NpcapSource.hpp"
#include <iostream>
#include <chrono>
#include <cstring>

// Npcap includes - these would normally come from Npcap SDK
// For now, we'll provide stub implementations
#ifdef NPCAP_AVAILABLE
#include <pcap.h>
#else
// Stub definitions when Npcap SDK is not available
struct pcap {};
struct pcap_pkthdr {
    struct timeval ts;
    unsigned int caplen;
    unsigned int len;
};
typedef struct pcap pcap_t;

// Stub functions
pcap_t* pcap_open_live(const char*, int, int, int, char*) { return nullptr; }
void pcap_close(pcap_t*) {}
int pcap_loop(pcap_t*, int, void(*)(unsigned char*, const struct pcap_pkthdr*, const unsigned char*), unsigned char*) { return -1; }
void pcap_breakloop(pcap_t*) {}
int pcap_findalldevs(void**, char*) { return -1; }
void pcap_freealldevs(void*) {}
#endif

namespace capture {

NpcapSource::NpcapSource(const std::string& interface) : interface_(interface) {
    if (interface_.empty()) {
        auto interfaces = list_interfaces();
        if (!interfaces.empty()) {
            interface_ = interfaces[0];
            std::cout << "[NpcapSource] Auto-selected interface: " << interface_ << std::endl;
        }
    }
}

NpcapSource::~NpcapSource() {
    stop();
}

void NpcapSource::start(Callback cb) {
    stop();
    current_callback_ = cb;
    running_ = true;
    worker_ = std::thread([this, cb]() { capture_loop(cb); });
}

void NpcapSource::stop() {
    running_ = false;
    if (handle_) {
        pcap_breakloop(handle_);
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

void NpcapSource::capture_loop(Callback cb) {
#ifdef NPCAP_AVAILABLE
    char errbuf[256];
    handle_ = pcap_open_live(interface_.c_str(), 65536, 1, 1000, errbuf);
    if (!handle_) {
        std::cerr << "[NpcapSource] Failed to open interface " << interface_ << ": " << errbuf << std::endl;
        return;
    }

    std::cout << "[NpcapSource] Started capture on " << interface_ << std::endl;
    
    // Set callback for packet handler
    current_callback_ = cb;
    
    // Start capture loop
    pcap_loop(handle_, -1, packet_handler, reinterpret_cast<unsigned char*>(this));
#else
    std::cout << "[NpcapSource] Npcap not available, falling back to simulation mode" << std::endl;
    
    // Fallback to simulation when Npcap is not available
    using namespace std::chrono_literals;
    int counter = 0;
    while (running_ && counter < 50) {
        core::Packet pkt;
        pkt.ts = std::chrono::steady_clock::now();
        
        // Generate alternating test packets
        bool match_rule = (counter % 2 == 0);
        const char* payload = match_rule ? "testpattern" : "normaltraffic";
        
        // Simple Ethernet + IPv4 + TCP packet
        std::vector<std::uint8_t> packet_data;
        packet_data.resize(54 + std::strlen(payload));
        
        // Ethernet header (14 bytes)
        std::fill(packet_data.begin(), packet_data.begin() + 6, 0xAA); // dst MAC
        std::fill(packet_data.begin() + 6, packet_data.begin() + 12, 0xBB); // src MAC
        packet_data[12] = 0x08; packet_data[13] = 0x00; // IPv4
        
        // IPv4 header (20 bytes)
        packet_data[14] = 0x45; // version + IHL
        packet_data[23] = 6;    // protocol TCP
        packet_data[26] = 192; packet_data[27] = 168; packet_data[28] = 1; packet_data[29] = 10; // src IP
        packet_data[30] = 93; packet_data[31] = 184; packet_data[32] = 216; packet_data[33] = 34; // dst IP
        
        // TCP header (20 bytes)
        packet_data[34] = 0x30; packet_data[35] = 0x39; // src port 12345
        packet_data[36] = 0x00; packet_data[37] = 0x50; // dst port 80
        packet_data[46] = 0x50; // data offset
        
        // Payload
        std::memcpy(packet_data.data() + 54, payload, std::strlen(payload));
        
        pkt.bytes = std::move(packet_data);
        pkt.link = core::LinkType::Ethernet;
        
        cb(std::move(pkt));
        
        std::this_thread::sleep_for(100ms);
        counter++;
    }
#endif
}

void NpcapSource::packet_handler(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet) {
    auto* source = reinterpret_cast<NpcapSource*>(user);
    if (!source->running_) return;
    
    core::Packet pkt;
    pkt.ts = std::chrono::steady_clock::now();
    pkt.bytes.assign(packet, packet + header->caplen);
    pkt.link = core::LinkType::Ethernet;
    
    source->current_callback_(std::move(pkt));
}

std::vector<std::string> NpcapSource::list_interfaces() {
    std::vector<std::string> interfaces;
    
#ifdef NPCAP_AVAILABLE
    char errbuf[256];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[NpcapSource] Error finding devices: " << errbuf << std::endl;
        return interfaces;
    }
    
    for (pcap_if_t* dev = alldevs; dev; dev = dev->next) {
        interfaces.emplace_back(dev->name);
    }
    
    pcap_freealldevs(alldevs);
#else
    // Return dummy interface when Npcap is not available
    interfaces.emplace_back("\\Device\\NPF_Loopback");
#endif
    
    return interfaces;
}

} // namespace capture
