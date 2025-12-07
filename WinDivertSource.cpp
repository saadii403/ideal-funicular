#include "ips/WinDivertSource.hpp"
#include <iostream>
#include <chrono>
#include <cstring>

// WinDivert includes - these would normally come from WinDivert SDK
#ifdef WINDIVERT_AVAILABLE
#include <windivert.h>
#else
// Stub definitions when WinDivert SDK is not available
typedef void* HANDLE;
struct WINDIVERT_ADDRESS {
    uint32_t IfIdx;
    uint32_t SubIfIdx;
    uint8_t Direction;
};

// Stub functions
HANDLE WinDivertOpen(const char*, int, int16_t, uint64_t) { return nullptr; }
int WinDivertRecv(HANDLE, void*, uint32_t, uint32_t*, WINDIVERT_ADDRESS*) { return 0; }
int WinDivertSend(HANDLE, const void*, uint32_t, uint32_t*, const WINDIVERT_ADDRESS*) { return 0; }
int WinDivertClose(HANDLE) { return 1; }
#endif

namespace ips {

WinDivertSource::WinDivertSource(const std::string& filter, WinDivertLayer layer)
    : filter_(filter), layer_(layer) {
}

WinDivertSource::~WinDivertSource() {
    stop();
}

void WinDivertSource::start(Callback cb) {
    stop();
    running_ = true;
    worker_ = std::thread([this, cb]() { capture_loop(cb); });
}

void WinDivertSource::stop() {
    running_ = false;
    if (worker_.joinable()) {
        worker_.join();
    }
    if (handle_) {
        WinDivertClose(handle_);
        handle_ = nullptr;
    }
}

void WinDivertSource::set_decision_callback(std::function<Decision(const core::Packet&)> cb) {
    decision_callback_ = cb;
}

void WinDivertSource::capture_loop(Callback cb) {
#ifdef WINDIVERT_AVAILABLE
    handle_ = WinDivertOpen(filter_.c_str(), static_cast<int>(layer_), 0, 0);
    if (!handle_) {
        std::cerr << "[WinDivertSource] Failed to open WinDivert handle" << std::endl;
        return;
    }

    std::cout << "[WinDivertSource] Started IPS capture with filter: " << filter_ << std::endl;

    unsigned char buffer[65536];
    uint32_t packet_len;
    WINDIVERT_ADDRESS addr;

    while (running_) {
        if (WinDivertRecv(handle_, buffer, sizeof(buffer), &packet_len, &addr)) {
            core::Packet pkt;
            pkt.ts = std::chrono::steady_clock::now();
            pkt.bytes.assign(buffer, buffer + packet_len);
            pkt.link = core::LinkType::None; // WinDivert captures at IP layer
            
            // Make IPS decision
            Decision decision = make_decision(pkt);
            
            // Pass to detection pipeline
            cb(std::move(pkt));
            
            // Apply IPS action
            if (decision == Decision::Pass) {
                WinDivertSend(handle_, buffer, packet_len, nullptr, &addr);
            }
            // Drop packets by not re-injecting them
        }
    }
#else
    std::cout << "[WinDivertSource] WinDivert not available, using simulation mode" << std::endl;
    
    // Fallback simulation when WinDivert is not available
    using namespace std::chrono_literals;
    int counter = 0;
    while (running_ && counter < 30) {
        core::Packet pkt;
        pkt.ts = std::chrono::steady_clock::now();
        
        // Generate test packets
        bool suspicious = (counter % 3 == 0);
        const char* payload = suspicious ? "malicious_payload" : "normal_traffic";
        
        // Simple IPv4 + TCP packet (no Ethernet header for WinDivert)
        std::vector<std::uint8_t> packet_data;
        packet_data.resize(40 + std::strlen(payload));
        
        // IPv4 header (20 bytes)
        packet_data[0] = 0x45; // version + IHL
        packet_data[9] = 6;    // protocol TCP
        packet_data[12] = 192; packet_data[13] = 168; packet_data[14] = 1; packet_data[15] = 10; // src IP
        packet_data[16] = 10; packet_data[17] = 0; packet_data[18] = 0; packet_data[19] = 1; // dst IP
        
        // TCP header (20 bytes)
        packet_data[20] = 0x30; packet_data[21] = 0x39; // src port 12345
        packet_data[22] = 0x00; packet_data[23] = 0x50; // dst port 80
        packet_data[32] = 0x50; // data offset
        
        // Payload
        std::memcpy(packet_data.data() + 40, payload, std::strlen(payload));
        
        pkt.bytes = std::move(packet_data);
        pkt.link = core::LinkType::None;
        
        // Simulate IPS decision
        Decision decision = make_decision(pkt);
        std::cout << "[WinDivertSource] Packet " << counter << " decision: " 
                  << (decision == Decision::Pass ? "PASS" : "DROP") << std::endl;
        
        cb(std::move(pkt));
        
        std::this_thread::sleep_for(200ms);
        counter++;
    }
#endif
}

Decision WinDivertSource::make_decision(const core::Packet& packet) {
    if (decision_callback_) {
        return decision_callback_(packet);
    }
    
    // Default: pass all packets
    return Decision::Pass;
}

bool WinDivertSource::inject_packet(const core::Packet& packet) {
#ifdef WINDIVERT_AVAILABLE
    if (!handle_) return false;
    
    WINDIVERT_ADDRESS addr{};
    uint32_t written;
    return WinDivertSend(handle_, packet.bytes.data(), 
                        static_cast<uint32_t>(packet.bytes.size()), 
                        &written, &addr) != 0;
#else
    std::cout << "[WinDivertSource] Simulated packet injection (" << packet.bytes.size() << " bytes)" << std::endl;
    return true;
#endif
}

} // namespace ips
