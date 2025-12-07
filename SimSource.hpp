#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>
#include <cstring>

#include "capture/ISource.hpp"

namespace capture {

class SimSource : public ISource {
public:
    void start(Callback cb) override {
        stop();
        running_ = true;
        worker_ = std::thread([this, cb]() { run(cb); });
    }

    void stop() override {
        running_ = false;
        if (worker_.joinable()) worker_.join();
    }

    ~SimSource() override { stop(); }

private:
    static std::vector<std::uint8_t> make_ipv4_tcp_packet(bool match_rule) {
        const char* payload = match_rule ? "testpattern" : "hello";
        const std::size_t payload_len = std::strlen(payload);

        const std::size_t eth_len = 14;
        const std::size_t ip_len = 20;
        const std::size_t tcp_len = 20;
        const std::size_t total_len = eth_len + ip_len + tcp_len + payload_len;

        std::vector<std::uint8_t> p(total_len, 0);
        // Ethernet
        // dst MAC
        for (int i = 0; i < 6; ++i) p[i] = 0xAA;
        // src MAC
        for (int i = 0; i < 6; ++i) p[6 + i] = 0xBB;
        // type 0x0800 (IPv4)
        p[12] = 0x08; p[13] = 0x00;

        // IPv4 header
        auto ip = p.data() + eth_len;
        ip[0] = 0x45; // version(4) + IHL(5)
        ip[1] = 0x00; // DSCP/ECN
        std::uint16_t ip_total = static_cast<std::uint16_t>(ip_len + tcp_len + payload_len);
        ip[2] = static_cast<std::uint8_t>(ip_total >> 8);
        ip[3] = static_cast<std::uint8_t>(ip_total & 0xFF);
        ip[4] = 0; ip[5] = 1; // identification
        ip[6] = 0x40; ip[7] = 0x00; // flags/frag offset
        ip[8] = 64; // ttl
        ip[9] = 6;  // protocol TCP
        // checksum left 0
        // src 192.168.1.10
        ip[12] = 192; ip[13] = 168; ip[14] = 1; ip[15] = 10;
        // dst 93.184.216.34 (example.com)
        ip[16] = 93; ip[17] = 184; ip[18] = 216; ip[19] = 34;

        // TCP header
        auto tcp = p.data() + eth_len + ip_len;
        // src port 12345
        tcp[0] = 0x30; tcp[1] = 0x39;
        // dst port 80
        tcp[2] = 0x00; tcp[3] = 0x50;
        // seq/ack left 0
        tcp[12] = 0x50; // data offset 5 (20 bytes)
        tcp[13] = 0x18; // PSH+ACK
        tcp[14] = 0x01; tcp[15] = 0x00; // window
        // checksum/urgent 0

        // payload
        std::memcpy(p.data() + eth_len + ip_len + tcp_len, payload, payload_len);
        return p;
    }

    void run(Callback cb) {
        using namespace std::chrono_literals;
        bool toggle = false;
        while (running_) {
            toggle = !toggle;
            core::Packet pkt;
            pkt.ts = std::chrono::steady_clock::now();
            pkt.bytes = make_ipv4_tcp_packet(toggle);
            pkt.link = core::LinkType::Ethernet;
            cb(std::move(pkt));
            std::this_thread::sleep_for(10ms);
        }
    }

    std::atomic<bool> running_{false};
    std::thread worker_{};
};

} // namespace capture
