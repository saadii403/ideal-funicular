#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "core/Packet.hpp"
#include "core/dsa/RingBufferSPSC.hpp"
#include "capture/ISource.hpp"
#include "capture/SimSource.hpp"
#include "capture/NpcapSource.hpp"
#include "ips/WinDivertSource.hpp"
#include "decode/Ethernet.hpp"
#include "decode/IPv4.hpp"
#include "decode/TCP.hpp"
#include "decode/DNS.hpp"
#include "flow/FlowTable.hpp"
#include "detect/Engine.hpp"
#include "output/EveJson.hpp"
#include "ips/Action.hpp"

enum class CaptureMode { Simulation, Npcap, WinDivert };

CaptureMode select_capture_mode() {
    std::cout << "Select capture mode:\n";
    std::cout << "1. Simulation (default)\n";
    std::cout << "2. Npcap (live capture - requires Npcap)\n";
    std::cout << "3. WinDivert (IPS mode - requires admin)\n";
    std::cout << "Choice (1-3): ";
    
    std::string input;
    std::getline(std::cin, input);
    
    if (input == "2") return CaptureMode::Npcap;
    if (input == "3") return CaptureMode::WinDivert;
    return CaptureMode::Simulation;
}

int main() {
    using namespace std::chrono_literals;

    std::cout << "=== Windows IDS/IPS (Suricata-style) ===\n" << std::endl;
    
    CaptureMode mode = select_capture_mode();
    
    core::dsa::RingBufferSPSC<core::Packet, 1024> ring;
    std::atomic<bool> done{false};
    std::atomic<std::size_t> packets_processed{0};
    std::atomic<std::size_t> alerts_generated{0};

    // Enhanced detection engine with multiple rules
    detect::Engine engine;
    engine.addRule({1, "Suspicious test pattern", std::string("test")});
    engine.addRule({2, "Malicious payload detected", std::string("malicious")});
    engine.addRule({3, "SQL injection attempt", std::string("SELECT * FROM")});
    engine.addRule({4, "XSS attempt", std::string("<script>")});
    engine.addRule({5, "Potential backdoor", std::string("backdoor")});
    engine.build();
    
    std::cout << "Loaded " << engine.rule_count() << " detection rules\n" << std::endl;

    // Flow table with larger capacity
    flow::FlowTable flows(8192);

    // IPS decision callback for WinDivert mode
    auto ips_decision = [&](const core::Packet& pkt) -> ips::Decision {
        // Simple policy: drop packets containing "malicious"
        std::string_view payload_str(reinterpret_cast<const char*>(pkt.bytes.data()), pkt.bytes.size());
        if (payload_str.find("malicious") != std::string_view::npos) {
            std::cout << "[IPS] DROPPING malicious packet\n";
            return ips::Decision::Drop;
        }
        return ips::Decision::Pass;
    };

    // Enhanced worker thread: decode -> flow -> detect -> alert/action
    std::thread worker([&]() {
        while (!done.load() || !ring.empty()) {
            core::Packet pkt;
            if (!ring.try_pop(pkt)) {
                std::this_thread::sleep_for(1ms);
                continue;
            }

            packets_processed++;
            core::ByteSpan bytes{pkt.bytes.data(), pkt.bytes.size()};
            
            // Handle different link types
            core::ByteSpan l3_data;
            bool has_ethernet = (pkt.link == core::LinkType::Ethernet);
            
            if (has_ethernet) {
                decode::EthernetHeader eth{};
                if (!decode::parse_ethernet(bytes, eth, l3_data)) continue;
                if (eth.ethertype != 0x0800) continue; // IPv4 only
            } else {
                l3_data = bytes; // WinDivert captures at IP layer
            }

            decode::IPv4Header ip{};
            core::ByteSpan l4_data{};
            if (!decode::parse_ipv4(l3_data, ip, l4_data)) continue;
            
            flow::FlowKey flow_key{ip.src, ip.dst, 0, 0, ip.protocol};
            
            core::ByteSpan payload{};
            if (ip.protocol == 6) { // TCP
                decode::TCPHeader tcp{};
                if (!decode::parse_tcp(l4_data, tcp, payload)) continue;
                flow_key.sport = tcp.srcPort;
                flow_key.dport = tcp.dstPort;
            } else if (ip.protocol == 17) { // UDP
                if (l4_data.size() < 8) continue;
                flow_key.sport = (l4_data[0] << 8) | l4_data[1];
                flow_key.dport = (l4_data[2] << 8) | l4_data[3];
                payload = l4_data.subspan(8);
                
                // Check for DNS
                if (flow_key.dport == 53 || flow_key.sport == 53) {
                    decode::DNSHeader dns_header{};
                    std::vector<decode::DNSQuestion> questions;
                    if (decode::parse_dns(payload, dns_header, questions)) {
                        for (const auto& q : questions) {
                            std::cout << "[DNS] Query: " << q.name << " (type " << q.type << ")\n";
                        }
                    }
                }
            } else {
                payload = l4_data; // Other protocols
            }

            // Update flow table
            auto &entry = flows.touch(flow_key, std::chrono::steady_clock::now());
            entry.bytes += pkt.bytes.size();

            // Run detection engine
            if (!payload.empty()) {
                auto matches = engine.match(payload, &flow_key);
                for (const auto &match : matches) {
                    alerts_generated++;
                    std::string line = output::make_eve_alert_line(match.rule, flow_key);
                    std::cout << "[ALERT] " << line << std::endl;
                    std::cout << "[CONTEXT] " << match.context << "\n" << std::endl;
                }
            }
        }
    });

    // Create appropriate capture source
    std::unique_ptr<capture::ISource> source;
    std::unique_ptr<ips::WinDivertSource> ips_source;
    
    switch (mode) {
        case CaptureMode::Npcap: {
            auto interfaces = capture::NpcapSource::list_interfaces();
            if (interfaces.empty()) {
                std::cout << "No network interfaces found, falling back to simulation\n";
                source = std::make_unique<capture::SimSource>();
            } else {
                std::cout << "Using Npcap on interface: " << interfaces[0] << "\n";
                source = std::make_unique<capture::NpcapSource>();
            }
            break;
        }
        case CaptureMode::WinDivert: {
            std::cout << "Using WinDivert IPS mode (requires admin privileges)\n";
            ips_source = std::make_unique<ips::WinDivertSource>("tcp.DstPort == 80 or udp.DstPort == 53");
            ips_source->set_decision_callback(ips_decision);
            source = std::unique_ptr<capture::ISource>(ips_source.get());
            break;
        }
        default:
            std::cout << "Using simulation mode\n";
            source = std::make_unique<capture::SimSource>();
            break;
    }

    // Start packet capture
    source->start([&](core::Packet &&p) {
        while (!ring.try_push(std::move(p))) {
            std::this_thread::sleep_for(100us);
        }
    });

    std::cout << "\nCapture started. Press Enter to stop...\n" << std::endl;
    
    // Statistics thread
    std::thread stats_thread([&]() {
        auto last_packets = packets_processed.load();
        auto last_alerts = alerts_generated.load();
        
        while (!done.load()) {
            std::this_thread::sleep_for(5s);
            auto current_packets = packets_processed.load();
            auto current_alerts = alerts_generated.load();
            
            std::cout << "[STATS] Packets: " << current_packets 
                      << " (+" << (current_packets - last_packets) << "/5s), "
                      << "Alerts: " << current_alerts 
                      << " (+" << (current_alerts - last_alerts) << "/5s)\n";
            
            last_packets = current_packets;
            last_alerts = current_alerts;
        }
    });
    
    // Wait for user input
    std::string input;
    std::getline(std::cin, input);
    
    std::cout << "\nStopping capture...\n";
    source->stop();
    done = true;
    
    worker.join();
    stats_thread.join();
    
    std::cout << "\nFinal Statistics:";
    std::cout << "\n- Packets processed: " << packets_processed.load();
    std::cout << "\n- Alerts generated: " << alerts_generated.load();
    std::cout << "\n- Detection rules: " << engine.rule_count() << std::endl;

    return 0;
}
