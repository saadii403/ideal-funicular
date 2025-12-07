#pragma once
#include <atomic>
#include <string>
#include <thread>
#include <vector>
#include <memory>
#include "capture/ISource.hpp"

// Forward declarations for Npcap types
struct pcap;
typedef struct pcap pcap_t;
struct pcap_pkthdr;

namespace capture {

class NpcapSource : public ISource {
public:
    explicit NpcapSource(const std::string& interface = "");
    ~NpcapSource() override;

    void start(Callback cb) override;
    void stop() override;

    static std::vector<std::string> list_interfaces();

private:
    void capture_loop(Callback cb);
    static void packet_handler(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet);

    std::string interface_;
    pcap_t* handle_{nullptr};
    std::atomic<bool> running_{false};
    std::thread worker_;
    Callback current_callback_;
};

} // namespace capture
