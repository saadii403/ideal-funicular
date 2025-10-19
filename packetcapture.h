#pragma once
#include <string>
#include <functional>
#include <cstdint>

struct RawPacket
{
    uint64_t ts_us;
    uint32_t len;
    std::vector<uint8_t> data;
};

using PacketHandler = std::function<void(RawPacket &&)>;

class PacketCapture
{
public:
    PacketCapture();
    ~PacketCapture();

    // Initialize with Npcap device name (device string from pcap_findalldevs)
    bool initialize(const std::string &device_name, const std::string &bpf_filter = "");

    // Start capture in current thread (blocking) - returns false on error
    bool capture_loop(const PacketHandler &handler);

    // Stop capture (thread-safe)
    void stop();

private:
    pcap_t *handle = nullptr;
    volatile bool running = false;
};