#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <arpa/inet.h> // windows: provided by Ws2_32; include path in CMake

struct FiveTuple
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
};

struct ParsedPacket
{
    FiveTuple ft;
    const uint8_t *payload;
    size_t payload_len;
    uint64_t ts_us;
    bool valid;
    std::string src_str() const;
    std::string dst_str() const;
};

bool parse_ethernet_ipv4(const uint8_t *data, size_t len, ParsedPacket &out);