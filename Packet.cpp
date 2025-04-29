#include "Packet.h"

Packet::Packet(std::string srcIP, std::string dstIP, int srcPort, int dstPort, std::string protocol, std::chrono::system_clock::time_point timestamp, int length)
    : sourceIP(std::move(srcIP)), destinationIP(std::move(dstIP)), sourcePort(srcPort),
      destinationPort(dstPort), protocol(std::move(protocol)), timestamp(timestamp), length(length) {}

std::string Packet::getSourceIP() const {
    return sourceIP;
}

std::string Packet::getDestinationIP() const {
    return destinationIP;
}

int Packet::getSourcePort() const {
    return sourcePort;
}

int Packet::getDestinationPort() const {
    return destinationPort;
}

std::string Packet::getProtocol() const {
    return protocol;
}

std::chrono::system_clock::time_point Packet::getTimestamp() const {
    return timestamp;
}

int Packet::getLength() const {
    return length;
}