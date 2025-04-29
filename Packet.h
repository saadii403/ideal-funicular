#ifndef PACKET_H
#define PACKET_H

#include <string>
#include <chrono>

class Packet {
public:
    Packet(std::string srcIP, std::string dstIP, int srcPort, int dstPort, std::string protocol, std::chrono::system_clock::time_point timestamp, int length);

    std::string getSourceIP() const;
    std::string getDestinationIP() const;
    int getSourcePort() const;
    int getDestinationPort() const;
    std::string getProtocol() const;
    std::chrono::system_clock::time_point getTimestamp() const;
    int getLength() const;

private:
    std::string sourceIP;
    std::string destinationIP;
    int sourcePort;
    int destinationPort;
    std::string protocol;
    std::chrono::system_clock::time_point timestamp;
    int length;
};

#endif // PACKET_H