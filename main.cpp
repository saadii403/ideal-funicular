#include "IDS.h"
#include <pcap.h>
#include <iostream>
#include <vector>
#include <string>

void listInterfaces() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[Error] Unable to list interfaces: " << errbuf << "\n";
        return;
    }

    int index = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        std::cout << "[" << index++ << "] " << (d->description ? d->description : d->name) << "\n";
    }

    pcap_freealldevs(alldevs);
}

std::string selectInterface() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[Error] Unable to list interfaces: " << errbuf << "\n";
        return "";
    }

    std::vector<pcap_if_t*> interfaces;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        interfaces.push_back(d);
    }

    for (size_t i = 0; i < interfaces.size(); ++i) {
        std::cout << "[" << i << "] " << (interfaces[i]->description ? interfaces[i]->description : interfaces[i]->name) << "\n";
    }

    std::cout << "Enter the number of the interface to use: ";
    size_t choice;
    std::cin >> choice;

    std::string name = interfaces[choice]->name;

    pcap_freealldevs(alldevs);
    return name;
}

int main() {
    IDS ids;
    int choice;

    do {
        std::cout << "\n===== IDS/IPS Menu =====\n";
        std::cout << "1. List Network Interfaces\n";
        std::cout << "2. Start Live Capture\n";
        std::cout << "3. Analyze PCAP File\n";
        std::cout << "4. View Alerts\n";
        std::cout << "5. Clear Alerts\n";
        std::cout << "6. Exit\n";
        std::cout << "Enter choice: ";
        std::cin >> choice;

        if (choice == 1) {
            listInterfaces();
        } else if (choice == 2) {
            std::string iface = selectInterface();
            if (!iface.empty()) {
                ids.startLiveCapture(iface);
            }
        } else if (choice == 3) {
            std::string filename;
            std::cout << "Enter PCAP file path: ";
            std::cin >> filename;
            ids.loadPcapFile(filename);
        } else if (choice == 4) {
            ids.showAlerts();
        } else if (choice == 5) {
            ids.clearAlerts();
            std::cout << "[*] Alerts cleared.\n";
        }

    } while (choice != 6);

    std::cout << "Exiting...\n";
    return 0;
}