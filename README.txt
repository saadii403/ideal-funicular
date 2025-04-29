Modern C++ Intrusion Detection and Prevention System (IDS/IPS)
===============================================================

Project Description:
---------------------
This project is a real-time Intrusion Detection and Prevention System (IDS/IPS) built using Modern C++17 principles.  
It captures live network traffic or analyzes saved PCAP files to detect suspicious activities such as packet floods, port scanning, and known blacklisted IPs.  
Upon detecting an attack, it generates an alert, saves it to a log file, and dynamically blocks the attacker’s IP address using the Windows Firewall.

Features:
---------
- Real-time live network packet capture using Npcap.
- Offline packet analysis from Wireshark `.pcap` files.
- Signature-based detection (known malicious IPs, suspicious ports).
- Smart anomaly detection (packet flood, port scanning, large packet size).
- GeoIP lookup to identify the country of attacking IP addresses.
- Automatic firewall blocking of attackers (both inbound and outbound).
- Logging of all alerts to a file (`alerts.log`) with timestamps.
- Console-based interactive menu system.
- Fully thread-safe alert management.
- Highly modular and extensible design.

Technologies Used:
-------------------
- C++17
- WinPcap/Npcap for packet capture
- Windows Command Line (netsh) for firewall rule management
- Standard C++ libraries: STL, chrono, mutex, unordered_map, vector

Object-Oriented Concepts Applied:
-----------------------------------
- **Encapsulation**: 
  - Data hiding through private members (Packet, Alert, FirewallManager, etc.).
- **Inheritance**: 
  - SignatureAnalyzer and AnomalyAnalyzer inherit from the Analyzer abstract class.
- **Polymorphism**: 
  - Virtual functions (analyze(), getName()) allow flexible analyzer behavior.
- **Abstraction**: 
  - Complex operations (packet parsing, firewall rule adding) are hidden behind clean interfaces.

Folder Structure:
------------------
- src/
  - All `.cpp` and `.h` source files.
- alerts.log
  - Log file where all alerts are recorded.
- PCAP samples (optional)
  - Test files for offline analysis.

How to Build:
--------------
1. Install Npcap (compatible with WinPcap applications).
2. Open the project in Visual Studio Code, Embarcadero Dev C++, or any modern C++17-supporting IDE.
3. Link against pcap.lib and include pcap.h from the Npcap SDK.
4. Ensure C++17 is selected as the standard.
5. Build the project successfully.

How to Run:
------------
1. Start the executable.
2. Choose an option from the menu:
   - List available network interfaces.
   - Start live packet capture (select an interface).
   - Analyze a saved PCAP file.
   - View logged alerts.
   - Clear alerts.
3. Monitor real-time alerts and watch attackers being blocked automatically.

Authors:
-------
Hamza zaka khan
Muhammad Saad
Ibrahim Malhi

