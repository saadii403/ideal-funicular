#ifndef ALERT_H
#define ALERT_H

#include <string>
#include <chrono>

class Alert {
public:
    Alert(std::string type, std::string description, std::chrono::system_clock::time_point timestamp);

    std::string getType() const;
    std::string getDescription() const;
    std::chrono::system_clock::time_point getTimestamp() const;

private:
    std::string type;
    std::string description;
    std::chrono::system_clock::time_point timestamp;
};

#endif // ALERT_H