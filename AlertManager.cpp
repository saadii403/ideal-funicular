#include "AlertManager.h"
#include <iostream>
#include <iomanip>

void AlertManager::logAlert(const Alert& alert) {
    std::lock_guard<std::mutex> lock(alertMutex);
    alerts.push_back(alert);

    
    // Simple log to file
    std::ofstream file("alerts.log", std::ios::app);
    if (file.is_open()) {
        std::time_t t = std::chrono::system_clock::to_time_t(alert.getTimestamp());
        file << "[" << std::put_time(std::localtime(&t), "%F %T") << "] "
             << alert.getType() << ": " << alert.getDescription() << "\n";
    }
}

void AlertManager::showAlerts() const {
    std::lock_guard<std::mutex> lock(alertMutex);
    std::cout << "=== ALERT LOG ===\n";
    for (const auto& alert : alerts) {
        std::time_t t = std::chrono::system_clock::to_time_t(alert.getTimestamp());
        std::cout << "[" << std::put_time(std::localtime(&t), "%F %T") << "] "
                  << alert.getType() << ": " << alert.getDescription() << "\n";
    }
}

void AlertManager::clearAlerts() {
    std::lock_guard<std::mutex> lock(alertMutex);
    alerts.clear();
}