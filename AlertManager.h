#ifndef ALERTMANAGER_H
#define ALERTMANAGER_H

#include "Alert.h"
#include <vector>
#include <fstream>
#include <mutex>

class AlertManager {
public:
    void logAlert(const Alert& alert);
    void showAlerts() const;
    void clearAlerts();

private:
    std::vector<Alert> alerts;
    mutable std::mutex alertMutex;
};

#endif // ALERTMANAGER_H