#include "Alert.h"

Alert::Alert(std::string type, std::string description, std::chrono::system_clock::time_point timestamp)
    : type(std::move(type)), description(std::move(description)), timestamp(timestamp) {}

std::string Alert::getType() const {
    return type;
}

std::string Alert::getDescription() const {
    return description;
}

std::chrono::system_clock::time_point Alert::getTimestamp() const {
    return timestamp;
}