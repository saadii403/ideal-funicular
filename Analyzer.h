#ifndef ANALYZER_H
#define ANALYZER_H

#include "Packet.h"
#include <vector>
#include <memory>

class Analyzer {
public:
    virtual ~Analyzer() = default;
    virtual void analyze(const Packet& packet) = 0;
    virtual std::string getName() const = 0;
};

#endif // ANALYZER_H