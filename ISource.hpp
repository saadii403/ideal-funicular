#pragma once
#include <functional>
#include "core/Packet.hpp"

namespace capture {

class ISource {
public:
    using Callback = std::function<void(core::Packet&&)>;
    virtual ~ISource() = default;
    virtual void start(Callback cb) = 0;
    virtual void stop() = 0;
};

} // namespace capture
