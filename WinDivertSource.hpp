#pragma once
#include <atomic>
#include <string>
#include <thread>
#include <functional>
#include "capture/ISource.hpp"
#include "ips/Action.hpp"

// Forward declarations for WinDivert types
typedef void* HANDLE;
struct WINDIVERT_ADDRESS;

namespace ips {

enum class WinDivertLayer {
    Network = 0,    // Network layer (IP packets)
    Forward = 1,    // Forward layer (forwarded packets)
    Flow = 2,       // Flow layer (flow events)
    Socket = 3,     // Socket layer (socket events)
    Reflect = 4     // Reflect layer (reflected packets)
};

class WinDivertSource : public capture::ISource {
public:
    explicit WinDivertSource(const std::string& filter = "true", WinDivertLayer layer = WinDivertLayer::Network);
    ~WinDivertSource() override;

    void start(Callback cb) override;
    void stop() override;

    // IPS-specific methods
    void set_decision_callback(std::function<Decision(const core::Packet&)> cb);
    bool inject_packet(const core::Packet& packet);

private:
    void capture_loop(Callback cb);
    Decision make_decision(const core::Packet& packet);

    std::string filter_;
    WinDivertLayer layer_;
    HANDLE handle_{nullptr};
    std::atomic<bool> running_{false};
    std::thread worker_;
    std::function<Decision(const core::Packet&)> decision_callback_;
};

} // namespace ips
