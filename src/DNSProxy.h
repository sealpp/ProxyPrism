#pragma once

#include "FakeIPStore.h"
#include "NetworkAddress.h"

#include <cstdint>
#include <functional>
#include <netinet/in.h>
#include <sys/socket.h>

namespace proxyprism {

using LogCallback = std::function<void(const char*)>;

class DNSProxy {
public:
    DNSProxy(FakeIPStore& store, const sockaddr_storage& nameserver, socklen_t nameserver_len, uint32_t self_pid);
    ~DNSProxy();

    bool start(uint16_t port = 34053);
    void stop();

private:
    void run();

    FakeIPStore& store_;
    sockaddr_storage nameserver_;
    socklen_t nameserver_len_;
    uint32_t self_pid_;

    int udp4_ = -1;
    int udp6_ = -1;
    int tcp4_ = -1;
    int tcp6_ = -1;
    int mark_for_bypass_ = 0xFF;

    bool running_ = false;
    pthread_t thread_ = 0;
};

} // namespace proxyprism
