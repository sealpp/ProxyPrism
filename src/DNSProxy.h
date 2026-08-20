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

    // Resolve an original domain directly against the configured real nameserver.
    // The query socket is marked so it bypasses the local fake-DNS REDIRECT path.
    // preferred_family hints which record type to prefer (IPv4 or IPv6); both are
    // queried if needed and the other family is used as fallback.
    bool resolve_domain(
        const char* domain,
        std::uint16_t port,
        sockaddr_storage* out,
        socklen_t* out_len,
        AddressFamily preferred_family = AddressFamily::IPv4);

private:
    void run();
    bool resolve_domain_qtype(const char* domain, std::uint16_t port, std::uint16_t qtype, sockaddr_storage* out, socklen_t* out_len);

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
