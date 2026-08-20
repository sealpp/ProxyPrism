#pragma once

#include "NetworkAddress.h"

#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace proxyprism {

class FakeIPStore {
public:
    FakeIPStore();
    ~FakeIPStore();

    // Configure pools. Returns false on invalid CIDR.
    bool set_ipv4_pool(std::string_view prefix);
    bool set_ipv6_pool(std::string_view prefix);

    // Allocate (or reuse) a fake IP for the given domain and address family.
    std::optional<NetworkAddress> allocate(AddressFamily family, std::string_view domain);

    // Check if an address belongs to either fake IP pool.
    bool contains(const NetworkAddress& address) const;

    // Map fake IP back to domain.
    std::optional<std::string> lookup_domain(const NetworkAddress& address) const;

    // Clear all mappings.
    void clear();

    // Pool constants used by callers.
    static constexpr const char* DEFAULT_IPV4_POOL = "198.18.0.0/15";
    static constexpr const char* DEFAULT_IPV6_POOL = "fc00::/18";

private:
    struct Pool {
        AddressFamily family;
        unsigned __int128 first{};      // first usable address
        unsigned __int128 last{};       // last usable address (broadcast - 1)
        unsigned __int128 current{};    // last allocated address
        unsigned __int128 network{};    // network address
        int prefix_len = 0;
        bool valid = false;
    };

    Pool ipv4_pool_;
    Pool ipv6_pool_;

    mutable std::shared_mutex lock_;

    std::unordered_map<std::string, NetworkAddress> domain_to_ip_v4_;
    std::unordered_map<std::string, NetworkAddress> domain_to_ip_v6_;
    std::unordered_map<NetworkAddress, std::string, NetworkAddressHash> ip_to_domain_;

    static bool parse_prefix(std::string_view text, Pool& pool);
    static NetworkAddress to_address(const Pool& pool, unsigned __int128 value);
    static unsigned __int128 to_integer(const NetworkAddress& address);

    std::optional<NetworkAddress> allocate_in_pool(Pool& pool, std::unordered_map<std::string, NetworkAddress>& domain_map, std::string_view domain);
};

} // namespace proxyprism
