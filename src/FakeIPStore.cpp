#include "FakeIPStore.h"

#include <arpa/inet.h>
#include <cctype>
#include <charconv>
#include <cstring>
#include <mutex>
#include <shared_mutex>

namespace proxyprism {

namespace {

std::string lowercase(std::string_view value)
{
    std::string result;
    result.reserve(value.size());
    for (char c : value)
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return result;
}

std::string normalize_domain(std::string_view domain)
{
    if (!domain.empty() && domain.back() == '.')
        domain.remove_suffix(1);
    return lowercase(domain);
}

bool is_ipv4_token(std::string_view token)
{
    for (char c : token)
    {
        if (c != '.' && c != '*' && c != '-' && !std::isdigit(static_cast<unsigned char>(c)))
            return false;
    }
    return true;
}

} // namespace

FakeIPStore::FakeIPStore() = default;
FakeIPStore::~FakeIPStore() = default;

bool FakeIPStore::parse_prefix(std::string_view text, FakeIPStore::Pool& pool)
{
    const auto slash = text.find('/');
    const std::string_view address_text = slash == std::string_view::npos ? text : text.substr(0, slash);

    struct in_addr v4;
    struct in6_addr v6;
    int prefix_len = 0;

    if (inet_pton(AF_INET, std::string(address_text).c_str(), &v4) == 1)
    {
        pool.family = AddressFamily::IPv4;
        unsigned __int128 addr = 0;
        for (int i = 0; i < 4; ++i)
            addr = (addr << 8) | reinterpret_cast<const uint8_t*>(&v4)[i];

        if (slash == std::string_view::npos)
            prefix_len = 32;
        else if (std::from_chars(text.data() + slash + 1, text.data() + text.size(), prefix_len).ec != std::errc{} || prefix_len < 0 || prefix_len > 32)
            return false;

        unsigned __int128 mask = prefix_len == 0 ? 0 : (((unsigned __int128)1) << (32 - prefix_len)) - 1;
        unsigned __int128 network = addr & ~mask;
        unsigned __int128 broadcast = network | mask;

        pool.network = network;
        pool.first = network + 2;   // skip network and network+1
        pool.last = broadcast - 1;  // skip broadcast
        pool.prefix_len = prefix_len;
        pool.current = 0;
        pool.valid = pool.first <= pool.last;
        return pool.valid;
    }

    if (inet_pton(AF_INET6, std::string(address_text).c_str(), &v6) == 1)
    {
        pool.family = AddressFamily::IPv6;
        unsigned __int128 addr = 0;
        for (int i = 0; i < 16; ++i)
            addr = (addr << 8) | v6.s6_addr[i];

        if (slash == std::string_view::npos)
            prefix_len = 128;
        else if (std::from_chars(text.data() + slash + 1, text.data() + text.size(), prefix_len).ec != std::errc{} || prefix_len < 0 || prefix_len > 128)
            return false;

        unsigned __int128 mask = prefix_len == 0 ? 0 : (((unsigned __int128)1) << (128 - prefix_len)) - 1;
        unsigned __int128 network = addr & ~mask;

        // Cap IPv6 usable range to a reasonable size so wrap/scan stays cheap.
        constexpr unsigned __int128 max_usable = 131071;
        unsigned __int128 usable = mask;
        if (usable > max_usable)
            usable = max_usable;

        pool.network = network;
        pool.first = network + 2;
        pool.last = network + usable - 1;
        pool.prefix_len = prefix_len;
        pool.current = 0;
        pool.valid = pool.first <= pool.last;
        return pool.valid;
    }

    return false;
}

NetworkAddress FakeIPStore::to_address(const FakeIPStore::Pool& pool, unsigned __int128 value)
{
    NetworkAddress address;
    address.family = pool.family;
    address.bytes.fill(0);

    if (pool.family == AddressFamily::IPv4)
    {
        for (int i = 3; i >= 0; --i)
        {
            address.bytes[static_cast<size_t>(i)] = static_cast<uint8_t>(value & 0xff);
            value >>= 8;
        }
    }
    else
    {
        for (int i = 15; i >= 0; --i)
        {
            address.bytes[static_cast<size_t>(i)] = static_cast<uint8_t>(value & 0xff);
            value >>= 8;
        }
    }

    return address;
}

unsigned __int128 FakeIPStore::to_integer(const NetworkAddress& address)
{
    unsigned __int128 value = 0;
    const size_t len = address.family == AddressFamily::IPv4 ? 4 : 16;
    for (size_t i = 0; i < len; ++i)
        value = (value << 8) | address.bytes[i];
    return value;
}

bool FakeIPStore::set_ipv4_pool(std::string_view prefix)
{
    std::unique_lock lock(lock_);
    return parse_prefix(prefix, ipv4_pool_);
}

bool FakeIPStore::set_ipv6_pool(std::string_view prefix)
{
    std::unique_lock lock(lock_);
    return parse_prefix(prefix, ipv6_pool_);
}

std::optional<NetworkAddress> FakeIPStore::allocate(AddressFamily family, std::string_view domain)
{
    std::unique_lock lock(lock_);

    auto& pool = (family == AddressFamily::IPv6) ? ipv6_pool_ : ipv4_pool_;
    if (!pool.valid)
        return std::nullopt;

    auto& domain_map = (family == AddressFamily::IPv6) ? domain_to_ip_v6_ : domain_to_ip_v4_;
    const std::string key = normalize_domain(domain);

    if (auto it = domain_map.find(key); it != domain_map.end())
        return it->second;

    if (pool.current == 0 || pool.current < pool.first || pool.current > pool.last)
        pool.current = pool.first - 1;

    const unsigned __int128 start = pool.current;
    do
    {
        pool.current++;
        if (pool.current > pool.last)
            pool.current = pool.first;

        NetworkAddress addr = to_address(pool, pool.current);
        if (ip_to_domain_.find(addr) == ip_to_domain_.end())
        {
            domain_map.emplace(key, addr);
            ip_to_domain_.emplace(addr, key);
            return addr;
        }
    } while (pool.current != start);

    return std::nullopt;
}

bool FakeIPStore::contains(const NetworkAddress& address) const
{
    std::shared_lock lock(lock_);

    unsigned __int128 value = to_integer(address);
    if (address.family == AddressFamily::IPv4)
    {
        if (!ipv4_pool_.valid)
            return false;
        if (value < ipv4_pool_.first || value > ipv4_pool_.last)
            return false;
        return (value & ~((((unsigned __int128)1) << (32 - ipv4_pool_.prefix_len)) - 1)) == ipv4_pool_.network;
    }

    if (!ipv6_pool_.valid)
        return false;
    if (value < ipv6_pool_.first || value > ipv6_pool_.last)
        return false;
    return (value & ~((((unsigned __int128)1) << (128 - ipv6_pool_.prefix_len)) - 1)) == ipv6_pool_.network;
}

std::optional<std::string> FakeIPStore::lookup_domain(const NetworkAddress& address) const
{
    std::shared_lock lock(lock_);

    if (auto it = ip_to_domain_.find(address); it != ip_to_domain_.end())
        return it->second;

    return std::nullopt;
}

void FakeIPStore::clear()
{
    std::unique_lock lock(lock_);
    domain_to_ip_v4_.clear();
    domain_to_ip_v6_.clear();
    ip_to_domain_.clear();
    ipv4_pool_.current = 0;
    ipv6_pool_.current = 0;
}

bool FakeIPStore::has_pools() const
{
    std::shared_lock lock(lock_);
    return ipv4_pool_.valid || ipv6_pool_.valid;
}

} // namespace proxyprism
