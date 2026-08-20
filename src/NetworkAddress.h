#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <netinet/in.h>
#include <sys/socket.h>
#include <optional>
#include <string>
#include <string_view>

namespace proxyprism {

enum class AddressFamily : std::uint8_t
{
    IPv4,
    IPv6,
};

struct NetworkAddress
{
    AddressFamily family = AddressFamily::IPv4;
    std::array<std::uint8_t, 16> bytes{};

    bool operator==(const NetworkAddress&) const = default;
};

std::optional<NetworkAddress> parse_network_address(std::string_view text);
std::string format_network_address(const NetworkAddress& address);

bool match_host_pattern(std::string_view pattern, const NetworkAddress& address);
bool match_host_list(std::string_view patterns, const NetworkAddress& address);
bool validate_host_list(std::string_view patterns, std::string* error_message = nullptr);

// Domain rule matching. Patterns support glob: '*' matches any substring (including empty),
// '?' matches any single character. Matching is case-insensitive and ignores a trailing dot.
bool match_domain_pattern(std::string_view pattern, std::string_view domain);
bool match_domain_list(std::string_view patterns, std::string_view domain);
bool validate_domain_pattern(std::string_view pattern);

// Match against a mixed `hosts` field that may contain IPs or domain patterns.
bool match_target_list(std::string_view patterns, const NetworkAddress& address, std::string_view domain);

bool match_port_list(std::string_view patterns, std::uint16_t port);
bool validate_port_list(std::string_view patterns, std::string* error_message = nullptr);

bool encode_socks5_address(
    const NetworkAddress& address,
    std::uint16_t port,
    std::uint8_t* output,
    std::size_t output_size,
    std::size_t* encoded_size);
bool decode_socks5_address(
    const std::uint8_t* input,
    std::size_t input_size,
    NetworkAddress* address,
    std::uint16_t* port,
    std::size_t* decoded_size);

bool make_loopback_endpoint(
    AddressFamily family,
    std::uint16_t port,
    sockaddr_storage* endpoint,
    socklen_t* endpoint_size);

NetworkAddress network_address_from_ipv4(std::uint32_t ip);
NetworkAddress network_address_from_ipv6(const in6_addr& ip);
NetworkAddress network_address_from_sockaddr(const sockaddr* address);

struct NetworkAddressHash {
    std::size_t operator()(const NetworkAddress& address) const noexcept;
};

} // namespace proxyprism
