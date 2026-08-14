#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
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

} // namespace proxyprism
