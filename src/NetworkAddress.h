#pragma once

#include <array>
#include <cstdint>
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

} // namespace proxyprism
