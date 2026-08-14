#include "NetworkAddress.h"

#include <arpa/inet.h>
#include <charconv>
#include <cstring>

namespace proxyprism {
namespace {

std::string_view trim(std::string_view value)
{
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.front() == '\r' || value.front() == '\n'))
        value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r' || value.back() == '\n'))
        value.remove_suffix(1);
    return value;
}

bool parse_decimal(std::string_view text, int minimum, int maximum, int* value)
{
    if (text.empty())
        return false;

    int parsed = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (ec != std::errc{} || ptr != text.data() + text.size() || parsed < minimum || parsed > maximum)
        return false;

    *value = parsed;
    return true;
}

bool parse_port_pattern(std::string_view pattern, int* first, int* last)
{
    pattern = trim(pattern);
    if (pattern == "*")
    {
        *first = 1;
        *last = 65535;
        return true;
    }

    const auto dash = pattern.find('-');
    if (dash == std::string_view::npos)
    {
        if (!parse_decimal(pattern, 1, 65535, first))
            return false;
        *last = *first;
        return true;
    }

    if (pattern.find('-', dash + 1) != std::string_view::npos)
        return false;
    if (!parse_decimal(pattern.substr(0, dash), 1, 65535, first)
        || !parse_decimal(pattern.substr(dash + 1), 1, 65535, last))
        return false;
    return *first <= *last;
}

bool parse_ipv4_octet_pattern(std::string_view pattern, int* first, int* last)
{
    if (pattern == "*")
    {
        *first = 0;
        *last = 255;
        return true;
    }

    const auto dash = pattern.find('-');
    if (dash == std::string_view::npos)
    {
        if (!parse_decimal(pattern, 0, 255, first))
            return false;
        *last = *first;
        return true;
    }

    if (pattern.find('-', dash + 1) != std::string_view::npos)
        return false;
    if (!parse_decimal(pattern.substr(0, dash), 0, 255, first)
        || !parse_decimal(pattern.substr(dash + 1), 0, 255, last))
        return false;
    return *first <= *last;
}

bool match_ipv4_wildcard(std::string_view pattern, const NetworkAddress& address)
{
    if (address.family != AddressFamily::IPv4)
        return false;

    std::size_t offset = 0;
    for (int index = 0; index < 4; ++index)
    {
        const auto dot = pattern.find('.', offset);
        if ((index < 3 && dot == std::string_view::npos) || (index == 3 && dot != std::string_view::npos))
            return false;

        const auto end = index < 3 ? dot : pattern.size();
        int first = 0;
        int last = 0;
        if (!parse_ipv4_octet_pattern(pattern.substr(offset, end - offset), &first, &last))
            return false;
        if (address.bytes[index] < first || address.bytes[index] > last)
            return false;
        offset = end + 1;
    }

    return true;
}

bool validate_ipv4_wildcard(std::string_view pattern)
{
    NetworkAddress placeholder;
    placeholder.family = AddressFamily::IPv4;
    return match_ipv4_wildcard(pattern, placeholder) || [&]() {
        std::size_t offset = 0;
        for (int index = 0; index < 4; ++index)
        {
            const auto dot = pattern.find('.', offset);
            if ((index < 3 && dot == std::string_view::npos) || (index == 3 && dot != std::string_view::npos))
                return false;
            const auto end = index < 3 ? dot : pattern.size();
            int first = 0;
            int last = 0;
            if (!parse_ipv4_octet_pattern(pattern.substr(offset, end - offset), &first, &last))
                return false;
            offset = end + 1;
        }
        return true;
    }();
}

bool parse_prefix(std::string_view pattern, NetworkAddress* network, int* prefix_length)
{
    const auto slash = pattern.find('/');
    const std::string_view address_text = slash == std::string_view::npos ? pattern : pattern.substr(0, slash);
    const auto parsed = parse_network_address(address_text);
    if (!parsed.has_value())
        return false;

    *network = *parsed;
    if (slash == std::string_view::npos)
    {
        *prefix_length = network->family == AddressFamily::IPv4 ? 32 : 128;
        return true;
    }

    if (pattern.find('/', slash + 1) != std::string_view::npos)
        return false;

    const int maximum = network->family == AddressFamily::IPv4 ? 32 : 128;
    return parse_decimal(pattern.substr(slash + 1), 0, maximum, prefix_length);
}

bool prefix_matches(const NetworkAddress& network, int prefix_length, const NetworkAddress& address)
{
    if (network.family != address.family)
        return false;

    const int whole_bytes = prefix_length / 8;
    const int remaining_bits = prefix_length % 8;
    if (whole_bytes > 0 && memcmp(network.bytes.data(), address.bytes.data(), whole_bytes) != 0)
        return false;
    if (remaining_bits == 0)
        return true;

    const std::uint8_t mask = static_cast<std::uint8_t>(0xffU << (8 - remaining_bits));
    return (network.bytes[whole_bytes] & mask) == (address.bytes[whole_bytes] & mask);
}

template <typename Match>
bool any_token(std::string_view list, std::string_view delimiters, Match&& match)
{
    std::size_t begin = 0;
    while (begin <= list.size())
    {
        const auto end = list.find_first_of(delimiters, begin);
        const auto token = trim(list.substr(begin, end == std::string_view::npos ? list.size() - begin : end - begin));
        if (!token.empty() && match(token))
            return true;
        if (end == std::string_view::npos)
            break;
        begin = end + 1;
    }
    return false;
}

template <typename Validate>
bool validate_tokens(std::string_view list, std::string_view delimiters, Validate&& validate, std::string* error_message)
{
    if (list.empty())
    {
        if (error_message != nullptr)
            *error_message = "empty list";
        return false;
    }

    std::size_t begin = 0;
    while (begin <= list.size())
    {
        const auto end = list.find_first_of(delimiters, begin);
        const auto token = trim(list.substr(begin, end == std::string_view::npos ? list.size() - begin : end - begin));
        if (token.empty() || !validate(token))
        {
            if (error_message != nullptr)
                *error_message = "invalid token '" + std::string(token) + "'";
            return false;
        }
        if (end == std::string_view::npos)
            return true;
        begin = end + 1;
    }
    return false;
}

} // namespace

std::optional<NetworkAddress> parse_network_address(std::string_view text)
{
    text = trim(text);
    if (text.empty())
        return std::nullopt;

    NetworkAddress address;
    std::string input(text);
    if (inet_pton(AF_INET, input.c_str(), address.bytes.data()) == 1)
    {
        address.family = AddressFamily::IPv4;
        return address;
    }
    if (inet_pton(AF_INET6, input.c_str(), address.bytes.data()) == 1)
    {
        address.family = AddressFamily::IPv6;
        return address;
    }
    return std::nullopt;
}

std::string format_network_address(const NetworkAddress& address)
{
    char buffer[INET6_ADDRSTRLEN]{};
    const int family = address.family == AddressFamily::IPv4 ? AF_INET : AF_INET6;
    if (inet_ntop(family, address.bytes.data(), buffer, sizeof(buffer)) == nullptr)
        return {};
    return buffer;
}

bool match_host_pattern(std::string_view pattern, const NetworkAddress& address)
{
    pattern = trim(pattern);
    if (pattern == "*")
        return true;

    if (address.family == AddressFamily::IPv4 && (pattern.find('*') != std::string_view::npos || pattern.find('-') != std::string_view::npos))
        return match_ipv4_wildcard(pattern, address);

    NetworkAddress network;
    int prefix_length = 0;
    return parse_prefix(pattern, &network, &prefix_length) && prefix_matches(network, prefix_length, address);
}

bool match_host_list(std::string_view patterns, const NetworkAddress& address)
{
    return any_token(patterns, ";", [&](std::string_view token) { return match_host_pattern(token, address); });
}

bool validate_host_list(std::string_view patterns, std::string* error_message)
{
    return validate_tokens(
        patterns,
        ";",
        [](std::string_view token) {
            if (token == "*")
                return true;
            if (token.find('*') != std::string_view::npos || token.find('-') != std::string_view::npos)
                return validate_ipv4_wildcard(token);
            NetworkAddress network;
            int prefix_length = 0;
            return parse_prefix(token, &network, &prefix_length);
        },
        error_message);
}

bool match_port_list(std::string_view patterns, std::uint16_t port)
{
    return any_token(patterns, ",;", [&](std::string_view token) {
        int first = 0;
        int last = 0;
        return parse_port_pattern(token, &first, &last) && port >= first && port <= last;
    });
}

bool validate_port_list(std::string_view patterns, std::string* error_message)
{
    return validate_tokens(
        patterns,
        ",;",
        [](std::string_view token) {
            int first = 0;
            int last = 0;
            return parse_port_pattern(token, &first, &last);
        },
        error_message);
}

} // namespace proxyprism
