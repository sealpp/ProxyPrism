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

std::size_t address_byte_count(const NetworkAddress& address)
{
    return address.family == AddressFamily::IPv4 ? 4 : 16;
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

NetworkAddress network_address_from_ipv4(uint32_t ip)
{
    NetworkAddress address;
    address.family = AddressFamily::IPv4;
    memcpy(address.bytes.data(), &ip, 4);
    return address;
}

NetworkAddress network_address_from_ipv6(const in6_addr& ip)
{
    NetworkAddress address;
    address.family = AddressFamily::IPv6;
    memcpy(address.bytes.data(), &ip, 16);
    return address;
}

NetworkAddress network_address_from_sockaddr(const sockaddr* address)
{
    if (address->sa_family == AF_INET6)
        return network_address_from_ipv6(((const sockaddr_in6*)address)->sin6_addr);
    return network_address_from_ipv4(((const sockaddr_in*)address)->sin_addr.s_addr);
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

static bool looks_like_ip_pattern(std::string_view token)
{
    // IPv6 literal or CIDR
    if (token.find(':') != std::string_view::npos || token.find('/') != std::string_view::npos)
        return true;

    // IPv4-style wildcard or range
    bool has_wildcard_or_range = false;
    for (char c : token)
    {
        if (c == '*' || c == '-')
        {
            has_wildcard_or_range = true;
        }
        else if (c != '.' && (c < '0' || c > '9'))
        {
            // contains letters or other characters, not a pure IPv4 pattern
            return false;
        }
    }

    // pure IPv4 with optional wildcard/range
    return has_wildcard_or_range || token.find('.') != std::string_view::npos;
}

bool validate_host_list(std::string_view patterns, std::string* error_message)
{
    return validate_tokens(
        patterns,
        ";",
        [](std::string_view token) {
            if (token == "*")
                return true;
            NetworkAddress network;
            int prefix_length = 0;
            if (parse_prefix(token, &network, &prefix_length))
                return true;
            if (token.find('*') != std::string_view::npos || token.find('-') != std::string_view::npos)
                if (validate_ipv4_wildcard(token))
                    return true;
            if (looks_like_ip_pattern(token))
                return false;
            return validate_domain_pattern(token);
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

bool encode_socks5_address(
    const NetworkAddress& address,
    std::uint16_t port,
    std::uint8_t* output,
    std::size_t output_size,
    std::size_t* encoded_size)
{
    const std::size_t address_size = address_byte_count(address);
    const std::size_t required = 1 + address_size + 2;
    if (output == nullptr || encoded_size == nullptr || output_size < required)
        return false;

    output[0] = address.family == AddressFamily::IPv4 ? 0x01 : 0x04;
    memcpy(output + 1, address.bytes.data(), address_size);
    const std::uint16_t network_port = htons(port);
    memcpy(output + 1 + address_size, &network_port, sizeof(network_port));
    *encoded_size = required;
    return true;
}

bool decode_socks5_address(
    const std::uint8_t* input,
    std::size_t input_size,
    NetworkAddress* address,
    std::uint16_t* port,
    std::size_t* decoded_size)
{
    if (input == nullptr || address == nullptr || port == nullptr || decoded_size == nullptr || input_size < 1)
        return false;

    const std::size_t address_size = input[0] == 0x01 ? 4 : input[0] == 0x04 ? 16 : 0;
    const std::size_t required = 1 + address_size + 2;
    if (address_size == 0 || input_size < required)
        return false;

    address->family = input[0] == 0x01 ? AddressFamily::IPv4 : AddressFamily::IPv6;
    address->bytes.fill(0);
    memcpy(address->bytes.data(), input + 1, address_size);
    std::uint16_t network_port = 0;
    memcpy(&network_port, input + 1 + address_size, sizeof(network_port));
    *port = ntohs(network_port);
    *decoded_size = required;
    return true;
}

bool make_loopback_endpoint(
    AddressFamily family,
    std::uint16_t port,
    sockaddr_storage* endpoint,
    socklen_t* endpoint_size)
{
    if (endpoint == nullptr || endpoint_size == nullptr)
        return false;

    memset(endpoint, 0, sizeof(*endpoint));
    if (family == AddressFamily::IPv4)
    {
        auto* ipv4 = reinterpret_cast<sockaddr_in*>(endpoint);
        ipv4->sin_family = AF_INET;
        ipv4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ipv4->sin_port = htons(port);
        *endpoint_size = sizeof(*ipv4);
    }
    else
    {
        auto* ipv6 = reinterpret_cast<sockaddr_in6*>(endpoint);
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_addr = in6addr_loopback;
        ipv6->sin6_port = htons(port);
        *endpoint_size = sizeof(*ipv6);
    }
    return true;
}

// Domain glob matching: '*' matches any substring (including empty), '?' matches any single character.
// Matching is case-insensitive and ignores a trailing dot on the domain.

namespace {

std::string normalize_for_match(std::string_view value)
{
    std::string result;
    result.reserve(value.size());
    for (char c : value)
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (!result.empty() && result.back() == '.')
        result.pop_back();
    return result;
}

bool glob_match(const char* p, std::size_t plen, const char* d, std::size_t dlen)
{
    std::size_t pi = 0;
    std::size_t di = 0;
    std::size_t star_pi = std::string::npos;
    std::size_t star_di = 0;

    while (di < dlen)
    {
        if (pi < plen && (p[pi] == '?' || p[pi] == d[di]))
        {
            ++pi;
            ++di;
        }
        else if (pi < plen && p[pi] == '*')
        {
            star_pi = pi++;
            star_di = di;
        }
        else if (star_pi != std::string::npos)
        {
            pi = star_pi + 1;
            di = ++star_di;
        }
        else
        {
            return false;
        }
    }

    while (pi < plen && p[pi] == '*')
        ++pi;

    return pi == plen;
}

} // namespace

bool match_domain_pattern(std::string_view pattern, std::string_view domain)
{
    const std::string p = normalize_for_match(pattern);
    const std::string d = normalize_for_match(domain);
    return glob_match(p.c_str(), p.size(), d.c_str(), d.size());
}

bool match_domain_list(std::string_view patterns, std::string_view domain)
{
    return any_token(patterns, ";", [&](std::string_view token) { return match_domain_pattern(token, domain); });
}

bool validate_domain_pattern(std::string_view pattern)
{
    pattern = trim(pattern);
    if (pattern.empty())
        return false;
    if (pattern == "*")
        return true;
    // Accept any non-empty token that does not contain the list delimiter.
    return pattern.find(';') == std::string_view::npos;
}

bool match_target_list(std::string_view patterns, const NetworkAddress& address, std::string_view domain)
{
    return any_token(patterns, ";", [&](std::string_view token) {
        if (match_host_pattern(token, address))
            return true;
        if (!domain.empty())
            return match_domain_pattern(token, domain);
        return false;
    });
}

std::size_t NetworkAddressHash::operator()(const NetworkAddress& address) const noexcept
{
    std::size_t hash = static_cast<std::size_t>(address.family);
    for (std::size_t i = 0; i < 16; ++i)
    {
        hash = hash * 1315423911u + address.bytes[i];
    }
    return hash;
}

} // namespace proxyprism
