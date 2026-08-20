#include "NetworkAddress.h"

#include <arpa/inet.h>

#include <gtest/gtest.h>

namespace proxyprism {
namespace {

TEST(NetworkAddress, ParsesAndFormatsIpv4AndIpv6)
{
    const auto ipv4 = parse_network_address("192.0.2.10");
    const auto ipv6 = parse_network_address("2001:db8::10");

    ASSERT_TRUE(ipv4.has_value());
    ASSERT_TRUE(ipv6.has_value());
    EXPECT_EQ(ipv4->family, AddressFamily::IPv4);
    EXPECT_EQ(ipv6->family, AddressFamily::IPv6);
    EXPECT_EQ(format_network_address(*ipv4), "192.0.2.10");
    EXPECT_EQ(format_network_address(*ipv6), "2001:db8::10");
}

TEST(NetworkAddress, MatchesCidrsWithoutCrossingFamilies)
{
    const auto ipv4 = parse_network_address("192.0.2.10");
    const auto ipv6 = parse_network_address("2001:db8:1::10");

    ASSERT_TRUE(ipv4.has_value());
    ASSERT_TRUE(ipv6.has_value());
    EXPECT_TRUE(match_host_pattern("192.0.2.0/24", *ipv4));
    EXPECT_FALSE(match_host_pattern("192.0.3.0/24", *ipv4));
    EXPECT_TRUE(match_host_pattern("2001:db8::/32", *ipv6));
    EXPECT_FALSE(match_host_pattern("2001:db9::/32", *ipv6));
    EXPECT_FALSE(match_host_pattern("192.0.2.0/24", *ipv6));
}

TEST(NetworkAddress, PreservesIpv4WildcardAndRangeRules)
{
    const auto address = parse_network_address("192.168.12.42");
    ASSERT_TRUE(address.has_value());

    EXPECT_TRUE(match_host_pattern("192.168.*.*", *address));
    EXPECT_TRUE(match_host_pattern("192.168.10-20.40-50", *address));
    EXPECT_FALSE(match_host_pattern("192.168.13-20.*", *address));
}

TEST(NetworkAddress, RejectsInvalidHostAndPortRules)
{
    EXPECT_TRUE(validate_host_list("example.com"));
    EXPECT_TRUE(validate_host_list("*.example.com"));
    EXPECT_FALSE(validate_host_list("2001:db8::/129"));
    EXPECT_FALSE(validate_host_list("2001:db8:*"));
    EXPECT_FALSE(validate_host_list("192.168.1.300"));
    EXPECT_FALSE(validate_port_list("0"));
    EXPECT_FALSE(validate_port_list("443-80"));
    EXPECT_FALSE(validate_port_list("80x"));
    EXPECT_TRUE(validate_port_list("53;80,443-8443"));
}

TEST(NetworkAddress, MatchesMixedIpAndDomainRules)
{
    const auto ipv4 = parse_network_address("192.0.2.10");
    ASSERT_TRUE(ipv4.has_value());

    EXPECT_TRUE(match_target_list("192.0.2.0/24", *ipv4, "example.com"));
    EXPECT_FALSE(match_target_list("192.0.3.0/24", *ipv4, "example.com"));
    EXPECT_TRUE(match_target_list("*.example.com", *ipv4, "www.example.com"));
    EXPECT_TRUE(match_target_list("example.com;192.0.2.0/24", *ipv4, "other.org"));
    EXPECT_FALSE(match_target_list("*.example.com", *ipv4, "example.org"));
}

TEST(NetworkAddress, EncodesAndDecodesSocks5Ipv6Addresses)
{
    const auto expected = parse_network_address("2001:db8::53");
    ASSERT_TRUE(expected.has_value());

    std::array<std::uint8_t, 32> encoded{};
    std::size_t encoded_size = 0;
    ASSERT_TRUE(encode_socks5_address(*expected, 5353, encoded.data(), encoded.size(), &encoded_size));
    EXPECT_EQ(encoded[0], 0x04);
    EXPECT_EQ(encoded_size, 19U);

    NetworkAddress decoded;
    std::uint16_t port = 0;
    std::size_t decoded_size = 0;
    ASSERT_TRUE(decode_socks5_address(encoded.data(), encoded_size, &decoded, &port, &decoded_size));
    EXPECT_EQ(decoded, *expected);
    EXPECT_EQ(port, 5353);
    EXPECT_EQ(decoded_size, encoded_size);
}

TEST(NetworkAddress, RoutesUdpResponsesToFamilyLoopback)
{
    sockaddr_storage endpoint{};
    socklen_t endpoint_size = 0;

    ASSERT_TRUE(make_loopback_endpoint(AddressFamily::IPv4, 43000, &endpoint, &endpoint_size));
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&endpoint);
    EXPECT_EQ(ipv4->sin_family, AF_INET);
    EXPECT_EQ(ipv4->sin_addr.s_addr, htonl(INADDR_LOOPBACK));
    EXPECT_EQ(ntohs(ipv4->sin_port), 43000);
    EXPECT_EQ(endpoint_size, sizeof(sockaddr_in));

    ASSERT_TRUE(make_loopback_endpoint(AddressFamily::IPv6, 43001, &endpoint, &endpoint_size));
    const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(&endpoint);
    EXPECT_EQ(ipv6->sin6_family, AF_INET6);
    EXPECT_TRUE(IN6_ARE_ADDR_EQUAL(&ipv6->sin6_addr, &in6addr_loopback));
    EXPECT_EQ(ntohs(ipv6->sin6_port), 43001);
    EXPECT_EQ(endpoint_size, sizeof(sockaddr_in6));
}

} // namespace
} // namespace proxyprism
