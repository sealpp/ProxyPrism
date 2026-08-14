#include "NetworkAddress.h"

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
    EXPECT_FALSE(validate_host_list("example.com"));
    EXPECT_FALSE(validate_host_list("2001:db8::/129"));
    EXPECT_FALSE(validate_host_list("2001:db8:*"));
    EXPECT_FALSE(validate_host_list("192.168.1.300"));
    EXPECT_FALSE(validate_port_list("0"));
    EXPECT_FALSE(validate_port_list("443-80"));
    EXPECT_FALSE(validate_port_list("80x"));
    EXPECT_TRUE(validate_port_list("53;80,443-8443"));
}

} // namespace
} // namespace proxyprism
