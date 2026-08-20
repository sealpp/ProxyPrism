#include "FakeIPStore.h"

#include <gtest/gtest.h>

namespace proxyprism {
namespace {

TEST(FakeIPStore, InitializesDefaultPools)
{
    FakeIPStore store;
    EXPECT_TRUE(store.set_ipv4_pool(FakeIPStore::DEFAULT_IPV4_POOL));
    EXPECT_TRUE(store.set_ipv6_pool(FakeIPStore::DEFAULT_IPV6_POOL));
    EXPECT_TRUE(store.has_pools());
}

TEST(FakeIPStore, AllocatesAndReusesFakeIps)
{
    FakeIPStore store;
    ASSERT_TRUE(store.set_ipv4_pool("198.18.0.0/15"));

    auto first = store.allocate(AddressFamily::IPv4, "example.com");
    ASSERT_TRUE(first.has_value());

    auto same = store.allocate(AddressFamily::IPv4, "example.com");
    ASSERT_TRUE(same.has_value());
    EXPECT_EQ(*first, *same);

    auto second = store.allocate(AddressFamily::IPv4, "other.org");
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(*first, *second);
}

TEST(FakeIPStore, ReverseLookup)
{
    FakeIPStore store;
    ASSERT_TRUE(store.set_ipv4_pool("198.18.0.0/15"));

    auto fake = store.allocate(AddressFamily::IPv4, "proxyprism.test");
    ASSERT_TRUE(fake.has_value());

    auto domain = store.lookup_domain(*fake);
    ASSERT_TRUE(domain.has_value());
    EXPECT_EQ(*domain, "proxyprism.test");
}

TEST(FakeIPStore, DetectsPoolMembership)
{
    FakeIPStore store;
    ASSERT_TRUE(store.set_ipv4_pool("198.18.0.0/15"));

    auto allocated = store.allocate(AddressFamily::IPv4, "in-pool.test");
    ASSERT_TRUE(allocated.has_value());
    EXPECT_TRUE(store.contains(*allocated));

    auto outside = parse_network_address("8.8.8.8");
    ASSERT_TRUE(outside.has_value());
    EXPECT_FALSE(store.contains(*outside));
}

TEST(FakeIPStore, AllocatesFromBothFamilies)
{
    FakeIPStore store;
    ASSERT_TRUE(store.set_ipv4_pool("198.18.0.0/15"));
    ASSERT_TRUE(store.set_ipv6_pool("fc00::/18"));

    auto v4 = store.allocate(AddressFamily::IPv4, "v4.test");
    auto v6 = store.allocate(AddressFamily::IPv6, "v6.test");
    ASSERT_TRUE(v4.has_value());
    ASSERT_TRUE(v6.has_value());

    EXPECT_EQ(v4->family, AddressFamily::IPv4);
    EXPECT_EQ(v6->family, AddressFamily::IPv6);
    EXPECT_TRUE(store.contains(*v4));
    EXPECT_TRUE(store.contains(*v6));
}

} // namespace
} // namespace proxyprism
