add_executable(proxyprism_unit_tests
    smoke_test.cpp
    NetworkAddressTest.cpp
)

target_link_libraries(proxyprism_unit_tests
    PRIVATE
        proxyprism_address_rules
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(proxyprism_unit_tests)
