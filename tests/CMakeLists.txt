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

set(PROXYPRISM_CONFIG_FIXTURES ${CMAKE_CURRENT_SOURCE_DIR}/fixtures)

add_test(
    NAME config_accepts_ipv6_rule
    COMMAND $<TARGET_FILE:proxyprism> --check-config --config ${PROXYPRISM_CONFIG_FIXTURES}/valid-ipv6.toml
)
set_tests_properties(config_accepts_ipv6_rule PROPERTIES PASS_REGULAR_EXPRESSION "Config OK")

add_test(
    NAME config_rejects_hostname_rule
    COMMAND $<TARGET_FILE:proxyprism> --check-config --config ${PROXYPRISM_CONFIG_FIXTURES}/invalid-hostname.toml
)
set_tests_properties(config_rejects_hostname_rule PROPERTIES WILL_FAIL TRUE)

add_test(
    NAME config_rejects_invalid_port
    COMMAND $<TARGET_FILE:proxyprism> --check-config --config ${PROXYPRISM_CONFIG_FIXTURES}/invalid-port.toml
)
set_tests_properties(config_rejects_invalid_port PROPERTIES WILL_FAIL TRUE)
