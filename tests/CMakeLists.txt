add_executable(proxyprism_smoke_tests
    smoke_test.cpp
)

target_link_libraries(proxyprism_smoke_tests PRIVATE GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(proxyprism_smoke_tests)
