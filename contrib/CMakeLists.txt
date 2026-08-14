# Third-party dependencies vendored as git submodules.
# They are built as static libraries and linked into libproxyprism.so
# (or directly into the static executable).

# Each source dir has its own "internal.h"; avoid global -I.../src that
# would shadow them across libraries.

# libmnl ---------------------------------------------------------------------
add_library(mnl STATIC
    libmnl/src/attr.c
    libmnl/src/callback.c
    libmnl/src/nlmsg.c
    libmnl/src/socket.c
)

target_compile_definitions(mnl PRIVATE _GNU_SOURCE)
target_compile_options(mnl PRIVATE -w)

target_include_directories(mnl
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/libmnl/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/libmnl/src
)

# libnfnetlink ---------------------------------------------------------------
add_library(nfnetlink STATIC
    libnfnetlink/src/libnfnetlink.c
    libnfnetlink/src/iftable.c
    libnfnetlink/src/rtnl.c
)

target_compile_definitions(nfnetlink PRIVATE _GNU_SOURCE)
target_compile_options(nfnetlink PRIVATE -w)

target_include_directories(nfnetlink
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/libnfnetlink/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/libnfnetlink/src
)

# libnetfilter_queue ---------------------------------------------------------
add_library(netfilter_queue STATIC
    libnetfilter_queue/src/libnetfilter_queue.c
    libnetfilter_queue/src/nlmsg.c
    libnetfilter_queue/src/extra/checksum.c
    libnetfilter_queue/src/extra/ipv4.c
    libnetfilter_queue/src/extra/ipv6.c
    libnetfilter_queue/src/extra/pktbuff.c
    libnetfilter_queue/src/extra/tcp.c
    libnetfilter_queue/src/extra/udp.c
)

target_compile_definitions(netfilter_queue PRIVATE _GNU_SOURCE)
target_compile_options(netfilter_queue PRIVATE -w)

target_include_directories(netfilter_queue
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/libnetfilter_queue/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/libnetfilter_queue/src
        ${CMAKE_CURRENT_SOURCE_DIR}/libmnl/include
        ${CMAKE_CURRENT_SOURCE_DIR}/libnfnetlink/include
)

target_link_libraries(netfilter_queue
    PUBLIC
        mnl
        nfnetlink
)

# tomlc17 --------------------------------------------------------------------
add_library(tomlc17 STATIC
    tomlc17/src/tomlc17.c
)

target_compile_options(tomlc17 PRIVATE -w)

target_include_directories(tomlc17
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/tomlc17/src
)

# GoogleTest is a test-only submodule. Keep it out of production builds and
# disable its own test/install targets.
if(PROXYPRISM_BUILD_TESTS)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(gtest_build_gmock OFF CACHE BOOL "" FORCE)
    set(gtest_build_tests OFF CACHE BOOL "" FORCE)
    add_subdirectory(googletest EXCLUDE_FROM_ALL)
endif()
