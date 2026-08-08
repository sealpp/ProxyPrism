# Single ProxyPrism executable.

add_executable(proxyprism
    ProxyPrism.cpp
    main.cpp
)

# Apply project-wide hardening to our code only.
target_compile_options(proxyprism PRIVATE ${PB_HARDENING_FLAGS})
target_compile_definitions(proxyprism PRIVATE _GNU_SOURCE)

target_include_directories(proxyprism
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(proxyprism
    PRIVATE
        tomlc17
        netfilter_queue
        nfnetlink
        mnl
        Threads::Threads
)

if(BUILD_STATIC_EXE)
    # Fully static link.  This will emit a glibc getaddrinfo warning that
    # we cannot avoid on glibc-based systems.
    target_link_options(proxyprism PRIVATE -no-pie -static)
endif()

# Strip the binary after build.
add_custom_command(TARGET proxyprism POST_BUILD
    COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:proxyprism>
    VERBATIM
)

install(TARGETS proxyprism
    RUNTIME DESTINATION .
)
