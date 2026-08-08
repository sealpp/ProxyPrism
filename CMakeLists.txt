cmake_minimum_required(VERSION 3.16)

project(ProxyPrism
    VERSION 0.1.0
    LANGUAGES C CXX
)

# Default install prefix is a local output/ directory, keeping the
# release layout flat.
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/output"
        CACHE PATH "ProxyPrism install prefix" FORCE)
endif()

# Generate compile_commands.json by default for clangd/IDE integration.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(BUILD_STATIC_EXE "Build a single fully-static proxyprism executable" OFF)

# Global hardening for project code; contrib libraries override with -w.
set(PB_HARDENING_FLAGS
    -O3
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -Wformat
    -Wformat-security
    -Werror=format-security
    -fno-delete-null-pointer-checks
    -fwrapv
)

find_package(Threads REQUIRED)

add_subdirectory(contrib)
add_subdirectory(src)

# Install ancillary files alongside the binaries.
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/proxyprism.conf.example"
        DESTINATION .)
install(PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/setup.sh"
        DESTINATION .)
