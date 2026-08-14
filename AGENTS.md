# ProxyPrism

## Scope

`src/` contains the Linux transparent-proxy implementation. Build with CMake
and keep production code compatible with C++23.

```bash
cmake -S . -B build
cmake --build build
```

When tests are enabled, configure with `-DPROXYPRISM_BUILD_TESTS=ON` and run
`ctest --test-dir build --output-on-failure`.

## Internal Specs

`me_ProxyPrism/` is an independent local Git repository for design and
maintenance specifications. It is intentionally ignored by this repository.

- Commit documentation changes inside `me_ProxyPrism` only.
- Do not add it as a submodule or gitlink.
- Its `AGENTS.md` defines documentation style and update rules.
