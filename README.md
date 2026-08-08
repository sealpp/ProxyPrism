# ProxyPrism

A Linux CLI for rule-based, transparent application traffic routing through
SOCKS5/HTTP proxies.

## Build

```bash
cmake -B build .
cmake --build build -j$(nproc)
cmake --install build
```

After installation, the single `proxyprism` binary is in `output/`:

- `proxyprism` — CLI
- `proxyprism.conf.example` — sample configuration
- `setup.sh` — system install script

## Static build

```bash
cmake -B build -DBUILD_STATIC_EXE=ON .
cmake --build build -j$(nproc)
cmake --install build
```

## Usage

```bash
sudo ./output/proxyprism --check-config
sudo ./output/proxyprism
```

## Disclaimer

ProxyPrism is a transparent traffic-routing tool intended for legitimate
network administration and local testing on systems you own or are authorized
to manage.

ProxyPrism routes application traffic through SOCKS5/HTTP proxies you
configure yourself, based on local rules you define. It is a local-only tool
and does not provide hosted proxy services, remote access, or any capability
for reaching network resources that the host system cannot already access.

By using this software, you agree to comply with all applicable local laws and
regulations. The authors and contributors are not responsible for any misuse or
illegal use of this software.

## License

ProxyPrism is released under the MIT License. See [LICENSE](LICENSE).

It uses Git submodules for the netfilter libraries (`libmnl`, `libnfnetlink`,
`libnetfilter_queue`) and `tomlc17`; their respective licenses are in
`contrib/`.

## Acknowledgments

- [ProxyBridge](https://github.com/InterceptSuite/ProxyBridge) by [Anof-cyber / InterceptSuite](https://github.com/InterceptSuite)
