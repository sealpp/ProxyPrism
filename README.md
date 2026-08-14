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

## Dual-stack Routing

ProxyPrism routes IPv4 and IPv6 traffic. Rules match literal addresses, CIDR
ranges, `*`, and the existing IPv4-only segmented wildcard/range syntax such
as `192.0.2.*` or `192.0.2.10-20`. Hostnames and IPv6 hextet wildcards are not
rule syntax.

| Traffic | SOCKS5 | HTTP |
| --- | --- | --- |
| IPv4 TCP | proxy | proxy |
| IPv6 TCP | proxy | proxy |
| IPv4 UDP | proxy | direct |
| IPv6 UDP | proxy | direct |

Use brackets around an IPv6 proxy endpoint in `proxy.url`, for example
`socks5://[2001:db8::1]:1080`. SOCKS5 UDP uses `UDP ASSOCIATE`; HTTP UDP is
kept direct. IPv6 packets with extension headers, fragments, or an unknown
next-header are accepted directly.

Transparent IPv6 routing requires both `iptables` and `ip6tables` with the
`NFQUEUE`, `mark`, and `REDIRECT` targets available. If `ip6tables` cannot
install its rules, IPv6 traffic is not transparently proxied.

### DNS traffic

DNS (port 53) follows the same rules as other traffic, so a catch-all PROXY
rule also routes DNS through the proxy. To keep DNS direct while proxying
everything else, put a port-53 DIRECT rule before the catch-all (see the
commented example in `proxyprism.conf.example`).

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
