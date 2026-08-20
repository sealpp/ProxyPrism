#include "DNSProxy.h"
#include "ProcessLookup.h"

#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace proxyprism {

namespace {

constexpr uint32_t FAKE_DNS_TTL = 1;

ssize_t send_all(int sock, const char* buf, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t n = send(sock, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0)
            return -1;
        sent += n;
    }
    return sent;
}

struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

uint16_t read_u16(const uint8_t* p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

void write_u16(uint8_t* p, uint16_t v)
{
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v & 0xff);
}

uint32_t read_u32(const uint8_t* p)
{
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

void write_u32(uint8_t* p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

// Parse a DNS name from a message, handling compression pointers.
// Returns the number of bytes consumed, or -1 on error.
int parse_dns_name(const uint8_t* msg, size_t msg_len, size_t offset, char* out, size_t out_size)
{
    if (offset >= msg_len)
        return -1;

    size_t pos = offset;
    size_t out_pos = 0;
    bool first_label = true;
    bool jumped = false;
    size_t real_offset = 0;

    while (pos < msg_len)
    {
        uint8_t len = msg[pos++];

        if ((len & 0xc0) == 0xc0)
        {
            if (pos >= msg_len)
                return -1;
            uint16_t ptr = ((static_cast<uint16_t>(len & 0x3f) << 8) | msg[pos++]);
            if (ptr >= msg_len)
                return -1;
            if (!jumped)
            {
                real_offset = pos;
                jumped = true;
            }
            pos = ptr;
            continue;
        }

        if (len == 0)
        {
            if (!jumped)
                real_offset = pos;
            break;
        }

        if (len > 63 || pos + len > msg_len)
            return -1;

        if (!first_label)
        {
            if (out_pos + 1 >= out_size)
                return -1;
            out[out_pos++] = '.';
        }
        first_label = false;

        if (out_pos + len >= out_size)
            return -1;

        for (uint8_t i = 0; i < len; ++i)
        {
            char c = static_cast<char>(msg[pos++]);
            out[out_pos++] = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        out[out_pos] = '\0';
    }

    out[out_pos] = '\0';
    return static_cast<int>(real_offset - offset);
}

// Build a fake A/AAAA response. The answer name is a pointer to the question.
// Returns the response length, or -1 on error.
bool build_fake_response(
    const uint8_t* query,
    size_t query_len,
    size_t question_end,
    const NetworkAddress& fake_ip,
    uint8_t* out,
    size_t out_size,
    size_t* out_len)
{
    if (out_size < query_len + 12 + (fake_ip.family == AddressFamily::IPv4 ? 4u : 16u))
        return false;

    memcpy(out, query, question_end); // header + question
    const uint16_t qtype = read_u16(query + question_end - 4);

    DNSHeader h{};
    h.id = read_u16(query);
    h.flags = htons(0x8180); // response, authoritative, recursion available
    h.qdcount = htons(1);
    h.ancount = htons(1);
    h.nscount = 0;
    h.arcount = 0;

    write_u16(out, h.id);
    write_u16(out + 2, h.flags);
    write_u16(out + 4, h.qdcount);
    write_u16(out + 6, h.ancount);
    write_u16(out + 8, h.nscount);
    write_u16(out + 10, h.arcount);

    size_t pos = question_end;

    // Answer NAME: pointer to the question name at offset 12 (start of question)
    if (pos + 2 > out_size)
        return false;
    write_u16(out + pos, 0xc00c);
    pos += 2;

    // TYPE
    if (pos + 2 > out_size)
        return false;
    write_u16(out + pos, qtype);
    pos += 2;

    // CLASS
    if (pos + 2 > out_size)
        return false;
    write_u16(out + pos, 1);
    pos += 2;

    // TTL
    if (pos + 4 > out_size)
        return false;
    write_u32(out + pos, FAKE_DNS_TTL);
    pos += 4;

    // RDLENGTH and RDATA
    const size_t addr_len = fake_ip.family == AddressFamily::IPv4 ? 4 : 16;
    if (pos + 2 + addr_len > out_size)
        return false;
    write_u16(out + pos, static_cast<uint16_t>(addr_len));
    pos += 2;
    memcpy(out + pos, fake_ip.bytes.data(), addr_len);
    pos += addr_len;

    *out_len = pos;
    return true;
}

bool set_socket_mark(int fd, int mark)
{
    return setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) == 0;
}

int create_dns_socket(int family, int type, uint16_t port)
{
    const int fd = socket(family, type | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    int on = 1;
    if (family == AF_INET6)
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));

    if (type == SOCK_DGRAM)
    {
        // allow sending responses to same port quickly
        int reuse = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    }

    struct sockaddr_storage addr{};
    socklen_t len = 0;
    if (family == AF_INET)
    {
        auto* in = reinterpret_cast<sockaddr_in*>(&addr);
        in->sin_family = AF_INET;
        in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        in->sin_port = htons(port);
        len = sizeof(*in);
    }
    else
    {
        auto* in6 = reinterpret_cast<sockaddr_in6*>(&addr);
        in6->sin6_family = AF_INET6;
        in6->sin6_addr = in6addr_loopback;
        in6->sin6_port = htons(port);
        len = sizeof(*in6);
    }

    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), len) < 0)
    {
        close(fd);
        return -1;
    }

    if (type == SOCK_STREAM && listen(fd, 16) < 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

bool forward_query_udp(
    const sockaddr_storage& nameserver,
    socklen_t nameserver_len,
    const uint8_t* query,
    size_t query_len,
    uint8_t* out,
    size_t out_size,
    size_t* out_len,
    int bypass_mark)
{
    if (out_size < 512)
        return false;

    const int family = (nameserver.ss_family == AF_INET) ? AF_INET : AF_INET6;
    int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;

    set_socket_mark(fd, bypass_mark);

    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (sendto(fd, query, query_len, 0, reinterpret_cast<const sockaddr*>(&nameserver), nameserver_len) < 0)
    {
        close(fd);
        return false;
    }

    const ssize_t rv = recv(fd, out, out_size, 0);
    close(fd);
    if (rv <= 0)
        return false;

    *out_len = static_cast<size_t>(rv);
    return true;
}

bool forward_query_tcp(
    const sockaddr_storage& nameserver,
    socklen_t nameserver_len,
    const uint8_t* query,
    size_t query_len,
    uint8_t* out,
    size_t out_size,
    size_t* out_len,
    int bypass_mark)
{
    const int family = (nameserver.ss_family == AF_INET) ? AF_INET : AF_INET6;
    int fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;

    set_socket_mark(fd, bypass_mark);

    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, reinterpret_cast<const sockaddr*>(&nameserver), nameserver_len) < 0)
    {
        close(fd);
        return false;
    }

    if (query_len > 0xffff)
    {
        close(fd);
        return false;
    }

    uint8_t len_buf[2];
    write_u16(len_buf, static_cast<uint16_t>(query_len));
    if (send_all(fd, reinterpret_cast<const char*>(len_buf), 2) < 0 ||
        send_all(fd, reinterpret_cast<const char*>(query), query_len) < 0)
    {
        close(fd);
        return false;
    }

    if (recv(fd, len_buf, 2, MSG_WAITALL) != 2)
    {
        close(fd);
        return false;
    }
    const uint16_t resp_len = read_u16(len_buf);
    if (resp_len == 0 || resp_len > out_size)
    {
        close(fd);
        return false;
    }

    const ssize_t rv = recv(fd, out, resp_len, MSG_WAITALL);
    close(fd);
    if (rv != static_cast<ssize_t>(resp_len))
        return false;

    *out_len = resp_len;
    return true;
}

} // namespace

DNSProxy::DNSProxy(FakeIPStore& store, const sockaddr_storage& nameserver, socklen_t nameserver_len, uint32_t self_pid)
    : store_(store), nameserver_(nameserver), nameserver_len_(nameserver_len), self_pid_(self_pid)
{
}

DNSProxy::~DNSProxy()
{
    stop();
}

bool DNSProxy::start(uint16_t port)
{
    if (running_)
        return false;

    udp4_ = create_dns_socket(AF_INET, SOCK_DGRAM, port);
    udp6_ = create_dns_socket(AF_INET6, SOCK_DGRAM, port);
    tcp4_ = create_dns_socket(AF_INET, SOCK_STREAM, port);
    tcp6_ = create_dns_socket(AF_INET6, SOCK_STREAM, port);

    if (udp4_ < 0 && udp6_ < 0)
    {
        stop();
        return false;
    }

    running_ = true;
    if (pthread_create(&thread_, nullptr, [](void* arg) -> void* { static_cast<DNSProxy*>(arg)->run(); return nullptr; }, this) != 0)
    {
        running_ = false;
        stop();
        return false;
    }

    return true;
}

void DNSProxy::stop()
{
    running_ = false;

    if (thread_ != 0)
    {
        pthread_cancel(thread_);
        pthread_join(thread_, nullptr);
        thread_ = 0;
    }

    if (udp4_ >= 0) { close(udp4_); udp4_ = -1; }
    if (udp6_ >= 0) { close(udp6_); udp6_ = -1; }
    if (tcp4_ >= 0) { close(tcp4_); tcp4_ = -1; }
    if (tcp6_ >= 0) { close(tcp6_); tcp6_ = -1; }
}

void DNSProxy::run()
{
    uint8_t in_buf[65535];
    uint8_t out_buf[65535];

    while (running_)
    {
        struct pollfd fds[4];
        int nfds = 0;

        if (udp4_ >= 0) { fds[nfds].fd = udp4_; fds[nfds].events = POLLIN; fds[nfds].revents = 0; ++nfds; }
        if (udp6_ >= 0) { fds[nfds].fd = udp6_; fds[nfds].events = POLLIN; fds[nfds].revents = 0; ++nfds; }
        if (tcp4_ >= 0) { fds[nfds].fd = tcp4_; fds[nfds].events = POLLIN; fds[nfds].revents = 0; ++nfds; }
        if (tcp6_ >= 0) { fds[nfds].fd = tcp6_; fds[nfds].events = POLLIN; fds[nfds].revents = 0; ++nfds; }

        if (nfds == 0)
            break;

        const int ready = poll(fds, nfds, 500);
        if (ready <= 0)
            continue;

        for (int i = 0; i < nfds; ++i)
        {
            if (!(fds[i].revents & POLLIN))
                continue;

            const int fd = fds[i].fd;
            const bool is_tcp_listener = (fd == tcp4_ || fd == tcp6_);

            if (is_tcp_listener)
            {
                struct sockaddr_storage client_addr{};
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept4(fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len, SOCK_CLOEXEC);
                if (client_fd < 0)
                    continue;

                struct timeval tv = {3, 0};
                setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

                uint8_t len_buf[2];
                ssize_t got = recv(client_fd, len_buf, 2, MSG_WAITALL);
                if (got != 2)
                {
                    close(client_fd);
                    continue;
                }
                const uint16_t msg_len = read_u16(len_buf);
                if (msg_len == 0 || msg_len > sizeof(in_buf))
                {
                    close(client_fd);
                    continue;
                }

                got = recv(client_fd, in_buf, msg_len, MSG_WAITALL);
                if (got != static_cast<ssize_t>(msg_len))
                {
                    close(client_fd);
                    continue;
                }

                const NetworkAddress client_ip = network_address_from_sockaddr(reinterpret_cast<sockaddr*>(&client_addr));
                const uint16_t client_port = (client_addr.ss_family == AF_INET6)
                    ? ntohs(reinterpret_cast<sockaddr_in6*>(&client_addr)->sin6_port)
                    : ntohs(reinterpret_cast<sockaddr_in*>(&client_addr)->sin_port);

                bool is_self = false;
                if (self_pid_ != 0)
                {
                    const uint32_t pid = get_process_id_from_connection(client_ip, client_port, false);
                    is_self = (pid == self_pid_);
                }

                size_t out_len = 0;
                bool ok = false;

                if (is_self)
                {
                    ok = forward_query_tcp(nameserver_, nameserver_len_, in_buf, msg_len, out_buf, sizeof(out_buf), &out_len, mark_for_bypass_);
                }
                else
                {
                    // Only A/AAAA get fake IPs for TCP too.
                    if (msg_len < 12)
                    {
                        close(client_fd);
                        continue;
                    }

                    const uint16_t qdcount = ntohs(*reinterpret_cast<const uint16_t*>(in_buf + 4));
                    if (qdcount != 1)
                    {
                        ok = forward_query_tcp(nameserver_, nameserver_len_, in_buf, msg_len, out_buf, sizeof(out_buf), &out_len, mark_for_bypass_);
                    }
                    else
                    {
                        char qname[256];
                        const int consumed = parse_dns_name(in_buf, msg_len, 12, qname, sizeof(qname));
                        if (consumed < 0)
                        {
                            ok = forward_query_tcp(nameserver_, nameserver_len_, in_buf, msg_len, out_buf, sizeof(out_buf), &out_len, mark_for_bypass_);
                        }
                        else
                        {
                            const size_t qend = 12 + consumed + 4;
                            const uint16_t qtype = read_u16(in_buf + qend - 4);
                            const uint16_t qclass = read_u16(in_buf + qend - 2);

                            if (qclass != 1 || (qtype != 1 && qtype != 28))
                            {
                                ok = forward_query_tcp(nameserver_, nameserver_len_, in_buf, msg_len, out_buf, sizeof(out_buf), &out_len, mark_for_bypass_);
                            }
                            else
                            {
                                const AddressFamily family = (qtype == 1) ? AddressFamily::IPv4 : AddressFamily::IPv6;
                                auto fake = store_.allocate(family, qname);
                                if (!fake)
                                {
                                    out_buf[0] = in_buf[0];
                                    out_buf[1] = in_buf[1];
                                    write_u16(out_buf + 2, htons(0x8182)); // SERVFAIL
                                    write_u16(out_buf + 4, htons(1));
                                    write_u16(out_buf + 6, 0);
                                    write_u16(out_buf + 8, 0);
                                    write_u16(out_buf + 10, 0);
                                    memcpy(out_buf + 12, in_buf + 12, msg_len - 12);
                                    out_len = msg_len;
                                    ok = true;
                                }
                                else
                                {
                                    ok = build_fake_response(in_buf, msg_len, qend, *fake, out_buf, sizeof(out_buf), &out_len);
                                }
                            }
                        }
                    }
                }

                if (ok)
                {
                    uint8_t resp_len_buf[2];
                    write_u16(resp_len_buf, static_cast<uint16_t>(out_len));
                    send_all(client_fd, reinterpret_cast<const char*>(resp_len_buf), 2);
                    send_all(client_fd, reinterpret_cast<const char*>(out_buf), out_len);
                }

                close(client_fd);
                continue;
            }

            // UDP
            struct sockaddr_storage client_addr{};
            socklen_t client_len = sizeof(client_addr);
            ssize_t in_len = recvfrom(fd, in_buf, sizeof(in_buf), 0, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
            if (in_len <= 0)
                continue;

            const NetworkAddress client_ip = network_address_from_sockaddr(reinterpret_cast<sockaddr*>(&client_addr));
            const uint16_t client_port = (client_addr.ss_family == AF_INET6)
                ? ntohs(reinterpret_cast<sockaddr_in6*>(&client_addr)->sin6_port)
                : ntohs(reinterpret_cast<sockaddr_in*>(&client_addr)->sin_port);

            bool is_self = false;
            if (self_pid_ != 0)
            {
                const uint32_t pid = get_process_id_from_connection(client_ip, client_port, true);
                is_self = (pid == self_pid_);
            }

            size_t out_len = 0;
            bool ok = false;

            if (is_self)
            {
                ok = forward_query_udp(nameserver_, nameserver_len_, in_buf, static_cast<size_t>(in_len), out_buf, sizeof(out_buf), &out_len, mark_for_bypass_);
            }
            else
            {
                if (static_cast<size_t>(in_len) < 12)
                    continue;

                const uint16_t qdcount = ntohs(*reinterpret_cast<const uint16_t*>(in_buf + 4));
                if (qdcount != 1)
                {
                    ok = forward_query_udp(nameserver_, nameserver_len_, in_buf, static_cast<size_t>(in_len), out_buf, sizeof(out_buf), &out_len, mark_for_bypass_);
                }
                else
                {
                    char qname[256];
                    const int consumed = parse_dns_name(in_buf, in_len, 12, qname, sizeof(qname));
                    if (consumed < 0)
                    {
                        ok = forward_query_udp(nameserver_, nameserver_len_, in_buf, static_cast<size_t>(in_len), out_buf, sizeof(out_buf), &out_len, mark_for_bypass_);
                    }
                    else
                    {
                        const size_t qend = 12 + consumed + 4;
                        const uint16_t qtype = read_u16(in_buf + qend - 4);
                        const uint16_t qclass = read_u16(in_buf + qend - 2);

                        if (qclass != 1 || (qtype != 1 && qtype != 28))
                        {
                            ok = forward_query_udp(nameserver_, nameserver_len_, in_buf, static_cast<size_t>(in_len), out_buf, sizeof(out_buf), &out_len, mark_for_bypass_);
                        }
                        else
                        {
                            const AddressFamily family = (qtype == 1) ? AddressFamily::IPv4 : AddressFamily::IPv6;
                            auto fake = store_.allocate(family, qname);
                            if (!fake)
                            {
                                out_buf[0] = in_buf[0];
                                out_buf[1] = in_buf[1];
                                write_u16(out_buf + 2, htons(0x8182)); // SERVFAIL
                                write_u16(out_buf + 4, htons(1));
                                write_u16(out_buf + 6, 0);
                                write_u16(out_buf + 8, 0);
                                write_u16(out_buf + 10, 0);
                                memcpy(out_buf + 12, in_buf + 12, in_len - 12);
                                out_len = in_len;
                                ok = true;
                            }
                            else
                            {
                                ok = build_fake_response(in_buf, in_len, qend, *fake, out_buf, sizeof(out_buf), &out_len);
                            }
                        }
                    }
                }
            }

            if (ok)
            {
                sendto(fd, out_buf, out_len, 0, reinterpret_cast<sockaddr*>(&client_addr), client_len);
            }
        }
    }
}

} // namespace proxyprism
