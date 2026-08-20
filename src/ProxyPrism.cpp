#include "ProxyPrism.h"
#include "NetworkAddress.h"
#include "FakeIPStore.h"
#include "ProcessLookup.h"
#include "DNSProxy.h"
#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <dirent.h>
#include <fcntl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/inet_diag.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace proxyprism {

constexpr std::uint16_t LOCAL_PROXY_PORT = 34010;
constexpr std::uint16_t LOCAL_UDP_RELAY_PORT = 34011;
constexpr std::uint16_t LOCAL_DNS_PROXY_PORT = 34053;
constexpr uint32_t BYPASS_REDIRECT_MARK = 0xFF;
constexpr std::uint32_t FAKE_IP_MARK_TCP = 3;
constexpr std::uint32_t FAKE_IP_MARK_UDP = 4;
constexpr std::size_t MAX_PROCESS_NAME = 256;
constexpr std::uint32_t PID_CACHE_SIZE = 1024;
constexpr std::uint64_t PID_CACHE_TTL_MS = 1000;
constexpr std::size_t NUM_PACKET_THREADS = 4;
constexpr std::uint32_t CONNECTION_HASH_SIZE = 256;
constexpr std::size_t SOCKS5_BUFFER_SIZE = 1024;
constexpr std::size_t HTTP_BUFFER_SIZE = 1024;
constexpr std::size_t LOG_BUFFER_SIZE = 1024;

// safe way to run commands without shell injection issues
static int run_command_v(const char * cmd_path, char * const argv[])
{
    pid_t pid = fork();
    if (pid == -1)
    {
        return -1;
    }
    else if (pid == 0)
    {
        // child process
        // send output to /dev/null so it doesnt clutter
        int fd = open("/dev/null", O_WRONLY);
        if (fd >= 0)
        {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        execvp(cmd_path, argv);
        _exit(127); // command not found or no perms
    }
    else
    {
        // parent waits for child
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status))
        {
            return WEXITSTATUS(status);
        }
        return -1;
    }
}

// run iptables commands easier
static int run_iptables_cmd(
    const char * arg1,
    const char * arg2,
    const char * arg3,
    const char * arg4,
    const char * arg5,
    const char * arg6,
    const char * arg7,
    const char * arg8,
    const char * arg9,
    const char * arg10 = nullptr,
    const char * arg11 = nullptr,
    const char * arg12 = nullptr,
    const char * arg13 = nullptr,
    const char * arg14 = nullptr)
{
    // build argv array skipping null args
    const char * argv[17];
    int i = 0;
    argv[i++] = "iptables";
    if (arg1)
        argv[i++] = arg1;
    if (arg2)
        argv[i++] = arg2;
    if (arg3)
        argv[i++] = arg3;
    if (arg4)
        argv[i++] = arg4;
    if (arg5)
        argv[i++] = arg5;
    if (arg6)
        argv[i++] = arg6;
    if (arg7)
        argv[i++] = arg7;
    if (arg8)
        argv[i++] = arg8;
    if (arg9)
        argv[i++] = arg9;
    if (arg10)
        argv[i++] = arg10;
    if (arg11)
        argv[i++] = arg11;
    if (arg12)
        argv[i++] = arg12;
    if (arg13)
        argv[i++] = arg13;
    if (arg14)
        argv[i++] = arg14;
    argv[i] = nullptr;

    return run_command_v("iptables", (char **)argv);
}

static int run_ip6tables_cmd(
    const char * arg1,
    const char * arg2,
    const char * arg3,
    const char * arg4,
    const char * arg5,
    const char * arg6,
    const char * arg7,
    const char * arg8,
    const char * arg9,
    const char * arg10 = nullptr,
    const char * arg11 = nullptr,
    const char * arg12 = nullptr,
    const char * arg13 = nullptr,
    const char * arg14 = nullptr)
{
    const char * argv[17];
    int i = 0;
    argv[i++] = "ip6tables";
    if (arg1)
        argv[i++] = arg1;
    if (arg2)
        argv[i++] = arg2;
    if (arg3)
        argv[i++] = arg3;
    if (arg4)
        argv[i++] = arg4;
    if (arg5)
        argv[i++] = arg5;
    if (arg6)
        argv[i++] = arg6;
    if (arg7)
        argv[i++] = arg7;
    if (arg8)
        argv[i++] = arg8;
    if (arg9)
        argv[i++] = arg9;
    if (arg10)
        argv[i++] = arg10;
    if (arg11)
        argv[i++] = arg11;
    if (arg12)
        argv[i++] = arg12;
    if (arg13)
        argv[i++] = arg13;
    if (arg14)
        argv[i++] = arg14;
    argv[i] = nullptr;

    return run_command_v("ip6tables", (char **)argv);
}

// convert string to int safely
static int safe_atoi(const char * str)
{
    if (!str)
        return 0;
    char * endptr;
    long val = strtol(str, &endptr, 10);
    if (endptr == str)
        return 0;
    return (int)val;
}


typedef struct PROCESS_RULE
{
    uint32_t rule_id;
    char process_name[MAX_PROCESS_NAME];
    char * target_hosts;
    char * target_ports;
    RuleProtocol protocol;
    RuleAction action;
    bool enabled;
    struct PROCESS_RULE * next;
} PROCESS_RULE;

#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04
#define SOCKS5_AUTH_NONE 0x00

typedef struct CONNECTION_INFO
{
    uint16_t src_port;
    NetworkAddress src_ip;
    NetworkAddress orig_dest_ip;
    uint16_t orig_dest_port;
    NetworkAddress resolved_dest_ip;
    uint16_t resolved_dest_port;
    bool resolved;
    bool is_tracked;
    uint64_t last_activity;
    RuleAction action;
    char domain[256];
    bool is_fake_ip;
    struct CONNECTION_INFO * next;
} CONNECTION_INFO;

typedef struct LOGGED_CONNECTION
{
    uint32_t pid;
    NetworkAddress dest_ip;
    uint16_t dest_port;
    RuleAction action;
    struct LOGGED_CONNECTION * next;
} LOGGED_CONNECTION;

typedef struct PID_CACHE_ENTRY
{
    NetworkAddress src_ip;
    uint16_t src_port;
    uint32_t pid;
    uint64_t timestamp;
    bool is_udp;
    struct PID_CACHE_ENTRY * next;
} PID_CACHE_ENTRY;

static CONNECTION_INFO * connection_hash_table[CONNECTION_HASH_SIZE] = {nullptr};
static LOGGED_CONNECTION * logged_connections = nullptr;
static PROCESS_RULE * rules_list = nullptr;
static uint32_t g_next_rule_id = 1;
static pthread_rwlock_t conn_lock = PTHREAD_RWLOCK_INITIALIZER; // read-heavy connection hash
static pthread_rwlock_t rules_lock = PTHREAD_RWLOCK_INITIALIZER; // read-heavy rules list
static pthread_mutex_t pid_cache_lock = PTHREAD_MUTEX_INITIALIZER; // PID cache only
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER; // logged connections only

typedef struct
{
    int client_socket;
    NetworkAddress orig_dest_ip;
    uint16_t orig_dest_port;
    RuleAction action;
    char domain[256];
    bool is_fake_ip;
} connection_config_t;

typedef struct
{
    int from_socket;
    int to_socket;
} transfer_config_t;

static struct nfq_handle * nfq_h = nullptr;
static struct nfq_q_handle * nfq_qh = nullptr;
static pthread_t packet_thread[NUM_PACKET_THREADS] = {0};
static pthread_t proxy_thread = 0;
static pthread_t udp_relay_thread = 0;
static pthread_t cleanup_thread = 0;
static PID_CACHE_ENTRY * pid_cache[PID_CACHE_SIZE] = {nullptr};
static bool g_has_active_rules = false;
static bool running = false;
static uint32_t g_current_process_id = 0;

static FakeIPStore g_fake_ip_store;
static char g_dns_nameserver[256] = "";
static struct sockaddr_storage g_dns_nameserver_addr;
static socklen_t g_dns_nameserver_addr_len = 0;
static DNSProxy* g_dns_proxy = nullptr;

// udp relay stuff
static int udp_relay_sockets[2] = {-1, -1};
static int socks5_udp_control_socket = -1;
static int socks5_udp_send_socket = -1;
static struct sockaddr_storage socks5_udp_relay_addr;
static socklen_t socks5_udp_relay_addr_len = 0;
static bool udp_associate_connected = false;
static uint64_t last_udp_connect_attempt = 0;

static bool g_traffic_logging_enabled = true;

static char g_proxy_host[256] = "";
static uint16_t g_proxy_port = 0;
static uint16_t g_local_relay_port = LOCAL_PROXY_PORT;
static ProxyType g_proxy_type = ProxyType::SOCKS5;
static char g_proxy_username[256] = "";
static char g_proxy_password[256] = "";
static struct sockaddr_storage g_proxy_addr;
static socklen_t g_proxy_addr_len = 0;
static LogCallback g_log_callback = nullptr;
static ConnectionCallback g_connection_callback = nullptr;

static void log_message(const char * msg, ...)
{
    if (g_log_callback == nullptr)
        return;
    char buffer[LOG_BUFFER_SIZE];
    va_list args;
    va_start(args, msg);
    vsnprintf(buffer, sizeof(buffer), msg, args);
    va_end(args);
    g_log_callback(buffer);
}

static const char * extract_filename(const char * path)
{
    if (!path)
        return "";
    const char * last_slash = strrchr(path, '/');
    return last_slash ? (last_slash + 1) : path;
}

static inline char * skip_whitespace(char * str)
{
    while (*str == ' ' || *str == '\t')
        str++;
    return str;
}

static void format_ip_address(uint32_t ip, char * buffer, size_t size)
{
    snprintf(buffer, size, "%d.%d.%d.%d", (ip >> 0) & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}

static int socket_family(AddressFamily family)
{
    return family == AddressFamily::IPv4 ? AF_INET : AF_INET6;
}

static std::size_t network_address_size(const NetworkAddress& address)
{
    return address.family == AddressFamily::IPv4 ? 4 : 16;
}

static void format_network_address(const NetworkAddress& address, char* buffer, size_t size)
{
    const std::string text = format_network_address(address);
    snprintf(buffer, size, "%s", text.c_str());
}

static bool resolve_endpoint(const char* host, uint16_t port, int socktype, struct sockaddr_storage* address, socklen_t* address_len)
{
    if (host == nullptr || host[0] == '\0')
        return false;

    char host_copy[256];
    snprintf(host_copy, sizeof(host_copy), "%s", host);
    const size_t host_len = strlen(host_copy);
    if (host_len >= 2 && host_copy[0] == '[' && host_copy[host_len - 1] == ']')
    {
        memmove(host_copy, host_copy + 1, host_len - 2);
        host_copy[host_len - 2] = '\0';
    }

    char service[8];
    snprintf(service, sizeof(service), "%u", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;

    struct addrinfo* result = nullptr;
    if (getaddrinfo(host_copy, service, &hints, &result) != 0 || result == nullptr)
        return false;

    if (result->ai_addrlen > sizeof(*address))
    {
        freeaddrinfo(result);
        return false;
    }

    memcpy(address, result->ai_addr, result->ai_addrlen);
    *address_len = result->ai_addrlen;
    freeaddrinfo(result);
    return true;
}

typedef bool (*token_match_func)(const char * token, const void * data);

static bool parse_token_list(const char * list, const char * delimiters, token_match_func match_func, const void * match_data)
{
    if (list == nullptr || list[0] == '\0' || strcmp(list, "*") == 0)
        return true;

    size_t len = strlen(list) + 1;
    char * list_copy = (char *)malloc(len);
    if (list_copy == nullptr)
        return false;

    memcpy(list_copy, list, len); // copy including null terminator
    bool matched = false;
    char * saveptr = nullptr;
    char * token = strtok_r(list_copy, delimiters, &saveptr);
    while (token != nullptr)
    {
        token = skip_whitespace(token);

        // remove spaces at end
        size_t tlen = strlen(token);
        while (tlen > 0 && (token[tlen - 1] == ' ' || token[tlen - 1] == '\t' || token[tlen - 1] == '\r' || token[tlen - 1] == '\n'))
        {
            token[tlen - 1] = '\0';
            tlen--;
        }

        if (tlen > 0 && match_func(token, match_data))
        {
            matched = true;
            break;
        }
        token = strtok_r(nullptr, delimiters, &saveptr);
    }
    free(list_copy);
    return matched;
}

static void configure_tcp_socket(int sock, int bufsize, int timeout_ms)
{
    int nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    struct timeval timeout = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static void configure_udp_socket(int sock, int bufsize, int timeout_ms)
{
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    struct timeval timeout = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static ssize_t send_all(int sock, const char * buf, size_t len)
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

static uint64_t get_monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint32_t parse_ipv4(const char * ip);
static uint32_t resolve_hostname(const char * hostname);
static int socks5_connect(int s, const NetworkAddress& dest_ip, uint16_t dest_port, const char* domain);
static bool match_process_pattern(const char * pattern, const char * process_name);
static bool match_process_list(const char * process_list, const char * process_name);
static int http_connect(int s, const NetworkAddress& dest_ip, uint16_t dest_port, const char* domain);
static void * local_proxy_server(void * arg);
static void * connection_handler(void * arg);
static void * transfer_handler(void * arg);
static void * packet_processor(void * arg);
uint32_t get_process_id_from_connection(const NetworkAddress& src_ip, uint16_t src_port, bool is_udp);
static bool get_process_name_from_pid(uint32_t pid, char * name, size_t name_size);
static RuleAction
check_process_rule(
    const NetworkAddress& src_ip,
    uint16_t src_port,
    const NetworkAddress& dest_ip,
    uint16_t dest_port,
    bool is_udp,
    uint32_t* out_pid,
    const char* domain = nullptr);
static void add_connection(
    uint16_t src_port,
    const NetworkAddress& src_ip,
    const NetworkAddress& dest_ip,
    uint16_t dest_port,
    RuleAction action,
    const char* domain,
    bool is_fake_ip);
static bool get_connection(
    const NetworkAddress& src_ip,
    uint16_t src_port,
    NetworkAddress* dest_ip,
    uint16_t* dest_port,
    RuleAction* action = nullptr,
    char* domain = nullptr,
    bool* is_fake_ip = nullptr,
    NetworkAddress* resolved_dest_ip = nullptr,
    uint16_t* resolved_dest_port = nullptr);
static bool is_connection_tracked(const NetworkAddress& src_ip, uint16_t src_port);
static void cleanup_stale_connections(void);
static bool is_connection_already_logged(uint32_t pid, const NetworkAddress& dest_ip, uint16_t dest_port, RuleAction action);
static void add_logged_connection(uint32_t pid, const NetworkAddress& dest_ip, uint16_t dest_port, RuleAction action);
static void clear_logged_connections(void);
static bool is_broadcast_or_multicast(const NetworkAddress& ip);
static uint32_t get_cached_pid(const NetworkAddress& src_ip, uint16_t src_port, bool is_udp);
static void cache_pid(const NetworkAddress& src_ip, uint16_t src_port, uint32_t pid, bool is_udp);
static void clear_pid_cache(void);
static void update_has_active_rules(void);

// find which process owns a socket by checking /proc
// uses uid hint to skip processes we dont need to check
static uint32_t find_pid_from_inode(unsigned long target_inode, uint32_t uid_hint)
{
    // build the socket string we're looking for
    char expected[64];
    int expected_len = snprintf(expected, sizeof(expected), "socket:[%lu]", target_inode);

    DIR * proc_dir = opendir("/proc");
    if (!proc_dir)
        return 0;

    uint32_t pid = 0;
    struct dirent * proc_entry;

    while ((proc_entry = readdir(proc_dir)) != nullptr)
    {
        // skip stuff that aint a pid folder
        if (proc_entry->d_type != DT_DIR || !isdigit(proc_entry->d_name[0]))
            continue;

        // if we know the user id, skip other users processes
        // makes this way faster cuz less folders to check
        if (uid_hint != (uint32_t)-1)
        {
            struct stat proc_stat;
            char proc_path[280];
            snprintf(proc_path, sizeof(proc_path), "/proc/%s", proc_entry->d_name);
            if (stat(proc_path, &proc_stat) == 0 && proc_stat.st_uid != uid_hint)
                continue;
        }

        char fd_path[280];
        snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", proc_entry->d_name);
        DIR * fd_dir = opendir(fd_path);
        if (!fd_dir)
            continue;

        struct dirent * fd_entry;
        while ((fd_entry = readdir(fd_dir)) != nullptr)
        {
            if (fd_entry->d_name[0] == '.')
                continue;

            char link_path[560];
            snprintf(link_path, sizeof(link_path), "/proc/%s/fd/%s", proc_entry->d_name, fd_entry->d_name);

            char link_target[64];
            ssize_t link_len = readlink(link_path, link_target, sizeof(link_target) - 1);
            if (link_len == expected_len)
            {
                link_target[link_len] = '\0';
                if (memcmp(link_target, expected, expected_len) == 0)
                {
                    pid = (uint32_t)safe_atoi(proc_entry->d_name);
                    closedir(fd_dir);
                    closedir(proc_dir);
                    return pid;
                }
            }
        }
        closedir(fd_dir);
    }
    closedir(proc_dir);
    return pid;
}

// fast pid lookup using netlink
// tcp uses exact query, udp needs dump
uint32_t get_process_id_from_connection(const NetworkAddress& src_ip, uint16_t src_port, bool is_udp)
{
    uint32_t cached_pid = get_cached_pid(src_ip, src_port, is_udp);
    if (cached_pid != 0)
        return cached_pid;

    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0)
        return 0;

    // short timeout so we dont block packet flow
    struct timeval tv = {0, 100000}; // 100ms
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct
    {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 r;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.r.sdiag_family = socket_family(src_ip.family);
    req.r.sdiag_protocol = is_udp ? IPPROTO_UDP : IPPROTO_TCP;

    // udp needs dump cuz no connection state to match on
    // tcp can filter to only syn_sent and established states
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    if (!is_udp)
        req.r.idiag_states = (1 << 2) | (1 << 3); // SYN_SENT(2) + ESTABLISHED(3) only
    else
        req.r.idiag_states = (uint32_t)-1; // All states for UDP
    req.r.idiag_ext = 0;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        close(fd);
        return 0;
    }

    uint32_t pid = 0;
    unsigned long target_inode = 0;
    uint32_t target_uid = (uint32_t)-1;
    bool found = false;
    char buf[16384];
    struct iovec iov = {buf, sizeof(buf)};
    struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &iov, .msg_iovlen = 1};

    while (1)
    {
        ssize_t len = recvmsg(fd, &msg, 0);
        if (len <= 0)
            break;

        struct nlmsghdr * h = (struct nlmsghdr *)buf;
        while (NLMSG_OK(h, (size_t)len))
        {
            if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR)
                goto nl_done;

            if (h->nlmsg_type == SOCK_DIAG_BY_FAMILY)
            {
                struct inet_diag_msg * r = (struct inet_diag_msg *)NLMSG_DATA(h);

                // check if this is our socket
                if (memcmp(r->id.idiag_src, src_ip.bytes.data(), network_address_size(src_ip)) == 0
                    && ntohs(r->id.idiag_sport) == src_port)
                {
                    target_inode = r->idiag_inode;
                    target_uid = r->idiag_uid; // UID to narrow /proc scan
                    found = true;
                    goto nl_done;
                }
            }
            h = NLMSG_NEXT(h, len);
        }
    }

nl_done:
    close(fd);

    // if netlink found it, now find pid from inode
    // no need to scan /proc/net/tcp since we got inode already
    if (found && target_inode != 0)
    {
        pid = find_pid_from_inode(target_inode, target_uid);
    }

    // fallback for udp if netlink didnt find it
    // happens when app uses sendto without connecting socket first
    if (!found && is_udp)
    {
        const char* udp_file = src_ip.family == AddressFamily::IPv4 ? "/proc/net/udp" : "/proc/net/udp6";
        FILE* fp = fopen(udp_file, "r");
        if (fp)
        {
            char line[512];
            if (fgets(line, sizeof(line), fp))
            {
                while (fgets(line, sizeof(line), fp))
                {
                    unsigned int local_port = 0;
                    unsigned long inode = 0;
                    int uid_val = 0;
                    if (sscanf(
                            line,
                            "%*d: %*32[0-9A-Fa-f]:%X %*32[0-9A-Fa-f]:%*X %*X %*X:%*X %*X:%*X %*X %d %*d %lu",
                            &local_port,
                            &uid_val,
                            &inode)
                        == 3)
                    {
                        if (local_port == src_port && inode != 0)
                        {
                            pid = find_pid_from_inode(inode, (uint32_t)uid_val);
                            break;
                        }
                    }
                }
            }
            fclose(fp);
        }
    }

    if (pid != 0)
        cache_pid(src_ip, src_port, pid, is_udp);
    return pid;
}

static bool get_process_name_from_pid(uint32_t pid, char * name, size_t name_size)
{
    if (pid == 0)
        return false;

    // pid 1 is always init/systemd
    // kinda like windows pid 4 for system stuff
    if (pid == 1)
    {
        snprintf(name, name_size, "systemd");
        return true;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/exe", pid);

    ssize_t len = readlink(path, name, name_size - 1);
    if (len < 0)
        return false;

    name[len] = '\0';
    return true;
}

static bool match_process_pattern(const char * pattern, const char * process_full_path)
{
    if (pattern == nullptr || strcmp(pattern, "*") == 0)
        return true;

    const char * filename = strrchr(process_full_path, '/');
    if (filename != nullptr)
        filename++;
    else
        filename = process_full_path;

    size_t pattern_len = strlen(pattern);
    size_t name_len = strlen(filename);
    size_t full_path_len = strlen(process_full_path);

    bool is_full_path_pattern = (strchr(pattern, '/') != nullptr);
    const char * match_target = is_full_path_pattern ? process_full_path : filename;
    size_t target_len = is_full_path_pattern ? full_path_len : name_len;

    if (pattern_len > 0 && pattern[pattern_len - 1] == '*')
    {
        return strncasecmp(pattern, match_target, pattern_len - 1) == 0;
    }

    if (pattern_len > 1 && pattern[0] == '*')
    {
        const char * pattern_suffix = pattern + 1;
        size_t suffix_len = pattern_len - 1;
        if (target_len >= suffix_len)
        {
            return strcasecmp(match_target + target_len - suffix_len, pattern_suffix) == 0;
        }
        return false;
    }

    return strcasecmp(pattern, match_target) == 0;
}

typedef struct
{
    const char * process_name;
} process_match_data;

static bool process_match_wrapper(const char * token, const void * data)
{
    const process_match_data * pdata = (const process_match_data *)data;
    return match_process_pattern(token, pdata->process_name);
}

static bool match_process_list(const char * process_list, const char * process_name)
{
    process_match_data data = {process_name};
    return parse_token_list(process_list, ";", process_match_wrapper, &data);
}

static uint32_t parse_ipv4(const char * ip)
{
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return 0;
    return (a << 0) | (b << 8) | (c << 16) | (d << 24);
}

static uint32_t resolve_hostname(const char * hostname)
{
    if (hostname == nullptr || hostname[0] == '\0')
        return 0;

    uint32_t ip = parse_ipv4(hostname);
    if (ip != 0)
        return ip;

    struct addrinfo hints, *result = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, nullptr, &hints, &result) != 0)
    {
        log_message("failed to resolve hostname: %s", hostname);
        return 0;
    }

    if (result == nullptr || result->ai_family != AF_INET)
    {
        if (result != nullptr)
            freeaddrinfo(result);
        log_message("no ipv4 address found for hostname: %s", hostname);
        return 0;
    }

    struct sockaddr_in * addr = (struct sockaddr_in *)result->ai_addr;
    uint32_t resolved_ip = addr->sin_addr.s_addr;
    freeaddrinfo(result);

    return resolved_ip;
}

static bool is_broadcast_or_multicast(const NetworkAddress& ip)
{
    if (ip.family == AddressFamily::IPv4)
    {
        const uint8_t first_octet = ip.bytes[0];
        const uint8_t second_octet = ip.bytes[1];
        return first_octet == 127 || (first_octet == 169 && second_octet == 254)
            || first_octet == 255 || (first_octet >= 224 && first_octet <= 239);
    }

    const bool loopback = ip.bytes[0] == 0 && ip.bytes[1] == 0 && ip.bytes[2] == 0 && ip.bytes[3] == 0
        && ip.bytes[4] == 0 && ip.bytes[5] == 0 && ip.bytes[6] == 0 && ip.bytes[7] == 0 && ip.bytes[8] == 0
        && ip.bytes[9] == 0 && ip.bytes[10] == 0 && ip.bytes[11] == 0 && ip.bytes[12] == 0 && ip.bytes[13] == 0
        && ip.bytes[14] == 0 && ip.bytes[15] == 1;
    return loopback || ip.bytes[0] == 0xff || (ip.bytes[0] == 0xfe && (ip.bytes[1] & 0xc0) == 0x80);
}

static RuleAction match_rule(const char * process_name, const NetworkAddress& dest_ip, uint16_t dest_port, bool is_udp, const char* domain)
{
    PROCESS_RULE * rule = rules_list;
    PROCESS_RULE * wildcard_rule = nullptr;
    const std::string_view domain_view = domain != nullptr ? domain : "";

    while (rule != nullptr)
    {
        if (!rule->enabled)
        {
            rule = rule->next;
            continue;
        }

        if (rule->protocol != RuleProtocol::BOTH)
        {
            if (rule->protocol == RuleProtocol::TCP && is_udp)
            {
                rule = rule->next;
                continue;
            }
            if (rule->protocol == RuleProtocol::UDP && !is_udp)
            {
                rule = rule->next;
                continue;
            }
        }

        bool is_wildcard_process = (strcmp(rule->process_name, "*") == 0 || strcasecmp(rule->process_name, "ANY") == 0);

        if (is_wildcard_process)
        {
            bool has_ip_filter = (strcmp(rule->target_hosts, "*") != 0);
            bool has_port_filter = (strcmp(rule->target_ports, "*") != 0);

            if (has_ip_filter || has_port_filter)
            {
                if (match_target_list(rule->target_hosts, dest_ip, domain_view) && match_port_list(rule->target_ports, dest_port))
                {
                    return rule->action;
                }
                rule = rule->next;
                continue;
            }

            if (wildcard_rule == nullptr)
            {
                wildcard_rule = rule;
            }
            rule = rule->next;
            continue;
        }

        if (match_process_list(rule->process_name, process_name))
        {
            if (match_target_list(rule->target_hosts, dest_ip, domain_view) && match_port_list(rule->target_ports, dest_port))
            {
                return rule->action;
            }
        }

        rule = rule->next;
    }

    if (wildcard_rule != nullptr)
    {
        return wildcard_rule->action;
    }

    return RuleAction::DIRECT;
}

static RuleAction
check_process_rule(
    const NetworkAddress& src_ip,
    uint16_t src_port,
    const NetworkAddress& dest_ip,
    uint16_t dest_port,
    bool is_udp,
    uint32_t* out_pid,
    const char* domain)
{
    uint32_t pid;
    char process_name[MAX_PROCESS_NAME];

    pid = get_process_id_from_connection(src_ip, src_port, is_udp);

    if (out_pid != nullptr)
        *out_pid = pid;

    if (pid == 0)
        return RuleAction::DIRECT;

    if (pid == g_current_process_id)
        return RuleAction::DIRECT;

    if (!get_process_name_from_pid(pid, process_name, sizeof(process_name)))
        return RuleAction::DIRECT;

    pthread_rwlock_rdlock(&rules_lock);
    RuleAction action = match_rule(process_name, dest_ip, dest_port, is_udp, domain);
    pthread_rwlock_unlock(&rules_lock);

    if (action == RuleAction::PROXY && is_udp && g_proxy_type == ProxyType::HTTP)
    {
        return RuleAction::DIRECT;
    }
    if (action == RuleAction::PROXY && (g_proxy_host[0] == '\0' || g_proxy_port == 0))
    {
        return RuleAction::DIRECT;
    }

    return action;
}

static int socks5_connect(int s, const NetworkAddress& dest_ip, uint16_t dest_port, const char* domain)
{
    unsigned char buf[SOCKS5_BUFFER_SIZE];
    ssize_t len;
    bool use_auth = (g_proxy_username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth)
    {
        buf[1] = 0x02;
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = 0x02;
        if (send(s, buf, 4, MSG_NOSIGNAL) != 4)
        {
            log_message("socks5 failed to send auth methods");
            return -1;
        }
    }
    else
    {
        buf[1] = 0x01;
        buf[2] = SOCKS5_AUTH_NONE;
        if (send(s, buf, 3, MSG_NOSIGNAL) != 3)
        {
            log_message("socks5 failed to send auth methods");
            return -1;
        }
    }

    len = recv(s, buf, 2, 0);
    if (len != 2 || buf[0] != SOCKS5_VERSION)
    {
        log_message("socks5 invalid auth response");
        return -1;
    }

    if (buf[1] == 0x02 && use_auth)
    {
        size_t ulen = strlen(g_proxy_username);
        size_t plen = strlen(g_proxy_password);
        buf[0] = 0x01;
        buf[1] = (unsigned char)ulen;
        memcpy(buf + 2, g_proxy_username, ulen);
        buf[2 + ulen] = (unsigned char)plen;
        memcpy(buf + 3 + ulen, g_proxy_password, plen);

        if (send(s, buf, 3 + ulen + plen, MSG_NOSIGNAL) != (ssize_t)(3 + ulen + plen))
        {
            log_message("socks5 failed to send credentials");
            return -1;
        }

        len = recv(s, buf, 2, 0);
        if (len != 2 || buf[0] != 0x01 || buf[1] != 0x00)
        {
            log_message("socks5 authentication failed");
            return -1;
        }
    }
    else if (buf[1] != SOCKS5_AUTH_NONE)
    {
        log_message("socks5 unsupported auth method");
        return -1;
    }

    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;
    size_t request_size = 3;

    if (domain != nullptr && domain[0] != '\0')
    {
        const size_t dlen = strlen(domain);
        if (dlen > 255 || dlen + 4 + request_size > sizeof(buf))
            return -1;
        buf[3] = SOCKS5_ATYP_DOMAIN;
        buf[4] = static_cast<unsigned char>(dlen);
        memcpy(buf + 5, domain, dlen);
        const uint16_t network_port = htons(dest_port);
        memcpy(buf + 5 + dlen, &network_port, sizeof(network_port));
        request_size = 5 + dlen + 2;
    }
    else
    {
        size_t encoded_size = 0;
        if (!encode_socks5_address(dest_ip, dest_port, buf + 3, sizeof(buf) - 3, &encoded_size))
            return -1;
        request_size += encoded_size;
    }
    if (send(s, buf, request_size, MSG_NOSIGNAL) != (ssize_t)request_size)
    {
        log_message("socks5 failed to send connect request");
        return -1;
    }

    len = recv(s, buf, 4, MSG_WAITALL);
    if (len != 4 || buf[0] != SOCKS5_VERSION || buf[1] != 0x00)
    {
        log_message("socks5 connect failed status %d", len > 1 ? buf[1] : -1);
        return -1;
    }

    size_t response_address_size = 0;
    if (buf[3] == SOCKS5_ATYP_IPV4)
        response_address_size = 4;
    else if (buf[3] == SOCKS5_ATYP_IPV6)
        response_address_size = 16;
    else
        return -1;
    if (recv(s, buf, response_address_size + 2, MSG_WAITALL) != (ssize_t)(response_address_size + 2))
        return -1;

    return 0;
}

static int http_connect(int s, const NetworkAddress& dest_ip, uint16_t dest_port, const char* domain)
{
    char buf[HTTP_BUFFER_SIZE];
    char authority[INET6_ADDRSTRLEN + 256 + 16];
    if (domain != nullptr && domain[0] != '\0')
    {
        const bool has_colon = strchr(domain, ':') != nullptr;
        if (has_colon && domain[0] != '[')
            snprintf(authority, sizeof(authority), "[%s]:%u", domain, dest_port);
        else
            snprintf(authority, sizeof(authority), "%s:%u", domain, dest_port);
    }
    else
    {
        char dest_ip_str[INET6_ADDRSTRLEN];
        format_network_address(dest_ip, dest_ip_str, sizeof(dest_ip_str));
        if (dest_ip.family == AddressFamily::IPv6)
            snprintf(authority, sizeof(authority), "[%s]:%u", dest_ip_str, dest_port);
        else
            snprintf(authority, sizeof(authority), "%s:%u", dest_ip_str, dest_port);
    }

    int len = snprintf(
        buf,
        sizeof(buf),
        "CONNECT %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Proxy-Connection: Keep-Alive\r\n",
        authority,
        authority);

    if (g_proxy_username[0] != '\0')
    {
        // encode user:pass in base64
        static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        char auth_raw[512];
        int auth_raw_len = snprintf(auth_raw, sizeof(auth_raw), "%s:%s", g_proxy_username, g_proxy_password);
        char auth_b64[700];
        int j = 0;
        for (int i = 0; i < auth_raw_len; i += 3)
        {
            unsigned int n = ((unsigned char)auth_raw[i]) << 16;
            if (i + 1 < auth_raw_len)
                n |= ((unsigned char)auth_raw[i + 1]) << 8;
            if (i + 2 < auth_raw_len)
                n |= ((unsigned char)auth_raw[i + 2]);
            auth_b64[j++] = b64[(n >> 18) & 0x3F];
            auth_b64[j++] = b64[(n >> 12) & 0x3F];
            auth_b64[j++] = (i + 1 < auth_raw_len) ? b64[(n >> 6) & 0x3F] : '=';
            auth_b64[j++] = (i + 2 < auth_raw_len) ? b64[n & 0x3F] : '=';
        }
        auth_b64[j] = '\0';
        len += snprintf(buf + len, sizeof(buf) - len, "Proxy-Authorization: Basic %s\r\n", auth_b64);
    }

    len += snprintf(buf + len, sizeof(buf) - len, "\r\n");

    if (send_all(s, buf, len) < 0)
    {
        log_message("http failed to send connect");
        return -1;
    }

    ssize_t recv_len = recv(s, buf, sizeof(buf) - 1, 0);
    if (recv_len < 12)
    {
        log_message("http invalid response");
        return -1;
    }

    buf[recv_len] = '\0';
    if (strncmp(buf, "HTTP/1.", 7) != 0)
    {
        log_message("http invalid response");
        return -1;
    }

    int status_code = 0;
    if (sscanf(buf + 9, "%d", &status_code) != 1 || status_code != 200)
    {
        log_message("http connect failed status %d", status_code);
        return -1;
    }

    return 0;
}

// relay functions for production use

// connection handler like windows - blocks on connect then transfers data
static void * connection_handler(void * arg)
{
    connection_config_t * config = (connection_config_t *)arg;
    int client_sock = config->client_socket;
    NetworkAddress dest_ip = config->orig_dest_ip;
    uint16_t dest_port = config->orig_dest_port;
    const RuleAction action = config->action;
    const bool is_fake_ip = config->is_fake_ip;
    const char* domain = (config->domain[0] != '\0') ? config->domain : nullptr;
    int target_sock = -1;

    delete config;

    if (action == RuleAction::BLOCK)
    {
        close(client_sock);
        return nullptr;
    }

    configure_tcp_socket(client_sock, 1048576, 60000);

    if (action == RuleAction::DIRECT)
    {
        // DIRECT for fake-IP: resolve the original domain and connect directly.
        if (!is_fake_ip || domain == nullptr)
        {
            close(client_sock);
            return nullptr;
        }

        struct sockaddr_storage real_addr{};
        socklen_t real_addr_len = 0;
        if (g_dns_proxy == nullptr || !g_dns_proxy->resolve_domain(domain, dest_port, &real_addr, &real_addr_len, dest_ip.family))
        {
            log_message("direct fake-ip: failed to resolve %s", domain);
            close(client_sock);
            return nullptr;
        }

        target_sock = socket(real_addr.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (target_sock < 0)
        {
            close(client_sock);
            return nullptr;
        }

        configure_tcp_socket(target_sock, 1048576, 60000);

        if (connect(target_sock, (struct sockaddr *)&real_addr, real_addr_len) < 0)
        {
            close(client_sock);
            close(target_sock);
            return nullptr;
        }

        // Setup transfer and return
        transfer_config_t * transfer_config = (transfer_config_t *)malloc(sizeof(transfer_config_t));
        if (transfer_config == nullptr)
        {
            close(client_sock);
            close(target_sock);
            return nullptr;
        }
        transfer_config->from_socket = client_sock;
        transfer_config->to_socket = target_sock;
        transfer_handler((void *)transfer_config);
        return nullptr;
    }

    // PROXY path
    if (g_proxy_addr_len == 0)
    {
        close(client_sock);
        return nullptr;
    }

    target_sock = socket(g_proxy_addr.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (target_sock < 0)
    {
        close(client_sock);
        return nullptr;
    }

    configure_tcp_socket(target_sock, 1048576, 60000);

    if (connect(target_sock, (struct sockaddr *)&g_proxy_addr, g_proxy_addr_len) < 0)
    {
        close(client_sock);
        close(target_sock);
        return nullptr;
    }

    // do handshake blocking
    if (g_proxy_type == ProxyType::SOCKS5)
    {
        if (socks5_connect(target_sock, dest_ip, dest_port, domain) != 0)
        {
            close(client_sock);
            close(target_sock);
            return nullptr;
        }
    }
    else if (g_proxy_type == ProxyType::HTTP)
    {
        if (http_connect(target_sock, dest_ip, dest_port, domain) != 0)
        {
            close(client_sock);
            close(target_sock);
            return nullptr;
        }
    }
    // Disable timeout for data transfer phase
    struct timeval zero_timeout = {0, 0};
    setsockopt(target_sock, SOL_SOCKET, SO_RCVTIMEO, &zero_timeout, sizeof(zero_timeout));
    setsockopt(target_sock, SOL_SOCKET, SO_SNDTIMEO, &zero_timeout, sizeof(zero_timeout));
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &zero_timeout, sizeof(zero_timeout));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &zero_timeout, sizeof(zero_timeout));

    // Enable and configure customized TCP keep-alives
    int keepalive = 1;
    int keepidle = 300; // 5 minutes in seconds
    int keepintvl = 1; // 1 second interval
    int keepcnt = 5; // 5 probes before dropping
    setsockopt(target_sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    setsockopt(target_sock, SOL_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    setsockopt(target_sock, SOL_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    setsockopt(target_sock, SOL_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
    setsockopt(client_sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    setsockopt(client_sock, SOL_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    setsockopt(client_sock, SOL_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    setsockopt(client_sock, SOL_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

    // setup transfer config
    transfer_config_t * transfer_config = (transfer_config_t *)malloc(sizeof(transfer_config_t));
    if (transfer_config == nullptr)
    {
        close(client_sock);
        close(target_sock);
        return nullptr;
    }

    transfer_config->from_socket = client_sock;
    transfer_config->to_socket = target_sock;

    // transfer data both ways in this thread
    transfer_handler((void *)transfer_config);

    return nullptr;
}

// relay data both ways using splice for zero-copy
// data goes kernel to kernel thru pipe, never hits userspace
// way faster than copying thru userspace buffers
static void * transfer_handler(void * arg)
{
    transfer_config_t * config = (transfer_config_t *)arg;
    int sock1 = config->from_socket; // client socket
    int sock2 = config->to_socket; // proxy socket
    free(config);

    // make 2 pipes for splice
    // pipe_a: proxy to client (download)
    // pipe_b: client to proxy (upload)
    int pipe_a[2] = {-1, -1};
    int pipe_b[2] = {-1, -1};

    if (pipe2(pipe_a, O_CLOEXEC | O_NONBLOCK) < 0 || pipe2(pipe_b, O_CLOEXEC | O_NONBLOCK) < 0)
    {
        // pipe failed, cleanup and fallback
        if (pipe_a[0] >= 0)
        {
            close(pipe_a[0]);
            close(pipe_a[1]);
        }
        if (pipe_b[0] >= 0)
        {
            close(pipe_b[0]);
            close(pipe_b[1]);
        }
        goto fallback;
    }

    // make pipes bigger for better speed (64kb to 1mb)
    fcntl(pipe_a[0], F_SETPIPE_SZ, 1048576);
    fcntl(pipe_b[0], F_SETPIPE_SZ, 1048576);

    // set sockets to nonblocking for splice
    fcntl(sock1, F_SETFL, fcntl(sock1, F_GETFL, 0) | O_NONBLOCK);
    fcntl(sock2, F_SETFL, fcntl(sock2, F_GETFL, 0) | O_NONBLOCK);

    {
        struct pollfd fds[2];
        ssize_t pipe_a_bytes = 0; // bytes in download pipe (proxy→client)
        ssize_t pipe_b_bytes = 0; // bytes in upload pipe (client→proxy)
        bool sock1_done = false; // client EOF or error
        bool sock2_done = false; // proxy EOF or error
        bool shut_wr_sock1 = false; // already called shutdown(sock1, SHUT_WR)
        bool shut_wr_sock2 = false; // already called shutdown(sock2, SHUT_WR)

        while (1)
        {
            // build poll set, use fd=-1 to skip closed sockets
            // important: poll reports POLLHUP even with events=0
            // so use fd=-1 to actually skip it or we get busy loop
            fds[0].fd = (!sock1_done || pipe_a_bytes > 0 || pipe_b_bytes > 0) ? sock1 : -1;
            fds[1].fd = (!sock2_done || pipe_b_bytes > 0 || pipe_a_bytes > 0) ? sock2 : -1;
            fds[0].events = 0;
            fds[1].events = 0;
            fds[0].revents = 0;
            fds[1].revents = 0;

            // download: proxy to client
            if (!sock2_done && pipe_a_bytes == 0)
                fds[1].events |= POLLIN; // read from proxy
            if (pipe_a_bytes > 0)
                fds[0].events |= POLLOUT; // write to client

            // upload: client to proxy
            if (!sock1_done && pipe_b_bytes == 0)
                fds[0].events |= POLLIN; // read from client
            if (pipe_b_bytes > 0)
                fds[1].events |= POLLOUT; // write to proxy

            // all done
            if (fds[0].fd == -1 && fds[1].fd == -1)
                break;
            if (fds[0].events == 0 && fds[1].events == 0)
                break;

            int ready = poll(fds, 2, -1);
            if (ready < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }

            // check for errors and hangups
            if (fds[0].revents & POLLERR)
                break;
            if (fds[1].revents & POLLERR)
                break;

            // pollhup means other side closed
            if ((fds[1].revents & POLLHUP) && !(fds[1].revents & POLLIN))
                sock2_done = true;
            if ((fds[0].revents & POLLHUP) && !(fds[0].revents & POLLIN))
                sock1_done = true;

            // download path

            if (!sock2_done && pipe_a_bytes == 0 && (fds[1].revents & POLLIN))
            {
                ssize_t n = splice(sock2, nullptr, pipe_a[1], nullptr, 1048576, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (n > 0)
                {
                    pipe_a_bytes = n;
                }
                else if (n == 0)
                {
                    sock2_done = true;
                }
                else if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    sock2_done = true;
                }
            }

            if (pipe_a_bytes > 0 && (fds[0].revents & POLLOUT))
            {
                ssize_t n = splice(pipe_a[0], nullptr, sock1, nullptr, pipe_a_bytes, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (n > 0)
                {
                    pipe_a_bytes -= n;
                }
                else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    break;
                }
            }

            // upload path

            if (!sock1_done && pipe_b_bytes == 0 && (fds[0].revents & POLLIN))
            {
                ssize_t n = splice(sock1, nullptr, pipe_b[1], nullptr, 1048576, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (n > 0)
                {
                    pipe_b_bytes = n;
                }
                else if (n == 0)
                {
                    sock1_done = true;
                }
                else if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    sock1_done = true;
                }
            }

            if (pipe_b_bytes > 0 && (fds[1].revents & POLLOUT))
            {
                ssize_t n = splice(pipe_b[0], nullptr, sock2, nullptr, pipe_b_bytes, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (n > 0)
                {
                    pipe_b_bytes -= n;
                }
                else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    break;
                }
            }

            // half-close when one side done and pipe empty
            // tell other side with shutdown
            if (sock2_done && pipe_a_bytes == 0 && !shut_wr_sock1)
            {
                shutdown(sock1, SHUT_WR);
                shut_wr_sock1 = true;
            }
            if (sock1_done && pipe_b_bytes == 0 && !shut_wr_sock2)
            {
                shutdown(sock2, SHUT_WR);
                shut_wr_sock2 = true;
            }

            // both sides finished and pipes empty
            if (sock1_done && sock2_done && pipe_a_bytes == 0 && pipe_b_bytes == 0)
                break;
        }
    }

    close(pipe_a[0]);
    close(pipe_a[1]);
    close(pipe_b[0]);
    close(pipe_b[1]);
    goto cleanup;

fallback:
    // fallback to normal recv/send if pipes didnt work
    {
        char buf[131072];
        struct pollfd fds[2];
        fds[0].fd = sock1;
        fds[0].events = POLLIN;
        fds[1].fd = sock2;
        fds[1].events = POLLIN;

        while (1)
        {
            int ready = poll(fds, 2, -1);
            if (ready < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }

            if (fds[0].revents & POLLERR || fds[1].revents & POLLERR)
                break;

            bool did_work = false;
            if (fds[0].revents & POLLIN)
            {
                ssize_t n = recv(sock1, buf, sizeof(buf), MSG_NOSIGNAL);
                if (n <= 0)
                    break;
                if (send_all(sock2, buf, n) < 0)
                    break;
                did_work = true;
            }
            if (fds[1].revents & POLLIN)
            {
                ssize_t n = recv(sock2, buf, sizeof(buf), MSG_NOSIGNAL);
                if (n <= 0)
                    break;
                if (send_all(sock1, buf, n) < 0)
                    break;
                did_work = true;
            }

            // pollhup with no data means peer closed
            if (!did_work)
                break;
        }
    }

cleanup:
    shutdown(sock1, SHUT_RDWR);
    shutdown(sock2, SHUT_RDWR);
    close(sock1);
    close(sock2);
    return nullptr;
}

static int create_tcp_listener(AddressFamily family)
{
    int on = 1;
    const int family_value = socket_family(family);
    const int listen_sock = socket(family_value, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_sock < 0)
        return -1;

    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    setsockopt(listen_sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    if (family == AddressFamily::IPv6)
    {
        const int v6_only = 1;
        setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only));
    }

    if (family == AddressFamily::IPv4)
    {
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(g_local_relay_port);
        if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            close(listen_sock);
            return -1;
        }
    }
    else
    {
        struct sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(g_local_relay_port);
        if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            close(listen_sock);
            return -1;
        }
    }

    if (listen(listen_sock, SOMAXCONN) < 0)
    {
        close(listen_sock);
        return -1;
    }
    return listen_sock;
}

// proxy server accepts connections from both redirect families.
static void * local_proxy_server(void * arg)
{
    (void)arg;
    int listen_socks[2] = {create_tcp_listener(AddressFamily::IPv4), create_tcp_listener(AddressFamily::IPv6)};
    if (listen_socks[0] < 0)
        log_message("IPv4 TCP relay listener failed");
    if (listen_socks[1] < 0)
        log_message("IPv6 TCP relay listener failed");
    if (listen_socks[0] < 0 && listen_socks[1] < 0)
        return nullptr;

    // create thread attrs with small stack (256kb not 8mb)
    // relay threads dont need big buffers anymore cuz splice
    pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&thread_attr, 262144); // 256KB stack

    while (running)
    {
        struct pollfd fds[2] = {
            {listen_socks[0], POLLIN, 0},
            {listen_socks[1], POLLIN, 0},
        };
        int ready = poll(fds, 2, 1000); // 1s timeout
        if (ready <= 0)
            continue;

        for (int index = 0; index < 2; ++index)
        {
            if (fds[index].fd < 0 || !(fds[index].revents & POLLIN))
                continue;

            struct sockaddr_storage client_addr{};
            socklen_t addr_len = sizeof(client_addr);
            const int client_sock = accept4(fds[index].fd, (struct sockaddr*)&client_addr, &addr_len, SOCK_CLOEXEC);
            if (client_sock < 0)
                continue;

            const NetworkAddress client_ip = network_address_from_sockaddr((const struct sockaddr*)&client_addr);
            const uint16_t client_port = client_addr.ss_family == AF_INET6
                ? ntohs(((struct sockaddr_in6*)&client_addr)->sin6_port)
                : ntohs(((struct sockaddr_in*)&client_addr)->sin_port);

            connection_config_t* conn_config = new connection_config_t;
            conn_config->client_socket = client_sock;
            conn_config->domain[0] = '\0';
            conn_config->is_fake_ip = false;
            conn_config->action = RuleAction::PROXY;
            if (!get_connection(
                    client_ip,
                    client_port,
                    &conn_config->orig_dest_ip,
                    &conn_config->orig_dest_port,
                    &conn_config->action,
                    conn_config->domain,
                    &conn_config->is_fake_ip))
            {
                close(client_sock);
                delete conn_config;
                continue;
            }

            pthread_t conn_thread;
            if (pthread_create(&conn_thread, &thread_attr, connection_handler, (void*)conn_config) != 0)
            {
                close(client_sock);
                delete conn_config;
            }
        }
    }

    pthread_attr_destroy(&thread_attr);
    if (listen_socks[0] >= 0)
        close(listen_socks[0]);
    if (listen_socks[1] >= 0)
        close(listen_socks[1]);
    return nullptr;
}

static void teardown_udp_associate(void);

// SOCKS5 UDP uses the proxy endpoint family for ASSOCIATE and accepts either
// IPv4 or IPv6 relay addresses in the response.
static int socks5_udp_associate(int s, struct sockaddr_storage* relay_addr, socklen_t* relay_addr_len)
{
    unsigned char buf[512];
    const bool use_auth = g_proxy_username[0] != '\0';
    buf[0] = SOCKS5_VERSION;
    buf[1] = use_auth ? 0x02 : 0x01;
    buf[2] = SOCKS5_AUTH_NONE;
    if (use_auth)
        buf[3] = 0x02;
    if (send(s, buf, use_auth ? 4 : 3, MSG_NOSIGNAL) != (use_auth ? 4 : 3))
        return -1;
    if (recv(s, buf, 2, MSG_WAITALL) != 2 || buf[0] != SOCKS5_VERSION)
        return -1;

    if (buf[1] == 0x02 && use_auth)
    {
        const size_t username_len = strlen(g_proxy_username);
        const size_t password_len = strlen(g_proxy_password);
        buf[0] = 0x01;
        buf[1] = (unsigned char)username_len;
        memcpy(buf + 2, g_proxy_username, username_len);
        buf[2 + username_len] = (unsigned char)password_len;
        memcpy(buf + 3 + username_len, g_proxy_password, password_len);
        if (send(s, buf, 3 + username_len + password_len, MSG_NOSIGNAL) != (ssize_t)(3 + username_len + password_len)
            || recv(s, buf, 2, MSG_WAITALL) != 2 || buf[0] != 0x01 || buf[1] != 0x00)
            return -1;
    }
    else if (buf[1] != SOCKS5_AUTH_NONE)
    {
        return -1;
    }

    const bool proxy_is_ipv6 = g_proxy_addr.ss_family == AF_INET6;
    const size_t request_address_size = proxy_is_ipv6 ? 16 : 4;
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_UDP_ASSOCIATE;
    buf[2] = 0x00;
    buf[3] = proxy_is_ipv6 ? SOCKS5_ATYP_IPV6 : SOCKS5_ATYP_IPV4;
    memset(buf + 4, 0, request_address_size);
    memset(buf + 4 + request_address_size, 0, 2);
    if (send(s, buf, 6 + request_address_size, MSG_NOSIGNAL) != (ssize_t)(6 + request_address_size))
        return -1;

    if (recv(s, buf, 4, MSG_WAITALL) != 4 || buf[0] != SOCKS5_VERSION || buf[1] != 0x00)
        return -1;
    const size_t response_address_size = buf[3] == SOCKS5_ATYP_IPV4 ? 4 : buf[3] == SOCKS5_ATYP_IPV6 ? 16 : 0;
    if (response_address_size == 0 || recv(s, buf + 4, response_address_size + 2, MSG_WAITALL) != (ssize_t)(response_address_size + 2))
        return -1;

    memset(relay_addr, 0, sizeof(*relay_addr));
    if (buf[3] == SOCKS5_ATYP_IPV4)
    {
        struct sockaddr_in* relay = (struct sockaddr_in*)relay_addr;
        relay->sin_family = AF_INET;
        memcpy(&relay->sin_addr, buf + 4, 4);
        memcpy(&relay->sin_port, buf + 8, 2);
        *relay_addr_len = sizeof(*relay);
    }
    else
    {
        struct sockaddr_in6* relay = (struct sockaddr_in6*)relay_addr;
        relay->sin6_family = AF_INET6;
        memcpy(&relay->sin6_addr, buf + 4, 16);
        memcpy(&relay->sin6_port, buf + 20, 2);
        *relay_addr_len = sizeof(*relay);
    }
    return 0;
}

static bool establish_udp_associate(void)
{
    const uint64_t now = get_monotonic_ms();
    if (now - last_udp_connect_attempt < 5000 || g_proxy_addr_len == 0)
        return false;
    last_udp_connect_attempt = now;
    teardown_udp_associate();

    const int tcp_sock = socket(g_proxy_addr.ss_family, SOCK_STREAM, 0);
    if (tcp_sock < 0)
        return false;
    configure_tcp_socket(tcp_sock, 262144, 3000);
    if (connect(tcp_sock, (struct sockaddr*)&g_proxy_addr, g_proxy_addr_len) < 0
        || socks5_udp_associate(tcp_sock, &socks5_udp_relay_addr, &socks5_udp_relay_addr_len) != 0)
    {
        close(tcp_sock);
        return false;
    }

    if (socks5_udp_relay_addr.ss_family == g_proxy_addr.ss_family)
    {
        if (socks5_udp_relay_addr.ss_family == AF_INET
            && ((struct sockaddr_in*)&socks5_udp_relay_addr)->sin_addr.s_addr == INADDR_ANY)
            ((struct sockaddr_in*)&socks5_udp_relay_addr)->sin_addr = ((struct sockaddr_in*)&g_proxy_addr)->sin_addr;
        if (socks5_udp_relay_addr.ss_family == AF_INET6
            && IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6*)&socks5_udp_relay_addr)->sin6_addr))
            ((struct sockaddr_in6*)&socks5_udp_relay_addr)->sin6_addr = ((struct sockaddr_in6*)&g_proxy_addr)->sin6_addr;
    }

    struct timeval zero_tv = {0, 0};
    setsockopt(tcp_sock, SOL_SOCKET, SO_RCVTIMEO, &zero_tv, sizeof(zero_tv));
    setsockopt(tcp_sock, SOL_SOCKET, SO_SNDTIMEO, &zero_tv, sizeof(zero_tv));
    const int keepalive = 1;
    setsockopt(tcp_sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));

    socks5_udp_control_socket = tcp_sock;
    socks5_udp_send_socket = socket(socks5_udp_relay_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (socks5_udp_send_socket < 0)
    {
        teardown_udp_associate();
        return false;
    }
    configure_udp_socket(socks5_udp_send_socket, 262144, 30000);
    udp_associate_connected = true;
    log_message("UDP ASSOCIATE established with SOCKS5 proxy");
    return true;
}

static void teardown_udp_associate(void)
{
    udp_associate_connected = false;
    if (socks5_udp_control_socket >= 0)
    {
        close(socks5_udp_control_socket);
        socks5_udp_control_socket = -1;
    }
    if (socks5_udp_send_socket >= 0)
    {
        close(socks5_udp_send_socket);
        socks5_udp_send_socket = -1;
    }
    socks5_udp_relay_addr_len = 0;
}

static int create_udp_relay_listener(AddressFamily family)
{
    const int relay_socket = socket(socket_family(family), SOCK_DGRAM, IPPROTO_UDP);
    if (relay_socket < 0)
        return -1;
    const int on = 1;
    setsockopt(relay_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (family == AddressFamily::IPv6)
    {
        const int v6_only = 1;
        setsockopt(relay_socket, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only));
        struct sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(LOCAL_UDP_RELAY_PORT);
        if (bind(relay_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            close(relay_socket);
            return -1;
        }
    }
    else
    {
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(LOCAL_UDP_RELAY_PORT);
        if (bind(relay_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            close(relay_socket);
            return -1;
        }
    }
    configure_udp_socket(relay_socket, 262144, 30000);
    return relay_socket;
}

static void * udp_relay_server(void * arg)
{
    (void)arg;
    udp_relay_sockets[0] = create_udp_relay_listener(AddressFamily::IPv4);
    udp_relay_sockets[1] = create_udp_relay_listener(AddressFamily::IPv6);
    if (udp_relay_sockets[0] < 0)
        log_message("IPv4 UDP relay listener failed");
    if (udp_relay_sockets[1] < 0)
        log_message("IPv6 UDP relay listener failed");
    if (udp_relay_sockets[0] < 0 && udp_relay_sockets[1] < 0)
        return nullptr;

    unsigned char recv_buf[65536];
    unsigned char send_buf[65536];
    udp_associate_connected = establish_udp_associate();

    while (running)
    {
        struct pollfd fds[4] = {
            {udp_relay_sockets[0], POLLIN, 0},
            {udp_relay_sockets[1], POLLIN, 0},
            {udp_associate_connected ? socks5_udp_send_socket : -1, POLLIN, 0},
            {udp_associate_connected ? socks5_udp_control_socket : -1, POLLIN, 0},
        };
        const int ready = poll(fds, 4, 1000);
        if (ready <= 0)
        {
            if (!udp_associate_connected)
                udp_associate_connected = establish_udp_associate();
            continue;
        }

        if (fds[3].fd >= 0 && (fds[3].revents & (POLLIN | POLLHUP | POLLERR)))
        {
            char peek_byte;
            const ssize_t peeked = recv(socks5_udp_control_socket, &peek_byte, 1, MSG_PEEK | MSG_DONTWAIT);
            if (peeked == 0 || (peeked < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
            {
                teardown_udp_associate();
                continue;
            }
        }

        for (int index = 0; index < 2; ++index)
        {
            if (fds[index].fd < 0 || !(fds[index].revents & POLLIN))
                continue;

            struct sockaddr_storage from_addr{};
            socklen_t from_len = sizeof(from_addr);
            const ssize_t recv_len = recvfrom(fds[index].fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&from_addr, &from_len);
            if (recv_len <= 0)
                continue;
            if (!udp_associate_connected && !establish_udp_associate())
                continue;

            const NetworkAddress client_ip = network_address_from_sockaddr((const struct sockaddr*)&from_addr);
            const uint16_t client_port = from_addr.ss_family == AF_INET6
                ? ntohs(((struct sockaddr_in6*)&from_addr)->sin6_port)
                : ntohs(((struct sockaddr_in*)&from_addr)->sin_port);
            NetworkAddress dest_ip;
            uint16_t dest_port = 0;
            if (!get_connection(client_ip, client_port, &dest_ip, &dest_port))
                continue;

            size_t encoded_size = 0;
            if (!encode_socks5_address(dest_ip, dest_port, send_buf + 3, sizeof(send_buf) - 3, &encoded_size))
                continue;
            const size_t header_size = 3 + encoded_size;
            if (recv_len > (ssize_t)(sizeof(send_buf) - header_size))
                continue;
            send_buf[0] = 0;
            send_buf[1] = 0;
            send_buf[2] = 0;
            memcpy(send_buf + header_size, recv_buf, recv_len);

            const ssize_t sent = sendto(
                socks5_udp_send_socket,
                send_buf,
                header_size + recv_len,
                0,
                (struct sockaddr*)&socks5_udp_relay_addr,
                socks5_udp_relay_addr_len);
            if (sent < 0)
                teardown_udp_associate();
        }

        if (fds[2].fd >= 0 && (fds[2].revents & POLLIN))
        {
            struct sockaddr_storage from_addr{};
            socklen_t from_len = sizeof(from_addr);
            const ssize_t recv_len = recvfrom(socks5_udp_send_socket, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&from_addr, &from_len);
            if (recv_len < 4 || recv_buf[2] != 0)
                continue;

            NetworkAddress source_ip;
            uint16_t source_port = 0;
            size_t decoded_size = 0;
            if (!decode_socks5_address(recv_buf + 3, recv_len - 3, &source_ip, &source_port, &decoded_size))
                continue;
            const size_t header_size = 3 + decoded_size;

            struct sockaddr_storage client_addr{};
            socklen_t client_addr_len = 0;
            int client_socket = -1;
            pthread_rwlock_rdlock(&conn_lock);
            for (int hash = 0; hash < CONNECTION_HASH_SIZE && client_socket < 0; ++hash)
            {
                for (CONNECTION_INFO* conn = connection_hash_table[hash]; conn != nullptr; conn = conn->next)
                {
                    if (conn->orig_dest_ip != source_ip || conn->orig_dest_port != source_port)
                        continue;
                    conn->last_activity = get_monotonic_ms();
                    if (!make_loopback_endpoint(conn->src_ip.family, conn->src_port, &client_addr, &client_addr_len))
                        continue;
                    client_socket = udp_relay_sockets[conn->src_ip.family == AddressFamily::IPv4 ? 0 : 1];
                    break;
                }
            }
            pthread_rwlock_unlock(&conn_lock);

            if (client_socket >= 0)
                sendto(client_socket, recv_buf + header_size, recv_len - header_size, 0, (struct sockaddr*)&client_addr, client_addr_len);
        }

        if (fds[2].fd >= 0 && (fds[2].revents & (POLLHUP | POLLERR)))
            teardown_udp_associate();
    }

    teardown_udp_associate();
    for (int index = 0; index < 2; ++index)
    {
        if (udp_relay_sockets[index] >= 0)
        {
            close(udp_relay_sockets[index]);
            udp_relay_sockets[index] = -1;
        }
    }
    return nullptr;
}

// nfqueue callback for packets
static int packet_callback(struct nfq_q_handle * qh, struct nfgenmsg * nfmsg, struct nfq_data * nfad, void * data)
{
    (void)data;

    struct nfqnl_msg_packet_hdr * ph = nfq_get_msg_packet_hdr(nfad);
    if (!ph)
        return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, nullptr);

    uint32_t id = ntohl(ph->packet_id);

    unsigned char * payload;
    int payload_len = nfq_get_payload(nfad, &payload);
    if (payload_len < 1)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

    // fast path when no rules
    if (!g_has_active_rules && g_connection_callback == nullptr)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

    NetworkAddress src_ip;
    NetworkAddress dest_ip;
    unsigned char* transport = nullptr;
    size_t transport_len = 0;
    uint8_t protocol = 0;

    const uint8_t version = payload[0] >> 4;
    if (version == 4)
    {
        if (payload_len < (int)sizeof(struct iphdr))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
        const struct iphdr* iph = (const struct iphdr*)payload;
        const size_t header_len = iph->ihl * 4;
        if (iph->ihl < 5 || payload_len < (int)header_len)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
        src_ip = network_address_from_ipv4(iph->saddr);
        dest_ip = network_address_from_ipv4(iph->daddr);
        protocol = iph->protocol;
        transport = payload + header_len;
        transport_len = payload_len - header_len;
    }
    else if (version == 6)
    {
        if (payload_len < (int)sizeof(struct ip6_hdr))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
        const struct ip6_hdr* ip6h = (const struct ip6_hdr*)payload;
        // Extension-header and fragmented traffic is deliberately outside this path.
        if (ip6h->ip6_nxt != IPPROTO_TCP && ip6h->ip6_nxt != IPPROTO_UDP)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
        src_ip = network_address_from_ipv6(ip6h->ip6_src);
        dest_ip = network_address_from_ipv6(ip6h->ip6_dst);
        protocol = ip6h->ip6_nxt;
        transport = payload + sizeof(struct ip6_hdr);
        transport_len = payload_len - sizeof(struct ip6_hdr);
    }
    else
    {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }

    uint16_t src_port = 0;
    uint16_t dest_port = 0;
    RuleAction action = RuleAction::DIRECT;
    uint32_t pid = 0;

    if (protocol == IPPROTO_TCP)
    {
        if (transport_len < sizeof(struct tcphdr))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

        struct tcphdr * tcph = (struct tcphdr *)transport;
        src_port = ntohs(tcph->source);
        dest_port = ntohs(tcph->dest);

        // skip our own packets from local relay and DNS proxy
        if (src_port == g_local_relay_port || src_port == LOCAL_DNS_PROXY_PORT)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

        if (is_connection_tracked(src_ip, src_port))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

        // only look at syn packets for new connections
        if (!(tcph->syn && !tcph->ack))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

        const bool dest_is_fake_ip = g_fake_ip_store.contains(dest_ip);
        char fake_domain[256] = "";
        const char* domain_for_rule = nullptr;

        if (dest_is_fake_ip)
        {
            auto mapped = g_fake_ip_store.lookup_domain(dest_ip);
            if (!mapped)
                return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr); // stale fake ip, force re-resolve
            snprintf(fake_domain, sizeof(fake_domain), "%s", mapped->c_str());
            domain_for_rule = fake_domain;
        }

        action = check_process_rule(src_ip, src_port, dest_ip, dest_port, false, &pid, domain_for_rule);

        if (action == RuleAction::PROXY && is_broadcast_or_multicast(dest_ip))
            action = RuleAction::DIRECT;

        // log it if not from our own process
        if (g_traffic_logging_enabled && g_connection_callback != nullptr && (tcph->syn && !tcph->ack) && pid > 0
            && pid != g_current_process_id)
        {
            char process_name[MAX_PROCESS_NAME];
            if (get_process_name_from_pid(pid, process_name, sizeof(process_name)))
            {
                if (!is_connection_already_logged(pid, dest_ip, dest_port, action))
                {
                    char dest_ip_str[INET6_ADDRSTRLEN];
                    format_network_address(dest_ip, dest_ip_str, sizeof(dest_ip_str));

                    char proxy_info[300];
                    if (action == RuleAction::PROXY)
                    {
                        snprintf(
                            proxy_info,
                            sizeof(proxy_info),
                            "proxy %s://%s:%d tcp",
                            g_proxy_type == ProxyType::HTTP ? "http" : "socks5",
                            g_proxy_host,
                            g_proxy_port);
                    }
                    else if (action == RuleAction::DIRECT)
                    {
                        snprintf(proxy_info, sizeof(proxy_info), "direct tcp");
                    }
                    else if (action == RuleAction::BLOCK)
                    {
                        snprintf(proxy_info, sizeof(proxy_info), "blocked tcp");
                    }

                    const char * display_name = extract_filename(process_name);
                    g_connection_callback(display_name, pid, dest_ip_str, dest_port, proxy_info);

                    add_logged_connection(pid, dest_ip, dest_port, action);
                }
            }
        }

        if (dest_is_fake_ip)
        {
            if (action == RuleAction::BLOCK)
                return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);

            // fake-IP connections always go to the local relay so it can resolve/connect
            add_connection(src_port, src_ip, dest_ip, dest_port, action, fake_domain, true);
            uint32_t mark = FAKE_IP_MARK_TCP;
            return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, nullptr);
        }

        if (action == RuleAction::DIRECT)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
        else if (action == RuleAction::BLOCK)
            return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
        else if (action == RuleAction::PROXY)
        {
            // store connection info
            add_connection(src_port, src_ip, dest_ip, dest_port, action, nullptr, false);

            // mark packet so nat table REDIRECT rule will catch it
            uint32_t mark = 1;
            return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, nullptr);
        }
    }
    else if (protocol == IPPROTO_UDP)
    {
        if (transport_len < sizeof(struct udphdr))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

        struct udphdr * udph = (struct udphdr *)transport;
        src_port = ntohs(udph->source);
        dest_port = ntohs(udph->dest);

        if (src_port == LOCAL_UDP_RELAY_PORT || src_port == LOCAL_DNS_PROXY_PORT)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

        if (is_connection_tracked(src_ip, src_port))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

        const bool dest_is_fake_ip = g_fake_ip_store.contains(dest_ip);
        char fake_domain[256] = "";
        const char* domain_for_rule = nullptr;

        if (dest_is_fake_ip)
        {
            auto mapped = g_fake_ip_store.lookup_domain(dest_ip);
            if (!mapped)
                return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
            snprintf(fake_domain, sizeof(fake_domain), "%s", mapped->c_str());
            domain_for_rule = fake_domain;
        }

        action = check_process_rule(src_ip, src_port, dest_ip, dest_port, true, &pid, domain_for_rule);

        if (action == RuleAction::PROXY && is_broadcast_or_multicast(dest_ip))
            action = RuleAction::DIRECT;

        if (action == RuleAction::PROXY && (dest_port == 67 || dest_port == 68))
            action = RuleAction::DIRECT;

        // UDP proxy only works with SOCKS5, not HTTP
        if (action == RuleAction::PROXY && g_proxy_type != ProxyType::SOCKS5)
            action = RuleAction::DIRECT;

        // log (skip our own process, log even without PID for ephemeral UDP sockets)
        if (g_traffic_logging_enabled && g_connection_callback != nullptr && pid != g_current_process_id)
        {
            char process_name[MAX_PROCESS_NAME];
            uint32_t log_pid = (pid == 0) ? 1 : pid; // Use PID 1 for unknown processes

            if (pid > 0 && get_process_name_from_pid(pid, process_name, sizeof(process_name)))
            {
                // Got process name from PID
            }
            else
            {
                // UDP socket not found - ephemeral or timing issue
                snprintf(process_name, sizeof(process_name), "unknown");
            }

            if (!is_connection_already_logged(log_pid, dest_ip, dest_port, action))
            {
                char dest_ip_str[INET6_ADDRSTRLEN];
                format_network_address(dest_ip, dest_ip_str, sizeof(dest_ip_str));

                char proxy_info[300];
                if (action == RuleAction::PROXY)
                {
                    snprintf(proxy_info, sizeof(proxy_info), "proxy socks5://%s:%d udp", g_proxy_host, g_proxy_port);
                }
                else if (action == RuleAction::DIRECT)
                {
                    snprintf(proxy_info, sizeof(proxy_info), "direct udp");
                }
                else if (action == RuleAction::BLOCK)
                {
                    snprintf(proxy_info, sizeof(proxy_info), "blocked udp");
                }

                const char * display_name = extract_filename(process_name);
                g_connection_callback(display_name, log_pid, dest_ip_str, dest_port, proxy_info);

                add_logged_connection(log_pid, dest_ip, dest_port, action);
            }
        }

        if (dest_is_fake_ip)
        {
            if (action == RuleAction::BLOCK)
                return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);

            add_connection(src_port, src_ip, dest_ip, dest_port, action, fake_domain, true);
            uint32_t mark = FAKE_IP_MARK_UDP;
            return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, nullptr);
        }

        if (action == RuleAction::DIRECT)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
        else if (action == RuleAction::BLOCK)
            return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
        else if (action == RuleAction::PROXY)
        {
            // UDP proxy via SOCKS5 UDP ASSOCIATE
            add_connection(src_port, src_ip, dest_ip, dest_port, action, nullptr, false);

            // Mark UDP packet for redirect to local UDP relay (port 34011)
            uint32_t mark = 2; // Use mark=2 for UDP (mark=1 is for TCP)
            return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, nullptr);
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

static void * packet_processor(void * arg)
{
    (void)arg;
    char buf[4096] __attribute__((aligned));
    int fd = nfq_fd(nfq_h);
    ssize_t rv;

    while (running)
    {
        rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0)
            nfq_handle_packet(nfq_h, buf, rv);
        // On error: ENOBUFS = kernel queue full (normal under load),
        // EINTR = signal, other = transient. Always continue -
        // stopping the thread would break all network traffic.
    }

    return nullptr;
}

static uint32_t connection_hash(const NetworkAddress& src_ip, uint16_t port)
{
    uint32_t hash = static_cast<uint32_t>(port) ^ static_cast<uint32_t>(src_ip.family);
    for (size_t i = 0; i < network_address_size(src_ip); ++i)
        hash = (hash * 16777619U) ^ src_ip.bytes[i];
    return hash % CONNECTION_HASH_SIZE;
}

static void add_connection(
    uint16_t src_port,
    const NetworkAddress& src_ip,
    const NetworkAddress& dest_ip,
    uint16_t dest_port,
    RuleAction action,
    const char* domain,
    bool is_fake_ip)
{
    uint32_t hash = connection_hash(src_ip, src_port);
    pthread_rwlock_wrlock(&conn_lock);

    CONNECTION_INFO * conn = connection_hash_table[hash];
    while (conn != nullptr)
    {
        if (conn->src_port == src_port && conn->src_ip == src_ip)
        {
            conn->orig_dest_ip = dest_ip;
            conn->orig_dest_port = dest_port;
            conn->resolved_dest_ip = is_fake_ip ? NetworkAddress{} : dest_ip;
            conn->resolved_dest_port = is_fake_ip ? 0 : dest_port;
            conn->resolved = !is_fake_ip;
            conn->src_ip = src_ip;
            conn->is_tracked = true;
            conn->last_activity = get_monotonic_ms();
            conn->action = action;
            conn->is_fake_ip = is_fake_ip;
            if (domain != nullptr)
                snprintf(conn->domain, sizeof(conn->domain), "%s", domain);
            else
                conn->domain[0] = '\0';
            pthread_rwlock_unlock(&conn_lock);
            return;
        }
        conn = conn->next;
    }

    CONNECTION_INFO* new_conn = new CONNECTION_INFO;
    new_conn->src_port = src_port;
    new_conn->src_ip = src_ip;
    new_conn->orig_dest_ip = dest_ip;
    new_conn->orig_dest_port = dest_port;
    new_conn->resolved_dest_ip = is_fake_ip ? NetworkAddress{} : dest_ip;
    new_conn->resolved_dest_port = is_fake_ip ? 0 : dest_port;
    new_conn->resolved = !is_fake_ip;
    new_conn->is_tracked = true;
    new_conn->last_activity = get_monotonic_ms();
    new_conn->action = action;
    new_conn->is_fake_ip = is_fake_ip;
    if (domain != nullptr)
        snprintf(new_conn->domain, sizeof(new_conn->domain), "%s", domain);
    else
        new_conn->domain[0] = '\0';
    new_conn->next = connection_hash_table[hash];
    connection_hash_table[hash] = new_conn;

    pthread_rwlock_unlock(&conn_lock);
}

static bool get_connection(
    const NetworkAddress& src_ip,
    uint16_t src_port,
    NetworkAddress* dest_ip,
    uint16_t* dest_port,
    RuleAction* action,
    char* domain,
    bool* is_fake_ip,
    NetworkAddress* resolved_dest_ip,
    uint16_t* resolved_dest_port)
{
    uint32_t hash = connection_hash(src_ip, src_port);
    pthread_rwlock_rdlock(&conn_lock);

    CONNECTION_INFO * conn = connection_hash_table[hash];
    while (conn != nullptr)
    {
        if (conn->src_port == src_port && conn->src_ip == src_ip && conn->is_tracked)
        {
            *dest_ip = conn->orig_dest_ip;
            *dest_port = conn->orig_dest_port;
            conn->last_activity = get_monotonic_ms(); // benign race on timestamp
            if (action != nullptr)
                *action = conn->action;
            if (is_fake_ip != nullptr)
                *is_fake_ip = conn->is_fake_ip;
            if (domain != nullptr)
                snprintf(domain, 256, "%s", conn->domain[0] != '\0' ? conn->domain : "");
            if (resolved_dest_ip != nullptr)
                *resolved_dest_ip = conn->resolved ? conn->resolved_dest_ip : conn->orig_dest_ip;
            if (resolved_dest_port != nullptr)
                *resolved_dest_port = conn->resolved ? conn->resolved_dest_port : conn->orig_dest_port;
            pthread_rwlock_unlock(&conn_lock);
            return true;
        }
        conn = conn->next;
    }

    pthread_rwlock_unlock(&conn_lock);
    return false;
}

static bool is_connection_tracked(const NetworkAddress& src_ip, uint16_t src_port)
{
    uint32_t hash = connection_hash(src_ip, src_port);
    pthread_rwlock_rdlock(&conn_lock);

    CONNECTION_INFO * conn = connection_hash_table[hash];
    while (conn != nullptr)
    {
        if (conn->src_port == src_port && conn->src_ip == src_ip && conn->is_tracked)
        {
            pthread_rwlock_unlock(&conn_lock);
            return true;
        }
        conn = conn->next;
    }

    pthread_rwlock_unlock(&conn_lock);
    return false;
}

static bool set_resolved_connection(
    const NetworkAddress& src_ip,
    uint16_t src_port,
    const NetworkAddress& resolved_ip,
    uint16_t resolved_port)
{
    uint32_t hash = connection_hash(src_ip, src_port);
    pthread_rwlock_wrlock(&conn_lock);

    CONNECTION_INFO* conn = connection_hash_table[hash];
    while (conn != nullptr)
    {
        if (conn->src_port == src_port && conn->src_ip == src_ip && conn->is_tracked)
        {
            conn->resolved_dest_ip = resolved_ip;
            conn->resolved_dest_port = resolved_port;
            conn->resolved = true;
            conn->last_activity = get_monotonic_ms();
            pthread_rwlock_unlock(&conn_lock);
            return true;
        }
        conn = conn->next;
    }

    pthread_rwlock_unlock(&conn_lock);
    return false;
}

static void __attribute__((unused)) remove_connection(const NetworkAddress& src_ip, uint16_t src_port)
{
    uint32_t hash = connection_hash(src_ip, src_port);
    pthread_rwlock_wrlock(&conn_lock);

    CONNECTION_INFO ** conn_ptr = &connection_hash_table[hash];
    while (*conn_ptr != nullptr)
    {
        if ((*conn_ptr)->src_port == src_port && (*conn_ptr)->src_ip == src_ip)
        {
            CONNECTION_INFO * to_free = *conn_ptr;
            *conn_ptr = (*conn_ptr)->next;
            delete to_free;
            pthread_rwlock_unlock(&conn_lock);
            return;
        }
        conn_ptr = &(*conn_ptr)->next;
    }

    pthread_rwlock_unlock(&conn_lock);
}

static void cleanup_stale_connections(void)
{
    uint64_t now = get_monotonic_ms();

    // Cleanup connection hash table
    for (int i = 0; i < CONNECTION_HASH_SIZE; i++)
    {
        pthread_rwlock_wrlock(&conn_lock);
        CONNECTION_INFO ** conn_ptr = &connection_hash_table[i];

        while (*conn_ptr != nullptr)
        {
            if (now - (*conn_ptr)->last_activity > 120000) // 120 sec timeout
            {
                CONNECTION_INFO * to_free = *conn_ptr;
                *conn_ptr = (*conn_ptr)->next;
                delete to_free;
            }
            else
            {
                conn_ptr = &(*conn_ptr)->next;
            }
        }
        pthread_rwlock_unlock(&conn_lock);
    }

    // Cleanup PID cache (separate lock - no contention with connection lookups)
    uint64_t now_cache = get_monotonic_ms();
    for (int i = 0; i < PID_CACHE_SIZE; i++)
    {
        pthread_mutex_lock(&pid_cache_lock);
        PID_CACHE_ENTRY ** entry_ptr = &pid_cache[i];
        while (*entry_ptr != nullptr)
        {
            if (now_cache - (*entry_ptr)->timestamp > 10000) // 10 sec cache TTL
            {
                PID_CACHE_ENTRY * to_free = *entry_ptr;
                *entry_ptr = (*entry_ptr)->next;
                delete to_free;
            }
            else
            {
                entry_ptr = &(*entry_ptr)->next;
            }
        }
        pthread_mutex_unlock(&pid_cache_lock);
    }

    // Keep only last 100 logged connections
    pthread_mutex_lock(&log_lock);
    int logged_count = 0;
    LOGGED_CONNECTION * temp = logged_connections;
    while (temp != nullptr)
    {
        logged_count++;
        temp = temp->next;
    }

    if (logged_count > 100)
    {
        temp = logged_connections;
        for (int i = 0; i < 99 && temp != nullptr; i++)
        {
            temp = temp->next;
        }
        if (temp != nullptr && temp->next != nullptr)
        {
            LOGGED_CONNECTION * to_free = temp->next;
            temp->next = nullptr;
            while (to_free != nullptr)
            {
                LOGGED_CONNECTION * next = to_free->next;
                delete to_free;
                to_free = next;
            }
        }
    }
    pthread_mutex_unlock(&log_lock);
}

static bool is_connection_already_logged(uint32_t pid, const NetworkAddress& dest_ip, uint16_t dest_port, RuleAction action)
{
    pthread_mutex_lock(&log_lock);

    LOGGED_CONNECTION * logged = logged_connections;
    while (logged != nullptr)
    {
        if (logged->pid == pid && logged->dest_ip == dest_ip && logged->dest_port == dest_port && logged->action == action)
        {
            pthread_mutex_unlock(&log_lock);
            return true;
        }
        logged = logged->next;
    }

    pthread_mutex_unlock(&log_lock);
    return false;
}

static void add_logged_connection(uint32_t pid, const NetworkAddress& dest_ip, uint16_t dest_port, RuleAction action)
{
    pthread_mutex_lock(&log_lock);

    // keep only last 100 entries to avoid memory growth
    int count = 0;
    LOGGED_CONNECTION * temp = logged_connections;
    while (temp != nullptr && count < 100)
    {
        count++;
        temp = temp->next;
    }

    if (count >= 100)
    {
        temp = logged_connections;
        for (int i = 0; i < 98 && temp != nullptr; i++)
        {
            temp = temp->next;
        }

        if (temp != nullptr && temp->next != nullptr)
        {
            LOGGED_CONNECTION * to_free_list = temp->next;
            temp->next = nullptr;

            // Free excess entries (still under log_lock, but this is rare)
            while (to_free_list != nullptr)
            {
                LOGGED_CONNECTION * next = to_free_list->next;
                delete to_free_list;
                to_free_list = next;
            }
        }
    }

    LOGGED_CONNECTION* logged = new LOGGED_CONNECTION;
    logged->pid = pid;
    logged->dest_ip = dest_ip;
    logged->dest_port = dest_port;
    logged->action = action;
    logged->next = logged_connections;
    logged_connections = logged;

    pthread_mutex_unlock(&log_lock);
}

static void clear_logged_connections(void)
{
    pthread_mutex_lock(&log_lock);

    while (logged_connections != nullptr)
    {
        LOGGED_CONNECTION * to_free = logged_connections;
        logged_connections = logged_connections->next;
        delete to_free;
    }

    pthread_mutex_unlock(&log_lock);
}

static uint32_t pid_cache_hash(const NetworkAddress& src_ip, uint16_t src_port, bool is_udp)
{
    uint32_t hash = static_cast<uint32_t>(src_port) ^ (is_udp ? 0x80000000 : 0) ^ static_cast<uint32_t>(src_ip.family);
    for (size_t i = 0; i < network_address_size(src_ip); ++i)
        hash = (hash * 16777619U) ^ src_ip.bytes[i];
    return hash % PID_CACHE_SIZE;
}

static uint32_t get_cached_pid(const NetworkAddress& src_ip, uint16_t src_port, bool is_udp)
{
    uint32_t hash = pid_cache_hash(src_ip, src_port, is_udp);
    uint64_t current_time = get_monotonic_ms();
    uint32_t pid = 0;

    pthread_mutex_lock(&pid_cache_lock);

    PID_CACHE_ENTRY * entry = pid_cache[hash];
    while (entry != nullptr)
    {
        if (entry->src_ip == src_ip && entry->src_port == src_port && entry->is_udp == is_udp)
        {
            if (current_time - entry->timestamp < PID_CACHE_TTL_MS)
            {
                pid = entry->pid;
                break;
            }
            else
            {
                break;
            }
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&pid_cache_lock);
    return pid;
}

static void cache_pid(const NetworkAddress& src_ip, uint16_t src_port, uint32_t pid, bool is_udp)
{
    uint32_t hash = pid_cache_hash(src_ip, src_port, is_udp);
    uint64_t current_time = get_monotonic_ms();

    pthread_mutex_lock(&pid_cache_lock);

    PID_CACHE_ENTRY * entry = pid_cache[hash];
    while (entry != nullptr)
    {
        if (entry->src_ip == src_ip && entry->src_port == src_port && entry->is_udp == is_udp)
        {
            entry->pid = pid;
            entry->timestamp = current_time;
            pthread_mutex_unlock(&pid_cache_lock);
            return;
        }
        entry = entry->next;
    }

    PID_CACHE_ENTRY* new_entry = new PID_CACHE_ENTRY;
    new_entry->src_ip = src_ip;
    new_entry->src_port = src_port;
    new_entry->pid = pid;
    new_entry->timestamp = current_time;
    new_entry->is_udp = is_udp;
    new_entry->next = pid_cache[hash];
    pid_cache[hash] = new_entry;

    pthread_mutex_unlock(&pid_cache_lock);
}

static void clear_pid_cache(void)
{
    pthread_mutex_lock(&pid_cache_lock);

    for (int i = 0; i < PID_CACHE_SIZE; i++)
    {
        while (pid_cache[i] != nullptr)
        {
            PID_CACHE_ENTRY * to_free = pid_cache[i];
            pid_cache[i] = pid_cache[i]->next;
            delete to_free;
        }
    }

    pthread_mutex_unlock(&pid_cache_lock);
}

static void * cleanup_worker(void * arg)
{
    (void)arg;
    while (running)
    {
        sleep(30); // 30 seconds
        if (running)
        {
            cleanup_stale_connections();
        }
    }
    return nullptr;
}

static void update_has_active_rules(void)
{
    g_has_active_rules = false;
    PROCESS_RULE * rule = rules_list;
    while (rule != nullptr)
    {
        if (rule->enabled)
        {
            g_has_active_rules = true;
            break;
        }
        rule = rule->next;
    }
}

uint32_t add_rule(
    const char * process_name, const char * target_hosts, const char * target_ports, RuleProtocol protocol, RuleAction action)
{
    if (process_name == nullptr || process_name[0] == '\0')
        return 0;

    const char * hosts = target_hosts != nullptr && target_hosts[0] != '\0' ? target_hosts : "*";
    const char * ports = target_ports != nullptr && target_ports[0] != '\0' ? target_ports : "*";
    std::string rule_error;
    if (!validate_host_list(hosts, &rule_error) || !validate_port_list(ports, &rule_error))
    {
        log_message("invalid rule for process %s: %s", process_name, rule_error.c_str());
        return 0;
    }

    PROCESS_RULE * rule = (PROCESS_RULE *)malloc(sizeof(PROCESS_RULE));
    if (rule == nullptr)
        return 0;

    rule->rule_id = g_next_rule_id++;
    strncpy(rule->process_name, process_name, MAX_PROCESS_NAME - 1);
    rule->process_name[MAX_PROCESS_NAME - 1] = '\0';
    rule->protocol = protocol;

    if (target_hosts != nullptr && target_hosts[0] != '\0')
    {
        rule->target_hosts = strdup(target_hosts);
        if (rule->target_hosts == nullptr)
        {
            free(rule);
            return 0;
        }
    }
    else
    {
        rule->target_hosts = strdup("*");
        if (rule->target_hosts == nullptr)
        {
            free(rule);
            return 0;
        }
    }

    if (target_ports != nullptr && target_ports[0] != '\0')
    {
        rule->target_ports = strdup(target_ports);
        if (rule->target_ports == nullptr)
        {
            free(rule->target_hosts);
            free(rule);
            return 0;
        }
    }
    else
    {
        rule->target_ports = strdup("*");
        if (rule->target_ports == nullptr)
        {
            free(rule->target_hosts);
            free(rule);
            return 0;
        }
    }

    rule->action = action;
    rule->enabled = true;

    pthread_rwlock_wrlock(&rules_lock);
    rule->next = nullptr;
    if (rules_list == nullptr)
    {
        rules_list = rule;
    }
    else
    {
        PROCESS_RULE * tail = rules_list;
        while (tail->next != nullptr)
            tail = tail->next;
        tail->next = rule;
    }
    update_has_active_rules();
    pthread_rwlock_unlock(&rules_lock);

    log_message("added rule id %u for process %s protocol %d action %d", rule->rule_id, process_name, protocol, action);

    return rule->rule_id;
}

bool enable_rule(uint32_t rule_id)
{
    if (rule_id == 0)
        return false;

    pthread_rwlock_wrlock(&rules_lock);
    PROCESS_RULE * rule = rules_list;
    while (rule != nullptr)
    {
        if (rule->rule_id == rule_id)
        {
            rule->enabled = true;
            update_has_active_rules();
            pthread_rwlock_unlock(&rules_lock);
            log_message("enabled rule id %u", rule_id);
            return true;
        }
        rule = rule->next;
    }
    pthread_rwlock_unlock(&rules_lock);
    return false;
}

bool disable_rule(uint32_t rule_id)
{
    if (rule_id == 0)
        return false;

    pthread_rwlock_wrlock(&rules_lock);
    PROCESS_RULE * rule = rules_list;
    while (rule != nullptr)
    {
        if (rule->rule_id == rule_id)
        {
            rule->enabled = false;
            update_has_active_rules();
            pthread_rwlock_unlock(&rules_lock);
            log_message("disabled rule id %u", rule_id);
            return true;
        }
        rule = rule->next;
    }
    pthread_rwlock_unlock(&rules_lock);
    return false;
}

bool delete_rule(uint32_t rule_id)
{
    if (rule_id == 0)
        return false;

    pthread_rwlock_wrlock(&rules_lock);
    PROCESS_RULE * rule = rules_list;
    PROCESS_RULE * prev = nullptr;

    while (rule != nullptr)
    {
        if (rule->rule_id == rule_id)
        {
            if (prev == nullptr)
                rules_list = rule->next;
            else
                prev->next = rule->next;

            update_has_active_rules();
            pthread_rwlock_unlock(&rules_lock);

            if (rule->target_hosts != nullptr)
                free(rule->target_hosts);
            if (rule->target_ports != nullptr)
                free(rule->target_ports);
            free(rule);

            log_message("deleted rule id %u", rule_id);
            return true;
        }
        prev = rule;
        rule = rule->next;
    }
    pthread_rwlock_unlock(&rules_lock);
    return false;
}

bool edit_rule(
    uint32_t rule_id,
    const char * process_name,
    const char * target_hosts,
    const char * target_ports,
    RuleProtocol protocol,
    RuleAction action)
{
    if (rule_id == 0 || process_name == nullptr || target_hosts == nullptr || target_ports == nullptr)
        return false;

    // Pre-allocate new strings before taking lock to minimize hold time
    char * new_hosts = strdup(target_hosts);
    char * new_ports = strdup(target_ports);
    if (new_hosts == nullptr || new_ports == nullptr)
    {
        free(new_hosts);
        free(new_ports);
        return false;
    }

    pthread_rwlock_wrlock(&rules_lock);
    PROCESS_RULE * rule = rules_list;
    while (rule != nullptr)
    {
        if (rule->rule_id == rule_id)
        {
            strncpy(rule->process_name, process_name, MAX_PROCESS_NAME - 1);
            rule->process_name[MAX_PROCESS_NAME - 1] = '\0';

            free(rule->target_hosts);
            rule->target_hosts = new_hosts;

            free(rule->target_ports);
            rule->target_ports = new_ports;

            rule->protocol = protocol;
            rule->action = action;

            update_has_active_rules();
            pthread_rwlock_unlock(&rules_lock);
            log_message("updated rule id %u", rule_id);
            return true;
        }
        rule = rule->next;
    }
    pthread_rwlock_unlock(&rules_lock);

    // Rule not found - free pre-allocated strings
    free(new_hosts);
    free(new_ports);
    return false;
}

bool set_proxy_config(ProxyType type, const char * proxy_ip, uint16_t proxy_port, const char * username, const char * password)
{
    if (proxy_ip == nullptr || proxy_ip[0] == '\0' || proxy_port == 0)
        return false;

    if (!resolve_endpoint(proxy_ip, proxy_port, SOCK_STREAM, &g_proxy_addr, &g_proxy_addr_len))
        return false;

    strncpy(g_proxy_host, proxy_ip, sizeof(g_proxy_host) - 1);
    g_proxy_host[sizeof(g_proxy_host) - 1] = '\0';
    g_proxy_port = proxy_port;
    g_proxy_type = (type == ProxyType::HTTP) ? ProxyType::HTTP : ProxyType::SOCKS5;

    if (username != nullptr)
    {
        strncpy(g_proxy_username, username, sizeof(g_proxy_username) - 1);
        g_proxy_username[sizeof(g_proxy_username) - 1] = '\0';
    }
    else
    {
        g_proxy_username[0] = '\0';
    }

    if (password != nullptr)
    {
        strncpy(g_proxy_password, password, sizeof(g_proxy_password) - 1);
        g_proxy_password[sizeof(g_proxy_password) - 1] = '\0';
    }
    else
    {
        g_proxy_password[0] = '\0';
    }

    log_message("proxy configured %s %s:%d", type == ProxyType::HTTP ? "http" : "socks5", proxy_ip, proxy_port);
    return true;
}

bool set_dns_nameserver(const char* nameserver)
{
    if (nameserver == nullptr || nameserver[0] == '\0')
    {
        // Load default from /etc/resolv.conf first nameserver line.
        FILE* fp = fopen("/etc/resolv.conf", "r");
        if (fp)
        {
            char line[512];
            while (fgets(line, sizeof(line), fp))
            {
                char server[256];
                if (sscanf(line, "nameserver %255s", server) == 1)
                {
                    if (resolve_endpoint(server, 53, SOCK_DGRAM, &g_dns_nameserver_addr, &g_dns_nameserver_addr_len))
                    {
                        snprintf(g_dns_nameserver, sizeof(g_dns_nameserver), "%s", server);
                        fclose(fp);
                        log_message("dns nameserver loaded from resolv.conf: %s", server);
                        return true;
                    }
                }
            }
            fclose(fp);
        }
        return false;
    }

    if (!resolve_endpoint(nameserver, 53, SOCK_DGRAM, &g_dns_nameserver_addr, &g_dns_nameserver_addr_len))
        return false;

    snprintf(g_dns_nameserver, sizeof(g_dns_nameserver), "%s", nameserver);
    log_message("dns nameserver configured: %s", nameserver);
    return true;
}

bool set_fake_ip_pools(const char* ipv4_pool, const char* ipv6_pool)
{
    const char* v4 = (ipv4_pool != nullptr && ipv4_pool[0] != '\0') ? ipv4_pool : FakeIPStore::DEFAULT_IPV4_POOL;
    const char* v6 = (ipv6_pool != nullptr && ipv6_pool[0] != '\0') ? ipv6_pool : FakeIPStore::DEFAULT_IPV6_POOL;

    if (!g_fake_ip_store.set_ipv4_pool(v4))
        return false;
    if (!g_fake_ip_store.set_ipv6_pool(v6))
        return false;

    log_message("fake-ip pools: %s, %s", v4, v6);
    return true;
}

void set_log_callback(LogCallback callback)
{
    g_log_callback = callback;
}

void set_connection_callback(ConnectionCallback callback)
{
    g_connection_callback = callback;
}

void set_traffic_logging_enabled(bool enable)
{
    g_traffic_logging_enabled = enable;
}

void clear_connection_logs(void)
{
    clear_logged_connections();
}

static void cleanup_firewall_rules(void)
{
    // mangle cleanup
    run_iptables_cmd("-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT");
    run_iptables_cmd("-t", "mangle", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT");
    run_iptables_cmd("-t", "mangle", "-D", "OUTPUT", "-m", "mark", "--mark", "0xFF", "-j", "ACCEPT");
    run_iptables_cmd("-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "-j", "NFQUEUE", "--queue-num", "0");
    run_iptables_cmd("-t", "mangle", "-D", "OUTPUT", "-p", "udp", "-j", "NFQUEUE", "--queue-num", "0");

    // nat cleanup
    run_iptables_cmd("-t", "nat", "-D", "OUTPUT", "-m", "mark", "--mark", "0xFF", "-j", "RETURN");
    run_iptables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "34053");
    run_iptables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", "34053");
    run_iptables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "mark", "--mark", "1", "-j", "REDIRECT", "--to-port", "34010");
    run_iptables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "udp", "-m", "mark", "--mark", "2", "-j", "REDIRECT", "--to-port", "34011");
    run_iptables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "mark", "--mark", "3", "-j", "REDIRECT", "--to-port", "34010");
    run_iptables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "udp", "-m", "mark", "--mark", "4", "-j", "REDIRECT", "--to-port", "34011");

    // IPv6
    run_ip6tables_cmd("-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT");
    run_ip6tables_cmd("-t", "mangle", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT");
    run_ip6tables_cmd("-t", "mangle", "-D", "OUTPUT", "-m", "mark", "--mark", "0xFF", "-j", "ACCEPT");
    run_ip6tables_cmd("-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "-j", "NFQUEUE", "--queue-num", "0");
    run_ip6tables_cmd("-t", "mangle", "-D", "OUTPUT", "-p", "udp", "-j", "NFQUEUE", "--queue-num", "0");

    run_ip6tables_cmd("-t", "nat", "-D", "OUTPUT", "-m", "mark", "--mark", "0xFF", "-j", "RETURN");
    run_ip6tables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "34053");
    run_ip6tables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", "34053");
    run_ip6tables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "mark", "--mark", "1", "-j", "REDIRECT", "--to-port", "34010");
    run_ip6tables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "udp", "-m", "mark", "--mark", "2", "-j", "REDIRECT", "--to-port", "34011");
    run_ip6tables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "mark", "--mark", "3", "-j", "REDIRECT", "--to-port", "34010");
    run_ip6tables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "udp", "-m", "mark", "--mark", "4", "-j", "REDIRECT", "--to-port", "34011");
}

bool start(void)
{
    if (running)
        return false;

    running = true;
    g_current_process_id = getpid();

    if (!g_fake_ip_store.has_pools())
        set_fake_ip_pools(nullptr, nullptr);

    if (g_dns_nameserver[0] == '\0')
        set_dns_nameserver(nullptr);

    g_dns_proxy = new DNSProxy(g_fake_ip_store, g_dns_nameserver_addr, g_dns_nameserver_addr_len, g_current_process_id);
    if (!g_dns_proxy->start(LOCAL_DNS_PROXY_PORT))
    {
        log_message("failed to start dns proxy");
        delete g_dns_proxy;
        g_dns_proxy = nullptr;
        running = false;
        return false;
    }

    // Ignore SIGPIPE - send() on a closed socket must return EPIPE, not kill the process
    signal(SIGPIPE, SIG_IGN);

    // Raise system socket buffer limits for high throughput (requires root)
    // Default rmem_max/wmem_max is usually 208KB, far too small for >100Mbps
    FILE * fp;
    fp = fopen("/proc/sys/net/core/rmem_max", "w");
    if (fp)
    {
        fprintf(fp, "4194304");
        fclose(fp);
    } // 4MB
    fp = fopen("/proc/sys/net/core/wmem_max", "w");
    if (fp)
    {
        fprintf(fp, "4194304");
        fclose(fp);
    } // 4MB

    if (pthread_create(&proxy_thread, nullptr, local_proxy_server, nullptr) != 0)
    {
        running = false;
        return false;
    }

    if (pthread_create(&cleanup_thread, nullptr, cleanup_worker, nullptr) != 0)
    {
        running = false;
        pthread_cancel(proxy_thread);
        pthread_join(proxy_thread, nullptr);
        proxy_thread = 0;
        return false;
    }

    // Start UDP relay server if SOCKS5 proxy
    if (g_proxy_type == ProxyType::SOCKS5)
    {
        if (pthread_create(&udp_relay_thread, nullptr, udp_relay_server, nullptr) != 0)
        {
            log_message("failed to create UDP relay thread");
        }
    }



    nfq_h = nfq_open();
    if (!nfq_h)
    {
        log_message("nfq_open failed");
        goto start_fail;
    }

    if (nfq_unbind_pf(nfq_h, AF_INET) < 0)
    {
        log_message("nfq_unbind_pf failed");
    }

    if (nfq_bind_pf(nfq_h, AF_INET) < 0)
    {
        log_message("nfq_bind_pf failed");
        nfq_close(nfq_h);
        nfq_h = nullptr;
        goto start_fail;
    }
    if (nfq_unbind_pf(nfq_h, AF_INET6) < 0)
    {
        log_message("nfq_unbind_pf(AF_INET6) failed");
    }
    if (nfq_bind_pf(nfq_h, AF_INET6) < 0)
    {
        log_message("nfq_bind_pf(AF_INET6) failed");
    }

    nfq_qh = nfq_create_queue(nfq_h, 0, &packet_callback, nullptr);
    if (!nfq_qh)
    {
        log_message("nfq_create_queue failed");
        nfq_close(nfq_h);
        nfq_h = nullptr;
        goto start_fail;
    }

    if (nfq_set_mode(nfq_qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        log_message("nfq_set_mode failed");
        nfq_destroy_queue(nfq_qh);
        nfq_qh = nullptr;
        nfq_close(nfq_h);
        nfq_h = nullptr;
        goto start_fail;
    }

    // Set larger queue length for better performance (16384 like Windows)
    nfq_set_queue_maxlen(nfq_qh, 16384);

    // setup iptables rules for packet interception - USE MANGLE table so it runs BEFORE nat
    log_message("setting up iptables rules");
    // DNS traffic (port 53) is passed to the local DNS proxy directly, no NFQUEUE decision.
    // Mark 0xFF traffic is the proxy's own DNS forwarder and must bypass NFQUEUE.
    run_iptables_cmd("-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT");
    run_iptables_cmd("-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT");
    run_iptables_cmd("-t", "mangle", "-A", "OUTPUT", "-m", "mark", "--mark", "0xFF", "-j", "ACCEPT");
    run_iptables_cmd("-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "-j", "NFQUEUE", "--queue-num", "0");
    run_iptables_cmd("-t", "mangle", "-A", "OUTPUT", "-p", "udp", "-j", "NFQUEUE", "--queue-num", "0");

    // nat redirect: proxy's own marked traffic is not redirected; then DNS, then proxy/fake-ip marks.
    run_iptables_cmd("-t", "nat", "-A", "OUTPUT", "-m", "mark", "--mark", "0xFF", "-j", "RETURN");
    run_iptables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "34053");
    run_iptables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", "34053");
    run_iptables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-m", "mark", "--mark", "1", "-j", "REDIRECT", "--to-port", "34010");
    run_iptables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "udp", "-m", "mark", "--mark", "2", "-j", "REDIRECT", "--to-port", "34011");
    run_iptables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-m", "mark", "--mark", "3", "-j", "REDIRECT", "--to-port", "34010");
    run_iptables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "udp", "-m", "mark", "--mark", "4", "-j", "REDIRECT", "--to-port", "34011");

    // IPv6
    run_ip6tables_cmd("-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT");
    run_ip6tables_cmd("-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT");
    run_ip6tables_cmd("-t", "mangle", "-A", "OUTPUT", "-m", "mark", "--mark", "0xFF", "-j", "ACCEPT");
    run_ip6tables_cmd("-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "-j", "NFQUEUE", "--queue-num", "0");
    run_ip6tables_cmd("-t", "mangle", "-A", "OUTPUT", "-p", "udp", "-j", "NFQUEUE", "--queue-num", "0");

    run_ip6tables_cmd("-t", "nat", "-A", "OUTPUT", "-m", "mark", "--mark", "0xFF", "-j", "RETURN");
    run_ip6tables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "34053");
    run_ip6tables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", "34053");
    run_ip6tables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-m", "mark", "--mark", "1", "-j", "REDIRECT", "--to-port", "34010");
    run_ip6tables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "udp", "-m", "mark", "--mark", "2", "-j", "REDIRECT", "--to-port", "34011");
    run_ip6tables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-m", "mark", "--mark", "3", "-j", "REDIRECT", "--to-port", "34010");
    run_ip6tables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "udp", "-m", "mark", "--mark", "4", "-j", "REDIRECT", "--to-port", "34011");

    for (int i = 0; i < NUM_PACKET_THREADS; i++)
    {
        if (pthread_create(&packet_thread[i], nullptr, packet_processor, nullptr) != 0)
        {
            log_message("failed to create packet thread %d", i);
        }
    }

    log_message("proxyprism started");
    return true;

start_fail:
    running = false;
    cleanup_firewall_rules();
    if (proxy_thread != 0)
    {
        pthread_cancel(proxy_thread);
        pthread_join(proxy_thread, nullptr);
        proxy_thread = 0;
    }
    if (cleanup_thread != 0)
    {
        pthread_cancel(cleanup_thread);
        pthread_join(cleanup_thread, nullptr);
        cleanup_thread = 0;
    }
    if (udp_relay_thread != 0)
    {
        pthread_cancel(udp_relay_thread);
        pthread_join(udp_relay_thread, nullptr);
        udp_relay_thread = 0;
    }
    if (g_dns_proxy != nullptr)
    {
        g_dns_proxy->stop();
        delete g_dns_proxy;
        g_dns_proxy = nullptr;
    }
    return false;
}

bool stop(void)
{
    if (!running)
    {
        cleanup_firewall_rules();
        return false;
    }

    running = false;

    cleanup_firewall_rules();

    for (int i = 0; i < NUM_PACKET_THREADS; i++)
    {
        if (packet_thread[i] != 0)
        {
            pthread_cancel(packet_thread[i]);
            pthread_join(packet_thread[i], nullptr);
            packet_thread[i] = 0;
        }
    }

    if (nfq_qh)
    {
        nfq_destroy_queue(nfq_qh);
        nfq_qh = nullptr;
    }

    if (nfq_h)
    {
        nfq_close(nfq_h);
        nfq_h = nullptr;
    }

    if (proxy_thread != 0)
    {
        pthread_cancel(proxy_thread);
        pthread_join(proxy_thread, nullptr);
        proxy_thread = 0;
    }

    if (udp_relay_thread != 0)
    {
        pthread_cancel(udp_relay_thread);
        pthread_join(udp_relay_thread, nullptr);
        udp_relay_thread = 0;
    }

    if (cleanup_thread != 0)
    {
        pthread_cancel(cleanup_thread);
        pthread_join(cleanup_thread, nullptr);
        cleanup_thread = 0;
    }

    if (g_dns_proxy != nullptr)
    {
        g_dns_proxy->stop();
        delete g_dns_proxy;
        g_dns_proxy = nullptr;
    }

    g_fake_ip_store.clear();

    // Free all connections in hash table
    pthread_rwlock_wrlock(&conn_lock);
    for (int i = 0; i < CONNECTION_HASH_SIZE; i++)
    {
        while (connection_hash_table[i] != nullptr)
        {
            CONNECTION_INFO * to_free = connection_hash_table[i];
            connection_hash_table[i] = connection_hash_table[i]->next;
            delete to_free;
        }
    }
    pthread_rwlock_unlock(&conn_lock);

    // Free all rules
    pthread_rwlock_wrlock(&rules_lock);
    while (rules_list != nullptr)
    {
        PROCESS_RULE * to_free = rules_list;
        rules_list = rules_list->next;
        free(to_free->target_hosts);
        free(to_free->target_ports);
        free(to_free);
    }
    g_has_active_rules = false;
    g_next_rule_id = 1;
    pthread_rwlock_unlock(&rules_lock);

    clear_logged_connections();
    clear_pid_cache();

    log_message("proxyprism stopped");
    return true;
}

int test_connection(const char * target_host, uint16_t target_port, char * result_buffer, size_t buffer_size)
{
    int test_sock = -1;
    struct sockaddr_storage target_addr;
    socklen_t target_addr_len = 0;
    NetworkAddress target_ip;
    int ret = -1;
    char temp_buffer[512];

    if (g_proxy_host[0] == '\0' || g_proxy_port == 0)
    {
        snprintf(result_buffer, buffer_size, "error no proxy configured");
        return -1;
    }

    if (target_host == nullptr || target_host[0] == '\0')
    {
        snprintf(result_buffer, buffer_size, "error invalid target host");
        return -1;
    }

    snprintf(
        temp_buffer,
        sizeof(temp_buffer),
        "testing connection to %s:%d via %s proxy %s:%d\n",
        target_host,
        target_port,
        g_proxy_type == ProxyType::HTTP ? "http" : "socks5",
        g_proxy_host,
        g_proxy_port);
    strncpy(result_buffer, temp_buffer, buffer_size - 1);
    result_buffer[buffer_size - 1] = '\0';

    if (!resolve_endpoint(target_host, target_port, SOCK_STREAM, &target_addr, &target_addr_len))
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "error failed to resolve hostname %s\n", target_host);
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        return -1;
    }
    target_ip = network_address_from_sockaddr((const struct sockaddr*)&target_addr);

    char target_ip_text[INET6_ADDRSTRLEN];
    format_network_address(target_ip, target_ip_text, sizeof(target_ip_text));
    snprintf(temp_buffer, sizeof(temp_buffer), "resolved %s to %s\n", target_host, target_ip_text);
    strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);

    test_sock = socket(g_proxy_addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (test_sock < 0)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "error socket creation failed\n");
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        return -1;
    }

    configure_tcp_socket(test_sock, 65536, 10000);

    snprintf(temp_buffer, sizeof(temp_buffer), "connecting to proxy %s:%d\n", g_proxy_host, g_proxy_port);
    strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);

    if (connect(test_sock, (struct sockaddr *)&g_proxy_addr, g_proxy_addr_len) < 0)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "error failed to connect to proxy\n");
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        close(test_sock);
        return -1;
    }

    strncat(result_buffer, "connected to proxy server\n", buffer_size - strlen(result_buffer) - 1);

    if (g_proxy_type == ProxyType::SOCKS5)
    {
        if (socks5_connect(test_sock, target_ip, target_port, target_host) != 0)
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "error socks5 handshake failed\n");
            strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
            close(test_sock);
            return -1;
        }
        strncat(result_buffer, "socks5 handshake successful\n", buffer_size - strlen(result_buffer) - 1);
    }
    else
    {
        if (http_connect(test_sock, target_ip, target_port, target_host) != 0)
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "error http connect failed\n");
            strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
            close(test_sock);
            return -1;
        }
        strncat(result_buffer, "http connect successful\n", buffer_size - strlen(result_buffer) - 1);
    }

    char host_header[INET6_ADDRSTRLEN + 3];
    if (target_ip.family == AddressFamily::IPv6)
        snprintf(host_header, sizeof(host_header), "[%s]", target_host);
    else
        snprintf(host_header, sizeof(host_header), "%s", target_host);

    char http_request[512];
    snprintf(
        http_request,
        sizeof(http_request),
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: ProxyPrism/0.1.0\r\n"
        "\r\n",
        host_header);

    if (send_all(test_sock, http_request, strlen(http_request)) < 0)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "error failed to send test request\n");
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        close(test_sock);
        return -1;
    }

    strncat(result_buffer, "sent http get request\n", buffer_size - strlen(result_buffer) - 1);
    char response[1024];
    ssize_t bytes_received = recv(test_sock, response, sizeof(response) - 1, 0);
    if (bytes_received > 0)
    {
        response[bytes_received] = '\0';

        if (strstr(response, "HTTP/") != nullptr)
        {
            char * status_line = strstr(response, "HTTP/");
            int status_code = 0;
            if (status_line != nullptr)
            {
                sscanf(status_line, "HTTP/%*s %d", &status_code);
            }

            snprintf(temp_buffer, sizeof(temp_buffer), "success received http %d response %ld bytes\n", status_code, (long)bytes_received);
            strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
            ret = 0;
        }
        else
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "error received data but not valid http response\n");
            strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
            ret = -1;
        }
    }
    else
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "error failed to receive response\n");
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        ret = -1;
    }

    close(test_sock);

    if (ret == 0)
    {
        strncat(result_buffer, "\nproxy connection test passed\n", buffer_size - strlen(result_buffer) - 1);
    }
    else
    {
        strncat(result_buffer, "\nproxy connection test failed\n", buffer_size - strlen(result_buffer) - 1);
    }

    return ret;
}

// Library destructor - automatically cleanup when library is unloaded
__attribute__((destructor)) static void library_cleanup(void)
{
    if (running)
    {
        log_message("library unloading - cleaning up automatically");
        stop();
    }
}

} // namespace proxyprism
