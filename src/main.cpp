#include <cctype>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include "ProxyPrism.h"
#include "NetworkAddress.h"
#include "tomlc17.h"

using namespace proxyprism;

constexpr int MAX_RULES = 100;
constexpr const char* DEFAULT_CONFIG_PATH = "/etc/proxyprism.conf";

struct ProxyRule
{
    char process_name[256];
    char target_hosts[256];
    char target_ports[256];
    RuleProtocol protocol;
    RuleAction action;
};

static volatile bool keep_running = false;
static int verbose_level = 0;

static void log_callback(const char * message)
{
    if (verbose_level == 1 || verbose_level == 3)
    {
        printf("[LOG] %s\n", message);
    }
}

static void connection_callback(const char * process_name, uint32_t pid, const char * dest_ip, uint16_t dest_port, const char * proxy_info)
{
    if (verbose_level == 2 || verbose_level == 3)
    {
        printf("[CONN] %s (PID:%u) -> %s:%u via %s\n", process_name, pid, dest_ip, dest_port, proxy_info);
    }
}

static void signal_handler(int sig)
{
    if (sig == SIGSEGV || sig == SIGABRT || sig == SIGBUS)
    {
        printf("\n\n=== CLI CRASH DETECTED ===\n");
        printf("Signal: %d (%s)\n", sig, sig == SIGSEGV ? "SEGFAULT" : sig == SIGABRT ? "ABORT" : "BUS ERROR");
        printf("Calling emergency cleanup...\n");
        stop();
        _exit(1);
    }

    if (keep_running)
    {
        printf("\n\nStopping ProxyPrism...\n");
        keep_running = false;
    }
}

static void show_banner(void)
{
    printf("\n");
    printf("  ProxyPrism  v0.1.0\n");
    printf("  Rule-based transparent proxy routing for Linux\n");
    printf("\n");
}

static void show_help(const char * prog)
{
    show_banner();
    printf("USAGE:\n");
    printf("  %s [OPTIONS]\n\n", prog);

    printf("OPTIONS:\n");
    printf("  --config <path>        Path to TOML configuration file\n");
    printf("                         Default: %s\n\n", DEFAULT_CONFIG_PATH);

    printf("  --check-config         Load and validate the configuration file, then exit\n");
    printf("                         without starting ProxyPrism or touching iptables\n\n");

    printf("  --cleanup              Cleanup resources (iptables, etc.) from crashed instance\n");
    printf("                         Use if ProxyPrism crashed without proper cleanup\n\n");

    printf("  --help, -h             Show this help message\n\n");

    printf("CONFIGURATION:\n");
    printf("  Proxy server, rules, and logging are set in the TOML file.\n");
    printf("  See proxyprism.conf.example for the format and examples.\n\n");

    printf("EXAMPLES:\n");
    printf("  # Validate the configuration\n");
    printf("  sudo %s --check-config\n\n", prog);

    printf("  # Run with the default config (/etc/proxyprism.conf)\n");
    printf("  sudo %s\n\n", prog);

    printf("  # Run with a custom configuration file\n");
    printf("  sudo %s --config /path/to/your.conf\n\n", prog);

    printf("NOTE:\n");
    printf("  ProxyPrism requires root privileges to use nfqueue.\n");
    printf("  Run with 'sudo' or as root user.\n\n");
}

static RuleProtocol parse_protocol(const char * str, int rule_index)
{
    char upper[16];
    for (size_t i = 0; str[i] && i < 15; i++)
        upper[i] = toupper(str[i]);
    upper[strlen(str) < 15 ? strlen(str) : 15] = '\0';

    if (strcmp(upper, "TCP") == 0)
        return RuleProtocol::TCP;
    else if (strcmp(upper, "UDP") == 0)
        return RuleProtocol::UDP;
    else if (strcmp(upper, "BOTH") == 0)
        return RuleProtocol::BOTH;
    else
    {
        fprintf(stderr, "ERROR: Config rule %d: invalid protocol '%s'. Use TCP, UDP, or BOTH\n", rule_index, str);
        exit(1);
    }
}

static RuleAction parse_action(const char * str, int rule_index)
{
    char upper[16];
    for (size_t i = 0; str[i] && i < 15; i++)
        upper[i] = toupper(str[i]);
    upper[strlen(str) < 15 ? strlen(str) : 15] = '\0';

    if (strcmp(upper, "PROXY") == 0)
        return RuleAction::PROXY;
    else if (strcmp(upper, "DIRECT") == 0)
        return RuleAction::DIRECT;
    else if (strcmp(upper, "BLOCK") == 0)
        return RuleAction::BLOCK;
    else
    {
        fprintf(stderr, "ERROR: Config rule %d: invalid action '%s'. Use PROXY, DIRECT, or BLOCK\n", rule_index, str);
        exit(1);
    }
}

static void default_if_empty(char * dest, const char * src, const char * default_val, size_t dest_size)
{
    if (src == dest)
    {
        if (dest[0] == '\0' || strcmp(dest, " ") == 0)
        {
            strncpy(dest, default_val, dest_size - 1);
            dest[dest_size - 1] = '\0';
        }
        return;
    }

    if (src == nullptr || src[0] == '\0' || strcmp(src, " ") == 0)
        strncpy(dest, default_val, dest_size - 1);
    else
        strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

static bool parse_proxy_url(const char * url, ProxyType * type, char * host, uint16_t * port, char * username, char * password)
{
    char buffer[512];
    strncpy(buffer, url, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    username[0] = '\0';
    password[0] = '\0';

    // parse type://
    char * scheme_end = strstr(buffer, "://");
    if (scheme_end == nullptr)
    {
        fprintf(stderr, "ERROR: Invalid proxy URL format. Expected type://host:port\n");
        return false;
    }

    *scheme_end = '\0';
    char * scheme = buffer;
    char * rest = scheme_end + 3;

    char upper_scheme[16];
    for (size_t i = 0; scheme[i] && i < 15; i++)
        upper_scheme[i] = toupper(scheme[i]);
    upper_scheme[strlen(scheme) < 15 ? strlen(scheme) : 15] = '\0';

    if (strcmp(upper_scheme, "SOCKS5") == 0)
        *type = ProxyType::SOCKS5;
    else if (strcmp(upper_scheme, "HTTP") == 0)
        *type = ProxyType::HTTP;
    else
    {
        fprintf(stderr, "ERROR: Invalid proxy type '%s'. Use 'socks5' or 'http'\n", scheme);
        return false;
    }

    // Parse host:port[:user:pass]. IPv6 hosts must be bracketed so ':'
    // remains available as the field separator.
    char* port_text = nullptr;
    if (rest[0] == '[')
    {
        char* closing_bracket = strchr(rest, ']');
        if (closing_bracket == nullptr || closing_bracket[1] != ':')
        {
            fprintf(stderr, "ERROR: IPv6 proxy URL must use [address]:port\n");
            return false;
        }
        *closing_bracket = '\0';
        strncpy(host, rest + 1, 255);
        host[255] = '\0';
        port_text = closing_bracket + 2;
    }
    else
    {
        char* port_separator = strchr(rest, ':');
        if (port_separator == nullptr)
        {
            fprintf(stderr, "ERROR: Invalid proxy URL. Missing host or port\n");
            return false;
        }
        *port_separator = '\0';
        strncpy(host, rest, 255);
        host[255] = '\0';
        port_text = port_separator + 1;
    }

    char* auth_separator = strchr(port_text, ':');
    if (auth_separator != nullptr)
        *auth_separator = '\0';

    if (host[0] == '\0' || port_text[0] == '\0')
    {
        fprintf(stderr, "ERROR: Invalid proxy URL. Missing host or port\n");
        return false;
    }

    *port = atoi(port_text);
    if (*port == 0)
    {
        fprintf(stderr, "ERROR: Invalid proxy port '%s'\n", port_text);
        return false;
    }

    if (auth_separator != nullptr)
    {
        char* password_separator = strchr(auth_separator + 1, ':');
        if (password_separator == nullptr)
        {
            fprintf(stderr, "ERROR: Proxy credentials require username and password\n");
            return false;
        }
        *password_separator = '\0';
        strncpy(username, auth_separator + 1, 255);
        username[255] = '\0';
        strncpy(password, password_separator + 1, 255);
        password[255] = '\0';
    }

    return true;
}

static bool is_root(void)
{
    return getuid() == 0;
}

// ── TOML config helpers ─────────────────────────────────────────────────────

static bool toml_get_bool(toml_datum_t table, const char * key, bool * out)
{
    toml_datum_t d = toml_get(table, key);
    if (d.type != TOML_BOOLEAN)
        return false;
    *out = d.u.boolean;
    return true;
}

static const char * toml_string_ptr(toml_datum_t d)
{
    if (d.type != TOML_STRING)
        return nullptr;
    if (d.u.s != nullptr)
        return d.u.s;
    if (d.u.str.ptr != nullptr)
        return d.u.str.ptr;
    return nullptr;
}

static bool join_array_to_string(toml_datum_t arr, char * out, size_t out_size, char sep)
{
    if (arr.type != TOML_ARRAY)
        return false;

    out[0] = '\0';
    size_t pos = 0;

    for (int i = 0; i < arr.u.arr.size; i++)
    {
        toml_datum_t elem = arr.u.arr.elem[i];
        const char * s = toml_string_ptr(elem);
        if (s == nullptr)
            continue;

        if (i > 0)
        {
            if (pos + 1 >= out_size)
                break;
            out[pos++] = sep;
            out[pos] = '\0';
        }

        size_t len = strlen(s);
        if (pos + len >= out_size)
        {
            size_t avail = out_size - pos - 1;
            if (avail > 0)
            {
                memcpy(out + pos, s, avail);
                pos += avail;
                out[pos] = '\0';
            }
            break;
        }

        memcpy(out + pos, s, len);
        pos += len;
        out[pos] = '\0';
    }

    return true;
}

static void get_rule_field(toml_datum_t rule, const char * key, char * out, size_t out_size, const char * default_val)
{
    toml_datum_t d = toml_get(rule, key);
    if (d.type == TOML_STRING)
    {
        const char * s = toml_string_ptr(d);
        if (s == nullptr)
            s = "";
        default_if_empty(out, s, default_val, out_size);
    }
    else if (d.type == TOML_ARRAY)
    {
        if (join_array_to_string(d, out, out_size, ';'))
            default_if_empty(out, out, default_val, out_size);
        else
            default_if_empty(out, "", default_val, out_size);
    }
    else
    {
        default_if_empty(out, "", default_val, out_size);
    }
}

static bool load_config(
    const char * path,
    char * proxy_url,
    size_t proxy_url_size,
    int * verbose_level,
    ProxyRule * rules,
    int * num_rules,
    int max_rules)
{
    toml_result_t result = toml_parse_file_ex(path);
    if (!result.ok)
    {
        fprintf(stderr, "ERROR: Failed to parse config '%s': %s\n", path, result.errmsg);
        return false;
    }

    toml_datum_t top = result.toptab;

    toml_datum_t proxy = toml_seek(top, "proxy.url");
    if (proxy.type == TOML_STRING)
    {
        const char * s = toml_string_ptr(proxy);
        if (s != nullptr && s[0] != '\0')
        {
            strncpy(proxy_url, s, proxy_url_size - 1);
            proxy_url[proxy_url_size - 1] = '\0';
        }
    }

    toml_datum_t verbose = toml_seek(top, "options.verbose");
    if (verbose.type == TOML_INT64)
    {
        int v = (int)verbose.u.int64;
        if (v < 0 || v > 3)
        {
            fprintf(stderr, "ERROR: Config verbose must be between 0 and 3\n");
            toml_free(result);
            return false;
        }
        *verbose_level = v;
    }

    toml_datum_t rules_arr = toml_seek(top, "rules");
    if (rules_arr.type == TOML_ARRAY)
    {
        for (int i = 0; i < rules_arr.u.arr.size; i++)
        {
            toml_datum_t rule = rules_arr.u.arr.elem[i];
            if (rule.type != TOML_TABLE)
                continue;

            bool enabled = true;
            toml_get_bool(rule, "enabled", &enabled);
            if (!enabled)
                continue;

            if (*num_rules >= max_rules)
            {
                fprintf(stderr, "ERROR: Config has more than %d enabled rules\n", max_rules);
                toml_free(result);
                return false;
            }

            ProxyRule * r = &rules[*num_rules];
            int rule_index = *num_rules + 1;

            get_rule_field(rule, "process", r->process_name, sizeof(r->process_name), "*");
            get_rule_field(rule, "hosts", r->target_hosts, sizeof(r->target_hosts), "*");
            get_rule_field(rule, "ports", r->target_ports, sizeof(r->target_ports), "*");

            std::string rule_error;
            if (!validate_host_list(r->target_hosts, &rule_error))
            {
                fprintf(stderr, "ERROR: Config rule %d: invalid hosts: %s\n", rule_index, rule_error.c_str());
                toml_free(result);
                return false;
            }
            if (!validate_port_list(r->target_ports, &rule_error))
            {
                fprintf(stderr, "ERROR: Config rule %d: invalid ports: %s\n", rule_index, rule_error.c_str());
                toml_free(result);
                return false;
            }

            char protocol[16];
            char action[16];
            get_rule_field(rule, "protocol", protocol, sizeof(protocol), "TCP");
            get_rule_field(rule, "action", action, sizeof(action), "PROXY");

            r->protocol = parse_protocol(protocol, rule_index);
            r->action = parse_action(action, rule_index);

            (*num_rules)++;
        }
    }

    toml_free(result);
    return true;
}

int main(int argc, char * argv[])
{
    const char * config_path = DEFAULT_CONFIG_PATH;
    bool check_config = false;

    // Single pass: handle immediate actions and parse options
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--cleanup") == 0)
        {
            printf("Running cleanup...\n");
            stop();
            printf("Cleanup complete.\n");
            return 0;
        }

        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            show_help(argv[0]);
            return 0;
        }

        if (strcmp(argv[i], "--config") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "ERROR: --config requires a path argument\n");
                return 1;
            }
            config_path = argv[++i];
            continue;
        }

        if (strcmp(argv[i], "--check-config") == 0)
        {
            check_config = true;
            continue;
        }

        fprintf(stderr, "ERROR: Unknown option '%s'\n", argv[i]);
        fprintf(stderr, "Use --help for usage information\n");
        return 1;
    }

    char proxy_url[512] = "socks5://127.0.0.1:4444";
    ProxyRule rules[MAX_RULES];
    int num_rules = 0;

    // The configuration file is mandatory
    if (access(config_path, F_OK) == 0)
    {
        if (!load_config(config_path, proxy_url, sizeof(proxy_url), &verbose_level, rules, &num_rules, MAX_RULES))
            return 1;
    }
    else
    {
        fprintf(stderr, "ERROR: Config file not found: %s\n", config_path);
        fprintf(stderr, "Create one from proxyprism.conf.example or pass --config <path>\n");
        return 1;
    }

    show_banner();
    printf("Loaded config: %s\n", config_path);

    // parse proxy config
    ProxyType proxy_type;
    char proxy_host[256];
    uint16_t proxy_port;
    char proxy_username[256];
    char proxy_password[256];

    if (!parse_proxy_url(proxy_url, &proxy_type, proxy_host, &proxy_port, proxy_username, proxy_password))
        return 1;

    // If --check-config was requested, print the parsed config and exit
    // without touching iptables, nfqueue, or the network.
    if (check_config)
    {
        if (strchr(proxy_host, ':') != nullptr)
            printf("Proxy: %s://[%s]:%u\n", proxy_type == ProxyType::HTTP ? "http" : "socks5", proxy_host, proxy_port);
        else
            printf("Proxy: %s://%s:%u\n", proxy_type == ProxyType::HTTP ? "http" : "socks5", proxy_host, proxy_port);

        if (proxy_username[0] != '\0')
            printf("Proxy Auth: %s:***\n", proxy_username);

        if (num_rules > 0)
        {
            printf("Rules: %d\n", num_rules);
            for (int i = 0; i < num_rules; i++)
            {
                const char * protocol_str = rules[i].protocol == RuleProtocol::TCP ? "TCP"
                    : rules[i].protocol == RuleProtocol::UDP                       ? "UDP"
                                                                                   : "BOTH";
                const char * action_str = rules[i].action == RuleAction::PROXY ? "PROXY"
                    : rules[i].action == RuleAction::DIRECT                    ? "DIRECT"
                                                                               : "BLOCK";

                printf(
                    "  [%d] %s:%s:%s:%s -> %s\n",
                    i + 1,
                    rules[i].process_name,
                    rules[i].target_hosts,
                    rules[i].target_ports,
                    protocol_str,
                    action_str);
            }
        }
        else
        {
            printf("WARNING: No rules specified. No traffic will be proxied.\n");
        }

        printf("\nConfig OK.\n");
        return 0;
    }

    // need root before touching nfqueue/iptables
    if (!is_root())
    {
        printf("\033[31m\nERROR: ProxyPrism requires root privileges!\033[0m\n");
        printf("Please run this application with sudo or as root.\n\n");
        return 1;
    }

    // setup callbacks based on verbose
    // 0=nothing 1=logs 2=connections 3=both

    if (verbose_level == 1 || verbose_level == 3)
        set_log_callback(log_callback);
    else
        set_log_callback(nullptr); // Explicitly disable

    if (verbose_level == 2 || verbose_level == 3)
        set_connection_callback(connection_callback);
    else
        set_connection_callback(nullptr); // Explicitly disable

    // turn on traffic logging when needed
    set_traffic_logging_enabled(verbose_level > 0);

    // show config
    if (strchr(proxy_host, ':') != nullptr)
        printf("Proxy: %s://[%s]:%u\n", proxy_type == ProxyType::HTTP ? "http" : "socks5", proxy_host, proxy_port);
    else
        printf("Proxy: %s://%s:%u\n", proxy_type == ProxyType::HTTP ? "http" : "socks5", proxy_host, proxy_port);

    if (proxy_username[0] != '\0')
        printf("Proxy Auth: %s:***\n", proxy_username);

    // setup proxy
    if (!set_proxy_config(
            proxy_type, proxy_host, proxy_port, proxy_username[0] ? proxy_username : "", proxy_password[0] ? proxy_password : ""))
    {
        fprintf(stderr, "ERROR: Failed to set proxy configuration\n");
        return 1;
    }

    // add rules
    if (num_rules > 0)
    {
        printf("Rules: %d\n", num_rules);
        for (int i = 0; i < num_rules; i++)
        {
            const char * protocol_str = rules[i].protocol == RuleProtocol::TCP ? "TCP"
                : rules[i].protocol == RuleProtocol::UDP                       ? "UDP"
                                                                               : "BOTH";
            const char * action_str = rules[i].action == RuleAction::PROXY ? "PROXY"
                : rules[i].action == RuleAction::DIRECT                    ? "DIRECT"
                                                                           : "BLOCK";

            uint32_t rule_id = add_rule(
                rules[i].process_name, rules[i].target_hosts, rules[i].target_ports, rules[i].protocol, rules[i].action);

            if (rule_id > 0)
            {
                printf(
                    "  [%u] %s:%s:%s:%s -> %s\n",
                    rule_id,
                    rules[i].process_name,
                    rules[i].target_hosts,
                    rules[i].target_ports,
                    protocol_str,
                    action_str);
            }
            else
            {
                fprintf(stderr, "  ERROR: Failed to add rule for %s\n", rules[i].process_name);
            }
        }
    }
    else
    {
        printf("\033[33mWARNING: No rules specified. No traffic will be proxied.\033[0m\n");
        printf("Define rules in %s. See proxyprism.conf.example for the format.\n", DEFAULT_CONFIG_PATH);
    }

    // start proxyprism
    if (!start())
    {
        fprintf(stderr, "ERROR: Failed to start ProxyPrism\n");
        return 1;
    }

    keep_running = true;
    printf("\nProxyPrism started. Press Ctrl+C to stop...\n\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler); // Catch segfault
    signal(SIGABRT, signal_handler); // Catch abort
    signal(SIGBUS, signal_handler); // Catch bus error

    // main loop
    while (keep_running)
    {
        sleep(1);
    }

    // cleanup
    stop();
    printf("ProxyPrism stopped.\n");

    return 0;
}
