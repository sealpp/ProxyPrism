#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ProxyPrism.h"
#include "tomlc17.h"

#define MAX_RULES 100
#define MAX_RULE_STR 1024
#define DEFAULT_CONFIG_PATH "/etc/proxyprism.conf"

typedef struct
{
    char process_name[256];
    char target_hosts[256];
    char target_ports[256];
    RuleProtocol protocol;
    RuleAction action;
} ProxyRule;

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
        ProxyPrism_Stop();
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

    printf("  --proxy <url>          Proxy server URL with optional authentication\n");
    printf("                         Format: type://ip:port or type://ip:port:username:password\n");
    printf("                         Examples: socks5://127.0.0.1:1080\n");
    printf("                                   http://proxy.com:8080:myuser:mypass\n");
    printf("                         Default: socks5://127.0.0.1:4444\n\n");

    printf("  --rule <rule>          Traffic routing rule (can be specified multiple times)\n");
    printf("                         Overrides any rules from the config file.\n");
    printf("                         Format: process:hosts:ports:protocol:action\n");
    printf("                           process  - Process name(s): curl, cur*, *, or multiple separated by ;\n");
    printf("                           hosts    - IP/host(s): *, google.com, 192.168.*.*, or multiple separated by ; or ,\n");
    printf("                           ports    - Port(s): *, 443, 80;8080, 80-100, or multiple separated by ; or ,\n");
    printf("                           protocol - TCP, UDP, or BOTH\n");
    printf("                           action   - PROXY, DIRECT, or BLOCK\n");
    printf("                         Examples:\n");
    printf("                           curl:*:*:TCP:PROXY\n");
    printf("                           curl;wget:*:*:TCP:PROXY\n");
    printf("                           *:*:53:UDP:PROXY\n");
    printf("                           firefox:*:80;443:TCP:DIRECT\n\n");

    printf("  --dns-via-proxy <bool> Route DNS queries through proxy\n");
    printf("                         Values: true, false, 1, 0\n");
    printf("                         Default: true\n\n");

    printf("  --verbose <level>      Logging verbosity level\n");
    printf("                           0 - No logs (default)\n");
    printf("                           1 - Show log messages only\n");
    printf("                           2 - Show connection events only\n");
    printf("                           3 - Show both logs and connections\n\n");

    printf("  --check-config         Load and validate the configuration file, then exit\n");
    printf("                         without starting ProxyPrism or touching iptables\n\n");

    printf("  --cleanup              Cleanup resources (iptables, etc.) from crashed instance\n");
    printf("                         Use if ProxyPrism crashed without proper cleanup\n\n");

    printf("  --help, -h             Show this help message\n\n");

    printf("EXAMPLES:\n");
    printf("  # Basic usage with default proxy\n");
    printf("  sudo %s --rule curl:*:*:TCP:PROXY\n\n", prog);

    printf("  # Use a custom configuration file\n");
    printf("  sudo %s --config /etc/proxyprism.conf\n\n", prog);

    printf("  # Multiple rules with custom proxy\n");
    printf("  sudo %s --proxy socks5://192.168.1.10:1080 \\\n", prog);
    printf("       --rule curl:*:*:TCP:PROXY \\\n");
    printf("       --rule wget:*:*:TCP:PROXY \\\n");
    printf("       --verbose 2\n\n");

    printf("  # Route DNS through proxy with multiple apps\n");
    printf("  sudo %s --proxy socks5://127.0.0.1:1080 \\\n", prog);
    printf("       --rule \"curl;wget;firefox:*:*:BOTH:PROXY\" \\\n");
    printf("       --dns-via-proxy true --verbose 3\n\n");

    printf("NOTE:\n");
    printf("  ProxyPrism requires root privileges to use nfqueue.\n");
    printf("  Run with 'sudo' or as root user.\n\n");
}

static RuleProtocol parse_protocol(const char * str)
{
    char upper[16];
    for (size_t i = 0; str[i] && i < 15; i++)
        upper[i] = toupper(str[i]);
    upper[strlen(str) < 15 ? strlen(str) : 15] = '\0';

    if (strcmp(upper, "TCP") == 0)
        return RULE_PROTOCOL_TCP;
    else if (strcmp(upper, "UDP") == 0)
        return RULE_PROTOCOL_UDP;
    else if (strcmp(upper, "BOTH") == 0)
        return RULE_PROTOCOL_BOTH;
    else
    {
        fprintf(stderr, "ERROR: Invalid protocol '%s'. Use TCP, UDP, or BOTH\n", str);
        exit(1);
    }
}

static RuleAction parse_action(const char * str)
{
    char upper[16];
    for (size_t i = 0; str[i] && i < 15; i++)
        upper[i] = toupper(str[i]);
    upper[strlen(str) < 15 ? strlen(str) : 15] = '\0';

    if (strcmp(upper, "PROXY") == 0)
        return RULE_ACTION_PROXY;
    else if (strcmp(upper, "DIRECT") == 0)
        return RULE_ACTION_DIRECT;
    else if (strcmp(upper, "BLOCK") == 0)
        return RULE_ACTION_BLOCK;
    else
    {
        fprintf(stderr, "ERROR: Invalid action '%s'. Use PROXY, DIRECT, or BLOCK\n", str);
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

    if (src == NULL || src[0] == '\0' || strcmp(src, " ") == 0)
        strncpy(dest, default_val, dest_size - 1);
    else
        strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

static bool parse_rule(const char * rule_str, ProxyRule * rule)
{
    char buffer[MAX_RULE_STR];
    strncpy(buffer, rule_str, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char * parts[5] = {NULL, NULL, NULL, NULL, NULL};
    int part_idx = 0;
    char * token = strtok(buffer, ":");

    while (token != NULL && part_idx < 5)
    {
        parts[part_idx++] = token;
        token = strtok(NULL, ":");
    }

    if (part_idx != 5)
    {
        fprintf(stderr, "ERROR: Invalid rule format '%s'\n", rule_str);
        fprintf(stderr, "Expected format: process:hosts:ports:protocol:action\n");
        return false;
    }

    default_if_empty(rule->process_name, parts[0], "*", sizeof(rule->process_name));
    default_if_empty(rule->target_hosts, parts[1], "*", sizeof(rule->target_hosts));
    default_if_empty(rule->target_ports, parts[2], "*", sizeof(rule->target_ports));

    rule->protocol = parse_protocol(parts[3]);
    rule->action = parse_action(parts[4]);

    return true;
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
    if (scheme_end == NULL)
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
        *type = PROXY_TYPE_SOCKS5;
    else if (strcmp(upper_scheme, "HTTP") == 0)
        *type = PROXY_TYPE_HTTP;
    else
    {
        fprintf(stderr, "ERROR: Invalid proxy type '%s'. Use 'socks5' or 'http'\n", scheme);
        return false;
    }

    // parse host:port[:user:pass]
    char * parts[4];
    int num_parts = 0;
    char * token = strtok(rest, ":");
    while (token != NULL && num_parts < 4)
    {
        parts[num_parts++] = token;
        token = strtok(NULL, ":");
    }

    if (num_parts < 2)
    {
        fprintf(stderr, "ERROR: Invalid proxy URL. Missing host or port\n");
        return false;
    }

    strncpy(host, parts[0], 255);
    host[255] = '\0';

    *port = atoi(parts[1]);
    if (*port == 0)
    {
        fprintf(stderr, "ERROR: Invalid proxy port '%s'\n", parts[1]);
        return false;
    }

    if (num_parts >= 4)
    {
        strncpy(username, parts[2], 255);
        username[255] = '\0';
        strncpy(password, parts[3], 255);
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
        return NULL;
    if (d.u.s != NULL)
        return d.u.s;
    if (d.u.str.ptr != NULL)
        return d.u.str.ptr;
    return NULL;
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
        if (s == NULL)
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
        if (s == NULL)
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
    bool * dns_via_proxy,
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
        if (s != NULL && s[0] != '\0')
        {
            strncpy(proxy_url, s, proxy_url_size - 1);
            proxy_url[proxy_url_size - 1] = '\0';
        }
    }

    toml_datum_t dns = toml_seek(top, "options.dns_via_proxy");
    if (dns.type == TOML_BOOLEAN)
        *dns_via_proxy = dns.u.boolean;

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
        for (int i = 0; i < rules_arr.u.arr.size && *num_rules < max_rules; i++)
        {
            toml_datum_t rule = rules_arr.u.arr.elem[i];
            if (rule.type != TOML_TABLE)
                continue;

            bool enabled = true;
            toml_get_bool(rule, "enabled", &enabled);
            if (!enabled)
                continue;

            char process[256];
            char hosts[256];
            char ports[256];
            char protocol[16];
            char action[16];

            get_rule_field(rule, "process", process, sizeof(process), "*");
            get_rule_field(rule, "hosts", hosts, sizeof(hosts), "*");
            get_rule_field(rule, "ports", ports, sizeof(ports), "*");
            get_rule_field(rule, "protocol", protocol, sizeof(protocol), "TCP");
            get_rule_field(rule, "action", action, sizeof(action), "PROXY");

            char rule_str[MAX_RULE_STR];
            snprintf(rule_str, sizeof(rule_str), "%s:%s:%s:%s:%s", process, hosts, ports, protocol, action);

            if (!parse_rule(rule_str, &rules[*num_rules]))
            {
                toml_free(result);
                return false;
            }

            (*num_rules)++;
        }
    }

    toml_free(result);
    return true;
}

int main(int argc, char * argv[])
{
    const char * config_path = DEFAULT_CONFIG_PATH;
    bool config_path_set = false;
    bool check_config = false;

    // First pass: handle cleanup, help, --config and --check-config
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--cleanup") == 0)
        {
            printf("Running cleanup...\n");
            ProxyPrism_Stop();
            printf("Cleanup complete.\n");
            return 0;
        }

        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            show_help(argv[0]);
            return 0;
        }

        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
        {
            config_path = argv[++i];
            config_path_set = true;
        }

        if (strcmp(argv[i], "--check-config") == 0)
        {
            check_config = true;
        }
    }

    char proxy_url[512] = "socks5://127.0.0.1:4444";
    ProxyRule rules[MAX_RULES];
    int num_rules = 0;
    bool dns_via_proxy = true;
    bool rules_overridden = false;

    // Load configuration file if it exists, or if explicitly requested
    if (access(config_path, F_OK) == 0)
    {
        if (!load_config(config_path, proxy_url, sizeof(proxy_url), &dns_via_proxy, &verbose_level, rules, &num_rules, MAX_RULES))
            return 1;
    }
    else if (config_path_set)
    {
        fprintf(stderr, "ERROR: Config file not found: %s\n", config_path);
        return 1;
    }

    // Second pass: process command-line overrides
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            show_help(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "--check-config") == 0)
        {
            // already handled in first pass
        }
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
        {
            i++; // already handled in first pass
        }
        else if (strcmp(argv[i], "--proxy") == 0 && i + 1 < argc)
        {
            strncpy(proxy_url, argv[++i], sizeof(proxy_url) - 1);
            proxy_url[sizeof(proxy_url) - 1] = '\0';
        }
        else if (strcmp(argv[i], "--rule") == 0 && i + 1 < argc)
        {
            if (!rules_overridden)
            {
                num_rules = 0;
                rules_overridden = true;
            }

            if (num_rules >= MAX_RULES)
            {
                fprintf(stderr, "ERROR: Maximum %d rules supported\n", MAX_RULES);
                return 1;
            }

            if (!parse_rule(argv[++i], &rules[num_rules]))
                return 1;

            num_rules++;
        }
        else if (strcmp(argv[i], "--dns-via-proxy") == 0 && i + 1 < argc)
        {
            char * value = argv[++i];
            if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0)
                dns_via_proxy = true;
            else if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0)
                dns_via_proxy = false;
            else
            {
                fprintf(stderr, "ERROR: Invalid value for --dns-via-proxy. Use: true, false, 1, or 0\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--verbose") == 0 && i + 1 < argc)
        {
            verbose_level = atoi(argv[++i]);
            if (verbose_level < 0 || verbose_level > 3)
            {
                fprintf(stderr, "ERROR: Verbose level must be 0-3\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--cleanup") == 0)
        {
            // already handled
        }
        else
        {
            fprintf(stderr, "ERROR: Unknown option '%s'\n", argv[i]);
            fprintf(stderr, "Use --help for usage information\n");
            return 1;
        }
    }

    show_banner();

    if (config_path_set || access(config_path, F_OK) == 0)
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
        printf("Proxy: %s://%s:%u\n", proxy_type == PROXY_TYPE_HTTP ? "http" : "socks5", proxy_host, proxy_port);

        if (proxy_username[0] != '\0')
            printf("Proxy Auth: %s:***\n", proxy_username);

        printf("DNS via Proxy: %s\n", dns_via_proxy ? "Enabled" : "Disabled");

        if (num_rules > 0)
        {
            printf("Rules: %d\n", num_rules);
            for (int i = 0; i < num_rules; i++)
            {
                const char * protocol_str = rules[i].protocol == RULE_PROTOCOL_TCP ? "TCP"
                    : rules[i].protocol == RULE_PROTOCOL_UDP                       ? "UDP"
                                                                                   : "BOTH";
                const char * action_str = rules[i].action == RULE_ACTION_PROXY ? "PROXY"
                    : rules[i].action == RULE_ACTION_DIRECT                    ? "DIRECT"
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
        ProxyPrism_SetLogCallback(log_callback);
    else
        ProxyPrism_SetLogCallback(NULL); // Explicitly disable

    if (verbose_level == 2 || verbose_level == 3)
        ProxyPrism_SetConnectionCallback(connection_callback);
    else
        ProxyPrism_SetConnectionCallback(NULL); // Explicitly disable

    // turn on traffic logging when needed
    ProxyPrism_SetTrafficLoggingEnabled(verbose_level > 0);

    // show config
    printf("Proxy: %s://%s:%u\n", proxy_type == PROXY_TYPE_HTTP ? "http" : "socks5", proxy_host, proxy_port);

    if (proxy_username[0] != '\0')
        printf("Proxy Auth: %s:***\n", proxy_username);

    printf("DNS via Proxy: %s\n", dns_via_proxy ? "Enabled" : "Disabled");

    // setup proxy
    if (!ProxyPrism_SetProxyConfig(
            proxy_type, proxy_host, proxy_port, proxy_username[0] ? proxy_username : "", proxy_password[0] ? proxy_password : ""))
    {
        fprintf(stderr, "ERROR: Failed to set proxy configuration\n");
        return 1;
    }

    ProxyPrism_SetDnsViaProxy(dns_via_proxy);

    // add rules
    if (num_rules > 0)
    {
        printf("Rules: %d\n", num_rules);
        for (int i = 0; i < num_rules; i++)
        {
            const char * protocol_str = rules[i].protocol == RULE_PROTOCOL_TCP ? "TCP"
                : rules[i].protocol == RULE_PROTOCOL_UDP                       ? "UDP"
                                                                               : "BOTH";
            const char * action_str = rules[i].action == RULE_ACTION_PROXY ? "PROXY"
                : rules[i].action == RULE_ACTION_DIRECT                    ? "DIRECT"
                                                                           : "BLOCK";

            uint32_t rule_id = ProxyPrism_AddRule(
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
        printf("Use --rule to add proxy rules or define rules in /etc/proxyprism.conf. See --help for examples.\n");
    }

    // start proxyprism
    if (!ProxyPrism_Start())
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
    ProxyPrism_Stop();
    printf("ProxyPrism stopped.\n");

    return 0;
}
