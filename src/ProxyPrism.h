#ifndef PROXYPRISM_H
#define PROXYPRISM_H

#define PROXYPRISM_VERSION "0.1.0"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*LogCallback)(const char * message);
typedef void (*ConnectionCallback)(
    const char * process_name, uint32_t pid, const char * dest_ip, uint16_t dest_port, const char * proxy_info);

typedef enum
{
    PROXY_TYPE_HTTP = 0,
    PROXY_TYPE_SOCKS5 = 1
} ProxyType;

typedef enum
{
    RULE_ACTION_PROXY = 0,
    RULE_ACTION_DIRECT = 1,
    RULE_ACTION_BLOCK = 2
} RuleAction;

typedef enum
{
    RULE_PROTOCOL_TCP = 0,
    RULE_PROTOCOL_UDP = 1,
    RULE_PROTOCOL_BOTH = 2
} RuleProtocol;

uint32_t ProxyPrism_AddRule(
    const char * process_name, const char * target_hosts, const char * target_ports, RuleProtocol protocol, RuleAction action);
bool ProxyPrism_EnableRule(uint32_t rule_id);
bool ProxyPrism_DisableRule(uint32_t rule_id);
bool ProxyPrism_DeleteRule(uint32_t rule_id);
bool ProxyPrism_EditRule(
    uint32_t rule_id,
    const char * process_name,
    const char * target_hosts,
    const char * target_ports,
    RuleProtocol protocol,
    RuleAction action);
bool ProxyPrism_SetProxyConfig(ProxyType type, const char * proxy_ip, uint16_t proxy_port, const char * username, const char * password);
void ProxyPrism_SetDnsViaProxy(bool enable);
void ProxyPrism_SetLogCallback(LogCallback callback);
void ProxyPrism_SetConnectionCallback(ConnectionCallback callback);
void ProxyPrism_SetTrafficLoggingEnabled(bool enable);
void ProxyPrism_ClearConnectionLogs(void);
bool ProxyPrism_Start(void);
bool ProxyPrism_Stop(void);
int ProxyPrism_TestConnection(const char * target_host, uint16_t target_port, char * result_buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif
