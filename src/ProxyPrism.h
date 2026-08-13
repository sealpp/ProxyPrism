#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

namespace proxyprism {

inline constexpr const char* version = "0.1.0";

using RuleId = std::uint32_t;

enum class ProxyType : std::uint8_t
{
    HTTP = 0,
    SOCKS5 = 1,
};

enum class RuleAction : std::uint8_t
{
    PROXY = 0,
    DIRECT = 1,
    BLOCK = 2,
};

enum class RuleProtocol : std::uint8_t
{
    TCP = 0,
    UDP = 1,
    BOTH = 2,
};

using LogCallback = std::function<void(const char* message)>;
using ConnectionCallback = std::function<void(
    const char* process_name,
    std::uint32_t pid,
    const char* dest_ip,
    std::uint16_t dest_port,
    const char* proxy_info)>;

RuleId add_rule(
    const char* process_name,
    const char* target_hosts,
    const char* target_ports,
    RuleProtocol protocol,
    RuleAction action);

bool enable_rule(RuleId rule_id);
bool disable_rule(RuleId rule_id);
bool delete_rule(RuleId rule_id);

bool edit_rule(
    RuleId rule_id,
    const char* process_name,
    const char* target_hosts,
    const char* target_ports,
    RuleProtocol protocol,
    RuleAction action);

bool set_proxy_config(
    ProxyType type,
    const char* proxy_ip,
    std::uint16_t proxy_port,
    const char* username,
    const char* password);

void set_log_callback(LogCallback callback);

void set_connection_callback(ConnectionCallback callback);

void set_traffic_logging_enabled(bool enable);

void clear_connection_logs();

bool start();

bool stop();

int test_connection(
    const char* target_host,
    std::uint16_t target_port,
    char* result_buffer,
    std::size_t buffer_size);

} // namespace proxyprism
