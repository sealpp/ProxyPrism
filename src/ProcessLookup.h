#pragma once

#include "NetworkAddress.h"

namespace proxyprism {

// Find the owning PID for a local socket identified by source address and port.
// Works for both TCP and UDP (unconnected UDP falls back to /proc/net/udp).
uint32_t get_process_id_from_connection(const NetworkAddress& src_ip, uint16_t src_port, bool is_udp);

} // namespace proxyprism
