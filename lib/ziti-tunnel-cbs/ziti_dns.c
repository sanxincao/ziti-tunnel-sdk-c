/*
 Copyright NetFoundry Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

// Prevent LWIP from providing byteorder functions to avoid conflicts with system headers
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#include <ziti/ziti_tunnel.h>
#include <ziti/ziti_log.h>
#include <ziti/ziti_dns.h>
#include "ziti_instance.h"
#include "dns_host.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

#define MAX_UPSTREAMS 5
#define MAX_DNS_NAME 256
#define MAX_IP_LENGTH 16
#define MAX_IP6_LENGTH 128

#ifndef IN6ADDR_V4MAPPED
#define IN6ADDR_V4MAPPED(v4) \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0xff, 0xff, v4[0], v4[1], v4[2], v4[3] }}}
#endif

enum ns_q_type {
    NS_T_A = 1,
    NS_T_AAAA = 28,
    NS_T_MX = 15,
    NS_T_TXT = 16,
    NS_T_SRV = 33,
};

typedef struct ziti_dns_client_s {
    io_ctx_t *io_ctx;
    bool is_tcp;
    model_map active_reqs; // dns_reqs keyed by address of ID.
} ziti_dns_client_t;

struct dns_req {
    uint16_t id;
    size_t req_len;
    uint8_t req[4096];
    size_t resp_len;
    uint8_t resp[4096];

    dns_message msg;

    struct in_addr addr;
    struct in6_addr addr6;

    uint8_t *rp;

    ziti_dns_client_t *clt;
};

static void* on_dns_client(const void *app_intercept_ctx, io_ctx_t *io);
static int on_dns_close(void *dns_io_ctx);
static ssize_t on_dns_req(const void *ziti_io_ctx, void *write_ctx, const void *q_packet, size_t len);
static int query_upstream(struct dns_req *req);
static void dns_upstream_alloc(uv_handle_t *h, size_t reqlen, uv_buf_t *b);
static void on_upstream_packet(uv_udp_t *h, ssize_t rc, const uv_buf_t *buf, const struct sockaddr* addr, unsigned int flags);
static void complete_dns_req(struct dns_req *req);
static void free_dns_req(struct dns_req *req);

typedef struct dns_domain_s {
    char name[MAX_DNS_NAME];

    model_map intercepts; // set[intercept]

    ziti_connection resolv_proxy;

} dns_domain_t;

// hostname or domain
typedef struct dns_entry_s {
    char name[MAX_DNS_NAME];
    char ip[MAX_IP_LENGTH];
    char ip6[MAX_IP6_LENGTH]; // 字符串用于显示
    ip_addr_t addr;
    ip_addr_t addr6;         // 真实的ip地址，用于数据传输
    dns_domain_t *domain;

    model_map intercepts;

} dns_entry_t;

struct ziti_dns_s {

    struct {
        uint32_t base;
        uint32_t counter;
        uint32_t counter_mask;
        uint32_t capacity;
    } ip_pool;
    struct {
        ip6_addr_t base;       // IPv6 base address
        uint64_t counter_mask_high;  // IPv6 address mask
        uint64_t counter_mask_low;
        uint64_t counter_mask;
        uint64_t counter;
        uint64_t capacity;
    } ip6_pool;
    // map[hostname -> dns_entry_t]
    model_map hostnames;

    // map[ip4_addr_t -> dns_entry_t]
    model_map ip_addresses;
    model_map ip6_addresses;
    // map[domain -> dns_domain_t]
    model_map domains;
    model_map concatenated;
    uv_loop_t *loop;
    tunneler_context tnlr;

    model_map requests;
    uv_udp_t upstream;
    bool is_ipv4;
    int num_dns_up;
    struct sockaddr_in6 upstream_addr[MAX_UPSTREAMS];
} ziti_dns;
struct address {
    char ipv4[INET_ADDRSTRLEN];    // 存储IPv4地址
    char ipv6[INET6_ADDRSTRLEN];   // 存储IPv6地址
};
#ifdef _WIN32

void detect_network_win(NetworkStatus* status) {
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pCurrAddress = NULL;
    memset(status, 0, sizeof(NetworkStatus));

    // 注册表禁用状态检测
    HKEY hKey;
    DWORD dwValue, dwSize = sizeof(DWORD);
    BOOL bRegistryDisabled = FALSE;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueEx(hKey, "DisabledComponents", NULL, NULL,
            (LPBYTE)&dwValue, &dwSize) == ERROR_SUCCESS && dwValue == 0xFF) {
            bRegistryDisabled = TRUE;
        }
        RegCloseKey(hKey);
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;

    // 首次调用获取缓冲区大小
    DWORD dwRet = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
    if (dwRet == ERROR_BUFFER_OVERFLOW) {
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        dwRet = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
    }

    if (dwRet == NO_ERROR) {
        for (pCurrAddress = pAddresses; pCurrAddress; pCurrAddress = pCurrAddress->Next) {
            // 筛选条件：仅活动状态的物理适配器（以太网/Wi-Fi）
            if (pCurrAddress->OperStatus != IfOperStatusUp ||
                pCurrAddress->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
                (pCurrAddress->IfType != IF_TYPE_ETHERNET_CSMACD &&
                    pCurrAddress->IfType != IF_TYPE_IEEE80211)) {
                continue;
            }

            // IPv4检测
            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddress->FirstUnicastAddress;
            for (; pUnicast; pUnicast = pUnicast->Next) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in* ipv4 = (struct sockaddr_in*)pUnicast->Address.lpSockaddr;
                    if (ipv4->sin_addr.s_addr != INADDR_ANY &&
                        ipv4->sin_addr.s_addr != INADDR_LOOPBACK) {
                        status->has_ipv4 = 1;
                        break;
                    }
                }
            }

            // IPv6检测（排除链路本地地址）
            if (!bRegistryDisabled) {  // 注册表未全局禁用时才检测
                for (pUnicast = pCurrAddress->FirstUnicastAddress; pUnicast; pUnicast = pUnicast->Next) {
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)pUnicast->Address.lpSockaddr;
                        const UCHAR* addr = ipv6->sin6_addr.s6_addr;

                        // 排除所有非全球单播地址（2000::/3）
                        if ((addr[0] & 0xE0) != 0x20) continue;  // 严格限定全球单播地址
                        if (IN6_IS_ADDR_LINKLOCAL(&ipv6->sin6_addr)) continue;  // 排除链路本地地址
                        if (IN6_IS_ADDR_SITELOCAL(&ipv6->sin6_addr)) continue;  // 排除站点本地地址

                        status->has_ipv6 = 1;
                        break;
                        
                    }
                }
            }
        }
        // 双栈状态判断
        status->is_dual_stack = (status->has_ipv4 && status->has_ipv6) ? 1 : 0;
        // 注册表强制覆盖
        if (bRegistryDisabled) status->has_ipv6 = 0;
    }
    free(pAddresses);
    WSACleanup();
}

int check_ipv6_route() {
    PMIB_IPFORWARD_TABLE2 pTable = NULL;
    if (GetIpForwardTable2(AF_INET6, &pTable) == NO_ERROR) {
        for (ULONG i = 0; i < pTable->NumEntries; i++) {
            MIB_IPFORWARD_ROW2 *row = &pTable->Table[i];
            // 默认路由：前缀长度为 0
            if (row->DestinationPrefix.PrefixLength == 0) {
                free(pTable);
                return 1;
            }

            // 匹配 ULA: fd00::/8 or Global Unicast: 2000::/3
            IN6_ADDR addr = row->DestinationPrefix.Prefix.Ipv6.sin6_addr;
            if ((addr.u.Byte[0] & 0xFE) == 0xFC ||  // ULA fd00::/8
                (addr.u.Byte[0] & 0xE0) == 0x20) {  // GUA 2000::/3
                free(pTable);
                return 1;
            }

            // 匹配 fe80::/10 (链路本地地址)
            if ((addr.u.Byte[0] == 0xFE) && ((addr.u.Byte[1] & 0xC0) == 0x80)) {
                free(pTable);
                return 1;
            }
        }
        free(pTable);
    }
    return 0;
}

#else

// Linux/macOS 原始实现
int check_ipv6_route() {
    FILE *fp = popen("ip -6 route show 2>/dev/null", "r");
    if (fp) {
        char buf[256];
        int has_valid_route = 0;
        while (fgets(buf, sizeof(buf), fp)) {
            if (strstr(buf, "default") || strstr(buf, "via 2") || strstr(buf, "via fd")) {
                has_valid_route = 1;
                break;
            }
            if (strstr(buf, "fe80::") && strstr(buf, "dev")) {
                has_valid_route = 1;
            }
        }
        pclose(fp);
        return has_valid_route;
    }
    return 0;
}

#endif

// 地址类型宏定义
#define IS_GLOBAL_IPv6(addr)  ((addr)->s6_addr[0] & 0xE0) == 0x20  // 2000::/3
#define IS_ULA_IPv6(addr)     ((addr)->s6_addr[0] == 0xFD)         // fd00::/8
#define IS_LINKLOCAL_IPv6(addr) ((addr)->s6_addr[0] == 0xFE && ((addr)->s6_addr[1] & 0xC0) == 0x80)  // fe80::/10

#ifdef _WIN32
void detect_network_support(NetworkStatus* status) {
    IP_ADAPTER_ADDRESSES* addresses = NULL, * addr = NULL;
    ULONG outBufLen = 15000;

    addresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, addresses, &outBufLen) != NO_ERROR) {
        free(addresses);
        return;
    }

    for (addr = addresses; addr != NULL; addr = addr->Next) {
        if (addr->OperStatus != IfOperStatusUp) continue;

        IP_ADAPTER_UNICAST_ADDRESS* unicast = addr->FirstUnicastAddress;
        for (; unicast != NULL; unicast = unicast->Next) {
            struct sockaddr* sa = unicast->Address.lpSockaddr;
            if (sa->sa_family == AF_INET) {
                status->has_ipv4 = 1;
            }
            else if (sa->sa_family == AF_INET6) {
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sa;
                if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
                    status->has_link_local = 1;
                }
                else {
                    status->has_valid_ipv6 = 1;
                }
            }
        }
    }

    status->has_ipv6 = (status->has_valid_ipv6 || status->has_link_local);
    status->is_dual_stack = (status->has_ipv4 && status->has_ipv6);
    free(addresses);
}
#else
// Stub implementation for non-Windows platforms
void detect_network_support(NetworkStatus* status) {
    // For non-Windows platforms, assume dual-stack support
    status->has_ipv4 = 1;
    status->has_ipv6 = 1;
    status->has_valid_ipv6 = 1;
    status->has_link_local = 1;
    status->is_dual_stack = 1;
}
#endif

static ip_addr_t next_ipv6() {
    ZITI_LOG(INFO, "从地址池拿一个ipv6地址\n");
    ip6_addr_t candidate;
    static uint64_t counter = 3;  // 从3开始计数，对应地址 ::303;
    static const ip_addr_t unspecified_ipv6_address = { {{0}} }; // Initialize to zero

    if (model_map_size(&ziti_dns.ip_addresses) >= ziti_dns.ip6_pool.capacity) {
       //printf("DNS IPv6 pool exhausted (%lu IPs). Try rerunning with a larger DNS range.\n", ziti_dns.ip6_pool.capacity);
       return unspecified_ipv6_address;
    }
    
    for (int j = 0; j < 4; j++) {
        candidate.addr[j] = ziti_dns.ip6_pool.base.addr[j];
        ////printf("==================== = % x\n", candidate.addr[j]);
    }
    candidate.addr[3] = htonl((ntohl(ziti_dns.ip6_pool.base.addr[3]) + counter) & 0xFFFFFFFF);  // 增加计数器到基础地址

    do {
        if (model_map_get(&ziti_dns.ip_addresses, &candidate) == NULL) {
            break; // 如果找到一个未被占用的地址，则跳出循环
        }
        counter += 1; // 否则递增计数器
        candidate.addr[3] = htonl((ntohl(ziti_dns.ip6_pool.base.addr[3]) + counter) & 0xFFFFFFFF); // 计算新的地址
            // 如果计数器达到掩码的最大值，重置为1。
        if (counter == ziti_dns.ip_pool.counter_mask) {
            counter = 1;
        }

    } while (model_map_get(&ziti_dns.ip_addresses, &candidate) != NULL && counter < ziti_dns.ip6_pool.capacity);

    ziti_dns.ip6_pool.counter = counter;  // 更新计数器
    counter++;  // 下次使用时继续递增

    //printf("外Value of candidate: %s\n", ip6addr_ntoa(&candidate));
    ip_addr_t candidate6;
    candidate6.type = IPADDR_TYPE_V6;
    candidate6.u_addr.ip6 = candidate;
    return candidate6;

}

static uint32_t next_ipv4() {
    uint32_t candidate;
    uint32_t i = 0; // track how many candidates have been considered. should never exceed pool capacity.

    if (model_map_size(&ziti_dns.ip_addresses) == ziti_dns.ip_pool.capacity) {
        ZITI_LOG(ERROR, "DNS ip pool exhausted (%u IPs). Try rerunning with larger DNS range.",
                 ziti_dns.ip_pool.capacity);
        return INADDR_NONE;
    }

    do {
        candidate = htonl(ziti_dns.ip_pool.base | (ziti_dns.ip_pool.counter++ & ziti_dns.ip_pool.counter_mask));
        i += 1;
        if (ziti_dns.ip_pool.counter == ziti_dns.ip_pool.counter_mask) {
            ziti_dns.ip_pool.counter = 1;
        }
    } while ((model_map_getl(&ziti_dns.ip_addresses, candidate) != NULL) && i < ziti_dns.ip_pool.capacity);

    if (i == ziti_dns.ip_pool.capacity) {
        ZITI_LOG(ERROR, "no IPs available after scanning entire pool");
        return INADDR_NONE;
    }

    return candidate;
}

static int seed_dns_ipv6(const char *dns_cidr) {
    ip6_addr_t ip6;
    char ipaddr[40];
    unsigned int bits;
    
    int rc = sscanf(dns_cidr, "%39[^/]/%d", ipaddr, &bits);
    if (rc != 2 || bits > 128) {
        ZITI_LOG(ERROR, "Invalid IPv6 range specification: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/n format is expected");
        return -1;
    }

    if (!ip6addr_aton(ipaddr, &ip6)) {
        ZITI_LOG(ERROR, "Invalid IPv6 address: %s", ipaddr);
        return -1;
    }

    ziti_dns.ip6_pool.base = ip6;
    ziti_dns.ip6_pool.capacity = (bits == 128) ? 1 : (1ULL << (128 - bits));

    // 模拟 128-bit 加法，获取结束地址
    ip6_addr_t end_addr = ip6;

    // 从低位到高位做加法
    uint64_t low = ntohl(ip6.addr[3]);
    uint64_t mid_low = ntohl(ip6.addr[2]);
    uint64_t mid_high = ntohl(ip6.addr[1]);
    uint64_t high = ntohl(ip6.addr[0]);

    uint64_t carry = ziti_dns.ip6_pool.capacity - 1;

    low += (carry & 0xFFFFFFFF);
    uint64_t c1 = low >> 32;
    low &= 0xFFFFFFFF;

    mid_low += ((carry >> 32) & 0xFFFFFFFF) + c1;
    uint64_t c2 = mid_low >> 32;
    mid_low &= 0xFFFFFFFF;

    mid_high += ((carry >> 64) & 0xFFFFFFFF) + c2;
    uint64_t c3 = mid_high >> 32;
    mid_high &= 0xFFFFFFFF;

    high += ((carry >> 96) & 0xFFFFFFFF) + c3;
    high &= 0xFFFFFFFF;

    end_addr.addr[3] = htonl((uint32_t)low);
    end_addr.addr[2] = htonl((uint32_t)mid_low);
    end_addr.addr[1] = htonl((uint32_t)mid_high);
    end_addr.addr[0] = htonl((uint32_t)high);

    char subnet_str[INET6_ADDRSTRLEN];
    char end_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6, subnet_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &end_addr, end_str, INET6_ADDRSTRLEN);

    ZITI_LOG(INFO, "DNS configured with range %s - %s (%llu ips)", subnet_str, end_str, ziti_dns.ip6_pool.capacity);

    return 0;
}

static int seed_dns(const char *dns_cidr) {
    uint32_t ip[4];
    uint32_t bits;
    int rc = sscanf(dns_cidr, "%d.%d.%d.%d/%d", &ip[0], &ip[1], &ip[2], &ip[3], &bits);
    if (rc != 5 || ip[0] > 255 || ip[1] > 255 || ip[2] > 255 || ip[3] > 255 || bits > 32) {
        ZITI_LOG(ERROR, "Invalid IP range specification: n.n.n.n/m format is expected");
        return -1;
    }
    uint32_t mask = 0;
    for (int i = 0; i < 4; i++) {
        mask <<= 8U;
        mask |= (ip[i] & 0xFFU);
    }

    ziti_dns.ip_pool.counter_mask = ~( (uint32_t)-1 << (32 - (uint32_t)bits));
    ziti_dns.ip_pool.base = mask & ~ziti_dns.ip_pool.counter_mask;

    ziti_dns.ip_pool.counter = 1;
    ziti_dns.ip_pool.capacity = (1 << (32 - bits)) - 2; // subtract 2 for network and broadcast IPs

    union ip_bits {
        uint8_t b[4];
        uint32_t ip;
    } min_ip, max_ip;

    min_ip.ip = htonl(ziti_dns.ip_pool.base);
    max_ip.ip = htonl(ziti_dns.ip_pool.base | ziti_dns.ip_pool.counter_mask);
    ZITI_LOG(INFO, "DNS configured with range %d.%d.%d.%d - %d.%d.%d.%d (%u ips)",
             min_ip.b[0],min_ip.b[1],min_ip.b[2],min_ip.b[3],
             max_ip.b[0],max_ip.b[1],max_ip.b[2],max_ip.b[3], ziti_dns.ip_pool.capacity
             );

    return 0;
}

int ziti_dns_setup(tunneler_context tnlr, const char* dns_addr_ipv4, const char* dns_cidr4, const char* dns_addr_ipv6, const char* dns_cidr6) {
    ziti_dns.tnlr = tnlr;  // 设置 tunneler 上下文（tnlr）

    ip_addr_t ip6;
    ip_addr_t ip4;

    seed_dns(dns_cidr4);  // 初始化 IPv4 DNS 配置
    seed_dns_ipv6(dns_cidr6);  // 初始化 IPv6 DNS 配置
    ipaddr_aton(dns_addr_ipv6, &ip6);  // 将 IPv6 地址转换为 ip_addr_t 结构体
    ipaddr_aton(dns_addr_ipv4, &ip4);  // 将 IPv4 地址转换为 ip_addr_t 结构体
    ziti_address dns_zaddr_ipv6, tun_zaddr;
    ziti_address dns_zaddr_ipv4;
    ziti_address_from_ip_addr(&dns_zaddr_ipv6, &ip6);  // 将 IPv6 地址转换为 ziti_address 结构体
    ziti_address_from_ip_addr(&dns_zaddr_ipv4, &ip4);  // 将 IPv4 地址转换为 ziti_address 结构体

    // 获取当前网络状态
    NetworkStatus status = g_network_status;

    // 根据网络环境（双栈、单栈）配置 DNS 拦截器
    if (status.is_dual_stack) {  // 双栈环境，支持 IPv4 和 IPv6
        intercept_ctx_t* dns_intercept_ipv4 = intercept_ctx_new(tnlr, "dns-ip-resolver", &ziti_dns);  // 创建 IPv4 DNS 拦截上下文
        intercept_ctx_add_address(dns_intercept_ipv4, &dns_zaddr_ipv4);  // 添加 IPv4 DNS 地址
        intercept_ctx_add_port_range(dns_intercept_ipv4, 53, 53);  // 设置 DNS 端口范围
        intercept_ctx_add_protocol(dns_intercept_ipv4, "udp");  // 设置协议为 UDP
        intercept_ctx_override_cbs(dns_intercept_ipv4, on_dns_client, on_dns_req, on_dns_close, on_dns_close);  // 设置回调函数
        ziti_tunneler_intercept(tnlr, dns_intercept_ipv4);  // 启动拦截

        ziti_address_from4_string(&tun_zaddr, dns_cidr4);  // 将 IPv4 CIDR 地址转换为 ziti_address
        ziti_address* reserved4[] = { &tun_zaddr, &dns_zaddr_ipv4 };  // 创建一个包含 TUN IP 和 DNS IPv4 地址的数组
        for (size_t i = 0; i < sizeof(reserved4) / sizeof(ziti_address*); i++) {
            struct in_addr* in4_p = (struct in_addr*)&reserved4[i]->addr.cidr.ip;  // 获取 IPv4 地址
            model_map_setl(&ziti_dns.ip_addresses, in4_p->s_addr, calloc(1, sizeof(dns_entry_t)));  // 将 IPv4 地址与 dns_entry_t 结构体关联
        }

        intercept_ctx_t* dns_intercept_ipv6 = intercept_ctx_new(tnlr, "dns-ip-resolver", &ziti_dns);  // 创建 IPv6 DNS 拦截上下文
        intercept_ctx_add_address(dns_intercept_ipv6, &dns_zaddr_ipv6);  // 添加 IPv6 DNS 地址
        intercept_ctx_add_port_range(dns_intercept_ipv6, 53, 53);  // 设置 DNS 端口范围
        intercept_ctx_add_protocol(dns_intercept_ipv6, "udp");  // 设置协议为 UDP
        intercept_ctx_override_cbs(dns_intercept_ipv6, on_dns_client, on_dns_req, on_dns_close, on_dns_close);  // 设置回调函数
        ziti_tunneler_intercept(tnlr, dns_intercept_ipv6);  // 启动拦截

        ziti_address_from_string(&tun_zaddr, dns_cidr6);  // 将 IPv6 CIDR 地址转换为 ziti_address
        ziti_address* reserved6[] = { &tun_zaddr, &dns_zaddr_ipv6 };  // 创建一个包含 TUN IP 和 DNS IPv6 地址的数组
        for (size_t i = 0; i < sizeof(reserved6) / sizeof(ziti_address*); i++) {
            struct in6_addr* in6_p = (struct in6_addr*)&reserved6[i]->addr.cidr.ip;  // 获取 IPv6 地址
            model_map_setl(&ziti_dns.ip_addresses, in6_p->s6_addr, calloc(1, sizeof(dns_entry_t)));  // 将 IPv6 地址与 dns_entry_t 结构体关联
        }
    }
    else if (status.has_ipv4) {  // 如果只有 IPv4 环境
        intercept_ctx_t* dns_intercept_ipv4 = intercept_ctx_new(tnlr, "dns-ip-resolver", &ziti_dns);  // 创建 IPv4 DNS 拦截上下文
        intercept_ctx_add_address(dns_intercept_ipv4, &dns_zaddr_ipv4);  // 添加 IPv4 DNS 地址
        intercept_ctx_add_port_range(dns_intercept_ipv4, 53, 53);  // 设置 DNS 端口范围
        intercept_ctx_add_protocol(dns_intercept_ipv4, "udp");  // 设置协议为 UDP
        intercept_ctx_override_cbs(dns_intercept_ipv4, on_dns_client, on_dns_req, on_dns_close, on_dns_close);  // 设置回调函数
        ziti_tunneler_intercept(tnlr, dns_intercept_ipv4);  // 启动拦截

        ziti_address_from4_string(&tun_zaddr, dns_cidr4);  // 将 IPv4 CIDR 地址转换为 ziti_address
        ziti_address* reserved4[] = { &tun_zaddr, &dns_zaddr_ipv4 };  // 创建一个包含 TUN IP 和 DNS IPv4 地址的数组
        for (size_t i = 0; i < sizeof(reserved4) / sizeof(ziti_address*); i++) {
            struct in_addr* in4_p = (struct in_addr*)&reserved4[i]->addr.cidr.ip;  // 获取 IPv4 地址
            model_map_setl(&ziti_dns.ip_addresses, in4_p->s_addr, calloc(1, sizeof(dns_entry_t)));  // 将 IPv4 地址与 dns_entry_t 结构体关联
        }
    }
    else {  // 如果只有 IPv6 环境
        intercept_ctx_t* dns_intercept_ipv6 = intercept_ctx_new(tnlr, "dns-ip-resolver", &ziti_dns);  // 创建 IPv6 DNS 拦截上下文
        intercept_ctx_add_address(dns_intercept_ipv6, &dns_zaddr_ipv6);  // 添加 IPv6 DNS 地址
        intercept_ctx_add_port_range(dns_intercept_ipv6, 53, 53);  // 设置 DNS 端口范围
        intercept_ctx_add_protocol(dns_intercept_ipv6, "udp");  // 设置协议为 UDP
        intercept_ctx_override_cbs(dns_intercept_ipv6, on_dns_client, on_dns_req, on_dns_close, on_dns_close);  // 设置回调函数
        ziti_tunneler_intercept(tnlr, dns_intercept_ipv6);  // 启动拦截

        ziti_address_from_string(&tun_zaddr, dns_cidr6);  // 将 IPv6 CIDR 地址转换为 ziti_address
        ziti_address* reserved6[] = { &tun_zaddr, &dns_zaddr_ipv6 };  // 创建一个包含 TUN IP 和 DNS IPv6 地址的数组
        for (size_t i = 0; i < sizeof(reserved6) / sizeof(ziti_address*); i++) {
            struct in6_addr* in6_p = (struct in6_addr*)&reserved6[i]->addr.cidr.ip;  // 获取 IPv6 地址
            model_map_setl(&ziti_dns.ip_addresses, in6_p->s6_addr, calloc(1, sizeof(dns_entry_t)));  // 将 IPv6 地址与 dns_entry_t 结构体关联
        }
    }

    return 0;  // 返回 0 表示函数执行成功
}

#define CHECK_UV(op) do{ int rc = (op); if (rc < 0) {\
ZITI_LOG(ERROR, "failed [" #op "]: %d(%s)", rc, uv_strerror(rc)); \
return rc;} \
}while(0)

int ziti_dns_set_upstream(uv_loop_t *l, tunnel_upstream_dns_array upstreams) {
    if (!uv_is_active((const uv_handle_t *) &ziti_dns.upstream)) {
        CHECK_UV(uv_udp_init(l, &ziti_dns.upstream));
        int r = uv_udp_bind(&ziti_dns.upstream,
                            (const struct sockaddr *) &(struct sockaddr_in6){
                                    .sin6_family = AF_INET6,
                                    .sin6_addr = in6addr_any,
                            }, 0);
        if (r != 0) {
            ZITI_LOG(WARN, "failed to bind upstream socket to IPv6 address: %s", uv_strerror(r));
            r = uv_udp_bind(&ziti_dns.upstream,
                            (const struct sockaddr *) &(struct sockaddr_in){
                                    .sin_family = AF_INET,
                                    .sin_addr = INADDR_ANY,
                            }, 0);
            if (r != 0) {
                ZITI_LOG(WARN, "failed to bind upstream socket to IPv4 address: %s", uv_strerror(r));
                return r;
            }
            ziti_dns.is_ipv4 = true;
        }
        CHECK_UV(uv_udp_recv_start(&ziti_dns.upstream, dns_upstream_alloc, on_upstream_packet));
        uv_unref((uv_handle_t *) &ziti_dns.upstream);
    }

    union {
        struct in_addr addr;
        uint8_t a[4];
    } ipv4;

    int idx = 0;
    for (int i = 0; upstreams[i] != NULL && idx < MAX_UPSTREAMS; i++) {
        const tunnel_upstream_dns *dns = upstreams[i];
        int port = dns->port != 0 ? (int)dns->port : 53;

        if (ziti_dns.is_ipv4) {
            if (uv_inet_pton(AF_INET, dns->host, &ipv4) == 0) {
                ((struct sockaddr_in *) &ziti_dns.upstream_addr[idx])->sin_family = AF_INET;
                ((struct sockaddr_in *) &ziti_dns.upstream_addr[idx])->sin_addr = ipv4.addr;
                ((struct sockaddr_in *) &ziti_dns.upstream_addr[idx])->sin_port = htons(port);
                idx++;
            } else {
                ZITI_LOG(WARN, "cannot set non-IPv4 upstream on IPv4 only socket");
            }
        } else {
            // set IPv6 upstream address, mapping IPv4 target to IPv6 space (if needed)
            ziti_dns.upstream_addr[idx].sin6_family = AF_INET6;
            ziti_dns.upstream_addr[idx].sin6_port = htons(port);
            if (uv_inet_pton(AF_INET6, dns->host, &ziti_dns.upstream_addr[idx].sin6_addr) != 0) {
                if (uv_inet_pton(AF_INET, dns->host, &ipv4) == 0) {
                    ziti_dns.upstream_addr[idx].sin6_addr = (struct in6_addr) IN6ADDR_V4MAPPED(ipv4.a);
                } else {
                    ZITI_LOG(WARN, "upstream address[%s] is not IP format", dns->host);
                    char port_str[6];
                    snprintf(port_str, sizeof(port_str), "%hu", port);
                    uv_getaddrinfo_t req = {0};
                    if(uv_getaddrinfo(l, &req, NULL, dns->host, port_str, NULL) == 0) {
                        memcpy(&ziti_dns.upstream_addr[idx], req.addrinfo->ai_addr, req.addrinfo->ai_addrlen);
                    }
                }
            }
            idx++;
        }
        ZITI_LOG(INFO, "DNS upstream[%d] is set to %s:%hu", idx, dns->host, port);
    }
    ziti_dns.num_dns_up = idx;
    return 0;
}


void* on_dns_client(const void *app_intercept_ctx, io_ctx_t *io) {
    ZITI_LOG(TRACE, "new DNS client");
    ziti_dns_client_t *clt = calloc(1, sizeof(ziti_dns_client_t));
    io->ziti_io = clt;
    clt->io_ctx = io;
    ziti_tunneler_set_idle_timeout(io, 5000); // 5 seconds
    ziti_tunneler_dial_completed(io, true);
    return clt;
}

static void remove_dns_req(void *p) {
    struct dns_req *req = p;
    if (req) {
        model_map_remove_key(&ziti_dns.requests, &req->id, sizeof(req->id));
        free_dns_req(req);
    }
}

int on_dns_close(void *dns_io_ctx) {
    ZITI_LOG(TRACE, "DNS client close");
    ziti_dns_client_t *clt = dns_io_ctx;
    // we may be here due to udp timeout, and reqs may have been sent to upstream.
    // remove reqs from ziti_dns to prevent completion (with invalid io_ctx) if upstream should respond after udp timeout.
    model_map_clear(&clt->active_reqs, remove_dns_req);
    ziti_tunneler_close(clt->io_ctx->tnlr_io);
    free(clt->io_ctx);
    free(dns_io_ctx);
    return 0;
}

static bool check_name(const char *name, char clean_name[MAX_DNS_NAME], bool *is_domain) {
    const char *hp = name;
    char *p = clean_name;

    if (*hp == '*' && *(hp + 1) == '.') {
        if (is_domain) *is_domain = true;
        *p++ = '*';
        *p++ = '.';
        hp += 2;
    } else {
        if (is_domain) *is_domain = false;
    }

    bool success = true;
    while (*hp != '\0') {
        *p++ = (char) tolower(*hp++);
        if (p - clean_name >= MAX_DNS_NAME) {
            p = clean_name;
            success = false;
            break;
        }
    }
    *p = '\0';
    return success;
}

static dns_entry_t* new_dns_entry(const char* host) {
    ZITI_LOG(INFO, "开始给域名分配地址");

    dns_entry_t* entry = calloc(1, sizeof(dns_entry_t));
    if (!entry) {
        ZITI_LOG(ERROR, "内存分配失败");
        return NULL;
    }

    strncpy(entry->name, host, sizeof(entry->name)-1);  // 设置主机名
    entry->name[sizeof(entry->name) - 1] = '\0'; // 确保以 '\0' 结尾
    // 分配 IPv4 地址
    uint32_t ipv4 = next_ipv4();
    if (ipv4 != INADDR_NONE) {
        ip_addr_set_ip4_u32(&entry->addr, ipv4);
        ipaddr_ntoa_r(&entry->addr, entry->ip, sizeof(entry->ip));
        model_map_setl(&ziti_dns.ip_addresses, ip_2_ip4(&entry->addr)->addr, entry);
        ZITI_LOG(INFO, "registered IPv4 address %s -> %s", host, entry->ip);
    }
    else {
        ZITI_LOG(ERROR, "Failed to obtain a valid IPv4 address");
    }

    // 分配 IPv6 地址
    ip_addr_t ipv6 = next_ipv6();
    if (ipv6.u_addr.ip6.addr[0] != 0 || ipv6.u_addr.ip6.addr[1] != 0 ||
        ipv6.u_addr.ip6.addr[2] != 0 || ipv6.u_addr.ip6.addr[3] != 0) {
        IP6_ADDR(&entry->addr6.u_addr.ip6, ipv6.u_addr.ip6.addr[0], ipv6.u_addr.ip6.addr[1],
            ipv6.u_addr.ip6.addr[2], ipv6.u_addr.ip6.addr[3]);
        ip6addr_ntoa_r(&entry->addr6, entry->ip6, sizeof(entry->ip6));
        model_map_setl(&ziti_dns.ip6_addresses, ip_2_ip6(&entry->addr6)->addr, entry);
        ZITI_LOG(INFO, "registered IPv6 address %s -> %s", host, entry->ip6);
    }
    else {
        ZITI_LOG(ERROR, "Failed to obtain a valid IPv6 address from next_ipv6()");
    }

    // 将域名和结构体映射
    model_map_set(&ziti_dns.hostnames, host, entry);
    //test_func(host, "9");
    //test_func(host, "19");
    ZITI_LOG(INFO, "Host: %s, Entry Name: %s\n", host, entry->name);

    return entry;
}

const char *ziti_dns_reverse_lookup_domain(const ip_addr_t *addr) {
    if (IP_IS_V4(addr)) { // 判断是否为 IPv4
        dns_entry_t *entry = model_map_getl(&ziti_dns.ip_addresses, ip_2_ip4(addr)->addr);
        if (entry && entry->domain) {
            //printf("ziti_dns_reverse_lookup_domain-ipv4 = %s\n", entry->domain->name);
            return entry->domain->name;
        }
    } else if (IP_IS_V6(addr)) { // 判断是否为 IPv6
        dns_entry_t *entry = model_map_getl(&ziti_dns.ip_addresses, ip_2_ip6(addr)->addr);
        if (entry && entry->domain) {
            //printf("ziti_dns_reverse_lookup_domain-ipv6 = %s\n", entry->domain->name);
            return entry->domain->name;
        }
    }
    return NULL; // 如果找不到匹配条目或类型不支持
}


const char *ziti_dns_reverse_lookup(const char *ip_addr) {
    ip_addr_t addr = {0};
    dns_entry_t *entry = NULL;

    if (ip4addr_aton(ip_addr, ip_2_ip4(&addr))) {
        // IPv4 address detected
        entry = model_map_getl(&ziti_dns.ip_addresses, ip_2_ip4(&addr)->addr);
        //printf("IPv4 domain: %s\n", entry ? entry->name : "NULL");
    } else if (ip6addr_aton(ip_addr, &addr)) {
        // IPv6 address detected
        entry = model_map_getl(&ziti_dns.ip_addresses, ip_2_ip6(&addr)->addr);
        //printf("IPv6 domain: %s\n", entry ? entry->name : "NULL");
    } else {
        //printf("Invalid IP address: %s\n", ip_addr);
    }

    return entry ? entry->name : NULL;
}

static dns_domain_t* find_domain(const char *hostname) {
    char *dot = strchr(hostname, '.');
    dns_domain_t *domain = model_map_get(&ziti_dns.domains, hostname);
    while (dot != NULL && domain == NULL) {
        domain = model_map_get(&ziti_dns.domains, dot + 1);
        dot = strchr(dot + 1, '.');
    }
    return domain;
}

static dns_entry_t *ziti_dns_lookup(const char *hostname) {
    char clean[MAX_DNS_NAME];
    bool is_wildcard;
    if (!check_name(hostname, clean, &is_wildcard) || is_wildcard) {
        ZITI_LOG(WARN, "invalid host lookup[%s]", hostname);
        return NULL;
    }

    dns_entry_t *entry = model_map_get(&ziti_dns.hostnames, clean);

    if (!entry) {         // try domains
        dns_domain_t *domain = find_domain(clean);

        if (domain && model_map_size(&domain->intercepts) > 0) {
            ZITI_LOG(DEBUG, "matching domain[%s] found for %s", domain->name, hostname);
            entry = new_dns_entry(clean);
            if (entry) {
                entry->domain = domain;
            }
        }
    }

    if (entry) {
        if (model_map_size(&entry->intercepts) > 0 ||
            (entry->domain && model_map_size(&entry->domain->intercepts) > 0)) {
            return entry;
        } else {
            return NULL; // inactive entry
        }
    }
    return entry;
}


void ziti_dns_deregister_intercept(void *intercept) {
    model_map_iter it = model_map_iterator(&ziti_dns.domains);
    while (it != NULL) {
        dns_domain_t *domain = model_map_it_value(it);
        model_map_remove_key(&domain->intercepts, &intercept, sizeof(intercept));
        it = model_map_it_next(it);
    }

    it = model_map_iterator(&ziti_dns.hostnames);
    while (it != NULL) {
        dns_entry_t *e = model_map_it_value(it);
        model_map_remove_key(&e->intercepts, &intercept, sizeof(intercept));
        if (model_map_size(&e->intercepts) == 0 && (e->domain == NULL || model_map_size(&e->domain->intercepts) == 0)) {
            it = model_map_it_remove(it);
            model_map_removel(&ziti_dns.ip_addresses, ip_2_ip4(&e->addr)->addr);
            ZITI_LOG(DEBUG, "%zu active hostnames mapped to %zu IPs", model_map_size(&ziti_dns.hostnames), model_map_size(&ziti_dns.ip_addresses));
            ZITI_LOG(INFO, "DNS mapping %s -> %s is now inactive", e->name, e->ip);
        } else {
            it = model_map_it_next(it);
        }
    }

    it = model_map_iterator(&ziti_dns.domains);
    while (it != NULL) {
        dns_domain_t *domain = model_map_it_value(it);
        if (model_map_size(&domain->intercepts) == 0) {
            it = model_map_it_remove(it);
            ZITI_LOG(INFO, "wildcard domain[*%s] is now inactive", domain->name);
        } else {
            it = model_map_it_next(it);
        }
    }
}

const _46double *ziti_dns_register_hostname(const ziti_address *addr, void *intercept) {
    // IP or CIDR block
    if (addr->type == ziti_address_cidr) {
        return NULL;
    }

    const char *hostname = addr->addr.hostname;
    char clean[MAX_DNS_NAME];
    bool is_domain = false;

    if (!check_name(hostname, clean, &is_domain)) {
        ZITI_LOG(ERROR, "invalid hostname[%s]", hostname);
    }

    if (is_domain) {
        dns_domain_t *domain = model_map_get(&ziti_dns.domains, clean + 2);
        if (domain == NULL) {
            ZITI_LOG(INFO, "registered wildcard domain[%s]", clean);
            domain = calloc(1, sizeof(dns_domain_t));
            strncpy(domain->name, clean, sizeof(domain->name));
            model_map_set(&ziti_dns.domains, clean + 2, domain);
        }
        model_map_set_key(&domain->intercepts, &intercept, sizeof(intercept), intercept);
        return NULL;
    } else {
        dns_entry_t *entry = model_map_get(&ziti_dns.hostnames, clean);
        if (!entry) {
            entry = calloc(1, sizeof(dns_entry_t));
            if (!entry) return NULL;
            const dns_entry_t* entry = new_dns_entry(clean);
            model_map_set_key(&entry->intercepts, &intercept, sizeof(intercept), intercept);
            _46double* bull = calloc(1, sizeof(_46double));  // 分配内存
            if (bull == NULL) {
                free(entry);  // 在分配bull失败时清理entry
                //printf("内存分配失败\n");
                return NULL;
            }
            bull->addr = entry->addr.u_addr.ip4;
            bull->addr6 = entry->addr6.u_addr.ip6;
            return bull;  // 返回地址结构体的指针
        }
        if (entry) {
            model_map_set_key(&entry->intercepts, &intercept, sizeof(intercept), intercept);
            return &entry->addr;
        } else {
            return NULL;
        }
    }
}

static const char DNS_OPT[] = { 0x0, 0x0, 0x29, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

#define DNS_HEADER_LEN 12
#define DNS_ID(p) ((uint8_t)(p)[0] << 8 | (uint8_t)(p)[1])
#define DNS_FLAGS(p) ((p)[2] << 8 | (p)[3])
#define DNS_QRS(p) ((p)[4] << 8 | (p)[5])
#define DNS_QR(p) ((p) + 12)
#define DNS_RD(p) ((p)[2] & 0x1)

#define DNS_SET_RA(p) ((p)[3] = (p)[3] | 0x80)
#define DNS_SET_TC(p) ((p)[2] = (p)[2] | 0x2)
#define DNS_SET_CODE(p,c) ((p)[3] = (p)[3] | ((c) & 0xf))
#define DNS_SET_ANS(p) ((p)[2] = (p)[2] | 0x80)
#define DNS_SET_ARS(p,n) do{ (p)[6] = (n) >> 8; (p)[7] = (n) & 0xff; } while(0)
#define DNS_SET_AARS(p,n) do{ (p)[10] = (n) >> 8; (p)[11] = (n) & 0xff; } while(0)

#define SET_U8(p,v) *(p)++ = (v) & 0xff
#define SET_U16(p,v) (*(p)++ = ((v) >> 8) & 0xff),*(p)++ = (v) & 0xff
#define SET_U32(p,v) (*(p)++ = ((v) >> 24) & 0xff), \
(*(p)++ = ((v)>>16) & 0xff),                          \
(*(p)++ = ((v) >> 8) & 0xff),                       \
*(p)++ = (v) & 0xff

#define IS_QUERY(flags) (((flags) & (1 << 15)) == 0)

static uint8_t* format_name(uint8_t* p, const char* name) {
    const char *np = name;
    do {
        const char *dot = strchr(np, '.');
        uint8_t len = dot ? dot - np : strlen(np);

        *p++ = len;
        if (len == 0) break;

        memcpy(p, np, len);
        p += len;

        if (dot == NULL) {
            *p++ = 0;
            break;
        } else {
            np = dot + 1;
        }
    } while(1);
    return p;
}

static void format_resp(struct dns_req *req) {

    // copy header from request
    memcpy(req->resp, req->req, DNS_HEADER_LEN); // DNS header
    DNS_SET_ANS(req->resp);
    DNS_SET_CODE(req->resp, req->msg.status);
    bool recursion_avail = uv_is_active((const uv_handle_t *) &ziti_dns.upstream);
    if (recursion_avail) {
        DNS_SET_RA(req->resp);
    }

    size_t query_section_len = strlen(req->msg.question[0]->name) + 2 + 4;
    memcpy(req->resp + DNS_HEADER_LEN, req->req + DNS_HEADER_LEN, query_section_len);

    uint8_t *rp = req->resp + DNS_HEADER_LEN + query_section_len;
    uint8_t *resp_end = req->resp + sizeof(req->resp);
    bool truncated = false;

    if (req->msg.status == DNS_NO_ERROR && req->msg.answer != NULL) {
        int ans_count = 0;
        for (int i = 0; req->msg.answer[i] != NULL; i++) {
            ans_count++;
            dns_answer *a = req->msg.answer[i];

            if (resp_end - rp < 10) { // 2 bytes for name ref, 2 for type, 2 for class, and 4 for ttl
                truncated = true;
                goto done;
            }

            // name ref
            *rp++ = 0xc0;
            *rp++ = 0x0c;

            ZITI_LOG(INFO, "found record[%s] for query[%d:%s]", a->data,
                     (int)req->msg.question[0]->type, req->msg.question[0]->name);

            SET_U16(rp, a->type);
            SET_U16(rp, 1); // class IN
            SET_U32(rp, a->ttl);

            switch (a->type) {
                case NS_T_A: {
                    if (resp_end - rp < (2 + sizeof(req->addr.s_addr))) {
                        truncated = true;
                        goto done;
                    }
                    SET_U16(rp, sizeof(req->addr.s_addr));
                    memcpy(rp, &req->addr.s_addr, sizeof(req->addr.s_addr));
                    rp += sizeof(req->addr.s_addr);
                    break;
                }

                case NS_T_AAAA: { // 添加处理AAAA记录的代码
                    if (resp_end - rp < (2 + sizeof(req->addr6.s6_addr))) {
                        truncated = true;
                        goto done;
                    }
                    SET_U16(rp, sizeof(req->addr6.s6_addr));
                    memcpy(rp, &req->addr6.s6_addr, sizeof(req->addr6.s6_addr));
                    rp += sizeof(req->addr6.s6_addr);
                    break;
                }
                case NS_T_TXT: {
                    uint16_t txtlen = strlen(a->data);
                    uint16_t datalen = 1 + txtlen;
                    if (resp_end - rp < (3 + txtlen)) {
                        truncated = true;
                        goto done;
                    }
                    SET_U16(rp, datalen);
                    SET_U8(rp, txtlen);
                    memcpy(rp, a->data, txtlen);
                    rp += txtlen;
                    break;
                }
                case NS_T_MX: {
                    uint8_t *hold = rp;
                    rp += 2;
                    uint16_t datalen_est = strlen(a->data) + 1;
                    if (resp_end - hold < (4 + datalen_est)) {
                        truncated = true;
                        goto done;
                    }
                    SET_U16(rp, a->priority);
                    rp = format_name(rp, a->data);
                    uint16_t datalen = rp - hold - 2;
                    SET_U16(hold, datalen);
                    break;
                }
                case NS_T_SRV: {
                    uint8_t *hold = rp;
                    rp += 2;
                    uint16_t datalen_est = strlen(a->data) + 1;
                    if (resp_end - hold < (8 + datalen_est)) {
                        truncated = true;
                        goto done;
                    }
                    SET_U16(rp, a->priority);
                    SET_U16(rp, a->weight);
                    SET_U16(rp, a->port);
                    rp = format_name(rp, a->data);
                    uint16_t datalen = rp - hold - 2;
                    SET_U16(hold, datalen);
                    break;
                }
                default:
                    ZITI_LOG(WARN, "unhandled response type[%d]", (int)a->type);
            }
        }
        done:
        if (truncated) {
            ZITI_LOG(DEBUG, "dns response truncated");
            DNS_SET_TC(req->resp);
        }
        DNS_SET_ARS(req->resp, ans_count);
    }

    DNS_SET_AARS(req->resp, 1);
    if (resp_end - rp > 11) {
        memcpy(rp, DNS_OPT, sizeof(DNS_OPT));
        rp += sizeof(DNS_OPT);
    }
    req->resp_len = rp - req->resp;
}

static void process_host_req(struct dns_req *req) {
    // 查找请求的域名是否存在于本地 DNS 解析表中
    dns_entry_t *entry = ziti_dns_lookup(req->msg.question[0]->name);
    NetworkStatus status = g_network_status;
    // 通过 detect_network_support 函数检测当前网络环境是否支持 IPv4/IPv6
    // NetworkStatus status;
    // detect_network_support(&status);

    if (entry) {  // 如果本地 DNS 解析表中存在该域名的解析记录
        req->msg.status = DNS_NO_ERROR;  // 设置 DNS 查询状态为无错误

        // 如果当前网络环境为双栈（IPv4+IPv6）
        if (status.is_dual_stack) {
            // 处理 IPv4 查询
            if (req->msg.question[0]->type == NS_T_A) {
                req->addr.s_addr = entry->addr.u_addr.ip4.addr;

                dns_answer *a = calloc(1, sizeof(dns_answer));
                a->ttl = 60;
                a->type = NS_T_A;
                a->data = strdup(entry->ip);

                req->msg.answer = calloc(2, sizeof(dns_answer *));
                req->msg.answer[0] = a;
            } 
            // 处理 IPv6 查询
            else if (req->msg.question[0]->type == NS_T_AAAA) {
                memcpy(req->addr6.s6_addr, entry->addr6.u_addr.ip6.addr, sizeof(req->addr6.s6_addr));

                dns_answer* a = calloc(1, sizeof(dns_answer));
                a->ttl = 60;
                a->type = NS_T_AAAA;
                a->data = strdup(entry->ip6);

                req->msg.answer = calloc(2, sizeof(dns_answer*));
                req->msg.answer[0] = a;
            }
        } 
        // 如果仅支持 IPv6
        else if (status.has_ipv6) { 
            if (req->msg.question[0]->type == NS_T_AAAA) {
                memcpy(req->addr6.s6_addr, entry->addr6.u_addr.ip6.addr, sizeof(req->addr6.s6_addr));

                dns_answer* a = calloc(1, sizeof(dns_answer));
                a->ttl = 60;
                a->type = NS_T_AAAA;
                a->data = strdup(entry->ip6);

                req->msg.answer = calloc(2, sizeof(dns_answer*));
                req->msg.answer[0] = a;
            }
        } 
        // 仅支持 IPv4
        else {
            if (req->msg.question[0]->type == NS_T_A) {
                req->addr.s_addr = entry->addr.u_addr.ip4.addr;

                dns_answer *a = calloc(1, sizeof(dns_answer));
                a->ttl = 60;
                a->type = NS_T_A;
                a->data = strdup(entry->ip);

                req->msg.answer = calloc(2, sizeof(dns_answer *));
                req->msg.answer[0] = a;
            }
        }

        // 格式化 DNS 响应并完成查询
        format_resp(req);
        complete_dns_req(req);
    } else {  
        // 如果本地 DNS 解析表中不存在该域名，查询上游 DNS 服务器
        int rc = query_upstream(req);
        if (rc != DNS_NO_ERROR) {
            req->msg.status = rc;
            format_resp(req);
            complete_dns_req(req);
        }
    }
}

static void proxy_domain_close_cb(ziti_connection c) {
    dns_domain_t *domain = ziti_conn_data(c);
    if (domain) {
        domain->resolv_proxy = NULL;
    }
}

static void on_proxy_connect(ziti_connection conn, int status) {
    dns_domain_t *domain = ziti_conn_data(conn);
    if (status == ZITI_OK) {
        ZITI_LOG(INFO, "proxy resolve connection established for domain[%s]", domain->name);
        domain->resolv_proxy = conn;
    } else {
        ZITI_LOG(ERROR, "failed to establish proxy resolve connection for domain[%s]", domain->name);
        ziti_close(conn, proxy_domain_close_cb);
    }
}

static ssize_t on_proxy_data(ziti_connection conn, const uint8_t* data, ssize_t status) {
    if (status >= 0) {
        ZITI_LOG(DEBUG, "proxy resolve: %.*s", (int)status, data);
        dns_message msg = {0};
        int rc = parse_dns_message(&msg, (const char *) data, status);
        if (rc < 0) {
            // the original DNS client's request won't be completed because we can't get the msg ID.
            return rc;
        }
        uint16_t id = msg.id;
        struct dns_req *req = model_map_get_key(&ziti_dns.requests, &id, sizeof(id));
        if (req) {
            req->msg.answer = msg.answer;
            msg.answer = NULL;
            format_resp(req);
            complete_dns_req(req);
        }
        free_dns_message(&msg);
    } else {
        ZITI_LOG(ERROR, "proxy resolve connection failed: %d(%s)", (int)status, ziti_errorstr(status));
        ziti_close(conn, proxy_domain_close_cb);
    }
    return status;
}

struct proxy_dns_req_wr_s {
    struct dns_req *req;
    char *json;
};

static void free_proxy_dns_wr(struct proxy_dns_req_wr_s *wr) {
    if (wr->json) {
        free(wr->json);
        wr->json = NULL;
    }
    free(wr);
}

static void on_proxy_write(ziti_connection conn, ssize_t len, void *ctx) {
    ZITI_LOG(DEBUG, "proxy resolve write: %d", (int)len);
    if (ctx) {
        struct proxy_dns_req_wr_s *wr = ctx;
        if (len < 0) {
            ZITI_LOG(WARN, "proxy resolve write failed: %s/%zd", ziti_errorstr(len), len);
            wr->req->msg.status = DNS_SERVFAIL;
            format_resp(wr->req);
            complete_dns_req(wr->req);
            ziti_close(conn, proxy_domain_close_cb);
        }
        free_proxy_dns_wr(wr);
    }
}

static void proxy_domain_req(struct dns_req *req, dns_domain_t *domain) {
    if (domain->resolv_proxy == NULL) {
        // initiate connection to hosting endpoint for this domain
        model_map_iter it = model_map_iterator(&domain->intercepts);
        void *intercept = model_map_it_value(it);
        domain->resolv_proxy = intercept_resolve_connect(intercept, domain, on_proxy_connect, on_proxy_data);
    }
    dns_question *q = req->msg.question[0];
    if (domain->resolv_proxy == NULL) {
        req->msg.status = DNS_SERVFAIL;
    } else if (q->type == NS_T_MX || q->type == NS_T_SRV || q->type == NS_T_TXT) {
        size_t jsonlen;
        struct proxy_dns_req_wr_s *wr = calloc(1, sizeof(struct proxy_dns_req_wr_s));
        wr->req = req;
        wr->json = dns_message_to_json(&req->msg, MODEL_JSON_COMPACT, &jsonlen);
        if (wr->json) {
            ZITI_LOG(DEBUG, "writing proxy resolve req[%04x]: %s", req->id, wr->json);

            // intercept_resolve_connect above can quick-fail if context does not have a valid API session
            // in that case resolve_proxy connection will be in Closed state and write will fail.
            // ziti_write will queue the message if the connection state is Connecting (as it will be the first time through)
            int rc = ziti_write(domain->resolv_proxy, (uint8_t *) wr->json, jsonlen, on_proxy_write, wr);
            if (rc == ZITI_OK) {
                // completion with client will happen in on_proxy_write if write fails, or on_proxy_data when response arrives
                return;
            }
            ZITI_LOG(WARN, "failed to write proxy resolve request[%04x]: %s", req->id, ziti_errorstr(rc));
            ziti_close(domain->resolv_proxy, proxy_domain_close_cb);
        } else {
            req->msg.status = DNS_FORMERR;
        }
        free_proxy_dns_wr(wr);
    } else {
        req->msg.status = DNS_NOT_IMPL;
    }

    format_resp(req);
    complete_dns_req(req);
}

ssize_t on_dns_req(const void *ziti_io_ctx, void *write_ctx, const void *q_packet, size_t q_len) {
    ziti_dns_client_t *clt = (ziti_dns_client_t *)ziti_io_ctx;
    const uint8_t *dns_packet = q_packet;
    size_t dns_packet_len = q_len;

    uint16_t req_id = DNS_ID(dns_packet);
    struct dns_req *req = model_map_get_key(&ziti_dns.requests, &req_id, sizeof(req_id));
    if (req != NULL) {
        ZITI_LOG(TRACE, "duplicate dns req[%04x] from %s client", req_id, req->clt == ziti_io_ctx ? "same" : "another");
        // just drop new request
        ziti_tunneler_ack(write_ctx);
        return (ssize_t)q_len;
    }

    req = calloc(1, sizeof(struct dns_req));
    req->clt = clt;

    req->req_len = q_len;
    memcpy(req->req, q_packet, q_len);

    if (parse_dns_req(&req->msg, dns_packet, dns_packet_len) != 0) {
        ZITI_LOG(ERROR, "failed to parse DNS message");
        on_dns_close(clt);
        free_dns_req(req);
        ziti_tunneler_ack(write_ctx);
        return (ssize_t)q_len;
    }
    req->id = req->msg.id;

    ZITI_LOG(TRACE, "received DNS query q_len=%zd id[%04x] recursive[%s] type[%d] name[%s]", q_len, req->id,
             req->msg.recursive ? "true" : "false",
             (int)req->msg.question[0]->type,
             req->msg.question[0]->name);

    model_map_set_key(&req->clt->active_reqs, &req->id, sizeof(req->id), req);
    model_map_set_key(&ziti_dns.requests, &req->id, sizeof(req->id), req);

    // route request
    dns_question *q = req->msg.question[0];

    if (q->type == NS_T_A || q->type == NS_T_AAAA) {
        process_host_req(req); // will send upstream if no local answer and req is recursive
    } else {
        // find domain requires normalized name
        char reqname[MAX_DNS_NAME];
        check_name(q->name, reqname, NULL);
        dns_domain_t *domain = find_domain(reqname);
        if (domain) {
            proxy_domain_req(req, domain);
        } else {
            int dns_status = query_upstream(req);
            if (dns_status != DNS_NO_ERROR) {
                req->msg.status = dns_status;
                format_resp(req);
                complete_dns_req(req);
            }
        }
    }

    ziti_tunneler_ack(write_ctx);
    return (ssize_t)q_len;
}

int query_upstream(struct dns_req *req) {
    bool avail = uv_is_active((const uv_handle_t *) &ziti_dns.upstream);
    bool success = false;
    if (avail && req->msg.recursive) {
        uv_buf_t buf = uv_buf_init((char *) req->req, req->req_len);

        for (int i = 0; i < ziti_dns.num_dns_up; i++) {
            int rc = uv_udp_try_send(&ziti_dns.upstream, &buf, 1,
                                     (struct sockaddr *) &ziti_dns.upstream_addr[i]);
            if (rc > 0) {
                success = true;
            } else {
                ZITI_LOG(WARN, "failed to query[%04x] upstream DNS server[%d]: %d(%s)",
                         req->id, i, rc, uv_strerror(rc));
            }
        }
    }
    return success ? DNS_NO_ERROR : DNS_REFUSE;
}

static void dns_upstream_alloc(uv_handle_t *h, size_t reqlen, uv_buf_t *b) {
    static char dns_buf[1024];
    b->base = dns_buf;
    b->len = sizeof(dns_buf);
}

static void on_upstream_packet(uv_udp_t *h, ssize_t rc, const uv_buf_t *buf, const struct sockaddr* addr, unsigned int flags) {
    if (rc > 0) {
        uint16_t id = DNS_ID(buf->base);
        struct dns_req *req = model_map_get_key(&ziti_dns.requests, &id, sizeof(id));
        if (req != NULL) {
            ZITI_LOG(TRACE, "upstream sent response to query[%04x] (rc=%zd)", id, rc);
            if (rc <= sizeof(req->resp)) {
                req->resp_len = rc;
                memcpy(req->resp, buf->base, rc);
            } else {
                ZITI_LOG(WARN, "unexpected DNS response: too large");
            }
            complete_dns_req(req);
        }
    }
}

static void free_dns_req(struct dns_req *req) {
    free_dns_message(&req->msg);
    free(req);
}

static void complete_dns_req(struct dns_req *req) {
    model_map_remove_key(&ziti_dns.requests, &req->id, sizeof(req->id));
    if (req->clt) {
        ziti_tunneler_write(req->clt->io_ctx->tnlr_io, req->resp, req->resp_len);
        model_map_remove_key(&req->clt->active_reqs, &req->id, sizeof(req->id));
        // close client if there are no other pending requests
        if (model_map_size(&req->clt->active_reqs) == 0) {
            on_dns_close(req->clt->io_ctx->ziti_io);
        }
    } else {
        ZITI_LOG(WARN, "query[%04x] is stale", req->id);
    }
    free_dns_req(req);
}