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

#include <stdint.h>
#include <ziti/netif_driver.h>

#ifndef _Out_cap_c_
#define _Out_cap_c_(n)
#endif

#ifndef _Ret_bytecount_
#define _Ret_bytecount_(n)
#endif

#ifndef _Post_maybenull_
#define _Post_maybenull_
#endif

#include <wintun.h>
#include <stdbool.h>
#include <ziti/ziti_log.h>
#include <netioapi.h>
#include <stdlib.h>
#include <combaseapi.h>
#include <ziti/model_support.h>
#include "lwip/ip6_addr.h"
#include "tun.h"

#define ZITI_TUN_NAME_BASE "idn-tun"

#define ROUTE_LIFETIME (10 * 60) /* in seconds */
#define ROUTE_REFRESH ((ROUTE_LIFETIME - (ROUTE_LIFETIME/10))*1000)

struct netif_handle_s {
    char name[MAX_ADAPTER_NAME];
    NET_LUID luid;
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;

    uv_thread_t reader;
    uv_async_t *read_available;
    HANDLE read_complete;

    packet_cb on_packet;
    void *netif;

    model_map excluded_routes;
    uv_timer_t route_timer;
};

static int tun_close(struct netif_handle_s *tun);
static int tun_setup_read(netif_handle tun, uv_loop_t *loop, packet_cb on_packet, void *netif);
static ssize_t tun_write(netif_handle tun, const void *buf, size_t len);
static int tun_add_route(netif_handle tun, const char *dest);
static int tun_del_route(netif_handle tun, const char *dest);
int set_dns(netif_handle tun, uint32_t dns_ip);
int set_ip6_dns(netif_handle tun, struct ip6_addr dns_ip6);
static int tun_exclude_rt(netif_handle dev, uv_loop_t *loop, const char *dest);

static void WINAPI if_change_cb(PVOID CallerContext, PMIB_IPINTERFACE_ROW Row, MIB_NOTIFICATION_TYPE NotificationType);
static void refresh_routes(uv_timer_t *timer);
static void cleanup_adapters(wchar_t *tun_name);
static HANDLE if_change_handle;

static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
static WINTUN_START_SESSION_FUNC *WintunStartSession;
static WINTUN_END_SESSION_FUNC *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

static uv_once_t wintunInit;
static HMODULE WINTUN;

static MIB_IPFORWARD_ROW2 default_rt;

static void CALLBACK WintunLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_ DWORD64 Timestamp, _In_z_ const WCHAR *LogLine) {
    switch (Level) {
        case WINTUN_LOG_INFO:
            ZITI_LOG(INFO, "%ls", LogLine);
            break;
        case WINTUN_LOG_WARN:
            ZITI_LOG(WARN, "%ls", LogLine);
            break;
        case WINTUN_LOG_ERR:
            ZITI_LOG(ERROR, "%ls", LogLine);
            break;
        default:
            return;
    }
}

static void InitializeWintun(void) {
    HMODULE Wintun =
            LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!Wintun) {
        DWORD error = GetLastError();
        fprintf(stderr, "Failed to load wintun.dll. Error code: %lu\n", error);
        return;
    }

#define X(Name) \
    if ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL) \
    { \
        DWORD error = GetLastError(); \
        fprintf(stderr, "Failed to get address of %s. Error code: %lu\n", #Name, error); \
        FreeLibrary(Wintun); \
        return; \
    }

    X(WintunCreateAdapter)
    X(WintunCloseAdapter)
    X(WintunOpenAdapter)
    X(WintunGetAdapterLUID)
    X(WintunGetRunningDriverVersion)
    X(WintunDeleteDriver)
    X(WintunSetLogger)
    X(WintunStartSession)
    X(WintunEndSession)
    X(WintunGetReadWaitEvent)
    X(WintunReceivePacket)
    X(WintunReleaseReceivePacket)
    X(WintunAllocateSendPacket)
    X(WintunSendPacket)

#undef X

    WINTUN =  Wintun;
}

static bool flush_dns() {
    static BOOL (*DnsFlushResolverCache)();
    if (DnsFlushResolverCache == NULL) {
        HMODULE dnsapi = LoadLibrary("dnsapi.dll");
        if (dnsapi == NULL) {
            ZITI_LOG(ERROR, "Failed loading module: %lu", GetLastError());
            return false;
        }
        DnsFlushResolverCache = (BOOL (*)()) GetProcAddress(dnsapi, "DnsFlushResolverCache");
        if (DnsFlushResolverCache == NULL) {
            ZITI_LOG(ERROR, "Failed loading DnsFlushResolverCache function: %lu", GetLastError());
            FreeLibrary(dnsapi);
            return false;
        }
    }
    BOOL result = DnsFlushResolverCache();
    if (result) {
        ZITI_LOG(INFO, "DnsFlushResolverCache succeeded");
    } else {
        ZITI_LOG(ERROR, "DnsFlushResolverCache failed: %lu", GetLastError());
    }
    return result;
}

static WINTUN_ADAPTER_HANDLE adapter = NULL;

void cleanup_resources() {
    if (adapter) WintunCloseAdapter(adapter);
    if (WINTUN) FreeLibrary(WINTUN);
}

static const char *get_tun_name(netif_handle tun) {
    return tun->name;
}

netif_driver tun_open(struct uv_loop_s* loop, uint32_t tun_ip, const char* cidr4,
    struct ip6_addr* tun_ip6, const char* cidr6, char* error, size_t error_len) {
    if (error != NULL) {
        memset(error, 0, error_len * sizeof(char));
    }

    uv_once(&wintunInit, InitializeWintun);
    if (WINTUN == NULL) {
        strcpy_s(error, error_len, "Failed to load wintun.dll");
        return NULL;
    }
    DWORD Version = WintunGetRunningDriverVersion();
    ZITI_LOG(INFO, "Wintun v%u.%u loaded", (Version >> 16) & 0xff, (Version >> 0) & 0xff);

    struct netif_handle_s *tun = calloc(1, sizeof(struct netif_handle_s));
    if (tun == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate tun");
        }
        return NULL;
    }
    flush_dns();

    int tun_num = 0;
    snprintf(tun->name, MAX_ADAPTER_NAME, "%s%d", ZITI_TUN_NAME_BASE, tun_num);

    wchar_t w_adapter_name[MAX_ADAPTER_NAME];
    swprintf(w_adapter_name, MAX_ADAPTER_NAME, L"%hs", tun->name);

    WINTUN_ADAPTER_HANDLE found = WintunOpenAdapter(w_adapter_name);
    while (found) {
        tun_num++;
        WintunCloseAdapter(found); // already exists. increment and try again
        if (tun_num > 15) {
            char* msg = "TOO MANY TUN DEVICES?";
            size_t msg_len = strlen(msg);
            snprintf(error, msg_len, "%s", msg);
            return NULL;
        }
        snprintf(tun->name, MAX_ADAPTER_NAME, "%s%d", ZITI_TUN_NAME_BASE, tun_num);
        swprintf(w_adapter_name, MAX_ADAPTER_NAME, L"%hs", tun->name);
        found = WintunOpenAdapter(w_adapter_name);
    }
    WintunSetLogger(WintunLogger); //set the logger here exclusively to avoid these errors from WinTun: Failed to find matching adapter name: Element not found. (Code 0x00000490)

    tun->adapter = WintunCreateAdapter(w_adapter_name, L"Idn", NULL); // Wintun adds "Tunnel" so this will be "OpenZiti Tunnel"
    if (!tun->adapter) {
        DWORD err = GetLastError();
        snprintf(error, error_len, "Failed to create adapter: %ld", err);
        return NULL;
    }

    adapter = tun->adapter;
    WintunGetAdapterLUID(tun->adapter, &tun->luid);

    if (atexit(cleanup_resources) != 0) {
        char* msg = "Cannot set exit function";
        size_t msg_len = strlen(msg);
        snprintf(error, msg_len, "%s", msg);
        return NULL;
    }

    NotifyIpInterfaceChange(AF_INET, if_change_cb, tun, TRUE, &if_change_handle);

    tun->session = WintunStartSession(tun->adapter, WINTUN_MAX_RING_CAPACITY);
    if (!tun->session) {
        DWORD err = GetLastError();
        snprintf(error, error_len, "Failed to start session: %d", err);
        return NULL;
    }

    struct netif_driver_s *driver = calloc(1, sizeof(struct netif_driver_s));
    if (driver == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate netif_device_s");
            tun_close(tun);
        }
        return NULL;
    }
	
	
	
	if (tun_ip) {
	        MIB_UNICASTIPADDRESS_ROW AddressRow;
	        InitializeUnicastIpAddressEntry(&AddressRow);
	        AddressRow.InterfaceLuid = tun->luid;
	        AddressRow.Address.Ipv4.sin_family = AF_INET;
	        AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = tun_ip;
	        char ipv4_str[40];
	        inet_ntop(AF_INET, &tun_ip, ipv4_str, INET_ADDRSTRLEN);
	        //ZITI_LOG(INFO, "tun_open里的IPv4 address: %s", ipv4_str);

	        if (cidr4) {
	            int bits;
	            uint32_t ip[4];
	            sscanf(cidr4, "%d.%d.%d.%d/%d", &ip[0], &ip[1], &ip[2], &ip[3], &bits);
	            AddressRow.OnLinkPrefixLength = bits;
	        }
	        else {
	            AddressRow.OnLinkPrefixLength = 16;
	        }
	        DWORD err = CreateUnicastIpAddressEntry(&AddressRow);
	        if (err != ERROR_SUCCESS && err != ERROR_OBJECT_ALREADY_EXISTS)
	        {
	            snprintf(error, error_len, "Failed to set IP address: %d", err);
	            tun_close(tun);
	            return NULL;
	        }
	    }
 
	    if (tun_ip6) {
	        MIB_UNICASTIPADDRESS_ROW AddressRow6;
	        InitializeUnicastIpAddressEntry(&AddressRow6);
	        AddressRow6.InterfaceLuid = tun->luid;
	        AddressRow6.Address.Ipv6.sin6_family = AF_INET6;
 
	        // 修复对 addr 字段的访问
            memcpy(&AddressRow6.Address.Ipv6.sin6_addr, tun_ip6->addr, sizeof(struct in6_addr));
	        char ipv6_str[INET6_ADDRSTRLEN];
	        inet_ntop(AF_INET6, &AddressRow6.Address.Ipv6.sin6_addr, ipv6_str, INET6_ADDRSTRLEN);
	        ZITI_LOG(INFO, "tun_open里的IPv6 address: %s", ipv6_str);
 
	        if (cidr6) {
	            char address_str[INET6_ADDRSTRLEN];
	            int prefix_length;
	            if (sscanf(cidr6, "%[^/]/%d", address_str, &prefix_length) == 2) {
	                AddressRow6.OnLinkPrefixLength = prefix_length;
	            }
	            else {
	                snprintf(error, error_len, "Invalid IPv6 CIDR format");
	                tun_close(tun);
	                return NULL;
	            }
	        }
 
	        DWORD err = CreateUnicastIpAddressEntry(&AddressRow6);  // 确保提交 IPv6 地址
	        if (err != ERROR_SUCCESS && err != ERROR_OBJECT_ALREADY_EXISTS) {
	            snprintf(error, error_len, "Failed to set IPv6 address: %d", err);
	            tun_close(tun);
	            return NULL;
	        }
	    }


    driver->handle       = tun;
    driver->setup        = tun_setup_read;
    driver->write        = tun_write;
    driver->add_route    = tun_add_route;
    driver->delete_route = tun_del_route;
    driver->close        = tun_close;
    driver->exclude_rt   = tun_exclude_rt;
    driver->get_name = get_tun_name;
    uv_timer_init(loop, &tun->route_timer);
    tun->route_timer.data = tun;
    uv_unref((uv_handle_t *) &tun->route_timer);
    uv_timer_start(&tun->route_timer, refresh_routes, ROUTE_REFRESH, ROUTE_REFRESH);

    if (cidr4) {
        tun_add_route(tun, cidr4);
    }
    if (cidr6) {
        tun_add_route(tun, cidr6);
    }


    return driver;
}

static int tun_close(struct netif_handle_s *tun) {
    if (tun == NULL) {
        return 0;
    }

    if (tun->session) {
        WintunEndSession(tun->session);
        tun->session = NULL;
    }

    if (tun->adapter) {
        WintunCloseAdapter(tun->adapter);
        tun->adapter = NULL;
    }
    free(tun);
    flush_dns();
    return 0;
}

static void tun_reader(void *h) {
    netif_handle tun = h;
    HANDLE readEv = WintunGetReadWaitEvent(tun->session);

    if (!readEv) {
        DWORD err = GetLastError();
        ZITI_LOG(ERROR, "failed to get ReadWaitEvent from(%p) err=%d", readEv, tun->session, err);
        return;
    }

    while(true) {
        DWORD rc = WaitForSingleObject(readEv, INFINITE);
        if (rc != WAIT_OBJECT_0) {
            DWORD err = GetLastError();
            ZITI_LOG(ERROR, "failed waiting for wintun read event(%p) from(%p) %d(err=%d)", readEv, tun->adapter, rc, err);
            break;
        }

        uv_async_send(tun->read_available);
    }
}

static void tun_read(uv_async_t *ar) {
    ZITI_LOG(TRACE, "starting read");
    netif_handle tun = ar->data;

    for (int i = 0; i < 128; i++) {
        DWORD len;
        BYTE *packet = WintunReceivePacket(tun->session, &len);
        
        if (packet) {
            tun->on_packet((const char*)packet, len, tun->netif);
            WintunReleaseReceivePacket(tun->session, packet);
        } else {
            DWORD error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS) {
                // done reading
                SetEvent(tun->read_complete);
            } else {
                ZITI_LOG(ERROR, "failed to receive packet: %d", error);
            }
            break;
        }
    }
}

int tun_setup_read(netif_handle tun, uv_loop_t *loop, packet_cb on_packet, void *netif) {
    ZITI_LOG(DEBUG, "tun=%p, adapter=%p, session=%p", tun, tun->adapter, tun->session);

    tun->on_packet = on_packet;
    tun->netif = netif;

    tun->read_available = calloc(1, sizeof(uv_async_t));
    uv_async_init(loop, tun->read_available, tun_read);
    tun->read_available->data = tun;

    tun->read_complete = CreateEventW(NULL, TRUE, FALSE, NULL);
    uv_thread_create(&tun->reader, tun_reader, tun);
    return 0;
}

ssize_t tun_write(netif_handle tun, const void *buf, size_t len) {
    BYTE* packet = WintunAllocateSendPacket(tun->session, len);
    memcpy(packet, buf, len);
    WintunSendPacket(tun->session, packet);
    return 0;
}

static int parse_ipv6(const char *str, uint8_t *addr) {
 uint16_t temp_addr[8] = {0};
 int double_colon_index = -1;
 int segment_count = 0;
 const char *ptr = str;
 
 // Initialize temporary address to all zeros
 memset(addr, 0, 16);
 
 //printf("Parsing IPv6 address: %s\n", str);//接收的字符串写出来，[2408:
 
 // Iterate through the input string
 while (*ptr) {
     if (segment_count > 7) {
         printf("Error: Too many segments\n");
         return -1; // Too many segments
     }
 
     if (*ptr == ':') {
         if (ptr == str || *(ptr - 1) == ':') {
             if (double_colon_index != -1) {
                // printf("Error: More than one '::' found\n");
                 return -1; // More than one '::' found
             }
             double_colon_index = segment_count;//遇到::左移一位
             //printf("Found '::' at segment %d\n", segment_count);
             ptr++;
             if (*ptr == ':') {
                 ptr++; // skip the second colon in '::'
             }
             continue;
         }
         ptr++;
         continue;
     }
 
     char segment_str[5] = {0}; // Maximum length of a segment is 4 digits
     int segment_len = 0;
 
     while (*ptr && *ptr != ':' && segment_len < 4) {
         if (!isxdigit(*ptr)) {
             printf("Error: Invalid character '%c' in segment\n", *ptr);
             return -1; // Invalid character
         }
         segment_str[segment_len++] = *ptr++;
     }
 
     if (segment_len == 0) {
         printf("Error: Empty segment\n");
         return -1; // Empty segment
     }
 
     temp_addr[segment_count] = (uint16_t)strtol(segment_str, NULL, 16);
     //printf("Parsed segment %d: %x\n", segment_count, temp_addr[segment_count]);
     segment_count++;
 }
 
 if (segment_count == 0) {
     printf("Error: No segments found\n");
     return -1; // No segments found
 }
 
 if (double_colon_index != -1) {
     int num_to_copy = segment_count - double_colon_index;
     memmove(&temp_addr[8 - num_to_copy], &temp_addr[double_colon_index], num_to_copy * sizeof(uint16_t));
     memset(&temp_addr[double_colon_index], 0, (8 - segment_count) * sizeof(uint16_t));
     //printf("Adjusted segments for '::' shorthand\n");
     segment_count = 8; // Correct segment count after handling '::'
 }
 
 for (int i = 0; i < 8; i++) {
     addr[2 * i] = (uint8_t)(temp_addr[i] >> 8);
     addr[2 * i + 1] = (uint8_t)(temp_addr[i] & 0xff);
 }
 
 //printf("Parsed IPv6 address: ");
 //for (int i = 0; i < 16; i++) {
 //    printf("%02x", addr[i]);
 //    if (i % 2 && i != 15) {
 //        printf(":");
 //    }
 //}
 //printf("\n");
 
 return 0;
}
static int parse_route(PIP_ADDRESS_PREFIX pfx, const char *route) {
	int ip[4];
	int bits;
	if (strchr(route, ':')) { // IPv6
	 char addr[40];
	 int rc = sscanf_s(route, "%39[^/]/%d", addr, (unsigned)_countof(addr), &bits);
	 // printf("route: %s\n", route);
	 // printf("addr: %s\n", addr);
	 // printf("bits: %d\n", bits);
	 // printf("rc: %d\n", rc);
	 if (rc < 1) {
	     printf("invalid IPV6 route spec[%s]\n", route);
	     return -1;
	 } else {
	     pfx->PrefixLength = rc == 1 ? 128 : bits;
	     pfx->Prefix.Ipv6.sin6_family = AF_INET6;
	     if (parse_ipv6(addr, pfx->Prefix.Ipv6.sin6_addr.s6_addr) != 0) {
	         printf("invalid IPV6 address[%s]\n", addr);
	         return -1;
	     }
	 }
	} else { // IPv4
	 int rc = sscanf_s(route, "%d.%d.%d.%d/%d", &ip[0], &ip[1], &ip[2], &ip[3], &bits);
	 if (rc < 4) {
	     printf("invalid IPV4 route spec[%s]\n", route);
	     return -1;
	 } else {
	     pfx->PrefixLength = rc == 4 ? 32 : bits;
	     pfx->Prefix.Ipv4.sin_family = AF_INET;
	     pfx->Prefix.Ipv4.sin_addr.S_un.S_addr = (ip[0]) | (ip[1] << 8) | (ip[2] << 16) | (ip[3] << 24);
	 }
	 //printf("=========5====解析一个IPv4路由得到ip和掩码:%s ===========\n", route);
	}
	return 0;
}


typedef NTSTATUS(__stdcall *route_f)(const MIB_IPFORWARD_ROW2*);

static DWORD tun_do_route(netif_handle tun, const char *dest, route_f rt_f) {
    MIB_IPFORWARD_ROW2 rt;
    InitializeIpForwardEntry(&rt);

    rt.InterfaceLuid = tun->luid;
    parse_route(&rt.DestinationPrefix, dest);

    return rt_f(&rt);
}

int tun_add_route(netif_handle tun, const char *dest) {
    ZITI_LOG(DEBUG, "adding route: %s", dest);
    DWORD rc = tun_do_route(tun, dest, CreateIpForwardEntry2);
    if (rc != 0 && rc != ERROR_OBJECT_ALREADY_EXISTS) {
        DWORD err = GetLastError();
        ZITI_LOG(WARN, "failed to add route %d err=%d", rc, err);
    }
    return 0;
}

int tun_del_route(netif_handle tun, const char *dest) {
    ZITI_LOG(DEBUG, "removing route: %s", dest);
    DWORD rc = tun_do_route(tun, dest, DeleteIpForwardEntry2);
    if (rc != 0) {
        DWORD err = GetLastError();
        ZITI_LOG(WARN, "failed to delete route %d err=%d", rc, err);
    }
    return 0;
}

static void WINAPI if_change_cb(PVOID CallerContext, PMIB_IPINTERFACE_ROW Row, MIB_NOTIFICATION_TYPE NotificationType) {
    struct netif_handle_s *tun = CallerContext;

    MIB_IPFORWARD_ROW2 rt = {0};
    rt.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    ZITI_LOG(DEBUG, "interface change: if_idx = %d, change = %d", Row ? Row->InterfaceIndex : 0, NotificationType);
    int rc = GetIpForwardEntry2(&rt);
    if (rc == NO_ERROR) {
        if (default_rt.InterfaceIndex != rt.InterfaceIndex) {
            ZITI_LOG(INFO, "default route is now via if_idx[%d]", rt.InterfaceIndex);
            default_rt.InterfaceIndex = rt.InterfaceIndex;
            default_rt.InterfaceLuid = rt.InterfaceLuid;
            default_rt.Metric = rt.Metric;
            default_rt.NextHop = rt.NextHop;

            ZITI_LOG(INFO, "updating excluded routes");
            const char *dest;
            MIB_IPFORWARD_ROW2 *route;
            MODEL_MAP_FOREACH(dest, route, &tun->excluded_routes) {
                route->NextHop = rt.NextHop;
                route->InterfaceIndex = rt.InterfaceIndex;
                route->InterfaceLuid = rt.InterfaceLuid;
                if (SetIpForwardEntry2(route) != NO_ERROR) {
                    char err[256];
                    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                  err, sizeof(err), NULL);
                    ZITI_LOG(WARN, "failed to update route[%s]: %d(%s)", dest, rc, err);
                }
            }
        }
    } else {
        char err[256];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      err, sizeof(err), NULL);
        ZITI_LOG(WARN, "failed to get default route: %d(%s)", rc, err);
    }
}

static int tun_exclude_rt(netif_handle dev, uv_loop_t *loop, const char *dest) {

    MIB_IPFORWARD_ROW2 *route = calloc(1, sizeof(MIB_IPFORWARD_ROW2));
    route->DestinationPrefix.Prefix.si_family = AF_INET;
    parse_route(&route->DestinationPrefix, dest);
    int rc = GetIpForwardEntry2(route);
    if (rc == NO_ERROR) {
        ZITI_LOG(DEBUG, "route to %s found", dest);
        DeleteIpForwardEntry2(route);
    }

    route->InterfaceIndex = default_rt.InterfaceIndex;
    route->InterfaceLuid = default_rt.InterfaceLuid;
    route->Metric = 0;
    route->NextHop = default_rt.NextHop;
    route->ValidLifetime = ROUTE_LIFETIME;
    route->PreferredLifetime = ROUTE_LIFETIME;

    rc = CreateIpForwardEntry2(route);
    if (rc != NO_ERROR) {
        char err[256];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      err, sizeof(err), NULL);
        ZITI_LOG(WARN, "failed to create exclusion route: %d(%s)", rc, err);
    }
    model_map_set(&dev->excluded_routes, dest, route);
    return 0;
}

void refresh_routes(uv_timer_t *timer) {
    ZITI_LOG(DEBUG, "refreshing excluded routes");
    struct netif_handle_s *tun = timer->data;
    const char *dest;
    MIB_IPFORWARD_ROW2 *route;
    MODEL_MAP_FOREACH(dest, route, &tun->excluded_routes) {
        ZITI_LOG(DEBUG, "refreshing route to %s", dest);
        int rc = SetIpForwardEntry2(route);
        if (rc != NO_ERROR) {
        char err[256];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      err, sizeof(err), NULL);
            ZITI_LOG(WARN, "failed to create exclusion route[%s]: %d(%s)", dest, rc, err);
        }
    }
}

int is_windows_10_or_later() {
	OSVERSIONINFOEXW osvi;
	DWORDLONG condition_mask = 0;
     
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW); 
	osvi.dwMajorVersion = 10; // Windows 10 的主版本号
     
	VER_SET_CONDITION(condition_mask, VER_MAJORVERSION, VER_GREATER_EQUAL);
	return VerifyVersionInfoW(&osvi, VER_MAJORVERSION, condition_mask);
}
 
// 设置 IPv6 DNS
int set_ip6_dns(netif_handle tun, struct ip6_addr dns_ip6) {
    // printf("开始设置ipv6 DNS\n");
    char cmd[2048];
    char dns_ipv6_str[INET6_ADDRSTRLEN];
    const char *tun_name = get_tun_name(tun);

    // 使用inet_ntop转换ip6_addr到字符串
    inet_ntop(AF_INET6, &dns_ip6, dns_ipv6_str, INET6_ADDRSTRLEN);
    ZITI_LOG(INFO, "DNS地址设置为：%s", dns_ipv6_str);
 
    if (is_windows_10_or_later()) {
        snprintf(cmd, sizeof(cmd),
                 "powershell -Command \"Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses %s\"",
                 tun_name, dns_ipv6_str);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "netsh interface ipv6 set dnsservers name=\"%s\" static %s validate=no",
                 tun_name, dns_ipv6_str);
    }
 
    ZITI_LOG(INFO, "执行命令：'%s'", cmd);
    int rc = system(cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "设置 IPv6 DNS 失败，返回码: %d, 错误: %ld", rc, GetLastError());
    } else {
        ZITI_LOG(INFO, "成功设置 IPv6 DNS。");
    }
 
    return rc;
}

int set_dns(netif_handle tun, uint32_t dns_ip) {
    char cmd[1024];
    unsigned char ip[4];
    const char *tun_name = get_tun_name(tun);
    printf("tun_name: %s\n", tun_name);
    int rc;
    dns_ip = htonl(dns_ip); // 将 dns_ip 转为网络字节序
    ip[0] = (dns_ip >> 24) & 0xFF;
    ip[1] = (dns_ip >> 16) & 0xFF;
    ip[2] = (dns_ip >> 8) & 0xFF;
    ip[3] = dns_ip & 0xFF;

    ZITI_LOG(INFO, "DNS地址设置为：%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    
    if (is_windows_10_or_later()) {
        // 使用 PowerShell
        snprintf(cmd, sizeof(cmd),
                "powershell -Command \"Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses %u.%u.%u.%u\"",
                tun_name, ip[0], ip[1], ip[2], ip[3]);
    } else {
        // 使用 netsh
        snprintf(cmd, sizeof(cmd),
                "netsh interface ip set dns name=\"%s\" source=static addr=%u.%u.%u.%u",
                tun_name, ip[0], ip[1], ip[2], ip[3]);
    }

    ZITI_LOG(INFO, "执行命令：'%s'", cmd);
    rc = system(cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "设置 IPv4 DNS 失败，返回码: %d, 错误: %ld", rc, GetLastError());
    } else {
        ZITI_LOG(INFO, "成功设置 IPv4 DNS。");
    }

    return rc;
}
 
static BOOL CALLBACK
tun_delete_cb(_In_ WINTUN_ADAPTER_HANDLE to_delete, _In_ LPARAM param) {
    ZITI_LOG(INFO, "Deleting wintun adapter");
    WintunCloseAdapter(to_delete);
    // the call back should always return value greater than zero, so the cleanup function will continue
    return 1;
}
