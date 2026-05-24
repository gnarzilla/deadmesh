/**
 * Deadlight Meshtastic VPN Gateway - Kernel TCP Implementation
 * Uses real kernel sockets, no userspace TCP stack
 * Phase 1: IPv4 TCP/UDP Support
 *
 * NOTE: The TUN/TAP VPN gateway is Linux-only (linux/if.h, linux/if_tun.h,
 * TUNSETIFF, /dev/net/tun). On macOS the public API is stubbed out so the
 * rest of the project builds cleanly. VPN functionality simply won't be
 * available when running on Darwin.
 */

#ifdef __APPLE__

#include "vpn_gateway.h"
#include "core/logging.h"

gboolean deadlight_vpn_gateway_init(DeadlightContext *context, GError **error) {
    (void)context;
    (void)error;
    log_warn("VPN: TUN/TAP gateway is not supported on macOS — skipping init");
    return TRUE;  /* non-fatal: let the rest of the daemon start */
}

void deadlight_vpn_gateway_cleanup(DeadlightContext *context) {
    (void)context;
}

void deadlight_vpn_gateway_get_stats(DeadlightContext *context,
                                     guint64 *active_connections,
                                     guint64 *total_connections,
                                     guint64 *bytes_sent,
                                     guint64 *bytes_received,
                                     guint *pooled_connections,
                                     gdouble *pool_hit_rate) {
    (void)context;
    if (active_connections)   *active_connections  = 0;
    if (total_connections)    *total_connections   = 0;
    if (bytes_sent)           *bytes_sent          = 0;
    if (bytes_received)       *bytes_received      = 0;
    if (pooled_connections)   *pooled_connections  = 0;
    if (pool_hit_rate)        *pool_hit_rate       = 0.0;
}

#else /* Linux — full implementation below */

/**
 * Deadlight Meshtastic VPN Gateway - Kernel TCP Implementation
 * Uses real kernel sockets, no userspace TCP stack
 * Phase 1: IPv4 TCP/UDP Support
 */
#include "vpn_gateway.h"
#include "core/deadlight.h"
#include "core/logging.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

//=============================================================================
// IP/TCP Header Structures and Constants
//=============================================================================

// TCP flags
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20


struct icmpv6_header {
    guint8 type;
    guint8 code;
    guint16 checksum;
    guint32 body;  // Varies by type
} __attribute__((packed));

// ICMPv6 types
#define ICMPV6_ECHO_REQUEST  128
#define ICMPV6_ECHO_REPLY    129
#define ICMPV6_ROUTER_SOLICIT 133
#define ICMPV6_ROUTER_ADVERT  134
#define ICMPV6_NEIGHBOR_SOLICIT 135
#define ICMPV6_NEIGHBOR_ADVERT  136

struct nd_router_advert {
    guint8 hop_limit;
    guint8 flags;  // M and O flags
    guint16 lifetime;
    guint32 reachable_time;
    guint32 retrans_timer;
} __attribute__((packed));

struct nd_opt_prefix_info {
    guint8 type;  // 3 for prefix information
    guint8 length;  // 4 (in units of 8 bytes)
    guint8 prefix_len;
    guint8 flags;  // L and A flags
    guint32 valid_lifetime;
    guint32 preferred_lifetime;
    guint32 reserved;
    struct in6_addr prefix;
} __attribute__((packed));

struct nd_neighbor_solicit {
    guint32 reserved;
    struct in6_addr target;
} __attribute__((packed));

struct nd_neighbor_advert {
    guint8 flags;  // R, S, O flags
    guint8 reserved[3];
    struct in6_addr target;
} __attribute__((packed));

struct nd_opt_link_addr {
    guint8 type;  // 1 for source, 2 for target
    guint8 length;  // 1 (in units of 8 bytes)
    guint8 addr[6];  // MAC address
} __attribute__((packed));

// IP header (simplified, 20 bytes without options)
struct ip_header {
    guint8 version_ihl;      // Version (4 bits) + IHL (4 bits)
    guint8 tos;              // Type of service
    guint16 total_length;    // Total length
    guint16 identification;  // Identification
    guint16 flags_offset;    // Flags (3 bits) + Fragment offset (13 bits)
    guint8 ttl;              // Time to live
    guint8 protocol;         // Protocol (TCP=6, UDP=17, ICMP=1)
    guint16 checksum;        // Header checksum
    guint32 src_addr;        // Source address
    guint32 dest_addr;       // Destination address
} __attribute__((packed));

// TCP header (simplified, 20 bytes without options)
struct tcp_header {
    guint16 src_port;        // Source port
    guint16 dest_port;       // Destination port
    guint32 seq_num;         // Sequence number
    guint32 ack_num;         // Acknowledgment number
    guint8 data_offset_flags;// Data offset (4 bits) + Reserved (3 bits) + Flags (1 bit)
    guint8 flags;            // Flags: FIN, SYN, RST, PSH, ACK, URG
    guint16 window_size;     // Window size
    guint16 checksum;        // Checksum
    guint16 urgent_pointer;  // Urgent pointer
} __attribute__((packed));

// IPv6 header (40 bytes fixed)
struct ipv6_header {
    guint32 version_tc_fl;   // Version(4) + Traffic class(8) + Flow label(20)
    guint16 payload_length;  // Payload length
    guint8 next_header;      // Next header (TCP=6, UDP=17, ICMPv6=58)
    guint8 hop_limit;        // Hop limit (like TTL)
    struct in6_addr src_addr;  // Source address (128 bits)
    struct in6_addr dest_addr; // Destination address (128 bits)
} __attribute__((packed));

// UDP header (8 bytes)
struct udp_header {
    guint16 src_port;
    guint16 dest_port;
    guint16 length;
    guint16 checksum;
} __attribute__((packed));

// VPNUDPSession is defined in vpn_gateway.h
// No need to redefine it here

//=============================================================================
// Forward Declarations
//=============================================================================

static gint create_tun_device(const gchar *dev_name, GError **error);
static gboolean configure_tun_device(const gchar *dev_name, const gchar *ip,
                                    const gchar *netmask, GError **error);
static gboolean on_tun_readable(GIOChannel *source, GIOCondition condition,
                               gpointer user_data);
static gboolean on_upstream_readable(GIOChannel *source, GIOCondition condition,
                                    gpointer user_data);
static gboolean on_udp_upstream_readable(GIOChannel *source, GIOCondition condition,
                                        gpointer user_data);
static void handle_ip_packet(DeadlightVPNManager *vpn, guint8 *packet,
                             gsize packet_len);
static void handle_tcp_packet(DeadlightVPNManager *vpn, struct ip_header *ip_hdr,
                              struct tcp_header *tcp_hdr, guint8 *payload,
                              gsize payload_len);
static void handle_udp_packet(DeadlightVPNManager *vpn, struct ip_header *ip_hdr,
                              struct udp_header *udp_hdr, guint8 *payload,
                              gsize payload_len);
static void send_tcp_packet(DeadlightVPNManager *vpn, VPNSession *session,
                           guint8 flags, const guint8 *payload, gsize payload_len);
static void send_udp_packet(DeadlightVPNManager *vpn, VPNUDPSession *session,
                           const guint8 *payload, gsize payload_len);
static guint16 ip_checksum(const void *data, gsize len);
static guint16 tcp_checksum(guint32 src_ip, guint32 dest_ip,
                           const void *tcp_data, gsize tcp_len);
static guint16 udp_checksum(guint32 src_ip, guint32 dest_ip,
                           const void *udp_data, gsize udp_len);
static VPNSession *vpn_session_new(DeadlightVPNManager *vpn, guint32 client_ip,
                                   guint16 client_port, guint32 dest_ip,
                                   guint16 dest_port);
static void vpn_session_free(VPNSession *session);
static VPNUDPSession *vpn_udp_session_new(DeadlightVPNManager *vpn, guint32 client_ip,
                                          guint16 client_port, guint32 dest_ip,
                                          guint16 dest_port);
static void vpn_udp_session_free(VPNUDPSession *session);
static gboolean cleanup_idle_sessions(gpointer user_data);
static gboolean cleanup_idle_udp_sessions(gpointer user_data);
static guint16 tcp6_checksum(const struct in6_addr *src_addr,
                            const struct in6_addr *dest_addr,
                            const void *tcp_data, gsize tcp_len);
static guint16 udp6_checksum(const struct in6_addr *src_addr,
                            const struct in6_addr *dest_addr,
                            const void *udp_data, gsize udp_len);
static void send_tcp6_packet(DeadlightVPNManager *vpn, VPNSession *session,
                            guint8 flags, const guint8 *payload, gsize payload_len);
static void send_udp6_packet(DeadlightVPNManager *vpn, VPNUDPSession *session,
                            const guint8 *payload, gsize payload_len);
static void handle_tcp6_packet(DeadlightVPNManager *vpn, struct ipv6_header *ip6_hdr,
                              struct tcp_header *tcp_hdr, guint8 *payload, gsize payload_len);
static void handle_udp6_packet(DeadlightVPNManager *vpn, struct ipv6_header *ip6_hdr,
                              struct udp_header *udp_hdr, guint8 *payload, gsize payload_len);
static void handle_ipv6_packet(DeadlightVPNManager *vpn, guint8 *packet, gsize packet_len);

//=============================================================================
// Helper functions
//=============================================================================

static inline void ipv4_to_mapped(guint32 ipv4_be, struct in6_addr *out)
{
    memset(out->s6_addr, 0, 16);
#ifdef __GLIBC__
    out->__in6_u.__u6_addr8[10] = 0xFF;
    out->__in6_u.__u6_addr8[11] = 0xFF;
    memcpy(&out->__in6_u.__u6_addr8[12], &ipv4_be, 4);
#else
    out->s6_addr[10] = 0xFF;
    out->s6_addr[11] = 0xFF;
    memcpy(&out->s6_addr[12], &ipv4_be, 4);
#endif
}

static inline guint32 mapped_to_ipv4(const struct in6_addr *addr)
{
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
#ifdef __GLIBC__
        return ntohl(*(guint32*)&addr->__in6_u.__u6_addr8[12]);
#else
        return ntohl(*(guint32*)&addr->s6_addr[12]);
#endif
    }
    return 0; /* not mapped */
}

static gchar* make_session_key(const struct in6_addr *src, guint16 sport,
                               const struct in6_addr *dst, guint16 dport)
{
    gchar src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, src, src_str, sizeof(src_str));
    inet_ntop(AF_INET6, dst, dst_str, sizeof(dst_str));

    if (IN6_IS_ADDR_V4MAPPED(src) && IN6_IS_ADDR_V4MAPPED(dst)) {
        /* IPv4-mapped → use dotted notation (no brackets) */
        gchar src4[INET_ADDRSTRLEN], dst4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src->s6_addr[12], src4, sizeof(src4));
        inet_ntop(AF_INET, &dst->s6_addr[12], dst4, sizeof(dst4));
        return g_strdup_printf("%s:%u->%s:%u", src4, sport, dst4, dport);
    } else {
        return g_strdup_printf("[%s]:%u->[%s]:%u", src_str, sport, dst_str, dport);
    }
}

static void handle_icmpv6_packet(DeadlightVPNManager *vpn, struct ipv6_header *ip6_hdr,
                                 struct icmpv6_header *icmp_hdr, guint8 *payload,
                                 gsize payload_len) {
    gchar src_str[INET6_ADDRSTRLEN];
    gchar dest_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6_hdr->src_addr, src_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6_hdr->dest_addr, dest_str, INET6_ADDRSTRLEN);
    
    log_debug("VPN: ICMPv6 packet: %s -> %s (type=%d, code=%d)",
             src_str, dest_str, icmp_hdr->type, icmp_hdr->code);
    
    // Handle echo requests (ping6)
    if (icmp_hdr->type == ICMPV6_ECHO_REQUEST) {
        // Build echo reply
        guint8 reply_packet[1500];
        struct ipv6_header *reply_ip6 = (struct ipv6_header *)reply_packet;
        struct icmpv6_header *reply_icmp = (struct icmpv6_header *)(reply_packet + sizeof(struct ipv6_header));
        
        // IPv6 header
        memset(reply_ip6, 0, sizeof(struct ipv6_header));
        reply_ip6->version_tc_fl = htonl(0x60000000);
        reply_ip6->payload_length = htons(sizeof(struct icmpv6_header) + payload_len);
        reply_ip6->next_header = 58;  // ICMPv6
        reply_ip6->hop_limit = 64;
        memcpy(&reply_ip6->src_addr, &ip6_hdr->dest_addr, sizeof(struct in6_addr));
        memcpy(&reply_ip6->dest_addr, &ip6_hdr->src_addr, sizeof(struct in6_addr));
        
        // ICMPv6 header
        reply_icmp->type = ICMPV6_ECHO_REPLY;
        reply_icmp->code = 0;
        reply_icmp->checksum = 0;
        reply_icmp->body = icmp_hdr->body;  // Copy ID and sequence
        
        // Copy payload
        if (payload_len > 0) {
            memcpy(reply_packet + sizeof(struct ipv6_header) + sizeof(struct icmpv6_header),
                   payload, payload_len);
        }
        
        // Calculate checksum using aligned copies (fixes warning)
        struct in6_addr src_copy, dest_copy;
        memcpy(&src_copy, &reply_ip6->src_addr, sizeof(struct in6_addr));
        memcpy(&dest_copy, &reply_ip6->dest_addr, sizeof(struct in6_addr));
        reply_icmp->checksum = udp6_checksum(&src_copy, &dest_copy,
                                            reply_icmp, sizeof(struct icmpv6_header) + payload_len);
        
        // Send reply
        gsize total_len = sizeof(struct ipv6_header) + sizeof(struct icmpv6_header) + payload_len;
        gssize written = write(vpn->tun_fd, reply_packet, total_len);
        if (written > 0) {
            log_debug("VPN: Sent ICMPv6 echo reply to %s", src_str);
        }
    }
    // Handle Router Solicitation - send Router Advertisement
    else if (icmp_hdr->type == ICMPV6_ROUTER_SOLICIT) {
        log_info("VPN: Sending Router Advertisement in response to solicitation from %s", src_str);
        
        guint8 ra_packet[1500];
        memset(ra_packet, 0, sizeof(ra_packet));
        
        struct ipv6_header *ra_ip6 = (struct ipv6_header *)ra_packet;
        struct icmpv6_header *ra_icmp = (struct icmpv6_header *)(ra_packet + sizeof(struct ipv6_header));
        struct nd_router_advert *ra = (struct nd_router_advert *)(ra_packet + sizeof(struct ipv6_header) + sizeof(struct icmpv6_header));
        
        // IPv6 header
        ra_ip6->version_tc_fl = htonl(0x60000000);
        ra_ip6->next_header = 58;  // ICMPv6
        ra_ip6->hop_limit = 255;  // Must be 255 for ND
        
        // Source: link-local address of gateway (fe80::1)
        memset(&ra_ip6->src_addr, 0, sizeof(struct in6_addr));
        ra_ip6->src_addr.s6_addr[0] = 0xfe;
        ra_ip6->src_addr.s6_addr[1] = 0x80;
        ra_ip6->src_addr.s6_addr[15] = 0x01;
        
        // Destination: all-nodes multicast (ff02::1) or source address
        struct in6_addr src_addr_copy;
        memcpy(&src_addr_copy, &ip6_hdr->src_addr, sizeof(struct in6_addr));
        if (IN6_IS_ADDR_LINKLOCAL(&src_addr_copy)) {
            memcpy(&ra_ip6->dest_addr, &src_addr_copy, sizeof(struct in6_addr));
        } else {
            // All nodes multicast
            memset(&ra_ip6->dest_addr, 0, sizeof(struct in6_addr));
            ra_ip6->dest_addr.s6_addr[0] = 0xff;
            ra_ip6->dest_addr.s6_addr[1] = 0x02;
            ra_ip6->dest_addr.s6_addr[15] = 0x01;
        }
        
        // ICMPv6 header
        ra_icmp->type = ICMPV6_ROUTER_ADVERT;
        ra_icmp->code = 0;
        ra_icmp->checksum = 0;
        
        // Router Advertisement
        ra->hop_limit = 64;
        ra->flags = 0x00;  // No managed/other config
        ra->lifetime = htons(1800);  // 30 minutes
        ra->reachable_time = 0;
        ra->retrans_timer = 0;
        
        // Add Prefix Information option
        struct nd_opt_prefix_info *prefix = (struct nd_opt_prefix_info *)((guint8 *)ra + sizeof(struct nd_router_advert));
        prefix->type = 3;  // Prefix Information
        prefix->length = 4;  // 32 bytes / 8
        prefix->prefix_len = 64;
        prefix->flags = 0xC0;  // L=1, A=1 (on-link and autonomous)
        prefix->valid_lifetime = htonl(86400);  // 1 day
        prefix->preferred_lifetime = htonl(43200);  // 12 hours
        prefix->reserved = 0;
        
        // Set prefix to fd00:dead:beef::/64
        memset(&prefix->prefix, 0, sizeof(struct in6_addr));
        prefix->prefix.s6_addr[0] = 0xfd;
        prefix->prefix.s6_addr[1] = 0x00;
        prefix->prefix.s6_addr[2] = 0xde;
        prefix->prefix.s6_addr[3] = 0xad;
        prefix->prefix.s6_addr[4] = 0xbe;
        prefix->prefix.s6_addr[5] = 0xef;
        
        gsize icmp_len = sizeof(struct icmpv6_header) + sizeof(struct nd_router_advert) + sizeof(struct nd_opt_prefix_info);
        ra_ip6->payload_length = htons(icmp_len);
        
        // Calculate checksum
        struct in6_addr src_copy, dest_copy;
        memcpy(&src_copy, &ra_ip6->src_addr, sizeof(struct in6_addr));
        memcpy(&dest_copy, &ra_ip6->dest_addr, sizeof(struct in6_addr));
        ra_icmp->checksum = udp6_checksum(&src_copy, &dest_copy, ra_icmp, icmp_len);
        
        gsize total_len = sizeof(struct ipv6_header) + icmp_len;
        gssize written = write(vpn->tun_fd, ra_packet, total_len);
        if (written > 0) {
            log_info("VPN: Sent Router Advertisement with prefix fd00:dead:beef::/64");
        }
    }
    // Handle Neighbor Solicitation
    else if (icmp_hdr->type == ICMPV6_NEIGHBOR_SOLICIT) {
        struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit *)payload;
        gchar target_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ns->target, target_str, INET6_ADDRSTRLEN);
        
        log_debug("VPN: Neighbor solicitation for %s from %s", target_str, src_str);
        
        // Check if it's asking for our address (gateway)
        struct in6_addr gateway_addr;
        memset(&gateway_addr, 0, sizeof(struct in6_addr));
        gateway_addr.s6_addr[0] = 0xfe;
        gateway_addr.s6_addr[1] = 0x80;
        gateway_addr.s6_addr[15] = 0x01;
        
        if (memcmp(&ns->target, &gateway_addr, sizeof(struct in6_addr)) == 0) {
            // Send Neighbor Advertisement
            guint8 na_packet[1500];
            memset(na_packet, 0, sizeof(na_packet));
            
            struct ipv6_header *na_ip6 = (struct ipv6_header *)na_packet;
            struct icmpv6_header *na_icmp = (struct icmpv6_header *)(na_packet + sizeof(struct ipv6_header));
            struct nd_neighbor_advert *na = (struct nd_neighbor_advert *)((guint8 *)na_icmp + sizeof(struct icmpv6_header));
            
            // IPv6 header
            na_ip6->version_tc_fl = htonl(0x60000000);
            na_ip6->next_header = 58;
            na_ip6->hop_limit = 255;
            memcpy(&na_ip6->src_addr, &gateway_addr, sizeof(struct in6_addr));
            memcpy(&na_ip6->dest_addr, &ip6_hdr->src_addr, sizeof(struct in6_addr));
            
            // ICMPv6 header
            na_icmp->type = ICMPV6_NEIGHBOR_ADVERT;
            na_icmp->code = 0;
            
            // Neighbor Advertisement
            na->flags = 0x60;  // Router=0, Solicited=1, Override=1
            memcpy(&na->target, &gateway_addr, sizeof(struct in6_addr));
            
            // Add Target Link-Layer Address option
            struct nd_opt_link_addr *opt = (struct nd_opt_link_addr *)((guint8 *)na + sizeof(struct nd_neighbor_advert));
            opt->type = 2;  // Target Link-Layer Address
            opt->length = 1;  // 8 bytes

            // Use a dummy MAC for TUN device (doesn't actually need MAC)
            opt->addr[0] = 0x02;
            opt->addr[1] = 0x00;
            opt->addr[2] = 0x00;
            opt->addr[3] = 0x00;
            opt->addr[4] = 0x00;
            opt->addr[5] = 0x01;
            
            gsize icmp_len = sizeof(struct icmpv6_header) + sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_link_addr);
            na_ip6->payload_length = htons(icmp_len);
            
            // Calculate checksum
            struct in6_addr src_copy, dest_copy;
            memcpy(&src_copy, &na_ip6->src_addr, sizeof(struct in6_addr));
            memcpy(&dest_copy, &na_ip6->dest_addr, sizeof(struct in6_addr));
            na_icmp->checksum = udp6_checksum(&src_copy, &dest_copy, na_icmp, icmp_len);
            
            gsize total_len = sizeof(struct ipv6_header) + icmp_len;
            gssize written = write(vpn->tun_fd, na_packet, total_len);
            if (written > 0) {
                log_debug("VPN: Sent Neighbor Advertisement for gateway");
            }
        }
    }
    // Log other ICMPv6 types for debugging
    else {
        const char *type_name = "Unknown";
        switch (icmp_hdr->type) {
            case 1: type_name = "Destination Unreachable"; break;
            case 2: type_name = "Packet Too Big"; break;
            case 3: type_name = "Time Exceeded"; break;
            case 4: type_name = "Parameter Problem"; break;
            case 130: type_name = "Multicast Listener Query"; break;
            case 131: type_name = "Multicast Listener Report"; break;
            case 132: type_name = "Multicast Listener Done"; break;
            case 137: type_name = "Redirect"; break;
        }
        log_debug("VPN: ICMPv6 %s (type=%d) from %s", type_name, icmp_hdr->type, src_str);
    }
}

//=============================================================================
// TUN Device Management
//=============================================================================

static gint create_tun_device(const gchar *dev_name, GError **error) {
    struct ifreq ifr;
    gint fd;
    gchar *mtu_cmd = g_strdup_printf("ip link set %s mtu 1420", dev_name);
    int ret = system(mtu_cmd);
    (void)ret;  
    g_free(mtu_cmd);

    // First, try to delete any existing device with this name
    if (dev_name) {
        gchar *cmd = g_strdup_printf("ip link delete %s 2>/dev/null", dev_name);
        int ret = system(cmd);
        (void)ret;  // Explicitly ignore return value
        g_free(cmd);
        
        // Give the kernel a moment to clean up
        g_usleep(100000);  // 100ms
    }

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno),
                   "Failed to open /dev/net/tun: %s", g_strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (dev_name) {
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
    }

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errno),
                   "TUNSETIFF ioctl failed: %s", g_strerror(errno));
        close(fd);
        return -1;
    }

    log_info("VPN: Created TUN device %s (fd=%d)", ifr.ifr_name, fd);
    return fd;
}

static gboolean configure_tun_device(const gchar *dev_name, const gchar *ip,
                                    const gchar *netmask, GError **error) {
    gchar *cmd;
    gint ret;

    // Bring interface up
    cmd = g_strdup_printf("ip link set %s up", dev_name);
    ret = system(cmd);
    (void)ret;
    g_free(cmd);
    if (ret != 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to bring up %s", dev_name);
        return FALSE;
    }

    // Set IPv4 address
    cmd = g_strdup_printf("ip addr add %s/%s dev %s", ip, netmask, dev_name);
    ret = system(cmd);
    (void)ret;
    g_free(cmd);
    if (ret != 0) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to set IP on %s", dev_name);
        return FALSE;
    }

    // Add IPv6 address (link-local)
    cmd = g_strdup_printf("ip -6 addr add fe80::1/64 dev %s", dev_name);
    ret = system(cmd);
    (void)ret;
    g_free(cmd);
    
    // Add IPv6 ULA (Unique Local Address) prefix
    cmd = g_strdup_printf("ip -6 addr add fd00:dead:beef::1/64 dev %s", dev_name);
    ret = system(cmd);
    (void)ret;
    g_free(cmd);
    
    // Enable IPv6 forwarding on the interface
    cmd = g_strdup_printf("sysctl -w net.ipv6.conf.%s.forwarding=1", dev_name);
    ret = system(cmd);
    (void)ret;
    g_free(cmd);
    
    // Enable IPv6 router advertisements (optional, we handle manually)
    cmd = g_strdup_printf("sysctl -w net.ipv6.conf.%s.accept_ra=0", dev_name);
    ret = system(cmd);
    (void)ret;
    g_free(cmd);
    
    // Set MTU
    cmd = g_strdup_printf("ip link set %s mtu 1420", dev_name);
    ret = system(cmd);
    (void)ret;
    g_free(cmd);

    log_info("VPN: Configured %s with IPv4 %s/%s and IPv6 fd00:dead:beef::1/64", 
             dev_name, ip, netmask);
    return TRUE;
}

//=============================================================================
// Checksum Functions
//=============================================================================

static guint16 ip_checksum(const void *data, gsize len) {
    const guint16 *buf = data;
    guint32 sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(guint8 *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (guint16)~sum;
}

static guint16 tcp_checksum(guint32 src_ip, guint32 dest_ip,
                           const void *tcp_data, gsize tcp_len) {
    guint8 pseudo_buf[12];
    guint32 src_addr_net = htonl(src_ip);
    guint32 dest_addr_net = htonl(dest_ip);
    guint16 tcp_length_net = htons(tcp_len);
    
    memcpy(pseudo_buf + 0, &src_addr_net, 4);
    memcpy(pseudo_buf + 4, &dest_addr_net, 4);
    pseudo_buf[8] = 0;
    pseudo_buf[9] = IPPROTO_TCP;
    memcpy(pseudo_buf + 10, &tcp_length_net, 2);

    guint32 sum = 0;
    const guint16 *buf = (const guint16 *)pseudo_buf;
    gsize len = 12;

    while (len > 1) { sum += *buf++; len -= 2; }

    buf = tcp_data;
    len = tcp_len;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(guint8 *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (guint16)~sum;
}

static guint16 udp_checksum(guint32 src_ip, guint32 dest_ip,
                           const void *udp_data, gsize udp_len) {
    guint8 pseudo_buf[12];
    guint32 src_addr_net = htonl(src_ip);
    guint32 dest_addr_net = htonl(dest_ip);
    guint16 udp_length_net = htons(udp_len);
    
    memcpy(pseudo_buf + 0, &src_addr_net, 4);
    memcpy(pseudo_buf + 4, &dest_addr_net, 4);
    pseudo_buf[8] = 0;
    pseudo_buf[9] = IPPROTO_UDP;
    memcpy(pseudo_buf + 10, &udp_length_net, 2);

    guint32 sum = 0;
    const guint16 *buf = (const guint16 *)pseudo_buf;
    gsize len = 12;

    while (len > 1) { sum += *buf++; len -= 2; }

    buf = udp_data;
    len = udp_len;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(guint8 *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (guint16)~sum;
}

static guint16 tcp6_checksum(const struct in6_addr *src_addr,
                            const struct in6_addr *dest_addr,
                            const void *tcp_data, gsize tcp_len) {
    guint8 pseudo_buf[40];
    memcpy(pseudo_buf + 0, src_addr, 16);
    memcpy(pseudo_buf + 16, dest_addr, 16);
    guint32 tcp_length_net = htonl(tcp_len);
    memcpy(pseudo_buf + 32, &tcp_length_net, 4);
    pseudo_buf[36] = pseudo_buf[37] = pseudo_buf[38] = 0;
    pseudo_buf[39] = IPPROTO_TCP;

    guint32 sum = 0;
    const guint16 *buf = (const guint16 *)pseudo_buf;
    gsize len = 40;
    while (len > 1) { sum += *buf++; len -= 2; }

    buf = tcp_data; len = tcp_len;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(guint8 *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (guint16)~sum;
}

static guint16 udp6_checksum(const struct in6_addr *src_addr,
                            const struct in6_addr *dest_addr,
                            const void *udp_data, gsize udp_len) {
    guint8 pseudo_buf[40];
    memcpy(pseudo_buf + 0, src_addr, 16);
    memcpy(pseudo_buf + 16, dest_addr, 16);
    guint32 udp_length_net = htonl(udp_len);
    memcpy(pseudo_buf + 32, &udp_length_net, 4);
    pseudo_buf[36] = pseudo_buf[37] = pseudo_buf[38] = 0;
    pseudo_buf[39] = IPPROTO_UDP;

    guint32 sum = 0;
    const guint16 *buf = (const guint16 *)pseudo_buf;
    gsize len = 40;
    while (len > 1) { sum += *buf++; len -= 2; }

    buf = udp_data; len = udp_len;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(guint8 *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (guint16)~sum;
}

//=============================================================================
// Session Management, Packet Sending/Receiving, Protocol Handlers,
// and Public API — unchanged from original
//=============================================================================

static gboolean parse_destination_from_session_key(const gchar *session_key,
                                                   gchar **out_host,
                                                   guint16 *out_port) {
    if (!session_key || !out_host || !out_port) return FALSE;
    const gchar *arrow = strstr(session_key, "->");
    if (!arrow) return FALSE;
    const gchar *dest_part = arrow + 2;
    if (dest_part[0] == '[') {
        const gchar *bracket_end = strchr(dest_part, ']');
        if (!bracket_end) return FALSE;
        gsize addr_len = bracket_end - dest_part - 1;
        *out_host = g_strndup(dest_part + 1, addr_len);
        *out_port = (guint16)atoi(bracket_end + 2);
    } else {
        const gchar *colon = strrchr(dest_part, ':');
        if (!colon) return FALSE;
        *out_host = g_strndup(dest_part, colon - dest_part);
        *out_port = (guint16)atoi(colon + 1);
    }
    return (*out_port > 0);
}

static gboolean send_periodic_router_advertisement(gpointer user_data) {
    DeadlightVPNManager *vpn = user_data;
    guint8 ra_packet[1500];
    memset(ra_packet, 0, sizeof(ra_packet));
    struct ipv6_header *ra_ip6 = (struct ipv6_header *)ra_packet;
    struct icmpv6_header *ra_icmp = (struct icmpv6_header *)(ra_packet + sizeof(struct ipv6_header));
    struct nd_router_advert *ra = (struct nd_router_advert *)(ra_packet + sizeof(struct ipv6_header) + sizeof(struct icmpv6_header));
    ra_ip6->version_tc_fl = htonl(0x60000000);
    ra_ip6->next_header = 58;
    ra_ip6->hop_limit = 255;
    memset(&ra_ip6->src_addr, 0, sizeof(struct in6_addr));
    ra_ip6->src_addr.s6_addr[0] = 0xfe; ra_ip6->src_addr.s6_addr[1] = 0x80; ra_ip6->src_addr.s6_addr[15] = 0x01;
    memset(&ra_ip6->dest_addr, 0, sizeof(struct in6_addr));
    ra_ip6->dest_addr.s6_addr[0] = 0xff; ra_ip6->dest_addr.s6_addr[1] = 0x02; ra_ip6->dest_addr.s6_addr[15] = 0x01;
    ra_icmp->type = ICMPV6_ROUTER_ADVERT; ra_icmp->code = 0;
    ra->hop_limit = 64; ra->flags = 0x00; ra->lifetime = htons(1800);
    struct nd_opt_prefix_info *prefix = (struct nd_opt_prefix_info *)((guint8 *)ra + sizeof(struct nd_router_advert));
    prefix->type = 3; prefix->length = 4; prefix->prefix_len = 64; prefix->flags = 0xC0;
    prefix->valid_lifetime = htonl(86400); prefix->preferred_lifetime = htonl(43200);
    memset(&prefix->prefix, 0, sizeof(struct in6_addr));
    prefix->prefix.s6_addr[0]=0xfd; prefix->prefix.s6_addr[1]=0x00;
    prefix->prefix.s6_addr[2]=0xde; prefix->prefix.s6_addr[3]=0xad;
    prefix->prefix.s6_addr[4]=0xbe; prefix->prefix.s6_addr[5]=0xef;
    gsize icmp_len = sizeof(struct icmpv6_header) + sizeof(struct nd_router_advert) + sizeof(struct nd_opt_prefix_info);
    ra_ip6->payload_length = htons(icmp_len);
    struct in6_addr src_copy, dest_copy;
    memcpy(&src_copy, &ra_ip6->src_addr, sizeof(struct in6_addr));
    memcpy(&dest_copy, &ra_ip6->dest_addr, sizeof(struct in6_addr));
    ra_icmp->checksum = udp6_checksum(&src_copy, &dest_copy, ra_icmp, icmp_len);
    gsize total_len = sizeof(struct ipv6_header) + icmp_len;
    gssize written = write(vpn->tun_fd, ra_packet, total_len);
    if (written > 0) log_debug("VPN: Sent periodic Router Advertisement");
    return G_SOURCE_CONTINUE;
}

static VPNSession *vpn_session_new(DeadlightVPNManager *vpn, guint32 client_ip,
                                   guint16 client_port, guint32 dest_ip,
                                   guint16 dest_port) {
    VPNSession *session = g_new0(VPNSession, 1);
    guint32 client_ip_net = htonl(client_ip);
    guint32 dest_ip_net   = htonl(dest_ip);
    ipv4_to_mapped(client_ip_net, &session->client_ip);
    ipv4_to_mapped(dest_ip_net,   &session->dest_ip);
    session->client_port = client_port;
    session->dest_port = dest_port;
    session->session_key = make_session_key(&session->client_ip, client_port,
                                           &session->dest_ip,   dest_port);
    session->state = VPN_TCP_CLOSED;
    session->seq = g_random_int();
    session->isn = session->seq;
    session->ack = 0;
    session->created_at = g_get_monotonic_time();
    session->last_activity = session->created_at;
    session->vpn = vpn;
    session->upstream_conn = NULL;
    session->upstream_watch_id = 0;
    session->retrans_timer_id = 0;
    session->last_packet.data = NULL;
    session->last_packet.len = 0;
    return session;
}

static void vpn_session_free(VPNSession *session) {
    if (!session) return;
    g_debug("VPN: Freeing session %s", session->session_key);
    if (session->upstream_watch_id > 0) { g_source_remove(session->upstream_watch_id); session->upstream_watch_id = 0; }
    if (session->retrans_timer_id > 0)  { g_source_remove(session->retrans_timer_id);  session->retrans_timer_id = 0; }
    if (session->upstream_conn) {
        GSocket *socket = g_socket_connection_get_socket(session->upstream_conn);
        gboolean should_pool = FALSE;
        if (session->state == VPN_TCP_TIME_WAIT || session->state == VPN_TCP_FIN_WAIT_2 || session->state == VPN_TCP_LAST_ACK) {
            if (g_socket_is_connected(socket) && g_socket_condition_check(socket, G_IO_ERR | G_IO_HUP) == 0)
                should_pool = TRUE;
        }
        if (should_pool) {
            gchar *dest_host = NULL; guint16 dest_port = 0;
            if (parse_destination_from_session_key(session->session_key, &dest_host, &dest_port)) {
                connection_pool_release(session->vpn->context->conn_pool, G_IO_STREAM(session->upstream_conn), dest_host, dest_port, CONN_TYPE_PLAIN);
                g_free(dest_host);
                session->upstream_conn = NULL;
            }
        }
        if (session->upstream_conn) {
            GError *error = NULL;
            g_io_stream_close(G_IO_STREAM(session->upstream_conn), NULL, &error);
            if (error) { g_debug("VPN: Error closing upstream: %s", error->message); g_error_free(error); }
            g_object_unref(session->upstream_conn);
            session->upstream_conn = NULL;
        }
    }
    g_free(session->last_packet.data);
    g_free(session->session_key);
    g_free(session);
}

static VPNUDPSession* vpn_udp_session_new(DeadlightVPNManager *vpn,
                                          guint32 client_ip, guint16 client_port,
                                          guint32 dest_ip, guint16 dest_port) {
    VPNUDPSession *session = g_new0(VPNUDPSession, 1);
    ipv4_to_mapped(htonl(client_ip), &session->client_ip);
    ipv4_to_mapped(htonl(dest_ip),   &session->dest_ip);
    session->client_port = client_port;
    session->dest_port = dest_port;
    session->session_key = make_session_key(&session->client_ip, client_port, &session->dest_ip, dest_port);
    session->last_activity = g_get_monotonic_time();
    session->vpn = vpn;
    session->upstream_socket = NULL;
    session->upstream_watch_id = 0;
    return session;
}

static void vpn_udp_session_free(VPNUDPSession *session) {
    if (!session) return;
    if (session->upstream_watch_id > 0) g_source_remove(session->upstream_watch_id);
    if (session->upstream_socket) { g_socket_close(session->upstream_socket, NULL); g_object_unref(session->upstream_socket); }
    g_free(session->session_key);
    g_free(session);
}

static gboolean cleanup_idle_sessions(gpointer user_data) {
    DeadlightVPNManager *vpn = user_data;
    gint64 now = g_get_monotonic_time();
    gint64 timeout = 300 * G_TIME_SPAN_SECOND;
    GList *to_remove = NULL;
    g_mutex_lock(&vpn->sessions_mutex);
    GHashTableIter iter; gpointer key, value;
    g_hash_table_iter_init(&iter, vpn->sessions);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        VPNSession *session = value;
        if ((now - session->last_activity) > timeout)
            to_remove = g_list_prepend(to_remove, g_strdup(session->session_key));
    }
    for (GList *l = to_remove; l; l = l->next) { g_hash_table_remove(vpn->sessions, l->data); vpn->active_connections--; g_free(l->data); }
    g_list_free(to_remove);
    g_mutex_unlock(&vpn->sessions_mutex);
    return G_SOURCE_CONTINUE;
}

static gboolean cleanup_idle_udp_sessions(gpointer user_data) {
    DeadlightVPNManager *vpn = user_data;
    gint64 now = g_get_monotonic_time();
    gint64 timeout = 30 * G_TIME_SPAN_SECOND;
    GList *to_remove = NULL;
    g_mutex_lock(&vpn->sessions_mutex);
    GHashTableIter iter; gpointer key, value;
    g_hash_table_iter_init(&iter, vpn->udp_sessions);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        VPNUDPSession *session = value;
        if ((now - session->last_activity) > timeout)
            to_remove = g_list_prepend(to_remove, g_strdup(session->session_key));
    }
    guint removed = 0;
    for (GList *l = to_remove; l; l = l->next) { g_hash_table_remove(vpn->udp_sessions, l->data); removed++; g_free(l->data); }
    g_list_free(to_remove);
    if (removed > 0) log_debug("VPN: Cleaned up %u idle UDP sessions (%u remaining)", removed, g_hash_table_size(vpn->udp_sessions));
    g_mutex_unlock(&vpn->sessions_mutex);
    return G_SOURCE_CONTINUE;
}

static void send_tcp_packet(DeadlightVPNManager *vpn, VPNSession *session,
                           guint8 flags, const guint8 *payload, gsize payload_len) {
    guint8 packet[4096];
    struct ip_header *ip_hdr = (struct ip_header *)packet;
    struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + sizeof(struct ip_header));
    gsize ip_hdr_len = sizeof(struct ip_header);
    gsize tcp_hdr_len = sizeof(struct tcp_header);
    gsize total_len = ip_hdr_len + tcp_hdr_len + payload_len;
    if (total_len > sizeof(packet)) { log_warn("VPN: TCP packet too large (%zu bytes)", total_len); return; }
    guint32 client_ip = mapped_to_ipv4(&session->client_ip);
    guint32 dest_ip   = mapped_to_ipv4(&session->dest_ip);
    memset(ip_hdr, 0, ip_hdr_len);
    ip_hdr->version_ihl = 0x45; ip_hdr->total_length = htons(total_len);
    ip_hdr->ttl = 64; ip_hdr->protocol = IPPROTO_TCP;
    ip_hdr->src_addr = htonl(dest_ip); ip_hdr->dest_addr = htonl(client_ip);
    ip_hdr->checksum = 0;
    ip_hdr->checksum = ip_checksum(ip_hdr, ip_hdr_len);
    memset(tcp_hdr, 0, tcp_hdr_len);
    tcp_hdr->src_port = htons(session->dest_port); tcp_hdr->dest_port = htons(session->client_port);
    tcp_hdr->seq_num = htonl(session->seq); tcp_hdr->ack_num = htonl(session->ack);
    tcp_hdr->data_offset_flags = (5 << 4); tcp_hdr->flags = flags; tcp_hdr->window_size = htons(65535);
    if (payload_len > 0 && payload) memcpy(packet + ip_hdr_len + tcp_hdr_len, payload, payload_len);
    tcp_hdr->checksum = 0;
    tcp_hdr->checksum = tcp_checksum(dest_ip, client_ip, tcp_hdr, tcp_hdr_len + payload_len);
    gssize written = write(vpn->tun_fd, packet, total_len);
    if (written < 0 || (gsize)written != total_len) { log_warn("VPN: Failed/partial TUN write: %zd/%zu", written, total_len); return; }
    vpn->bytes_sent += (guint64)written;
    if (flags & (TCP_SYN | TCP_PSH | TCP_FIN)) {
        g_free(session->last_packet.data);
        session->last_packet.data = payload_len ? g_memdup2(payload, payload_len) : NULL;
        session->last_packet.len = payload_len; session->last_packet.flags = flags;
        session->last_packet.retries = 0; session->last_packet.sent_at = g_get_monotonic_time();
    }
}

static void send_udp_packet(DeadlightVPNManager *vpn, VPNUDPSession *session,
                           const guint8 *payload, gsize payload_len) {
    guint8 packet[4096];
    struct ip_header *ip_hdr = (struct ip_header *)packet;
    struct udp_header *udp_hdr = (struct udp_header *)(packet + sizeof(struct ip_header));
    gsize ip_hdr_len = sizeof(struct ip_header), udp_hdr_len = sizeof(struct udp_header);
    gsize total_len = ip_hdr_len + udp_hdr_len + payload_len;
    if (total_len > sizeof(packet)) { log_warn("VPN: UDP packet too large (%zu bytes)", total_len); return; }
    guint32 client_ip = mapped_to_ipv4(&session->client_ip);
    guint32 dest_ip   = mapped_to_ipv4(&session->dest_ip);
    memset(ip_hdr, 0, ip_hdr_len);
    ip_hdr->version_ihl = 0x45; ip_hdr->total_length = htons(total_len);
    ip_hdr->ttl = 64; ip_hdr->protocol = IPPROTO_UDP;
    ip_hdr->src_addr = htonl(dest_ip); ip_hdr->dest_addr = htonl(client_ip);
    ip_hdr->checksum = 0;
    ip_hdr->checksum = ip_checksum(ip_hdr, ip_hdr_len);
    memset(udp_hdr, 0, udp_hdr_len);
    udp_hdr->src_port = htons(session->dest_port); udp_hdr->dest_port = htons(session->client_port);
    udp_hdr->length = htons(udp_hdr_len + payload_len);
    if (payload_len > 0 && payload) memcpy(packet + ip_hdr_len + udp_hdr_len, payload, payload_len);
    udp_hdr->checksum = 0;
    udp_hdr->checksum = udp_checksum(dest_ip, client_ip, udp_hdr, udp_hdr_len + payload_len);
    gssize written = write(vpn->tun_fd, packet, total_len);
    if (written < 0) { log_warn("VPN: Failed to write UDP packet to TUN: %s", g_strerror(errno)); return; }
    vpn->bytes_sent += written;
}

static void send_udp6_packet(DeadlightVPNManager *vpn, VPNUDPSession *session,
                            const guint8 *payload, gsize payload_len) {
    guint8 packet[4096];
    struct ipv6_header *ip6_hdr = (struct ipv6_header *)packet;
    struct udp_header *udp_hdr = (struct udp_header *)(packet + sizeof(struct ipv6_header));
    gsize ip6_hdr_len = sizeof(struct ipv6_header), udp_hdr_len = sizeof(struct udp_header);
    gsize total_len = ip6_hdr_len + udp_hdr_len + payload_len;
    if (total_len > sizeof(packet)) { log_warn("VPN: IPv6 UDP packet too large (%zu bytes)", total_len); return; }
    memset(ip6_hdr, 0, ip6_hdr_len);
    ip6_hdr->version_tc_fl = htonl(0x60000000);
    ip6_hdr->payload_length = htons(udp_hdr_len + payload_len);
    ip6_hdr->next_header = IPPROTO_UDP; ip6_hdr->hop_limit = 64;
    memcpy(&ip6_hdr->src_addr, &session->dest_ip, sizeof(struct in6_addr));
    memcpy(&ip6_hdr->dest_addr, &session->client_ip, sizeof(struct in6_addr));
    memset(udp_hdr, 0, udp_hdr_len);
    udp_hdr->src_port = htons(session->dest_port); udp_hdr->dest_port = htons(session->client_port);
    udp_hdr->length = htons(udp_hdr_len + payload_len);
    if (payload_len > 0 && payload) memcpy(packet + ip6_hdr_len + udp_hdr_len, payload, payload_len);
    struct in6_addr src_copy, dest_copy;
    memcpy(&src_copy, &ip6_hdr->src_addr, sizeof(struct in6_addr));
    memcpy(&dest_copy, &ip6_hdr->dest_addr, sizeof(struct in6_addr));
    udp_hdr->checksum = udp6_checksum(&src_copy, &dest_copy, udp_hdr, udp_hdr_len + payload_len);
    gssize written = write(vpn->tun_fd, packet, total_len);
    if (written < 0) { log_warn("VPN: Failed to write IPv6 UDP packet to TUN: %s", g_strerror(errno)); return; }
    vpn->bytes_sent += written;
}

static void send_tcp6_packet(DeadlightVPNManager *vpn, VPNSession *session,
                            guint8 flags, const guint8 *payload, gsize payload_len) {
    guint8 packet[4096];
    struct ipv6_header *ip6_hdr = (struct ipv6_header *)packet;
    struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + sizeof(struct ipv6_header));
    gsize ip6_hdr_len = sizeof(struct ipv6_header), tcp_hdr_len = sizeof(struct tcp_header);
    gsize total_len = ip6_hdr_len + tcp_hdr_len + payload_len;
    if (total_len > sizeof(packet)) { log_warn("VPN: IPv6 packet too large (%zu bytes), dropping", total_len); return; }
    memset(ip6_hdr, 0, ip6_hdr_len);
    ip6_hdr->version_tc_fl = htonl(0x60000000);
    ip6_hdr->payload_length = htons(tcp_hdr_len + payload_len);
    ip6_hdr->next_header = IPPROTO_TCP; ip6_hdr->hop_limit = 64;
    memcpy(&ip6_hdr->src_addr, &session->dest_ip, sizeof(struct in6_addr));
    memcpy(&ip6_hdr->dest_addr, &session->client_ip, sizeof(struct in6_addr));
    memset(tcp_hdr, 0, tcp_hdr_len);
    tcp_hdr->src_port = htons(session->dest_port); tcp_hdr->dest_port = htons(session->client_port);
    tcp_hdr->seq_num = htonl(session->seq); tcp_hdr->ack_num = htonl(session->ack);
    tcp_hdr->data_offset_flags = (5 << 4); tcp_hdr->flags = flags; tcp_hdr->window_size = htons(65535);
    if (payload_len > 0 && payload) memcpy(packet + ip6_hdr_len + tcp_hdr_len, payload, payload_len);
    struct in6_addr src_copy, dest_copy;
    memcpy(&src_copy, &ip6_hdr->src_addr, sizeof(struct in6_addr));
    memcpy(&dest_copy, &ip6_hdr->dest_addr, sizeof(struct in6_addr));
    tcp_hdr->checksum = tcp6_checksum(&src_copy, &dest_copy, tcp_hdr, tcp_hdr_len + payload_len);
    gssize written = write(vpn->tun_fd, packet, total_len);
    if (written < 0 || (gsize)written != total_len) { log_warn("VPN: Failed/partial TUN write for IPv6: %zd/%zu", written, total_len); return; }
    vpn->bytes_sent += (guint64)written;
    if (flags & (TCP_SYN | TCP_PSH | TCP_FIN)) {
        g_free(session->last_packet.data);
        session->last_packet.data = payload_len ? g_memdup2(payload, payload_len) : NULL;
        session->last_packet.len = payload_len; session->last_packet.flags = flags;
        session->last_packet.retries = 0; session->last_packet.sent_at = g_get_monotonic_time();
    }
}

static gboolean on_upstream_readable(GIOChannel *source, GIOCondition condition, gpointer user_data) {
    VPNSession *session = user_data; DeadlightVPNManager *vpn = session->vpn; (void)source;
    if (condition & (G_IO_HUP | G_IO_ERR)) {
        send_tcp_packet(vpn, session, TCP_FIN | TCP_ACK, NULL, 0);
        session->seq++; session->state = VPN_TCP_FIN_WAIT_1;
        return G_SOURCE_REMOVE;
    }
    guint8 buffer[8192];
    GInputStream *input = g_io_stream_get_input_stream(G_IO_STREAM(session->upstream_conn));
    GError *error = NULL;
    gssize bytes = g_input_stream_read(input, buffer, sizeof(buffer), NULL, &error);
    if (bytes > 0) {
        send_tcp_packet(vpn, session, TCP_PSH | TCP_ACK, buffer, bytes);
        session->seq += bytes; session->last_activity = g_get_monotonic_time();
    } else {
        if (error) { g_error_free(error); }
        send_tcp_packet(vpn, session, TCP_FIN | TCP_ACK, NULL, 0);
        session->seq++; session->state = VPN_TCP_FIN_WAIT_1;
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

static gboolean on_udp_upstream_readable(GIOChannel *source, GIOCondition condition, gpointer user_data) {
    VPNUDPSession *session = user_data; DeadlightVPNManager *vpn = session->vpn; (void)source;
    if (condition & (G_IO_HUP | G_IO_ERR)) return G_SOURCE_REMOVE;
    if (!(condition & G_IO_IN)) return G_SOURCE_CONTINUE;
    guint8 buffer[65535];
    GError *error = NULL;
    gssize bytes = g_socket_receive(session->upstream_socket, (gchar *)buffer, sizeof(buffer), NULL, &error);
    if (bytes > 0) {
        if (IN6_IS_ADDR_V4MAPPED(&session->client_ip))
            send_udp_packet(vpn, session, buffer, bytes);
        else
            send_udp6_packet(vpn, session, buffer, bytes);
        session->last_activity = g_get_monotonic_time();
    } else if (bytes == 0) {
        return G_SOURCE_REMOVE;
    } else if (error) {
        if (error->code != G_IO_ERROR_WOULD_BLOCK) { g_error_free(error); return G_SOURCE_REMOVE; }
        g_error_free(error);
    }
    return G_SOURCE_CONTINUE;
}

static void handle_tcp_packet(DeadlightVPNManager *vpn, struct ip_header *ip_hdr,
                              struct tcp_header *tcp_hdr, guint8 *payload, gsize payload_len) {
    guint32 client_ip = ntohl(ip_hdr->src_addr), dest_ip = ntohl(ip_hdr->dest_addr);
    guint16 client_port = ntohs(tcp_hdr->src_port), dest_port = ntohs(tcp_hdr->dest_port);
    guint8 flags = tcp_hdr->flags;
    guint32 recv_seq = ntohl(tcp_hdr->seq_num), recv_ack = ntohl(tcp_hdr->ack_num);
    gchar dest_str[INET_ADDRSTRLEN];
    struct in_addr tmp; tmp.s_addr = ip_hdr->dest_addr;
    inet_ntop(AF_INET, &tmp, dest_str, INET_ADDRSTRLEN);
    struct in6_addr client_ip6, dest_ip6;
    ipv4_to_mapped(htonl(client_ip), &client_ip6);
    ipv4_to_mapped(htonl(dest_ip), &dest_ip6);
    gchar *key = make_session_key(&client_ip6, client_port, &dest_ip6, dest_port);
    g_mutex_lock(&vpn->sessions_mutex);
    VPNSession *session = g_hash_table_lookup(vpn->sessions, key);
    if (session &&
        session->state == VPN_TCP_SYN_RECEIVED &&
        (flags & TCP_SYN) &&
        !(flags & TCP_ACK)) {
        send_tcp_packet(vpn, session, TCP_SYN | TCP_ACK, NULL, 0);

        g_mutex_unlock(&vpn->sessions_mutex);
        g_free(key);
        return;
    }
    if (!session && (flags & TCP_SYN) && !(flags & TCP_ACK)) {
        if (vpn->active_connections >= 1000) { g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return; }
        session = vpn_session_new(vpn, client_ip, client_port, dest_ip, dest_port);
        g_free(key); key = make_session_key(&session->client_ip, client_port, &session->dest_ip, dest_port);
        session->ack = recv_seq + 1; session->state = VPN_TCP_SYN_RECEIVED;
        GIOStream *pooled = connection_pool_get(vpn->context->conn_pool, dest_str, dest_port, CONN_TYPE_PLAIN);
        if (pooled) session->upstream_conn = G_SOCKET_CONNECTION(pooled);
        if (!session->upstream_conn) {
            GError *error = NULL;
            session->upstream_conn = deadlight_network_connect_tcp(vpn->context, dest_str, dest_port, &error);
            if (!session->upstream_conn) {
                if (error) g_error_free(error);
                send_tcp_packet(vpn, session, TCP_RST | TCP_ACK, NULL, 0);
                vpn_session_free(session); g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return;
            }
            connection_pool_register(vpn->context->conn_pool, G_IO_STREAM(session->upstream_conn), dest_str, dest_port, CONN_TYPE_PLAIN);
        }
        GSocket *sock = g_socket_connection_get_socket(session->upstream_conn);
        GIOChannel *chan = g_io_channel_unix_new(g_socket_get_fd(sock));
        session->upstream_watch_id = g_io_add_watch(chan, G_IO_IN | G_IO_HUP | G_IO_ERR, on_upstream_readable, session);
        g_io_channel_unref(chan);
        g_hash_table_insert(vpn->sessions, g_strdup(key), session);
        vpn->total_connections++; vpn->active_connections++;
        send_tcp_packet(vpn, session, TCP_SYN | TCP_ACK, NULL, 0); session->seq++;
        g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return;
    }
    if (!session) { g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return; }
    session->last_activity = g_get_monotonic_time();
    if (session->state == VPN_TCP_SYN_RECEIVED && (flags & TCP_ACK)) {
        if (recv_ack != session->seq) {
            send_tcp_packet(vpn, session, TCP_RST, NULL, 0);
            g_hash_table_remove(vpn->sessions, session->session_key); vpn->active_connections--;
            g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return;
        }
        session->state = VPN_TCP_ESTABLISHED;
    }
    if ((session->state == VPN_TCP_ESTABLISHED) && payload_len > 0) {
        GOutputStream *output = g_io_stream_get_output_stream(G_IO_STREAM(session->upstream_conn));
        GError *error = NULL;
        gssize written = g_output_stream_write(output, payload, payload_len, NULL, &error);
        if (written > 0) { session->ack = recv_seq + written; send_tcp_packet(vpn, session, TCP_ACK, NULL, 0); }
        else if (error) { g_error_free(error); send_tcp_packet(vpn, session, TCP_RST, NULL, 0); g_hash_table_remove(vpn->sessions, session->session_key); vpn->active_connections--; }
    }
    if (flags & TCP_FIN) {
        session->ack = recv_seq + 1; send_tcp_packet(vpn, session, TCP_ACK, NULL, 0);
        if (session->state == VPN_TCP_ESTABLISHED) {
            session->state = VPN_TCP_CLOSE_WAIT;
            send_tcp_packet(vpn, session, TCP_FIN | TCP_ACK, NULL, 0); session->seq++;
            session->state = VPN_TCP_LAST_ACK;
        } else if (session->state == VPN_TCP_FIN_WAIT_1) session->state = VPN_TCP_FIN_WAIT_2;
    }
    if (session->state == VPN_TCP_FIN_WAIT_2 && (flags & TCP_ACK) && recv_ack == session->seq) {
        session->state = VPN_TCP_TIME_WAIT; g_hash_table_remove(vpn->sessions, session->session_key); vpn->active_connections--;
    }
    if (flags & TCP_RST) { g_hash_table_remove(vpn->sessions, session->session_key); vpn->active_connections--; }
    if (session->state == VPN_TCP_LAST_ACK && (flags & TCP_ACK) && recv_ack == session->seq) {
        g_hash_table_remove(vpn->sessions, session->session_key); vpn->active_connections--;
    }
    g_mutex_unlock(&vpn->sessions_mutex); g_free(key);
}

static void handle_udp_packet(DeadlightVPNManager *vpn, struct ip_header *ip_hdr,
                              struct udp_header *udp_hdr, guint8 *payload, gsize payload_len) {
    guint32 client_ip = ntohl(ip_hdr->src_addr), dest_ip = ntohl(ip_hdr->dest_addr);
    guint16 client_port = ntohs(udp_hdr->src_port), dest_port = ntohs(udp_hdr->dest_port);
    gchar dest_str[INET_ADDRSTRLEN];
    struct in_addr tmp; tmp.s_addr = ip_hdr->dest_addr;
    inet_ntop(AF_INET, &tmp, dest_str, INET_ADDRSTRLEN);
    struct in6_addr client_ip6, dest_ip6;
    ipv4_to_mapped(htonl(client_ip), &client_ip6); ipv4_to_mapped(htonl(dest_ip), &dest_ip6);
    gchar *key = make_session_key(&client_ip6, client_port, &dest_ip6, dest_port);
    g_mutex_lock(&vpn->sessions_mutex);
    VPNUDPSession *session = g_hash_table_lookup(vpn->udp_sessions, key);
    if (!session) {
        if (g_hash_table_size(vpn->udp_sessions) >= 500) { g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return; }
        session = vpn_udp_session_new(vpn, client_ip, client_port, dest_ip, dest_port);
        GError *error = NULL;
        session->upstream_socket = g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM, G_SOCKET_PROTOCOL_UDP, &error);
        if (!session->upstream_socket) { if (error) g_error_free(error); vpn_udp_session_free(session); g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return; }
        g_socket_set_blocking(session->upstream_socket, FALSE);
        gint fd = g_socket_get_fd(session->upstream_socket);
        GIOChannel *chan = g_io_channel_unix_new(fd);
        g_io_channel_set_encoding(chan, NULL, NULL); g_io_channel_set_buffered(chan, FALSE);
        session->upstream_watch_id = g_io_add_watch(chan, G_IO_IN | G_IO_HUP | G_IO_ERR, on_udp_upstream_readable, session);
        g_io_channel_unref(chan);
        g_hash_table_insert(vpn->udp_sessions, g_strdup(session->session_key), session);
    }
    session->last_activity = g_get_monotonic_time();
    GSocketAddress *addr = g_inet_socket_address_new(g_inet_address_new_from_string(dest_str), dest_port);
    GError *error = NULL;
    g_socket_send_to(session->upstream_socket, addr, (const gchar *)payload, payload_len, NULL, &error);
    g_object_unref(addr);
    if (error) { g_error_free(error); }
    g_mutex_unlock(&vpn->sessions_mutex); g_free(key);
}

static void handle_ip_packet(DeadlightVPNManager *vpn, guint8 *packet, gsize packet_len) {
    if (packet_len < 1) return;
    guint8 version = (packet[0] >> 4) & 0x0F;
    if (version == 4) {
        if (packet_len < sizeof(struct ip_header)) return;
        struct ip_header *ip_hdr = (struct ip_header *)packet;
        guint8 ihl = (ip_hdr->version_ihl & 0x0F) * 4;
        if (packet_len < ihl) return;
        if (ip_hdr->protocol == IPPROTO_TCP) {
            if (packet_len < ihl + sizeof(struct tcp_header)) return;
            struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + ihl);
            guint8 tcp_hdr_len = ((tcp_hdr->data_offset_flags >> 4) & 0x0F) * 4;
            if (packet_len < ihl + tcp_hdr_len) return;
            handle_tcp_packet(vpn, ip_hdr, tcp_hdr, packet + ihl + tcp_hdr_len, packet_len - ihl - tcp_hdr_len);
        } else if (ip_hdr->protocol == IPPROTO_UDP) {
            if (packet_len < ihl + sizeof(struct udp_header)) return;
            struct udp_header *udp_hdr = (struct udp_header *)(packet + ihl);
            handle_udp_packet(vpn, ip_hdr, udp_hdr, packet + ihl + sizeof(struct udp_header), packet_len - ihl - sizeof(struct udp_header));
        }
    } else if (version == 6) {
        handle_ipv6_packet(vpn, packet, packet_len);
    }
}

static void handle_ipv6_packet(DeadlightVPNManager *vpn, guint8 *packet, gsize packet_len) {
    if (packet_len < sizeof(struct ipv6_header)) return;
    struct ipv6_header *ip6_hdr = (struct ipv6_header *)packet;
    guint8 next_header = ip6_hdr->next_header;
    if (next_header == IPPROTO_TCP) {
        if (packet_len < sizeof(struct ipv6_header) + sizeof(struct tcp_header)) return;
        struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + sizeof(struct ipv6_header));
        guint8 tcp_hdr_len = ((tcp_hdr->data_offset_flags >> 4) & 0x0F) * 4;
        handle_tcp6_packet(vpn, ip6_hdr, tcp_hdr, packet + sizeof(struct ipv6_header) + tcp_hdr_len, packet_len - sizeof(struct ipv6_header) - tcp_hdr_len);
    } else if (next_header == IPPROTO_UDP) {
        if (packet_len < sizeof(struct ipv6_header) + sizeof(struct udp_header)) return;
        struct udp_header *udp_hdr = (struct udp_header *)(packet + sizeof(struct ipv6_header));
        handle_udp6_packet(vpn, ip6_hdr, udp_hdr, packet + sizeof(struct ipv6_header) + sizeof(struct udp_header), packet_len - sizeof(struct ipv6_header) - sizeof(struct udp_header));
    } else if (next_header == 58) {
        if (packet_len < sizeof(struct ipv6_header) + sizeof(struct icmpv6_header)) return;
        struct icmpv6_header *icmp_hdr = (struct icmpv6_header *)(packet + sizeof(struct ipv6_header));
        handle_icmpv6_packet(vpn, ip6_hdr, icmp_hdr, packet + sizeof(struct ipv6_header) + sizeof(struct icmpv6_header), packet_len - sizeof(struct ipv6_header) - sizeof(struct icmpv6_header));
    }
}

static void handle_udp6_packet(DeadlightVPNManager *vpn, struct ipv6_header *ip6_hdr,
                               struct udp_header *udp_hdr, guint8 *payload, gsize payload_len) {
    guint16 client_port = ntohs(udp_hdr->src_port), dest_port = ntohs(udp_hdr->dest_port);
    gchar dest_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6_hdr->dest_addr, dest_str, INET6_ADDRSTRLEN);
    struct in6_addr client_addr, dest_addr;
    memcpy(&client_addr, &ip6_hdr->src_addr, sizeof(struct in6_addr));
    memcpy(&dest_addr, &ip6_hdr->dest_addr, sizeof(struct in6_addr));
    gchar *key = make_session_key(&client_addr, client_port, &dest_addr, dest_port);
    g_mutex_lock(&vpn->sessions_mutex);
    VPNUDPSession *session = g_hash_table_lookup(vpn->udp_sessions_v6, key);
    if (!session) {
        if (g_hash_table_size(vpn->udp_sessions_v6) >= 500) { g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return; }
        session = g_new0(VPNUDPSession, 1);
        memcpy(&session->client_ip, &ip6_hdr->src_addr, sizeof(struct in6_addr));
        memcpy(&session->dest_ip, &ip6_hdr->dest_addr, sizeof(struct in6_addr));
        session->client_port = client_port; session->dest_port = dest_port;
        session->session_key = g_strdup(key); session->last_activity = g_get_monotonic_time();
        session->vpn = vpn;
        GError *error = NULL;
        session->upstream_socket = g_socket_new(G_SOCKET_FAMILY_IPV6, G_SOCKET_TYPE_DATAGRAM, G_SOCKET_PROTOCOL_UDP, &error);
        if (!session->upstream_socket) { if (error) g_error_free(error); vpn_udp_session_free(session); g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return; }
        g_socket_set_blocking(session->upstream_socket, FALSE);
        GIOChannel *chan = g_io_channel_unix_new(g_socket_get_fd(session->upstream_socket));
        g_io_channel_set_encoding(chan, NULL, NULL); g_io_channel_set_buffered(chan, FALSE);
        session->upstream_watch_id = g_io_add_watch(chan, G_IO_IN | G_IO_HUP | G_IO_ERR, on_udp_upstream_readable, session);
        g_io_channel_unref(chan);
        g_hash_table_insert(vpn->udp_sessions_v6, g_strdup(session->session_key), session);
    }
    session->last_activity = g_get_monotonic_time();
    GSocketAddress *addr = g_inet_socket_address_new(g_inet_address_new_from_string(dest_str), dest_port);
    GError *error = NULL;
    g_socket_send_to(session->upstream_socket, addr, (const gchar *)payload, payload_len, NULL, &error);
    g_object_unref(addr);
    if (error) g_error_free(error);
    g_mutex_unlock(&vpn->sessions_mutex); g_free(key);
}

static void handle_tcp6_packet(DeadlightVPNManager *vpn, struct ipv6_header *ip6_hdr,
                               struct tcp_header *tcp_hdr, guint8 *payload, gsize payload_len) {
    guint16 client_port = ntohs(tcp_hdr->src_port), dest_port = ntohs(tcp_hdr->dest_port);
    guint8 flags = tcp_hdr->flags;
    guint32 recv_seq = ntohl(tcp_hdr->seq_num), recv_ack = ntohl(tcp_hdr->ack_num);
    gchar dest_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6_hdr->dest_addr, dest_str, INET6_ADDRSTRLEN);
    struct in6_addr client_addr, dest_addr;
    memcpy(&client_addr, &ip6_hdr->src_addr, sizeof(struct in6_addr));
    memcpy(&dest_addr, &ip6_hdr->dest_addr, sizeof(struct in6_addr));
    gchar *key = make_session_key(&client_addr, client_port, &dest_addr, dest_port);
    g_mutex_lock(&vpn->sessions_mutex);
    VPNSession *session = g_hash_table_lookup(vpn->sessions_v6, key);
    if (!session && (flags & TCP_SYN) && !(flags & TCP_ACK)) {
        if (vpn->active_connections >= 1000) { g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return; }
        session = g_new0(VPNSession, 1);
        memcpy(&session->client_ip, &ip6_hdr->src_addr, sizeof(struct in6_addr));
        memcpy(&session->dest_ip, &ip6_hdr->dest_addr, sizeof(struct in6_addr));
        session->client_port = client_port; session->dest_port = dest_port;
        session->session_key = g_strdup(key);
        session->state = VPN_TCP_CLOSED; session->seq = g_random_int(); session->isn = session->seq;
        session->ack = recv_seq + 1; session->created_at = g_get_monotonic_time();
        session->last_activity = session->created_at; session->vpn = vpn;
        GError *error = NULL;
        session->upstream_conn = deadlight_network_connect_tcp(vpn->context, dest_str, dest_port, &error);
        if (!session->upstream_conn) {
            if (error) g_error_free(error);
            send_tcp6_packet(vpn, session, TCP_RST | TCP_ACK, NULL, 0);
            vpn_session_free(session); g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return;
        }
        GSocket *sock = g_socket_connection_get_socket(session->upstream_conn);
        GIOChannel *chan = g_io_channel_unix_new(g_socket_get_fd(sock));
        session->upstream_watch_id = g_io_add_watch(chan, G_IO_IN | G_IO_HUP | G_IO_ERR, on_upstream_readable, session);
        g_io_channel_unref(chan);
        g_hash_table_insert(vpn->sessions_v6, g_strdup(key), session);
        vpn->total_connections++; vpn->active_connections++;
        send_tcp6_packet(vpn, session, TCP_SYN | TCP_ACK, NULL, 0); session->seq++;
        session->state = VPN_TCP_SYN_RECEIVED;
        g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return;
    }
    if (!session) { g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return; }
    session->last_activity = g_get_monotonic_time();
    if (session->state == VPN_TCP_SYN_RECEIVED && (flags & TCP_ACK)) {
        if (recv_ack != session->seq) {
            send_tcp6_packet(vpn, session, TCP_RST, NULL, 0);
            g_hash_table_remove(vpn->sessions_v6, session->session_key); vpn->active_connections--;
            g_mutex_unlock(&vpn->sessions_mutex); g_free(key); return;
        }
        session->state = VPN_TCP_ESTABLISHED;
    }
    if ((session->state == VPN_TCP_ESTABLISHED) && payload_len > 0) {
        GOutputStream *output = g_io_stream_get_output_stream(G_IO_STREAM(session->upstream_conn));
        GError *error = NULL;
        gssize written = g_output_stream_write(output, payload, payload_len, NULL, &error);
        if (written > 0) { session->ack = recv_seq + written; send_tcp6_packet(vpn, session, TCP_ACK, NULL, 0); }
        else if (error) { g_error_free(error); send_tcp6_packet(vpn, session, TCP_RST, NULL, 0); g_hash_table_remove(vpn->sessions_v6, session->session_key); vpn->active_connections--; }
    }
    if (flags & TCP_FIN) {
        session->ack = recv_seq + 1; send_tcp6_packet(vpn, session, TCP_ACK, NULL, 0);
        if (session->state == VPN_TCP_ESTABLISHED) {
            session->state = VPN_TCP_CLOSE_WAIT;
            send_tcp6_packet(vpn, session, TCP_FIN | TCP_ACK, NULL, 0); session->seq++;
            session->state = VPN_TCP_LAST_ACK;
        } else if (session->state == VPN_TCP_FIN_WAIT_1) session->state = VPN_TCP_FIN_WAIT_2;
    }
    if (session->state == VPN_TCP_FIN_WAIT_2 && (flags & TCP_ACK) && recv_ack == session->seq) {
        session->state = VPN_TCP_TIME_WAIT; g_hash_table_remove(vpn->sessions_v6, session->session_key); vpn->active_connections--;
    }
    if (flags & TCP_RST) { g_hash_table_remove(vpn->sessions_v6, session->session_key); vpn->active_connections--; }
    if (session->state == VPN_TCP_LAST_ACK && (flags & TCP_ACK) && recv_ack == session->seq) {
        g_hash_table_remove(vpn->sessions_v6, session->session_key); vpn->active_connections--;
    }
    g_mutex_unlock(&vpn->sessions_mutex); g_free(key);
}

static gboolean on_tun_readable(GIOChannel *source, GIOCondition condition, gpointer user_data) {
    DeadlightVPNManager *vpn = user_data; (void)source;
    if (condition & (G_IO_HUP | G_IO_ERR)) { log_error("VPN: TUN device error or hangup"); return G_SOURCE_REMOVE; }
    guint8 packet[2048];
    gssize bytes = read(vpn->tun_fd, packet, sizeof(packet));
    if (bytes < 0) { if (errno != EAGAIN && errno != EWOULDBLOCK) log_warn("VPN: TUN read error: %s", g_strerror(errno)); return G_SOURCE_CONTINUE; }
    if (bytes > 0) { vpn->bytes_received += bytes; handle_ip_packet(vpn, packet, bytes); }
    return G_SOURCE_CONTINUE;
}

gboolean deadlight_vpn_gateway_init(DeadlightContext *context, GError **error) {
    g_return_val_if_fail(context != NULL, FALSE);
    g_return_val_if_fail(context->vpn != NULL, FALSE);
    DeadlightVPNManager *vpn = context->vpn;
    log_info("VPN: Initializing VPN gateway...");
    gchar *dev_name    = deadlight_config_get_string(context, "vpn", "device",  "tun0");
    gchar *gateway_ip  = deadlight_config_get_string(context, "vpn", "address", "10.8.0.1");
    gchar *netmask     = deadlight_config_get_string(context, "vpn", "netmask", "255.255.255.0");
    vpn->tun_device_name = g_strdup(dev_name);
    vpn->gateway_ip = g_strdup(gateway_ip);
    vpn->netmask = g_strdup(netmask);
    vpn->tun_fd = create_tun_device(dev_name, error);
    g_free(dev_name);
    if (vpn->tun_fd < 0) { g_free(gateway_ip); g_free(netmask); return FALSE; }
    if (!configure_tun_device(vpn->tun_device_name, gateway_ip, netmask, error)) {
        g_free(gateway_ip); g_free(netmask); close(vpn->tun_fd); return FALSE;
    }
    g_free(gateway_ip); g_free(netmask);
    fcntl(vpn->tun_fd, F_SETFL, O_NONBLOCK);
    vpn->tun_channel = g_io_channel_unix_new(vpn->tun_fd);
    g_io_channel_set_encoding(vpn->tun_channel, NULL, NULL);
    g_io_channel_set_buffered(vpn->tun_channel, FALSE);
    vpn->tun_watch_id = g_io_add_watch(vpn->tun_channel, G_IO_IN | G_IO_HUP | G_IO_ERR, on_tun_readable, vpn);
    vpn->sessions = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)vpn_session_free);
    vpn->udp_sessions = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)vpn_udp_session_free);
    vpn->sessions_v6 = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)vpn_session_free);
    vpn->udp_sessions_v6 = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)vpn_udp_session_free);
    g_mutex_init(&vpn->sessions_mutex);
    g_timeout_add_seconds(60, cleanup_idle_sessions, vpn);
    g_timeout_add_seconds(10, cleanup_idle_udp_sessions, vpn);
    g_timeout_add_seconds(10, send_periodic_router_advertisement, vpn);
    log_info("VPN: Gateway initialized successfully on %s", vpn->tun_device_name);
    return TRUE;
}

void deadlight_vpn_gateway_cleanup(DeadlightContext *context) {
    g_return_if_fail(context != NULL);
    g_return_if_fail(context->vpn != NULL);
    DeadlightVPNManager *vpn = context->vpn;
    log_info("VPN: Shutting down gateway...");
    if (vpn->tun_watch_id > 0) { g_source_remove(vpn->tun_watch_id); vpn->tun_watch_id = 0; }
    if (vpn->tun_channel) { g_io_channel_shutdown(vpn->tun_channel, FALSE, NULL); g_io_channel_unref(vpn->tun_channel); vpn->tun_channel = NULL; }
    if (vpn->tun_fd >= 0) { close(vpn->tun_fd); vpn->tun_fd = -1; }
    if (vpn->tun_device_name) {
        gchar *cmd = g_strdup_printf("ip link delete %s 2>/dev/null", vpn->tun_device_name);
        gint ret = system(cmd); (void)ret; g_free(cmd);
    }
    if (vpn->sessions)      { g_hash_table_destroy(vpn->sessions);      vpn->sessions      = NULL; }
    if (vpn->udp_sessions)  { g_hash_table_destroy(vpn->udp_sessions);  vpn->udp_sessions  = NULL; }
    if (vpn->sessions_v6)   { g_hash_table_destroy(vpn->sessions_v6);   vpn->sessions_v6   = NULL; }
    if (vpn->udp_sessions_v6){ g_hash_table_destroy(vpn->udp_sessions_v6); vpn->udp_sessions_v6 = NULL; }
    g_mutex_clear(&vpn->sessions_mutex);
    g_free(vpn->tun_device_name); g_free(vpn->gateway_ip);
    g_free(vpn->client_subnet);   g_free(vpn->netmask);
    log_info("VPN: Gateway cleanup complete");
}

void deadlight_vpn_gateway_get_stats(DeadlightContext *context,
                                     guint64 *active_connections, guint64 *total_connections,
                                     guint64 *bytes_sent, guint64 *bytes_received,
                                     guint *pooled_connections, gdouble *pool_hit_rate) {
    g_return_if_fail(context != NULL);
    g_return_if_fail(context->vpn != NULL);
    DeadlightVPNManager *vpn = context->vpn;
    if (active_connections)  *active_connections  = vpn->active_connections;
    if (total_connections)   *total_connections   = vpn->total_connections;
    if (bytes_sent)          *bytes_sent          = vpn->bytes_sent;
    if (bytes_received)      *bytes_received      = vpn->bytes_received;
    if ((pooled_connections || pool_hit_rate) && context->conn_pool) {
        guint idle = 0, active = 0; guint64 total_gets = 0, cache_hits = 0, evicted = 0, failed = 0; gdouble hit_rate = 0.0;
        connection_pool_get_stats(context->conn_pool, &idle, &active, &total_gets, &cache_hits, &hit_rate, &evicted, &failed);
        if (pooled_connections) *pooled_connections = idle;
        if (pool_hit_rate)      *pool_hit_rate      = hit_rate;
    } else {
        if (pooled_connections) *pooled_connections = 0;
        if (pool_hit_rate)      *pool_hit_rate      = 0.0;
    }
}

#endif /* __APPLE__ */