/*
 * Copyright (c) 2026, AURP Implementation Project
 * All rights reserved.
 *
 * AURP (AppleTalk Update-Based Routing Protocol) - RFC 1504
 * UDP socket handling and packet encoding/decoding
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <atalk/logger.h>
#include <atalk/ddp.h>
#include <atalk/nbp.h>
#include <atalk/util.h>
#include <netatalk/at.h>
#include <netatalk/ddp.h>

#include "aurp.h"
#include "rtmp.h"
#include "interface.h"
#include "atserv.h"
#include "zip.h"
#include "list.h"
#include "multicast.h"
#include "nbp.h"
#include "main.h"

#ifdef __linux__
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#ifndef ETH_P_AT
#define ETH_P_AT 0x809B
#endif
#endif

/* Global AURP configuration */
struct aurp_config aurp_config = {
    .ac_enabled = 0,
    .ac_port = AURP_PORT,
    .ac_open_peering = 0,
    .ac_listen_addr = { INADDR_ANY },
    .ac_local_ip = { INADDR_ANY },
    .ac_peers = NULL
};

/* Global AURP socket file descriptor */
int aurp_fd = -1;

#define AURP_NBP_TRACK_MAX 256
#define AURP_NBP_TRACK_TTL 30

struct aurp_nbp_track {
    uint8_t nbp_id;
    uint16_t src_net;
    uint8_t src_node;
    uint8_t src_socket;
    int is_inbound;         /* 1 = inbound FwdReq (reply goes back via AURP) */
    time_t ts;
    int in_use;
};

static struct aurp_nbp_track aurp_nbp_track[AURP_NBP_TRACK_MAX];

static int aurp_nbp_track_find_slot(uint8_t nbp_id)
{
    int i;
    time_t now = time(NULL);
    int free_slot = -1;

    for (i = 0; i < AURP_NBP_TRACK_MAX; i++) {
        if (aurp_nbp_track[i].in_use) {
            if ((now - aurp_nbp_track[i].ts) > AURP_NBP_TRACK_TTL) {
                aurp_nbp_track[i].in_use = 0;
            } else if (aurp_nbp_track[i].nbp_id == nbp_id) {
                return i;
            }
        }
        if (!aurp_nbp_track[i].in_use && free_slot == -1) {
            free_slot = i;
        }
    }
    return free_slot;
}

void aurp_track_nbp_request(uint8_t nbp_id, uint16_t src_net,
                            uint8_t src_node, uint8_t src_socket)
{
    int slot = aurp_nbp_track_find_slot(nbp_id);
    if (slot >= 0) {
        aurp_nbp_track[slot].nbp_id = nbp_id;
        aurp_nbp_track[slot].src_net = src_net;
        aurp_nbp_track[slot].src_node = src_node;
        aurp_nbp_track[slot].src_socket = src_socket;
        aurp_nbp_track[slot].is_inbound = 0;
        aurp_nbp_track[slot].ts = time(NULL);
        aurp_nbp_track[slot].in_use = 1;
    }
}

void aurp_track_inbound_nbp_request(uint8_t nbp_id, uint16_t src_net,
                                    uint8_t src_node, uint8_t src_socket)
{
    int slot = aurp_nbp_track_find_slot(nbp_id);
    if (slot >= 0) {
        aurp_nbp_track[slot].nbp_id = nbp_id;
        aurp_nbp_track[slot].src_net = src_net;
        aurp_nbp_track[slot].src_node = src_node;
        aurp_nbp_track[slot].src_socket = src_socket;
        aurp_nbp_track[slot].is_inbound = 1;
        aurp_nbp_track[slot].ts = time(NULL);
        aurp_nbp_track[slot].in_use = 1;
    }
}

int aurp_lookup_nbp_request(uint8_t nbp_id, struct sockaddr_at *sat)
{
    int i;
    time_t now = time(NULL);

    for (i = 0; i < AURP_NBP_TRACK_MAX; i++) {
        if (!aurp_nbp_track[i].in_use) {
            continue;
        }
        if ((now - aurp_nbp_track[i].ts) > AURP_NBP_TRACK_TTL) {
            aurp_nbp_track[i].in_use = 0;
            continue;
        }
        if (aurp_nbp_track[i].nbp_id == nbp_id) {
            memset(sat, 0, sizeof(*sat));
#ifdef BSD4_4
            sat->sat_len = sizeof(struct sockaddr_at);
#endif
            sat->sat_family = AF_APPLETALK;
            sat->sat_addr.s_net = htons(aurp_nbp_track[i].src_net);
            sat->sat_addr.s_node = aurp_nbp_track[i].src_node;
            sat->sat_port = aurp_nbp_track[i].src_socket;
            return aurp_nbp_track[i].is_inbound ? 2 : 1;
        }
    }

    return 0;
}

/*
 * Debug helper: hex dump for packet debugging
 */
static void aurp_hexdump(const char *prefix, const char *data, int len)
{
    char line[80];
    int i, j, offset;

    for (i = 0; i < len; i += 16) {
        offset = snprintf(line, sizeof(line), "%s %04x: ", prefix, i);
        if (offset < 0 || offset >= (int)sizeof(line)) {
            continue;
        }
        for (j = 0; j < 16 && (i + j) < len; j++) {
            int wrote = snprintf(line + offset, sizeof(line) - offset,
                                 "%02x ", (unsigned char)data[i + j]);
            if (wrote < 0) {
                break;
            }
            if (wrote >= (int)sizeof(line) - offset) {
                offset = (int)sizeof(line) - 1;
                break;
            }
            offset += wrote;
        }
        /* Pad if less than 16 bytes */
        for (; j < 16; j++) {
            int wrote = snprintf(line + offset, sizeof(line) - offset, "   ");
            if (wrote < 0) {
                break;
            }
            if (wrote >= (int)sizeof(line) - offset) {
                offset = (int)sizeof(line) - 1;
                break;
            }
            offset += wrote;
        }
        if (offset < (int)sizeof(line)) {
            int wrote = snprintf(line + offset, sizeof(line) - offset, " |");
            if (wrote > 0 && wrote < (int)sizeof(line) - offset) {
                offset += wrote;
            } else {
                offset = (int)sizeof(line) - 1;
            }
        }
        for (j = 0; j < 16 && (i + j) < len; j++) {
            char c = data[i + j];
            if (offset >= (int)sizeof(line) - 1) {
                break;
            }
            line[offset++] = (c >= 32 && c < 127) ? c : '.';
            line[offset] = '\0';
        }
        if (offset < (int)sizeof(line) - 1) {
            line[offset++] = '|';
            line[offset] = '\0';
        } else {
            line[sizeof(line) - 1] = '\0';
        }
        LOG(log_debug9, logtype_atalkd, "%s", line);
    }
}

/*
 * DDP checksum verification (long header).
 * Algorithm: checksum := checksum + next byte; rotate MSB to LSB; repeat.
 * Computation covers bytes after checksum field through end of DDP packet.
 */
static uint16_t aurp_ddp_checksum(const unsigned char *ddp, int ddp_len)
{
    uint16_t sum = 0;
    int i;

    for (i = 4; i < ddp_len; i++) {
        sum = (uint16_t)(sum + ddp[i]);
        sum = (uint16_t)((sum << 1) | (sum >> 15));
    }

    if (sum == 0) {
        sum = 0xffff;
    }

    return sum;
}

/*
 * Debug helper: get command name string
 */
static const char *aurp_cmd_name(uint16_t cmd)
{
    switch (cmd) {
        case AURP_CMD_RI_REQ:     return "RI-Req";
        case AURP_CMD_RI_RSP:     return "RI-Rsp";
        case AURP_CMD_RI_ACK:     return "RI-Ack";
        case AURP_CMD_RI_UPD:     return "RI-Upd";
        case AURP_CMD_RD:         return "RD";
        case AURP_CMD_ZI_REQ:     return "ZI-Req";
        case AURP_CMD_ZI_RSP:     return "ZI-Rsp";
        case AURP_CMD_OPEN_REQ:   return "Open-Req";
        case AURP_CMD_OPEN_RSP:   return "Open-Rsp";
        case AURP_CMD_TICKLE:     return "Tickle";
        case AURP_CMD_TICKLE_ACK: return "Tickle-Ack";
        default:                  return "Unknown";
    }
}

/*
 * Debug helper: get recv state name string
 */
static const char *aurp_recv_state_name(int state)
{
    switch (state) {
        case AURP_RECV_UNCONNECTED:      return "UNCONNECTED";
        case AURP_RECV_WAIT_OPEN_RSP:    return "WAIT_OPEN_RSP";
        case AURP_RECV_WAIT_RI_RSP:      return "WAIT_RI_RSP";
        case AURP_RECV_WAIT_ZI_RSP:      return "WAIT_ZI_RSP";
        case AURP_RECV_CONNECTED:        return "CONNECTED";
        case AURP_RECV_WAIT_TICKLE_ACK:  return "WAIT_TICKLE_ACK";
        default:                         return "UNKNOWN";
    }
}

/*
 * Debug helper: get send state name string
 */
static const char *aurp_send_state_name(int state)
{
    switch (state) {
        case AURP_SEND_UNCONNECTED:      return "UNCONNECTED";
        case AURP_SEND_CONNECTED:        return "CONNECTED";
        case AURP_SEND_WAIT_RI_RSP_ACK:  return "WAIT_RI_RSP_ACK";
        case AURP_SEND_WAIT_RI_UPD_ACK:  return "WAIT_RI_UPD_ACK";
        default:                         return "UNKNOWN";
    }
}

/*
 * Sequence number utilities
 */

/* Get next sequence number (skip 0) */
uint16_t aurp_next_seq(uint16_t seq)
{
    seq++;
    if (seq == AURP_SEQ_ZERO) {
        seq = 1;
    }
    return seq;
}

/* Check if seq is the successor of prev */
int aurp_seq_is_successor(uint16_t seq, uint16_t prev)
{
    uint16_t expected = aurp_next_seq(prev);
    return (seq == expected);
}

/*
 * Domain Identifier encoding/decoding
 */

/* Build domain identifier into buffer (RFC 1504 format) */
int aurp_build_domain_id(char *buf, int buflen, struct in_addr *addr)
{
    if (buflen < 2) {
        return -1;
    }

    if (addr->s_addr == INADDR_ANY) {
        /* NULL domain identifier: length=1, authority=0 */
        buf[0] = 1;  /* Length 1 (includes authority byte) */
        buf[1] = AURP_DI_NULL;
        return 2;
    } else {
        /* IP domain identifier (RFC 1504): length=7, authority=1, distinguisher(2), IP(4) */
        if (buflen < 8) {
            return -1;
        }
        buf[0] = 7;  /* Length 7 */
        buf[1] = AURP_DI_IP;
        buf[2] = 0;  /* Distinguisher high byte */
        buf[3] = 0;  /* Distinguisher low byte */
        memcpy(buf + 4, &addr->s_addr, 4);
        return 8;
    }
}

/* Parse domain identifier from buffer (RFC 1504 format) */
int aurp_parse_domain_id(char *buf, int len, struct in_addr *addr)
{
    uint8_t di_len;
    uint8_t di_type;

    if (len < 2) {
        return -1;
    }

    di_len = (uint8_t)buf[0];
    di_type = (uint8_t)buf[1];

    if (di_type == AURP_DI_NULL) {
        addr->s_addr = INADDR_ANY;
        return 2;
    } else if (di_type == AURP_DI_IP) {
        /* RFC 1504: length=7, authority=1, distinguisher(2), IP(4) */
        if (di_len != 7 || len < 8) {
            return -1;
        }
        /* Skip distinguisher bytes (2-3), read IP from bytes 4-7 */
        memcpy(&addr->s_addr, buf + 4, 4);
        return 8;
    } else {
        /* Unknown domain identifier type */
        return -1;
    }
}

/*
 * Domain Header and AURP Header building
 */

/* Build complete domain header into buffer */
static int aurp_build_domain_header(char *buf, int buflen, struct aurp_peer *peer,
                                     uint16_t pkt_type)
{
    int len = 0;
    int n;
    uint16_t tmp;

    /* Destination domain identifier - use what the peer advertises
     * jrouter uses "call you by what you call yourself" doctrine:
     * Use ap_remote_di (the DI the peer sends as their source), NOT ap_addr.
     * Peers behind NAT advertise their private IP, and they validate that
     * incoming packets have that private IP as the destination DI.
     * If ap_remote_di is not yet set, fall back to ap_addr.
     */
    if (peer->ap_remote_di.s_addr != INADDR_ANY) {
        n = aurp_build_domain_id(buf + len, buflen - len, &peer->ap_remote_di);
    } else {
        n = aurp_build_domain_id(buf + len, buflen - len, &peer->ap_addr);
    }
    if (n < 0) return -1;
    len += n;

    /* Source domain identifier (our DI) */
    n = aurp_build_domain_id(buf + len, buflen - len, &peer->ap_local_di);
    if (n < 0) return -1;
    len += n;

    /* Check remaining space for version + reserved + packet type */
    if (buflen - len < 6) {
        return -1;
    }

    /* Version (2 bytes) */
    tmp = htons(AURP_VERSION);
    memcpy(buf + len, &tmp, 2);
    len += 2;

    /* Reserved (2 bytes) */
    tmp = 0;
    memcpy(buf + len, &tmp, 2);
    len += 2;

    /* Packet type (2 bytes) */
    tmp = htons(pkt_type);
    memcpy(buf + len, &tmp, 2);
    len += 2;

    return len;
}

/* Build transport header (connection ID + sequence) */
static int aurp_build_transport_header(char *buf, int buflen, uint16_t conn_id,
                                        uint16_t seq)
{
    uint16_t tmp;

    if (buflen < 4) {
        return -1;
    }

    /* Connection ID (2 bytes, big-endian) */
    tmp = htons(conn_id);
    memcpy(buf, &tmp, 2);

    /* Sequence number (2 bytes, big-endian) */
    tmp = htons(seq);
    memcpy(buf + 2, &tmp, 2);

    return 4;
}

/* Build AURP command header (command code + flags) */
static int aurp_build_cmd_header(char *buf, int buflen, uint16_t cmd,
                                  uint16_t flags)
{
    uint16_t tmp;

    if (buflen < 4) {
        return -1;
    }

    /* Command code (2 bytes, big-endian) */
    tmp = htons(cmd);
    memcpy(buf, &tmp, 2);

    /* Flags (2 bytes, big-endian) */
    tmp = htons(flags);
    memcpy(buf + 2, &tmp, 2);

    return 4;
}

/* Build complete routing packet header (domain + transport + command) */
static int aurp_build_routing_header(char *buf, int buflen, struct aurp_peer *peer,
                                      uint16_t conn_id, uint16_t seq,
                                      uint16_t cmd, uint16_t flags)
{
    int len = 0;
    int n;

    /* Domain header */
    n = aurp_build_domain_header(buf + len, buflen - len, peer, AURP_PKT_ROUTING);
    if (n < 0) return -1;
    len += n;

    /* Transport header */
    n = aurp_build_transport_header(buf + len, buflen - len, conn_id, seq);
    if (n < 0) return -1;
    len += n;

    /* Command header */
    n = aurp_build_cmd_header(buf + len, buflen - len, cmd, flags);
    if (n < 0) return -1;
    len += n;

    return len;
}

/* Legacy function - now builds complete routing header */
int aurp_build_header(char *buf, int buflen, uint16_t conn_id, uint16_t seq,
                      uint16_t cmd, uint16_t flags)
{
    uint16_t tmp;

    if (buflen < 8) {
        return -1;
    }

    /* Connection ID (2 bytes, big-endian) */
    tmp = htons(conn_id);
    memcpy(buf, &tmp, 2);

    /* Sequence number (2 bytes, big-endian) */
    tmp = htons(seq);
    memcpy(buf + 2, &tmp, 2);

    /* Command code (2 bytes, big-endian) */
    tmp = htons(cmd);
    memcpy(buf + 4, &tmp, 2);

    /* Flags (2 bytes, big-endian) */
    tmp = htons(flags);
    memcpy(buf + 6, &tmp, 2);

    return 8;
}

/*
 * Socket initialization
 */

/* Initialize AURP - create UDP socket and bind to configured port */
int aurp_init(struct aurp_config *cfg)
{
    struct sockaddr_in sin;
    int sock;
    int on = 1;

    LOG(log_error, logtype_atalkd, "*** aurp_init: ENTRY - cfg=%p enabled=%d ***",
        cfg, cfg ? cfg->ac_enabled : -1);

    if (!cfg || !cfg->ac_enabled) {
        LOG(log_error, logtype_atalkd, "*** aurp_init: EARLY EXIT - no config or not enabled ***");
        return -1;
    }

    /* Create UDP socket */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG(log_error, logtype_atalkd, "aurp_init: socket() failed: %s",
            strerror(errno));
        return -1;
    }

    /* Set socket options */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        LOG(log_error, logtype_atalkd, "aurp_init: setsockopt(SO_REUSEADDR) failed: %s",
            strerror(errno));
        close(sock);
        return -1;
    }

    /* Bind to configured address and port */
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr = cfg->ac_listen_addr;
    sin.sin_port = htons(cfg->ac_port);

    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        LOG(log_error, logtype_atalkd, "aurp_init: bind(%s:%d) failed: %s",
            inet_ntoa(cfg->ac_listen_addr), cfg->ac_port, strerror(errno));
        close(sock);
        return -1;
    }

    aurp_fd = sock;

    /* Determine our local IP address for domain identifiers
     * Use the bind address if it's not INADDR_ANY, otherwise find interface IP */
    if (cfg->ac_listen_addr.s_addr == INADDR_ANY) {
        /* Use getifaddrs to find first non-loopback IPv4 address */
        struct ifaddrs *ifaddr, *ifa;
        extern struct interface *interfaces;
        struct interface *iface;
        int found = 0;
        
        if (getifaddrs(&ifaddr) == 0) {
            /* First try to match an AppleTalk interface name */
            for (iface = interfaces; iface != NULL && !found; iface = iface->i_next) {
                if ((iface->i_flags & IFACE_CONFIG) && !(iface->i_flags & IFACE_LOOPBACK)) {
                    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
                            strcmp(ifa->ifa_name, iface->i_name) == 0) {
                            struct sockaddr_in *sin_ifa = (struct sockaddr_in *)ifa->ifa_addr;
                            cfg->ac_local_ip = sin_ifa->sin_addr;
                            LOG(log_info, logtype_atalkd, "AURP using local IP %s from interface %s",
                                inet_ntoa(cfg->ac_local_ip), iface->i_name);
                            found = 1;
                            break;
                        }
                    }
                }
            }
            
            /* If no match, use first non-loopback IPv4 address */
            if (!found) {
                for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                    if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                        struct sockaddr_in *sin_ifa = (struct sockaddr_in *)ifa->ifa_addr;
                        if (sin_ifa->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
                            cfg->ac_local_ip = sin_ifa->sin_addr;
                            LOG(log_info, logtype_atalkd, "AURP using local IP %s from interface %s",
                                inet_ntoa(cfg->ac_local_ip), ifa->ifa_name);
                            found = 1;
                            break;
                        }
                    }
                }
            }
            freeifaddrs(ifaddr);
        }
        
        if (!found || cfg->ac_local_ip.s_addr == INADDR_ANY) {
            LOG(log_warning, logtype_atalkd, 
                "AURP: could not determine local IP, using 0.0.0.0 (connections may fail)");
        }
    } else {
        cfg->ac_local_ip = cfg->ac_listen_addr;
        LOG(log_info, logtype_atalkd, "AURP using configured IP %s",
            inet_ntoa(cfg->ac_local_ip));
    }

    LOG(log_info, logtype_atalkd, "AURP initialized on %s:%d",
        inet_ntoa(cfg->ac_listen_addr), cfg->ac_port);

    /* Load peer list from file if configured */
    if (cfg->ac_peerlist_file != NULL) {
        int peers_added = aurp_load_peerlist(cfg->ac_peerlist_file);
        if (peers_added < 0) {
            LOG(log_error, logtype_atalkd,
                "AURP: failed to load peer list from %s (continuing with manual peers)",
                cfg->ac_peerlist_file);
        } else if (peers_added == 0) {
            LOG(log_warning, logtype_atalkd,
                "AURP: no valid peers found in %s", cfg->ac_peerlist_file);
        }
    }

    /* Check if we have any peers configured */
    LOG(log_error, logtype_atalkd, "*** aurp_init: Checking peer list - cfg->ac_peers=%p ***",
        cfg->ac_peers);
    
    if (cfg->ac_peers == NULL) {
        LOG(log_error, logtype_atalkd,
            "*** aurp_init: AURP disabled - no peers configured ***");
        close(sock);
        aurp_fd = -1;
        return -1;
    }

    /* Initiate connections to configured peers */
    LOG(log_error, logtype_atalkd, "*** aurp_init: Initiating peer connections ***");
    struct aurp_peer *peer;
    int peer_count = 0;
    for (peer = cfg->ac_peers; peer != NULL; peer = peer->ap_next) {
        peer_count++;
        LOG(log_error, logtype_atalkd, "*** aurp_init: Calling aurp_peer_connect for peer #%d: %s ***",
            peer_count, inet_ntoa(peer->ap_addr));
        aurp_peer_connect(peer);
    }
    LOG(log_error, logtype_atalkd, "*** aurp_init: Completed %d peer connections ***", peer_count);

    return sock;
}

/*
 * Packet reception and dispatch
 */

/* Forward declaration for data packet handler */
static void aurp_handle_data(struct aurp_peer *peer, char *data, int len);

/* Receive and process AURP packets */
void aurp_input(int fd)
{
    char buf[AURP_MAX_PKT_SIZE];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t len;
    struct aurp_peer *peer;
    struct in_addr peer_addr, dest_di, src_di;
    uint16_t version, reserved, pkt_type;
    uint16_t conn_id, seq, cmd, flags;
    char *p;
    int n, remaining;

    /* Receive UDP packet */
    len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    if (len < 0) {
        LOG(log_error, logtype_atalkd, "aurp_input: recvfrom() failed: %s",
            strerror(errno));
        return;
    }

    LOG(log_debug, logtype_atalkd,
        "*** AURP PACKET RECEIVED: %zd bytes from %s:%d ***",
        len, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
    aurp_hexdump("RECV", buf, len);

    if (len < 22) {  /* Minimum: 2 null DIs (4 bytes) + version(2) + reserved(2) + type(2) + header(8) = 18 */
        LOG(log_debug, logtype_atalkd, "aurp_input: packet too short (%zd bytes)", len);
        return;
    }

    peer_addr = from.sin_addr;
    p = buf;
    remaining = len;

    /*
     * Parse Domain Header (RFC 1504)
     * - Destination Domain Identifier
     * - Source Domain Identifier
     * - Version (2 bytes)
     * - Reserved (2 bytes)
     * - Packet Type (2 bytes)
     */

    /* Parse destination domain identifier */
    n = aurp_parse_domain_id(p, remaining, &dest_di);
    if (n < 0) {
        LOG(log_debug, logtype_atalkd, "aurp_input: failed to parse dest DI from %s",
            inet_ntoa(peer_addr));
        return;
    }
    p += n;
    remaining -= n;

    /* Parse source domain identifier */
    n = aurp_parse_domain_id(p, remaining, &src_di);
    if (n < 0) {
        LOG(log_debug, logtype_atalkd, "aurp_input: failed to parse src DI from %s",
            inet_ntoa(peer_addr));
        return;
    }
    p += n;
    remaining -= n;

    /* Parse version, reserved, packet type */
    if (remaining < 6) {
        LOG(log_debug, logtype_atalkd, "aurp_input: packet too short for domain header");
        return;
    }

    memcpy(&version, p, 2);
    version = ntohs(version);
    memcpy(&reserved, p + 2, 2);
    reserved = ntohs(reserved);
    memcpy(&pkt_type, p + 4, 2);
    pkt_type = ntohs(pkt_type);
    p += 6;
    remaining -= 6;

    LOG(log_debug, logtype_atalkd,
        "aurp_input: parsed domain header: version=0x%04x reserved=0x%04x pkt_type=0x%04x remaining=%d",
        version, reserved, pkt_type, remaining);

    /* Verify version */
    if (version != AURP_VERSION) {
        LOG(log_warning, logtype_atalkd,
            "aurp_input: unsupported version %u from %s", version, inet_ntoa(peer_addr));
        return;
    }

    /* Find or create peer */
    peer = aurp_peer_find(peer_addr);
    if (peer == NULL) {
        if (!aurp_config.ac_open_peering) {
            LOG(log_info, logtype_atalkd,
                "aurp_input: ignoring packet from unknown peer %s (open peering disabled)",
                inet_ntoa(peer_addr));
            return;
        }
        peer = aurp_peer_find_or_create(peer_addr);
        if (peer == NULL) {
            LOG(log_error, logtype_atalkd,
                "aurp_input: failed to create peer for %s", inet_ntoa(peer_addr));
            return;
        }
    }

    /* Update last heard time and remote DI */
    peer->ap_last_heard = time(NULL);
    peer->ap_remote_di = src_di;

    /* Handle packet based on type */
    if (pkt_type == AURP_PKT_APPLETALK) {
        /* Encapsulated AppleTalk data packet */
        LOG(log_debug, logtype_atalkd,
            "*** AURP DATA PACKET RECEIVED! from %s len=%d ***",
            inet_ntoa(peer_addr), remaining);

        /* Log DDP header details if present.
         * DDP Extended Header format:
         *   [0-1] hop+len, [2-3] checksum, [4-5] dst_net, [6-7] src_net,
         *   [8] dst_node, [9] src_node, [10] dst_socket, [11] src_socket, [12] type
         */
        if (remaining >= 13) {
            unsigned char *dp = (unsigned char *)p;
            uint16_t hop_len = (dp[0] << 8) | dp[1];
            uint16_t ddp_len = hop_len & 0x03FF;
            uint16_t dnet = (dp[4] << 8) | dp[5];
            uint16_t snet = (dp[6] << 8) | dp[7];
            LOG(log_debug, logtype_atalkd,
                "aurp_input: DDP %u.%u.%u -> %u.%u.%u proto=%u ddp_len=%u raw_len=%d",
                snet, dp[9], dp[11],   /* src_net, src_node, src_socket */
                dnet, dp[8], dp[10],   /* dst_net, dst_node, dst_socket */
                dp[12], ddp_len, remaining);

            if (ddp_len > remaining) {
                LOG(log_warning, logtype_atalkd,
                    "aurp_input: DDP length %u exceeds payload %d", ddp_len, remaining);
            }
        } else {
            LOG(log_warning, logtype_atalkd,
                "aurp_input: AppleTalk payload too short (%d)", remaining);
        }

        aurp_handle_data(peer, p, remaining);
        return;
    } else if (pkt_type != AURP_PKT_ROUTING) {
        LOG(log_warning, logtype_atalkd,
            "aurp_input: unknown packet type 0x%04x from %s",
            pkt_type, inet_ntoa(peer_addr));
        return;
    }

    /*
     * Parse Transport Header for Routing packets
     * - Connection ID (2 bytes)
     * - Sequence Number (2 bytes)
     * Then AURP Header:
     * - Command Code (2 bytes)
     * - Flags (2 bytes)
     */
    if (remaining < 8) {
        LOG(log_debug, logtype_atalkd,
            "aurp_input: routing packet too short (%d bytes)", remaining);
        return;
    }

    memcpy(&conn_id, p, 2);
    conn_id = ntohs(conn_id);
    memcpy(&seq, p + 2, 2);
    seq = ntohs(seq);
    memcpy(&cmd, p + 4, 2);
    cmd = ntohs(cmd);
    memcpy(&flags, p + 6, 2);
    flags = ntohs(flags);
    p += 8;
    remaining -= 8;

    LOG(log_debug, logtype_atalkd,
        "aurp_input: %s from %s conn_id=%u seq=%u flags=0x%04x data_len=%d recv_state=%s send_state=%s",
        aurp_cmd_name(cmd), inet_ntoa(peer_addr), conn_id, seq, flags, remaining,
        aurp_recv_state_name(peer->ap_recv_state), aurp_send_state_name(peer->ap_send_state));

    /* Update remote connection ID and sequence if appropriate */
    if (cmd == AURP_CMD_OPEN_REQ || cmd == AURP_CMD_OPEN_RSP) {
        peer->ap_remote_conn_id = conn_id;
    }
    peer->ap_remote_seq = seq;

    /* Store flags for handler use */
    peer->ap_last_recv_flags = flags;

    /* Dispatch to appropriate handler */
    switch (cmd) {
        case AURP_CMD_OPEN_REQ:
            aurp_handle_open_req(peer, p, remaining);
            break;
        case AURP_CMD_OPEN_RSP:
            aurp_handle_open_rsp(peer, p, remaining);
            break;
        case AURP_CMD_RI_REQ:
            aurp_handle_ri_req(peer, p, remaining);
            break;
        case AURP_CMD_RI_RSP:
            aurp_handle_ri_rsp(peer, p, remaining);
            break;
        case AURP_CMD_RI_ACK:
            aurp_handle_ri_ack(peer, p, remaining);
            break;
        case AURP_CMD_RI_UPD:
            aurp_handle_ri_upd(peer, p, remaining);
            break;
        case AURP_CMD_RD:
            aurp_handle_rd(peer, p, remaining);
            break;
        case AURP_CMD_ZI_REQ:
            aurp_handle_zi_req(peer, p, remaining);
            break;
        case AURP_CMD_ZI_RSP:
            aurp_handle_zi_rsp(peer, p, remaining);
            break;
        case AURP_CMD_TICKLE:
            aurp_handle_tickle(peer);
            break;
        case AURP_CMD_TICKLE_ACK:
            aurp_handle_tickle_ack(peer);
            break;
        default:
            LOG(log_info, logtype_atalkd,
                "aurp_input: unknown command 0x%04x from %s",
                cmd, inet_ntoa(peer_addr));
            break;
    }
}

/*
 * Packet sending functions
 */

/* Send AURP packet to peer */
static int aurp_send_packet(struct aurp_peer *peer, char *buf, int len)
{
    struct sockaddr_in sin;
    ssize_t sent;

    if (aurp_fd < 0 || peer == NULL || buf == NULL || len <= 0) {
        return -1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr = peer->ap_addr;
    sin.sin_port = htons(aurp_config.ac_port);

    LOG(log_debug, logtype_atalkd,
        "aurp_send_packet: sending %d bytes to %s:%d",
        len, inet_ntoa(peer->ap_addr), aurp_config.ac_port);
    aurp_hexdump("SEND", buf, len);

    sent = sendto(aurp_fd, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin));
    if (sent < 0) {
        LOG(log_error, logtype_atalkd, "aurp_send_packet: sendto(%s) failed: %s",
            inet_ntoa(peer->ap_addr), strerror(errno));
        return -1;
    }

    if (sent != len) {
        LOG(log_warning, logtype_atalkd,
            "aurp_send_packet: partial send to %s (%zd of %d bytes)",
            inet_ntoa(peer->ap_addr), sent, len);
        return -1;
    }

    peer->ap_last_send = time(NULL);
    return 0;
}

/* Send Open-Req */
int aurp_send_open_req(struct aurp_peer *peer)
{
    char buf[256];
    int len = 0;
    int n;
    uint16_t version;

    /* Build routing header (domain + transport + command) */
    n = aurp_build_routing_header(buf, sizeof(buf), peer, peer->ap_local_conn_id,
                                   0, AURP_CMD_OPEN_REQ, AURP_FLAG_SUI_ALL);
    if (n < 0) return -1;
    len += n;

    /* AURP version (2 bytes) */
    version = htons(AURP_VERSION);
    memcpy(buf + len, &version, 2);
    len += 2;

    /* Option count (1 byte) - per jrouter/RFC, this is a single byte */
    buf[len++] = 0;  /* No options */

    /* Send packet */
    if (aurp_send_packet(peer, buf, len) < 0) {
        return -1;
    }

    /* Save for retransmission */
    if (peer->ap_last_pkt) {
        free(peer->ap_last_pkt);
    }
    peer->ap_last_pkt = malloc(len);
    if (peer->ap_last_pkt) {
        memcpy(peer->ap_last_pkt, buf, len);
        peer->ap_last_pkt_len = len;
    }

    LOG(log_info, logtype_atalkd, "aurp_send_open_req: sent to %s",
        inet_ntoa(peer->ap_addr));

    return 0;
}

/* Send Open-Rsp */
int aurp_send_open_rsp(struct aurp_peer *peer, int16_t result)
{
    char buf[256];
    int len = 0;
    int n;
    int16_t error_code;

    /* Build routing header (domain + transport + command) */
    n = aurp_build_routing_header(buf, sizeof(buf), peer, peer->ap_remote_conn_id,
                                   0, AURP_CMD_OPEN_RSP, 0);
    if (n < 0) return -1;
    len += n;

    /* Error code / update rate (2 bytes, signed, big-endian) */
    error_code = htons((uint16_t)result);
    memcpy(buf + len, &error_code, 2);
    len += 2;

    /* Option count (1 byte) - per jrouter/RFC, this is a single byte */
    buf[len++] = 0;  /* No options */

    /* Send packet */
    if (aurp_send_packet(peer, buf, len) < 0) {
        return -1;
    }

    LOG(log_info, logtype_atalkd, "aurp_send_open_rsp: sent to %s result=%d",
        inet_ntoa(peer->ap_addr), result);

    return 0;
}

/* Send RI-Req */
int aurp_send_ri_req(struct aurp_peer *peer)
{
    char buf[256];
    int len = 0;
    int n;

    /* Build routing header (domain + transport + command) */
    /* Request zone information along with routing info */
    n = aurp_build_routing_header(buf, sizeof(buf), peer, peer->ap_local_conn_id,
                                   0, AURP_CMD_RI_REQ, AURP_FLAG_SUI_ALL | AURP_FLAG_SZI);
    if (n < 0) return -1;
    len += n;

    /* Send packet */
    if (aurp_send_packet(peer, buf, len) < 0) {
        return -1;
    }

    /* Save for retransmission */
    if (peer->ap_last_pkt) {
        free(peer->ap_last_pkt);
    }
    peer->ap_last_pkt = malloc(len);
    if (peer->ap_last_pkt) {
        memcpy(peer->ap_last_pkt, buf, len);
        peer->ap_last_pkt_len = len;
    }

    LOG(log_info, logtype_atalkd, "aurp_send_ri_req: sent to %s",
        inet_ntoa(peer->ap_addr));

    return 0;
}

/* Send Tickle */
int aurp_send_tickle(struct aurp_peer *peer)
{
    char buf[256];
    int len = 0;
    int n;

    /* Build routing header (domain + transport + command) */
    n = aurp_build_routing_header(buf, sizeof(buf), peer, peer->ap_local_conn_id,
                                   0, AURP_CMD_TICKLE, 0);
    if (n < 0) return -1;
    len += n;

    /* Send packet */
    if (aurp_send_packet(peer, buf, len) < 0) {
        return -1;
    }

    /* Save for retransmission */
    if (peer->ap_last_pkt) {
        free(peer->ap_last_pkt);
    }
    peer->ap_last_pkt = malloc(len);
    if (peer->ap_last_pkt) {
        memcpy(peer->ap_last_pkt, buf, len);
        peer->ap_last_pkt_len = len;
    }

    LOG(log_debug, logtype_atalkd, "aurp_send_tickle: sent to %s",
        inet_ntoa(peer->ap_addr));

    return 0;
}

/* Send Tickle-Ack */
int aurp_send_tickle_ack(struct aurp_peer *peer)
{
    char buf[256];
    int len = 0;
    int n;

    /* Build routing header (domain + transport + command) */
    n = aurp_build_routing_header(buf, sizeof(buf), peer, peer->ap_remote_conn_id,
                                   0, AURP_CMD_TICKLE_ACK, 0);
    if (n < 0) return -1;
    len += n;

    /* Send packet */
    if (aurp_send_packet(peer, buf, len) < 0) {
        return -1;
    }

    LOG(log_debug, logtype_atalkd, "aurp_send_tickle_ack: sent to %s",
        inet_ntoa(peer->ap_addr));

    return 0;
}

/*
 * RI-Rsp - Send routing information response
 * Builds network tuples from our local routes
 */
int aurp_send_ri_rsp(struct aurp_peer *peer, int last)
{
    char buf[AURP_MAX_PKT_SIZE];
    int len = 0;
    int n;
    uint16_t flags = 0;
    uint16_t tmp;
    struct interface *iface;
    extern struct interface *interfaces;

    if (last) {
        flags |= AURP_FLAG_LAST;
    }

    /* Build routing header (domain + transport + command) */
    n = aurp_build_routing_header(buf, sizeof(buf), peer, peer->ap_remote_conn_id,
                                   peer->ap_local_seq, AURP_CMD_RI_RSP, flags);
    if (n < 0) return -1;
    len += n;

    /* Build network tuples from our local interfaces */
    int iface_count = 0, skipped_unconfig = 0, skipped_loopback = 0, added_count = 0;
    for (iface = interfaces; iface != NULL; iface = iface->i_next) {
        uint16_t firstnet, lastnet;
        uint8_t dist;
        
        iface_count++;

        /* Skip unconfigured interfaces */
        if ((iface->i_flags & IFACE_CONFIG) == 0) {
            skipped_unconfig++;
            LOG(log_debug, logtype_atalkd,
                "aurp_send_ri_rsp: skipping unconfigured interface (flags=0x%x)",
                iface->i_flags);
            continue;
        }

        /* Skip loopback */
        if (iface->i_flags & IFACE_LOOPBACK) {
            skipped_loopback++;
            continue;
        }

        firstnet = ntohs(iface->i_rt->rt_firstnet);
        lastnet = ntohs(iface->i_rt->rt_lastnet);
        dist = 0;  /* Distance 0 for directly connected networks */

        /* Check if this is an extended (Phase 2) network */
        int is_extended = (iface->i_flags & IFACE_PHASE2) ? 1 : 0;

        /* Check buffer space */
        if (len + 6 > sizeof(buf)) {
            LOG(log_warning, logtype_atalkd,
                "aurp_send_ri_rsp: packet full, need multiple packets");
            break;
        }

        if (firstnet == lastnet && !is_extended) {
            /* Non-extended tuple (3 bytes) - single network, Phase 1 */
            tmp = htons(firstnet);
            memcpy(buf + len, &tmp, 2);
            len += 2;
            buf[len++] = dist;
        } else {
            /* Extended tuple (6 bytes) - Phase 2 or network range */
            tmp = htons(firstnet);
            memcpy(buf + len, &tmp, 2);
            len += 2;
            buf[len++] = dist | 0x80;  /* Extended flag */
            tmp = htons(lastnet);
            memcpy(buf + len, &tmp, 2);
            len += 2;
            buf[len++] = 0x00;  /* Reserved */
        }

        LOG(log_debug, logtype_atalkd,
            "aurp_send_ri_rsp: adding network %u-%u dist %u (extended=%d)",
            firstnet, lastnet, dist, is_extended);
        added_count++;
    }
    
    LOG(log_info, logtype_atalkd,
        "aurp_send_ri_rsp: %d interfaces, added %d networks",
        iface_count, added_count);

    /* Send packet */
    if (aurp_send_packet(peer, buf, len) < 0) {
        return -1;
    }

    /* Save for retransmission */
    if (peer->ap_last_pkt) {
        free(peer->ap_last_pkt);
    }
    peer->ap_last_pkt = malloc(len);
    if (peer->ap_last_pkt) {
        memcpy(peer->ap_last_pkt, buf, len);
        peer->ap_last_pkt_len = len;
    }

    peer->ap_local_seq = aurp_next_seq(peer->ap_local_seq);

    LOG(log_info, logtype_atalkd, "aurp_send_ri_rsp: sent to %s (last=%d)",
        inet_ntoa(peer->ap_addr), last);

    return 0;
}

/*
 * RI-Ack - Send routing information acknowledgement
 */
int aurp_send_ri_ack(struct aurp_peer *peer, uint16_t flags)
{
    char buf[256];
    int len = 0;
    int n;

    /* Build routing header (domain + transport + command) */
    n = aurp_build_routing_header(buf, sizeof(buf), peer, peer->ap_local_conn_id,
                                   peer->ap_remote_seq, AURP_CMD_RI_ACK, flags);
    if (n < 0) return -1;
    len += n;

    /* Send packet */
    if (aurp_send_packet(peer, buf, len) < 0) {
        return -1;
    }

    LOG(log_debug, logtype_atalkd, "aurp_send_ri_ack: sent to %s flags=0x%04x",
        inet_ntoa(peer->ap_addr), flags);

    return 0;
}

/*
 * RI-Upd - Send routing information update with pending events
 */
int aurp_send_ri_upd(struct aurp_peer *peer)
{
    char buf[AURP_MAX_PKT_SIZE];
    int len = 0;
    int n, i;
    uint16_t tmp;

    if (peer->ap_pending_count == 0) {
        return 0;  /* Nothing to send */
    }

    /* Build routing header (domain + transport + command) */
    n = aurp_build_routing_header(buf, sizeof(buf), peer, peer->ap_remote_conn_id,
                                   peer->ap_local_seq, AURP_CMD_RI_UPD, 0);
    if (n < 0) return -1;
    len += n;

    /* Build event tuples */
    for (i = 0; i < peer->ap_pending_count && len + 6 < sizeof(buf); i++) {
        struct aurp_event *evt = &peer->ap_pending[i];

        buf[len++] = evt->ae_code;

        if (evt->ae_code == AURP_EVT_NULL) {
            continue;  /* Null event is just the code */
        }

        tmp = htons(evt->ae_firstnet);
        memcpy(buf + len, &tmp, 2);
        len += 2;

        if (evt->ae_firstnet == evt->ae_lastnet) {
            /* Non-extended tuple */
            buf[len++] = evt->ae_distance;
        } else {
            /* Extended tuple */
            buf[len++] = evt->ae_distance | 0x80;
            tmp = htons(evt->ae_lastnet);
            memcpy(buf + len, &tmp, 2);
            len += 2;
        }
    }

    /* Send packet */
    if (aurp_send_packet(peer, buf, len) < 0) {
        return -1;
    }

    /* Save for retransmission */
    if (peer->ap_last_pkt) {
        free(peer->ap_last_pkt);
    }
    peer->ap_last_pkt = malloc(len);
    if (peer->ap_last_pkt) {
        memcpy(peer->ap_last_pkt, buf, len);
        peer->ap_last_pkt_len = len;
    }

    peer->ap_local_seq = aurp_next_seq(peer->ap_local_seq);
    peer->ap_send_state = AURP_SEND_WAIT_RI_UPD_ACK;

    LOG(log_info, logtype_atalkd, "aurp_send_ri_upd: sent %d events to %s",
        peer->ap_pending_count, inet_ntoa(peer->ap_addr));

    /* Clear pending events */
    peer->ap_pending_count = 0;

    return 0;
}

/*
 * RD - Send Router Down notification
 */
int aurp_send_rd(struct aurp_peer *peer, int16_t error)
{
    char buf[256];
    int len = 0;
    int n;
    int16_t error_net;

    /* Build routing header (domain + transport + command) */
    n = aurp_build_routing_header(buf, sizeof(buf), peer, peer->ap_local_conn_id,
                                   0, AURP_CMD_RD, 0);
    if (n < 0) return -1;
    len += n;

    /* Error code (2 bytes, signed, big-endian) */
    error_net = htons((uint16_t)error);
    memcpy(buf + len, &error_net, 2);
    len += 2;

    /* Send packet */
    if (aurp_send_packet(peer, buf, len) < 0) {
        return -1;
    }

    LOG(log_info, logtype_atalkd, "aurp_send_rd: sent to %s error=%d",
        inet_ntoa(peer->ap_addr), error);

    return 0;
}

/*
 * ZI-Req - Send zone information request for specific networks
 */
int aurp_send_zi_req(struct aurp_peer *peer, uint16_t *nets, int count)
{
    char buf[AURP_MAX_PKT_SIZE];
    int len = 0;
    int n, i;
    uint16_t tmp;

    if (count == 0) {
        return 0;  /* Nothing to request */
    }

    /* Build routing header (domain + transport + command) */
    n = aurp_build_routing_header(buf, sizeof(buf), peer, peer->ap_local_conn_id,
                                   0, AURP_CMD_ZI_REQ, 0);
    if (n < 0) return -1;
    len += n;

    /* Subcode (2 bytes) */
    tmp = htons(AURP_SUBCODE_ZI_REQ);
    memcpy(buf + len, &tmp, 2);
    len += 2;

    /* Network numbers (2 bytes each) */
    for (i = 0; i < count && len + 2 <= sizeof(buf); i++) {
        tmp = htons(nets[i]);
        memcpy(buf + len, &tmp, 2);
        len += 2;
    }

    /* Send packet */
    if (aurp_send_packet(peer, buf, len) < 0) {
        return -1;
    }

    /* Save for retransmission */
    if (peer->ap_last_pkt) {
        free(peer->ap_last_pkt);
    }
    peer->ap_last_pkt = malloc(len);
    if (peer->ap_last_pkt) {
        memcpy(peer->ap_last_pkt, buf, len);
        peer->ap_last_pkt_len = len;
    }

    LOG(log_info, logtype_atalkd, "aurp_send_zi_req: sent request for %d networks to %s",
        count, inet_ntoa(peer->ap_addr));

    return 0;
}

/*
 * ZI-Rsp - Send zone information response
 * Builds zone tuples from our local interfaces
 */
int aurp_send_zi_rsp(struct aurp_peer *peer, int last)
{
    char buf[AURP_MAX_PKT_SIZE];
    int len = 0;
    int n;
    uint16_t flags = 0;
    uint16_t tmp, zone_count = 0;
    char *zone_count_ptr;
    struct interface *iface;
    struct list *l;
    struct ziptab *zt;
    extern struct interface *interfaces;

    if (last) {
        flags |= AURP_FLAG_LAST;
    }

    /* Build routing header (domain + transport + command) */
    n = aurp_build_routing_header(buf, sizeof(buf), peer, peer->ap_remote_conn_id,
                                   0, AURP_CMD_ZI_RSP, flags);
    if (n < 0) return -1;
    len += n;

    /* Subcode (2 bytes) - use non-extended for simplicity */
    tmp = htons(AURP_SUBCODE_ZI_NONEXT);
    memcpy(buf + len, &tmp, 2);
    len += 2;

    /* Zone count placeholder (2 bytes) - we'll fill it in later */
    zone_count_ptr = buf + len;
    len += 2;

    /* Build zone tuples from our local interfaces */
    for (iface = interfaces; iface != NULL; iface = iface->i_next) {
        uint16_t network;

        /* Skip unconfigured interfaces */
        if ((iface->i_flags & IFACE_CONFIG) == 0) {
            continue;
        }

        /* Skip loopback */
        if (iface->i_flags & IFACE_LOOPBACK) {
            continue;
        }

        /* Skip interfaces without routes or zones */
        if (iface->i_rt == NULL || iface->i_rt->rt_zt == NULL) {
            continue;
        }

        network = ntohs(iface->i_rt->rt_firstnet);

        /* Add zone tuples for each zone on this network */
        for (l = iface->i_rt->rt_zt; l != NULL; l = l->l_next) {
            zt = (struct ziptab *)l->l_data;

            /* Check buffer space: network(2) + length(1) + name(n) */
            if (len + 3 + zt->zt_len > sizeof(buf)) {
                LOG(log_warning, logtype_atalkd,
                    "aurp_send_zi_rsp: packet full, need multiple packets");
                goto send;
            }

            /* Network number (2 bytes) */
            tmp = htons(network);
            memcpy(buf + len, &tmp, 2);
            len += 2;

            /* Zone name length (1 byte) + name */
            buf[len++] = zt->zt_len;
            memcpy(buf + len, zt->zt_name, zt->zt_len);
            len += zt->zt_len;

            zone_count++;

            LOG(log_debug, logtype_atalkd,
                "aurp_send_zi_rsp: adding zone '%.*s' for network %u",
                zt->zt_len, zt->zt_name, network);
        }
    }

send:
    /* Fill in zone count */
    tmp = htons(zone_count);
    memcpy(zone_count_ptr, &tmp, 2);

    /* Send packet */
    if (aurp_send_packet(peer, buf, len) < 0) {
        return -1;
    }

    peer->ap_local_seq = aurp_next_seq(peer->ap_local_seq);

    LOG(log_info, logtype_atalkd, "aurp_send_zi_rsp: sent %u zones to %s (last=%d)",
        zone_count, inet_ntoa(peer->ap_addr), last);

    return 0;
}

/*
 * ZI-Rsp - Send zone information response for requested networks only
 * Splits across multiple packets if needed and sets LAST on final packet.
 */
int aurp_send_zi_rsp_for_nets(struct aurp_peer *peer, const uint16_t *nets, int count)
{
    char buf[AURP_MAX_PKT_SIZE];
    int len = 0;
    uint16_t tmp, zone_count = 0;
    char *zone_count_ptr = NULL;
    int sent_any = 0;
    int ret = 0;
    int i;
    struct interface *iface;
    struct list *l;
    struct ziptab *zt;
    extern struct interface *interfaces;

    if (peer == NULL || nets == NULL || count <= 0) {
        return -1;
    }

    for (i = 0; i < count; i++) {
        uint16_t network = nets[i];

        /* Find interface that owns this network (local interface routes) */
        for (iface = interfaces; iface != NULL; iface = iface->i_next) {
            uint16_t firstnet, lastnet;

            if ((iface->i_flags & IFACE_CONFIG) == 0 || iface->i_rt == NULL) {
                continue;
            }
            if (iface->i_flags & IFACE_LOOPBACK) {
                continue;
            }

            firstnet = ntohs(iface->i_rt->rt_firstnet);
            lastnet = ntohs(iface->i_rt->rt_lastnet);

            if (network < firstnet || network > lastnet) {
                continue;
            }

            if (iface->i_rt->rt_zt == NULL) {
                break;
            }

            for (l = iface->i_rt->rt_zt; l != NULL; l = l->l_next) {
                zt = (struct ziptab *)l->l_data;

                if (len == 0) {
                    int n = aurp_build_routing_header(buf, sizeof(buf), peer,
                                                     peer->ap_remote_conn_id,
                                                     0, AURP_CMD_ZI_RSP, 0);
                    if (n < 0) {
                        return -1;
                    }
                    len = n;

                    tmp = htons(AURP_SUBCODE_ZI_NONEXT);
                    memcpy(buf + len, &tmp, 2);
                    len += 2;

                    zone_count_ptr = buf + len;
                    len += 2;
                    zone_count = 0;
                }

                /* Ensure space: network(2) + length(1) + name(n) */
                if (len + 3 + zt->zt_len > (int)sizeof(buf)) {
                    tmp = htons(zone_count);
                    memcpy(zone_count_ptr, &tmp, 2);

                    if (aurp_send_packet(peer, buf, len) < 0) {
                        return -1;
                    }
                    sent_any = 1;
                    len = 0;
                    zone_count_ptr = NULL;
                    zone_count = 0;
                }

                if (len == 0) {
                    int n = aurp_build_routing_header(buf, sizeof(buf), peer,
                                                     peer->ap_remote_conn_id,
                                                     0, AURP_CMD_ZI_RSP, 0);
                    if (n < 0) {
                        return -1;
                    }
                    len = n;

                    tmp = htons(AURP_SUBCODE_ZI_NONEXT);
                    memcpy(buf + len, &tmp, 2);
                    len += 2;

                    zone_count_ptr = buf + len;
                    len += 2;
                    zone_count = 0;
                }

                tmp = htons(network);
                memcpy(buf + len, &tmp, 2);
                len += 2;

                buf[len++] = zt->zt_len;
                memcpy(buf + len, zt->zt_name, zt->zt_len);
                len += zt->zt_len;

                zone_count++;
            }

            break;
        }
    }

    if (len == 0 && !sent_any) {
        int n = aurp_build_routing_header(buf, sizeof(buf), peer,
                                         peer->ap_remote_conn_id,
                                         0, AURP_CMD_ZI_RSP, AURP_FLAG_LAST);
        if (n < 0) {
            return -1;
        }
        len = n;
        tmp = htons(AURP_SUBCODE_ZI_NONEXT);
        memcpy(buf + len, &tmp, 2);
        len += 2;
        tmp = htons(0);
        memcpy(buf + len, &tmp, 2);
        len += 2;

        ret = aurp_send_packet(peer, buf, len);
        goto done;
    }

    if (len == 0 && sent_any) {
        int n = aurp_build_routing_header(buf, sizeof(buf), peer,
                                         peer->ap_remote_conn_id,
                                         0, AURP_CMD_ZI_RSP, AURP_FLAG_LAST);
        if (n < 0) {
            return -1;
        }
        len = n;
        tmp = htons(AURP_SUBCODE_ZI_NONEXT);
        memcpy(buf + len, &tmp, 2);
        len += 2;
        tmp = htons(0);
        memcpy(buf + len, &tmp, 2);
        len += 2;

        ret = aurp_send_packet(peer, buf, len);
        goto done;
    }

    if (len > 0) {
        char header_buf[AURP_MAX_PKT_SIZE];
        int header_len;

        header_len = aurp_build_routing_header(header_buf, sizeof(header_buf), peer,
                                               peer->ap_remote_conn_id,
                                               0, AURP_CMD_ZI_RSP, AURP_FLAG_LAST);
        if (header_len < 0) {
            return -1;
        }

        memcpy(buf, header_buf, header_len);
        tmp = htons(zone_count);
        memcpy(zone_count_ptr, &tmp, 2);

        if (aurp_send_packet(peer, buf, len) < 0) {
            return -1;
        }
    }

done:
    if (ret < 0) {
        return -1;
    }

    peer->ap_local_seq = aurp_next_seq(peer->ap_local_seq);

    LOG(log_info, logtype_atalkd,
        "aurp_send_zi_rsp_for_nets: sent zones for %d networks to %s",
        count, inet_ntoa(peer->ap_addr));

    return 0;
}

/*
 * Data Forwarding Functions
 */

/* Persistent AF_PACKET socket fd shared across all raw send/recv operations.
 * Opening and closing an AF_PACKET socket per-send causes synchronize_rcu()
 * D-state hangs (packet_release → synchronize_rcu) under frequent access.
 * This fd is initialised once by aurp_raw_init() and reused forever. */
static int g_raw_fd = -1;

void aurp_set_raw_fd(int fd)
{
    g_raw_fd = fd;
}

int aurp_get_raw_fd(void)
{
    return g_raw_fd;
}

int aurp_raw_init(void)
{
#ifdef __linux__
    int fd;
    int one = 1;

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_802_2));
    if (fd < 0) {
        LOG(log_warning, logtype_atalkd,
            "aurp_raw_init: socket(AF_PACKET) failed: %s", strerror(errno));
        return -1;
    }

#ifdef PACKET_IGNORE_OUTGOING
    if (setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one)) < 0) {
        LOG(log_debug, logtype_atalkd,
            "aurp_raw_init: PACKET_IGNORE_OUTGOING not set: %s", strerror(errno));
    }
#endif

    g_raw_fd = fd;
    return fd;
#else
    return -1;
#endif
}

void aurp_raw_input(int fd)
{
#ifdef __linux__
    unsigned char buf[2048];
    struct sockaddr_ll sll;
    socklen_t sll_len = sizeof(sll);
    int len;

    len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&sll, &sll_len);
    if (len <= 0) {
        return;
    }

    if (len < 22) {
        return;
    }

    /* 802.2 SNAP header check: AA AA 03 00 00 00 80 9B */
    if (buf[14] != 0xAA || buf[15] != 0xAA || buf[16] != 0x03 ||
        buf[17] != 0x00 || buf[18] != 0x00 || buf[19] != 0x00 ||
        buf[20] != ((ETH_P_AT >> 8) & 0xFF) || buf[21] != (ETH_P_AT & 0xFF)) {
        return;
    }

    /* DDP starts after 14-byte 802.3 header + 8-byte SNAP */
    unsigned char *ddp = buf + 22;
    int ddp_avail = len - 22;
    if (ddp_avail < 13) {
        return;
    }

    uint16_t hop_len = (ddp[0] << 8) | ddp[1];
    uint16_t ddp_len = hop_len & 0x3FF;
    if (ddp_len < 13 || ddp_len > ddp_avail) {
        return;
    }

    uint16_t dst_net = (ddp[4] << 8) | ddp[5];
    if (dst_net == 0) {
        return;
    }

    /* Avoid duplicating NBP forwarding (handled in nbp.c). */
    if (ddp[12] == DDPTYPE_NBP) {
        return;
    }

    if (aurp_find_peer_for_net(dst_net) == NULL) {
        return;
    }

    /* Increment hop count (4 bits) if possible. */
    uint16_t hop = (hop_len >> 10) & 0x0F;
    if (hop >= 15) {
        return;
    }
    hop_len = (uint16_t)(((hop + 1) << 10) | (ddp_len & 0x3FF));

    unsigned char ddp_copy[2048];
    if (ddp_len > sizeof(ddp_copy)) {
        return;
    }
    memcpy(ddp_copy, ddp, ddp_len);
    ddp_copy[0] = (hop_len >> 8) & 0xFF;
    ddp_copy[1] = hop_len & 0xFF;

    if (aurp_send_data(dst_net, (char *)ddp_copy, ddp_len) < 0) {
        LOG(log_debug, logtype_atalkd,
            "aurp_raw_input: failed forwarding DDP to net %u", dst_net);
    } else {
        LOG(log_debug, logtype_atalkd,
            "aurp_raw_input: forwarded DDP type %u to net %u", ddp_copy[12], dst_net);
    }
#else
    (void)fd;
#endif
}

#ifdef __linux__
static int aurp_send_zone_multicast(struct interface *iface,
                                    const unsigned char *dst_hw,
                                    const unsigned char *ddp, int ddp_len)
{
    unsigned char frame[1600];
    unsigned char src_hw[6];
    struct ifreq ifr;
    struct sockaddr_ll sll;
    uint16_t llc_len;
    unsigned char *p = frame;
    int frame_len;

    if (ddp_len <= 0 || ddp_len > 1400) {
        return -1;
    }

    /* Use the persistent raw fd — never open/close per-send to avoid
     * synchronize_rcu() D-state hangs in packet_release(). */
    if (g_raw_fd < 0) {
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface->i_name, sizeof(ifr.ifr_name) - 1);

    if (ioctl(g_raw_fd, SIOCGIFINDEX, &ifr) < 0) {
        return -1;
    }

    if (ioctl(g_raw_fd, SIOCGIFHWADDR, &ifr) < 0) {
        return -1;
    }

    memcpy(src_hw, ifr.ifr_hwaddr.sa_data, sizeof(src_hw));

    memcpy(p, dst_hw, 6);
    p += 6;
    memcpy(p, src_hw, 6);
    p += 6;

    llc_len = htons((uint16_t)(8 + ddp_len));
    memcpy(p, &llc_len, sizeof(llc_len));
    p += sizeof(llc_len);

    p[0] = 0xAA;
    p[1] = 0xAA;
    p[2] = 0x03;
    p[3] = 0x00;
    p[4] = 0x00;
    p[5] = 0x00;
    p[6] = (ETH_P_AT >> 8) & 0xFF;
    p[7] = ETH_P_AT & 0xFF;
    p += 8;

    memcpy(p, ddp, ddp_len);

    frame_len = 14 + 8 + ddp_len;

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_802_2);
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, dst_hw, 6);

    if (sendto(g_raw_fd, frame, frame_len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        return -1;
    }

    return 0;
}
#endif

static int aurp_try_zone_multicast(struct interface *iface, struct ziptab *zt,
                                   const unsigned char *ddp, int ddp_len,
                                   uint8_t dst_socket)
{
#ifdef __linux__
    unsigned char *ddp_copy;

    if (zt == NULL || zt->zt_bcast == NULL || ddp_len < 13) {
        return 0;
    }

    ddp_copy = (unsigned char *)malloc(ddp_len);
    if (ddp_copy == NULL) {
        return 0;
    }

    memcpy(ddp_copy, ddp, ddp_len);
    ddp_copy[4] = 0x00;
    ddp_copy[5] = 0x00;
    ddp_copy[6] = ATADDR_BCAST;
    ddp_copy[7] = dst_socket;

    if (aurp_send_zone_multicast(iface, zt->zt_bcast, ddp_copy, ddp_len) == 0) {
        free(ddp_copy);
        return 1;
    }

    free(ddp_copy);
#endif
    (void)iface;
    (void)zt;
    (void)ddp;
    (void)ddp_len;
    (void)dst_socket;
    return 0;
}

/*
 * Find the AURP peer that provides a route to the given network
 * Returns NULL if no AURP peer serves that network
 */
struct aurp_peer *aurp_find_peer_for_net(uint16_t net)
{
    struct aurp_peer *peer;
    struct rtmptab *rt;
    int peer_count = 0;
    int route_count = 0;

    LOG(log_debug, logtype_atalkd,
        "aurp_find_peer_for_net: looking for network %u", net);

    for (peer = aurp_config.ac_peers; peer != NULL; peer = peer->ap_next) {
        peer_count++;
        
        if (peer->ap_recv_state != AURP_RECV_CONNECTED && 
            peer->ap_recv_state != AURP_RECV_WAIT_TICKLE_ACK) {
            continue;
        }

        route_count = 0;
        for (rt = peer->ap_routes; rt != NULL; rt = rt->rt_next) {
            uint16_t firstnet = ntohs(rt->rt_firstnet);
            uint16_t lastnet = ntohs(rt->rt_lastnet);
            route_count++;

            if (net >= firstnet && net <= lastnet) {
                LOG(log_debug, logtype_atalkd,
                    "aurp_find_peer_for_net: net %u -> peer %s (route %u-%u)",
                    net, inet_ntoa(peer->ap_addr), firstnet, lastnet);
                return peer;
            }
        }
    }

    LOG(log_warning, logtype_atalkd,
        "aurp_find_peer_for_net: no peer for network %u (checked %d peers)",
        net, peer_count);

    return NULL;
}

/*
 * Handle incoming AURP data packet (encapsulated DDP)
 * Parse the DDP header and forward to local AppleTalk network
 */
static void aurp_handle_data(struct aurp_peer *peer, char *data, int len)
{
    struct ddpehdr *ddp;
    struct sockaddr_at sat;
    struct interface *iface, *dest_iface = NULL;
    struct atport *ap;
    extern struct interface *interfaces;
    uint16_t dst_net, src_net;
    uint8_t dst_node, src_node, dst_socket;
    int ddp_len;

    LOG(log_debug, logtype_atalkd,
        "aurp_handle_data: peer=%s len=%d",
        inet_ntoa(peer->ap_addr), len);

    /* Need at least the DDP header (12 bytes) + type (1 byte) */
    if (len < 13) {
        LOG(log_warning, logtype_atalkd,
            "aurp_handle_data: packet too short (%d bytes)", len);
        return;
    }

    /* Parse DDP extended header manually.
     * DDP Extended Header wire format (13 bytes) — verified against jrouter captures:
     *   Bytes 0-1: Hop count (4 bits, bits 13-10) + Length (10 bits, bits 9-0)
     *   Bytes 2-3: Checksum (0x0000 = no checksum)
     *   Bytes 4-5: Destination Network (big-endian)
     *   Byte  6:   Destination Node
     *   Byte  7:   Destination Socket
     *   Bytes 8-9: Source Network (big-endian)
     *   Byte  10:  Source Node
     *   Byte  11:  Source Socket
     *   Byte  12:  DDP Type
     */
    unsigned char *p = (unsigned char *)data;
    uint16_t hop_len = (p[0] << 8) | p[1];
    uint16_t checksum = (p[2] << 8) | p[3];
    ddp_len = hop_len & 0x3FF;
    
    dst_net    = (p[4] << 8) | p[5];
    dst_node   = p[6];
    dst_socket = p[7];
    src_net    = (p[8] << 8) | p[9];
    src_node   = p[10];
    /* src_socket = p[11]; */
    if (ddp_len < 13 || ddp_len > len) {
        LOG(log_warning, logtype_atalkd,
            "aurp_handle_data: invalid DDP length %d (packet len %d)",
            ddp_len, len);
        return;
    }

    if (checksum != 0) {
        uint16_t calc = aurp_ddp_checksum(p, ddp_len);
        if (calc != checksum) {
            LOG(log_warning, logtype_atalkd,
                "aurp_handle_data: bad DDP checksum (got 0x%04x expected 0x%04x)",
                checksum, calc);
            return;
        }
    }

    LOG(log_debug, logtype_atalkd,
        "aurp_handle_data: DDP %u.%u.%u -> %u.%u.%u type=0x%02x len=%d",
        src_net, src_node, p[11],
        dst_net, dst_node, dst_socket, (uint8_t)p[12], ddp_len);

    /* Log NBP details at info level for scan tracking */
    if (p[12] == DDPTYPE_NBP) {
        int nbp_len = ddp_len - 13;
        if (nbp_len >= SZ_NBPHDR) {
            struct nbphdr nh;
            struct nbptuple nt;
            unsigned char *nbp = p + 13;
            memcpy(&nh, nbp, SZ_NBPHDR);

            if (nbp_len >= SZ_NBPHDR + SZ_NBPTUPLE) {
                memcpy(&nt, nbp + SZ_NBPHDR, SZ_NBPTUPLE);

                unsigned char *q = nbp + SZ_NBPHDR + SZ_NBPTUPLE;
                unsigned char *nbp_end = nbp + nbp_len;
                if (q < nbp_end) {
                    unsigned char objlen = *q++;
                    unsigned char *obj = q;
                    if (q + objlen <= nbp_end) {
                        q += objlen;
                        if (q < nbp_end) {
                            unsigned char typelen = *q++;
                            unsigned char *typ = q;
                            if (q + typelen <= nbp_end) {
                                q += typelen;
                                if (q < nbp_end) {
                                    unsigned char zonelen = *q++;
                                    unsigned char *zone = q;
                                    if (q + zonelen <= nbp_end) {
                                        LOG(log_info, logtype_atalkd,
                                            "aurp_handle_data: NBP op=%u id=%u '%.*s:%.*s@%.*s' tuple=%u.%u.%u",
                                            nh.nh_op, nh.nh_id,
                                            objlen, (char *)obj,
                                            typelen, (char *)typ,
                                            zonelen, (char *)zone,
                                            ntohs(nt.nt_net), nt.nt_node, nt.nt_port);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /*
     * Find the local interface for this network.
     * If dst_net is 0, it means "this network"; use the first configured
     * non-loopback interface.
     */
    LOG(log_debug, logtype_atalkd,
        "aurp_handle_data: finding interface for dest network %u", dst_net);

    if (dst_net == 0) {
        for (iface = interfaces; iface != NULL; iface = iface->i_next) {
            if ((iface->i_flags & IFACE_CONFIG) == 0) {
                continue;
            }
            if (iface->i_flags & IFACE_LOOPBACK) {
                continue;
            }
            if (iface->i_rt == NULL) {
                continue;
            }
            dest_iface = iface;
            break;
        }
    } else {
        for (iface = interfaces; iface != NULL; iface = iface->i_next) {
            if ((iface->i_flags & IFACE_CONFIG) == 0) {
                if ((iface->i_flags & IFACE_LOOPBACK) != 0) {
                    continue;
                }
                if (iface->i_rt != NULL) {
                    uint16_t firstnet = ntohs(iface->i_rt->rt_firstnet);
                    uint16_t lastnet = ntohs(iface->i_rt->rt_lastnet);
                    if (dst_net >= firstnet && dst_net <= lastnet) {
                        dest_iface = iface;
                        break;
                    }
                }
                continue;
            }
            if (iface->i_flags & IFACE_LOOPBACK) {
                continue;
            }
            if (iface->i_rt == NULL) {
                continue;
            }

            uint16_t firstnet = ntohs(iface->i_rt->rt_firstnet);
            uint16_t lastnet = ntohs(iface->i_rt->rt_lastnet);

            if (dst_net >= firstnet && dst_net <= lastnet) {
                dest_iface = iface;
                break;
            }
        }
    }

    if (dest_iface == NULL) {
        LOG(log_error, logtype_atalkd,
            "aurp_handle_data: no local interface for network %u", dst_net);
        return;
    }

    /*
     * jrouter relies on DDP destination routing for NBP replies.
     * Tuple addresses in replies describe the responder, not the requester.
     * If a peer sends replies to the router anyway, use the request tracker.
     */
    if ((uint8_t)data[12] == DDPTYPE_NBP && ddp_len >= 13 + SZ_NBPHDR) {
        struct nbphdr nh;
        memcpy(&nh, data + 13, SZ_NBPHDR);

        LOG(log_debug, logtype_atalkd,
            "aurp_handle_data: NBP packet op=%u id=%u count=%u",
            nh.nh_op, nh.nh_id, nh.nh_cnt);

        if (nh.nh_op == NBPOP_LKUPREPLY || nh.nh_op == NBPOP_FWDREPLY) {
            struct sockaddr_at reply_dest;
            struct interface *reply_iface = NULL;
            uint16_t reply_net;

            if (aurp_lookup_nbp_request(nh.nh_id, &reply_dest)) {
                reply_net = ntohs(reply_dest.sat_addr.s_net);
                
                LOG(log_info, logtype_atalkd,
                    "aurp_handle_data: NBP reply (op=%u id=%u) → deliver to %u.%u.%u",
                    nh.nh_op, nh.nh_id,
                    reply_net, reply_dest.sat_addr.s_node, reply_dest.sat_port);
                for (iface = interfaces; iface != NULL; iface = iface->i_next) {
                    if ((iface->i_flags & IFACE_CONFIG) == 0 || iface->i_rt == NULL) {
                        continue;
                    }
                    uint16_t firstnet = ntohs(iface->i_rt->rt_firstnet);
                    uint16_t lastnet = ntohs(iface->i_rt->rt_lastnet);
                    if (reply_net >= firstnet && reply_net <= lastnet) {
                        reply_iface = iface;
                        break;
                    }
                }

                if (reply_iface != NULL) {
                    for (ap = reply_iface->i_ports; ap != NULL; ap = ap->ap_next) {
                        if (ap->ap_port == 2) {
                            break;
                        }
                    }
                    if (ap == NULL) {
                        ap = reply_iface->i_ports;
                    }

                    if (ap != NULL) {
                        LOG(log_info, logtype_atalkd,
                            "aurp_handle_data: delivering NBP reply via %s to %u.%u.%u",
                            reply_iface->i_name,
                            reply_net, reply_dest.sat_addr.s_node,
                            reply_dest.sat_port);
                        if (sendto(ap->ap_fd, data + 12, len - 12, 0,
                                   (struct sockaddr *)&reply_dest,
                                   sizeof(reply_dest)) < 0) {
                            LOG(log_warning, logtype_atalkd,
                                "aurp_handle_data: tracked reply sendto(%u.%u.%u) failed: %s",
                                reply_net, reply_dest.sat_addr.s_node,
                                reply_dest.sat_port, strerror(errno));
                        } else {
                            LOG(log_debug, logtype_atalkd,
                                "aurp_handle_data: forwarded tracked NBP reply to %u.%u.%u",
                                reply_net, reply_dest.sat_addr.s_node,
                                reply_dest.sat_port);
                        }
                        return;
                    }
                }
            }
        }
    }

    /*
     * Handle NBP FwdReq addressed to a local router, even if the destination
     * socket is not 2. Some peers target the router node directly with a
     * non-NBP socket; in that case, treat it as a router-directed FwdReq.
     */
    if ((uint8_t)data[12] == DDPTYPE_NBP && ddp_len >= 13 + SZ_NBPHDR) {
        struct nbphdr nh;
        memcpy(&nh, data + 13, SZ_NBPHDR);

        if (nh.nh_op == NBPOP_FWD) {
            LOG(log_debug, logtype_atalkd,
                "aurp_handle_data: treating NBP FwdReq as router-directed (dst %u.%u.%u)",
                dst_net, dst_node, dst_socket);
            /* Convert to LkUp before broadcasting */
            nh.nh_op = NBPOP_LKUP;
            memcpy(data + 13, &nh, SZ_NBPHDR);

            /*
             * Rewrite the tuple reply-to address to our local router so
             * that LkUpReply packets from afpd are deliverable on the local
             * network (the kernel has no route for the remote Mac's network).
             * Track the original requester so we can forward the reply back
             * through AURP when it arrives.
             */
            if (ddp_len >= 13 + SZ_NBPHDR + SZ_NBPTUPLE && dest_iface != NULL) {
                unsigned char *tuple = (unsigned char *)data + 13 + SZ_NBPHDR;
                uint16_t orig_net = (tuple[0] << 8) | tuple[1];
                uint8_t  orig_node = tuple[2];
                uint8_t  orig_socket = tuple[3];

                uint16_t local_net = ntohs(dest_iface->i_addr.sat_addr.s_net);
                uint8_t  local_node = dest_iface->i_addr.sat_addr.s_node;

                aurp_track_inbound_nbp_request(nh.nh_id,
                    orig_net, orig_node, orig_socket);

                tuple[0] = (local_net >> 8) & 0xFF;
                tuple[1] = local_net & 0xFF;
                tuple[2] = local_node;
                tuple[3] = 2;  /* NBP socket */

                LOG(log_info, logtype_atalkd,
                    "aurp_handle_data: rewrote tuple reply-to %u.%u.%u -> %u.%u.2 (id=%u)",
                    orig_net, orig_node, orig_socket,
                    local_net, local_node, nh.nh_id);
            }

            /* Try to resolve the requested zone and ensure multicast is configured */
            if (ddp_len >= 13 + SZ_NBPHDR + SZ_NBPTUPLE + 1) {
                unsigned char *nbp = (unsigned char *)data + 13;
                int nbp_len = ddp_len - 13;
                unsigned char *q = nbp + SZ_NBPHDR + SZ_NBPTUPLE;
                unsigned char *nbp_end = nbp + nbp_len;
                unsigned char *zone_name = NULL;
                unsigned char zone_len = 0;

                if (q < nbp_end) {
                    unsigned char objlen = *q++;
                    if (q + objlen <= nbp_end) {
                        q += objlen;
                        if (q < nbp_end) {
                            unsigned char typelen = *q++;
                            if (q + typelen <= nbp_end) {
                                q += typelen;
                                if (q < nbp_end) {
                                    zone_len = *q++;
                                    if (q + zone_len <= nbp_end) {
                                        zone_name = q;
                                    }
                                }
                            }
                        }
                    }
                }

                if (zone_name != NULL && zone_len > 0) {
                    struct ziptab *zt = NULL;
                    struct list *l;
                    unsigned char *lookup_name = zone_name;
                    unsigned char lookup_len = zone_len;

                    if (lookup_len == 1 && *lookup_name == '*') {
                        if (dest_iface->i_rt != NULL && dest_iface->i_rt->rt_zt != NULL) {
                            zt = (struct ziptab *)dest_iface->i_rt->rt_zt->l_data;
                            lookup_name = (unsigned char *)zt->zt_name;
                            lookup_len = zt->zt_len;
                        }
                    } else if (lookup_len == 0) {
                        if (dest_iface->i_rt != NULL && dest_iface->i_rt->rt_zt != NULL) {
                            zt = (struct ziptab *)dest_iface->i_rt->rt_zt->l_data;
                            lookup_name = (unsigned char *)zt->zt_name;
                            lookup_len = zt->zt_len;
                        }
                    }

                    if (zt == NULL && dest_iface->i_rt != NULL) {
                        for (l = dest_iface->i_rt->rt_zt; l; l = l->l_next) {
                            zt = (struct ziptab *)l->l_data;
                            if (zt->zt_len == lookup_len &&
                                    strndiacasecmp(zt->zt_name, (char *)lookup_name, lookup_len) == 0) {
                                break;
                            }
                        }
                        if (l == NULL) {
                            zt = NULL;
                        }
                    }

                    if (zt != NULL && zt->zt_bcast == NULL) {
                        if (zone_bcast(zt) < 0) {
                            LOG(log_warning, logtype_atalkd,
                                "aurp_handle_data: zone_bcast failed for zone %.*s",
                                lookup_len, (char *)lookup_name);
                        } else if (addmulti(dest_iface->i_name, zt->zt_bcast) < 0) {
                            LOG(log_warning, logtype_atalkd,
                                "aurp_handle_data: addmulti failed for zone %.*s on %s: %s",
                                lookup_len, (char *)lookup_name, dest_iface->i_name,
                                strerror(errno));
                        }
                    }

                    if (zt != NULL && aurp_try_zone_multicast(dest_iface, zt,
                                                             (unsigned char *)data,
                                                             ddp_len, 2)) {
                        LOG(log_debug, logtype_atalkd,
                            "aurp_handle_data: zone-multicast NBP LkUp to %.*s on %s",
                            lookup_len, (char *)lookup_name, dest_iface->i_name);
                        return;
                    }
                }
            }

            /* Broadcast on local network using NBP socket */
            memset(&sat, 0, sizeof(sat));
#ifdef BSD4_4
            sat.sat_len = sizeof(struct sockaddr_at);
#endif
            sat.sat_family = AF_APPLETALK;
            sat.sat_addr.s_net = 0;
            sat.sat_addr.s_node = ATADDR_BCAST;
            sat.sat_port = 2;

            for (ap = dest_iface->i_ports; ap; ap = ap->ap_next) {
                if (ap->ap_port == 2) {
                    break;
                }
            }
            if (ap == NULL) {
                ap = dest_iface->i_ports;
            }

            if (ap != NULL) {
                LOG(log_info, logtype_atalkd,
                    "aurp_handle_data: broadcast FwdReq as LkUp iface=%s port=%u -> %u.%u.%u",
                    dest_iface->i_name, ap->ap_port, 0, ATADDR_BCAST, 2);
                if (sendto(ap->ap_fd, data + 12, len - 12, 0,
                           (struct sockaddr *)&sat, sizeof(sat)) < 0) {
                    LOG(log_warning, logtype_atalkd,
                        "aurp_handle_data: broadcast sendto failed: %s", strerror(errno));
                } else {
                    LOG(log_debug, logtype_atalkd,
                        "aurp_handle_data: broadcasted NBP FwdReq as LkUp to local network %u",
                        dst_net);
                }
            }
            return;
        }
    }

    /*
     * If destination node is 0, the packet is for "any router" on this network.
     * This is typically used for NBP FwdReq - broadcast it on the local network.
     */
    if (dst_node == 0) {
        uint8_t ddp_type;

        ddp_type = (uint8_t)data[12];  /* DDP type follows 12-byte header */

        if (dst_socket == 2 && ddp_type == DDPTYPE_NBP) {
            struct nbphdr nh;

            if (ddp_len >= 13 + SZ_NBPHDR) {
                memcpy(&nh, data + 13, SZ_NBPHDR);
            } else {
                memset(&nh, 0, sizeof(nh));
            }

            /* If this is an NBP FwdReq, convert to LkUp and rewrite tuple */
            if (ddp_len >= 13 + SZ_NBPHDR) {
                if (nh.nh_op == NBPOP_FWD) {
                    nh.nh_op = NBPOP_LKUP;
                    memcpy(data + 13, &nh, SZ_NBPHDR);

                    if (ddp_len >= 13 + SZ_NBPHDR + SZ_NBPTUPLE && dest_iface != NULL) {
                        unsigned char *tuple = (unsigned char *)data + 13 + SZ_NBPHDR;
                        uint16_t orig_net = (tuple[0] << 8) | tuple[1];
                        uint8_t  orig_node = tuple[2];
                        uint8_t  orig_socket = tuple[3];

                        uint16_t local_net = ntohs(dest_iface->i_addr.sat_addr.s_net);
                        uint8_t  local_node = dest_iface->i_addr.sat_addr.s_node;

                        aurp_track_inbound_nbp_request(nh.nh_id,
                            orig_net, orig_node, orig_socket);

                        tuple[0] = (local_net >> 8) & 0xFF;
                        tuple[1] = local_net & 0xFF;
                        tuple[2] = local_node;
                        tuple[3] = 2;

                        LOG(log_info, logtype_atalkd,
                            "aurp_handle_data: rewrote tuple reply-to %u.%u.%u -> %u.%u.2 (id=%u)",
                            orig_net, orig_node, orig_socket,
                            local_net, local_node, nh.nh_id);
                    }
                }
            }

            /* Try to resolve the requested zone and ensure multicast is configured */
            if (ddp_len >= 13 + SZ_NBPHDR + SZ_NBPTUPLE + 1 && dest_iface != NULL) {
                unsigned char *nbp = (unsigned char *)data + 13;
                int nbp_len = ddp_len - 13;
                unsigned char *q = nbp + SZ_NBPHDR + SZ_NBPTUPLE;
                unsigned char *nbp_end = nbp + nbp_len;
                unsigned char *zone_name = NULL;
                unsigned char zone_len = 0;

                if (q < nbp_end) {
                    unsigned char objlen = *q++;
                    if (q + objlen <= nbp_end) {
                        q += objlen;
                        if (q < nbp_end) {
                            unsigned char typelen = *q++;
                            if (q + typelen <= nbp_end) {
                                q += typelen;
                                if (q < nbp_end) {
                                    zone_len = *q++;
                                    if (q + zone_len <= nbp_end) {
                                        zone_name = q;
                                    }
                                }
                            }
                        }
                    }
                }

                if (zone_name != NULL && zone_len > 0) {
                    struct ziptab *zt = NULL;
                    struct list *l;
                    unsigned char *lookup_name = zone_name;
                    unsigned char lookup_len = zone_len;

                    if (lookup_len == 1 && *lookup_name == '*') {
                        if (dest_iface->i_rt != NULL && dest_iface->i_rt->rt_zt != NULL) {
                            zt = (struct ziptab *)dest_iface->i_rt->rt_zt->l_data;
                            lookup_name = (unsigned char *)zt->zt_name;
                            lookup_len = zt->zt_len;
                        }
                    }

                    if (zt == NULL && dest_iface->i_rt != NULL) {
                        for (l = dest_iface->i_rt->rt_zt; l; l = l->l_next) {
                            zt = (struct ziptab *)l->l_data;
                            if (zt->zt_len == lookup_len &&
                                    strndiacasecmp(zt->zt_name, (char *)lookup_name, lookup_len) == 0) {
                                break;
                            }
                        }
                        if (l == NULL) {
                            zt = NULL;
                        }
                    }

                    if (zt != NULL) {
                        if (zt->zt_bcast == NULL) {
                            if (zone_bcast(zt) < 0) {
                                LOG(log_warning, logtype_atalkd,
                                    "aurp_handle_data: zone_bcast failed for zone %.*s",
                                    lookup_len, (char *)lookup_name);
                            } else if (addmulti(dest_iface->i_name, zt->zt_bcast) < 0) {
                                LOG(log_warning, logtype_atalkd,
                                    "aurp_handle_data: addmulti failed for zone %.*s on %s: %s",
                                    lookup_len, (char *)lookup_name, dest_iface->i_name,
                                    strerror(errno));
                            }
                        }

                        if (aurp_try_zone_multicast(dest_iface, zt,
                                                    (unsigned char *)data,
                                                    ddp_len, dst_socket)) {
                            LOG(log_debug, logtype_atalkd,
                                "aurp_handle_data: zone-multicast NBP LkUp to %.*s on %s",
                                lookup_len, (char *)lookup_name, dest_iface->i_name);
                            return;
                        }
                    }
                }
            }

            /* NBP packet to router - broadcast it on local network */
            LOG(log_debug, logtype_atalkd,
                "aurp_handle_data: broadcasting NBP packet from %u.%u to network %u",
                src_net, src_node, dst_net);
            
            /* Change destination to broadcast
             * Per Inside AppleTalk SE pp 8-20:
             * "If the destination network is extended, however, the router must also
             * change the destination network number to $0000, so that the packet is
             * received by all nodes on the network (within the correct zone multicast address)."
             */
            sat.sat_family = AF_APPLETALK;
            sat.sat_addr.s_net = 0;  /* Network 0 = "this network" for extended networks */
            sat.sat_addr.s_node = ATADDR_BCAST;  /* 255 = broadcast */
            sat.sat_port = dst_socket;
            
            /* Find an atport on this interface */
            for (ap = dest_iface->i_ports; ap; ap = ap->ap_next) {
                if (ap->ap_port == dst_socket) {
                    break;
                }
            }
            if (ap == NULL) {
                LOG(log_error, logtype_atalkd,
                    "aurp_handle_data: broadcast any-router NBP iface=%s port=%u -> %u.%u.%u",
                    dest_iface->i_name, ap->ap_port, 0, ATADDR_BCAST, 2);
                ap = dest_iface->i_ports;  /* Use first available port */
            }
            
            if (ap != NULL) {
                /* Send as broadcast (skip DDP header, send from type byte onwards) */
                if (sendto(ap->ap_fd, data + 12, len - 12, 0,
                           (struct sockaddr *)&sat, sizeof(sat)) < 0) {
                    LOG(log_warning, logtype_atalkd,
                        "aurp_handle_data: broadcast sendto failed: %s", strerror(errno));
                } else {
                    LOG(log_debug, logtype_atalkd,
                        "aurp_handle_data: broadcasted NBP packet to network %u", dst_net);
                }
            }
        }
        return;
    }

    /*
     * Forward the DDP packet to the destination on the local network
     * We use the interface's socket bound to the appropriate DDP socket
     */
    memset(&sat, 0, sizeof(sat));
#ifdef BSD4_4
    sat.sat_len = sizeof(struct sockaddr_at);
#endif
    sat.sat_family = AF_APPLETALK;
    sat.sat_addr.s_net = htons(dst_net);
    sat.sat_addr.s_node = dst_node;
    sat.sat_port = dst_socket;

    /* Find the appropriate port to send from.
     * For NBP packets, always send from socket 2 (NBP), regardless of the
     * destination socket (which may be the requester's socket).
     * For other packets, use a matching port or RTMP port. */
    if ((uint8_t)data[12] == DDPTYPE_NBP) {
        for (ap = dest_iface->i_ports; ap != NULL; ap = ap->ap_next) {
            if (ap->ap_port == 2) {  /* NBP port */
                break;
            }
        }
        if (ap == NULL) {
            ap = dest_iface->i_ports;
        }
    } else {
        for (ap = dest_iface->i_ports; ap != NULL; ap = ap->ap_next) {
            if (ap->ap_port == dst_socket) {
                break;
            }
        }

        /* Fallback to RTMP port if no exact match */
        if (ap == NULL) {
            for (ap = dest_iface->i_ports; ap != NULL; ap = ap->ap_next) {
                if (ap->ap_port == 1) {  /* RTMP port */
                    break;
                }
            }
        }
    }

    if (ap == NULL) {
        LOG(log_warning, logtype_atalkd,
            "aurp_handle_data: no port available on interface %s",
            dest_iface->i_name);
        return;
    }

    /* Send the packet (skip DDP header, send from type byte onwards)
     * This forwards the packet directly to the destination node on the local network
     * Per jrouter: "Output the packet!" - just forward it, don't process it */
#ifdef __linux__
    /* On Linux, use raw sockets to preserve the original source address.
     * AF_APPLETALK sockets overwrite the source with the router's address,
     * which breaks protocols like ATP that expect consistent addressing. */
    {
        struct sockaddr_at src_sat;
        unsigned char dest_hw[6] = {0x09, 0x00, 0x07, 0xFF, 0xFF, 0xFF}; /* AppleTalk broadcast MAC */
        
        /* Extract source address from DDP header */
        memset(&src_sat, 0, sizeof(src_sat));
#ifdef BSD4_4
        src_sat.sat_len = sizeof(struct sockaddr_at);
#endif
        src_sat.sat_family = AF_APPLETALK;
        src_sat.sat_addr.s_net = htons((data[6] << 8) | data[7]);
        src_sat.sat_addr.s_node = data[9];
        src_sat.sat_port = data[11];
        
        if (sendto_iface_raw(dest_iface, data + 12, len - 12,
                            &src_sat, &sat, dest_hw) < 0) {
            LOG(log_warning, logtype_atalkd,
                "aurp_handle_data: sendto_iface_raw(%u.%u.%u) failed: %s",
                dst_net, dst_node, dst_socket, strerror(errno));
        } else {
            LOG(log_debug, logtype_atalkd,
                "*** aurp_handle_data: RAW forwarded %u.%u.%u -> %u.%u.%u ***",
                ntohs(src_sat.sat_addr.s_net), src_sat.sat_addr.s_node, src_sat.sat_port,
                dst_net, dst_node, dst_socket);
        }
    }
#else
    if (sendto(ap->ap_fd, data + 12, len - 12, 0,
               (struct sockaddr *)&sat, sizeof(sat)) < 0) {
        LOG(log_warning, logtype_atalkd,
            "aurp_handle_data: sendto(%u.%u.%u) failed: %s",
            dst_net, dst_node, dst_socket, strerror(errno));
    } else {
        LOG(log_debug, logtype_atalkd,
            "aurp_handle_data: forwarded to %u.%u.%u via %s",
            dst_net, dst_node, dst_socket, dest_iface->i_name);
    }
#endif
}

/*
 * Send a DDP packet via AURP to the appropriate peer
 * The data should be a raw DDP packet including the extended header
 */
int aurp_send_data(uint16_t dst_net, char *ddp_data, int ddp_len)
{
    char buf[AURP_MAX_PKT_SIZE];
    struct aurp_peer *peer;
    int len = 0;
    int n;

    /* Find the peer that serves this network */
    peer = aurp_find_peer_for_net(dst_net);
    if (peer == NULL) {
        LOG(log_warning, logtype_atalkd,
            "aurp_send_data: no AURP peer for network %u (check peer route lists)", dst_net);
        return -1;
    }

    /* Only send if peer's send channel is connected */
    if (peer->ap_send_state != AURP_SEND_CONNECTED) {
        LOG(log_warning, logtype_atalkd,
            "aurp_send_data: peer %s (net %u) send channel not connected (send_state=%d)",
            inet_ntoa(peer->ap_addr), dst_net, peer->ap_send_state);
        return -1;
    }

    /* Check packet size */
    if (ddp_len > AURP_MAX_PKT_SIZE - 50) {  /* Leave room for headers */
        LOG(log_warning, logtype_atalkd,
            "aurp_send_data: packet too large (%d bytes)", ddp_len);
        return -1;
    }

    /* Build domain header for AppleTalk data packet */
    n = aurp_build_domain_header(buf + len, sizeof(buf) - len, peer, AURP_PKT_APPLETALK);
    if (n < 0) return -1;
    len += n;

    /* Copy DDP packet data */
    memcpy(buf + len, ddp_data, ddp_len);
    len += ddp_len;

    /* Log key DDP extended header fields for AURP data sends.
     * DDP extended: [0-1] hop+len, [2-3] cksum, [4-5] dst_net,
     * [6-7] src_net, [8] dst_node, [9] src_node, [10] dst_sock, [11] src_sock, [12] type */
    if (ddp_len >= 13) {
        unsigned char *p = (unsigned char *)ddp_data;
        uint16_t ddp_dst_net = (p[4] << 8) | p[5];
        uint16_t ddp_src_net = (p[6] << 8) | p[7];
        uint8_t ddp_dst_node = p[8];
        uint8_t ddp_src_node = p[9];
        uint8_t ddp_dst_sock = p[10];
        uint8_t ddp_src_sock = p[11];
        uint8_t ddp_type = p[12];

        LOG(log_info, logtype_atalkd,
            "aurp_send_data: peer %s DDP %u.%u.%u -> %u.%u.%u type=0x%02x",
            inet_ntoa(peer->ap_addr),
            ddp_src_net, ddp_src_node, ddp_src_sock,
            ddp_dst_net, ddp_dst_node, ddp_dst_sock,
            ddp_type);
    }

    /* DEBUG: Log packet hex for analysis */
    {
        char hex_buf[256];
        int hex_len = (len < 80) ? len : 80;
        char *hex_ptr = hex_buf;
        for (int i = 0; i < hex_len && (hex_ptr - hex_buf) < 240; i++) {
            hex_ptr += snprintf(hex_ptr, 4, "%02x ", (unsigned char)buf[i]);
        }
        LOG(log_debug, logtype_atalkd, "aurp_send_data: HEX (first %d of %d): %s", hex_len, len, hex_buf);
    }

    /* Send to peer */
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr = peer->ap_addr;
    sin.sin_port = htons(aurp_config.ac_port);

    if (sendto(aurp_fd, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        LOG(log_warning, logtype_atalkd,
            "aurp_send_data: sendto(%s) failed: %s",
            inet_ntoa(peer->ap_addr), strerror(errno));
        return -1;
    }

    LOG(log_debug, logtype_atalkd,
        "aurp_send_data: sent %d byte packet to %s for network %u",
        len, inet_ntoa(peer->ap_addr), dst_net);

    return 0;
}

/* Send a DDP packet via AURP directly to a specific peer */
int aurp_send_data_to_peer(struct aurp_peer *peer, char *ddp_data, int ddp_len)
{
    char buf[AURP_MAX_PKT_SIZE];
    int len = 0;
    int n;

    if (peer == NULL) {
        return -1;
    }

    /* Only send if peer is connected */
    if (peer->ap_recv_state != AURP_RECV_CONNECTED) {
        LOG(log_warning, logtype_atalkd,
            "aurp_send_data_to_peer: peer %s not connected (state=%d)",
            inet_ntoa(peer->ap_addr), peer->ap_recv_state);
        return -1;
    }

    /* Check packet size */
    if (ddp_len > AURP_MAX_PKT_SIZE - 50) {
        LOG(log_warning, logtype_atalkd,
            "aurp_send_data_to_peer: packet too large (%d bytes)", ddp_len);
        return -1;
    }

    /* Build domain header for AppleTalk data packet */
    n = aurp_build_domain_header(buf + len, sizeof(buf) - len, peer, AURP_PKT_APPLETALK);
    if (n < 0) return -1;
    len += n;

    /* Copy DDP packet data */
    memcpy(buf + len, ddp_data, ddp_len);
    len += ddp_len;

    /* Send to peer */
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr = peer->ap_addr;
    sin.sin_port = htons(aurp_config.ac_port);

    if (sendto(aurp_fd, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        LOG(log_warning, logtype_atalkd,
            "aurp_send_data_to_peer: sendto(%s) failed: %s",
            inet_ntoa(peer->ap_addr), strerror(errno));
        return -1;
    }

    peer->ap_last_send = time(NULL);

    LOG(log_error, logtype_atalkd,
        "aurp_send_data_to_peer: sent %d byte packet to %s",
        len, inet_ntoa(peer->ap_addr));
    return 0;
}

/*
 * Shutdown
 */

/* Clean up AURP resources */
void aurp_shutdown(void)
{
    struct aurp_peer *peer, *next;

    if (aurp_fd >= 0) {
        close(aurp_fd);
        aurp_fd = -1;
    }

    /* Disconnect and free all peers */
    for (peer = aurp_config.ac_peers; peer != NULL; peer = next) {
        next = peer->ap_next;
        aurp_peer_disconnect(peer);
        aurp_peer_free(peer);
    }
    aurp_config.ac_peers = NULL;

    LOG(log_info, logtype_atalkd, "AURP shutdown complete");
}
