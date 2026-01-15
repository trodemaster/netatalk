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
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <atalk/logger.h>
#include <atalk/ddp.h>
#include <netatalk/at.h>
#include <netatalk/ddp.h>

#include "aurp.h"
#include "rtmp.h"
#include "interface.h"
#include "atserv.h"
#include "zip.h"
#include "list.h"

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

/*
 * Debug helper: hex dump for packet debugging
 */
static void aurp_hexdump(const char *prefix, const char *data, int len)
{
    char line[80];
    int i, j, offset;

    for (i = 0; i < len; i += 16) {
        offset = snprintf(line, sizeof(line), "%s %04x: ", prefix, i);
        for (j = 0; j < 16 && (i + j) < len; j++) {
            offset += snprintf(line + offset, sizeof(line) - offset,
                              "%02x ", (unsigned char)data[i + j]);
        }
        /* Pad if less than 16 bytes */
        for (; j < 16; j++) {
            offset += snprintf(line + offset, sizeof(line) - offset, "   ");
        }
        offset += snprintf(line + offset, sizeof(line) - offset, " |");
        for (j = 0; j < 16 && (i + j) < len; j++) {
            char c = data[i + j];
            offset += snprintf(line + offset, sizeof(line) - offset, "%c",
                              (c >= 32 && c < 127) ? c : '.');
        }
        snprintf(line + offset, sizeof(line) - offset, "|");
        LOG(log_debug9, logtype_atalkd, "%s", line);
    }
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

    /* Destination domain identifier (peer's DI) */
    n = aurp_build_domain_id(buf + len, buflen - len, &peer->ap_remote_di);
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

    if (!cfg || !cfg->ac_enabled) {
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
    if (cfg->ac_peers == NULL) {
        LOG(log_info, logtype_atalkd,
            "AURP disabled: no peers configured");
        close(sock);
        aurp_fd = -1;
        return -1;
    }

    /* Initiate connections to configured peers */
    struct aurp_peer *peer;
    for (peer = cfg->ac_peers; peer != NULL; peer = peer->ap_next) {
        aurp_peer_connect(peer);
    }

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
        "aurp_input: received %zd bytes from %s:%d",
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
            "aurp_input: AppleTalk data packet from %s len=%d",
            inet_ntoa(peer_addr), remaining);
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

    LOG(log_info, logtype_atalkd,
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
    n = aurp_build_routing_header(buf, sizeof(buf), peer, peer->ap_local_conn_id,
                                   0, AURP_CMD_RI_REQ, AURP_FLAG_SUI_ALL);
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
    for (iface = interfaces; iface != NULL; iface = iface->i_next) {
        uint16_t firstnet, lastnet;
        uint8_t dist;

        /* Skip unconfigured interfaces */
        if ((iface->i_flags & IFACE_CONFIG) == 0) {
            continue;
        }

        /* Skip loopback */
        if (iface->i_flags & IFACE_LOOPBACK) {
            continue;
        }

        firstnet = ntohs(iface->i_rt->rt_firstnet);
        lastnet = ntohs(iface->i_rt->rt_lastnet);
        dist = 0;  /* Distance 0 for directly connected networks */

        /* Check buffer space */
        if (len + 6 > sizeof(buf)) {
            LOG(log_warning, logtype_atalkd,
                "aurp_send_ri_rsp: packet full, need multiple packets");
            break;
        }

        if (firstnet == lastnet) {
            /* Non-extended tuple (3 bytes) */
            tmp = htons(firstnet);
            memcpy(buf + len, &tmp, 2);
            len += 2;
            buf[len++] = dist;
        } else {
            /* Extended tuple (6 bytes) */
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
            "aurp_send_ri_rsp: adding network %u-%u dist %u",
            firstnet, lastnet, dist);
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
 * Data Forwarding Functions
 */

/*
 * Find the AURP peer that provides a route to the given network
 * Returns NULL if no AURP peer serves that network
 */
struct aurp_peer *aurp_find_peer_for_net(uint16_t net)
{
    struct aurp_peer *peer;
    struct rtmptab *rt;

    for (peer = aurp_config.ac_peers; peer != NULL; peer = peer->ap_next) {
        /* Only consider connected peers */
        if (peer->ap_recv_state != AURP_RECV_CONNECTED) {
            continue;
        }

        /* Search through routes learned from this peer */
        for (rt = peer->ap_routes; rt != NULL; rt = rt->rt_next) {
            uint16_t firstnet = ntohs(rt->rt_firstnet);
            uint16_t lastnet = ntohs(rt->rt_lastnet);

            if (net >= firstnet && net <= lastnet) {
                return peer;
            }
        }
    }

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

    /* Need at least the DDP header (12 bytes) + type (1 byte) */
    if (len < 13) {
        LOG(log_warning, logtype_atalkd,
            "aurp_handle_data: packet too short (%d bytes)", len);
        return;
    }

    /* Parse DDP extended header */
    ddp = (struct ddpehdr *)data;
    dst_net = ntohs(ddp->deh_dnet);
    src_net = ntohs(ddp->deh_snet);
    dst_node = ddp->deh_dnode;
    src_node = ddp->deh_snode;
    dst_socket = ddp->deh_dport;

    /* Extract length from header (10 bits) */
    ddp_len = ntohs(ddp->deh_bytes) & 0x3FF;
    if (ddp_len < 13 || ddp_len > len) {
        LOG(log_warning, logtype_atalkd,
            "aurp_handle_data: invalid DDP length %d (packet len %d)",
            ddp_len, len);
        return;
    }

    LOG(log_debug, logtype_atalkd,
        "aurp_handle_data: DDP %u.%u.%u -> %u.%u.%u len=%d",
        src_net, src_node, ddp->deh_sport,
        dst_net, dst_node, dst_socket, ddp_len);

    /*
     * Find the local interface for this network
     * Node 0 means "any router for this network" - that's us
     */
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

        uint16_t firstnet = ntohs(iface->i_rt->rt_firstnet);
        uint16_t lastnet = ntohs(iface->i_rt->rt_lastnet);

        if (dst_net >= firstnet && dst_net <= lastnet) {
            dest_iface = iface;
            break;
        }
    }

    if (dest_iface == NULL) {
        LOG(log_debug, logtype_atalkd,
            "aurp_handle_data: no local interface for network %u", dst_net);
        return;
    }

    /*
     * If destination node is 0, the packet is for "any router" on this network.
     * This is typically used for NBP FwdReq. Check if it's NBP (socket 2).
     */
    if (dst_node == 0) {
        uint8_t ddp_type;

        ddp_type = (uint8_t)data[12];  /* DDP type follows 12-byte header */

        if (dst_socket == 2 && ddp_type == DDPTYPE_NBP) {
            /* NBP packet to router - could be FwdReq for name lookup */
            LOG(log_debug, logtype_atalkd,
                "aurp_handle_data: NBP packet to router on network %u", dst_net);
            /* TODO: Handle NBP FwdReq - convert to BrRq and send on local network */
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

    /* Find the appropriate port to send from */
    for (ap = dest_iface->i_ports; ap != NULL; ap = ap->ap_next) {
        /* Use the RTMP port (socket 1) for general forwarding */
        if (ap->ap_port == 1) {
            break;
        }
    }

    if (ap == NULL) {
        LOG(log_warning, logtype_atalkd,
            "aurp_handle_data: no port available on interface %s",
            dest_iface->i_name);
        return;
    }

    /* Send the packet (skip DDP header, send from type byte onwards) */
    if (sendto(ap->ap_fd, data + 12, len - 12, 0,
               (struct sockaddr *)&sat, sizeof(sat)) < 0) {
        LOG(log_warning, logtype_atalkd,
            "aurp_handle_data: sendto(%u.%u) failed: %s",
            dst_net, dst_node, strerror(errno));
    } else {
        LOG(log_debug, logtype_atalkd,
            "aurp_handle_data: forwarded packet to %u.%u.%u",
            dst_net, dst_node, dst_socket);
    }
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
        LOG(log_debug, logtype_atalkd,
            "aurp_send_data: no AURP peer for network %u", dst_net);
        return -1;
    }

    /* Only send if peer is connected */
    if (peer->ap_recv_state != AURP_RECV_CONNECTED) {
        LOG(log_debug, logtype_atalkd,
            "aurp_send_data: peer %s not connected", inet_ntoa(peer->ap_addr));
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
