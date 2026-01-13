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
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <atalk/logger.h>

#include "aurp.h"
#include "rtmp.h"

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

/* Build domain identifier into buffer */
int aurp_build_domain_id(char *buf, int buflen, struct in_addr *addr)
{
    if (buflen < 3) {
        return -1;
    }

    if (addr->s_addr == INADDR_ANY) {
        /* NULL domain identifier */
        buf[0] = 0;  /* Length 0 */
        buf[1] = AURP_DI_NULL;
        return 2;
    } else {
        /* IP domain identifier (4 bytes) */
        if (buflen < 6) {
            return -1;
        }
        buf[0] = 4;  /* Length 4 */
        buf[1] = AURP_DI_IP;
        memcpy(buf + 2, &addr->s_addr, 4);
        return 6;
    }
}

/* Parse domain identifier from buffer */
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
        if (di_len != 4 || len < 6) {
            return -1;
        }
        memcpy(&addr->s_addr, buf + 2, 4);
        return 6;
    } else {
        /* Unknown domain identifier type */
        return -1;
    }
}

/*
 * AURP Header building
 */

/* Build AURP header (connection ID + sequence + command code + flags) */
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
        LOG(log_error, logtype_default, "aurp_init: socket() failed: %s",
            strerror(errno));
        return -1;
    }

    /* Set socket options */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        LOG(log_error, logtype_default, "aurp_init: setsockopt(SO_REUSEADDR) failed: %s",
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
        LOG(log_error, logtype_default, "aurp_init: bind(%s:%d) failed: %s",
            inet_ntoa(cfg->ac_listen_addr), cfg->ac_port, strerror(errno));
        close(sock);
        return -1;
    }

    aurp_fd = sock;

    LOG(log_info, logtype_default, "AURP initialized on %s:%d",
        inet_ntoa(cfg->ac_listen_addr), cfg->ac_port);

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

/* Receive and process AURP packets */
void aurp_input(int fd)
{
    char buf[AURP_MAX_PKT_SIZE];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t len;
    struct aurp_peer *peer;
    struct in_addr peer_addr;
    uint16_t conn_id, seq, cmd, flags;
    char *data;
    int datalen;

    /* Receive UDP packet */
    len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    if (len < 0) {
        LOG(log_error, logtype_default, "aurp_input: recvfrom() failed: %s",
            strerror(errno));
        return;
    }

    if (len < 8) {
        LOG(log_debug, logtype_default, "aurp_input: packet too short (%zd bytes)", len);
        return;
    }

    peer_addr = from.sin_addr;

    /* Parse AURP header */
    memcpy(&conn_id, buf, 2);
    conn_id = ntohs(conn_id);
    memcpy(&seq, buf + 2, 2);
    seq = ntohs(seq);
    memcpy(&cmd, buf + 4, 2);
    cmd = ntohs(cmd);
    memcpy(&flags, buf + 6, 2);
    flags = ntohs(flags);

    data = buf + 8;
    datalen = len - 8;

    LOG(log_debug, logtype_default,
        "aurp_input: from %s conn_id=%u seq=%u cmd=0x%04x flags=0x%04x len=%d",
        inet_ntoa(peer_addr), conn_id, seq, cmd, flags, datalen);

    /* Find or create peer */
    peer = aurp_peer_find(peer_addr);
    if (peer == NULL) {
        if (!aurp_config.ac_open_peering) {
            LOG(log_info, logtype_default,
                "aurp_input: ignoring packet from unknown peer %s (open peering disabled)",
                inet_ntoa(peer_addr));
            return;
        }
        peer = aurp_peer_find_or_create(peer_addr);
        if (peer == NULL) {
            LOG(log_error, logtype_default,
                "aurp_input: failed to create peer for %s", inet_ntoa(peer_addr));
            return;
        }
    }

    /* Update last heard time */
    peer->ap_last_heard = time(NULL);

    /* Update remote connection ID and sequence if appropriate */
    if (cmd == AURP_CMD_OPEN_REQ || cmd == AURP_CMD_OPEN_RSP) {
        peer->ap_remote_conn_id = conn_id;
    }
    peer->ap_remote_seq = seq;

    /* Dispatch to appropriate handler */
    switch (cmd) {
        case AURP_CMD_OPEN_REQ:
            aurp_handle_open_req(peer, data, datalen);
            break;
        case AURP_CMD_OPEN_RSP:
            aurp_handle_open_rsp(peer, data, datalen);
            break;
        case AURP_CMD_RI_REQ:
            aurp_handle_ri_req(peer, data, datalen);
            break;
        case AURP_CMD_RI_RSP:
            aurp_handle_ri_rsp(peer, data, datalen);
            break;
        case AURP_CMD_RI_ACK:
            aurp_handle_ri_ack(peer, data, datalen);
            break;
        case AURP_CMD_RI_UPD:
            aurp_handle_ri_upd(peer, data, datalen);
            break;
        case AURP_CMD_RD:
            aurp_handle_rd(peer, data, datalen);
            break;
        case AURP_CMD_ZI_REQ:
            aurp_handle_zi_req(peer, data, datalen);
            break;
        case AURP_CMD_ZI_RSP:
            aurp_handle_zi_rsp(peer, data, datalen);
            break;
        case AURP_CMD_TICKLE:
            aurp_handle_tickle(peer);
            break;
        case AURP_CMD_TICKLE_ACK:
            aurp_handle_tickle_ack(peer);
            break;
        default:
            LOG(log_info, logtype_default,
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

    sent = sendto(aurp_fd, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin));
    if (sent < 0) {
        LOG(log_error, logtype_default, "aurp_send_packet: sendto(%s) failed: %s",
            inet_ntoa(peer->ap_addr), strerror(errno));
        return -1;
    }

    if (sent != len) {
        LOG(log_warning, logtype_default,
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
    uint16_t option_count = 0;

    /* Build header */
    n = aurp_build_header(buf, sizeof(buf), peer->ap_local_conn_id,
                          peer->ap_local_seq, AURP_CMD_OPEN_REQ, 0);
    if (n < 0) return -1;
    len += n;

    /* Build sender's domain identifier */
    n = aurp_build_domain_id(buf + len, sizeof(buf) - len, &peer->ap_local_di);
    if (n < 0) return -1;
    len += n;

    /* AURP version (2 bytes) */
    version = htons(AURP_VERSION);
    memcpy(buf + len, &version, 2);
    len += 2;

    /* Option count (2 bytes) - currently 0 */
    memcpy(buf + len, &option_count, 2);
    len += 2;

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

    LOG(log_info, logtype_default, "aurp_send_open_req: sent to %s",
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
    uint16_t option_count = 0;

    /* Build header */
    n = aurp_build_header(buf, sizeof(buf), peer->ap_local_conn_id,
                          peer->ap_local_seq, AURP_CMD_OPEN_RSP, 0);
    if (n < 0) return -1;
    len += n;

    /* Build sender's domain identifier */
    n = aurp_build_domain_id(buf + len, sizeof(buf) - len, &peer->ap_local_di);
    if (n < 0) return -1;
    len += n;

    /* Error code (2 bytes, signed, big-endian) */
    error_code = htons((uint16_t)result);
    memcpy(buf + len, &error_code, 2);
    len += 2;

    /* Option count (2 bytes) - currently 0 */
    memcpy(buf + len, &option_count, 2);
    len += 2;

    /* Send packet */
    if (aurp_send_packet(peer, buf, len) < 0) {
        return -1;
    }

    peer->ap_local_seq = aurp_next_seq(peer->ap_local_seq);

    LOG(log_info, logtype_default, "aurp_send_open_rsp: sent to %s result=%d",
        inet_ntoa(peer->ap_addr), result);

    return 0;
}

/* Send RI-Req */
int aurp_send_ri_req(struct aurp_peer *peer)
{
    char buf[256];
    int len = 0;
    int n;

    /* Build header */
    n = aurp_build_header(buf, sizeof(buf), peer->ap_local_conn_id,
                          peer->ap_local_seq, AURP_CMD_RI_REQ, 0);
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

    peer->ap_local_seq = aurp_next_seq(peer->ap_local_seq);

    LOG(log_info, logtype_default, "aurp_send_ri_req: sent to %s",
        inet_ntoa(peer->ap_addr));

    return 0;
}

/* Send Tickle */
int aurp_send_tickle(struct aurp_peer *peer)
{
    char buf[256];
    int len = 0;
    int n;

    /* Build header */
    n = aurp_build_header(buf, sizeof(buf), peer->ap_local_conn_id,
                          peer->ap_local_seq, AURP_CMD_TICKLE, 0);
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

    peer->ap_local_seq = aurp_next_seq(peer->ap_local_seq);

    LOG(log_debug, logtype_default, "aurp_send_tickle: sent to %s",
        inet_ntoa(peer->ap_addr));

    return 0;
}

/* Send Tickle-Ack */
int aurp_send_tickle_ack(struct aurp_peer *peer)
{
    char buf[256];
    int len = 0;
    int n;

    /* Build header */
    n = aurp_build_header(buf, sizeof(buf), peer->ap_local_conn_id,
                          peer->ap_local_seq, AURP_CMD_TICKLE_ACK, 0);
    if (n < 0) return -1;
    len += n;

    /* Send packet */
    if (aurp_send_packet(peer, buf, len) < 0) {
        return -1;
    }

    peer->ap_local_seq = aurp_next_seq(peer->ap_local_seq);

    LOG(log_debug, logtype_default, "aurp_send_tickle_ack: sent to %s",
        inet_ntoa(peer->ap_addr));

    return 0;
}

/* Placeholder stubs for other send functions - will be implemented in aurp_peer.c */
int aurp_send_ri_rsp(struct aurp_peer *peer, int last)
{
    /* TODO: Implement in Phase 4 */
    LOG(log_debug, logtype_default, "aurp_send_ri_rsp: stub called");
    return 0;
}

int aurp_send_ri_ack(struct aurp_peer *peer, uint16_t flags)
{
    /* TODO: Implement in Phase 4 */
    LOG(log_debug, logtype_default, "aurp_send_ri_ack: stub called");
    return 0;
}

int aurp_send_ri_upd(struct aurp_peer *peer)
{
    /* TODO: Implement in Phase 4 */
    LOG(log_debug, logtype_default, "aurp_send_ri_upd: stub called");
    return 0;
}

int aurp_send_rd(struct aurp_peer *peer, int16_t error)
{
    /* TODO: Implement in Phase 4 */
    LOG(log_debug, logtype_default, "aurp_send_rd: stub called");
    return 0;
}

int aurp_send_zi_req(struct aurp_peer *peer, uint16_t *nets, int count)
{
    /* TODO: Implement in Phase 5 */
    LOG(log_debug, logtype_default, "aurp_send_zi_req: stub called");
    return 0;
}

int aurp_send_zi_rsp(struct aurp_peer *peer, int last)
{
    /* TODO: Implement in Phase 5 */
    LOG(log_debug, logtype_default, "aurp_send_zi_rsp: stub called");
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

    LOG(log_info, logtype_default, "AURP shutdown complete");
}
