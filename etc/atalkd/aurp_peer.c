/*
 * Copyright (c) 2026, AURP Implementation Project
 * All rights reserved.
 *
 * AURP (AppleTalk Update-Based Routing Protocol) - RFC 1504
 * Peer connection state machine and route management
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <netatalk/at.h>
#include <atalk/logger.h>

#include "aurp.h"
#include "rtmp.h"
#include "zip.h"
#include "list.h"
#include "interface.h"

/* Generate random connection ID */
static uint16_t aurp_generate_conn_id(void)
{
    uint16_t id;
    do {
        id = (uint16_t)(rand() & 0xFFFF);
    } while (id == 0);  /* Connection ID must not be 0 */
    return id;
}

/*
 * Peer lifecycle management
 */

/* Create new peer */
struct aurp_peer *aurp_peer_new(struct in_addr addr, const char *hostname)
{
    struct aurp_peer *peer;

    peer = calloc(1, sizeof(struct aurp_peer));
    if (peer == NULL) {
        LOG(log_error, logtype_atalkd, "aurp_peer_new: calloc failed");
        return NULL;
    }

    peer->ap_addr = addr;
    if (hostname != NULL) {
        peer->ap_hostname = strdup(hostname);
    }

    /* Initialize connection state */
    peer->ap_recv_state = AURP_RECV_UNCONNECTED;
    peer->ap_send_state = AURP_SEND_UNCONNECTED;

    /* Generate local connection ID and initialize sequence */
    peer->ap_local_conn_id = aurp_generate_conn_id();
    peer->ap_local_seq = 1;  /* Start at 1, never use 0 */
    peer->ap_remote_conn_id = 0;
    peer->ap_remote_seq = 0;

    /* Initialize timers */
    peer->ap_last_heard = 0;
    peer->ap_last_send = 0;
    peer->ap_last_reconnect = 0;
    peer->ap_send_retries = 0;
    peer->ap_tickle_retries = 0;

    /* Initialize event queue */
    peer->ap_pending = NULL;
    peer->ap_pending_count = 0;
    peer->ap_pending_alloc = 0;

    /* Initialize route list */
    peer->ap_routes = NULL;

    /* Initialize zone request queue */
    peer->ap_zi_pending = NULL;
    peer->ap_zi_pending_count = 0;
    peer->ap_zi_pending_alloc = 0;

    /* Initialize packet buffer */
    peer->ap_last_pkt = NULL;
    peer->ap_last_pkt_len = 0;

    /* Set local domain identifier */
    peer->ap_local_di = aurp_config.ac_local_ip;

    peer->ap_flags = 0;

    LOG(log_info, logtype_atalkd, "aurp_peer_new: created peer %s conn_id=%u",
        inet_ntoa(peer->ap_addr), peer->ap_local_conn_id);

    return peer;
}

/* Free peer */
void aurp_peer_free(struct aurp_peer *peer)
{
    if (peer == NULL) {
        return;
    }

    if (peer->ap_hostname) {
        free(peer->ap_hostname);
    }

    if (peer->ap_pending) {
        free(peer->ap_pending);
    }

    if (peer->ap_zi_pending) {
        free(peer->ap_zi_pending);
    }

    if (peer->ap_last_pkt) {
        free(peer->ap_last_pkt);
    }

    /* Note: Routes should be cleaned up before calling this */

    free(peer);
}

/* Find peer by IP address */
struct aurp_peer *aurp_peer_find(struct in_addr addr)
{
    struct aurp_peer *peer;

    for (peer = aurp_config.ac_peers; peer != NULL; peer = peer->ap_next) {
        if (peer->ap_addr.s_addr == addr.s_addr) {
            return peer;
        }
    }

    return NULL;
}

/* Find or create peer */
struct aurp_peer *aurp_peer_find_or_create(struct in_addr addr)
{
    struct aurp_peer *peer;

    peer = aurp_peer_find(addr);
    if (peer != NULL) {
        return peer;
    }

    peer = aurp_peer_new(addr, NULL);
    if (peer == NULL) {
        return NULL;
    }

    /* Add to peer list */
    peer->ap_next = aurp_config.ac_peers;
    if (aurp_config.ac_peers != NULL) {
        aurp_config.ac_peers->ap_prev = peer;
    }
    aurp_config.ac_peers = peer;

    return peer;
}

/*
 * Peer list fetching from URL
 */

/* Parse peer list data (one IP/hostname per line) */
int aurp_parse_peerlist(const char *data, size_t len)
{
    const char *line_start, *line_end;
    char line[256];
    int line_num = 0;
    int peers_added = 0;
    struct hostent *he;
    struct in_addr addr;
    struct aurp_peer *peer;

    if (data == NULL || len == 0) {
        return 0;
    }

    line_start = data;
    while (line_start < data + len) {
        line_num++;

        /* Find end of line */
        line_end = line_start;
        while (line_end < data + len && *line_end != '\n' && *line_end != '\r') {
            line_end++;
        }

        /* Extract line */
        size_t line_len = line_end - line_start;
        if (line_len >= sizeof(line)) {
            LOG(log_warning, logtype_atalkd,
                "aurp_parse_peerlist: line %d too long, skipping", line_num);
            goto next_line;
        }

        memcpy(line, line_start, line_len);
        line[line_len] = '\0';

        /* Trim leading whitespace */
        char *p = line;
        while (*p && isspace(*p)) {
            p++;
        }

        /* Skip empty lines and comments */
        if (*p == '\0' || *p == '#') {
            goto next_line;
        }

        /* Trim trailing whitespace */
        char *end = p + strlen(p) - 1;
        while (end > p && isspace(*end)) {
            *end = '\0';
            end--;
        }

        /* Try parsing as IP address first */
        if (inet_aton(p, &addr) == 0) {
            /* Try hostname resolution */
            he = gethostbyname(p);
            if (he == NULL) {
                LOG(log_warning, logtype_atalkd,
                    "aurp_parse_peerlist: line %d: cannot resolve '%s'", line_num, p);
                goto next_line;
            }
            memcpy(&addr, he->h_addr, sizeof(addr));
        }

        /* Check if peer already exists */
        if (aurp_peer_find(addr) != NULL) {
            LOG(log_debug, logtype_atalkd,
                "aurp_parse_peerlist: peer %s already configured, skipping", p);
            goto next_line;
        }

        /* Create peer */
        peer = aurp_peer_new(addr, p);
        if (peer == NULL) {
            LOG(log_error, logtype_atalkd,
                "aurp_parse_peerlist: failed to create peer for '%s'", p);
            goto next_line;
        }

        peer->ap_flags |= AURP_PEER_CONFIGURED;

        /* Add to peer list */
        peer->ap_next = aurp_config.ac_peers;
        if (aurp_config.ac_peers != NULL) {
            aurp_config.ac_peers->ap_prev = peer;
        }
        aurp_config.ac_peers = peer;

        LOG(log_info, logtype_atalkd,
            "aurp_parse_peerlist: added peer %s (%s)", p, inet_ntoa(addr));

        peers_added++;

next_line:
        /* Skip to next line */
        line_start = line_end;
        while (line_start < data + len &&
               (*line_start == '\n' || *line_start == '\r')) {
            line_start++;
        }
    }

    LOG(log_info, logtype_atalkd,
        "aurp_parse_peerlist: added %d peers from list (%d lines processed)",
        peers_added, line_num);

    return peers_added;
}

/* Load peer list from file */
int aurp_load_peerlist(const char *filepath)
{
    FILE *fp;
    char *data = NULL;
    size_t size = 0;
    size_t capacity = 4096;
    size_t nread;
    int peers_added = 0;

    if (filepath == NULL) {
        return -1;
    }

    LOG(log_info, logtype_atalkd, "aurp_load_peerlist: loading from %s", filepath);

    fp = fopen(filepath, "r");
    if (fp == NULL) {
        LOG(log_error, logtype_atalkd,
            "aurp_load_peerlist: failed to open %s: %s", filepath, strerror(errno));
        return -1;
    }

    /* Read entire file into memory */
    data = malloc(capacity);
    if (data == NULL) {
        LOG(log_error, logtype_atalkd, "aurp_load_peerlist: out of memory");
        fclose(fp);
        return -1;
    }

    while ((nread = fread(data + size, 1, capacity - size, fp)) > 0) {
        size += nread;
        if (size == capacity) {
            capacity *= 2;
            char *new_data = realloc(data, capacity);
            if (new_data == NULL) {
                LOG(log_error, logtype_atalkd, "aurp_load_peerlist: out of memory");
                free(data);
                fclose(fp);
                return -1;
            }
            data = new_data;
        }
    }

    fclose(fp);

    /* Parse the file contents */
    if (size > 0) {
        peers_added = aurp_parse_peerlist(data, size);
    }

    free(data);

    if (peers_added > 0) {
        LOG(log_info, logtype_atalkd,
            "aurp_load_peerlist: successfully loaded %d peers from %s",
            peers_added, filepath);
    } else {
        LOG(log_warning, logtype_atalkd,
            "aurp_load_peerlist: no valid peers found in %s", filepath);
    }

    return peers_added;
}

/*
 * Connection management
 */

/* Initiate connection to peer */
void aurp_peer_connect(struct aurp_peer *peer)
{
    if (peer == NULL) {
        return;
    }

    LOG(log_info, logtype_atalkd, "aurp_peer_connect: connecting to %s",
        inet_ntoa(peer->ap_addr));

    /* Set state */
    peer->ap_recv_state = AURP_RECV_WAIT_OPEN_RSP;
    peer->ap_send_state = AURP_SEND_UNCONNECTED;

    /* Reset retries */
    peer->ap_send_retries = 0;
    peer->ap_tickle_retries = 0;

    int result = aurp_send_open_req(peer);
    if (result < 0) {
        LOG(log_warning, logtype_atalkd, "aurp_peer_connect: open_req to %s failed",
            inet_ntoa(peer->ap_addr));
    }
}

/* Disconnect from peer */
void aurp_peer_disconnect(struct aurp_peer *peer)
{
    if (peer == NULL) {
        return;
    }

    LOG(log_info, logtype_atalkd, "aurp_peer_disconnect: disconnecting from %s",
        inet_ntoa(peer->ap_addr));

    /* Send Router Down if connected */
    if (peer->ap_flags & AURP_PEER_CONNECTED) {
        aurp_send_rd(peer, AURP_ERR_NORMAL_CLOSE);
    }

    /* Clear connection state */
    peer->ap_recv_state = AURP_RECV_UNCONNECTED;
    peer->ap_send_state = AURP_SEND_UNCONNECTED;
    peer->ap_flags &= ~AURP_PEER_CONNECTED;

    /* Delete routes learned from this peer */
    aurp_rtmp_delete_routes(peer);

    /* Clear event queue */
    aurp_flush_events(peer);
}

/*
 * Timer processing
 */

/* Called periodically (from main timer) */
void aurp_timer(void)
{
    struct aurp_peer *peer;
    time_t now = time(NULL);
    static time_t last_status_log = 0;

    /* Log status summary every 10 minutes */
    if (now - last_status_log >= 600) {
        aurp_log_status();
        last_status_log = now;
    }

    for (peer = aurp_config.ac_peers; peer != NULL; peer = peer->ap_next) {
        /* Check for connection timeout */
        if (peer->ap_recv_state != AURP_RECV_UNCONNECTED &&
            peer->ap_recv_state != AURP_RECV_CONNECTED) {
            if (peer->ap_last_heard > 0 &&
                (now - peer->ap_last_heard) > AURP_LAST_HEARD_TIMER) {
                LOG(log_warning, logtype_atalkd,
                    "aurp_timer: peer %s timed out waiting for response",
                    inet_ntoa(peer->ap_addr));
                aurp_peer_disconnect(peer);
                peer->ap_last_reconnect = now;
                continue;
            }

            /* Retry sending last packet */
            if ((now - peer->ap_last_send) >= AURP_SEND_RETRY_TIMER) {
                if (peer->ap_send_retries >= AURP_SEND_RETRY_LIMIT) {
                    LOG(log_error, logtype_atalkd,
                        "aurp_timer: peer %s exceeded retry limit",
                        inet_ntoa(peer->ap_addr));
                    aurp_peer_disconnect(peer);
                    peer->ap_last_reconnect = now;
                    continue;
                }

                if (peer->ap_last_pkt != NULL && peer->ap_last_pkt_len > 0) {
                    LOG(log_debug, logtype_atalkd,
                        "aurp_timer: retransmitting to %s (attempt %d)",
                        inet_ntoa(peer->ap_addr), peer->ap_send_retries + 1);
                    /* Retransmit last packet */
                    struct sockaddr_in sin;
                    memset(&sin, 0, sizeof(sin));
                    sin.sin_family = AF_INET;
                    sin.sin_addr = peer->ap_addr;
                    sin.sin_port = htons(aurp_config.ac_port);
                    sendto(aurp_fd, peer->ap_last_pkt, peer->ap_last_pkt_len, 0,
                           (struct sockaddr *)&sin, sizeof(sin));
                    peer->ap_last_send = now;
                    peer->ap_send_retries++;
                }
            }
        }

        /* Connected state - send tickles and check for timeout */
        if (peer->ap_recv_state == AURP_RECV_CONNECTED) {
            /* Check if peer is alive */
            if (peer->ap_last_heard > 0 &&
                (now - peer->ap_last_heard) > AURP_LAST_HEARD_TIMER) {
                LOG(log_warning, logtype_atalkd,
                    "aurp_timer: peer %s not responding to tickles",
                    inet_ntoa(peer->ap_addr));
                aurp_peer_disconnect(peer);
                peer->ap_last_reconnect = now;
                continue;
            }

            /* Send periodic tickle */
            if ((now - peer->ap_last_send) >= AURP_UPDATE_TIMER) {
                aurp_send_tickle(peer);
                peer->ap_recv_state = AURP_RECV_WAIT_TICKLE_ACK;
                peer->ap_tickle_retries = 0;
            }
        }

        /* Tickle-Ack timeout */
        if (peer->ap_recv_state == AURP_RECV_WAIT_TICKLE_ACK) {
            if ((now - peer->ap_last_send) >= AURP_SEND_RETRY_TIMER) {
                if (peer->ap_tickle_retries >= AURP_TICKLE_RETRY_LIMIT) {
                    LOG(log_error, logtype_atalkd,
                        "aurp_timer: peer %s tickle timeout",
                        inet_ntoa(peer->ap_addr));
                    aurp_peer_disconnect(peer);
                    peer->ap_last_reconnect = now;
                    continue;
                }
                aurp_send_tickle(peer);
                peer->ap_tickle_retries++;
            }
        }

        /* Reconnection attempts */
        if (peer->ap_recv_state == AURP_RECV_UNCONNECTED &&
            (peer->ap_flags & AURP_PEER_CONFIGURED)) {
            if (peer->ap_last_reconnect > 0 &&
                (now - peer->ap_last_reconnect) >= AURP_RECONNECT_TIMER) {
                LOG(log_info, logtype_atalkd,
                    "aurp_timer: attempting to reconnect to %s",
                    inet_ntoa(peer->ap_addr));
                aurp_peer_connect(peer);
            }
        }

        /* Send pending route updates */
        if (peer->ap_send_state == AURP_SEND_CONNECTED &&
            peer->ap_pending_count > 0) {
            aurp_send_ri_upd(peer);
        }
    }
}

/*
 * Debug status logging
 */

/* Get recv state name for logging */
static const char *get_recv_state_name(int state)
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

/* Get send state name for logging */
static const char *get_send_state_name(int state)
{
    switch (state) {
        case AURP_SEND_UNCONNECTED:      return "UNCONNECTED";
        case AURP_SEND_CONNECTED:        return "CONNECTED";
        case AURP_SEND_WAIT_RI_RSP_ACK:  return "WAIT_RI_RSP_ACK";
        case AURP_SEND_WAIT_RI_UPD_ACK:  return "WAIT_RI_UPD_ACK";
        default:                         return "UNKNOWN";
    }
}

/* Log detailed peer and zone status for debugging */
void aurp_log_status(void)
{
    struct aurp_peer *peer;
    struct rtmptab *rt;
    struct list *l;
    struct ziptab *zt;
    int peer_count = 0, connected_count = 0;
    int total_routes = 0, total_zones = 0;

    for (peer = aurp_config.ac_peers; peer != NULL; peer = peer->ap_next) {
        int route_count = 0, zone_count = 0;
        peer_count++;

        for (rt = peer->ap_routes; rt != NULL; rt = rt->rt_next) {
            route_count++;
            for (l = rt->rt_zt; l != NULL; l = l->l_next) {
                zone_count++;
            }
        }
        total_routes += route_count;
        total_zones += zone_count;

        if (peer->ap_recv_state == AURP_RECV_CONNECTED ||
            peer->ap_recv_state == AURP_RECV_WAIT_TICKLE_ACK) {
            connected_count++;
        }
    }

    /* Log summary only - per-peer detail at debug level */
    LOG(log_info, logtype_atalkd,
        "AURP: %d peers (%d connected), %d routes, %d zones",
        peer_count, connected_count, total_routes, total_zones);
}

/*
 * Packet handlers
 */

/* Handle Open-Req */
void aurp_handle_open_req(struct aurp_peer *peer, char *data, int len)
{
    uint16_t version;

    LOG(log_info, logtype_atalkd, "aurp_handle_open_req: from %s",
        inet_ntoa(peer->ap_addr));

    /*
     * Note: Domain identifiers are already parsed in aurp_input() and
     * stored in peer->ap_remote_di. The data pointer here points to
     * the Open-Req specific payload (version + option count).
     */

    /* Parse version (2 bytes) */
    if (len < 2) {
        LOG(log_error, logtype_atalkd,
            "aurp_handle_open_req: packet too short for version");
        return;
    }
    memcpy(&version, data, 2);
    version = ntohs(version);
    data += 2;
    len -= 2;

    if (version != AURP_VERSION) {
        LOG(log_warning, logtype_atalkd,
            "aurp_handle_open_req: unsupported version %u", version);
        aurp_send_open_rsp(peer, AURP_ERR_INVALID_VERSION);
        return;
    }

    /* Option count is 1 byte, followed by option tuples if count > 0 */
    /* For now, we ignore options */

    /* Accept connection - set our sender state to connected */
    peer->ap_send_state = AURP_SEND_CONNECTED;
    aurp_send_open_rsp(peer, 0);  /* 0 = success */

    LOG(log_info, logtype_atalkd,
        "aurp_handle_open_req: accepted connection from %s (send_state=CONNECTED)",
        inet_ntoa(peer->ap_addr));

    /*
     * IMPORTANT: AURP connections are unidirectional. The peer's Open-Req
     * establishes THEIR ability to send data TO us. We also need to establish
     * OUR ability to receive data FROM them by sending our own Open-Req.
     * This creates a bidirectional data path.
     *
     * RACE CONDITION FIX: If we're already in WAIT_OPEN_RSP state, it means
     * we already sent them an Open-Req and are waiting for their Open-Rsp.
     * In this case, do NOT send another Open-Req (which would create an
     * infinite loop). Instead, just wait for their Open-Rsp to our original
     * Open-Req. Both sides will establish their connections simultaneously.
     */
    if (peer->ap_recv_state == AURP_RECV_UNCONNECTED) {
        LOG(log_info, logtype_atalkd,
            "aurp_handle_open_req: initiating reverse connection to %s",
            inet_ntoa(peer->ap_addr));
        peer->ap_recv_state = AURP_RECV_WAIT_OPEN_RSP;
        peer->ap_send_retries = 0;
        aurp_send_open_req(peer);
    } else if (peer->ap_recv_state == AURP_RECV_WAIT_OPEN_RSP) {
        LOG(log_info, logtype_atalkd,
            "aurp_handle_open_req: already waiting for Open-Rsp from %s, not sending duplicate Open-Req",
            inet_ntoa(peer->ap_addr));
    }
}

/* Handle Open-Rsp */
void aurp_handle_open_rsp(struct aurp_peer *peer, char *data, int len)
{
    int16_t error_code;
    uint16_t error_code_net;

    LOG(log_info, logtype_atalkd, "aurp_handle_open_rsp: from %s",
        inet_ntoa(peer->ap_addr));

    if (peer->ap_recv_state != AURP_RECV_WAIT_OPEN_RSP) {
        LOG(log_warning, logtype_atalkd,
            "aurp_handle_open_rsp: unexpected Open-Rsp in state %d",
            peer->ap_recv_state);
        return;
    }

    /*
     * Note: Domain identifiers are already parsed in aurp_input() and
     * stored in peer->ap_remote_di. The data pointer here points to
     * the Open-Rsp specific payload (error code/rate + option count).
     */

    /* Parse error code / rate (2 bytes, signed) */
    if (len < 2) {
        LOG(log_error, logtype_atalkd,
            "aurp_handle_open_rsp: packet too short for error code");
        return;
    }
    memcpy(&error_code_net, data, 2);
    error_code = (int16_t)ntohs(error_code_net);
    data += 2;
    len -= 2;

    if (error_code < 0) {
        LOG(log_error, logtype_atalkd,
            "aurp_handle_open_rsp: peer %s rejected connection (error %d)",
            inet_ntoa(peer->ap_addr), error_code);
        aurp_peer_disconnect(peer);
        return;
    }

    /* Option count is 1 byte, followed by option tuples if count > 0 */
    /* For now, we ignore options */

    /* Connection accepted - request routing information */
    peer->ap_recv_state = AURP_RECV_WAIT_RI_RSP;
    peer->ap_send_state = AURP_SEND_CONNECTED;  /* Mark send channel as connected */
    peer->ap_send_retries = 0;
    peer->ap_flags |= AURP_PEER_CONNECTED;

    aurp_send_ri_req(peer);

    LOG(log_info, logtype_atalkd,
        "aurp_handle_open_rsp: connection accepted by %s (rate=%d, send_state=CONNECTED)",
        inet_ntoa(peer->ap_addr), error_code);
}

/* Handle RI-Req */
void aurp_handle_ri_req(struct aurp_peer *peer, char *data, int len)
{
    LOG(log_info, logtype_atalkd, "aurp_handle_ri_req: from %s",
        inet_ntoa(peer->ap_addr));

    /*
     * Reset local sequence number to 1 for the new sender connection.
     * The peer (as receiver) expects sequence numbers starting from 1.
     * This is called on each RI-Req because the peer may have restarted
     * their receiver state machine.
     */
    LOG(log_error, logtype_atalkd,
        "aurp_handle_ri_req: RESETTING local_seq from %u to 1",
        peer->ap_local_seq);
    peer->ap_local_seq = 1;

    /* Send routing information response */
    aurp_send_ri_rsp(peer, 1);  /* 1 = last packet */

    /* Move to waiting for RI-Ack state */
    peer->ap_send_state = AURP_SEND_WAIT_RI_RSP_ACK;
}

/* Handle RI-Rsp - parse network tuples and store routes */
void aurp_handle_ri_rsp(struct aurp_peer *peer, char *data, int len)
{
    int count = 0;
    uint16_t firstnet, lastnet;
    uint8_t dist;

    LOG(log_info, logtype_atalkd, "aurp_handle_ri_rsp: from %s len=%d",
        inet_ntoa(peer->ap_addr), len);

    /* Parse network tuples */
    while (len >= 3) {
        /* Read first network number (2 bytes big-endian) */
        memcpy(&firstnet, data, 2);
        firstnet = ntohs(firstnet);
        data += 2;
        len -= 2;

        /* Read distance byte */
        dist = (uint8_t)*data++;
        len--;

        if (dist & 0x80) {
            /* Extended tuple - has range end and reserved byte */
            if (len < 3) {
                LOG(log_warning, logtype_atalkd,
                    "aurp_handle_ri_rsp: truncated extended tuple");
                break;
            }
            dist &= 0x7f;  /* Clear extended flag */
            memcpy(&lastnet, data, 2);
            lastnet = ntohs(lastnet);
            data += 2;
            len -= 2;
            data++;  /* Skip reserved byte */
            len--;
        } else {
            /* Non-extended tuple - single network */
            lastnet = firstnet;
        }

        LOG(log_info, logtype_atalkd,
            "aurp_handle_ri_rsp: learned route %u-%u dist %u from %s",
            firstnet, lastnet, dist, inet_ntoa(peer->ap_addr));

        /* Add route to peer's route list */
        aurp_rtmp_add_route(peer, firstnet, lastnet, dist);
        count++;
    }

    LOG(log_info, logtype_atalkd,
        "aurp_handle_ri_rsp: learned %d routes from %s",
        count, inet_ntoa(peer->ap_addr));

    /* Send acknowledgement with SZI flag to request zone information */
    if (peer->ap_recv_state == AURP_RECV_WAIT_RI_RSP) {
        /* Send RI-Ack with SZI flag to request zone info */
        aurp_send_ri_ack(peer, AURP_FLAG_SZI);

        /* Collect networks that need zones */
        if (count > 0) {
            struct rtmptab *rt;
            uint16_t *nets;
            int net_count = 0;

            /* Allocate array for networks */
            nets = malloc(count * sizeof(uint16_t));
            if (nets != NULL) {
                for (rt = peer->ap_routes; rt != NULL; rt = rt->rt_next) {
                    if ((rt->rt_flags & RTMPTAB_HASZONES) == 0) {
                        nets[net_count++] = ntohs(rt->rt_firstnet);
                    }
                }

                if (net_count > 0) {
                    /* Save pending zone requests */
                    peer->ap_zi_pending = nets;
                    peer->ap_zi_pending_count = net_count;
                    peer->ap_zi_pending_alloc = count;

                    /* Request zone information */
                    aurp_send_zi_req(peer, nets, net_count);
                    peer->ap_recv_state = AURP_RECV_WAIT_ZI_RSP;
                    LOG(log_info, logtype_atalkd,
                        "aurp_handle_ri_rsp: requesting zones for %d networks from %s",
                        net_count, inet_ntoa(peer->ap_addr));
                } else {
                    free(nets);
                    peer->ap_recv_state = AURP_RECV_CONNECTED;
                    LOG(log_error, logtype_atalkd,
                        "*** RECV_CONNECTED: bidirectional connection with %s fully established (no zones needed) ***",
                        inet_ntoa(peer->ap_addr));
                }
            } else {
                /* Malloc failed, just connect without zones */
                peer->ap_recv_state = AURP_RECV_CONNECTED;
                LOG(log_error, logtype_atalkd,
                    "*** RECV_CONNECTED: bidirectional connection with %s established (malloc failed, no zones) ***",
                    inet_ntoa(peer->ap_addr));
            }
        } else {
            peer->ap_recv_state = AURP_RECV_CONNECTED;
            LOG(log_error, logtype_atalkd,
                "*** RECV_CONNECTED: bidirectional connection with %s fully established (no routes) ***",
                inet_ntoa(peer->ap_addr));
        }
    }
}

/* Handle RI-Ack */
void aurp_handle_ri_ack(struct aurp_peer *peer, char *data, int len)
{
    LOG(log_info, logtype_atalkd, "aurp_handle_ri_ack: from %s SZI=%d",
        inet_ntoa(peer->ap_addr),
        !!(peer->ap_last_recv_flags & AURP_FLAG_SZI));

    /* Clear pending retransmission */
    if (peer->ap_last_pkt) {
        free(peer->ap_last_pkt);
        peer->ap_last_pkt = NULL;
        peer->ap_last_pkt_len = 0;
    }
    peer->ap_send_retries = 0;

    /* If we're in SEND state waiting for RI-Rsp Ack, transition to connected */
    if (peer->ap_send_state == AURP_SEND_WAIT_RI_RSP_ACK) {
        peer->ap_send_state = AURP_SEND_CONNECTED;
        LOG(log_debug, logtype_atalkd,
            "aurp_handle_ri_ack: sender now connected to %s",
            inet_ntoa(peer->ap_addr));

        /* If SZI flag is set, peer wants zone information */
        if (peer->ap_last_recv_flags & AURP_FLAG_SZI) {
            LOG(log_info, logtype_atalkd,
                "aurp_handle_ri_ack: peer %s requested zone info (SZI flag)",
                inet_ntoa(peer->ap_addr));
            aurp_send_zi_rsp(peer, 1);  /* Send all our zones */
        }
    }

    /* If we're waiting for RI-Upd Ack, transition back to connected */
    if (peer->ap_send_state == AURP_SEND_WAIT_RI_UPD_ACK) {
        peer->ap_send_state = AURP_SEND_CONNECTED;
        aurp_flush_events(peer);  /* Clear processed events */
    }
}

/* Handle RI-Upd - parse event tuples and update routes */
void aurp_handle_ri_upd(struct aurp_peer *peer, char *data, int len)
{
    int count = 0;
    uint8_t event_code;
    uint16_t firstnet, lastnet;
    uint8_t dist;

    LOG(log_info, logtype_atalkd, "aurp_handle_ri_upd: from %s len=%d",
        inet_ntoa(peer->ap_addr), len);

    /* Parse event tuples */
    while (len >= 1) {
        event_code = (uint8_t)*data++;
        len--;

        if (event_code == AURP_EVT_NULL) {
            /* Null event - just the code, no data */
            LOG(log_debug, logtype_atalkd, "aurp_handle_ri_upd: null event");
            continue;
        }

        /* All other events have network tuple data */
        if (len < 3) {
            LOG(log_warning, logtype_atalkd,
                "aurp_handle_ri_upd: truncated event tuple");
            break;
        }

        memcpy(&firstnet, data, 2);
        firstnet = ntohs(firstnet);
        data += 2;
        len -= 2;

        dist = (uint8_t)*data++;
        len--;

        if (dist & 0x80) {
            /* Extended tuple */
            if (len < 2) {
                LOG(log_warning, logtype_atalkd,
                    "aurp_handle_ri_upd: truncated extended event");
                break;
            }
            dist &= 0x7f;
            memcpy(&lastnet, data, 2);
            lastnet = ntohs(lastnet);
            data += 2;
            len -= 2;
        } else {
            lastnet = firstnet;
        }

        LOG(log_info, logtype_atalkd,
            "aurp_handle_ri_upd: event %u net %u-%u dist %u from %s",
            event_code, firstnet, lastnet, dist, inet_ntoa(peer->ap_addr));

        /* Process event */
        switch (event_code) {
        case AURP_EVT_NA:  /* Network Added */
            aurp_rtmp_add_route(peer, firstnet, lastnet, dist);
            break;

        case AURP_EVT_ND:  /* Network Deleted */
            aurp_rtmp_remove_route(peer, firstnet, lastnet);
            break;

        case AURP_EVT_NRC:  /* Network Route Change */
        case AURP_EVT_NDC:  /* Network Distance Change */
            /* Update route with new distance */
            aurp_rtmp_update_route(peer, firstnet, lastnet, dist);
            break;

        case AURP_EVT_ZC:  /* Zone Change */
            {
                struct rtmptab *rt;
                int net_count = 0;
                uint16_t *nets;

                /* Count affected routes */
                for (rt = peer->ap_routes; rt != NULL; rt = rt->rt_next) {
                    uint16_t rt_firstnet = ntohs(rt->rt_firstnet);
                    uint16_t rt_lastnet = ntohs(rt->rt_lastnet);

                    if (rt_lastnet < firstnet || rt_firstnet > lastnet) {
                        continue;
                    }
                    net_count++;
                }

                if (net_count == 0) {
                    LOG(log_debug, logtype_atalkd,
                        "aurp_handle_ri_upd: zone change for %u-%u (no matching routes)",
                        firstnet, lastnet);
                    break;
                }

                nets = calloc(net_count, sizeof(uint16_t));
                if (nets == NULL) {
                    LOG(log_error, logtype_atalkd,
                        "aurp_handle_ri_upd: zone change alloc failed for %d nets",
                        net_count);
                    break;
                }

                net_count = 0;
                for (rt = peer->ap_routes; rt != NULL; rt = rt->rt_next) {
                    uint16_t rt_firstnet = ntohs(rt->rt_firstnet);
                    uint16_t rt_lastnet = ntohs(rt->rt_lastnet);

                    if (rt_lastnet < firstnet || rt_firstnet > lastnet) {
                        continue;
                    }

                    /* Clear existing zone map so it can be refreshed */
                    if (rt->rt_zt != NULL) {
                        rtmp_delzonemap(rt);
                    }
                    rt->rt_flags &= ~RTMPTAB_HASZONES;

                    nets[net_count++] = rt_firstnet;
                }

                if (net_count > 0) {
                    aurp_send_zi_req(peer, nets, net_count);
                    LOG(log_info, logtype_atalkd,
                        "aurp_handle_ri_upd: requested zone refresh for %d nets from %s",
                        net_count, inet_ntoa(peer->ap_addr));
                }

                free(nets);
            }
            break;

        default:
            LOG(log_warning, logtype_atalkd,
                "aurp_handle_ri_upd: unknown event code %u", event_code);
            break;
        }

        count++;
    }

    LOG(log_info, logtype_atalkd,
        "aurp_handle_ri_upd: processed %d events from %s",
        count, inet_ntoa(peer->ap_addr));

    /* Acknowledge update */
    aurp_send_ri_ack(peer, 0);
}

/* Handle Router Down */
void aurp_handle_rd(struct aurp_peer *peer, char *data, int len)
{
    int16_t error_code = 0;

    if (len >= 2) {
        uint16_t error_code_net;
        memcpy(&error_code_net, data, 2);
        error_code = (int16_t)ntohs(error_code_net);
    }

    LOG(log_info, logtype_atalkd, "aurp_handle_rd: from %s error=%d",
        inet_ntoa(peer->ap_addr), error_code);

    aurp_peer_disconnect(peer);
}

/* Handle Tickle */
void aurp_handle_tickle(struct aurp_peer *peer)
{
    LOG(log_debug, logtype_atalkd, "aurp_handle_tickle: from %s",
        inet_ntoa(peer->ap_addr));

    /* Send Tickle-Ack */
    aurp_send_tickle_ack(peer);
}

/* Handle Tickle-Ack */
void aurp_handle_tickle_ack(struct aurp_peer *peer)
{
    LOG(log_debug, logtype_atalkd, "aurp_handle_tickle_ack: from %s",
        inet_ntoa(peer->ap_addr));

    /* Return to connected state */
    if (peer->ap_recv_state == AURP_RECV_WAIT_TICKLE_ACK) {
        peer->ap_recv_state = AURP_RECV_CONNECTED;
        peer->ap_tickle_retries = 0;
    }
}

/* Handle ZI-Req - respond with zone information for requested networks */
void aurp_handle_zi_req(struct aurp_peer *peer, char *data, int len)
{
    uint16_t subcode;
    int count;

    LOG(log_info, logtype_atalkd, "aurp_handle_zi_req: from %s len=%d",
        inet_ntoa(peer->ap_addr), len);

    /* Parse subcode (2 bytes) */
    if (len < 2) {
        LOG(log_warning, logtype_atalkd,
            "aurp_handle_zi_req: packet too short for subcode");
        return;
    }
    memcpy(&subcode, data, 2);
    subcode = ntohs(subcode);
    data += 2;
    len -= 2;

    if (subcode != AURP_SUBCODE_ZI_REQ) {
        LOG(log_warning, logtype_atalkd,
            "aurp_handle_zi_req: unsupported subcode 0x%04x", subcode);
        return;
    }

    /* Count requested networks */
    count = len / 2;
    LOG(log_debug, logtype_atalkd,
        "aurp_handle_zi_req: peer requesting zones for %d networks", count);

    if (count > 0) {
        uint16_t *nets = calloc((size_t)count, sizeof(uint16_t));
        int i;

        if (nets == NULL) {
            aurp_send_zi_rsp(peer, 1);
            return;
        }

        for (i = 0; i < count; i++) {
            uint16_t net;
            memcpy(&net, data + (i * 2), 2);
            nets[i] = ntohs(net);
        }

        aurp_send_zi_rsp_for_nets(peer, nets, count);
        free(nets);
        return;
    }

    /* Fallback: send all zones */
    aurp_send_zi_rsp(peer, 1);
}

/* Handle ZI-Rsp - parse zone tuples and add zones to routes */
void aurp_handle_zi_rsp(struct aurp_peer *peer, char *data, int len)
{
    uint16_t subcode, zone_count, network;
    int i, zone_len;
    char zone_name[33];
    struct rtmptab *rt;
    int zones_added = 0;
    unsigned char *p;
    int remaining;
    const unsigned char *first_zone = NULL;
    const unsigned char *packet_end;

    LOG(log_info, logtype_atalkd, "aurp_handle_zi_rsp: from %s len=%d",
        inet_ntoa(peer->ap_addr), len);

    /* Parse subcode (2 bytes) */
    if (len < 4) {
        LOG(log_warning, logtype_atalkd,
            "aurp_handle_zi_rsp: packet too short");
        return;
    }
    memcpy(&subcode, data, 2);
    subcode = ntohs(subcode);
    data += 2;
    len -= 2;

    /* Parse zone count (2 bytes) */
    memcpy(&zone_count, data, 2);
    zone_count = ntohs(zone_count);
    data += 2;
    len -= 2;

    LOG(log_debug, logtype_atalkd,
        "aurp_handle_zi_rsp: subcode=0x%04x zone_count=%u",
        subcode, zone_count);

    p = (unsigned char *)data;
    remaining = len;
    packet_end = p + remaining;

    /* Parse zone tuples */
    for (i = 0; i < zone_count && remaining >= 3; i++) {
        /* Network number (2 bytes) */
        memcpy(&network, p, 2);
        network = ntohs(network);
        p += 2;
        remaining -= 2;

        /* Check for optimized tuple (high bit set in first byte) */
        if ((uint8_t)p[0] & 0x80) {
            uint16_t offset;
            const unsigned char *name_ptr;

            if (remaining < 2) {
                LOG(log_warning, logtype_atalkd,
                    "aurp_handle_zi_rsp: truncated optimized tuple for net %u",
                    network);
                break;
            }

            offset = (uint16_t)((p[0] << 8) | p[1]);
            offset &= 0x7fff;
            p += 2;
            remaining -= 2;

            if (first_zone == NULL) {
                LOG(log_warning, logtype_atalkd,
                    "aurp_handle_zi_rsp: optimized tuple before first zone name (net %u)",
                    network);
                continue;
            }

            name_ptr = first_zone + offset;
            if (name_ptr >= packet_end) {
                LOG(log_warning, logtype_atalkd,
                    "aurp_handle_zi_rsp: optimized tuple offset %u out of range", offset);
                continue;
            }

            zone_len = (uint8_t)name_ptr[0];
            name_ptr++;

            if (zone_len > 32 || name_ptr + zone_len > packet_end) {
                LOG(log_warning, logtype_atalkd,
                    "aurp_handle_zi_rsp: invalid optimized zone length %d", zone_len);
                continue;
            }

            memcpy(zone_name, name_ptr, zone_len);
            zone_name[zone_len] = '\0';
        } else {
            /* Long tuple - zone name length (1 byte) + name */
            zone_len = (uint8_t)*p++;
            remaining--;

            if (first_zone == NULL) {
                first_zone = p - 1;
            }

            if (zone_len > 32 || zone_len > remaining) {
                LOG(log_warning, logtype_atalkd,
                    "aurp_handle_zi_rsp: invalid zone length %d", zone_len);
                break;
            }

            memcpy(zone_name, p, zone_len);
            zone_name[zone_len] = '\0';
            p += zone_len;
            remaining -= zone_len;
        }

        LOG(log_info, logtype_atalkd,
            "aurp_handle_zi_rsp: network %u zone '%s'",
            network, zone_name);

        /* Find the route for this network in peer's route list */
        int route_found = 0;
        for (rt = peer->ap_routes; rt != NULL; rt = rt->rt_next) {
            uint16_t rt_firstnet = ntohs(rt->rt_firstnet);
            uint16_t rt_lastnet = ntohs(rt->rt_lastnet);

            if (network >= rt_firstnet && network <= rt_lastnet) {
                route_found = 1;
                /* Add zone to this route */
                int addzone_result = addzone(rt, zone_len, zone_name);
                if (addzone_result == 0) {
                    rt->rt_flags |= RTMPTAB_HASZONES;
                    zones_added++;
                    LOG(log_info, logtype_atalkd,
                        "aurp_handle_zi_rsp: ADDED zone '%s' to route %u-%u",
                        zone_name, rt_firstnet, rt_lastnet);
                } else {
                    LOG(log_warning, logtype_atalkd,
                        "aurp_handle_zi_rsp: addzone('%s') failed with %d for route %u-%u",
                        zone_name, addzone_result, rt_firstnet, rt_lastnet);
                }
                break;
            }
        }
        if (!route_found) {
            LOG(log_warning, logtype_atalkd,
                "aurp_handle_zi_rsp: no route found for network %u, cannot add zone '%s'",
                network, zone_name);
        }
    }

    LOG(log_info, logtype_atalkd,
        "aurp_handle_zi_rsp: added %d zones from %s",
        zones_added, inet_ntoa(peer->ap_addr));

    /* Only finalize if this is the last ZI-Rsp packet */
    if (peer->ap_last_recv_flags & AURP_FLAG_LAST) {
        if (peer->ap_zi_pending) {
            free(peer->ap_zi_pending);
            peer->ap_zi_pending = NULL;
        }
        peer->ap_zi_pending_count = 0;
        peer->ap_zi_pending_alloc = 0;

        if (peer->ap_recv_state == AURP_RECV_WAIT_ZI_RSP) {
            peer->ap_recv_state = AURP_RECV_CONNECTED;
            LOG(log_info, logtype_atalkd,
                "aurp: connected to %s (with zones)",
                inet_ntoa(peer->ap_addr));
        }
    } else {
        LOG(log_debug, logtype_atalkd,
            "aurp_handle_zi_rsp: awaiting more zone packets from %s",
            inet_ntoa(peer->ap_addr));
    }
}

/*
 * Event queue management
 */

/* Queue an event for RI-Upd */
void aurp_queue_event(struct aurp_peer *peer, int code, struct rtmptab *rt)
{
    struct aurp_event *event;

    if (peer == NULL || rt == NULL) {
        return;
    }

    /* Allocate event array if needed */
    if (peer->ap_pending == NULL) {
        peer->ap_pending_alloc = 16;
        peer->ap_pending = malloc(peer->ap_pending_alloc * sizeof(struct aurp_event));
        if (peer->ap_pending == NULL) {
            LOG(log_error, logtype_atalkd, "aurp_queue_event: malloc failed");
            return;
        }
        peer->ap_pending_count = 0;
    }

    /* Expand array if needed */
    if (peer->ap_pending_count >= peer->ap_pending_alloc) {
        int new_alloc = peer->ap_pending_alloc * 2;
        struct aurp_event *new_pending = realloc(peer->ap_pending,
                                                  new_alloc * sizeof(struct aurp_event));
        if (new_pending == NULL) {
            LOG(log_error, logtype_atalkd, "aurp_queue_event: realloc failed");
            return;
        }
        peer->ap_pending = new_pending;
        peer->ap_pending_alloc = new_alloc;
    }

    /* Add event */
    event = &peer->ap_pending[peer->ap_pending_count];
    event->ae_code = code;
    event->ae_firstnet = rt->rt_firstnet;
    event->ae_lastnet = rt->rt_lastnet;
    event->ae_distance = rt->rt_hops;
    peer->ap_pending_count++;

    LOG(log_debug, logtype_atalkd,
        "aurp_queue_event: queued event %d for peer %s (net %u-%u dist %u)",
        code, inet_ntoa(peer->ap_addr), rt->rt_firstnet, rt->rt_lastnet,
        rt->rt_hops);
}

/* Flush event queue */
void aurp_flush_events(struct aurp_peer *peer)
{
    if (peer == NULL) {
        return;
    }

    if (peer->ap_pending) {
        free(peer->ap_pending);
        peer->ap_pending = NULL;
    }
    peer->ap_pending_count = 0;
    peer->ap_pending_alloc = 0;
}

/*
 * RTMP integration - route management for AURP-learned routes
 */

/* Find route in peer's route list */
static struct rtmptab *aurp_find_route(struct aurp_peer *peer, uint16_t firstnet,
                                        uint16_t lastnet)
{
    struct rtmptab *rt;

    for (rt = peer->ap_routes; rt != NULL; rt = rt->rt_next) {
        if (ntohs(rt->rt_firstnet) == firstnet &&
            ntohs(rt->rt_lastnet) == lastnet) {
            return rt;
        }
    }

    return NULL;
}

/* Add route learned from AURP peer */
int aurp_rtmp_add_route(struct aurp_peer *peer, uint16_t firstnet,
                        uint16_t lastnet, uint8_t hops)
{
    struct rtmptab *rt, *irt;
    extern struct interface *interfaces;
    struct interface *iface;

    if (peer == NULL) {
        return -1;
    }

    /* Get primary AppleTalk interface for route attachment
     * Skip loopback interface, find first real interface */
    for (iface = interfaces; iface != NULL; iface = iface->i_next) {
        if ((iface->i_flags & IFACE_LOOPBACK) == 0 && iface->i_rt != NULL) {
            break;
        }
    }
    if (iface == NULL || iface->i_rt == NULL) {
        LOG(log_error, logtype_atalkd,
            "aurp_rtmp_add_route: no valid non-loopback interface for AURP routes");
        return -1;
    }

    /* Check if route already exists */
    rt = aurp_find_route(peer, firstnet, lastnet);
    if (rt != NULL) {
        /* Update existing route */
        rt->rt_hops = hops + 1;  /* Add 1 for the AURP tunnel hop */
        rt->rt_state = RTMPTAB_GOOD;
        LOG(log_debug, logtype_atalkd,
            "aurp_rtmp_add_route: updated %u-%u hops %u from %s",
            firstnet, lastnet, rt->rt_hops, inet_ntoa(peer->ap_addr));
        return 0;
    }

    /* Allocate new route */
    rt = calloc(1, sizeof(struct rtmptab));
    if (rt == NULL) {
        LOG(log_error, logtype_atalkd, "aurp_rtmp_add_route: calloc failed");
        return -1;
    }

    /* Initialize route */
    rt->rt_firstnet = htons(firstnet);
    rt->rt_lastnet = htons(lastnet);
    rt->rt_hops = hops + 1;  /* Add 1 for the AURP tunnel hop */
    rt->rt_state = RTMPTAB_GOOD;
    rt->rt_flags = RTMPTAB_AURP | RTMPTAB_HASZONES | RTMPTAB_ROUTE;  /* Mark as active route for RTMP */
    if (firstnet != lastnet) {
        rt->rt_flags |= RTMPTAB_EXTENDED;
    }
    rt->rt_gate = NULL;  /* No AppleTalk gateway for AURP routes */
    rt->rt_iface = iface;  /* Set interface for route lookups */

    /* Add to peer's route list */
    rt->rt_next = peer->ap_routes;
    if (peer->ap_routes != NULL) {
        peer->ap_routes->rt_prev = rt;
    }
    peer->ap_routes = rt;

    /* Add to interface's route list (i_rt circular list)
     * This makes the route visible to ZIP/NBP lookups */
    irt = iface->i_rt;
    if (irt->rt_inext == NULL) {  /* empty list */
        rt->rt_inext = NULL;
        rt->rt_iprev = rt;
        irt->rt_inext = rt;
    } else {
        rt->rt_inext = irt->rt_inext;
        rt->rt_iprev = irt->rt_inext->rt_iprev;
        irt->rt_inext->rt_iprev = rt;
        irt->rt_inext = rt;
    }

    LOG(log_info, logtype_atalkd,
        "aurp_rtmp_add_route: added AURP route %u-%u hops %u from %s (via IP tunnel)",
        firstnet, lastnet, rt->rt_hops, inet_ntoa(peer->ap_addr));

    return 0;
}

/*
 * Remove a route from all zone table references (zt->zt_rt) and free
 * the route's own zone list (rt->rt_zt).  Must be called before freeing
 * the rtmptab to prevent dangling pointers in the zone table that cause
 * SIGSEGV when NBP or ZIP later iterates zt->zt_rt.
 */
static void aurp_rtmp_cleanup_zones(struct rtmptab *rt)
{
    struct list *l, *lnext;
    struct ziptab *zt;
    struct list *zl, *zlnext;

    for (l = rt->rt_zt; l != NULL; l = lnext) {
        lnext = l->l_next;
        zt = (struct ziptab *)l->l_data;

        if (zt != NULL) {
            for (zl = zt->zt_rt; zl != NULL; zl = zlnext) {
                zlnext = zl->l_next;
                if (zl->l_data == (void *)rt) {
                    if (zl->l_prev != NULL) {
                        zl->l_prev->l_next = zl->l_next;
                    } else {
                        zt->zt_rt = zl->l_next;
                    }
                    if (zl->l_next != NULL) {
                        zl->l_next->l_prev = zl->l_prev;
                    }
                    free(zl);
                    break;
                }
            }
        }
        free(l);
    }
    rt->rt_zt = NULL;
}

/* Remove specific route from peer */
void aurp_rtmp_remove_route(struct aurp_peer *peer, uint16_t firstnet,
                            uint16_t lastnet)
{
    struct rtmptab *rt, *irt;

    if (peer == NULL) {
        return;
    }

    rt = aurp_find_route(peer, firstnet, lastnet);
    if (rt == NULL) {
        LOG(log_debug, logtype_atalkd,
            "aurp_rtmp_remove_route: route %u-%u not found", firstnet, lastnet);
        return;
    }

    /* Remove from peer's list */
    if (rt->rt_prev != NULL) {
        rt->rt_prev->rt_next = rt->rt_next;
    } else {
        peer->ap_routes = rt->rt_next;
    }
    if (rt->rt_next != NULL) {
        rt->rt_next->rt_prev = rt->rt_prev;
    }

    /* Remove from interface list */
    if (rt->rt_iprev != NULL) {
        if (rt->rt_iprev == rt) {  /* only route in list */
            if (rt->rt_iface != NULL && rt->rt_iface->i_rt != NULL) {
                rt->rt_iface->i_rt->rt_inext = NULL;
            }
        } else {
            /* Unlink from circular list */
            if (rt->rt_inext != NULL) {
                rt->rt_inext->rt_iprev = rt->rt_iprev;
            }
            if (rt->rt_iface != NULL && rt->rt_iface->i_rt != NULL) {
                irt = rt->rt_iface->i_rt;
                if (irt->rt_inext == rt) {
                    if (rt->rt_inext != NULL) {
                        irt->rt_inext = rt->rt_inext;
                    } else {
                        irt->rt_inext = NULL;
                    }
                }
            }
            rt->rt_iprev->rt_inext = rt->rt_inext;
        }
    }

    aurp_rtmp_cleanup_zones(rt);

    LOG(log_info, logtype_atalkd,
        "aurp_rtmp_remove_route: removed %u-%u from %s",
        firstnet, lastnet, inet_ntoa(peer->ap_addr));

    free(rt);
}

/* Update route distance */
void aurp_rtmp_update_route(struct aurp_peer *peer, uint16_t firstnet,
                            uint16_t lastnet, uint8_t hops)
{
    struct rtmptab *rt;

    if (peer == NULL) {
        return;
    }

    rt = aurp_find_route(peer, firstnet, lastnet);
    if (rt == NULL) {
        /* Route doesn't exist, add it */
        aurp_rtmp_add_route(peer, firstnet, lastnet, hops);
        return;
    }

    rt->rt_hops = hops + 1;
    rt->rt_state = RTMPTAB_GOOD;

    LOG(log_debug, logtype_atalkd,
        "aurp_rtmp_update_route: updated %u-%u hops %u from %s",
        firstnet, lastnet, rt->rt_hops, inet_ntoa(peer->ap_addr));
}

/* Delete all routes learned from peer */
void aurp_rtmp_delete_routes(struct aurp_peer *peer)
{
    struct rtmptab *rt, *next, *irt;
    int count = 0;

    if (peer == NULL) {
        return;
    }

    for (rt = peer->ap_routes; rt != NULL; rt = next) {
        next = rt->rt_next;

        /* Must unlink from the interface's circular i_rt list before freeing.
         * aurp_rtmp_add_route inserts into both lists; failing to remove from
         * the interface list here leaves dangling pointers that cause SIGSEGV
         * when the RTMP timer or ZIP/NBP code later iterates i_rt->rt_inext. */
        if (rt->rt_iprev != NULL) {
            if (rt->rt_iprev == rt) {
                /* Only route in the circular list */
                if (rt->rt_iface != NULL && rt->rt_iface->i_rt != NULL) {
                    rt->rt_iface->i_rt->rt_inext = NULL;
                }
            } else {
                /* Unlink from the circular list */
                if (rt->rt_inext != NULL) {
                    rt->rt_inext->rt_iprev = rt->rt_iprev;
                }
                rt->rt_iprev->rt_inext = rt->rt_inext;
                if (rt->rt_iface != NULL && rt->rt_iface->i_rt != NULL) {
                    irt = rt->rt_iface->i_rt;
                    if (irt->rt_inext == rt) {
                        irt->rt_inext = (rt->rt_inext != NULL) ? rt->rt_inext : NULL;
                    }
                }
            }
        }

        aurp_rtmp_cleanup_zones(rt);
        free(rt);
        count++;
    }
    peer->ap_routes = NULL;

    LOG(log_info, logtype_atalkd,
        "aurp_rtmp_delete_routes: deleted %d routes from %s",
        count, inet_ntoa(peer->ap_addr));
}

/* Notify AURP peers of local route changes */
void aurp_rtmp_notify_route_added(struct rtmptab *rt)
{
    struct aurp_peer *peer;

    if (rt == NULL || (rt->rt_flags & RTMPTAB_AURP)) {
        return;  /* Don't redistribute AURP-learned routes */
    }

    LOG(log_debug, logtype_atalkd,
        "aurp_rtmp_notify_route_added: net %u-%u",
        ntohs(rt->rt_firstnet), ntohs(rt->rt_lastnet));

    /* Queue NA event for all connected peers */
    for (peer = aurp_config.ac_peers; peer != NULL; peer = peer->ap_next) {
        if (peer->ap_send_state == AURP_SEND_CONNECTED) {
            aurp_queue_event(peer, AURP_EVT_NA, rt);
        }
    }
}

void aurp_rtmp_notify_route_deleted(struct rtmptab *rt)
{
    struct aurp_peer *peer;

    if (rt == NULL || (rt->rt_flags & RTMPTAB_AURP)) {
        return;  /* Don't redistribute AURP-learned routes */
    }

    LOG(log_debug, logtype_atalkd,
        "aurp_rtmp_notify_route_deleted: net %u-%u",
        ntohs(rt->rt_firstnet), ntohs(rt->rt_lastnet));

    /* Queue ND event for all connected peers */
    for (peer = aurp_config.ac_peers; peer != NULL; peer = peer->ap_next) {
        if (peer->ap_send_state == AURP_SEND_CONNECTED) {
            aurp_queue_event(peer, AURP_EVT_ND, rt);
        }
    }
}

void aurp_rtmp_notify_route_changed(struct rtmptab *rt)
{
    struct aurp_peer *peer;

    if (rt == NULL || (rt->rt_flags & RTMPTAB_AURP)) {
        return;  /* Don't redistribute AURP-learned routes */
    }

    LOG(log_debug, logtype_atalkd,
        "aurp_rtmp_notify_route_changed: net %u-%u",
        ntohs(rt->rt_firstnet), ntohs(rt->rt_lastnet));

    /* Queue NDC event for all connected peers */
    for (peer = aurp_config.ac_peers; peer != NULL; peer = peer->ap_next) {
        if (peer->ap_send_state == AURP_SEND_CONNECTED) {
            aurp_queue_event(peer, AURP_EVT_NDC, rt);
        }
    }
}
