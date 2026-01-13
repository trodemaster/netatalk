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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <atalk/logger.h>

#include "aurp.h"
#include "rtmp.h"

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
        LOG(log_error, logtype_default, "aurp_peer_new: calloc failed");
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

    /* Initialize packet buffer */
    peer->ap_last_pkt = NULL;
    peer->ap_last_pkt_len = 0;

    /* Set local domain identifier */
    peer->ap_local_di = aurp_config.ac_local_ip;

    peer->ap_flags = 0;

    LOG(log_info, logtype_default, "aurp_peer_new: created peer %s conn_id=%u",
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
 * Connection management
 */

/* Initiate connection to peer */
void aurp_peer_connect(struct aurp_peer *peer)
{
    if (peer == NULL) {
        return;
    }

    LOG(log_info, logtype_default, "aurp_peer_connect: connecting to %s",
        inet_ntoa(peer->ap_addr));

    /* Set state */
    peer->ap_recv_state = AURP_RECV_WAIT_OPEN_RSP;
    peer->ap_send_state = AURP_SEND_UNCONNECTED;

    /* Reset retries */
    peer->ap_send_retries = 0;
    peer->ap_tickle_retries = 0;

    /* Send Open-Req */
    aurp_send_open_req(peer);
}

/* Disconnect from peer */
void aurp_peer_disconnect(struct aurp_peer *peer)
{
    if (peer == NULL) {
        return;
    }

    LOG(log_info, logtype_default, "aurp_peer_disconnect: disconnecting from %s",
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

    for (peer = aurp_config.ac_peers; peer != NULL; peer = peer->ap_next) {
        /* Check for connection timeout */
        if (peer->ap_recv_state != AURP_RECV_UNCONNECTED &&
            peer->ap_recv_state != AURP_RECV_CONNECTED) {
            if (peer->ap_last_heard > 0 &&
                (now - peer->ap_last_heard) > AURP_LAST_HEARD_TIMER) {
                LOG(log_warning, logtype_default,
                    "aurp_timer: peer %s timed out waiting for response",
                    inet_ntoa(peer->ap_addr));
                aurp_peer_disconnect(peer);
                peer->ap_last_reconnect = now;
                continue;
            }

            /* Retry sending last packet */
            if ((now - peer->ap_last_send) >= AURP_SEND_RETRY_TIMER) {
                if (peer->ap_send_retries >= AURP_SEND_RETRY_LIMIT) {
                    LOG(log_error, logtype_default,
                        "aurp_timer: peer %s exceeded retry limit",
                        inet_ntoa(peer->ap_addr));
                    aurp_peer_disconnect(peer);
                    peer->ap_last_reconnect = now;
                    continue;
                }

                if (peer->ap_last_pkt != NULL && peer->ap_last_pkt_len > 0) {
                    LOG(log_debug, logtype_default,
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
                LOG(log_warning, logtype_default,
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
                    LOG(log_error, logtype_default,
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
                LOG(log_info, logtype_default,
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
 * Packet handlers
 */

/* Handle Open-Req */
void aurp_handle_open_req(struct aurp_peer *peer, char *data, int len)
{
    struct in_addr remote_di;
    uint16_t version;
    int n;

    LOG(log_info, logtype_default, "aurp_handle_open_req: from %s",
        inet_ntoa(peer->ap_addr));

    /* Parse remote domain identifier */
    n = aurp_parse_domain_id(data, len, &remote_di);
    if (n < 0) {
        LOG(log_error, logtype_default,
            "aurp_handle_open_req: failed to parse domain identifier");
        return;
    }
    data += n;
    len -= n;

    peer->ap_remote_di = remote_di;

    /* Parse version */
    if (len < 2) {
        LOG(log_error, logtype_default,
            "aurp_handle_open_req: packet too short for version");
        return;
    }
    memcpy(&version, data, 2);
    version = ntohs(version);
    data += 2;
    len -= 2;

    if (version != AURP_VERSION) {
        LOG(log_warning, logtype_default,
            "aurp_handle_open_req: unsupported version %u", version);
        aurp_send_open_rsp(peer, AURP_ERR_INVALID_VERSION);
        return;
    }

    /* TODO: Parse options if present */

    /* Accept connection */
    peer->ap_send_state = AURP_SEND_CONNECTED;
    aurp_send_open_rsp(peer, 0);  /* 0 = success */

    LOG(log_info, logtype_default,
        "aurp_handle_open_req: accepted connection from %s",
        inet_ntoa(peer->ap_addr));
}

/* Handle Open-Rsp */
void aurp_handle_open_rsp(struct aurp_peer *peer, char *data, int len)
{
    struct in_addr remote_di;
    int16_t error_code;
    uint16_t error_code_net;
    int n;

    LOG(log_info, logtype_default, "aurp_handle_open_rsp: from %s",
        inet_ntoa(peer->ap_addr));

    if (peer->ap_recv_state != AURP_RECV_WAIT_OPEN_RSP) {
        LOG(log_warning, logtype_default,
            "aurp_handle_open_rsp: unexpected Open-Rsp in state %d",
            peer->ap_recv_state);
        return;
    }

    /* Parse remote domain identifier */
    n = aurp_parse_domain_id(data, len, &remote_di);
    if (n < 0) {
        LOG(log_error, logtype_default,
            "aurp_handle_open_rsp: failed to parse domain identifier");
        return;
    }
    data += n;
    len -= n;

    peer->ap_remote_di = remote_di;

    /* Parse error code */
    if (len < 2) {
        LOG(log_error, logtype_default,
            "aurp_handle_open_rsp: packet too short for error code");
        return;
    }
    memcpy(&error_code_net, data, 2);
    error_code = (int16_t)ntohs(error_code_net);
    data += 2;
    len -= 2;

    if (error_code != 0) {
        LOG(log_error, logtype_default,
            "aurp_handle_open_rsp: peer %s rejected connection (error %d)",
            inet_ntoa(peer->ap_addr), error_code);
        aurp_peer_disconnect(peer);
        return;
    }

    /* Connection accepted - request routing information */
    peer->ap_recv_state = AURP_RECV_WAIT_RI_RSP;
    peer->ap_send_retries = 0;
    peer->ap_flags |= AURP_PEER_CONNECTED;

    aurp_send_ri_req(peer);

    LOG(log_info, logtype_default,
        "aurp_handle_open_rsp: connection accepted by %s",
        inet_ntoa(peer->ap_addr));
}

/* Handle RI-Req */
void aurp_handle_ri_req(struct aurp_peer *peer, char *data, int len)
{
    LOG(log_info, logtype_default, "aurp_handle_ri_req: from %s",
        inet_ntoa(peer->ap_addr));

    /* Send routing information response */
    aurp_send_ri_rsp(peer, 1);  /* 1 = last packet */
}

/* Handle RI-Rsp */
void aurp_handle_ri_rsp(struct aurp_peer *peer, char *data, int len)
{
    LOG(log_info, logtype_default, "aurp_handle_ri_rsp: from %s (stub)",
        inet_ntoa(peer->ap_addr));

    /* TODO: Parse routing tuples and add routes */
    /* For now, just acknowledge and go to connected state */

    if (peer->ap_recv_state == AURP_RECV_WAIT_RI_RSP) {
        peer->ap_recv_state = AURP_RECV_CONNECTED;
        aurp_send_ri_ack(peer, 0);
        LOG(log_info, logtype_default,
            "aurp_handle_ri_rsp: connection fully established with %s",
            inet_ntoa(peer->ap_addr));
    }
}

/* Handle RI-Ack */
void aurp_handle_ri_ack(struct aurp_peer *peer, char *data, int len)
{
    LOG(log_debug, logtype_default, "aurp_handle_ri_ack: from %s",
        inet_ntoa(peer->ap_addr));

    /* Clear pending retransmission */
    if (peer->ap_last_pkt) {
        free(peer->ap_last_pkt);
        peer->ap_last_pkt = NULL;
        peer->ap_last_pkt_len = 0;
    }
    peer->ap_send_retries = 0;
}

/* Handle RI-Upd */
void aurp_handle_ri_upd(struct aurp_peer *peer, char *data, int len)
{
    LOG(log_info, logtype_default, "aurp_handle_ri_upd: from %s (stub)",
        inet_ntoa(peer->ap_addr));

    /* TODO: Parse event tuples and update routes */

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

    LOG(log_info, logtype_default, "aurp_handle_rd: from %s error=%d",
        inet_ntoa(peer->ap_addr), error_code);

    aurp_peer_disconnect(peer);
}

/* Handle Tickle */
void aurp_handle_tickle(struct aurp_peer *peer)
{
    LOG(log_debug, logtype_default, "aurp_handle_tickle: from %s",
        inet_ntoa(peer->ap_addr));

    /* Send Tickle-Ack */
    aurp_send_tickle_ack(peer);
}

/* Handle Tickle-Ack */
void aurp_handle_tickle_ack(struct aurp_peer *peer)
{
    LOG(log_debug, logtype_default, "aurp_handle_tickle_ack: from %s",
        inet_ntoa(peer->ap_addr));

    /* Return to connected state */
    if (peer->ap_recv_state == AURP_RECV_WAIT_TICKLE_ACK) {
        peer->ap_recv_state = AURP_RECV_CONNECTED;
        peer->ap_tickle_retries = 0;
    }
}

/* Handle ZI-Req (stub) */
void aurp_handle_zi_req(struct aurp_peer *peer, char *data, int len)
{
    LOG(log_debug, logtype_default, "aurp_handle_zi_req: from %s (stub)",
        inet_ntoa(peer->ap_addr));
    /* TODO: Implement in Phase 5 */
}

/* Handle ZI-Rsp (stub) */
void aurp_handle_zi_rsp(struct aurp_peer *peer, char *data, int len)
{
    LOG(log_debug, logtype_default, "aurp_handle_zi_rsp: from %s (stub)",
        inet_ntoa(peer->ap_addr));
    /* TODO: Implement in Phase 5 */
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
            LOG(log_error, logtype_default, "aurp_queue_event: malloc failed");
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
            LOG(log_error, logtype_default, "aurp_queue_event: realloc failed");
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

    LOG(log_debug, logtype_default,
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
 * RTMP integration stubs - will be implemented when integrating with rtmp.c
 */

int aurp_rtmp_add_route(struct aurp_peer *peer, uint16_t firstnet,
                        uint16_t lastnet, uint8_t hops)
{
    LOG(log_debug, logtype_default,
        "aurp_rtmp_add_route: stub - net %u-%u hops %u", firstnet, lastnet, hops);
    /* TODO: Implement in Phase 4 */
    return 0;
}

void aurp_rtmp_delete_routes(struct aurp_peer *peer)
{
    LOG(log_debug, logtype_default, "aurp_rtmp_delete_routes: stub");
    /* TODO: Implement in Phase 4 */
}

void aurp_rtmp_notify_route_added(struct rtmptab *rt)
{
    LOG(log_debug, logtype_default, "aurp_rtmp_notify_route_added: stub");
    /* TODO: Implement in Phase 4 */
}

void aurp_rtmp_notify_route_deleted(struct rtmptab *rt)
{
    LOG(log_debug, logtype_default, "aurp_rtmp_notify_route_deleted: stub");
    /* TODO: Implement in Phase 4 */
}

void aurp_rtmp_notify_route_changed(struct rtmptab *rt)
{
    LOG(log_debug, logtype_default, "aurp_rtmp_notify_route_changed: stub");
    /* TODO: Implement in Phase 4 */
}
