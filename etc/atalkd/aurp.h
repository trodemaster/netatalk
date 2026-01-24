/*
 * Copyright (c) 2026, AURP Implementation Project
 * All rights reserved.
 *
 * AURP (AppleTalk Update-Based Routing Protocol) - RFC 1504
 * IP tunneling support for atalkd
 */

#ifndef ATALKD_AURP_H
#define ATALKD_AURP_H

#include <netinet/in.h>
#include <sys/types.h>
#include <time.h>
#include <stdint.h>

/*
 * AURP Constants (RFC 1504)
 */
#define AURP_VERSION        0x0001
#define AURP_PORT           387

/* Domain Identifier Types */
#define AURP_DI_NULL        0x00
#define AURP_DI_IP          0x01

/* Packet Types */
#define AURP_PKT_APPLETALK  0x0002  /* Encapsulated DDP packet */
#define AURP_PKT_ROUTING    0x0003  /* Routing information packet */

/* Command Codes */
#define AURP_CMD_RI_REQ     0x0001  /* Routing Info Request */
#define AURP_CMD_RI_RSP     0x0002  /* Routing Info Response */
#define AURP_CMD_RI_ACK     0x0003  /* Routing Info Acknowledgement */
#define AURP_CMD_RI_UPD     0x0004  /* Routing Info Update */
#define AURP_CMD_RD         0x0005  /* Router Down */
#define AURP_CMD_ZI_REQ     0x0006  /* Zone Info Request */
#define AURP_CMD_ZI_RSP     0x0007  /* Zone Info Response */
#define AURP_CMD_OPEN_REQ   0x0008  /* Open Request */
#define AURP_CMD_OPEN_RSP   0x0009  /* Open Response */
#define AURP_CMD_TICKLE     0x000e  /* Tickle (keepalive) */
#define AURP_CMD_TICKLE_ACK 0x000f  /* Tickle Acknowledgement */

/* Routing Flags */
#define AURP_FLAG_SUI_NA        0x4000  /* Send updates: Network Added */
#define AURP_FLAG_SUI_ND_NRC    0x2000  /* Network Deleted or Route Change */
#define AURP_FLAG_SUI_NDC       0x1000  /* Network Distance Change */
#define AURP_FLAG_SUI_ZC        0x0800  /* Zone Change */
#define AURP_FLAG_SUI_ALL       0x7800  /* All SUI flags combined */
#define AURP_FLAG_LAST          0x8000  /* Last packet in sequence */
#define AURP_FLAG_SZI           0x4000  /* Send Zone Info (in RI-Ack) */

/* Event Codes for RI-Upd */
#define AURP_EVT_NULL   0
#define AURP_EVT_NA     1   /* Network Added */
#define AURP_EVT_ND     2   /* Network Deleted */
#define AURP_EVT_NRC    3   /* Network Route Change */
#define AURP_EVT_NDC    4   /* Network Distance Change */
#define AURP_EVT_ZC     5   /* Zone Change (reserved) */

/* Error Codes (in Open-Rsp) */
#define AURP_ERR_NORMAL_CLOSE       -1
#define AURP_ERR_ROUTING_LOOP       -2
#define AURP_ERR_OUT_OF_SYNC        -3
#define AURP_ERR_OPTION_NEG         -4
#define AURP_ERR_INVALID_VERSION    -5
#define AURP_ERR_INSUFFICIENT_RES   -6
#define AURP_ERR_AUTHENTICATION     -7

/* ZI-Req/ZI-Rsp Subcodes */
#define AURP_SUBCODE_ZI_REQ         0x0001  /* Zone Info Request */
#define AURP_SUBCODE_ZI_NONEXT      0x0001  /* Zone Info Non-Extended Response */
#define AURP_SUBCODE_ZI_EXT         0x0002  /* Zone Info Extended Response */
#define AURP_SUBCODE_GZN            0x0003  /* Get Zones Net */
#define AURP_SUBCODE_GDZL           0x0004  /* Get Domain Zone List */

/* Timer constants (seconds) */
#define AURP_LAST_HEARD_TIMER     90
#define AURP_SEND_RETRY_TIMER     10
#define AURP_SEND_RETRY_LIMIT      5
#define AURP_TICKLE_RETRY_LIMIT   10
#define AURP_RECONNECT_TIMER     600  /* 10 minutes */
#define AURP_UPDATE_TIMER         10

/* Maximum packet size */
#define AURP_MAX_PKT_SIZE       8192

/* Sequence number handling */
#define AURP_MAX_SEQ            65535
#define AURP_SEQ_ZERO           0     /* Never used as sequence number */

/*
 * Peer State Machines
 */

/* Receiver States (we receive route data from peer) */
typedef enum {
    AURP_RECV_UNCONNECTED = 0,
    AURP_RECV_WAIT_OPEN_RSP,
    AURP_RECV_WAIT_RI_RSP,
    AURP_RECV_WAIT_ZI_RSP,
    AURP_RECV_CONNECTED,
    AURP_RECV_WAIT_TICKLE_ACK
} aurp_recv_state_t;

/* Sender States (we send route data to peer) */
typedef enum {
    AURP_SEND_UNCONNECTED = 0,
    AURP_SEND_CONNECTED,
    AURP_SEND_WAIT_RI_RSP_ACK,
    AURP_SEND_WAIT_RI_UPD_ACK,
    AURP_SEND_WAIT_RD_ACK
} aurp_send_state_t;

/*
 * Data Structures
 */

/* Event tuple for RI-Upd */
struct aurp_event {
    uint8_t     ae_code;
    uint16_t    ae_firstnet;
    uint16_t    ae_lastnet;
    uint8_t     ae_distance;
};

/* Forward declaration for rtmptab from rtmp.h */
struct rtmptab;

/* AURP Peer */
struct aurp_peer {
    struct aurp_peer    *ap_next;
    struct aurp_peer    *ap_prev;

    /* Network identification */
    struct in_addr       ap_addr;       /* Peer's IP address */
    char                *ap_hostname;   /* Configured hostname (or NULL) */

    /* Domain identifiers */
    struct in_addr       ap_local_di;   /* Our IP as domain identifier */
    struct in_addr       ap_remote_di;  /* Peer's domain identifier */

    /* Connection state */
    aurp_recv_state_t    ap_recv_state;
    aurp_send_state_t    ap_send_state;

    /* Connection IDs and sequence numbers */
    uint16_t             ap_local_conn_id;
    uint16_t             ap_remote_conn_id;
    uint16_t             ap_local_seq;
    uint16_t             ap_remote_seq;

    /* Timers */
    time_t               ap_last_heard;
    time_t               ap_last_send;
    time_t               ap_last_reconnect;
    int                  ap_send_retries;
    int                  ap_tickle_retries;

    /* Pending events for RI-Upd */
    struct aurp_event   *ap_pending;
    int                  ap_pending_count;
    int                  ap_pending_alloc;

    /* Routes learned from this peer */
    struct rtmptab      *ap_routes;

    /* Pending zone requests */
    uint16_t            *ap_zi_pending;     /* Networks waiting for zones */
    int                  ap_zi_pending_count;
    int                  ap_zi_pending_alloc;

    /* Last sent packet (for retransmission) */
    char                *ap_last_pkt;
    int                  ap_last_pkt_len;

    /* Last received packet flags (for handler use) */
    uint16_t             ap_last_recv_flags;

    /* Flags */
    int                  ap_flags;
#define AURP_PEER_CONFIGURED    0x01
#define AURP_PEER_CONNECTED     0x02
};

/* Global AURP Configuration */
struct aurp_config {
    int                  ac_enabled;
    int                  ac_port;
    int                  ac_open_peering;
    struct in_addr       ac_listen_addr;
    struct in_addr       ac_local_ip;       /* Our domain identifier */
    struct aurp_peer    *ac_peers;
    char                *ac_peerlist_file;  /* Path to peer list file */
};

extern struct aurp_config aurp_config;
extern int aurp_fd;  /* Global AURP socket file descriptor */

/*
 * Function Prototypes - aurp.c
 */

/* Initialization and cleanup */
int aurp_init(struct aurp_config *cfg);
void aurp_input(int fd);
void aurp_shutdown(void);

/* Packet sending functions */
int aurp_send_open_req(struct aurp_peer *peer);
int aurp_send_open_rsp(struct aurp_peer *peer, int16_t result);
int aurp_send_ri_req(struct aurp_peer *peer);
int aurp_send_ri_rsp(struct aurp_peer *peer, int last);
int aurp_send_ri_ack(struct aurp_peer *peer, uint16_t flags);
int aurp_send_ri_upd(struct aurp_peer *peer);
int aurp_send_rd(struct aurp_peer *peer, int16_t error);
int aurp_send_tickle(struct aurp_peer *peer);
int aurp_send_tickle_ack(struct aurp_peer *peer);

void aurp_track_nbp_request(uint8_t nbp_id, uint16_t src_net,
                            uint8_t src_node, uint8_t src_socket);

/* Raw EtherTalk capture for local->AURP forwarding (Linux only) */
int aurp_raw_init(void);
void aurp_raw_input(int fd);
int aurp_send_zi_req(struct aurp_peer *peer, uint16_t *nets, int count);
int aurp_send_zi_rsp(struct aurp_peer *peer, int last);
int aurp_send_zi_rsp_for_nets(struct aurp_peer *peer, const uint16_t *nets, int count);

/* Data forwarding functions */
struct aurp_peer *aurp_find_peer_for_net(uint16_t net);
int aurp_send_data(uint16_t dst_net, char *ddp_data, int ddp_len);
int aurp_send_data_to_peer(struct aurp_peer *peer, char *ddp_data, int ddp_len);

/* Packet building helpers */
int aurp_build_header(char *buf, int buflen, uint16_t conn_id, uint16_t seq,
                      uint16_t cmd, uint16_t flags);
int aurp_build_domain_id(char *buf, int buflen, struct in_addr *addr);
int aurp_parse_domain_id(char *buf, int len, struct in_addr *addr);

/* Sequence number utilities */
uint16_t aurp_next_seq(uint16_t seq);
int aurp_seq_is_successor(uint16_t seq, uint16_t prev);

/*
 * Function Prototypes - aurp_peer.c
 */

/* Peer lifecycle management */
struct aurp_peer *aurp_peer_new(struct in_addr addr, const char *hostname);
void aurp_peer_free(struct aurp_peer *peer);
struct aurp_peer *aurp_peer_find(struct in_addr addr);
struct aurp_peer *aurp_peer_find_or_create(struct in_addr addr);

/* Peer list loading from file */
int aurp_load_peerlist(const char *filepath);
int aurp_parse_peerlist(const char *data, size_t len);

/* Connection management */
void aurp_peer_connect(struct aurp_peer *peer);
void aurp_peer_disconnect(struct aurp_peer *peer);
void aurp_timer(void);
void aurp_log_status(void);  /* Debug: log all peer/route/zone info */

/* Packet handlers */
void aurp_handle_open_req(struct aurp_peer *peer, char *data, int len);
void aurp_handle_open_rsp(struct aurp_peer *peer, char *data, int len);
void aurp_handle_ri_req(struct aurp_peer *peer, char *data, int len);
void aurp_handle_ri_rsp(struct aurp_peer *peer, char *data, int len);
void aurp_handle_ri_ack(struct aurp_peer *peer, char *data, int len);
void aurp_handle_ri_upd(struct aurp_peer *peer, char *data, int len);
void aurp_handle_rd(struct aurp_peer *peer, char *data, int len);
void aurp_handle_tickle(struct aurp_peer *peer);
void aurp_handle_tickle_ack(struct aurp_peer *peer);
void aurp_handle_zi_req(struct aurp_peer *peer, char *data, int len);
void aurp_handle_zi_rsp(struct aurp_peer *peer, char *data, int len);

/* Event queue management */
void aurp_queue_event(struct aurp_peer *peer, int code, struct rtmptab *rt);
void aurp_flush_events(struct aurp_peer *peer);

/*
 * Function Prototypes - aurp_rtmp.c (RTMP integration)
 */

/* Route management for AURP */
int aurp_rtmp_add_route(struct aurp_peer *peer, uint16_t firstnet,
                        uint16_t lastnet, uint8_t hops);
void aurp_rtmp_remove_route(struct aurp_peer *peer, uint16_t firstnet,
                            uint16_t lastnet);
void aurp_rtmp_update_route(struct aurp_peer *peer, uint16_t firstnet,
                            uint16_t lastnet, uint8_t hops);
void aurp_rtmp_delete_routes(struct aurp_peer *peer);
void aurp_rtmp_notify_route_added(struct rtmptab *rt);
void aurp_rtmp_notify_route_deleted(struct rtmptab *rt);
void aurp_rtmp_notify_route_changed(struct rtmptab *rt);

/*
 * Function Prototypes - aurp_zip.c (ZIP integration)
 */

/* Zone information for AURP */
int aurp_zip_get_zones(uint16_t *nets, int count, char ***zones_out,
                       int **zone_counts_out);
int aurp_zip_add_zones(uint16_t network, char **zones, int count);

/*
 * Function Prototypes - aurp_config.c (Configuration parsing)
 */

/* Configuration parsing functions */
int aurp_config_parse(char **argv);
int aurp_config_peer(char **av);
int aurp_config_port(char **av);
int aurp_config_listen(char **av);
int aurp_config_open_peering(char **av);

#endif /* ATALKD_AURP_H */
