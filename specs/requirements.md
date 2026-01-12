# AURP IP Tunneling Implementation Plan for atalkd

## Overview

This document details the plan for implementing AURP (AppleTalk Update-Based Routing Protocol, RFC 1504) IP tunneling in the atalkd daemon, allowing AppleTalk networks to be connected across IP networks.

**Date**: January 2026
**Goal**: Implement AURP IP tunneling directly in netatalk/atalkd to enable standalone AppleTalk routing without external dependencies
**Target**: `/Users/blake/Developer/netatalk/etc/atalkd/` (C)
**Basis**: Testing results documented in `jrouter_netatalk_coexistence_findings.md` demonstrate that running jrouter and atalkd concurrently on the same L2 network is not viable. This implementation replaces jrouter's role by integrating AURP directly into atalkd.

---

## Requirements


| Requirement   | Decision                                                      |
| ------------- | ------------------------------------------------------------- |
| Integration   | Pure atalkd integration (single daemon, no companion process) |
| Platform      | Linux only                                                    |
| Compliance    | Full RFC 1504 AURP specification                              |
| Configuration | Extend existing atalkd.conf format                            |


---

## Background

### What is AURP?

AURP (AppleTalk Update-Based Routing Protocol) encapsulates AppleTalk routing information and data packets in UDP (default port 387). This enables AppleTalk networks to be connected across IP networks without requiring native AppleTalk support on the intermediate networks.

Key features:

- **Routing Information Exchange**: RI-Req/RI-Rsp/RI-Upd/RI-Ack packets
- **Zone Information Exchange**: ZI-Req/ZI-Rsp packets
- **Connection Management**: Open-Req/Open-Rsp, Tickle/Tickle-Ack, Router Down
- **Data Forwarding**: DDP packets encapsulated in AURP

### Current atalkd Architecture

atalkd is the userland AppleTalk network manager daemon in netatalk:

- **Location**: `/Users/blake/Developer/netatalk/etc/atalkd/`
- **Size**: ~6,000 lines of C code
- **Protocols**: RTMP, ZIP, NBP, AEP
- **Network**: Uses `AF_APPLETALK` sockets (kernel AppleTalk stack)
- **Main Loop**: `select()` based with `fd_set`
- **Timer**: 10-second SIGALRM handler (`as_timer()`)
- **No IP tunneling support currently**

### Implementation Goals

This AURP implementation will:

- Add IP tunneling capability directly to atalkd
- Allow atalkd to act as a seed router with AURP peer connectivity
- Enable AppleTalk network connectivity across IP-only networks
- Eliminate external router dependencies
- Maintain compatibility with existing atalkd configuration and protocols

### Why Replace jrouter with atalkd AURP?

Findings from testing with jrouter and atalkd running concurrently (documented in `jrouter_netatalk_coexistence_findings.md`) revealed:

- **Single L2 broadcast domain limitation**: Only one seed router can exist on the same L2 network
- **Configuration conflicts**: Running both jrouter and atalkd on the same L2 causes routing loops and service failures
- **Coexistence challenges**: atalkd's `-dontroute` flag cannot reliably coexist with another seed router when both need to operate on the same interface
- **Operational simplicity**: A single daemon (atalkd with AURP) is more maintainable than coordinating two separate processes

By implementing AURP directly in atalkd, we eliminate these conflicts and create a unified solution for both local AppleTalk networking and IP-tunneled AURP connectivity.

---

## Technical Design

### New Files to Create

#### 1. `etc/atalkd/aurp.h` (~350 lines)

AURP packet structures, constants, and peer state definitions.

```c
#ifndef ATALKD_AURP_H
#define ATALKD_AURP_H

#include <netinet/in.h>
#include <sys/types.h>
#include <time.h>

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

/* Timer constants (seconds) */
#define AURP_LAST_HEARD_TIMER     90
#define AURP_SEND_RETRY_TIMER     10
#define AURP_SEND_RETRY_LIMIT      5
#define AURP_TICKLE_RETRY_LIMIT   10
#define AURP_RECONNECT_TIMER     600  /* 10 minutes */
#define AURP_UPDATE_TIMER         10

/*
 * Peer State Machines
 */

/* Receiver States (we receive route data from peer) */
typedef enum {
    AURP_RECV_UNCONNECTED = 0,
    AURP_RECV_WAIT_OPEN_RSP,
    AURP_RECV_WAIT_RI_RSP,
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

    /* Pending events for RI-Upd */
    struct aurp_event   *ap_pending;
    int                  ap_pending_count;
    int                  ap_pending_alloc;

    /* Routes learned from this peer */
    struct rtmptab      *ap_routes;

    /* Last sent packet (for retransmission) */
    char                *ap_last_pkt;
    int                  ap_last_pkt_len;

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
};

extern struct aurp_config aurp_config;

/*
 * Function Prototypes - aurp.c
 */
int aurp_init(struct aurp_config *cfg);
void aurp_input(int fd);
void aurp_shutdown(void);

int aurp_send_open_req(struct aurp_peer *peer);
int aurp_send_open_rsp(struct aurp_peer *peer, int16_t result);
int aurp_send_ri_req(struct aurp_peer *peer);
int aurp_send_ri_rsp(struct aurp_peer *peer, int last);
int aurp_send_ri_ack(struct aurp_peer *peer, uint16_t flags);
int aurp_send_ri_upd(struct aurp_peer *peer);
int aurp_send_rd(struct aurp_peer *peer, int16_t error);
int aurp_send_tickle(struct aurp_peer *peer);
int aurp_send_tickle_ack(struct aurp_peer *peer);

/*
 * Function Prototypes - aurp_peer.c
 */
struct aurp_peer *aurp_peer_new(struct in_addr addr, const char *hostname);
void aurp_peer_free(struct aurp_peer *peer);
struct aurp_peer *aurp_peer_find(struct in_addr addr);
struct aurp_peer *aurp_peer_find_or_create(struct in_addr addr);

void aurp_peer_connect(struct aurp_peer *peer);
void aurp_peer_disconnect(struct aurp_peer *peer);
void aurp_timer(void);

void aurp_handle_open_req(struct aurp_peer *peer, char *data, int len);
void aurp_handle_open_rsp(struct aurp_peer *peer, char *data, int len);
void aurp_handle_ri_req(struct aurp_peer *peer, char *data, int len);
void aurp_handle_ri_rsp(struct aurp_peer *peer, char *data, int len);
void aurp_handle_ri_ack(struct aurp_peer *peer, char *data, int len);
void aurp_handle_ri_upd(struct aurp_peer *peer, char *data, int len);
void aurp_handle_rd(struct aurp_peer *peer, char *data, int len);
void aurp_handle_tickle(struct aurp_peer *peer);
void aurp_handle_tickle_ack(struct aurp_peer *peer);

void aurp_queue_event(struct aurp_peer *peer, int code, struct rtmptab *rt);

#endif /* ATALKD_AURP_H */
```

#### 2. `etc/atalkd/aurp.c` (~800 lines)

UDP socket handling and packet encoding/decoding.

Key functions:

- `aurp_init()` - Create UDP socket, bind to configured port
- `aurp_input()` - Receive UDP packets, parse headers, dispatch to handlers
- `aurp_send_*()` - Build and send each AURP packet type
- Domain identifier parsing/building
- Transport header parsing/building

#### 3. `etc/atalkd/aurp_peer.c` (~1200 lines)

Peer connection state machine and route management.

Key functions:

- Peer lifecycle: `aurp_peer_new()`, `aurp_peer_free()`, `aurp_peer_find()`
- Connection: `aurp_peer_connect()`, `aurp_peer_disconnect()`
- State machine handlers for each packet type
- Timer processing: retransmits, tickles, reconnection attempts
- Event queue management for RI-Upd

---

### Files to Modify

#### 1. `etc/atalkd/main.c`

Add AURP socket to the main `select()` loop.

**Changes:**

```c
/* Add after line ~90 (global variables) */
#include "aurp.h"
static int aurp_fd = -1;

/* In main(), after interface setup, before main loop */
if (aurp_config.ac_enabled) {
    aurp_fd = aurp_init(&aurp_config);
    if (aurp_fd >= 0) {
        FD_SET(aurp_fd, &fds);
        if (aurp_fd >= nfds) nfds = aurp_fd + 1;
    }
}

/* In the main for(;;) select() loop */
if (aurp_fd >= 0 && FD_ISSET(aurp_fd, &readfds)) {
    aurp_input(aurp_fd);
}

/* In as_timer() function */
if (aurp_config.ac_enabled) {
    aurp_timer();
}

/* In as_down() function, before exit */
if (aurp_config.ac_enabled) {
    aurp_shutdown();
}
```

#### 2. `etc/atalkd/config.c`

Add AURP configuration parsing.

**Changes:**

```c
/* Add to params[] array */
{ "aurp-peer",         aurp_peer_conf },
{ "aurp-port",         aurp_port_conf },
{ "aurp-open-peering", aurp_open_peering_conf },
{ "aurp-listen",       aurp_listen_conf },

/* Implement config functions */
static int aurp_peer_conf(char **av) {
    struct aurp_peer *peer;
    struct hostent *he;

    if (av[0] == NULL) {
        fprintf(stderr, "No peer address specified.\n");
        return -1;
    }

    peer = aurp_peer_new((struct in_addr){0}, av[0]);
    if (!peer) return -1;

    /* Try parsing as IP address */
    if (inet_aton(av[0], &peer->ap_addr) == 0) {
        /* Try hostname resolution */
        he = gethostbyname(av[0]);
        if (!he) {
            fprintf(stderr, "Cannot resolve AURP peer: %s\n", av[0]);
            aurp_peer_free(peer);
            return -1;
        }
        memcpy(&peer->ap_addr, he->h_addr, sizeof(peer->ap_addr));
    }

    /* Add to peer list */
    peer->ap_next = aurp_config.ac_peers;
    aurp_config.ac_peers = peer;
    aurp_config.ac_enabled = 1;

    return 2;
}
```

#### 3. `etc/atalkd/rtmp.h`

Extend `struct rtmptab` for AURP routes.

**Changes:**

```c
/* Add flag */
#define RTMPTAB_AURP    0x10    /* Route learned via AURP */

/* Add field to struct rtmptab (after rt_iface) */
struct aurp_peer    *rt_aurp_peer;  /* Non-NULL if AURP-sourced */
```

#### 4. `etc/atalkd/rtmp.c`

Add AURP route management functions.

**Changes:**

```c
/* New functions for AURP route integration */

int rtmp_add_aurp_route(struct aurp_peer *peer, uint16_t firstnet,
                        uint16_t lastnet, uint8_t hops) {
    struct rtmptab *rt;

    /* Check for routing loop */
    if (is_local_network(firstnet, lastnet)) {
        return -1;  /* Would create loop */
    }

    /* Check hop count */
    if (hops >= 15) {
        return 0;  /* Too far away */
    }

    /* Look for existing route */
    rt = find_route(firstnet, lastnet);
    if (rt == NULL) {
        /* Create new route */
        rt = newrt(NULL);
        rt->rt_firstnet = firstnet;
        rt->rt_lastnet = lastnet;
        rt->rt_hops = hops + 1;
        rt->rt_flags |= RTMPTAB_AURP | RTMPTAB_EXTENDED;
        rt->rt_aurp_peer = peer;
        rt->rt_state = RTMPTAB_GOOD;

        /* Link to peer's route list */
        /* ... */

        /* Install in kernel if valid */
        if (rt->rt_flags & RTMPTAB_HASZONES) {
            gateroute(RTMP_ADD, rt);
        }
    } else if (rt->rt_hops > hops + 1) {
        /* Better route found */
        rt->rt_hops = hops + 1;
        rt->rt_aurp_peer = peer;
        rt->rt_state = RTMPTAB_GOOD;
    }

    return 0;
}

void rtmp_delete_aurp_routes(struct aurp_peer *peer) {
    struct rtmptab *rt, *next;

    for (rt = peer->ap_routes; rt; rt = next) {
        next = rt->rt_inext;  /* Assuming AURP routes use this list */

        if (rt->rt_flags & RTMPTAB_ROUTE) {
            gateroute(RTMP_DEL, rt);
        }
        rtmp_free(rt);
    }
    peer->ap_routes = NULL;
}

/* Route change notification (call from existing route modification code) */
void rtmp_notify_route_added(struct rtmptab *rt) {
    struct aurp_peer *peer;

    /* Don't propagate AURP routes back to AURP peers (split horizon) */
    if (rt->rt_flags & RTMPTAB_AURP) return;

    for (peer = aurp_config.ac_peers; peer; peer = peer->ap_next) {
        if (peer->ap_send_state == AURP_SEND_CONNECTED) {
            aurp_queue_event(peer, AURP_EVT_NA, rt);
        }
    }
}
```

#### 5. `etc/atalkd/zip.c`

Add AURP zone exchange support.

**Changes:**

```c
/* Get zones for networks (for ZI-Rsp) */
int aurp_get_zones_for_nets(uint16_t *nets, int count,
                            char ***zones_out, int *zone_count_out) {
    /* Implementation */
}

/* Add zones received from AURP peer */
int aurp_add_zones(uint16_t network, char **zones, int count) {
    struct rtmptab *rt;
    struct ziptab *zt;
    int i;

    rt = find_route_by_net(network);
    if (!rt) return -1;

    for (i = 0; i < count; i++) {
        zt = find_or_create_zone(zones[i]);
        if (zt) {
            /* Link zone to route */
            /* ... */
        }
    }

    rt->rt_flags |= RTMPTAB_HASZONES;
    return 0;
}
```

#### 6. `etc/atalkd/meson.build`

Add new source files.

**Changes:**

```meson
atalkd_sources = [
    'aep.c',
    'aurp.c',        # NEW
    'aurp_peer.c',   # NEW
    'config.c',
    'main.c',
    'multicast.c',
    'nbp.c',
    'route.c',
    'rtmp.c',
    'zip.c',
]
```

---

## Configuration Format

### atalkd.conf Syntax Extensions

```
# Existing interface configuration (unchanged)
eth0 -seed -phase 2 -net 100-100 -addr 100.1 -zone "My Zone"

# AURP configuration (new, global options)
aurp-listen 0.0.0.0          # IP address to bind UDP socket
                              # Default: 0.0.0.0 (all interfaces)

aurp-port 387                 # UDP port number
                              # Default: 387 (standard AURP port)

aurp-open-peering no          # Accept connections from unknown peers
                              # Default: no

# AURP peers (can specify multiple)
aurp-peer 192.168.1.100       # By IP address
aurp-peer router.example.com  # By hostname (resolved at startup)
aurp-peer 10.0.0.1            # Another peer
```

---

## Implementation Phases

### Phase 1: Foundation

**Goal**: Basic structure and packet encoding/decoding

1. Create `aurp.h` with all structure definitions and constants
2. Create initial `aurp.c` with:
  - Domain identifier parsing/building
  - Transport header parsing/building
  - AURP header parsing/building
3. Update `meson.build` with new files
4. Add basic config parsing to `config.c` (just `aurp-peer` and `aurp-port`)
5. Test: Verify compilation

### Phase 2: UDP Socket Integration

**Goal**: Receive and parse AURP packets

1. Implement `aurp_init()` - socket creation and binding
2. Modify `main.c` to add AURP socket to `select()` loop
3. Implement `aurp_input()` - packet reception and dispatch
4. Add logging for received packets
5. Test: Verify AURP packets can be sent to and received from external peers

### Phase 3: Peer State Machine

**Goal**: Establish and maintain peer connections

1. Create `aurp_peer.c` with peer management
2. Implement Open-Req/Open-Rsp handshake
3. Implement Tickle/Tickle-Ack keepalive
4. Implement reconnection logic after failures
5. Add `aurp_timer()` for periodic tasks
6. Test: Verify connection establishment with AURP peers

### Phase 4: Route Exchange

**Goal**: Exchange routing information with peers

1. Implement RI-Req/RI-Rsp for initial route exchange
2. Implement RI-Upd/RI-Ack for incremental updates
3. Implement Router Down (RD) handling
4. Extend `rtmp.c` with AURP route management
5. Add route change notification hooks
6. Test: Verify routes are learned from AURP peers

### Phase 5: Zone Information

**Goal**: Exchange zone information with peers

1. Implement ZI-Req/ZI-Rsp for zone data
2. Implement GDZL-Req/GDZL-Rsp (GetDomainZoneList)
3. Integrate with existing `zip.c` zone management
4. Test: Verify zones are learned from AURP peers

### Phase 6: Data Forwarding

**Goal**: Forward encapsulated AppleTalk packets

1. Implement DDP packet encapsulation (AURP packet type 0x0002)
2. Route encapsulated packets to local interfaces
3. Encapsulate outbound packets for AURP peers
4. Handle NBP FwdReq for cross-tunnel name lookups
5. Test: Verify end-to-end AppleTalk connectivity through tunnel

### Phase 7: Testing and Polish

**Goal**: Robust, production-ready implementation

1. compile and install netatalk locally
2. Configure netatalk and atalkd use netatalk tools to inspect appletalk traffic
3. use netatalk existing test functions to confirm the code builds and works
4. Test failure and recovery scenarios
5. Add comprehensive error handling
6. Write documentation and man page updates

---

## Key Reference Files

### Testing and Configuration Reference


| File                                                                                     | Purpose                                                                                                                                                                                                                                           |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/Users/blake/Developer/machine-cfg/macpro2013/jrouter_netatalk_coexistence_findings.md` | **Basis for this implementation**: Documents testing results with jrouter and atalkd running concurrently. Key finding: jrouter and atalkd cannot coexist on the same L2 broadcast domain, motivating the AURP implementation directly in atalkd. |
| `/Users/blake/Developer/machine-cfg/macpro2013/netatalk_setup.md`                        | Netatalk host setup and configuration guide. This implementation uses a single network interface approach.                                                                                                                                        |


### jrouter (Go) - Reference Implementation

jrouter is a Go-based AppleTalk router with AURP support. While we're replacing jrouter's routing functionality with atalkd's AURP implementation, jrouter's source code is an excellent reference for AURP packet encoding/decoding and state machine logic. **We are NOT fixing or improving jrouter—it is reference material only.**


| File                                                  | Purpose                           |
| ----------------------------------------------------- | --------------------------------- |
| `/Users/blake/code/jrouter/aurp/aurp.go`              | AURP header, command codes, flags |
| `/Users/blake/code/jrouter/aurp/domain.go`            | Domain identifier encoding        |
| `/Users/blake/code/jrouter/aurp/transport.go`         | Transport header (conn ID, seq)   |
| `/Users/blake/code/jrouter/aurp/routing_info.go`      | RI packet encoding                |
| `/Users/blake/code/jrouter/aurp/zone_info.go`         | ZI packet encoding                |
| `/Users/blake/code/jrouter/router/aurp_peer.go`       | Peer state machine (~1365 lines)  |
| `/Users/blake/code/jrouter/router/aurp_peer_table.go` | Peer management                   |
| `/Users/blake/code/jrouter/router/aurp.go`            | UDP input handling                |
| `/Users/blake/code/jrouter/router/route_table.go`     | Route table management            |


### AURP Protocol Reference


| File                                                                                     | Purpose                                               |
| ---------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| RFC 1504                                                                                 | AppleTalk Update-Based Routing Protocol specification |
| `/Users/blake/Developer/machine-cfg/macpro2013/jrouter_netatalk_coexistence_findings.md` | Network topology and AURP integration findings        |


### atalkd (C) - Target Implementation


| File                                                     | Purpose                     |
| -------------------------------------------------------- | --------------------------- |
| `/Users/blake/Developer/netatalk/etc/atalkd/main.c`      | Main loop, select(), timers |
| `/Users/blake/Developer/netatalk/etc/atalkd/config.c`    | Configuration parsing       |
| `/Users/blake/Developer/netatalk/etc/atalkd/rtmp.c`      | Route table management      |
| `/Users/blake/Developer/netatalk/etc/atalkd/rtmp.h`      | Route table structures      |
| `/Users/blake/Developer/netatalk/etc/atalkd/zip.c`       | Zone management             |
| `/Users/blake/Developer/netatalk/etc/atalkd/zip.h`       | Zone structures             |
| `/Users/blake/Developer/netatalk/etc/atalkd/interface.h` | Interface structures        |


---

## Estimated Size


| Component                       | Lines     |
| ------------------------------- | --------- |
| `aurp.h`                        | ~350      |
| `aurp.c`                        | ~800      |
| `aurp_peer.c`                   | ~1200     |
| Modifications to existing files | ~300      |
| **Total**                       | **~2650** |


---

## Risks and Mitigations


| Risk                            | Mitigation                                                               |
| ------------------------------- | ------------------------------------------------------------------------ |
| Kernel AppleTalk interaction    | Test thoroughly on Linux; AURP is userspace-only                         |
| Sequence number synchronization | Implement robust out-of-sync detection per RFC 1504                      |
| Route table consistency         | Use AURP_PEER_CONNECTED flag to track peer state before accepting routes |
| Memory leaks in peer management | Use consistent alloc/free patterns; test with valgrind                   |
| Multi-peer complexity           | Start with single peer; add multi-peer after basic functionality works   |


---

## Testing Strategy

### Unit Tests

- Packet encoding/decoding for all AURP packet types
- Sequence number arithmetic (successor/predecessor, avoiding 0)
- Domain identifier parsing with various formats

### Integration Tests

- Use netatalk tools to inspect appletalk advertisements
- Route learning and propagation
- Zone information exchange
- Reconnection after network failure
- Graceful shutdown (Router Down)

### AURP Peer Testing

- Test with multiple simultaneous AURP peers
- Mixed seed/non-seed configurations
- Route propagation from multiple peers
- Zone information aggregation

**Note**: Testing with jrouter is for reference/validation purposes only. We are not fixing jrouter or coordinating with its operation—atalkd with AURP will operate independently as a complete AppleTalk routing solution.

---

## References

- RFC 1504: AppleTalk Update-Based Routing Protocol (AURP)
- Inside AppleTalk, Second Edition (Apple Computer)
- jrouter source code: [https://github.com/sfiera/jrouter](https://github.com/sfiera/jrouter) (or local copy)
- netatalk documentation: [https://netatalk.io/](https://netatalk.io/)

---

## Resume Checklist

To resume this implementation effort:

1. [ ] Read this document to refresh context
2. [ ] Reference jrouter source code at `/Users/blake/code/jrouter` for AURP packet format details
3. [ ] Ensure netatalk is buildable: `cd /Users/blake/Developer/netatalk && meson setup build && meson compile -C build`
4. [ ] Start with Phase 1: Create `aurp.h` with structure definitions
5. [ ] Use jrouter AURP implementation as reference for packet formats and state machine logic
6. [ ] Test each phase with AURP peers before proceeding to next phase

