/*
 * Copyright (c) 2026, AURP Implementation Project
 * All rights reserved.
 *
 * AURP (AppleTalk Update-Based Routing Protocol) - RFC 1504
 * Configuration parsing
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <atalk/logger.h>

#include "aurp.h"

/*
 * Parse AURP configuration directive
 * Returns: 0 on success, -1 on error
 */
int aurp_config_parse(char **argv)
{
    if (argv == NULL || argv[0] == NULL) {
        return -1;
    }

    if (strcmp(argv[0], "aurp-peer") == 0) {
        return aurp_config_peer(argv);
    } else if (strcmp(argv[0], "aurp-peerlist-file") == 0) {
        return aurp_config_peerlist_file(argv);
    } else if (strcmp(argv[0], "aurp-port") == 0) {
        return aurp_config_port(argv);
    } else if (strcmp(argv[0], "aurp-listen") == 0) {
        return aurp_config_listen(argv);
    } else if (strcmp(argv[0], "aurp-open-peering") == 0) {
        return aurp_config_open_peering(argv);
    }

    /* Not an AURP directive */
    return -1;
}

/* Configure AURP peer */
int aurp_config_peer(char **av)
{
    struct aurp_peer *peer;
    struct hostent *he;
    struct in_addr addr;

    if (av[1] == NULL) {
        fprintf(stderr, "aurp-peer: no address specified\n");
        return -1;
    }

    /* Try parsing as IP address first */
    if (inet_aton(av[1], &addr) == 0) {
        /* Try hostname resolution */
        he = gethostbyname(av[1]);
        if (he == NULL) {
            fprintf(stderr, "aurp-peer: cannot resolve %s\n", av[1]);
            return -1;
        }
        memcpy(&addr, he->h_addr, sizeof(addr));
    }

    /* Create peer */
    peer = aurp_peer_new(addr, av[1]);
    if (peer == NULL) {
        fprintf(stderr, "aurp-peer: failed to create peer\n");
        return -1;
    }

    peer->ap_flags |= AURP_PEER_CONFIGURED;

    /* Add to peer list */
    peer->ap_next = aurp_config.ac_peers;
    if (aurp_config.ac_peers != NULL) {
        aurp_config.ac_peers->ap_prev = peer;
    }
    aurp_config.ac_peers = peer;

    /* Enable AURP */
    aurp_config.ac_enabled = 1;

    LOG(log_info, logtype_default, "aurp-peer: configured peer %s (%s)",
        av[1], inet_ntoa(addr));

    return 0;
}

/* Configure AURP port */
int aurp_config_port(char **av)
{
    int port;

    if (av[1] == NULL) {
        fprintf(stderr, "aurp-port: no port specified\n");
        return -1;
    }

    port = atoi(av[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "aurp-port: invalid port %s\n", av[1]);
        return -1;
    }

    aurp_config.ac_port = port;
    aurp_config.ac_enabled = 1;

    LOG(log_info, logtype_default, "aurp-port: set to %d", port);

    return 0;
}

/* Configure AURP listen address */
int aurp_config_listen(char **av)
{
    struct in_addr addr;

    if (av[1] == NULL) {
        fprintf(stderr, "aurp-listen: no address specified\n");
        return -1;
    }

    if (inet_aton(av[1], &addr) == 0) {
        fprintf(stderr, "aurp-listen: invalid address %s\n", av[1]);
        return -1;
    }

    aurp_config.ac_listen_addr = addr;
    aurp_config.ac_enabled = 1;

    /* Also use this as our domain identifier */
    if (aurp_config.ac_local_ip.s_addr == INADDR_ANY) {
        aurp_config.ac_local_ip = addr;
    }

    LOG(log_info, logtype_default, "aurp-listen: set to %s", inet_ntoa(addr));

    return 0;
}

/* Configure AURP open peering */
int aurp_config_open_peering(char **av)
{
    if (av[1] == NULL) {
        fprintf(stderr, "aurp-open-peering: no value specified\n");
        return -1;
    }

    if (strcmp(av[1], "yes") == 0 || strcmp(av[1], "true") == 0 ||
            strcmp(av[1], "1") == 0) {
        aurp_config.ac_open_peering = 1;
        LOG(log_info, logtype_default, "aurp-open-peering: enabled");
    } else if (strcmp(av[1], "no") == 0 || strcmp(av[1], "false") == 0 ||
               strcmp(av[1], "0") == 0) {
        aurp_config.ac_open_peering = 0;
        LOG(log_info, logtype_default, "aurp-open-peering: disabled");
    } else {
        fprintf(stderr, "aurp-open-peering: invalid value %s\n", av[1]);
        return -1;
    }

    aurp_config.ac_enabled = 1;

    return 0;
}

/* Configure AURP peer list file */
int aurp_config_peerlist_file(char **av)
{
    if (av[1] == NULL) {
        fprintf(stderr, "aurp-peerlist-file: no file path specified\n");
        return -1;
    }

    /* Free existing path if present */
    if (aurp_config.ac_peerlist_file != NULL) {
        free(aurp_config.ac_peerlist_file);
    }

    /* Store file path (will be loaded during aurp_init()) */
    aurp_config.ac_peerlist_file = strdup(av[1]);
    if (aurp_config.ac_peerlist_file == NULL) {
        fprintf(stderr, "aurp-peerlist-file: out of memory\n");
        return -1;
    }

    aurp_config.ac_enabled = 1;

    LOG(log_info, logtype_default, "aurp-peerlist-file: set to %s", av[1]);

    return 0;
}
