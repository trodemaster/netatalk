/*
 * Copyright (c) 1990,1993 Regents of The University of Michigan.
 * All Rights Reserved. See COPYRIGHT.
 */

#ifndef ATALKD_NBP_H
#define ATALKD_NBP_H 1

struct nbptab {
    struct nbptab	*nt_prev, *nt_next;
    struct nbpnve	nt_nve;
    struct interface    *nt_iface;
};

struct aurp_peer;

extern struct nbptab	*nbptab;

int nbp_packet(struct atport *ap, struct sockaddr_at *from, char *data,
               int len);

/* Track pending AURP-forwarded NBP requests so replies can be tunneled back. */

#endif
