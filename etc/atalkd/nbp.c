/*
 * Copyright (c) 1990,1993 Regents of The University of Michigan.
 * All Rights Reserved. See COPYRIGHT.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <atalk/logger.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netatalk/at.h>
#include <netatalk/ddp.h>
#include <atalk/ddp.h>
#include <atalk/atp.h>
#include <atalk/nbp.h>
#include <atalk/util.h>

#ifdef __svr4__
#include <sys/sockio.h>
#endif /* __svr4__ */

#ifdef __linux__
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#ifndef ETH_P_AT
#define ETH_P_AT 0x809B
#endif
#endif

#include "atserv.h"
#include "interface.h"
#include "list.h"
#include "rtmp.h"
#include "gate.h"
#include "zip.h"
#include "nbp.h"
#include "multicast.h"
#include "aurp.h"


#ifdef __linux__
static int nbp_send_zone_multicast(struct interface *iface,
                                   const unsigned char *dst_hw,
                                   const unsigned char *nbp_payload,
                                   int nbp_len)
{
    unsigned char frame[1800];
    unsigned char ddp_packet[1600];
    unsigned char src_hw[6];
    struct ifreq ifr;
    struct sockaddr_ll sll;
    uint16_t llc_len;
    uint16_t src_net_host;
    uint16_t hop_len;
    int ddp_len;
    int frame_len;
    int fd;
    int pos;

    if (nbp_len <= 0 || nbp_len > 1400) {
        return -1;
    }

    ddp_len = 13 + nbp_len;
    if (ddp_len > (int)sizeof(ddp_packet)) {
        return -1;
    }

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_802_2));
    if (fd < 0) {
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface->i_name, sizeof(ifr.ifr_name) - 1);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        close(fd);
        return -1;
    }

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }

    memcpy(src_hw, ifr.ifr_hwaddr.sa_data, sizeof(src_hw));

    src_net_host = ntohs(iface->i_addr.sat_addr.s_net);

    pos = 0;
    hop_len = (0 << 10) | (ddp_len & 0x3FF);
    ddp_packet[pos++] = (hop_len >> 8) & 0xFF;
    ddp_packet[pos++] = hop_len & 0xFF;
    ddp_packet[pos++] = 0x00;
    ddp_packet[pos++] = 0x00;
    ddp_packet[pos++] = 0x00;
    ddp_packet[pos++] = 0x00;
    ddp_packet[pos++] = ATADDR_BCAST;
    ddp_packet[pos++] = 2;
    ddp_packet[pos++] = (src_net_host >> 8) & 0xFF;
    ddp_packet[pos++] = src_net_host & 0xFF;
    ddp_packet[pos++] = iface->i_addr.sat_addr.s_node;
    ddp_packet[pos++] = 2;
    ddp_packet[pos++] = DDPTYPE_NBP;

    memcpy(ddp_packet + pos, nbp_payload, nbp_len);

    memcpy(frame, dst_hw, 6);
    memcpy(frame + 6, src_hw, 6);
    llc_len = htons((uint16_t)(8 + ddp_len));
    memcpy(frame + 12, &llc_len, sizeof(llc_len));
    frame[14] = 0xAA;
    frame[15] = 0xAA;
    frame[16] = 0x03;
    frame[17] = 0x00;
    frame[18] = 0x00;
    frame[19] = 0x00;
    frame[20] = (ETH_P_AT >> 8) & 0xFF;
    frame[21] = ETH_P_AT & 0xFF;
    memcpy(frame + 22, ddp_packet, ddp_len);

    frame_len = 22 + ddp_len;

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_802_2);
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, dst_hw, 6);

    if (sendto(fd, frame, frame_len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}
#endif

extern int  transition;

struct nbptab   *nbptab = NULL;

static uint16_t nbp_ddp_checksum(const unsigned char *ddp, int ddp_len)
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


static
void nbp_ack(int fd, int nh_op, int nh_id, struct sockaddr_at *to)
{
    struct nbphdr   nh;
    char        *data, packet[SZ_NBPHDR + 1];
    nh.nh_op = nh_op;
    nh.nh_cnt = 0;
    nh.nh_id = nh_id;
    data = packet;
    *data++ = DDPTYPE_NBP;
    memcpy(data, &nh, SZ_NBPHDR);
    data += SZ_NBPHDR;

    if (sendto(fd, packet, data - packet, 0, (struct sockaddr *)to,
               sizeof(struct sockaddr_at)) < 0) {
        LOG(log_error, logtype_atalkd, "sendto: %s", strerror(errno));
    }
}

int nbp_packet(struct atport *ap, struct sockaddr_at *from, char *data, int len)
{
    struct nbphdr   nh;
    struct nbptuple nt;
    struct nbpnve   nn;
    struct sockaddr_at  sat;
    struct nbptab   *ntab;
    struct ziptab   *zt = NULL;
    struct interface    *iface;
    struct list     *l;
    struct rtmptab  *rtmp;
    char        *end, *nbpop, *zonep, packet[ATP_BUFSIZ];
    int         n, i, cc, locallkup;
    unsigned char      tmplen;
    /* initialize per valgrind */
    memset(&sat, 0, sizeof(struct sockaddr_at));
    end = data + len;

    if (data >= end) {
        LOG(log_info, logtype_atalkd, "nbp_packet malformed packet");
        return 1;
    }

    if (*data++ != DDPTYPE_NBP) {
        LOG(log_info, logtype_atalkd, "nbp_packet bad ddp type");
        return 1;
    }

    if (data + SZ_NBPHDR + SZ_NBPTUPLE > end) {
        LOG(log_info, logtype_atalkd, "nbp_packet: malformed packet");
        return 1;
    }

    memcpy(&nh, data, SZ_NBPHDR);
    nbpop = data;           /* remember for fwd and brrq */
    data += SZ_NBPHDR;

    if (nh.nh_cnt < 1) {
        LOG(log_info, logtype_atalkd, "nbp_packet: bad tuple count (%d/%d)", nh.nh_cnt,
            nh.nh_op);
        return 1;
    }

    /* Requests should carry exactly one tuple. Replies may contain multiple tuples. */
    if (nh.nh_op == NBPOP_BRRQ || nh.nh_op == NBPOP_LKUP ||
        nh.nh_op == NBPOP_FWD || nh.nh_op == NBPOP_RGSTR ||
        nh.nh_op == NBPOP_UNRGSTR) {
        if (nh.nh_cnt != 1) {
            LOG(log_info, logtype_atalkd, "nbp_packet: bad tuple count (%d/%d)", nh.nh_cnt,
                nh.nh_op);
            return 1;
        }
    }

    memcpy(&nt, data, SZ_NBPTUPLE);
    data += SZ_NBPTUPLE;
    memset(&nn.nn_sat, 0, sizeof(struct sockaddr_at));
#ifdef BSD4_4
    nn.nn_sat.sat_len = sizeof(struct sockaddr_at);
#endif /* BSD4_4 */
    nn.nn_sat.sat_family = AF_APPLETALK;
    nn.nn_sat.sat_addr.s_net = nt.nt_net;
    nn.nn_sat.sat_addr.s_node = nt.nt_node;
    nn.nn_sat.sat_port = nt.nt_port;
    /* object */
    tmplen = (unsigned char) * data;

    if (data >= end || tmplen > 32 || data + tmplen > end) {
        LOG(log_info, logtype_atalkd, "nbp_packet: malformed packet");
        return 1;
    }

    nn.nn_objlen = tmplen;
    data++;
    memcpy(nn.nn_obj, data, nn.nn_objlen);
    data += nn.nn_objlen;
    /* type */
    tmplen = (unsigned char) * data;

    if (data >= end || tmplen > 32 || data + tmplen > end) {
        LOG(log_info, logtype_atalkd, "nbp_packet: malformed packet");
        return 1;
    }

    nn.nn_typelen = tmplen;
    data++;
    memcpy(nn.nn_type, data, nn.nn_typelen);
    data += nn.nn_typelen;
    /* zone */
    tmplen = (unsigned char) * data;

    if (data >= end || tmplen > 32 || data + tmplen > end) {
        LOG(log_info, logtype_atalkd, "nbp_packet: malformed packet");
        return 1;
    }

    zonep = data;           /* remember for fwd */
    nn.nn_zonelen = tmplen;
    data++;
    memcpy(nn.nn_zone, data, nn.nn_zonelen);
    data += nn.nn_zonelen;

    if (data != end) {
        LOG(log_info, logtype_atalkd, "nbp_packet: malformed packet");
        return 1;
    }

    locallkup = 0;

    switch (nh.nh_op) {
    case NBPOP_RGSTR :

        /*
         * Find the ziptab entry for the zone we're trying to register in.
         */
        if (nn.nn_zonelen == 0 ||
                (nn.nn_zonelen == 1 && *nn.nn_zone == '*')) {
            if (interfaces->i_next->i_rt->rt_zt) {
                zt = (struct ziptab *)interfaces->i_next->i_rt->rt_zt->l_data;
            } else {
                zt = NULL;
            }
        } else {
            for (zt = ziptab; zt; zt = zt->zt_next) {
                if (zt->zt_len == nn.nn_zonelen && strndiacasecmp(zt->zt_name,
                        nn.nn_zone, zt->zt_len) == 0) {
                    break;
                }
            }

            if (zt == NULL) {
                nbp_ack(ap->ap_fd, NBPOP_ERROR, (int)nh.nh_id, from);
                return 0;
            }
        }

        /*
         * Observe that we don't have to do any local-zone verification
         * if the zone aleady has a multicast address set.
         */
        if (zt != NULL && zt->zt_bcast == NULL) {
            /*
             * Check if zone is associated with any of our local interfaces.
             */
            for (iface = interfaces; iface; iface = iface->i_next) {
                for (l = iface->i_rt->rt_zt; l; l = l->l_next) {
                    if (zt == (struct ziptab *)l->l_data) {
                        break;
                    }
                }

                if (l != NULL) {
                    break;
                }
            }

            if (iface == NULL) {
                nbp_ack(ap->ap_fd, NBPOP_ERROR, (int)nh.nh_id, from);
                return 0;
            }

            /* calculate and save multicast address */
            if (zone_bcast(zt) < 0) {
                LOG(log_error, logtype_atalkd, "nbp_packet: zone_bcast");
                return -1;
            }

            for (iface = interfaces; iface; iface = iface->i_next) {
                if ((iface->i_flags & IFACE_PHASE2) == 0) {
                    continue;
                }

                for (l = iface->i_rt->rt_zt; l; l = l->l_next) {
                    if (zt == (struct ziptab *)l->l_data) {
                        /* add multicast */
                        if (addmulti(iface->i_name, zt->zt_bcast) < 0) {
                            LOG(log_error, logtype_atalkd, "nbp_packet: addmulti: %s",
                                strerror(errno));
                            return -1;
                        }
                    }
                }
            }
        }

        if ((ntab = (struct nbptab *)malloc(sizeof(struct nbptab)))
                == NULL) {
            LOG(log_error, logtype_atalkd, "nbp_packet: malloc: %s", strerror(errno));
            return -1;
        }

        memcpy(&ntab->nt_nve, &nn, sizeof(struct nbpnve));
        ntab->nt_iface = ap->ap_iface;
        ntab->nt_next = nbptab;
        ntab->nt_prev = NULL;

        if (nbptab) {
            nbptab->nt_prev = ntab;
        }

        nbptab = ntab;
        nbp_ack(ap->ap_fd, NBPOP_OK, (int)nh.nh_id, from);
        break;

    case NBPOP_UNRGSTR :

        /* deal with local zone info */
        if ((nn.nn_zonelen == 1 && *nn.nn_zone == '*') ||
                (nn.nn_zonelen == 0)) {
            locallkup = 1;

            if (interfaces->i_next->i_rt->rt_zt) {
                zt = (struct ziptab *)interfaces->i_next->i_rt->rt_zt->l_data;
            } else {
                zt = NULL;
            }
        }

        /* remove from our data, perhaps removing a multicast address */
        for (ntab = nbptab; ntab; ntab = ntab->nt_next) {
            if (ntab->nt_nve.nn_objlen != nn.nn_objlen ||
                    strndiacasecmp(ntab->nt_nve.nn_obj, nn.nn_obj,
                                   nn.nn_objlen)) {
                continue;
            }

            if (ntab->nt_nve.nn_typelen != nn.nn_typelen ||
                    strndiacasecmp(ntab->nt_nve.nn_type, nn.nn_type,
                                   nn.nn_typelen)) {
                continue;
            }

            /*
             * I *think* we really do check the zone, here.
             *
             * i changed it to better handle local zone cases as well.
             * -- asun
             */

            /* match local zones */
            if (locallkup) {
                /* ntab is also local zone */
                if ((ntab->nt_nve.nn_zonelen == 1 &&
                        *ntab->nt_nve.nn_zone == '*') ||
                        (ntab->nt_nve.nn_zonelen == 0)) {
                    break;
                }

                /* ntab is default zone */
                if (zt && (zt->zt_len == ntab->nt_nve.nn_zonelen) &&
                        (strndiacasecmp(ntab->nt_nve.nn_zone, zt->zt_name,
                                        zt->zt_len) == 0)) {
                    break;
                }
            }

            /* match particular zone */
            if ((ntab->nt_nve.nn_zonelen == nn.nn_zonelen) &&
                    (strndiacasecmp(ntab->nt_nve.nn_zone, nn.nn_zone,
                                    nn.nn_zonelen) == 0)) {
                break;
            }
        }

        if (ntab == NULL) {
            nbp_ack(ap->ap_fd, NBPOP_ERROR, (int)nh.nh_id, from);
            return 0;
        }

        if (ntab->nt_next != NULL) {
            ntab->nt_next->nt_prev = ntab->nt_prev;
        }

        if (ntab->nt_prev != NULL) {
            ntab->nt_prev->nt_next = ntab->nt_next;
        }

        if (ntab == nbptab) {
            nbptab = ntab->nt_next;
        }

        /*
         * Check for another nbptab entry with the same zone.  If
         * there isn't one, find the ziptab entry for the zone and
         * remove the multicast address from the appropriate interfaces.
         * XXX
         */
        nbp_ack(ap->ap_fd, NBPOP_OK, (int)nh.nh_id, from);
        break;

    case NBPOP_BRRQ :

        /*
         * Couple of things:  1. Unless we have the -t flag (which is sort
         * of a misnomer, since you need it if you're doing any phase 1
         * work), always send NBPOP_FWD.  2. If we get a zone of '*',
         * and we know what the sender meant by '*', we copy the real
         * zone into the packet.
         */
        if (nn.nn_zonelen == 0 ||
                (nn.nn_zonelen == 1 && *nn.nn_zone == '*')) {
            iface = ap->ap_iface;

            if (iface && iface->i_rt->rt_zt) {
                zt = (struct ziptab *)iface->i_rt->rt_zt->l_data;
            } else if (interfaces->i_next->i_rt->rt_zt) {
                zt = (struct ziptab *)interfaces->i_next->i_rt->rt_zt->l_data;
            } else {
                zt = NULL;
            }

            /*
             * Copy zone into packet.  Note that we're changing len, data, and
             * nbpop.  Later, we'll use ( data - len ) to mean the beginning
             * of this packet.
             */
            if (zt) {
                memcpy(packet, data - len, len);
                nbpop = packet + (len - (data - nbpop));
                data = packet + (len - (data - zonep));
                *data++ = zt->zt_len;
                memcpy(data, zt->zt_name, zt->zt_len);
                data += zt->zt_len;
                len = data - packet;
            }
        } else {
            for (zt = ziptab; zt; zt = zt->zt_next) {
                if (zt->zt_len == nn.nn_zonelen && strndiacasecmp(zt->zt_name,
                        nn.nn_zone, zt->zt_len) == 0) {
                    break;
                }
            }

            if (zt == NULL) {
                nbp_ack(ap->ap_fd, NBPOP_ERROR, (int)nh.nh_id, from);
                return 0;
            }
        }

        /*
         * If we've got no zones, send out LKUP on the local net.
         * Otherwise, look through the zone table.
         */
        if (zt == NULL) {
#ifdef BSD4_4
            sat.sat_len = sizeof(struct sockaddr_at);
#endif /* BSD4_4 */
            sat.sat_family = AF_APPLETALK;
            sat.sat_port = ap->ap_port;
            nh.nh_op = NBPOP_LKUP;
            memcpy(nbpop, &nh, SZ_NBPHDR);
            sat.sat_addr.s_net = 0;         /* XXX */
            sat.sat_addr.s_node = ATADDR_BCAST;

            /* Find the first non-loopback ap */
            for (iface = interfaces; iface; iface = iface->i_next) {
                if (((iface->i_flags & IFACE_LOOPBACK) == 0) &&
                        (iface == ap->ap_iface ||
                         (iface->i_flags & IFACE_ISROUTER))) {
                    break;
                }
            }

            if (iface == NULL) {
                return 0;
            }

            for (ap = iface->i_ports; ap; ap = ap->ap_next) {
                if (ap->ap_packet == nbp_packet) {
                    break;
                }
            }

            if (ap == NULL) {
                return 0;
            }

            if (sendto(ap->ap_fd, data - len, len, 0, (struct sockaddr *)&sat,
                       sizeof(struct sockaddr_at)) < 0) {
                LOG(log_error, logtype_atalkd, "nbp brrq sendto: %s", strerror(errno));
            }

            locallkup = 1;
        } else {
#ifdef BSD4_4
            sat.sat_len = sizeof(struct sockaddr_at);
#endif /* BSD4_4 */
            sat.sat_family = AF_APPLETALK;
            sat.sat_port = ap->ap_port;

            for (l = zt->zt_rt; l; l = l->l_next) {
                rtmp = (struct rtmptab *)l->l_data;

                if (rtmp->rt_gate == NULL) {
                    /* Check if route has iface set (AURP routes) */
                    if (rtmp->rt_iface != NULL) {
                        iface = (struct interface *)rtmp->rt_iface;
                    } else {
                        /* Local route - find interface by checking i_rt head */
                        for (iface = interfaces; iface;
                                iface = iface->i_next) {
                            if (iface->i_rt == rtmp) {
                                break;
                            }
                        }

                        if (!iface) {
                            LOG(log_error, logtype_atalkd, "nbp_packet: Can't find route's interface!");
                            return -1;
                        }
                    }

                    ap = iface->i_ports;
                } else {
                    ap = rtmp->rt_gate->g_iface->i_ports;
                }

                for (; ap; ap = ap->ap_next) {
                    if (ap->ap_packet == nbp_packet) {
                        break;
                    }
                }

                if (!ap) {
                    LOG(log_error, logtype_atalkd, "nbp_packet: Can't find port!");
                    return -1;
                }

                if (transition &&
                        (rtmp->rt_flags & RTMPTAB_EXTENDED) == 0) {
                    if (rtmp->rt_gate == NULL) {
                        locallkup = 1;
                    }

                    nh.nh_op = NBPOP_LKUP;
                    memcpy(nbpop, &nh, SZ_NBPHDR);
                    sat.sat_addr.s_net = rtmp->rt_firstnet;
                    sat.sat_addr.s_node = ATADDR_BCAST;
                } else {
                    if (rtmp->rt_gate == NULL) {
                        /* AURP routes have no gate but use IP tunnels */
                        if (rtmp->rt_flags & RTMPTAB_AURP) {
                            nh.nh_op = NBPOP_FWD;
                            memcpy(nbpop, &nh, SZ_NBPHDR);
                            sat.sat_addr.s_net = rtmp->rt_firstnet;
                            sat.sat_addr.s_node = 0;  /* Router on that network */
                        } else {
                            /* Local route without gateway */
                            nh.nh_op = NBPOP_LKUP;
                            memcpy(nbpop, &nh, SZ_NBPHDR);
                            sat.sat_addr.s_net = 0;
                            sat.sat_addr.s_node = ATADDR_BCAST;
                            locallkup = 1;
                        }
                    } else {
                        nh.nh_op = NBPOP_FWD;
                        memcpy(nbpop, &nh, SZ_NBPHDR);
                        sat.sat_addr.s_net = rtmp->rt_firstnet;
                        sat.sat_addr.s_node = 0;
                    }
                }

                /* Check if this is an AURP route - needs tunnel forwarding */
                if (rtmp->rt_flags & RTMPTAB_AURP) {
                    /* Build extended DDP packet for AURP forwarding */
                    unsigned char ddp_packet[ATP_BUFSIZ];
                    uint16_t dst_net = ntohs(sat.sat_addr.s_net);
                    uint16_t src_net = ntohs(from->sat_addr.s_net);
                    
                    /* Calculate NBP data length from current position to end of packet
                     * nbpop points to NBP header (after DDP type was consumed)
                     * end points to end of received packet */
                    int nbp_data_len = end - nbpop;
                    uint16_t total_len = 13 + nbp_data_len;  /* 13-byte DDP header + NBP data */
                    
                    /* Parse NBP tuple address (after 2-byte NBP header) */
                    unsigned char *tuple_start = (unsigned char *)(nbpop + 2);
                    uint16_t tuple_net = (tuple_start[0] << 8) | tuple_start[1];
                    uint8_t tuple_node = tuple_start[2];
                    uint8_t tuple_socket = tuple_start[3];
                    
                    /*
                     * DDP source policy for AURP‑forwarded NBP:
                     * - Keep the tuple reply‑to as the original requester.
                     * - Use the original requester as the DDP source (matches jrouter).
                     */
                    LOG(log_debug, logtype_atalkd,
                        "DEBUG NBP TUPLE: from %u.%u.%u, tuple says respond to %u.%u.%u",
                        src_net, from->sat_addr.s_node, from->sat_port,
                        tuple_net, tuple_node, tuple_socket);
                    uint16_t src_net_host = src_net;
                    uint8_t src_node = from->sat_addr.s_node;
                    uint8_t src_socket = from->sat_port;
                    LOG(log_debug, logtype_atalkd,
                        "DEBUG DDP SOURCE: Using REQUESTER address %u.%u.%u",
                        src_net_host, src_node, src_socket);
                    
                    /* DEBUG: Show the full NBP data bytes before sending */
                    char hex_buf[256];
                    int hex_pos = 0;
                    for (int i = 0; i < (nbp_data_len < 20 ? nbp_data_len : 20); i++) {
                        hex_pos += sprintf(hex_buf + hex_pos, "%02x ", (unsigned char)nbpop[i]);
                    }
                    LOG(log_debug, logtype_atalkd,
                        "DEBUG NBP DATA HEX (first %d bytes): %s",
                        (nbp_data_len < 20 ? nbp_data_len : 20), hex_buf);
                    
                    LOG(log_debug, logtype_atalkd,
                        "DEBUG: AURP path executing! nbp_data_len=%d total_len=%d len=%d",
                        nbp_data_len, total_len, len);

                    /* Skip if destination network is 0 (local broadcast) */
                    if (dst_net == 0) {
                        LOG(log_debug, logtype_atalkd, "nbp brrq: skipping local broadcast (net 0)");
                        continue;
                    }

                    if (total_len > sizeof(ddp_packet)) {
                        LOG(log_error, logtype_atalkd, "nbp brrq: packet too large for AURP");
                        continue;
                    }

                    /* Build extended DDP header manually in correct byte order
                     * The struct ddpehdr has fields in wrong order for wire format! */
                    int pos = 0;

                    /* Bytes 0-1: Hop count (4 bits) + Length (10 bits) in BIG ENDIAN */
                    uint16_t hop_len = (0 << 10) | (total_len & 0x3FF);
                    ddp_packet[pos++] = (hop_len >> 8) & 0xFF;  /* High byte */
                    ddp_packet[pos++] = hop_len & 0xFF;         /* Low byte */

                    /* Bytes 2-3: Checksum (0x0000) */
                    ddp_packet[pos++] = 0x00;
                    ddp_packet[pos++] = 0x00;

                    /* Bytes 4-5: Destination Network (big-endian) */
                    ddp_packet[pos++] = (dst_net >> 8) & 0xFF;
                    ddp_packet[pos++] = dst_net & 0xFF;

                    /* Byte 6: Destination Node */
                    ddp_packet[pos++] = sat.sat_addr.s_node;

                    /* Byte 7: Destination Socket */
                    ddp_packet[pos++] = sat.sat_port;

                    /* Bytes 8-9: Source Network (big-endian) - router interface */
                    ddp_packet[pos++] = (src_net_host >> 8) & 0xFF;
                    ddp_packet[pos++] = src_net_host & 0xFF;

                    /* Byte 10: Source Node - router interface */
                    ddp_packet[pos++] = src_node;

                    /* Byte 11: Source Socket - NBP socket */
                    ddp_packet[pos++] = src_socket;

                    /* Byte 12: DDP Type (NBP = 0x02) */
                    ddp_packet[pos++] = DDPTYPE_NBP;

                    /* Copy NBP data after DDP header
                     * 'nbpop' points to NBP header (operation code was updated to FwdReq)
                     * 'end' points to end of received packet
                     * This includes: NBP header (2 bytes) + NBP tuples */
                    memcpy(ddp_packet + pos, nbpop, nbp_data_len);

                    /* DEBUG: Verify DDP packet construction */
                    LOG(log_debug, logtype_atalkd,
                        "DEBUG DDP: pos=%d bytes[0-1]=%02x%02x bytes[12]=%02x total_len=%d",
                        pos, ddp_packet[0], ddp_packet[1], ddp_packet[12], total_len);

                    /* Forward through AURP tunnel */
                    LOG(log_warning, logtype_atalkd,
                        "nbp brrq: AURP fwd zone '%.*s' to net %u tuple %u.%u.%u",
                        nn.nn_zonelen, nn.nn_zone, dst_net,
                        tuple_net, tuple_node, tuple_socket);
                    aurp_track_nbp_request(nh.nh_id, tuple_net, tuple_node, tuple_socket);
                    if (aurp_send_data(dst_net, (char *)ddp_packet, total_len) < 0) {
                        LOG(log_debug, logtype_atalkd,
                            "nbp brrq: AURP forward to net %u failed", dst_net);
                    } else {
                        LOG(log_debug, logtype_atalkd,
                            "nbp brrq: forwarded to AURP network %u", dst_net);
                    }
                    continue;
                }

                /* Local route - prefer zone multicast when available */
#ifdef __linux__
                if (zt != NULL &&
                    sat.sat_addr.s_net == 0 && sat.sat_addr.s_node == ATADDR_BCAST) {
                    if (zt->zt_bcast == NULL) {
                        if (zone_bcast(zt) < 0) {
                            LOG(log_warning, logtype_atalkd,
                                "nbp_packet: zone_bcast failed for zone %s",
                                zt->zt_name);
                        } else if (addmulti(ap->ap_iface->i_name, zt->zt_bcast) < 0) {
                            LOG(log_warning, logtype_atalkd,
                                "nbp_packet: addmulti failed for zone %s on %s: %s",
                                zt->zt_name, ap->ap_iface->i_name,
                                strerror(errno));
                        }
                    }

                    if (zt->zt_bcast != NULL) {
                        unsigned char *nbp_payload = (unsigned char *)(data - len) + 1;
                        int nbp_len = len - 1;

                        if (nbp_len > 0 &&
                            nbp_send_zone_multicast(ap->ap_iface, zt->zt_bcast,
                                                    nbp_payload, nbp_len) == 0) {
                            continue;
                        }
                    }
                }
#endif

                if (sendto(ap->ap_fd, data - len, len, 0,
                           (struct sockaddr *)&sat,
                           sizeof(struct sockaddr_at)) < 0) {
                    LOG(log_error, logtype_atalkd, "nbp brrq sendto %u.%u: %s",
                        ntohs(sat.sat_addr.s_net), sat.sat_addr.s_node,
                        strerror(errno));
                    continue;
                }
            }
        }

        if (!locallkup) {
            break;
        }

    /*FALL THROUGH*/

    case NBPOP_FWD :

        /* send lkup on net. we need to make sure we're a router. */
        if (!locallkup && (ap->ap_iface->i_flags & IFACE_ISROUTER)) {
            nh.nh_op = NBPOP_LKUP;
            memcpy(nbpop, &nh, SZ_NBPHDR);
            from->sat_addr.s_net = 0;
            from->sat_addr.s_node = ATADDR_BCAST;

            if (sendto(ap->ap_fd, data - len, len, 0, (struct sockaddr *)from,
                       sizeof(struct sockaddr_at)) < 0) {
                LOG(log_error, logtype_atalkd, "nbp fwd sendto %u.%u: %s",
                    ntohs(from->sat_addr.s_net), from->sat_addr.s_node,
                    strerror(errno));
                return 0;
            }
        }

    /*FALL THROUGH*/

    case NBPOP_LKUP :

        /* do not send replies from the loopback interface */
        if (ap->ap_iface->i_flags & IFACE_LOOPBACK) {
            return 0;
        }

        /* Check if this is a query for a remote zone - if so, forward via AURP */
        if (nn.nn_zonelen > 0 && !(nn.nn_zonelen == 1 && *nn.nn_zone == '*')) {
            /* Look up the zone in our zone table */
            for (zt = ziptab; zt; zt = zt->zt_next) {
                if (zt->zt_len == nn.nn_zonelen && 
                    strndiacasecmp(zt->zt_name, nn.nn_zone, zt->zt_len) == 0) {
                    break;
                }
            }

            if (zt != NULL) {
                /* Check if any of the zone's routes are AURP routes */
                for (l = zt->zt_rt; l; l = l->l_next) {
                    rtmp = (struct rtmptab *)l->l_data;
                    
                    if (rtmp->rt_flags & RTMPTAB_AURP) {
                        /* This is a remote zone via AURP - forward the request */
                        unsigned char ddp_packet[ATP_BUFSIZ];
                        uint16_t dst_net = ntohs(rtmp->rt_firstnet);
                        uint16_t src_net = ntohs(from->sat_addr.s_net);
                        
                        int nbp_data_len = end - nbpop;
                        uint16_t total_len = 13 + nbp_data_len;
                        
                        /* Parse NBP tuple address (after 2-byte NBP header) */
                        unsigned char *tuple_start = (unsigned char *)(nbpop + 2);
                        uint16_t tuple_net = (tuple_start[0] << 8) | tuple_start[1];
                        uint8_t tuple_node = tuple_start[2];
                        uint8_t tuple_socket = tuple_start[3];
                        
                        uint16_t src_net_host = src_net;
                        uint8_t src_node = from->sat_addr.s_node;
                        uint8_t src_socket = from->sat_port;
                        
                        if (dst_net == 0 || total_len > sizeof(ddp_packet)) {
                            continue;
                        }
                        
                        /* Build extended DDP header */
                        int pos = 0;
                        uint16_t hop_len = (0 << 10) | (total_len & 0x3FF);
                        ddp_packet[pos++] = (hop_len >> 8) & 0xFF;
                        ddp_packet[pos++] = hop_len & 0xFF;
                        ddp_packet[pos++] = 0x00;  /* Checksum */
                        ddp_packet[pos++] = 0x00;
                        ddp_packet[pos++] = (dst_net >> 8) & 0xFF;
                        ddp_packet[pos++] = dst_net & 0xFF;
                        ddp_packet[pos++] = 0;     /* Router node */
                        ddp_packet[pos++] = 2;     /* NBP socket */
                        ddp_packet[pos++] = (src_net_host >> 8) & 0xFF;
                        ddp_packet[pos++] = src_net_host & 0xFF;
                        ddp_packet[pos++] = src_node;
                        ddp_packet[pos++] = src_socket;
                        ddp_packet[pos++] = DDPTYPE_NBP;
                        
                        /* Convert LkUp to FwdReq */
                        struct nbphdr nh_fwd;
                        memcpy(&nh_fwd, nbpop, SZ_NBPHDR);
                        nh_fwd.nh_op = NBPOP_FWD;
                        memcpy(ddp_packet + pos, &nh_fwd, SZ_NBPHDR);
                        pos += SZ_NBPHDR;
                        
                        /* Copy rest of NBP data (tuples) */
                        memcpy(ddp_packet + pos, nbpop + SZ_NBPHDR, nbp_data_len - SZ_NBPHDR);
                        
                        /* Forward through AURP tunnel */
                        LOG(log_warning, logtype_atalkd,
                            "nbp lkup: AURP fwd zone '%.*s' to net %u from %u.%u.%u (id=%u)",
                            nn.nn_zonelen, nn.nn_zone, dst_net,
                            src_net_host, src_node, src_socket, nh.nh_id);
                        aurp_track_nbp_request(nh.nh_id, tuple_net, tuple_node, tuple_socket);
                        if (aurp_send_data(dst_net, (char *)ddp_packet, total_len) < 0) {
                            LOG(log_debug, logtype_atalkd,
                                "nbp lkup: AURP forward to net %u failed", dst_net);
                        } else {
                            LOG(log_warning, logtype_atalkd,
                                "nbp lkup: sent FwdReq to net %u (tracked id=%u)", dst_net, nh.nh_id);
                        }
                        /* Continue to check other routes for this zone */
                    }
                }
            }
        }

        /* search our local data */
        n = i = 0;
        data = packet + 1 + SZ_NBPHDR;
        end = packet + sizeof(packet);

        for (ntab = nbptab; ntab; ntab = ntab->nt_next) {
            /* don't send out entries if we don't want to route. */
            if ((ap->ap_iface != ntab->nt_iface) &&
                    (ntab->nt_iface->i_flags & IFACE_ISROUTER) == 0) {
                continue;
            }

            if (nn.nn_objlen != 1 || *nn.nn_obj != '=') {
                if (ntab->nt_nve.nn_objlen != nn.nn_objlen ||
                        strndiacasecmp(ntab->nt_nve.nn_obj, nn.nn_obj,
                                       nn.nn_objlen)) {
                    continue;
                }
            }

            if (nn.nn_typelen != 1 || *nn.nn_type != '=') {
                if (ntab->nt_nve.nn_typelen != nn.nn_typelen ||
                        strndiacasecmp(ntab->nt_nve.nn_type, nn.nn_type,
                                       nn.nn_typelen)) {
                    continue;
                }
            }

            if (nn.nn_zonelen != 0 &&
                    (nn.nn_zonelen != 1 || *nn.nn_zone != '*')) {
                if (ntab->nt_nve.nn_zonelen == 0 ||
                        (ntab->nt_nve.nn_zonelen == 1 &&
                         *ntab->nt_nve.nn_zone == '*')) {
                    if (interfaces->i_next->i_rt->rt_zt) {
                        zt = (struct ziptab *)interfaces->i_next->i_rt->
                             rt_zt->l_data;

                        if (zt->zt_len != nn.nn_zonelen ||
                                strndiacasecmp(zt->zt_name, nn.nn_zone,
                                               zt->zt_len)) {
                            continue;
                        }
                    }
                } else {
                    if (ntab->nt_nve.nn_zonelen != nn.nn_zonelen ||
                            strndiacasecmp(ntab->nt_nve.nn_zone, nn.nn_zone,
                                           nn.nn_zonelen)) {
                        continue;
                    }
                }
            }

            /*
             * Another tuple won't fit. Send what we've already
             * got, and start the next packet.
             */
            if (n > 14 || data + SZ_NBPTUPLE + 3 + ntab->nt_nve.nn_objlen +
                    ntab->nt_nve.nn_typelen + ntab->nt_nve.nn_zonelen > end) {
                nh.nh_op = NBPOP_LKUPREPLY;
                nh.nh_cnt = n;
                cc = data - packet;
                data = packet;
                *data++ = DDPTYPE_NBP;
                memcpy(data, &nh, SZ_NBPHDR);

                if (sendto(ap->ap_fd, packet, cc, 0,
                           (struct sockaddr *)&nn.nn_sat,
                           sizeof(struct sockaddr_at)) < 0) {
                    LOG(log_error, logtype_atalkd, "nbp lkup sendto %u.%u: %s",
                        ntohs(nn.nn_sat.sat_addr.s_net),
                        nn.nn_sat.sat_addr.s_node,
                        strerror(errno));
                    return 0;
                }

                n = 0;
                data = packet + 1 + SZ_NBPHDR;
                end = packet + sizeof(packet);
            }

            nt.nt_net = ntab->nt_nve.nn_sat.sat_addr.s_net;
            nt.nt_node = ntab->nt_nve.nn_sat.sat_addr.s_node;
            nt.nt_port = ntab->nt_nve.nn_sat.sat_port;
            /*
             * Right now, we'll just give each name a unique enum.  In
             * the future, we might need to actually assign and save
             * an enum, based on the associated address.  For the moment,
             * the enums will be unique and constant, since the order
             * is fixed.
             */
            nt.nt_enum = i++;
            memcpy(data, &nt, SZ_NBPTUPLE);
            data += SZ_NBPTUPLE;
            *data++ = ntab->nt_nve.nn_objlen;
            memcpy(data, ntab->nt_nve.nn_obj, ntab->nt_nve.nn_objlen);
            data += ntab->nt_nve.nn_objlen;
            *data++ = ntab->nt_nve.nn_typelen;
            memcpy(data, ntab->nt_nve.nn_type, ntab->nt_nve.nn_typelen);
            data += ntab->nt_nve.nn_typelen;

            /*
             * Macs won't see something with a zone of 0 length.  We
             * will always return '*' instead.  Perhaps we should
             * unconditionally return the real zone?
             */
            if (ntab->nt_nve.nn_zonelen) {
                *data++ = ntab->nt_nve.nn_zonelen;
                memcpy(data, ntab->nt_nve.nn_zone, ntab->nt_nve.nn_zonelen);
                data += ntab->nt_nve.nn_zonelen;
            } else {
                *data++ = 1;
                *data++ = '*';
            }

            n++;
        }

        if (n != 0) {
            nh.nh_op = NBPOP_LKUPREPLY;
            nh.nh_cnt = n;
            cc = data - packet;
            data = packet;
            *data++ = DDPTYPE_NBP;
            memcpy(data, &nh, SZ_NBPHDR);

            if (sendto(ap->ap_fd, packet, cc, 0,
                       (struct sockaddr *)&nn.nn_sat,
                       sizeof(struct sockaddr_at)) < 0) {
                LOG(log_error, logtype_atalkd, "nbp lkup sendto %u.%u: %s",
                    ntohs(nn.nn_sat.sat_addr.s_net),
                    nn.nn_sat.sat_addr.s_node,
                    strerror(errno));
                return 0;
            }
        }

        break;

    case NBPOP_LKUPREPLY :
    case NBPOP_FWDREPLY :
        /*
         * This is a Lookup Reply or Forward Reply, typically from a remote AFP
         * server responding to our NBP FwdReq. The reply is addressed to us
         * (the router) because we used our address as the DDP source in the FwdReq.
         * 
         * We need to forward this reply to the original requester (the Mac).
         * The original requester's address is in the NBP tuple's reply-to field.
         */
        LOG(log_debug, logtype_atalkd,
            "nbp_packet: NBP reply received (op=%u) from %u.%u.%u id=%u count=%u len=%d",
            nh.nh_op,
            ntohs(from->sat_addr.s_net), from->sat_addr.s_node, from->sat_port,
            nh.nh_id, nh.nh_cnt, len);
        break;

    default :
        LOG(log_info, logtype_atalkd, "nbp_packet: bad op (%d)", nh.nh_op);
        return 1;
    }

    return 0;
}
