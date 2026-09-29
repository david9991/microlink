/**
 * @file ml_derp_node.c
 * @brief Which of a region's DERP nodes is dialled, and how (see ml_derp_node.h)
 */

#include "ml_derp_node.h"

#include <string.h>

static bool addr_none(const char *addr) {
    return strcmp(addr, "none") == 0;
}

/* An address to dial: not empty, and not "none" */
static bool addr_given(const char *addr) {
    return addr[0] != '\0' && !addr_none(addr);
}

/* An ended string into a buffer, cut to fit */
static void copy_str(char *dst, size_t size, const char *src) {
    size_t n = strlen(src);
    if (n > size - 1) n = size - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

int ml_derp_pick(const ml_derp_node_t *nodes, int count, bool ipv6_alone,
                 ml_derp_dial_t *out) {
    for (int i = 0; i < count; i++) {
        /* The node is copied, each field ended, before anything is decided:
         * what is decided on is what is dialled */
        ml_derp_node_t n;
        memcpy(&n, &nodes[i], sizeof(n));
        n.hostname[sizeof(n.hostname) - 1] = '\0';
        n.cert_name[sizeof(n.cert_name) - 1] = '\0';
        n.ipv4[sizeof(n.ipv4) - 1] = '\0';
        n.ipv6[sizeof(n.ipv6) - 1] = '\0';
        if (n.stun_only || n.hostname[0] == '\0') continue;

        const char *dial = n.hostname;
        ml_derp_family_t family;
        if (addr_given(n.ipv4)) {
            dial = n.ipv4;
            family = ML_DERP_IPV4;
        } else if (addr_none(n.ipv4)) {
            if (addr_none(n.ipv6) || !ipv6_alone) continue;
            if (addr_given(n.ipv6)) dial = n.ipv6;
            family = ML_DERP_IPV6;
        } else {
            family = addr_none(n.ipv6) ? ML_DERP_IPV4 : ML_DERP_ANY;
        }

        copy_str(out->host, sizeof(out->host), n.hostname);
        copy_str(out->dial, sizeof(out->dial), dial);
        copy_str(out->cert, sizeof(out->cert), n.cert_name[0] ? n.cert_name : n.hostname);
        out->family = family;
        out->port = n.derp_port;
        return i;
    }
    return -1;
}
