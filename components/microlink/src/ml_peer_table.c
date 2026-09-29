/**
 * @file ml_peer_table.c
 * @brief The peer table's pure logic (see ml_peer_table.h)
 */

#include "ml_peer_table.h"

#include <string.h>

bool ml_name_from_fqdn(char *out, size_t size, const char *fqdn) {
    if (size == 0) return false;
    size_t len = fqdn ? strlen(fqdn) : 0;
    if (len > 0 && fqdn[len - 1] == '.') len--;
    const bool whole = len < size;
    const size_t n = whole ? len : size - 1;
    if (n > 0) memcpy(out, fqdn, n);
    out[n] = '\0';
    return whole;
}

bool ml_name_domain(char *out, size_t size, const char *fqdn) {
    if (size == 0) return false;
    const char *dot = fqdn ? strchr(fqdn, '.') : NULL;
    if (!dot || !ml_name_from_fqdn(out, size, dot + 1) || out[0] == '\0') {
        out[0] = '\0';
        return false;
    }
    return true;
}

void ml_peers_forget(ml_peer_t *peers, int *count, int idx) {
    peers[idx].active = false;
    peers[idx].cached = false;
    while (*count > 0 && !peers[*count - 1].active) {
        (*count)--;
    }
}

void ml_peers_map_begin(ml_peer_t *peers, int count) {
    for (int i = 0; i < count; i++) {
        peers[i].in_map = false;
    }
}

bool ml_peers_map_drops(const ml_peer_t *peer, bool complete) {
    return complete && peer->active && !peer->in_map;
}

bool ml_peers_map_end(ml_peer_t *peers, int *count, bool complete,
                      void (*drop)(void *ctx, int idx), void *ctx) {
    for (int i = 0; i < *count; i++) {
        if (ml_peers_map_drops(&peers[i], complete)) {
            if (drop) drop(ctx, i);
            ml_peers_forget(peers, count, i);
        }
    }
    return true;
}

/* Whether the first `len` characters of a and b match, ignoring ASCII case,
 * a NUL in both ending the match early */
static bool same_name(const char *a, const char *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
        if (ca == '\0') return true;
    }
    return true;
}

uint32_t ml_peers_resolve(const ml_peer_t *peers, int count, const char *own_domain,
                          const char *name) {
    if (!name || name[0] == '\0') return 0;
    const size_t name_len = strlen(name);
    for (int i = 0; i < count; i++) {
        const ml_peer_t *p = &peers[i];
        /* A cached peer's name is cut, and so is one that did not fit: it
         * could stand for another peer */
        if (!p->active || p->cached || p->name_cut) continue;

        /* A name with no domain cannot be placed in the board's own tailnet
         * or in another: it answers for nothing, by itself or as a label */
        const char *dot = strchr(p->hostname, '.');
        if (!dot || dot[1] == '\0') continue;

        /* 1. Its full name, any case */
        if (same_name(p->hostname, name, sizeof(p->hostname))) {
            return p->vpn_ip;
        }

        /* 2. Its first label ("npc1" for "npc1.tail12345.ts.net"), when the
         * rest of its name is the board's own tailnet: never a node shared in */
        const size_t short_len = (size_t)(dot - p->hostname);
        if (own_domain && own_domain[0] != '\0' && name_len == short_len &&
            same_name(p->hostname, name, short_len) &&
            same_name(dot + 1, own_domain, sizeof(p->hostname))) {
            return p->vpn_ip;
        }
    }
    return 0;
}
