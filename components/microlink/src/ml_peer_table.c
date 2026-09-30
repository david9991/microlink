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

bool ml_peers_map_end(ml_peer_t *peers, int *count, bool complete) {
    for (int i = 0; i < *count; i++) {
        if (ml_peers_map_drops(&peers[i], complete)) {
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

/* Whether a peer's whole name `hostname` answers to `name` (`name_len`
 * characters): the rule ml_peers_resolve documents */
static bool name_is(const char *hostname, size_t hostname_size, const char *own_domain,
                    const char *name, size_t name_len) {
    /* A name with no domain cannot be placed in the board's own tailnet
     * or in another: it answers for nothing, by itself or as a label */
    const char *dot = strchr(hostname, '.');
    if (!dot || dot[1] == '\0') return false;

    /* 1. Its full name, any case */
    if (same_name(hostname, name, hostname_size)) return true;

    /* 2. Its first label ("npc1" for "npc1.tail12345.ts.net"), when the
     * rest of its name is the board's own tailnet: never a node shared in */
    const size_t short_len = (size_t)(dot - hostname);
    return own_domain && own_domain[0] != '\0' && name_len == short_len &&
           same_name(hostname, name, short_len) &&
           same_name(dot + 1, own_domain, hostname_size);
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
        if (name_is(p->hostname, sizeof(p->hostname), own_domain, name, name_len)) {
            return p->vpn_ip;
        }
    }
    return 0;
}

bool ml_keep_has(const microlink_keep_t *keep, int keep_count, const char *own_domain,
                 uint32_t vpn_ip, const char *hostname, bool named) {
    for (int i = 0; i < keep_count; i++) {
        const microlink_keep_t *k = &keep[i];
        if (k->vpn_ip != 0) {
            if (k->vpn_ip == vpn_ip) return true;
        } else if (named && k->name[0] != '\0' &&
                   name_is(hostname, sizeof(((ml_peer_t *)0)->hostname), own_domain, k->name,
                           strlen(k->name))) {
            return true;
        }
    }
    return false;
}

/* When the peer last answered a ping or was sent a packet */
static uint64_t last_activity_ms(const ml_peer_t *p) {
    return p->last_pong_recv_ms > p->last_send_ms ? p->last_pong_recv_ms : p->last_send_ms;
}

int ml_peers_slot(const ml_peer_t *peers, int slots, const microlink_keep_t *keep,
                  int keep_count, const char *own_domain, bool kept) {
    for (int i = 0; i < slots; i++) {
        if (!peers[i].active) return i;
    }
    if (!kept) return -1;
    int gives_way = -1;
    for (int i = 0; i < slots; i++) {
        const ml_peer_t *p = &peers[i];
        if (ml_keep_has(keep, keep_count, own_domain, p->vpn_ip, p->hostname,
                        !p->cached && !p->name_cut)) {
            continue;
        }
        if (gives_way < 0) {
            gives_way = i;
            continue;
        }
        const ml_peer_t *g = &peers[gives_way];
        if (p->in_map != g->in_map ? !p->in_map : last_activity_ms(p) < last_activity_ms(g)) {
            gives_way = i;
        }
    }
    return gives_way;
}

bool ml_keep_valid(const microlink_keep_t *peers, int count) {
    if (count < 0 || count > ML_KEEP_PEERS_MAX || (count > 0 && !peers)) return false;
    for (int i = 0; i < count; i++) {
        if (peers[i].vpn_ip != 0) continue;
        const void *end = memchr(peers[i].name, '\0', sizeof(peers[i].name));
        if (!end || end == peers[i].name) return false;
    }
    return true;
}

/* Whether the table holds the peer `k` names: a peer at its address, or the
 * one its name resolves to */
static bool keep_held(const ml_peer_t *peers, int count, const char *own_domain,
                      const microlink_keep_t *k) {
    if (k->vpn_ip == 0) return ml_peers_resolve(peers, count, own_domain, k->name) != 0;
    for (int i = 0; i < count; i++) {
        if (peers[i].active && peers[i].vpn_ip == k->vpn_ip) return true;
    }
    return false;
}

/* Whether two entries name a peer the same way: the same address, or the
 * same name in any case */
static bool keep_same(const microlink_keep_t *a, const microlink_keep_t *b) {
    if (a->vpn_ip != 0 || b->vpn_ip != 0) return a->vpn_ip == b->vpn_ip;
    return same_name(a->name, b->name, sizeof(a->name));
}

bool ml_keep_replace(microlink_keep_t *keep, int *keep_count, const microlink_keep_t *peers,
                     int count, const ml_peer_t *table, int table_count,
                     const char *own_domain, bool map_applied) {
    /* What the new set names that the old one did not, and the table lacks:
     * read before the old set is written over */
    bool fetch = false;
    for (int i = 0; i < count && map_applied && !fetch; i++) {
        bool named_before = false;
        for (int j = 0; j < *keep_count && !named_before; j++) {
            named_before = keep_same(&peers[i], &keep[j]);
        }
        fetch = !named_before && !keep_held(table, table_count, own_domain, &peers[i]);
    }
    /* Each entry as it is kept: an address, or a name and nothing after it */
    for (int i = 0; i < ML_KEEP_PEERS_MAX; i++) {
        const uint32_t vpn_ip = i < count ? peers[i].vpn_ip : 0;
        const char *name = i < count && vpn_ip == 0 ? peers[i].name : "";
        if (keep[i].vpn_ip == vpn_ip && strcmp(keep[i].name, name) == 0) continue;
        memset(&keep[i], 0, sizeof(keep[i]));
        keep[i].vpn_ip = vpn_ip;
        strcpy(keep[i].name, name);
    }
    *keep_count = count;
    return fetch;
}
