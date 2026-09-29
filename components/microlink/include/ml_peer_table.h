/**
 * @file ml_peer_table.h
 * @brief The peer table's state, and what a full map and a name do to it:
 *        pure functions, built and tested on the host too
 *
 * No ESP-IDF call here: host_test/ builds these with the host's compiler.
 * The table itself is owned by the WG manager task.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ML_MAX_ENDPOINTS        8

/* ============================================================================
 * Peer State (owned exclusively by wg_mgr task)
 * ========================================================================== */

typedef struct {
    /* Identity */
    uint32_t vpn_ip;
    uint8_t public_key[32];
    uint8_t disco_key[32];
    char hostname[64];
    bool active;
    /* Restored from the NVS cache at start, its name cut to 6 characters, and
     * not yet in a map: never a MagicDNS answer */
    bool cached;
    /* In the full map being applied */
    bool in_map;
    /* Its name from the map did not fit whole: cut, never a MagicDNS answer */
    bool name_cut;

    /* Endpoints */
    struct {
        uint32_t ip;
        uint16_t port;
        bool is_ipv6;
    } endpoints[ML_MAX_ENDPOINTS];
    int endpoint_count;
    uint16_t derp_region;

    /* DISCO state (rate limiting) */
    uint64_t last_ping_sent_ms;     /* Last DISCO ping we sent */
    uint64_t last_pong_recv_ms;     /* Last DISCO pong we received */
    uint64_t trust_until_ms;        /* Direct path trusted until */
    uint64_t last_send_ms;          /* Last data sent to this peer */
    uint64_t last_upgrade_ms;       /* Last path upgrade attempt */

    /* Best direct path */
    uint32_t best_ip;
    uint16_t best_port;
    bool has_direct_path;

    /* WireGuard peer index in wireguard-lwip */
    int wg_peer_index;

    /* On-demand handshake: tried once on first DISCO direct path discovery */
    bool tried_initial_handshake;
} ml_peer_t;

/**
 * @brief A node's MagicDNS name ("host.tail1234.ts.net."), its trailing dot
 *        taken off, into `out`
 * @param out Where it goes, NUL-terminated
 * @param size Its size
 * @param fqdn The name as the map gives it (may be NULL: an empty name)
 * @return true when it fits whole; false when `out` holds only as much of it
 *         as fits — a cut name, which must answer for nothing
 */
bool ml_name_from_fqdn(char *out, size_t size, const char *fqdn);

/**
 * @brief The domain of a node's MagicDNS name: what follows its first label,
 *        the trailing dot taken off ("tail1234.ts.net")
 * @return true when there is one and it fits whole; else `out` is empty
 */
bool ml_name_domain(char *out, size_t size, const char *fqdn);

/**
 * @brief Forget the peer at `idx`: no longer active nor cached, and the
 *        table's count cut past the last active peer
 * @param peers The table
 * @param count Its count of slots in use, updated
 * @param idx The peer's slot
 */
void ml_peers_forget(ml_peer_t *peers, int *count, int idx);

/**
 * @brief A full map begins: no peer is in it yet
 */
void ml_peers_map_begin(ml_peer_t *peers, int count);

/**
 * @brief Whether a full map's end drops this peer
 * @param complete Every peer of the map was queued as an ADD
 *
 * An active peer the map did not contain — a peer of an earlier map, or one
 * restored from the NVS cache — is dropped, but only when the map is
 * complete: a map cut short drops nothing.
 */
bool ml_peers_map_drops(const ml_peer_t *peer, bool complete);

/**
 * @brief A full map ends: every peer ml_peers_map_drops says it drops is
 *        forgotten
 * @param peers The table
 * @param count Its count of slots in use, updated
 * @param complete Every peer of the map was queued as an ADD
 * @param drop Called with each dropped peer's slot before it is forgotten;
 *        may be NULL (the caller then drops what ml_peers_map_drops selects
 *        before calling this)
 * @param ctx Passed to `drop`
 * @return true: the map is applied, complete or not — names then resolve
 *         among the peers it added, never among cached ones
 */
bool ml_peers_map_end(ml_peer_t *peers, int *count, bool complete,
                      void (*drop)(void *ctx, int idx), void *ctx);

/**
 * @brief The address a name resolves to among the peers, 0 when none
 * @param peers The table
 * @param count Its count of slots in use
 * @param own_domain The board's own tailnet domain ("tail1234.ts.net"),
 *        empty (or NULL) while not known
 * @param name A peer's full name, or its first label
 *
 * A peer's full name ("host.tail1234.ts.net", any case) always resolves; its
 * first label ("host") only when the rest of its name is `own_domain`, so a
 * node shared in from another tailnet is found by its full name alone, and
 * while the board's own domain is not known no first label resolves. A
 * peer's name with no domain ("host", "host.") never resolves, not even
 * whole: nothing says which tailnet it is in. A
 * cached peer, and one whose name did not fit whole, never resolves: its
 * name is cut, and could stand for another.
 */
uint32_t ml_peers_resolve(const ml_peer_t *peers, int count, const char *own_domain,
                          const char *name);
