/**
 * @file ml_peer_table.h
 * @brief The peer table's state, and what a full map, a name and a full
 *        table do to it: pure functions, built and tested on the host too
 *
 * No ESP-IDF call here: host_test/ builds these with the host's compiler.
 * The table itself is owned by the WG manager task.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "microlink.h"

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
 * @return true: the map is applied, complete or not — names then resolve
 *         among the peers it added, never among cached ones
 *
 * The caller drops what ml_peers_map_drops selects — its WireGuard peers —
 * before calling this.
 */
bool ml_peers_map_end(ml_peer_t *peers, int *count, bool complete);

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

/**
 * @brief Whether a peer is one of the kept ones (microlink_keep_peers)
 * @param keep The kept peers
 * @param keep_count How many
 * @param own_domain As ml_peers_resolve takes it
 * @param vpn_ip The peer's address
 * @param hostname Its name
 * @param named Its name is the map's, whole: a cached peer's name and a cut
 *        one stand for no kept name
 *
 * A peer kept by address is the peer at that address. A peer kept by name
 * is the peer ml_peers_resolve would find that name at: its full name, or
 * its first label within the board's own tailnet.
 */
bool ml_keep_has(const microlink_keep_t *keep, int keep_count, const char *own_domain,
                 uint32_t vpn_ip, const char *hostname, bool named);

/**
 * @brief The slot a peer new to the table takes
 * @param peers The table
 * @param slots How many slots it has, in use or not
 * @param keep The kept peers
 * @param keep_count How many
 * @param own_domain As ml_peers_resolve takes it
 * @param kept Whether the new peer is a kept one (ml_keep_has)
 * @return The first free slot. With none free, and only for a kept peer,
 *         the slot of a peer not kept, which the caller evicts: one the
 *         last full map has not listed (a cached peer, a peer of an earlier
 *         map, or one the map being applied has not come to) before one it
 *         has, and among those the one whose last pong or last packet sent
 *         is the oldest — the first of several as old. Else -1: the peer is
 *         left out.
 */
int ml_peers_slot(const ml_peer_t *peers, int slots, const microlink_keep_t *keep,
                  int keep_count, const char *own_domain, bool kept);

/**
 * @brief Whether a set of peers is one microlink_keep_peers takes: at most
 *        ML_KEEP_PEERS_MAX, each with an address, or a name that is not
 *        empty and ends within its field
 */
bool ml_keep_valid(const microlink_keep_t *peers, int count);

/**
 * @brief Replace the kept peers, in place, and say whether the full map
 *        must be fetched for them
 * @param keep The kept peers, ML_KEEP_PEERS_MAX entries: rewritten, each an
 *        address, or a name and nothing after it; the rest empty
 * @param keep_count How many: rewritten
 * @param peers The new set, valid (ml_keep_valid), and not `keep` itself
 * @param count How many
 * @param table The peer table
 * @param table_count Its count of slots in use
 * @param own_domain As ml_peers_resolve takes it
 * @param map_applied A full map was applied; until one is, the first map is
 *        still to come, and brings every kept peer it lists
 * @return true when the new set names a peer the old one did not — by that
 *         address, or by that name in any case — and the table holds no
 *         such peer: an address no peer of it has, or a name
 *         ml_peers_resolve finds at none. Such a peer comes with a full map
 *         only. The same set named again asks for nothing, and neither does
 *         a peer that was named and missing before: one name that stands
 *         for no peer of the tailnet does not make every later call a fetch.
 */
bool ml_keep_replace(microlink_keep_t *keep, int *keep_count, const microlink_keep_t *peers,
                     int count, const ml_peer_t *table, int table_count,
                     const char *own_domain, bool map_applied);
