/*
 * Host tests of the peer table's pure logic (ml_peer_table.c): what a full
 * map's BEGIN and END do to it, and which peer a name resolves to.
 * Run by run.sh with the host's C compiler.
 */
#include <stdio.h>
#include <string.h>

#include "ml_peer_table.h"

static int failures;

#define CHECK(cond, ...)                                     \
    do {                                                     \
        if (!(cond)) {                                       \
            failures++;                                      \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);      \
            printf(__VA_ARGS__);                             \
            printf("\n");                                    \
        }                                                    \
    } while (0)

#define PEERS 8

static ml_peer_t peers[PEERS];
static int count;

static void peer(int idx, const char *name, uint32_t ip, bool cached) {
    memset(&peers[idx], 0, sizeof peers[idx]);
    peers[idx].active = true;
    peers[idx].cached = cached;
    peers[idx].vpn_ip = ip;
    strncpy(peers[idx].hostname, name, sizeof peers[idx].hostname - 1);
    if (idx >= count) count = idx + 1;
}

static void reset(void) {
    memset(peers, 0, sizeof peers);
    count = 0;
}

/* The slots a map's end dropped, in order */
static int dropped[PEERS];
static int drops;

static void drop(void *ctx, int idx) {
    CHECK(ctx == &drops, "drop's context");
    CHECK(peers[idx].active, "slot %d dropped while still active", idx);
    dropped[drops++] = idx;
}

/* What the WG manager does with a full map: BEGIN, an ADD per peer of it
 * (marking it in the map), END; true once the map is applied */
static bool apply_map(const int *in_map, int n, bool complete) {
    ml_peers_map_begin(peers, count);
    for (int i = 0; i < n; i++) {
        peers[in_map[i]].in_map = true;
        peers[in_map[i]].cached = false;
    }
    drops = 0;
    return ml_peers_map_end(peers, &count, complete, drop, &drops);
}

static void full_maps(void) {
    /* A complete map drops the peers it lacks: cached ones and an earlier map's */
    reset();
    peer(0, "a.tail1.ts.net", 1, false);
    peer(1, "cached", 2, true);
    peer(2, "c.tail1.ts.net", 3, false);
    peer(3, "d.tail1.ts.net", 4, false);
    const int keep[] = {0, 2};
    CHECK(apply_map(keep, 2, true), "complete map applied");
    CHECK(drops == 2 && dropped[0] == 1 && dropped[1] == 3, "dropped slots 1 and 3: %d", drops);
    CHECK(peers[0].active && peers[2].active, "kept");
    CHECK(!peers[1].active && !peers[1].cached, "cached peer dropped");
    CHECK(!peers[3].active, "earlier map's peer dropped");
    CHECK(count == 3, "count cut past the last active peer: %d", count);

    /* A map cut short drops nothing, cached peers included */
    reset();
    peer(0, "a.tail1.ts.net", 1, false);
    peer(1, "cached", 2, true);
    peer(2, "c.tail1.ts.net", 3, false);
    const int some[] = {0};
    CHECK(apply_map(some, 1, false), "a map cut short is applied too");
    CHECK(drops == 0, "incomplete map: %d dropped", drops);
    CHECK(peers[0].active && peers[1].active && peers[2].active, "incomplete map drops nothing");
    CHECK(peers[1].cached, "a cached peer stays cached");
    CHECK(count == 3, "count kept: %d", count);

    /* A complete, empty map drops every peer, the last slots too as the
     * count shrinks under it */
    CHECK(apply_map(NULL, 0, true), "empty map applied");
    CHECK(drops == 3, "empty map: %d dropped", drops);
    CHECK(count == 0, "empty map: count %d", count);
    for (int i = 0; i < PEERS; i++) {
        CHECK(!peers[i].active, "empty map: peer %d dropped", i);
    }

    /* BEGIN clears the mark an earlier map left */
    reset();
    peer(0, "a.tail1.ts.net", 1, false);
    peers[0].in_map = true;
    ml_peers_map_begin(peers, count);
    CHECK(!peers[0].in_map, "begin clears in_map");
    CHECK(ml_peers_map_drops(&peers[0], true), "not in the map: dropped when complete");
    CHECK(!ml_peers_map_drops(&peers[0], false), "not dropped when incomplete");
    peers[0].active = false;
    CHECK(!ml_peers_map_drops(&peers[0], true), "an inactive slot is not dropped again");

    /* Forgetting a slot in the middle leaves the count; the last cuts it past
     * every inactive slot before it */
    reset();
    peer(0, "a", 1, false);
    peer(1, "b", 2, false);
    peer(2, "c", 3, false);
    ml_peers_forget(peers, &count, 1);
    CHECK(count == 3, "middle: count %d", count);
    ml_peers_forget(peers, &count, 2);
    CHECK(count == 1, "last: count %d", count);
}

static void names(void) {
    reset();
    peer(0, "control-host.tail1.ts.net", 0x64400001, false);
    peer(1, "contro", 0x64400002, true);  /* cached: name cut to 6 */
    peer(2, "Laptop.tail1.ts.net", 0x64400003, false);
    peer(3, "nodot", 0x64400004, false);
    CHECK(ml_peers_resolve(peers, count, "control-host.tail1.ts.net") == 0x64400001, "full name");
    CHECK(ml_peers_resolve(peers, count, "CONTROL-HOST.tail1.ts.net") == 0x64400001, "any case");
    CHECK(ml_peers_resolve(peers, count, "control-host") == 0x64400001, "first label");
    CHECK(ml_peers_resolve(peers, count, "laptop") == 0x64400003, "first label, any case");
    CHECK(ml_peers_resolve(peers, count, "nodot") == 0x64400004, "a name without a dot");
    /* A cached peer never answers, not even by its own cut name */
    CHECK(ml_peers_resolve(peers, count, "contro") == 0, "cached peer");
    /* A prefix that is not a whole label, or a longer name, is not a match */
    CHECK(ml_peers_resolve(peers, count, "control") == 0, "part of a label");
    CHECK(ml_peers_resolve(peers, count, "control-host.tail1") == 0, "part of the name");
    CHECK(ml_peers_resolve(peers, count, "control-host.tail1.ts.net.x") == 0, "longer name");
    CHECK(ml_peers_resolve(peers, count, "") == 0, "empty");
    CHECK(ml_peers_resolve(peers, count, NULL) == 0, "none");
    /* The map replaces the cached peer: then it answers by its whole name */
    peer(1, "contro-box.tail1.ts.net", 0x64400002, false);
    CHECK(ml_peers_resolve(peers, count, "contro-box") == 0x64400002, "no longer cached");
    CHECK(ml_peers_resolve(peers, count, "contro") == 0, "and not by the cut name");
    /* An inactive slot never answers */
    peers[2].active = false;
    CHECK(ml_peers_resolve(peers, count, "laptop") == 0, "inactive");
}

int main(void) {
    full_maps();
    names();
    if (failures) {
        printf("%d failed\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
