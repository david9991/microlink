/*
 * Host tests of the peer table's pure logic (ml_peer_table.c): what a full
 * map's BEGIN and END do to it, and which peer a name resolves to.
 * Run by run.sh with the host's C compiler.
 */
#include <ctype.h>
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
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

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

/* The board's own tailnet */
static const char *own = "tail1.ts.net";

static uint32_t resolve(const char *name) {
    return ml_peers_resolve(peers, count, own, name);
}

static void names(void) {
    reset();
    peer(0, "control-host.tail1.ts.net", 0x64400001, false);
    peer(1, "contro", 0x64400002, true);  /* cached: name cut to 6 */
    peer(2, "Laptop.tail1.ts.net", 0x64400003, false);
    peer(3, "nodot", 0x64400004, false);
    CHECK(resolve("control-host.tail1.ts.net") == 0x64400001, "full name");
    CHECK(resolve("CONTROL-HOST.tail1.ts.net") == 0x64400001, "any case");
    CHECK(resolve("control-host") == 0x64400001, "first label");
    CHECK(resolve("laptop") == 0x64400003, "first label, any case");
    /* A name with no domain answers for nothing, not even itself */
    CHECK(resolve("nodot") == 0, "a name without a dot");
    /* A cached peer never answers, not even by its own cut name */
    CHECK(resolve("contro") == 0, "cached peer");
    /* A prefix that is not a whole label, or a longer name, is not a match */
    CHECK(resolve("control") == 0, "part of a label");
    CHECK(resolve("control-host.tail1") == 0, "part of the name");
    CHECK(resolve("control-host.tail1.ts.net.x") == 0, "longer name");
    CHECK(resolve("") == 0, "empty");
    CHECK(resolve(NULL) == 0, "none");
    /* The map replaces the cached peer: then it answers by its whole name */
    peer(1, "contro-box.tail1.ts.net", 0x64400002, false);
    CHECK(resolve("contro-box") == 0x64400002, "no longer cached");
    CHECK(resolve("contro") == 0, "and not by the cut name");
    /* An inactive slot never answers */
    peers[2].active = false;
    CHECK(resolve("laptop") == 0, "inactive");

    /* A node shared in from another tailnet, listed first, with the same
     * first label as one of the board's own, and one with a label of its
     * own: a first label never finds them, their full names do */
    reset();
    peer(0, "control-host.other.ts.net", 0x64500001, false);
    peer(1, "control-host.tail1.ts.net", 0x64400001, false);
    peer(2, "shared-box.other.ts.net", 0x64500002, false);
    peer(3, "evil.tail1.ts.net.other.ts.net", 0x64500003, false);
    CHECK(resolve("control-host") == 0x64400001, "first label: the board's own tailnet's node");
    CHECK(resolve("shared-box") == 0, "first label of a shared-in node");
    CHECK(resolve("SHARED-BOX") == 0, "first label of a shared-in node, any case");
    CHECK(resolve("shared-box.other.ts.net") == 0x64500002, "full name of a shared-in node");
    CHECK(resolve("control-host.other.ts.net") == 0x64500001, "full name, the other tailnet's");
    CHECK(resolve("evil") == 0, "a domain that only starts with the board's own");
    /* The board's domain in another case still is the board's */
    own = "TAIL1.ts.net";
    CHECK(resolve("control-host") == 0x64400001, "own domain, any case");
    /* Until the board knows its own domain, no first label resolves */
    own = "";
    CHECK(resolve("control-host") == 0, "own domain unknown");
    CHECK(resolve("control-host.tail1.ts.net") == 0x64400001, "full name, own domain unknown");
    own = NULL;
    CHECK(resolve("control-host") == 0, "no own domain");
    own = "tail1.ts.net";

    /* A name that did not fit whole answers for nothing, not even for
     * what was kept of it */
    reset();
    peer(0, "a-rather-long-host-name-that-was-cut.tail1.ts.net", 0x64400009, false);
    peers[0].name_cut = true;
    CHECK(resolve("a-rather-long-host-name-that-was-cut.tail1.ts.net") == 0, "cut: full name");
    CHECK(resolve("a-rather-long-host-name-that-was-cut") == 0, "cut: first label");
}

static void fqdns(void) {
    char out[16];
    CHECK(ml_name_from_fqdn(out, sizeof out, "a.tail1.ts.net.") && strcmp(out, "a.tail1.ts.net") == 0,
          "trailing dot off: %s", out);
    CHECK(ml_name_from_fqdn(out, sizeof out, "a.tail1.ts.net") && strcmp(out, "a.tail1.ts.net") == 0,
          "no trailing dot: %s", out);
    /* 15 characters fit a 16-byte buffer, the dot not counted */
    CHECK(ml_name_from_fqdn(out, sizeof out, "abcdefghijklmno.") && strcmp(out, "abcdefghijklmno") == 0,
          "exactly full: %s", out);
    CHECK(!ml_name_from_fqdn(out, sizeof out, "abcdefghijklmnop.") && strcmp(out, "abcdefghijklmno") == 0,
          "one too long: cut, and said so: %s", out);
    CHECK(ml_name_from_fqdn(out, sizeof out, "") && out[0] == '\0', "empty");
    CHECK(ml_name_from_fqdn(out, sizeof out, ".") && out[0] == '\0', "a lone dot");
    CHECK(ml_name_from_fqdn(out, sizeof out, NULL) && out[0] == '\0', "none");
    CHECK(!ml_name_from_fqdn(out, 0, "a"), "no room at all");

    CHECK(ml_name_domain(out, sizeof out, "host.tail1.ts.net.") && strcmp(out, "tail1.ts.net") == 0,
          "domain: %s", out);
    CHECK(ml_name_domain(out, sizeof out, "host.tail1.ts.net") && strcmp(out, "tail1.ts.net") == 0,
          "domain, no trailing dot: %s", out);
    CHECK(!ml_name_domain(out, sizeof out, "host") && out[0] == '\0', "no dot: no domain");
    CHECK(!ml_name_domain(out, sizeof out, "host.") && out[0] == '\0', "only the trailing dot");
    CHECK(!ml_name_domain(out, sizeof out, "host..") && out[0] == '\0', "an empty domain");
    CHECK(!ml_name_domain(out, sizeof out, "h.a-very-long-tailnet.ts.net") && out[0] == '\0',
          "a domain that does not fit is none, not a cut one");
    CHECK(!ml_name_domain(out, sizeof out, NULL) && out[0] == '\0', "none");
}

/* ---- random tables against a reference model ---------------------------- */

static uint32_t rng = 0x9e3779b9;

static uint32_t next(void) {
    rng ^= rng << 13;
    rng ^= rng >> 17;
    rng ^= rng << 5;
    return rng;
}

static const char *pick(const char *const *from, size_t n) {
    return from[next() % n];
}

/* `s` in lower case, into `out` */
static void lower(char *out, size_t size, const char *s) {
    size_t i = 0;
    for (; s && s[i] && i + 1 < size; i++) {
        out[i] = (char)tolower((unsigned char)s[i]);
    }
    out[i] = '\0';
}

/* The resolve rule, written plainly: the first slot that is active, not
 * cached, not cut, and has a name with a domain, whose whole name is the
 * query, or whose first label is and whose domain is the board's own */
static uint32_t model_resolve(const char *own, const char *name) {
    if (!name || !name[0]) return 0;
    char q[80];
    char o[80];
    lower(q, sizeof q, name);
    lower(o, sizeof o, own);
    for (int i = 0; i < count; i++) {
        const ml_peer_t *p = &peers[i];
        if (!p->active || p->cached || p->name_cut) continue;
        char h[80];
        lower(h, sizeof h, p->hostname);
        char *dot = strchr(h, '.');
        if (!dot || !dot[1]) continue;
        if (strcmp(h, q) == 0) return p->vpn_ip;
        *dot = '\0';
        if (o[0] && strcmp(h, q) == 0 && strcmp(dot + 1, o) == 0) return p->vpn_ip;
    }
    return 0;
}

static void random_names(void) {
    static const char *const labels[] = {"a", "host", "HOST", "control-host", "x1", "b-2"};
    static const char *const domains[] = {"tail1.ts.net", "TAIL1.ts.net", "other.ts.net",
                                          "tail1.ts.net.x", "tail1", ""};
    static const char *const owns[] = {"tail1.ts.net", "Tail1.TS.net", "other.ts.net", "", NULL};
    int found = 0;
    int by_label = 0;
    for (int round = 0; round < 20000; round++) {
        reset();
        const int n = (int)(next() % (PEERS + 1));
        for (int i = 0; i < n; i++) {
            char fqdn[160];
            const char *label = pick(labels, COUNT(labels));
            const char *domain = pick(domains, COUNT(domains));
            switch (next() % 6) {
            case 0:  /* dotless */
                snprintf(fqdn, sizeof fqdn, "%s", label);
                break;
            case 1:  /* a label long enough that the name is cut at 63 */
                snprintf(fqdn, sizeof fqdn, "%s%s.%s.", label,
                         "-0123456789012345678901234567890123456789012345678901234", domain);
                break;
            default:
                snprintf(fqdn, sizeof fqdn, "%s.%s%s", label, domain, next() & 1 ? "." : "");
            }
            memset(&peers[i], 0, sizeof peers[i]);
            peers[i].name_cut = !ml_name_from_fqdn(peers[i].hostname, sizeof peers[i].hostname, fqdn);
            peers[i].active = next() % 4 != 0;
            peers[i].cached = next() % 5 == 0;
            peers[i].vpn_ip = 0x64400000u + (uint32_t)i + 1;
        }
        count = n;
        const char *own = owns[next() % COUNT(owns)];
        /* The query: a slot's name or label, in any case, or a pick */
        char query[80];
        if (n > 0 && next() % 3 != 0) {
            const ml_peer_t *p = &peers[next() % (uint32_t)n];
            snprintf(query, sizeof query, "%s", p->hostname);
            if (next() & 1) {
                char *dot = strchr(query, '.');
                if (dot) *dot = '\0';
            }
            for (char *c = query; *c; c++) {
                if (next() & 1) *c = (char)toupper((unsigned char)*c);
            }
        } else {
            snprintf(query, sizeof query, "%s%s%s", pick(labels, COUNT(labels)),
                     next() & 1 ? "." : "", next() & 1 ? pick(domains, COUNT(domains)) : "");
        }
        const uint32_t got = ml_peers_resolve(peers, count, own, query);
        const uint32_t want = model_resolve(own, query);
        CHECK(got == want, "round %d: \"%s\" (own %s): %08x, model %08x", round, query,
              own ? own : "(none)", (unsigned)got, (unsigned)want);
        found += got != 0;
        by_label += got != 0 && !strchr(query, '.');
    }
    /* The sweep reaches both rules, not only the misses */
    CHECK(found > 2000 && by_label > 500, "found %d, by label %d", found, by_label);
}

static void random_map_ends(void) {
    for (int round = 0; round < 20000; round++) {
        reset();
        count = (int)(next() % (PEERS + 1));
        for (int i = 0; i < count; i++) {
            peers[i].active = next() % 4 != 0;
            peers[i].cached = next() % 3 == 0;
            peers[i].in_map = next() & 1;
            peers[i].vpn_ip = (uint32_t)i + 1;
        }
        const bool complete = next() & 1;
        ml_peer_t before[PEERS];
        memcpy(before, peers, sizeof before);
        const int count_before = count;
        drops = 0;
        CHECK(ml_peers_map_end(peers, &count, complete, drop, &drops), "round %d: applied", round);
        /* The model: a complete map drops, in order, every active slot not in
         * it; the count ends past the last active slot, and never grows */
        int want_drops = 0;
        int last_active = -1;
        for (int i = 0; i < count_before; i++) {
            const bool dropped_here = complete && before[i].active && !before[i].in_map;
            if (dropped_here) {
                CHECK(want_drops < drops && dropped[want_drops] == i, "round %d: drop %d", round, i);
                want_drops++;
                CHECK(!peers[i].active && !peers[i].cached, "round %d: slot %d forgotten", round, i);
            } else {
                CHECK(peers[i].active == before[i].active && peers[i].cached == before[i].cached,
                      "round %d: slot %d untouched", round, i);
                if (before[i].active) last_active = i;
            }
        }
        CHECK(drops == want_drops, "round %d: %d drops, model %d", round, drops, want_drops);
        const int want_count = want_drops ? last_active + 1 : count_before;
        CHECK(count == want_count || (!want_drops && count == count_before),
              "round %d: count %d, model %d", round, count, want_count);
        CHECK(count <= count_before, "round %d: count grew", round);
    }
}

int main(void) {
    fqdns();
    random_names();
    random_map_ends();
    full_maps();
    names();
    if (failures) {
        printf("%d failed\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
