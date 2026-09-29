/*
 * Host tests of which DERP node is dialled and how (ml_derp_node.c): every
 * combination of a node's IPv4 and IPv6 being an address, "none" or unset,
 * with and without IPv6 alone allowed, and the nodes a region skips.
 * Run by run.sh with the host's C compiler.
 */
#include <stdio.h>
#include <string.h>

#include "ml_derp_node.h"

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

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

#define HOST "derp9.example.net"
#define V4 "192.0.2.9"
#define V6 "2001:db8::9"

static ml_derp_node_t node(const char *ipv4, const char *ipv6) {
    ml_derp_node_t n;
    memset(&n, 0, sizeof n);
    strcpy(n.hostname, HOST);
    strcpy(n.ipv4, ipv4);
    strcpy(n.ipv6, ipv6);
    n.derp_port = 8443;
    return n;
}

/* Each of the nine combinations, with IPv6 alone allowed and not */
static void families(void) {
    static const struct {
        const char *ipv4, *ipv6;
        bool dialled;           /* with IPv6 alone allowed */
        bool dialled_v4_only;   /* without */
        const char *dial;
        ml_derp_family_t family;
    } cases[] = {
        { V4, V6, true, true, V4, ML_DERP_IPV4 },
        { V4, "none", true, true, V4, ML_DERP_IPV4 },
        { V4, "", true, true, V4, ML_DERP_IPV4 },
        { "none", V6, true, false, V6, ML_DERP_IPV6 },
        { "none", "none", false, false, NULL, ML_DERP_ANY },
        { "none", "", true, false, HOST, ML_DERP_IPV6 },
        { "", V6, true, true, HOST, ML_DERP_ANY },
        { "", "none", true, true, HOST, ML_DERP_IPV4 },
        { "", "", true, true, HOST, ML_DERP_ANY },
    };
    for (size_t c = 0; c < COUNT(cases); c++) {
        for (int v6 = 0; v6 < 2; v6++) {
            const ml_derp_node_t n = node(cases[c].ipv4, cases[c].ipv6);
            ml_derp_dial_t out;
            memset(&out, 0x5a, sizeof out);
            const int idx = ml_derp_pick(&n, 1, v6 != 0, &out);
            const bool dialled = v6 ? cases[c].dialled : cases[c].dialled_v4_only;
            CHECK(idx == (dialled ? 0 : -1), "IPv4 \"%s\" IPv6 \"%s\" ipv6_alone %d: %d",
                  cases[c].ipv4, cases[c].ipv6, v6, idx);
            if (idx != 0 || !dialled) continue;
            CHECK(strcmp(out.dial, cases[c].dial) == 0, "IPv4 \"%s\" IPv6 \"%s\": dials %s",
                  cases[c].ipv4, cases[c].ipv6, out.dial);
            CHECK(out.family == cases[c].family, "IPv4 \"%s\" IPv6 \"%s\": family %d",
                  cases[c].ipv4, cases[c].ipv6, (int)out.family);
            CHECK(strcmp(out.host, HOST) == 0, "the host is HostName: %s", out.host);
            CHECK(strcmp(out.cert, HOST) == 0, "no CertName: HostName's certificate: %s",
                  out.cert);
            CHECK(out.port == 8443, "the node's port: %u", out.port);
        }
    }
}

/* The first node that can be dialled, in the map's order */
static void skipped(void) {
    ml_derp_node_t nodes[5];
    nodes[0] = node(V4, V6);
    nodes[0].stun_only = true;                  /* serves STUN only */
    nodes[1] = node(V4, V6);
    nodes[1].hostname[0] = '\0';                /* no HostName */
    nodes[2] = node("none", "none");            /* no family */
    nodes[3] = node("none", V6);                /* IPv6 alone */
    nodes[4] = node("", "");
    strcpy(nodes[4].hostname, "derp10.example.net");
    ml_derp_dial_t out;
    CHECK(ml_derp_pick(nodes, 5, true, &out) == 3, "IPv6 alone allowed: the fourth node");
    CHECK(strcmp(out.dial, V6) == 0, "its IPv6: %s", out.dial);
    CHECK(ml_derp_pick(nodes, 5, false, &out) == 4, "IPv6 alone not allowed: the fifth node");
    CHECK(strcmp(out.dial, "derp10.example.net") == 0 && out.family == ML_DERP_ANY,
          "its HostName, either family: %s %d", out.dial, (int)out.family);
    CHECK(ml_derp_pick(nodes, 3, true, &out) == -1, "a region of nodes none can dial: none");
    CHECK(ml_derp_pick(nodes, 0, true, &out) == -1, "no nodes: none");
}

/* CertName, when given, is the certificate's name; HostName stays the host */
static void cert_name(void) {
    ml_derp_node_t n = node(V4, "");
    strcpy(n.cert_name, "relay.example.org");
    ml_derp_dial_t out;
    CHECK(ml_derp_pick(&n, 1, true, &out) == 0, "dialled");
    CHECK(strcmp(out.cert, "relay.example.org") == 0, "CertName's certificate: %s", out.cert);
    CHECK(strcmp(out.host, HOST) == 0, "HostName the host: %s", out.host);
}

/* Fields that fill their arrays, with no end in them, are cut, never
 * read past */
static void full_fields(void) {
    ml_derp_node_t n;
    memset(&n, 'a', sizeof n);
    n.stun_only = false;
    ml_derp_dial_t out;
    CHECK(ml_derp_pick(&n, 1, true, &out) == 0, "a node of full fields is dialled");
    CHECK(strlen(out.host) == sizeof n.hostname - 1, "HostName cut to its array: %zu",
          strlen(out.host));
    CHECK(strlen(out.dial) == sizeof n.ipv4 - 1, "IPv4 cut to its array: %zu",
          strlen(out.dial));
    CHECK(strlen(out.cert) == sizeof n.cert_name - 1, "CertName cut to its array: %zu",
          strlen(out.cert));
}

int main(void) {
    families();
    skipped();
    cert_name();
    full_fields();
    if (failures) {
        printf("%d failed\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
