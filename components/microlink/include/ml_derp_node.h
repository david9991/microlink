/**
 * @file ml_derp_node.h
 * @brief A DERP relay node from the control server's map, and which of a
 *        region's nodes is dialled and how: pure functions, built and tested
 *        on the host too
 *
 * No ESP-IDF call here: host_test/ builds these with the host's compiler.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    char hostname[64];
    char cert_name[64];     /* the name its certificate is for, when not hostname */
    char ipv4[16];
    char ipv6[46];
    uint16_t stun_port;     /* 0 = default 3478 */
    uint16_t derp_port;     /* 0 = default 443 */
    bool stun_only;         /* true if node only serves STUN, not DERP */
} ml_derp_node_t;

/* The address family a node is dialled over */
typedef enum {
    ML_DERP_ANY,            /* HostName's addresses, either family */
    ML_DERP_IPV4,           /* IPv4 only */
    ML_DERP_IPV6,           /* IPv6 only */
} ml_derp_family_t;

/* How a node is dialled: copies, never pointers into the map, which the
 * control connection rewrites while a relay is dialled */
typedef struct {
    char host[64];          /* HostName: the upgrade's Host, and the SNI unless an IP literal */
    char dial[64];          /* what is resolved and dialled: the map's address, else HostName */
    char cert[64];          /* the name its certificate must be for: CertName, else HostName */
    ml_derp_family_t family;
    uint16_t port;          /* its DERP port, 0 for the default */
} ml_derp_dial_t;

/**
 * @brief Which of a region's nodes is dialled, and how
 * @param nodes The region's nodes, in the map's order (the first preferred)
 * @param count How many
 * @param ipv6_alone Whether a node reachable over IPv6 alone may be dialled:
 *        not over the cellular modem's AT socket, which resolves no name for
 *        IPv6 alone
 * @param out How the node is dialled, when one is
 * @return The node's index — the first that serves DERP, has a HostName and
 *         can be dialled — or -1 when none can
 *
 * A node's IPv4 and IPv6 are each an address ("given"), "none" (that family
 * is not used at all) or empty (unset: HostName's addresses of it):
 *
 *   IPv4 given                 its IPv4 address, over IPv4
 *   IPv4 "none", IPv6 "none"   not dialled
 *   IPv4 "none"                its IPv6 address if given, else HostName,
 *                              over IPv6 only — and only with ipv6_alone
 *   IPv4 unset, IPv6 "none"    HostName, over IPv4 only
 *   IPv4 unset                 HostName, over either family
 *
 * Its certificate is for its CertName when the map gives one, else for its
 * HostName (an IP literal among them).
 */
int ml_derp_pick(const ml_derp_node_t *nodes, int count, bool ipv6_alone,
                 ml_derp_dial_t *out);
