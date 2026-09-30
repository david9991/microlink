/**
 * @file microlink.h
 * @brief MicroLink v2 - ESP32 Tailscale Client (Public API)
 *
 * Production-ready Tailscale client for ESP32-S3 with:
 * - Queue-based architecture (no mutex deadlocks)
 * - Dedicated tasks for DERP TX, network I/O, coordination, WireGuard
 * - Rate-limited DISCO (matching native tailscaled timing)
 * - Async STUN (non-blocking)
 * - PSRAM-optimized memory layout
 */

#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle */
typedef struct microlink_s microlink_t;

/* The longest auth key an instance keeps, its NUL included: microlink_init
 * and microlink_set_auth_key refuse a longer one */
#define ML_AUTH_KEY_MAX 256

/* Configuration */
typedef struct {
    const char *auth_key;       /* Tailscale auth key (tskey-auth-...), shorter than ML_AUTH_KEY_MAX */
    const char *device_name;    /* Device hostname on the tailnet */
    bool enable_derp;           /* Enable DERP relay (default: true) */
    bool enable_stun;           /* Enable STUN endpoint discovery */
    bool enable_disco;          /* Enable DISCO NAT traversal */
    uint8_t max_peers;          /* Max simultaneous peers (default: 16) */
    int8_t wifi_tx_power_dbm;   /* WiFi TX power in dBm (0 = default 19.5) */

    /* Priority peer: the one peer kept a slot of the peer table from the
     * start, as microlink_keep_peers() keeps one — until that is called,
     * which replaces it. Set to 0 for none. */
    uint32_t priority_peer_ip;  /* VPN IP in host byte order (e.g., microlink_parse_ip("100.x.y.z")) */

    /* Optional timing overrides (0 = use defaults) */
    uint32_t disco_heartbeat_ms;    /* DISCO keepalive interval (default: 3000) */
    uint32_t stun_interval_ms;      /* STUN re-probe interval (default: 23000) */
    uint32_t ctrl_watchdog_ms;      /* Control plane watchdog timeout (default: 120000) */
} microlink_config_t;

/* The most peers microlink_keep_peers() takes */
#define ML_KEEP_PEERS_MAX 8

/* A peer the application keeps a slot of the peer table for: by its tailnet
 * address, or by its name */
typedef struct {
    uint32_t vpn_ip;    /* VPN IP in host byte order, or 0: the peer is given by name */
    char name[64];      /* Read when vpn_ip is 0: a name as microlink_resolve() takes one */
} microlink_keep_t;

/* Peer info (read-only snapshot) */
typedef struct {
    uint32_t vpn_ip;
    char hostname[64];
    uint8_t public_key[32];
    bool online;
    bool direct_path;           /* true if communicating via direct UDP */
} microlink_peer_info_t;

/* Connection state */
typedef enum {
    ML_STATE_IDLE = 0,
    ML_STATE_WIFI_WAIT,
    ML_STATE_CONNECTING,
    ML_STATE_REGISTERING,
    ML_STATE_CONNECTED,
    ML_STATE_RECONNECTING,
    ML_STATE_ERROR,
} microlink_state_t;

/* What the control server answered a registration */
typedef enum {
    ML_REGISTRATION_NONE = 0,       /* none answered yet */
    ML_REGISTRATION_AUTHORIZED,     /* MachineAuthorized */
    ML_REGISTRATION_NOT_AUTHORIZED, /* a login or an approval pending (AuthURL, or not MachineAuthorized) */
    ML_REGISTRATION_KEY_EXPIRED,    /* NodeKeyExpired */
    ML_REGISTRATION_REFUSED,        /* an Error, or an HTTP 401 or 403 */
    ML_REGISTRATION_UNREADABLE,     /* no answer that can be read: no response, a connection
                                       dropped, any other status that is not 2xx (5xx, 408,
                                       429, ...), or no JSON body; registered again, key kept */
} microlink_registration_t;

/* What the control server's last map gave this node */
typedef enum {
    ML_MAP_NONE = 0,    /* no map read yet */
    ML_MAP_SERVED,      /* its tailnet address */
    ML_MAP_UNSERVED,    /* no IPv4 address: the control server does not serve the node */
    ML_MAP_OVERSIZED,   /* it did not fit the node's buffers, and could not be read */
} microlink_map_t;

/* What NVS holds of this device's identity */
typedef enum {
    ML_IDENTITY_NONE = 0,    /* no machine key: nothing to start on */
    ML_IDENTITY_KEPT,        /* a machine key, and no record of an authorisation */
    ML_IDENTITY_AUTHORIZED,  /* a machine key the control server has authorised */
    ML_IDENTITY_UNREADABLE,  /* NVS does not say: it does not open, or it holds a machine
                                key it cannot give. The identity may well be there. */
} microlink_identity_t;

/* Callback types */
typedef void (*microlink_state_cb_t)(microlink_t *ml, microlink_state_t state, void *user_data);
typedef void (*microlink_peer_cb_t)(microlink_t *ml, const microlink_peer_info_t *peer, void *user_data);
typedef void (*microlink_data_cb_t)(microlink_t *ml, uint32_t src_ip, const uint8_t *data,
                                     size_t len, void *user_data);

/**
 * @brief Factory reset — erase all stored keys and cached peers
 * @return ESP_OK once both are erased and committed, else the NVS error that
 *         stopped it (the keys are erased first; a failure leaves the rest)
 *
 * Call it with no instance: before microlink_init() or after
 * microlink_destroy(). Erases:
 * - Machine key, WireGuard key, DISCO key (NVS namespace "microlink")
 * - Cached peer data (NVS namespace "ml_peers")
 * After reset, next microlink_init() will generate fresh keys.
 */
esp_err_t microlink_factory_reset(void);

/**
 * @brief What NVS holds of this device's identity
 * @return ML_IDENTITY_NONE only when NVS answers that it holds no machine
 *         key — or no namespace of MicroLink's at all. An NVS that does not
 *         open, that answers a read of the key with an error, or that holds
 *         a key of another length, is ML_IDENTITY_UNREADABLE: not "none",
 *         for a start then makes no key and writes nothing, and the
 *         identity may be read again by a later start.
 *
 * microlink_has_machine_key() and microlink_has_identity() are this answer
 * as yes or no, and say no for UNREADABLE: a caller that tells a person
 * there is no identity must ask this first. Reads NVS only: callable with or
 * without an instance, before microlink_init().
 */
microlink_identity_t microlink_get_identity(void);

/**
 * @brief Whether this device holds a node identity the control server has authorised
 * @return true once a registration was answered MachineAuthorized, with no AuthURL,
 *         no Error and the node key not expired — until a later registration is
 *         answered otherwise, or microlink_factory_reset()
 *
 * Such a node registers again without an auth key. Keys that exist but were
 * never authorised (a first start whose key was refused, say) do not count.
 * Reads NVS only: callable with or without an instance, before microlink_init().
 */
bool microlink_has_identity(void);

/**
 * @brief Whether this device holds a machine key from an earlier microlink_init
 * @return true once keys were generated and kept, authorised or not
 *
 * A device enrolled before its authorisation was recorded has keys and no
 * record (microlink_has_identity() is false); it registers on its node key,
 * which the control server accepts without an auth key while the node is
 * authorised and its key has not expired — and records the authorisation.
 * Reads NVS only: callable with or without an instance, before microlink_init().
 */
bool microlink_has_machine_key(void);

/**
 * @brief Initialize MicroLink
 * @param config Configuration (copied internally)
 * @return Handle on success, NULL on failure
 *
 * Creates all internal tasks, queues, and event groups.
 * Does NOT start connecting - call microlink_start() for that.
 */
microlink_t *microlink_init(const microlink_config_t *config);

/**
 * @brief Replace the auth key the instance registers with
 * @param ml Handle
 * @param auth_key The new key (copied), or NULL or "" for none: the next
 *        registration goes on the node key alone
 * @return ESP_OK, or ESP_ERR_INVALID_SIZE for a key of ML_AUTH_KEY_MAX bytes
 *         or more (nothing changed)
 *
 * The instance keeps its own copy of the key from microlink_init() on; this
 * wipes it and copies the new one, under the lock a registration holds while
 * it reads the key. The caller's copy is the caller's to wipe.
 */
esp_err_t microlink_set_auth_key(microlink_t *ml, const char *auth_key);

/**
 * @brief Start connecting to Tailscale
 * @param ml Handle from microlink_init()
 * @return ESP_OK on success
 *
 * WiFi must be connected before calling this.
 * Connection proceeds asynchronously - use callbacks or poll state.
 * An instance starts once: after microlink_stop() it refuses
 * (ESP_ERR_INVALID_STATE); destroy it and init another.
 */
esp_err_t microlink_start(microlink_t *ml);

/**
 * @brief Rebind to a new network interface without destroying the session
 * @param ml Handle
 * @return ESP_OK on success
 *
 * Use this when switching between WiFi and cellular (or vice versa).
 * Closes and reopens all sockets on the new interface while preserving:
 * - WireGuard peer state and crypto keys
 * - Peer table and DISCO discovery state
 * - VPN IP assignment
 * - Task state machines
 *
 * The coord and DERP connections will reconnect automatically (~5-10s).
 * Much faster than stop/destroy/init/start which requires full re-registration
 * and MapResponse re-download.
 */
esp_err_t microlink_rebind(microlink_t *ml);

/**
 * @brief Stop and disconnect from Tailscale
 * @param ml Handle
 * @return ESP_OK on success
 *
 * Gracefully shuts down all tasks and closes connections.
 */
esp_err_t microlink_stop(microlink_t *ml);

/**
 * @brief Destroy MicroLink instance and free all resources
 * @param ml Handle (NULL-safe)
 */
void microlink_destroy(microlink_t *ml);

/**
 * @brief Get current connection state
 */
microlink_state_t microlink_get_state(const microlink_t *ml);

/**
 * @brief Check if connected and ready to send/receive
 */
bool microlink_is_connected(const microlink_t *ml);

/**
 * @brief What the control server answered this instance's last registration
 * @param ml Handle
 * @param with_auth_key Set to whether that registration carried the auth key
 *        (may be NULL)
 * @return ML_REGISTRATION_NONE until one is answered
 *
 * A registration answered anything but ML_REGISTRATION_AUTHORIZED fails:
 * the client backs off and registers again, with whatever auth key it holds
 * then — none, once the caller has emptied the one it was given.
 */
microlink_registration_t microlink_get_registration(const microlink_t *ml, bool *with_auth_key);

/**
 * @brief What the control server's last map gave this instance's node
 * @param ml Handle
 * @return ML_MAP_NONE until a map is read
 *
 * The control server answers a node it does not serve — one that reports
 * another OS than it last connected with, say — with an authorised
 * registration, and then a map that gives the node no address, no peers and
 * no DERP map, the reason in its Health (logged at WARN). That map is
 * ML_MAP_UNSERVED: the fetch fails — or the session ends, when a streaming
 * update takes the address away — and the instance registers again, after a
 * minute, then two, up to fifteen: nothing it does changes the answer.
 *
 * ML_MAP_OVERSIZED is a first map larger than ML_H2_BUFFER_SIZE_KB or
 * ML_JSON_BUFFER_SIZE_KB: it is cut at the buffer's end and cannot be read,
 * the fetch fails, and the instance registers again at the same pace — the
 * map stays as large until the tailnet shrinks, its policy shows the node
 * fewer peers, or a build has larger buffers.
 *
 * Either answer stands through those reconnects, whatever
 * microlink_get_state() says meanwhile, until a map is read.
 */
microlink_map_t microlink_get_map(const microlink_t *ml);

/**
 * @brief Get our assigned VPN IP
 * @return VPN IP in host byte order; 0 if not yet assigned, and again once
 *         a map gives the node none (ML_MAP_UNSERVED)
 */
uint32_t microlink_get_vpn_ip(const microlink_t *ml);

/**
 * @brief Get number of known peers
 */
int microlink_get_peer_count(const microlink_t *ml);

/**
 * @brief Get peer info by index
 * @param ml Handle
 * @param index Peer index (0 to peer_count-1)
 * @param info Output peer info (copied)
 * @return ESP_OK if valid index
 *
 * Waits on nothing but the peer table's own lock, held only for the copy:
 * it may be called with lwIP's core lock held.
 */
esp_err_t microlink_get_peer_info(const microlink_t *ml, int index, microlink_peer_info_t *info);

/**
 * @brief Send UDP data to a peer by VPN IP
 * @param ml Handle
 * @param dest_vpn_ip Destination VPN IP (host byte order)
 * @param data Payload
 * @param len Payload length (max 1400 bytes)
 * @return ESP_OK on success, ESP_ERR_TIMEOUT if send queue full
 */
esp_err_t microlink_send(microlink_t *ml, uint32_t dest_vpn_ip,
                          const uint8_t *data, size_t len);

/**
 * @brief Register callbacks
 */
void microlink_set_state_callback(microlink_t *ml, microlink_state_cb_t cb, void *user_data);
void microlink_set_peer_callback(microlink_t *ml, microlink_peer_cb_t cb, void *user_data);
void microlink_set_data_callback(microlink_t *ml, microlink_data_cb_t cb, void *user_data);

/**
 * @brief Convert VPN IP to string
 */
void microlink_ip_to_str(uint32_t ip, char *buf);

/**
 * @brief Parse IP string "A.B.C.D" to host byte order uint32
 * @return IP in host byte order, 0 on error
 */
uint32_t microlink_parse_ip(const char *ip_str);

/**
 * @brief Get default device name based on MAC address
 * @return Static string like "esp32-a1b2c3"
 */
const char *microlink_default_device_name(void);

/**
 * @brief Get device name based on IMEI (cellular modem)
 * @return Static string like "prefix-123456789012345", or NULL if no IMEI available
 *
 * Requires ml_cellular_init() to have been called first.
 * Returns NULL if cellular module is not initialized or IMEI not available.
 */
const char *microlink_imei_device_name(void);

/* ============================================================================
 * MagicDNS — Resolve Tailnet hostnames to VPN IPs
 *
 * Resolves short or FQDN hostnames (e.g., "npc1", "npc1.tail12345.ts.net")
 * against the known peer list. No network calls — lookup only.
 * ========================================================================== */

/**
 * @brief Resolve a tailnet hostname to its VPN IP
 * @param ml Handle
 * @param hostname Short name ("npc1") or FQDN ("npc1.tail12345.ts.net"),
 *        with no trailing dot
 * @return VPN IP in host byte order, 0 if not found
 *
 * The rule is ml_peers_resolve's (ml_peer_table.h). In short, any case: a
 * peer's full name always resolves; its first label ("npc1") only when the
 * rest of its name is the board's own tailnet domain, so a node shared in
 * from another tailnet is found by its full name alone, and before the
 * board's domain is known no first label resolves. A peer's name with no
 * domain ("npc1") never resolves, nor does a peer cached in NVS or one
 * whose name was cut to fit: their names could stand for another node.
 *
 * Waits on nothing but the peer table's own lock, held only for the lookup:
 * it may be called with lwIP's core lock held (from an lwIP DNS hook, say).
 */
uint32_t microlink_resolve(const microlink_t *ml, const char *hostname);

/**
 * @brief Name the peers that keep a slot of the peer table
 * @param ml Handle
 * @param peers The peers, copied (may be NULL when count is 0)
 * @param count How many: at most ML_KEEP_PEERS_MAX
 * @return ESP_OK; ESP_ERR_INVALID_ARG for more than that, or for a peer
 *         with neither an address nor a name that ends within its field
 *         (nothing changed); ESP_ERR_TIMEOUT when the set is kept and the
 *         full map it needs could not be asked for — the next call, with
 *         any set, asks again
 *
 * The peer table has CONFIG_ML_MAX_PEERS slots. A tailnet with more peers
 * than that leaves the rest out — those the control server lists after the
 * table filled — with no tunnel, and no name to resolve. A kept peer is
 * never the one left out while a peer that is not kept holds a slot: when
 * the table is full it takes the slot of a peer not kept, whose tunnel
 * closes — one the last full map has not listed before one it has, and
 * among those the one heard from or sent to the longest ago. A peer kept by
 * name is the peer microlink_resolve() finds that name at. With every slot
 * held by a kept peer, a further kept peer is left out like any other.
 *
 * The call replaces the set; config.priority_peer_ip is the set until the
 * first call. It may come before microlink_start() or while the instance
 * runs: when, after a full map was applied, the new set names a peer the
 * set before did not, and the table does not hold it, the instance
 * reconnects to the control server for the full map — the tunnels stay up —
 * and the peer takes its slot as that map lists it. The same set named
 * again reconnects nothing, and a name that stands for no peer of the
 * tailnet costs one reconnect, when it is first named.
 */
esp_err_t microlink_keep_peers(microlink_t *ml, const microlink_keep_t *peers, int count);

/**
 * @brief Whether a full peer map from the control server has been applied
 * @return true from the first full map on, through reconnects (which keep the
 *         peers of the last map applied)
 *
 * Until then the peer table holds only the peers cached in NVS, their names
 * cut to 6 characters; microlink_resolve() never answers from those.
 */
bool microlink_map_applied(const microlink_t *ml);

/* ============================================================================
 * UDP Socket API
 *
 * Provides simple UDP send/receive over the Tailscale VPN tunnel.
 * Packets are routed through WireGuard for encryption.
 * ========================================================================== */

/* Opaque UDP socket handle */
typedef struct microlink_udp_socket microlink_udp_socket_t;

/* UDP receive callback (called from RX task context) */
typedef void (*microlink_udp_rx_cb_t)(microlink_udp_socket_t *sock,
                                       uint32_t src_ip, uint16_t src_port,
                                       const uint8_t *data, size_t len,
                                       void *user_data);

/**
 * @brief Create a UDP socket bound to the WireGuard VPN IP
 * @param ml Handle
 * @param local_port Port to bind (0 = auto-assign)
 * @return Socket handle, NULL on failure
 *
 * On creation, sends CallMeMaybe to all peers to trigger WG handshakes.
 */
microlink_udp_socket_t *microlink_udp_create(microlink_t *ml, uint16_t local_port);

/**
 * @brief Close UDP socket and free resources
 */
void microlink_udp_close(microlink_udp_socket_t *sock);

/**
 * @brief Send UDP data to a peer
 * @param sock Socket handle
 * @param dest_ip Destination VPN IP (host byte order)
 * @param dest_port Destination port
 * @param data Payload
 * @param len Payload length (max 1400)
 * @return ESP_OK on success
 */
esp_err_t microlink_udp_send(microlink_udp_socket_t *sock, uint32_t dest_ip,
                              uint16_t dest_port, const void *data, size_t len);

/**
 * @brief Receive UDP data (blocking with timeout)
 * @param sock Socket handle
 * @param src_ip Output source VPN IP (can be NULL)
 * @param src_port Output source port (can be NULL)
 * @param buffer Output buffer
 * @param len In: buffer size, Out: bytes received
 * @param timeout_ms Timeout in milliseconds (0 = non-blocking)
 * @return ESP_OK on success, ESP_ERR_TIMEOUT if timed out
 */
esp_err_t microlink_udp_recv(microlink_udp_socket_t *sock, uint32_t *src_ip,
                              uint16_t *src_port, void *buffer, size_t *len,
                              uint32_t timeout_ms);

/**
 * @brief Register receive callback for immediate packet handling
 * @param sock Socket handle
 * @param cb Callback (NULL to clear)
 * @param user_data Passed to callback
 */
esp_err_t microlink_udp_set_rx_callback(microlink_udp_socket_t *sock,
                                         microlink_udp_rx_cb_t cb, void *user_data);

/**
 * @brief Get local bound port
 */
uint16_t microlink_udp_get_local_port(const microlink_udp_socket_t *sock);

/* ============================================================================
 * TCP Socket API
 *
 * Provides TCP connections over the Tailscale VPN tunnel.
 * Traffic is routed through WireGuard — standard BSD TCP sockets
 * over the encrypted tunnel. Works with any TCP service on a peer
 * (HTTP, Traccar, MQTT, custom protocols, etc).
 * ========================================================================== */

/* Opaque TCP socket handle */
typedef struct microlink_tcp_socket microlink_tcp_socket_t;

/**
 * @brief Connect TCP to a peer over the VPN tunnel
 * @param ml Handle
 * @param dest_ip Destination VPN IP (host byte order)
 * @param dest_port Destination port
 * @param timeout_ms Connection timeout in ms (0 = default 15s)
 * @return Socket handle, NULL on failure
 *
 * Automatically triggers WG handshake if tunnel is not yet established.
 * Retries once if the initial connect fails due to tunnel not ready.
 */
microlink_tcp_socket_t *microlink_tcp_connect(microlink_t *ml, uint32_t dest_ip,
                                                uint16_t dest_port,
                                                uint32_t timeout_ms);

/**
 * @brief Send data over TCP connection
 * @param sock Socket handle
 * @param data Payload
 * @param len Payload length
 * @return ESP_OK on success, ESP_FAIL on error
 *
 * Blocks until all data is sent or an error occurs.
 */
esp_err_t microlink_tcp_send(microlink_tcp_socket_t *sock, const void *data, size_t len);

/**
 * @brief Receive data from TCP connection
 * @param sock Socket handle
 * @param buffer Output buffer
 * @param len Buffer size
 * @param timeout_ms Timeout in ms (0 = use socket default)
 * @return Bytes received (>0), 0 on timeout, -1 on error/disconnect
 */
int microlink_tcp_recv(microlink_tcp_socket_t *sock, void *buffer, size_t len,
                        uint32_t timeout_ms);

/**
 * @brief Check if TCP connection is still alive
 */
bool microlink_tcp_is_connected(const microlink_tcp_socket_t *sock);

/**
 * @brief Close TCP connection and free resources
 */
void microlink_tcp_close(microlink_tcp_socket_t *sock);

#ifdef __cplusplus
}
#endif
