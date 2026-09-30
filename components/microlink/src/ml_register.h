/**
 * @file ml_register.h
 * @brief What a registration and a map were answered, and what a start does
 *        about the identity it finds: pure functions, built and tested on
 *        the host too
 *
 * No ESP-IDF call here: host_test/ builds these with the host's compiler.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "microlink.h"

/* What a RegisterResponse carried */
typedef struct {
    int status;               /* its HTTP :status; 0 when none could be read */
    bool body;                /* a JSON object was read from its body */
    bool machine_authorized;  /* MachineAuthorized */
    bool node_key_expired;    /* NodeKeyExpired */
    bool auth_url;            /* a non-empty AuthURL */
    bool error;               /* a non-empty Error */
} ml_register_reply_t;

/**
 * @brief The answer a reply stands for
 *
 * A 401 or a 403 is REFUSED (a plain-text 401 for a spent key, say). Any
 * other status that is not 2xx is UNREADABLE — a server error (5xx), a
 * timeout (408), a rate limit (429), an interim response (1xx) left as the
 * answer, and the rest — and so is a reply with no JSON body: no response at
 * all, and a connection dropped before the body was read, among them. The
 * caller registers again and keeps its key. Otherwise the body decides: an
 * Error is REFUSED, NodeKeyExpired KEY_EXPIRED, an AuthURL or no
 * MachineAuthorized NOT_AUTHORIZED, and only what is left AUTHORIZED.
 */
microlink_registration_t ml_register_classify(const ml_register_reply_t *reply);

/**
 * @brief The :status of a response's HEADERS frame
 * @param payload The frame's payload
 * @param len Its length
 * @param flags The frame's flags (PADDED and PRIORITY move the header block)
 * @return The status, or 0 when the block does not start with one this can read
 *
 * A server sends :status first. Read: an indexed field of the static table
 * (200, 204, 206, 304, 400, 404, 500), or a literal whose name is :status,
 * its value three plain digits or three Huffman-coded ones and at most 7 bits
 * of padding — after any dynamic table size updates.
 */
int ml_h2_response_status(const uint8_t *payload, size_t len, uint8_t flags);

/**
 * @brief The OS a node reports to the control server (Hostinfo.OS)
 * @param new_keys The node's machine key is made by this start
 * @param stored The OS stored with its keys; NULL or "" when none is
 * @param configured The OS a node with new keys reports (ML_HOSTINFO_OS)
 * @param unstored The OS keys with none stored report
 *        (ML_HOSTINFO_OS_UNSTORED); NULL or "" when the build does not say
 *
 * The control server holds a node to the OS it last connected with: a node
 * that reports another is answered with a map that gives it no address and no
 * peers, and the health message "node OS changed since last connection". So
 * a node's OS is fixed with its keys. New keys report `configured`, which is
 * stored before them; keys already made report the OS stored with them, or,
 * when none is, `unstored`: the OS the build that made them reported, which
 * only its configuration can say — "linux" before 3908474, ML_HOSTINFO_OS
 * from there until the OS was stored.
 */
const char *ml_register_hostinfo_os(bool new_keys, const char *stored, const char *configured,
                                    const char *unstored);

/* What NVS answered a read of one thing an identity keeps there */
typedef enum {
    ML_KEPT_FOUND,       /* read */
    ML_KEPT_ABSENT,      /* none is kept (ESP_ERR_NVS_NOT_FOUND) */
    ML_KEPT_UNREADABLE,  /* anything else: an NVS error, or a key of another length */
} ml_kept_t;

/**
 * @brief What NVS answered a read, as one of the three
 * @param err What nvs_get_blob or nvs_get_str returned
 * @param len The length it read
 * @param want The length the thing has when it is whole; 0 for any
 * @return FOUND for ESP_OK and the length wanted; ABSENT for
 *         ESP_ERR_NVS_NOT_FOUND and nothing else; UNREADABLE for every other
 *         error, and for a thing read at another length — a key cut short
 *         is not a key to replace
 */
ml_kept_t ml_register_kept(esp_err_t err, size_t len, size_t want);

/* What a start does about the identity NVS keeps */
typedef struct {
    bool fail;          /* the start fails, and nothing is written: something kept cannot
                           be read, or (no_unstored_os) the OS cannot be known */
    bool no_unstored_os;  /* the keys have no OS stored, and the build names none for them */
    bool make_machine;  /* the keys this start makes, and saves */
    bool make_wg;
    bool make_disco;
    const char *os;     /* the OS the node reports */
    bool store_os;      /* ... stored, before the machine key is */
} ml_identity_plan_t;

/**
 * @brief What a start does about the identity NVS keeps
 * @param machine,wg,disco What NVS answered for each private key
 * @param os What it answered for the OS stored with them
 * @param stored_os That OS, when found
 * @param configured,unstored As ml_register_hostinfo_os takes them
 *
 * A key is made only when NVS holds none. A key, or the OS, that NVS holds
 * and cannot give fails the start: a key made in its place would overwrite
 * an identity a later start may still read, and an OS guessed in its place
 * may not be the one the node was registered with. For the same reason a
 * machine key with no OS stored fails the start when the build gives no
 * `unstored` OS: only the integrator knows what such a node was registered
 * as. A start that reads every key makes none, and saves nothing.
 */
ml_identity_plan_t ml_register_identity_plan(ml_kept_t machine, ml_kept_t wg, ml_kept_t disco,
                                             ml_kept_t os, const char *stored_os,
                                             const char *configured, const char *unstored);

/**
 * @brief Whether a plan has anything to save: it makes a key
 *
 * A start that read every key saves nothing, and needs no handle that can
 * write: this is what says so, to the save and to its caller alike.
 */
bool ml_register_identity_saves(const ml_identity_plan_t *plan);

/* One write of an identity's save */
typedef enum {
    ML_SAVE_UNAUTHORIZE,  /* erase the record of an authorisation: it was the old keys' */
    ML_SAVE_OS,
    ML_SAVE_MACHINE_PUB,
    ML_SAVE_MACHINE_PRI,
    ML_SAVE_WG_PUB,
    ML_SAVE_WG_PRI,
    ML_SAVE_DISCO_PUB,
    ML_SAVE_DISCO_PRI,
    ML_SAVE_COMMIT,
} ml_identity_write_t;

/**
 * @brief Save what a plan makes: each write in order, stopping at the first
 *        that fails
 * @param plan The plan
 * @param write Makes one write; false when it failed
 * @param ctx Passed to `write`
 * @return true when every write was made — none at all for a plan with
 *         nothing to save (ml_register_identity_saves): a key that was read
 *         is never written again
 *
 * The record of an authorisation goes first, then the OS, then each new key,
 * its public half before its private one, then the commit. So whatever a
 * save cut short leaves behind, a private key NVS holds has its public half
 * beside it, a machine key has its OS, and no authorisation outlives the
 * keys it was given to. A save that fails must fail the start: a node that
 * registered on keys it did not keep would spend its auth key on them.
 */
bool ml_register_identity_save(const ml_identity_plan_t *plan,
                               bool (*write)(void *ctx, ml_identity_write_t what), void *ctx);

/**
 * @brief An IPv4 address of a node's Addresses: "a.b.c.d", or "a.b.c.d/n"
 * @param addr The address as the control server writes it
 * @param ip Where the address goes, host order
 * @return true when `addr` is one: four decimal octets of at most three
 *         digits and 255 each, and, if a prefix follows, one of 0 to 32
 */
bool ml_register_address_ipv4(const char *addr, uint32_t *ip);

/**
 * @brief A node's IPv4 address: the first of its Addresses that is one
 * @param next The list's next member into *addr — its string, or NULL for a
 *        member that is not a string; false at the list's end
 * @param ctx Passed to `next`
 * @return The address, host order; 0 when the list has none — an empty
 *         list, IPv6 addresses only, members that are not addresses
 */
uint32_t ml_register_first_ipv4(bool (*next)(void *ctx, const char **addr), void *ctx);

/**
 * @brief Whether a map request's response may be read as a map
 * @param status Its final :status (ml_h2_final_status); 0 when none could be
 *        read
 * @return true for 2xx — and for 0, where the body decides; false for any
 *         other status: an error's body is not a map, whatever JSON it is
 */
bool ml_register_map_status_ok(int status);

/* What a map says of the node's own address */
typedef enum {
    ML_MAP_ADDRESS_GIVEN,      /* the map gives it */
    ML_MAP_ADDRESS_UNCHANGED,  /* an update that does not speak of it */
    ML_MAP_ADDRESS_NONE,       /* the map gives the node none: it is not served */
    ML_MAP_ADDRESS_NO_MAP,     /* a first map with no Node: it is no map, and says nothing */
} ml_map_address_t;

/**
 * @brief What a map says of the node's own address
 * @param first The first map of a session, which is the node's whole state;
 *        else a streaming update, which carries only what changed
 * @param node The map has a Node object
 * @param listed That Node has an Addresses member, whatever it holds
 * @param ip The first IPv4 address of that list (ml_register_first_ipv4), 0 for none
 *
 * A node the control server does not serve — one whose OS changed since it
 * last connected, say — is sent a Node with "Addresses": null. A first map
 * whose Node has no address is that, however it says it; one with no Node
 * at all is not a map — an error's body, a proxy's page — and says nothing
 * of the node: the fetch failed. An update says it only with a Node whose
 * list has no IPv4 address: an update with no Node, or a Node with no
 * Addresses, leaves the address as it was.
 */
ml_map_address_t ml_register_map_address(bool first, bool node, bool listed, uint32_t ip);

/**
 * @brief Whether the last map's answer is one that trying again does not
 *        change: no address for the node (ML_MAP_UNSERVED), or a map larger
 *        than the node's buffers (ML_MAP_OVERSIZED)
 */
bool ml_register_map_lasting(microlink_map_t map);

/* The longest wait before the control server is connected to again */
#define ML_CTRL_BACKOFF_MAX_MS          30000
/* ... and while the last map's answer is a lasting one: the first wait, and
 * the longest */
#define ML_CTRL_BACKOFF_LASTING_MS      60000
#define ML_CTRL_BACKOFF_LASTING_MAX_MS  900000

/**
 * @brief How long to wait before connecting to the control server again
 * @param attempts How many reconnects were made before this one
 * @param lasting The last map's answer is a lasting one
 *        (ml_register_map_lasting)
 * @return 1 s doubling to ML_CTRL_BACKOFF_MAX_MS; with a lasting answer
 *         ML_CTRL_BACKOFF_LASTING_MS doubling to
 *         ML_CTRL_BACKOFF_LASTING_MAX_MS: nothing the node does changes
 *         that answer, and each try is a registration
 */
uint32_t ml_register_backoff_ms(int attempts, bool lasting);

/* The reconnects made since the last session, and what they wait for */
typedef struct {
    int attempts;
    bool lasting;
} ml_backoff_t;

/**
 * @brief The wait before the next reconnect, which is then counted
 * @param backoff The reconnects so far; all zero after a session
 * @param lasting The last map's answer is a lasting one, now
 * @return ml_register_backoff_ms of the reconnects made for the same
 *         reason: when `lasting` changes the count starts again, so the
 *         first wait of a node that just became unserved is the first
 *         lasting one, however many reconnects came before, and a node
 *         served again goes back to a second
 */
uint32_t ml_register_backoff_next(ml_backoff_t *backoff, bool lasting);

/* The most of a control server's message that is logged, its NUL included */
#define ML_HEALTH_TEXT_MAX 201

/**
 * @brief A message of the control server's, fit to log
 * @param out Where it goes, NUL-terminated
 * @param size Its size: at most size - 1 bytes of `text` are taken
 * @param text The message (may be NULL: an empty one)
 *
 * Every byte that is not printable ASCII — a control character, an escape,
 * a byte of a UTF-8 sequence — becomes '?': the text is another host's.
 */
void ml_register_printable(char *out, size_t size, const char *text);

/* One HTTP/2 frame of a run received */
typedef struct {
    uint8_t type;
    uint8_t flags;
    uint32_t stream;
    const uint8_t *payload;  /* inside the run */
    size_t len;
} ml_h2_frame_t;

/**
 * @brief The frame at *pos of a run of frames, each with its 9-byte header
 * @return true, and *pos past it; false when no whole frame is there (yet)
 */
bool ml_h2_next_frame(const uint8_t *frames, size_t len, size_t *pos, ml_h2_frame_t *f);

/* A stream's response, as far as a run of frames holds it */
typedef struct {
    int status;        /* its final :status; 0 until one is read, or when it cannot be */
    size_t data_len;   /* its body's length, padding off (more than was copied, if cut) */
    bool ended;        /* END_STREAM came, its header block (if any) finished; or a reset */
    bool reset;        /* RST_STREAM ended it */
    bool malformed;    /* frames no response is made of: status and data_len are 0 */
} ml_h2_response_t;

/**
 * @brief Read a stream's response from a run of frames: the one walk a
 *        registration's response is read by, its end, its status and its
 *        body alike
 * @param frames HTTP/2 frames as received, each with its 9-byte header
 * @param len Their length
 * @param stream The stream the response is on
 * @param data Where its body goes, DATA frames' padding off (may be NULL
 *        when `cap` is 0)
 * @param cap How much of the body `data` takes; the rest is counted, not copied
 * @param r What was read
 *
 * A header block is a HEADERS frame and the CONTINUATION frames that follow
 * it on the same stream up to END_HEADERS; its status is read as
 * ml_h2_response_status reads one. An interim response (1xx) is skipped: the
 * status is that of the first block that is not 1xx, and a later block
 * (trailers) does not change it. Frames of other streams are passed over. A
 * frame not whole yet ends the walk: more may come. Malformed, and so no
 * response: any frame between a HEADERS frame and its END_HEADERS, a DATA
 * frame before the final header block, padding that does not fit, and a 1xx
 * that ends the stream.
 *
 * The first map's response is read by it too (do_fetch_peers, stream 3):
 * its end by ml_h2_response_complete, its status and its body by this. The
 * streaming updates are not: poll_map_update reads the long-poll stream — a
 * stream that does not end, among the server's PINGs and SETTINGS — its
 * own way.
 */
void ml_h2_read_response(const uint8_t *frames, size_t len, uint32_t stream,
                         uint8_t *data, size_t cap, ml_h2_response_t *r);

/**
 * @brief Whether there is nothing more to wait for on the stream: its
 *        response ended (or was reset), or the frames are malformed
 */
bool ml_h2_response_complete(const uint8_t *frames, size_t len, uint32_t stream);

/**
 * @brief The final :status of a stream's response (ml_h2_read_response's),
 *        0 when none could be read
 */
int ml_h2_final_status(const uint8_t *frames, size_t len, uint32_t stream);

/**
 * @brief What a run of frames takes of the connection's flow-control window:
 *        every whole DATA frame's payload, on any stream, its Pad Length and
 *        padding included (RFC 9113 section 6.9.1) — what a connection-level
 *        WINDOW_UPDATE gives back
 */
size_t ml_h2_data_flow(const uint8_t *frames, size_t len);
