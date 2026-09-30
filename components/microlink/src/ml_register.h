/**
 * @file ml_register.h
 * @brief What a registration was answered: pure functions, built and tested on the host too
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

/* The OS a node reported before one was stored with its keys: every
 * MicroLink build until then reported "linux" */
#define ML_HOSTINFO_OS_UNSTORED "linux"

/**
 * @brief The OS a node reports to the control server (Hostinfo.OS)
 * @param new_keys The node's machine key was made by this start
 * @param stored The OS stored with its keys; NULL or "" when none was
 * @param configured The OS a node with new keys reports (ML_HOSTINFO_OS)
 *
 * The control server holds a node to the OS it last connected with: a node
 * that reports another is answered with a map that gives it no address and no
 * peers, and the health message "node OS changed since last connection". So
 * a node's OS is fixed with its keys. New keys report `configured`, which is
 * stored beside them; keys already made report the OS stored with them, or,
 * when none was, ML_HOSTINFO_OS_UNSTORED — the OS they were registered with.
 */
const char *ml_register_hostinfo_os(bool new_keys, const char *stored, const char *configured);

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
 * The map's readers in ml_coord.c do not use it; each walks its frames its
 * own way: do_fetch_peers's scan for the first map's end and its copy of
 * that map's DATA, and poll_map_update's read of the long-poll stream, a
 * stream that does not end, among the server's PINGs and SETTINGS.
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
