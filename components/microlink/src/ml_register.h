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

/**
 * @brief The final :status of a stream's response, from the frames received
 * @param frames HTTP/2 frames as received, each with its 9-byte header
 * @param len Their length
 * @param stream The stream the response is on
 * @return The status, or 0 when none could be read
 *
 * A header block is a HEADERS frame and the CONTINUATION frames that follow
 * it on the same stream up to END_HEADERS; its status is read as
 * ml_h2_response_status reads one. An interim response (1xx) is skipped: the
 * status is the first that is not 1xx. A block not finished within `frames`,
 * a frame cut short, and any other frame between a HEADERS and its
 * END_HEADERS give 0.
 */
int ml_h2_final_status(const uint8_t *frames, size_t len, uint32_t stream);
