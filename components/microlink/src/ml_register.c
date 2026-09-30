/**
 * @file ml_register.c
 * @brief What a registration and a map were answered, and what a start does
 *        about the identity it finds (see ml_register.h)
 */

#include "ml_register.h"
#include "ml_h2_frame.h"

#include "nvs.h"

#include <string.h>

microlink_registration_t ml_register_classify(const ml_register_reply_t *reply) {
    if (reply->status == 401 || reply->status == 403) {
        return ML_REGISTRATION_REFUSED;
    }
    if (reply->status != 0 && (reply->status < 200 || reply->status > 299)) {
        return ML_REGISTRATION_UNREADABLE;
    }
    if (!reply->body) {
        return ML_REGISTRATION_UNREADABLE;
    }
    if (reply->error) {
        return ML_REGISTRATION_REFUSED;
    }
    if (reply->node_key_expired) {
        return ML_REGISTRATION_KEY_EXPIRED;
    }
    if (reply->auth_url || !reply->machine_authorized) {
        return ML_REGISTRATION_NOT_AUTHORIZED;
    }
    return ML_REGISTRATION_AUTHORIZED;
}

const char *ml_register_hostinfo_os(bool new_keys, const char *stored, const char *configured,
                                    const char *unstored) {
    if (new_keys) {
        return configured;
    }
    if (stored != NULL && stored[0] != '\0') {
        return stored;
    }
    return unstored;
}

ml_kept_t ml_register_kept(esp_err_t err, size_t len, size_t want) {
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ML_KEPT_ABSENT;
    }
    if (err != ESP_OK || (want != 0 && len != want)) {
        return ML_KEPT_UNREADABLE;
    }
    return ML_KEPT_FOUND;
}

ml_identity_plan_t ml_register_identity_plan(ml_kept_t machine, ml_kept_t wg, ml_kept_t disco,
                                             ml_kept_t os, const char *stored_os,
                                             const char *configured, const char *unstored) {
    ml_identity_plan_t plan = {0};
    if (machine == ML_KEPT_UNREADABLE || wg == ML_KEPT_UNREADABLE ||
        disco == ML_KEPT_UNREADABLE || os == ML_KEPT_UNREADABLE) {
        plan.fail = true;
        return plan;
    }
    plan.make_machine = machine == ML_KEPT_ABSENT;
    plan.make_wg = wg == ML_KEPT_ABSENT;
    plan.make_disco = disco == ML_KEPT_ABSENT;
    plan.os = ml_register_hostinfo_os(plan.make_machine, os == ML_KEPT_FOUND ? stored_os : NULL,
                                      configured, unstored);
    plan.store_os = plan.make_machine;
    return plan;
}

bool ml_register_identity_saves(const ml_identity_plan_t *plan) {
    return !plan->fail && (plan->make_machine || plan->make_wg || plan->make_disco);
}

bool ml_register_identity_save(const ml_identity_plan_t *plan,
                               bool (*write)(void *ctx, ml_identity_write_t what), void *ctx) {
    if (!ml_register_identity_saves(plan)) {
        return !plan->fail;
    }
    const struct {
        ml_identity_write_t what;
        bool due;
    } writes[] = {
        {ML_SAVE_UNAUTHORIZE, true},
        {ML_SAVE_OS, plan->store_os},
        {ML_SAVE_MACHINE_PUB, plan->make_machine},
        {ML_SAVE_MACHINE_PRI, plan->make_machine},
        {ML_SAVE_WG_PUB, plan->make_wg},
        {ML_SAVE_WG_PRI, plan->make_wg},
        {ML_SAVE_DISCO_PUB, plan->make_disco},
        {ML_SAVE_DISCO_PRI, plan->make_disco},
        {ML_SAVE_COMMIT, true},
    };
    for (size_t i = 0; i < sizeof(writes) / sizeof(writes[0]); i++) {
        if (writes[i].due && !write(ctx, writes[i].what)) {
            return false;
        }
    }
    return true;
}

/* A decimal number of 1 to 3 digits at most `max`, from *p; -1 if none */
static int small_decimal(const char **p, int max) {
    int value = 0;
    int digits = 0;
    while (**p >= '0' && **p <= '9' && digits < 3) {
        value = value * 10 + (**p - '0');
        (*p)++;
        digits++;
    }
    return digits == 0 || value > max ? -1 : value;
}

bool ml_register_address_ipv4(const char *addr, uint32_t *ip) {
    if (addr == NULL) {
        return false;
    }
    const char *p = addr;
    uint32_t value = 0;
    for (int i = 0; i < 4; i++) {
        if (i > 0 && *p++ != '.') {
            return false;
        }
        const int octet = small_decimal(&p, 255);
        if (octet < 0) {
            return false;
        }
        value = value << 8 | (uint32_t)octet;
    }
    if (*p == '/') {
        p++;
        if (small_decimal(&p, 32) < 0) {
            return false;
        }
    }
    if (*p != '\0') {
        return false;
    }
    *ip = value;
    return true;
}

uint32_t ml_register_first_ipv4(bool (*next)(void *ctx, const char **addr), void *ctx) {
    const char *addr;
    while (next(ctx, &addr)) {
        uint32_t ip;
        if (ml_register_address_ipv4(addr, &ip)) {
            return ip;
        }
    }
    return 0;
}

bool ml_register_map_status_ok(int status) {
    return status == 0 || (status >= 200 && status <= 299);
}

ml_map_address_t ml_register_map_address(bool first, bool node, bool listed, uint32_t ip) {
    if (!node) {
        return first ? ML_MAP_ADDRESS_NO_MAP : ML_MAP_ADDRESS_UNCHANGED;
    }
    if (ip != 0) {
        return ML_MAP_ADDRESS_GIVEN;
    }
    return first || listed ? ML_MAP_ADDRESS_NONE : ML_MAP_ADDRESS_UNCHANGED;
}

bool ml_register_map_lasting(microlink_map_t map) {
    return map == ML_MAP_UNSERVED || map == ML_MAP_OVERSIZED;
}

uint32_t ml_register_backoff_ms(int attempts, bool lasting) {
    const uint32_t first = lasting ? ML_CTRL_BACKOFF_LASTING_MS : 1000;
    const uint32_t max = lasting ? ML_CTRL_BACKOFF_LASTING_MAX_MS : ML_CTRL_BACKOFF_MAX_MS;
    uint32_t wait = first;
    for (int i = 0; i < attempts && wait < max; i++) {
        wait *= 2;
    }
    return wait < max ? wait : max;
}

uint32_t ml_register_backoff_next(ml_backoff_t *backoff, bool lasting) {
    if (backoff->lasting != lasting) {
        backoff->attempts = 0;
        backoff->lasting = lasting;
    }
    return ml_register_backoff_ms(backoff->attempts++, lasting);
}

void ml_register_printable(char *out, size_t size, const char *text) {
    if (size == 0) {
        return;
    }
    size_t n = 0;
    for (; text != NULL && text[n] != '\0' && n + 1 < size; n++) {
        const char c = text[n];
        out[n] = c >= ' ' && c <= '~' ? c : '?';
    }
    out[n] = '\0';
}

/* HPACK's integer (RFC 7541 5.1) with an n-bit prefix, from *pos; -1 if cut short or too large */
static long hpack_int(const uint8_t *p, size_t len, size_t *pos, int prefix_bits) {
    if (*pos >= len) return -1;
    const long max = (1L << prefix_bits) - 1;
    long value = p[(*pos)++] & max;
    if (value < max) return value;
    for (int shift = 0; shift < 28; shift += 7) {
        if (*pos >= len) return -1;
        const uint8_t b = p[(*pos)++];
        value += (long)(b & 0x7f) << shift;
        if (!(b & 0x80)) return value;
    }
    return -1;
}

/* Three digits, Huffman-coded (RFC 7541 Appendix B): '0'-'2' are 5-bit
 * codes 0-2, '3'-'9' 6-bit codes 25-31. */
static int huffman_digits(const uint8_t *p, size_t len) {
    size_t bit = 0;
    const size_t bits = len * 8;
    int value = 0;
    for (int digit = 0; digit < 3; digit++) {
        unsigned code = 0;
        int width = 0;
        while (width < 6) {
            if (bit >= bits) return 0;
            code = (code << 1) | ((p[bit / 8] >> (7 - bit % 8)) & 1);
            bit++;
            width++;
            if (width == 5 && code <= 2) break;
        }
        int d;
        if (width == 5) {
            d = (int)code;
        } else if (code >= 25 && code <= 31) {
            d = (int)code - 22;
        } else {
            return 0;
        }
        value = value * 10 + d;
    }
    /* What is left is padding: fewer than 8 bits, all ones (EOS's first) */
    if (bits - bit > 7) return 0;
    for (; bit < bits; bit++) {
        if (!((p[bit / 8] >> (7 - bit % 8)) & 1)) return 0;
    }
    return value;
}

/* Where a HEADERS frame's header block fragment lies in its payload, PADDED
 * and PRIORITY taken off; false when they do not fit */
static bool headers_fragment(const uint8_t *payload, size_t len, uint8_t flags,
                             size_t *start, size_t *end) {
    size_t pos = 0;
    size_t stop = len;
    if (flags & H2_FLAG_PADDED) {
        if (len < 1 || payload[0] >= len) return false;
        stop = len - payload[0];
        pos = 1;
    }
    if (flags & H2_FLAG_PRIORITY) {
        pos += 5;
    }
    if (pos > stop) return false;
    *start = pos;
    *end = stop;
    return true;
}

/* The :status a whole header block starts with; 0 when it starts otherwise */
static int block_status(const uint8_t *payload, size_t end) {
    size_t pos = 0;
    if (pos >= end) return 0;
    /* Dynamic table size updates (001xxxxx) may come first */
    while (pos < end && (payload[pos] & 0xe0) == 0x20) {
        if (hpack_int(payload, end, &pos, 5) < 0) return 0;
    }
    if (pos >= end) return 0;
    const uint8_t first = payload[pos];
    long name;
    if (first & 0x80) {  /* indexed field */
        static const int statuses[] = {200, 204, 206, 304, 400, 404, 500};
        const long index = hpack_int(payload, end, &pos, 7);
        return index >= 8 && index <= 14 ? statuses[index - 8] : 0;
    } else if (first & 0x40) {  /* literal, incremental indexing */
        name = hpack_int(payload, end, &pos, 6);
    } else {  /* literal without indexing, or never indexed */
        name = hpack_int(payload, end, &pos, 4);
    }
    if (name < 8 || name > 14 || pos >= end) return 0;
    const bool huffman = payload[pos] & 0x80;
    const long vlen = hpack_int(payload, end, &pos, 7);
    if (vlen <= 0 || pos + (size_t)vlen > end) return 0;
    if (huffman) return huffman_digits(payload + pos, (size_t)vlen);
    if (vlen != 3) return 0;
    int value = 0;
    for (int i = 0; i < 3; i++) {
        const uint8_t c = payload[pos + i];
        if (c < '0' || c > '9') return 0;
        value = value * 10 + (c - '0');
    }
    return value;
}

int ml_h2_response_status(const uint8_t *payload, size_t len, uint8_t flags) {
    size_t start;
    size_t end;
    if (!headers_fragment(payload, len, flags, &start, &end)) return 0;
    return block_status(payload + start, end - start);
}

/* How much of a header block is kept to read its status from: the status
 * comes first, after at most a few table size updates */
#define STATUS_BLOCK_MAX 128


bool ml_h2_next_frame(const uint8_t *frames, size_t len, size_t *pos, ml_h2_frame_t *f) {
    if (*pos > len || len - *pos < 9) return false;
    const uint8_t *h = frames + *pos;
    const size_t flen = ((size_t)h[0] << 16) | ((size_t)h[1] << 8) | h[2];
    if (flen > len - *pos - 9) return false;  /* not whole yet */
    f->type = h[3];
    f->flags = h[4];
    f->stream = ((uint32_t)(h[5] & 0x7f) << 24) | ((uint32_t)h[6] << 16) |
                ((uint32_t)h[7] << 8) | h[8];
    f->payload = h + 9;
    f->len = flen;
    *pos += 9 + flen;
    return true;
}

size_t ml_h2_data_flow(const uint8_t *frames, size_t len) {
    size_t flow = 0;
    size_t pos = 0;
    ml_h2_frame_t f;
    while (ml_h2_next_frame(frames, len, &pos, &f)) {
        if (f.type == H2_FRAME_DATA) flow += f.len;
    }
    return flow;
}

void ml_h2_read_response(const uint8_t *frames, size_t len, uint32_t stream,
                         uint8_t *data, size_t cap, ml_h2_response_t *r) {
    memset(r, 0, sizeof(*r));
    uint8_t block[STATUS_BLOCK_MAX];
    size_t block_len = 0;
    bool in_block = false;    /* a HEADERS frame for `stream` came, not yet its END_HEADERS */
    bool block_ends = false;  /* that HEADERS frame carried END_STREAM */
    bool final_seen = false;  /* a header block that is not 1xx is read */
    size_t pos = 0;
    ml_h2_frame_t f;
    while (!r->ended && !r->malformed && ml_h2_next_frame(frames, len, &pos, &f)) {
        size_t start = 0;
        size_t end = f.len;
        if (in_block) {
            /* Only its CONTINUATION frames may follow a HEADERS frame */
            if (f.type != H2_FRAME_CONTINUATION || f.stream != stream) {
                r->malformed = true;
                break;
            }
        } else if (f.stream != stream) {
            continue;  /* the connection's frames, and other streams' */
        } else if (f.type == H2_FRAME_HEADERS) {
            if (!headers_fragment(f.payload, f.len, f.flags, &start, &end)) {
                r->malformed = true;
                break;
            }
            block_len = 0;
            in_block = true;
            block_ends = f.flags & H2_FLAG_END_STREAM;
        } else if (f.type == H2_FRAME_DATA) {
            /* A body before the response's final header block, or padding
             * that does not fit, is no response that can be read */
            if (!final_seen || !headers_fragment(f.payload, f.len, f.flags & H2_FLAG_PADDED,
                                                 &start, &end)) {
                r->malformed = true;
                break;
            }
            const size_t n = end - start;
            if (r->data_len < cap) {
                const size_t take = n < cap - r->data_len ? n : cap - r->data_len;
                memcpy(data + r->data_len, f.payload + start, take);
            }
            r->data_len += n;
            r->ended = f.flags & H2_FLAG_END_STREAM;
            continue;
        } else if (f.type == H2_FRAME_RST_STREAM) {
            r->ended = true;  /* reset: nothing more comes on it */
            r->reset = true;
            continue;
        } else {
            continue;  /* PRIORITY, WINDOW_UPDATE and the like */
        }
        /* A HEADERS or CONTINUATION frame of the block */
        const size_t n = end - start;
        const size_t take = n < STATUS_BLOCK_MAX - block_len ? n : STATUS_BLOCK_MAX - block_len;
        if (take > 0) {
            memcpy(block + block_len, f.payload + start, take);
            block_len += take;
        }
        if (!(f.flags & H2_FLAG_END_HEADERS)) continue;  /* CONTINUATION follows */
        in_block = false;
        if (!final_seen) {
            const int status = block_status(block, block_len);
            if (status >= 100 && status <= 199) {
                /* An interim response: the final one follows; one that ends
                 * the stream is a broken response */
                if (block_ends) r->malformed = true;
                continue;
            }
            final_seen = true;
            r->status = status;
        }
        /* else: trailers, which do not change the status */
        r->ended = block_ends;
    }
    if (r->malformed) {
        r->status = 0;
        r->data_len = 0;
    }
}

bool ml_h2_response_complete(const uint8_t *frames, size_t len, uint32_t stream) {
    ml_h2_response_t r;
    ml_h2_read_response(frames, len, stream, NULL, 0, &r);
    return r.ended || r.malformed;
}

int ml_h2_final_status(const uint8_t *frames, size_t len, uint32_t stream) {
    ml_h2_response_t r;
    ml_h2_read_response(frames, len, stream, NULL, 0, &r);
    return r.status;
}
