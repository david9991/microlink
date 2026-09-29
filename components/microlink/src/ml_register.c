/**
 * @file ml_register.c
 * @brief What a registration was answered (see ml_register.h)
 */

#include "ml_register.h"

microlink_registration_t ml_register_classify(const ml_register_reply_t *reply) {
    if (reply->status != 0 && (reply->status < 200 || reply->status > 299)) {
        return ML_REGISTRATION_REFUSED;
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
    return value;
}

int ml_h2_response_status(const uint8_t *payload, size_t len, uint8_t flags) {
    size_t pos = 0;
    size_t end = len;
    if (flags & 0x08) {  /* PADDED */
        if (len < 1 || payload[0] >= len) return 0;
        end = len - payload[0];
        pos = 1;
    }
    if (flags & 0x20) {  /* PRIORITY */
        pos += 5;
    }
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
