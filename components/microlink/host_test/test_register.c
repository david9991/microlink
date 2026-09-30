/*
 * Host tests of what a registration and a map were answered (ml_register.c):
 * the classification of a reply, the :status of its HEADERS frame, what a
 * start does about the identity NVS keeps and how it saves one, the OS a
 * node's registrations report, a node's IPv4 address, what a map says of
 * it, the wait before a reconnect, and a server's message made fit to log.
 * Run by run.sh with the host's C compiler.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ml_register.h"

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

static void classify_every_reply(void) {
    /* The body alone decides, for every 2xx and for an unread status */
    const int statuses[] = {0, 200, 204, 299};
    for (size_t s = 0; s < sizeof statuses / sizeof statuses[0]; s++) {
        for (int bits = 0; bits < 16; bits++) {
            const ml_register_reply_t r = {
                .status = statuses[s],
                .body = true,
                .machine_authorized = bits & 1,
                .node_key_expired = bits & 2,
                .auth_url = bits & 4,
                .error = bits & 8,
            };
            microlink_registration_t want;
            if (r.error) {
                want = ML_REGISTRATION_REFUSED;
            } else if (r.node_key_expired) {
                want = ML_REGISTRATION_KEY_EXPIRED;
            } else if (r.auth_url || !r.machine_authorized) {
                want = ML_REGISTRATION_NOT_AUTHORIZED;
            } else {
                want = ML_REGISTRATION_AUTHORIZED;
            }
            CHECK(ml_register_classify(&r) == want, "status %d bits %d", r.status, bits);
            /* No body: unreadable, whatever else */
            ml_register_reply_t none = r;
            none.body = false;
            CHECK(ml_register_classify(&none) == ML_REGISTRATION_UNREADABLE,
                  "no body, status %d bits %d", r.status, bits);
        }
    }
    /* A 401 or a 403 is a refusal, body or none: headscale's plain-text 401
     * for a spent key among them */
    const int refusals[] = {401, 403};
    /* Any other status that is not 2xx is no answer: a server hiccup, a
     * timeout, a rate limit, an interim response, never a refusal */
    const int unreadable[] = {100, 101, 103, 199, 300, 301, 400, 404, 408, 429, 500, 502, 503, 504};
    for (int body = 0; body < 2; body++) {
        for (int error = 0; error < 2; error++) {
            for (size_t s = 0; s < sizeof refusals / sizeof refusals[0]; s++) {
                const ml_register_reply_t r = {.status = refusals[s], .body = body,
                                               .machine_authorized = true, .error = error};
                CHECK(ml_register_classify(&r) == ML_REGISTRATION_REFUSED, "status %d", r.status);
            }
            for (size_t s = 0; s < sizeof unreadable / sizeof unreadable[0]; s++) {
                const ml_register_reply_t r = {.status = unreadable[s], .body = body,
                                               .machine_authorized = true, .error = error};
                CHECK(ml_register_classify(&r) == ML_REGISTRATION_UNREADABLE, "status %d body %d error %d",
                      r.status, body, error);
            }
        }
    }
    /* No response at all, or a connection dropped before anything was read */
    const ml_register_reply_t nothing = {0};
    CHECK(ml_register_classify(&nothing) == ML_REGISTRATION_UNREADABLE, "no response");
}

/* A HEADERS frame's payload, its flags, and the status it must read as */
struct vector {
    const char *name;
    uint8_t bytes[12];
    size_t len;
    uint8_t flags;
    int status;
};

#define V(name, flags, status, ...)                                              \
    {name, {__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__}), flags, status}

static const struct vector vectors[] = {
    /* RFC 7541 C.5.1: a literal with incremental indexing, plain "302" */
    V("C.5.1", 0, 302, 0x48, 0x03, '3', '0', '2', 0x58, 0x07),
    /* C.6.1 and C.6.2: the same, Huffman-coded "302" and "307" */
    V("C.6.1", 0, 302, 0x48, 0x82, 0x64, 0x02),
    V("C.6.2", 0, 307, 0x48, 0x83, 0x64, 0x0e, 0xff),
    /* Indexed from the static table */
    V("indexed 200", 0, 200, 0x88),
    V("indexed 204", 0, 204, 0x89),
    V("indexed 206", 0, 206, 0x8a),
    V("indexed 304", 0, 304, 0x8b),
    V("indexed 400", 0, 400, 0x8c),
    V("indexed 404", 0, 404, 0x8d),
    V("indexed 500", 0, 500, 0x8e),
    /* Huffman "401" (011010 00000 00001), with indexing, without, never indexed */
    V("huffman 401", 0, 401, 0x48, 0x82, 0x68, 0x01),
    V("without indexing", 0, 401, 0x08, 0x03, '4', '0', '1'),
    V("never indexed", 0, 401, 0x18, 0x03, '4', '0', '1'),
    /* After dynamic table size updates, one of them multi-byte (4096) */
    V("size updates", 0, 200, 0x20, 0x3f, 0xe1, 0x1f, 0x88),
    /* PADDED and PRIORITY move the block */
    V("padded", 0x08, 200, 0x02, 0x88, 0x00, 0x00),
    V("priority", 0x20, 404, 0x00, 0x00, 0x00, 0x03, 0x10, 0x8d),
    V("padded and priority", 0x28, 400, 0x01, 0x00, 0x00, 0x00, 0x03, 0x10, 0x8c, 0x00),
    /* What is not a status: another field first, letters, cut short */
    V("indexed :method", 0, 0, 0x82),
    V("letters", 0, 0, 0x48, 0x03, 'a', 'b', 'c'),
    V("huffman letters", 0, 0, 0x48, 0x81, 0x1f),  /* 'a' 00011, then padding */
    V("cut short", 0, 0, 0x48, 0x03, '4', '0'),
    V("huffman cut short", 0, 0, 0x48, 0x81, 0x68),
    V("padding past the end", 0x08, 0, 0x05, 0x88),
    /* Huffman data after the three digits: more than 7 bits, or padding
     * that is not all ones */
    V("huffman, a byte after the digits", 0, 0, 0x48, 0x83, 0x68, 0x01, 0xff),
    V("huffman, padding not all ones", 0, 0, 0x48, 0x83, 0x64, 0x0e, 0xfe),
    V("huffman, a fourth digit", 0, 0, 0x48, 0x83, 0x64, 0x02, 0x08),
};

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static void read_every_status(void) {
    for (size_t i = 0; i < COUNT(vectors); i++) {
        const struct vector *v = &vectors[i];
        const int got = ml_h2_response_status(v->bytes, v->len, v->flags);
        CHECK(got == v->status, "%s: %d, not %d", v->name, got, v->status);
    }
    CHECK(ml_h2_response_status(NULL, 0, 0) == 0, "empty");
}

/* Every prefix of every vector, each in a buffer of exactly its length (so
 * a read past it is caught under AddressSanitizer), reads as no status or
 * as the whole vector's */
static void read_every_prefix(void) {
    for (size_t i = 0; i < COUNT(vectors); i++) {
        const struct vector *v = &vectors[i];
        for (size_t len = 0; len <= v->len; len++) {
            uint8_t *copy = malloc(len ? len : 1);
            memcpy(copy, v->bytes, len);
            const int got = ml_h2_response_status(copy, len, v->flags);
            CHECK(got == 0 || got == v->status, "%s, first %zu bytes: %d", v->name, len, got);
            free(copy);
        }
    }
}

/* One HTTP/2 frame: its header, then the payload */
static size_t frame(uint8_t *out, uint8_t type, uint8_t flags, uint32_t stream,
                    const uint8_t *payload, size_t len) {
    out[0] = (uint8_t)(len >> 16);
    out[1] = (uint8_t)(len >> 8);
    out[2] = (uint8_t)len;
    out[3] = type;
    out[4] = flags;
    out[5] = (uint8_t)(stream >> 24);
    out[6] = (uint8_t)(stream >> 16);
    out[7] = (uint8_t)(stream >> 8);
    out[8] = (uint8_t)stream;
    if (len) memcpy(out + 9, payload, len);
    return 9 + len;
}

enum { DATA = 0x0, HEADERS = 0x1, RST_STREAM = 0x3, SETTINGS = 0x4, WINDOW_UPDATE = 0x8, CONTINUATION = 0x9 };
enum { END_STREAM = 0x1, END_HEADERS = 0x4, PADDED = 0x8 };

static void read_every_final_status(void) {
    uint8_t buf[256];
    size_t n;
    const uint8_t s200[] = {0x88};
    const uint8_t s103[] = {0x08, 0x03, '1', '0', '3'};
    const uint8_t s401[] = {0x08, 0x03, '4', '0', '1'};
    const uint8_t body[] = {'{', '}'};
    /* A plain response, after the server's SETTINGS */
    n = frame(buf, SETTINGS, 0, 0, NULL, 0);
    n += frame(buf + n, HEADERS, END_HEADERS, 1, s200, sizeof s200);
    n += frame(buf + n, DATA, END_STREAM, 1, body, sizeof body);
    CHECK(ml_h2_final_status(buf, n, 1) == 200, "plain");
    CHECK(ml_h2_final_status(buf, n, 3) == 0, "another stream");
    /* Split over CONTINUATION frames: :status cut in the middle */
    n = frame(buf, HEADERS, 0, 1, s401, 2);
    n += frame(buf + n, CONTINUATION, 0, 1, s401 + 2, 1);
    n += frame(buf + n, CONTINUATION, END_HEADERS | END_STREAM, 1, s401 + 3, 2);
    CHECK(ml_h2_final_status(buf, n, 1) == 401, "continuation");
    /* A block not finished: no END_HEADERS yet */
    CHECK(ml_h2_final_status(buf, n - 11, 1) == 0, "continuation still to come");
    /* An empty, padded HEADERS fragment, all of it in the CONTINUATION */
    const uint8_t pad_only[] = {0x02, 0x00, 0x00};
    n = frame(buf, HEADERS, PADDED, 1, pad_only, sizeof pad_only);
    n += frame(buf + n, CONTINUATION, END_HEADERS, 1, s401, sizeof s401);
    CHECK(ml_h2_final_status(buf, n, 1) == 401, "padded empty fragment");
    /* Another frame between a HEADERS frame and its CONTINUATION */
    n = frame(buf, HEADERS, 0, 1, s401, 2);
    n += frame(buf + n, DATA, 0, 1, body, sizeof body);
    n += frame(buf + n, CONTINUATION, END_HEADERS, 1, s401 + 2, 3);
    CHECK(ml_h2_final_status(buf, n, 1) == 0, "interleaved");
    /* An interim response, then the final one */
    n = frame(buf, HEADERS, END_HEADERS, 1, s103, sizeof s103);
    n += frame(buf + n, HEADERS, END_HEADERS | END_STREAM, 1, s401, sizeof s401);
    CHECK(ml_h2_final_status(buf, n, 1) == 401, "interim, then final");
    /* An interim response alone is no answer */
    n = frame(buf, HEADERS, END_HEADERS, 1, s103, sizeof s103);
    CHECK(ml_h2_final_status(buf, n, 1) == 0, "interim alone");
    /* Trailers after the final response do not replace its status */
    n = frame(buf, HEADERS, END_HEADERS, 1, s200, sizeof s200);
    n += frame(buf + n, HEADERS, END_HEADERS | END_STREAM, 1, s401, sizeof s401);
    CHECK(ml_h2_final_status(buf, n, 1) == 200, "trailers");
    /* A frame cut short */
    n = frame(buf, HEADERS, END_HEADERS, 1, s401, sizeof s401);
    CHECK(ml_h2_final_status(buf, n - 1, 1) == 0, "cut short");
    CHECK(ml_h2_final_status(NULL, 0, 1) == 0, "nothing");
}

/* A fixed sequence of pseudo-random numbers (xorshift32): the same buffers
 * on every run */
static uint32_t rng = 0x2545f491;

static uint32_t next(void) {
    rng ^= rng << 13;
    rng ^= rng >> 17;
    rng ^= rng << 5;
    return rng;
}

/* A status read from anything is none, or three digits */
static bool status_like(int status) {
    return status == 0 || (status >= 100 && status <= 999);
}

/* Random bytes as a HEADERS payload, each buffer exactly its length */
static void read_random_payloads(void) {
    static const uint8_t flags[] = {0x00, 0x08, 0x20, 0x28};
    for (int round = 0; round < 200000; round++) {
        const size_t len = next() % 24;
        uint8_t *buf = malloc(len ? len : 1);
        for (size_t i = 0; i < len; i++) {
            buf[i] = (uint8_t)next();
        }
        /* Bias the first byte toward the ones a status starts with */
        if (len && (next() & 1)) {
            static const uint8_t starts[] = {0x08, 0x18, 0x48, 0x88, 0x8e, 0x20, 0x3f};
            buf[0] = starts[next() % sizeof starts];
        }
        const int got = ml_h2_response_status(buf, len, flags[next() % sizeof flags]);
        CHECK(status_like(got), "random payload %d: %d", round, got);
        free(buf);
    }
}

/* Random runs of frames: HEADERS, CONTINUATION, DATA, RST_STREAM, SETTINGS
 * and WINDOW_UPDATE on streams 0, 1 and 3, their payloads a status or random
 * bytes, their flags random, cut anywhere. Every reader walks them alike:
 * what the run cut short says once it is complete is what the whole run
 * says, a malformed run reads as nothing, and the status is never 1xx. */
static void read_random_frames(void) {
    static const uint8_t types[] = {HEADERS, HEADERS, CONTINUATION, CONTINUATION,
                                    DATA, DATA, RST_STREAM, SETTINGS, WINDOW_UPDATE};
    static const uint32_t streams[] = {1, 1, 1, 0, 3};
    int completes = 0;
    int statuses = 0;
    int bodies = 0;
    for (int round = 0; round < 50000; round++) {
        uint8_t buf[512];
        size_t n = 0;
        size_t data_sum = 0;
        const int frames = (int)(next() % 7);
        for (int f = 0; f < frames; f++) {
            uint8_t payload[24];
            const size_t len = next() % sizeof payload;
            for (size_t i = 0; i < len; i++) {
                payload[i] = (uint8_t)next();
            }
            if (len && (next() & 1)) {
                const struct vector *v = &vectors[next() % COUNT(vectors)];
                memcpy(payload, v->bytes, v->len < len ? v->len : len);
            }
            const uint8_t type = types[next() % sizeof types];
            /* Mostly the flags a real server sends */
            const uint8_t flags = next() % 3 ? (uint8_t)(next() & (END_STREAM | END_HEADERS))
                                             : (uint8_t)next();
            if (type == DATA) data_sum += len;
            n += frame(buf + n, type, flags, streams[next() % COUNT(streams)], payload, len);
        }
        const size_t cut = n ? next() % (n + 1) : 0;
        uint8_t *copy = malloc(cut ? cut : 1);
        memcpy(copy, buf, cut);
        const size_t cap = next() % 32;
        uint8_t data_cut[32];
        uint8_t data_full[32];
        ml_h2_response_t r_cut;
        ml_h2_response_t r_full;
        ml_h2_read_response(copy, cut, 1, data_cut, cap, &r_cut);
        ml_h2_read_response(buf, n, 1, data_full, cap, &r_full);
        const bool complete = ml_h2_response_complete(copy, cut, 1);
        CHECK(status_like(r_cut.status) && (r_cut.status < 100 || r_cut.status > 199),
              "random frames %d: status %d", round, r_cut.status);
        CHECK(ml_h2_final_status(copy, cut, 1) == r_cut.status, "random frames %d: final status", round);
        CHECK(complete == (r_cut.ended || r_cut.malformed), "random frames %d: complete", round);
        CHECK(!r_cut.malformed || (r_cut.status == 0 && r_cut.data_len == 0),
              "random frames %d: malformed reads as nothing", round);
        CHECK(r_cut.data_len <= data_sum, "random frames %d: body %zu of %zu", round, r_cut.data_len,
              data_sum);
        /* Flow control counts whole payloads: at least the body, at most every
         * DATA, and of the whole run exactly every DATA payload */
        CHECK(ml_h2_data_flow(copy, cut) >= r_cut.data_len &&
                  ml_h2_data_flow(copy, cut) <= ml_h2_data_flow(buf, n),
              "random frames %d: flow %zu, body %zu", round, ml_h2_data_flow(copy, cut),
              r_cut.data_len);
        CHECK(ml_h2_data_flow(buf, n) == data_sum, "random frames %d: whole flow %zu, DATA %zu",
              round, ml_h2_data_flow(buf, n), data_sum);
        if (complete) {
            completes++;
            CHECK(r_full.status == r_cut.status && r_full.data_len == r_cut.data_len &&
                      r_full.ended == r_cut.ended && r_full.malformed == r_cut.malformed &&
                      memcmp(data_full, data_cut, r_cut.data_len < cap ? r_cut.data_len : cap) == 0,
                  "random frames %d: a complete response changes with more frames", round);
        }
        statuses += r_full.status != 0;
        bodies += r_full.data_len != 0;
        free(copy);
    }
    /* The sweep reaches statuses, bodies and ends, not only malformed runs */
    CHECK(completes > 5000 && statuses > 1000 && bodies > 200, "completes %d, statuses %d, bodies %d",
          completes, statuses, bodies);
}

/* What a response's walk reads: its body, padding off; a body cut to the
 * buffer but counted whole; the malformed runs; a reset */
static void read_every_response(void) {
    uint8_t buf[256];
    uint8_t data[16];
    ml_h2_response_t r;
    size_t n;
    const uint8_t s200[] = {0x88};
    const uint8_t s103[] = {0x08, 0x03, '1', '0', '3'};
    const uint8_t s401[] = {0x08, 0x03, '4', '0', '1'};
    const uint8_t body[] = {'{', '"', 'a', '"', ':', '1', '}'};
    const uint8_t padded_body[] = {0x02, 'o', 'k', 0x00, 0x00};

    /* HEADERS, then the body in two DATA frames, one padded */
    n = frame(buf, HEADERS, END_HEADERS, 1, s200, sizeof s200);
    n += frame(buf + n, DATA, 0, 1, body, sizeof body);
    n += frame(buf + n, DATA, PADDED | END_STREAM, 1, padded_body, sizeof padded_body);
    ml_h2_read_response(buf, n, 1, data, sizeof data, &r);
    CHECK(r.status == 200 && r.ended && !r.malformed && r.data_len == 9 &&
              memcmp(data, "{\"a\":1}ok", 9) == 0,
          "body: %d %zu", r.status, r.data_len);
    CHECK(ml_h2_response_complete(buf, n, 1), "body: complete");
    CHECK(!ml_h2_response_complete(buf, n - 1, 1), "body: last frame cut: not complete");
    /* Flow control counts both DATA payloads whole, padding and all */
    CHECK(ml_h2_data_flow(buf, n) == sizeof body + sizeof padded_body, "body: flow %zu",
          ml_h2_data_flow(buf, n));
    CHECK(ml_h2_data_flow(buf, n - 1) == sizeof body, "body: last frame cut: flow %zu",
          ml_h2_data_flow(buf, n - 1));
    /* A body larger than the buffer: counted whole, copied as far as it fits */
    ml_h2_read_response(buf, n, 1, data, 4, &r);
    CHECK(r.data_len == 9 && memcmp(data, "{\"a\"", 4) == 0, "cut body: %zu", r.data_len);

    /* A DATA frame between a HEADERS frame and its CONTINUATION: every
     * reader says the same — complete, no status, no body */
    n = frame(buf, HEADERS, 0, 1, s401, 2);
    n += frame(buf + n, DATA, END_STREAM, 1, body, sizeof body);
    n += frame(buf + n, CONTINUATION, END_HEADERS, 1, s401 + 2, 3);
    ml_h2_read_response(buf, n, 1, data, sizeof data, &r);
    CHECK(r.malformed && r.status == 0 && r.data_len == 0, "interleaved DATA");
    CHECK(ml_h2_response_complete(buf, n, 1), "interleaved DATA: complete");
    CHECK(ml_h2_final_status(buf, n, 1) == 0, "interleaved DATA: no status");

    /* DATA before any header block */
    n = frame(buf, DATA, END_STREAM, 1, body, sizeof body);
    ml_h2_read_response(buf, n, 1, data, sizeof data, &r);
    CHECK(r.malformed, "DATA first");

    /* DATA whose padding does not fit */
    const uint8_t bad_padding[] = {0x05, 'x'};
    n = frame(buf, HEADERS, END_HEADERS, 1, s200, sizeof s200);
    n += frame(buf + n, DATA, PADDED | END_STREAM, 1, bad_padding, sizeof bad_padding);
    ml_h2_read_response(buf, n, 1, data, sizeof data, &r);
    CHECK(r.malformed && r.status == 0, "DATA padding past its end");

    /* A 1xx that ends the stream */
    n = frame(buf, HEADERS, END_HEADERS | END_STREAM, 1, s103, sizeof s103);
    ml_h2_read_response(buf, n, 1, data, sizeof data, &r);
    CHECK(r.malformed && ml_h2_response_complete(buf, n, 1), "1xx with END_STREAM");

    /* A status alone, no body: ended by the HEADERS frame's END_STREAM */
    n = frame(buf, HEADERS, END_HEADERS | END_STREAM, 1, s401, sizeof s401);
    ml_h2_read_response(buf, n, 1, data, sizeof data, &r);
    CHECK(r.status == 401 && r.ended && r.data_len == 0, "status alone");

    /* END_STREAM on a HEADERS frame whose block goes on: not ended until its
     * CONTINUATION is in */
    n = frame(buf, HEADERS, END_STREAM, 1, s401, 2);
    CHECK(!ml_h2_response_complete(buf, n, 1), "END_STREAM, block open");
    n += frame(buf + n, CONTINUATION, END_HEADERS, 1, s401 + 2, 3);
    CHECK(ml_h2_response_complete(buf, n, 1) && ml_h2_final_status(buf, n, 1) == 401,
          "END_STREAM, block closed");

    /* A reset ends the response: nothing more to wait for */
    const uint8_t cancel[] = {0x00, 0x00, 0x00, 0x08};
    n = frame(buf, HEADERS, END_HEADERS, 1, s200, sizeof s200);
    n += frame(buf + n, RST_STREAM, 0, 1, cancel, sizeof cancel);
    ml_h2_read_response(buf, n, 1, data, sizeof data, &r);
    CHECK(r.ended && r.reset && r.status == 200, "reset");

    /* Another stream's frames, and the connection's, are passed over */
    n = frame(buf, SETTINGS, 0, 0, NULL, 0);
    n += frame(buf + n, HEADERS, END_HEADERS | END_STREAM, 3, s401, sizeof s401);
    n += frame(buf + n, HEADERS, END_HEADERS, 1, s200, sizeof s200);
    n += frame(buf + n, DATA, END_STREAM, 3, body, sizeof body);
    CHECK(ml_h2_data_flow(buf, n) == sizeof body, "another stream's DATA flows too: %zu",
          ml_h2_data_flow(buf, n));
    n += frame(buf + n, DATA, END_STREAM, 1, body, 2);
    ml_h2_read_response(buf, n, 1, data, sizeof data, &r);
    CHECK(r.status == 200 && r.ended && r.data_len == 2, "other streams: %d %zu", r.status, r.data_len);
}

/* Every prefix of a response split over HEADERS and CONTINUATION reads as no
 * status or the whole response's */
static void read_every_frames_prefix(void) {
    uint8_t buf[128];
    const uint8_t s103[] = {0x08, 0x03, '1', '0', '3'};
    const uint8_t s401[] = {0x48, 0x82, 0x68, 0x01};
    const uint8_t pad[] = {0x01, 0x08, 0x03, '4', 0x00};
    size_t n = frame(buf, SETTINGS, 0, 0, NULL, 0);
    n += frame(buf + n, HEADERS, END_HEADERS, 1, s103, sizeof s103);
    n += frame(buf + n, HEADERS, PADDED, 1, pad, sizeof pad);
    n += frame(buf + n, CONTINUATION, 0, 1, s401, 0);
    n += frame(buf + n, CONTINUATION, END_HEADERS | END_STREAM, 1, (const uint8_t *)"01", 2);
    CHECK(ml_h2_final_status(buf, n, 1) == 401, "split response: %d", ml_h2_final_status(buf, n, 1));
    for (size_t len = 0; len <= n; len++) {
        uint8_t *copy = malloc(len ? len : 1);
        memcpy(copy, buf, len);
        const int got = ml_h2_final_status(copy, len, 1);
        CHECK(got == (len == n ? 401 : 0), "split response, first %zu bytes: %d", len, got);
        free(copy);
    }
}

static void hostinfo_os_is_fixed_with_the_keys(void) {
    const char *configured = "freertos";
    const char *unstored = "linux";
    /* New keys report what the build says, whatever was stored before them */
    const char *stored_before[] = {NULL, "", "linux", "freertos", "windows"};
    for (size_t i = 0; i < sizeof stored_before / sizeof stored_before[0]; i++) {
        CHECK(ml_register_hostinfo_os(true, stored_before[i], configured, unstored) == configured,
              "new keys, stored %s", stored_before[i] ? stored_before[i] : "(none)");
    }
    /* Keys already made report the OS stored with them, not the build's */
    const char *stored = "freertos";
    CHECK(ml_register_hostinfo_os(false, stored, "linux", unstored) == stored, "stored freertos");
    const char *other = "zephyr";
    CHECK(ml_register_hostinfo_os(false, other, configured, unstored) == other, "stored zephyr");
    /* ...and keys with none stored report what the build is told they were
     * registered with: neither the OS it gives new keys, nor a fixed one */
    CHECK(ml_register_hostinfo_os(false, NULL, configured, unstored) == unstored, "none stored");
    CHECK(ml_register_hostinfo_os(false, "", configured, unstored) == unstored, "empty stored");
    CHECK(ml_register_hostinfo_os(false, NULL, "linux", configured) == configured,
          "none stored, keys made by a build that reported freertos");
}

/* ---- the identity NVS keeps ------------------------------------------------ */

/* NVS as a start finds it, and as a save leaves it */
typedef struct {
    bool authorized;
    bool os;
    char os_value[16];
    bool pub[3];  /* machine, wg, disco */
    bool pri[3];
    bool committed;
} nvs_t;

/* A save's writes, and the one that fails */
typedef struct {
    nvs_t *nvs;
    const char *os;                /* the OS the start reports */
    int fail_at;                   /* the write that fails, from 0; -1 for none */
    int made;                      /* writes attempted */
    ml_identity_write_t order[16];
} save_t;

static bool save_write(void *ctx, ml_identity_write_t what) {
    save_t *s = ctx;
    s->order[s->made] = what;
    if (s->made++ == s->fail_at) return false;
    nvs_t *n = s->nvs;
    switch (what) {
    case ML_SAVE_UNAUTHORIZE: n->authorized = false; break;
    case ML_SAVE_OS:
        n->os = true;
        snprintf(n->os_value, sizeof n->os_value, "%s", s->os);
        break;
    case ML_SAVE_MACHINE_PUB: n->pub[0] = true; break;
    case ML_SAVE_MACHINE_PRI: n->pri[0] = true; break;
    case ML_SAVE_WG_PUB: n->pub[1] = true; break;
    case ML_SAVE_WG_PRI: n->pri[1] = true; break;
    case ML_SAVE_DISCO_PUB: n->pub[2] = true; break;
    case ML_SAVE_DISCO_PRI: n->pri[2] = true; break;
    case ML_SAVE_COMMIT: n->committed = true; break;
    }
    return true;
}

static ml_kept_t kept(bool there) {
    return there ? ML_KEPT_FOUND : ML_KEPT_ABSENT;
}

static ml_identity_plan_t plan_for(const nvs_t *n, const char *configured) {
    return ml_register_identity_plan(kept(n->pri[0]), kept(n->pri[1]), kept(n->pri[2]), kept(n->os),
                                     n->os_value, configured, "linux");
}

static void an_identity_that_cannot_be_read_is_left_alone(void) {
    const ml_kept_t answers[] = {ML_KEPT_FOUND, ML_KEPT_ABSENT, ML_KEPT_UNREADABLE};
    int failed = 0;
    for (int m = 0; m < 3; m++) {
        for (int w = 0; w < 3; w++) {
            for (int d = 0; d < 3; d++) {
                for (int o = 0; o < 3; o++) {
                    const ml_identity_plan_t plan = ml_register_identity_plan(
                        answers[m], answers[w], answers[d], answers[o], "freertos", "zephyr", "linux");
                    const bool unreadable = m == 2 || w == 2 || d == 2 || o == 2;
                    CHECK(plan.fail == unreadable, "%d%d%d%d: fail %d", m, w, d, o, plan.fail);
                    nvs_t nvs = {0};
                    save_t save = {.nvs = &nvs, .os = plan.os, .fail_at = -1};
                    const bool saved = ml_register_identity_save(&plan, save_write, &save);
                    if (unreadable) {
                        /* Nothing is made, nothing is written, and the save says no */
                        CHECK(!plan.make_machine && !plan.make_wg && !plan.make_disco && !plan.store_os,
                              "%d%d%d%d: a key is made", m, w, d, o);
                        CHECK(!saved && save.made == 0, "%d%d%d%d: %d writes", m, w, d, o, save.made);
                        failed++;
                        continue;
                    }
                    /* A key is made only where NVS holds none */
                    CHECK(plan.make_machine == (m == 1) && plan.make_wg == (w == 1) &&
                              plan.make_disco == (d == 1),
                          "%d%d%d%d: makes %d%d%d", m, w, d, o, plan.make_machine, plan.make_wg,
                          plan.make_disco);
                    /* The OS: new machine keys report the build's and store
                     * it; kept ones report what is stored, or the unstored OS */
                    const char *os = m == 1 ? "zephyr" : o == 0 ? "freertos" : "linux";
                    CHECK(strcmp(plan.os, os) == 0, "%d%d%d%d: reports %s", m, w, d, o, plan.os);
                    CHECK(plan.store_os == (m == 1), "%d%d%d%d: stores %d", m, w, d, o, plan.store_os);
                    /* Every key read: not one write */
                    const bool all_read = m == 0 && w == 0 && d == 0;
                    CHECK(saved && (save.made == 0) == all_read, "%d%d%d%d: %d writes", m, w, d, o,
                          save.made);
                }
            }
        }
    }
    CHECK(failed == 81 - 16, "plans that fail: %d", failed);
    /* An OS found empty is none stored */
    const ml_identity_plan_t empty = ml_register_identity_plan(
        ML_KEPT_FOUND, ML_KEPT_FOUND, ML_KEPT_FOUND, ML_KEPT_FOUND, "", "zephyr", "linux");
    CHECK(!empty.fail && strcmp(empty.os, "linux") == 0 && !empty.store_os, "empty OS: %s", empty.os);
}

/* Every identity NVS can hold, saved with a write failing at every position
 * and at none, and the start after it: what a save cut short leaves is an
 * identity the next start completes, never one it replaces or misreports */
static void a_save_cut_short_leaves_an_identity_the_next_start_completes(void) {
    int cut = 0;
    for (int held = 0; held < 16; held++) {
        nvs_t before = {.authorized = true};
        for (int k = 0; k < 3; k++) {
            before.pri[k] = before.pub[k] = held & (1 << k);
        }
        before.os = held & 8;
        snprintf(before.os_value, sizeof before.os_value, "%s", before.os ? "freertos" : "");
        for (int fail_at = -1; fail_at < 9; fail_at++) {
            nvs_t nvs = before;
            const ml_identity_plan_t plan = plan_for(&nvs, "zephyr");
            save_t save = {.nvs = &nvs, .os = plan.os, .fail_at = fail_at};
            const bool saved = ml_register_identity_save(&plan, save_write, &save);
            const bool all_read = before.pri[0] && before.pri[1] && before.pri[2];
            if (all_read) {
                CHECK(saved && save.made == 0, "held %d: an identity read whole is written", held);
                continue;
            }
            /* The writes, in their order: the authorisation's record first,
             * the OS before the machine key, each public half before its
             * private one, the commit last — and nothing after a failure */
            CHECK(save.order[0] == ML_SAVE_UNAUTHORIZE, "held %d: first write %d", held, save.order[0]);
            for (int i = 1; i < save.made; i++) {
                CHECK(save.order[i] > save.order[i - 1], "held %d: write %d after %d", held,
                      save.order[i], save.order[i - 1]);
            }
            const bool failed = fail_at >= 0 && fail_at < save.made;
            CHECK(saved == !failed, "held %d, failing write %d: saved %d", held, fail_at, saved);
            if (failed) {
                CHECK(save.made == fail_at + 1, "held %d: %d writes after the failed one", held,
                      save.made - fail_at - 1);
                CHECK(!nvs.committed, "held %d: committed after a failed write", held);
                cut++;
            } else {
                CHECK(save.order[save.made - 1] == ML_SAVE_COMMIT && nvs.committed,
                      "held %d: not committed", held);
            }
            /* A key that was read is never written: what it held, it holds */
            for (int k = 0; k < 3; k++) {
                CHECK(!before.pri[k] || (nvs.pri[k] && nvs.pub[k]), "held %d: key %d lost", held, k);
                CHECK(!nvs.pri[k] || nvs.pub[k], "held %d: key %d has no public half", held, k);
            }
            /* No authorisation outlives the keys it was given to */
            CHECK(save.made < 2 || !nvs.authorized, "held %d: still authorised", held);
            /* A machine key this save stored has its OS beside it */
            if (!before.pri[0] && nvs.pri[0]) {
                CHECK(nvs.os && strcmp(nvs.os_value, "zephyr") == 0, "held %d: machine key, OS %s",
                      held, nvs.os ? nvs.os_value : "(none)");
            }
            /* The start after: it makes only the keys still missing, and the
             * node reports the OS its machine key was stored with — by a
             * build configured for another OS as well */
            const nvs_t left = nvs;
            const ml_identity_plan_t next = plan_for(&nvs, "windows");
            CHECK(!next.fail, "held %d: the next start fails", held);
            CHECK(next.make_machine == !left.pri[0] && next.make_wg == !left.pri[1] &&
                      next.make_disco == !left.pri[2],
                  "held %d, failing write %d: the next start makes %d%d%d", held, fail_at,
                  next.make_machine, next.make_wg, next.make_disco);
            const char *os = !left.pri[0] ? "windows" : left.os ? left.os_value : "linux";
            CHECK(strcmp(next.os, os) == 0, "held %d, failing write %d: the next start reports %s",
                  held, fail_at, next.os);
            if (before.pri[0]) {
                /* A machine key that was there reports what it always did */
                CHECK(strcmp(next.os, plan.os) == 0, "held %d: OS %s, then %s", held, plan.os, next.os);
            }
            save_t again = {.nvs = &nvs, .os = next.os, .fail_at = -1};
            CHECK(ml_register_identity_save(&next, save_write, &again), "held %d: second save", held);
            CHECK(nvs.pri[0] && nvs.pri[1] && nvs.pri[2] && nvs.pub[0] && nvs.pub[1] && nvs.pub[2],
                  "held %d: not whole after the second start", held);
            const ml_identity_plan_t third = plan_for(&nvs, "plan9");
            CHECK(strcmp(third.os, next.os) == 0 && !third.make_machine && !third.store_os,
                  "held %d: the OS moves on the third start: %s, %s", held, next.os, third.os);
        }
    }
    CHECK(cut > 40, "saves cut short: %d", cut);
}

/* ---- a node's addresses ------------------------------------------------------ */

typedef struct {
    const char *const *members;
    size_t count;
    size_t at;
} list_t;

static bool list_next(void *ctx, const char **addr) {
    list_t *l = ctx;
    if (l->at >= l->count) return false;
    *addr = l->members[l->at++];
    return true;
}

static uint32_t first_ipv4(const char *const *members, size_t count) {
    list_t l = {members, count, 0};
    return ml_register_first_ipv4(list_next, &l);
}

static void read_every_list_of_addresses(void) {
    const char *const v4_first[] = {"100.121.110.65/32", "fd7a:115c:a1e0::4a39:6e42/128"};
    const char *const v6_first[] = {"fd7a:115c:a1e0::4a39:6e42/128", "100.121.110.65/32"};
    const char *const v6_only[] = {"fd7a:115c:a1e0::4a39:6e42/128", "fd7a:115c:a1e0::1/128"};
    /* NULL: a member that is not a string (a number, an object, a null) */
    const char *const not_strings[] = {NULL, NULL};
    const char *const after_others[] = {NULL, "", "256.1.1.1", "fd7a::1/128", "10.0.0.1/8", "10.0.0.2/8"};
    CHECK(first_ipv4(v4_first, 2) == 0x64796e41, "IPv4 first");
    CHECK(first_ipv4(v6_first, 2) == 0x64796e41, "IPv6 first");
    CHECK(first_ipv4(v6_only, 2) == 0, "IPv6 only");
    CHECK(first_ipv4(not_strings, 2) == 0, "no strings");
    CHECK(first_ipv4(NULL, 0) == 0, "an empty list, and none at all");
    CHECK(first_ipv4(after_others, 6) == 0x0a000001, "the first that is one");
    /* A list is read no further than its first address */
    list_t l = {after_others, 6, 0};
    CHECK(ml_register_first_ipv4(list_next, &l) == 0x0a000001 && l.at == 5, "read to %zu", l.at);
}

static void what_a_map_says_of_the_address(void) {
    /* An address is an address, in a first map and in an update */
    for (int first = 0; first < 2; first++) {
        for (int listed = 0; listed < 2; listed++) {
            CHECK(ml_register_map_address(first, listed, 0x64796e41) == ML_MAP_ADDRESS_GIVEN,
                  "first %d, listed %d: an address", first, listed);
        }
    }
    /* A first map without one: the node is not served, however it is said */
    CHECK(ml_register_map_address(true, true, 0) == ML_MAP_ADDRESS_NONE, "first map, empty list");
    CHECK(ml_register_map_address(true, false, 0) == ML_MAP_ADDRESS_NONE, "first map, no list");
    /* An update: only a list without an address takes it away */
    CHECK(ml_register_map_address(false, true, 0) == ML_MAP_ADDRESS_NONE, "update, empty list");
    CHECK(ml_register_map_address(false, false, 0) == ML_MAP_ADDRESS_UNCHANGED, "update, no list");
}

static void waits_before_a_reconnect(void) {
    const uint32_t served[] = {1000, 2000, 4000, 8000, 16000, 30000, 30000};
    for (int i = 0; i < 7; i++) {
        CHECK(ml_register_backoff_ms(i, false) == served[i], "attempt %d: %u ms", i,
              (unsigned)ml_register_backoff_ms(i, false));
    }
    const uint32_t unserved[] = {60000, 120000, 240000, 480000, 900000, 900000};
    for (int i = 0; i < 6; i++) {
        CHECK(ml_register_backoff_ms(i, true) == unserved[i], "unserved, attempt %d: %u ms", i,
              (unsigned)ml_register_backoff_ms(i, true));
    }
    /* The longest waits are reached, and never passed, however many attempts */
    for (int i = 0; i < 100000; i += 997) {
        CHECK(ml_register_backoff_ms(i, false) <= ML_CTRL_BACKOFF_MAX_MS, "attempt %d", i);
        CHECK(ml_register_backoff_ms(i, true) <= ML_CTRL_BACKOFF_UNSERVED_MAX_MS, "unserved %d", i);
    }
    CHECK(ml_register_backoff_ms(1 << 30, false) == ML_CTRL_BACKOFF_MAX_MS, "many attempts");
    CHECK(ml_register_backoff_ms(1 << 30, true) == ML_CTRL_BACKOFF_UNSERVED_MAX_MS,
          "unserved, many attempts");
    CHECK(ml_register_backoff_ms(-1, false) == 1000, "no attempt yet");
}

static void a_servers_message_is_made_fit_to_log(void) {
    char out[ML_HEALTH_TEXT_MAX];
    ml_register_printable(out, sizeof out, "node OS changed since last connection");
    CHECK(strcmp(out, "node OS changed since last connection") == 0, "plain text: %s", out);
    ml_register_printable(out, sizeof out, "a\nb\rc\033[2Jd\te\x7f" "f\xc3\xa9g");
    CHECK(strcmp(out, "a?b?c?[2Jd?e?f??g") == 0, "control and non-ASCII bytes: %s", out);
    ml_register_printable(out, sizeof out, NULL);
    CHECK(out[0] == '\0', "none");
    ml_register_printable(out, sizeof out, "");
    CHECK(out[0] == '\0', "empty");
    /* No more than fits, from a buffer of exactly the text's size */
    char *text = malloc(1000);
    memset(text, 'x', 999);
    text[999] = '\0';
    ml_register_printable(out, sizeof out, text);
    CHECK(strlen(out) == ML_HEALTH_TEXT_MAX - 1, "cut to %zu", strlen(out));
    char two[2] = {'z', 'z'};
    ml_register_printable(two, 1, text);
    CHECK(two[0] == '\0' && two[1] == 'z', "a buffer of one");
    ml_register_printable(two, 0, text);
    CHECK(two[0] == '\0' && two[1] == 'z', "no buffer at all");
    free(text);
}

static void read_every_address(void) {
    struct {
        const char *addr;
        bool ok;
        uint32_t ip;
    } cases[] = {
        {"100.121.110.65/32", true, 0x64796e41},
        {"100.121.110.65", true, 0x64796e41},
        {"0.0.0.0/0", true, 0},
        {"255.255.255.255/32", true, 0xffffffff},
        {"10.0.0.1/8", true, 0x0a000001},
        {"fd7a:115c:a1e0::4a39:6e42/128", false, 0},
        {"", false, 0},
        {"100.121.110", false, 0},
        {"100.121.110.65.1", false, 0},
        {"256.1.1.1", false, 0},
        {"1.1.1.1000", false, 0},
        {"1.1.1.1/33", false, 0},
        {"1.1.1.1/", false, 0},
        {"1.1.1.1/32x", false, 0},
        {"1..1.1", false, 0},
        {"-1.1.1.1", false, 0},
        {" 1.1.1.1", false, 0},
        {"1.1.1.1 ", false, 0},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        uint32_t ip = 0xdeadbeef;
        const bool ok = ml_register_address_ipv4(cases[i].addr, &ip);
        CHECK(ok == cases[i].ok, "%s: %d", cases[i].addr, ok);
        CHECK(ok ? ip == cases[i].ip : ip == 0xdeadbeef, "%s: 0x%08x", cases[i].addr, ip);
    }
    CHECK(!ml_register_address_ipv4(NULL, &(uint32_t){0}), "NULL");
    /* Every prefix of an address with a prefix length, each in a buffer of
     * its own length: an address only where one ends ("100.121.110.6" and
     * "100.121.110.65", with and without a prefix length), and a read never
     * goes past the end */
    const char *full = "100.121.110.65/32";
    for (size_t len = 0; len <= strlen(full); len++) {
        char *cut = malloc(len + 1);
        memcpy(cut, full, len);
        cut[len] = '\0';
        uint32_t ip = 0;
        const bool ok = ml_register_address_ipv4(cut, &ip);
        const bool want = len == 13 || len == 14 || len == 16 || len == 17;
        CHECK(ok == want, "prefix %zu of %s: %d", len, full, ok);
        CHECK(!ok || ip == (len == 13 ? 0x64796e06u : 0x64796e41u), "prefix %zu: 0x%08x", len, ip);
        free(cut);
    }
    /* Round trip: any address, written as the control server writes one,
     * with any prefix length or none, reads back as itself */
    for (int round = 0; round < 200000; round++) {
        const uint32_t want = next() ^ (next() << 16);
        const unsigned prefix = next() % 34;  /* 33: none */
        char text[24];
        int n = snprintf(text, sizeof text, "%u.%u.%u.%u", (unsigned)(want >> 24),
                         (unsigned)(want >> 16 & 0xff), (unsigned)(want >> 8 & 0xff),
                         (unsigned)(want & 0xff));
        if (prefix <= 32) snprintf(text + n, sizeof text - (size_t)n, "/%u", prefix);
        uint32_t got = ~want;
        CHECK(ml_register_address_ipv4(text, &got) && got == want, "%s: 0x%08x", text, (unsigned)got);
    }
}

int main(void) {
    classify_every_reply();
    read_every_address();
    read_every_list_of_addresses();
    what_a_map_says_of_the_address();
    waits_before_a_reconnect();
    a_servers_message_is_made_fit_to_log();
    hostinfo_os_is_fixed_with_the_keys();
    an_identity_that_cannot_be_read_is_left_alone();
    a_save_cut_short_leaves_an_identity_the_next_start_completes();
    read_every_status();
    read_every_prefix();
    read_random_payloads();
    read_every_final_status();
    read_every_frames_prefix();
    read_every_response();
    read_random_frames();
    if (failures) {
        printf("%d failed\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
