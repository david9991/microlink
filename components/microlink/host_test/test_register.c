/*
 * Host tests of what a registration was answered (ml_register.c): the
 * classification of a reply, and the :status of its HEADERS frame.
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

enum { DATA = 0x0, HEADERS = 0x1, SETTINGS = 0x4, CONTINUATION = 0x9 };
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

/* Random runs of frames: HEADERS, CONTINUATION, DATA and SETTINGS on streams
 * 0, 1 and 3, their payloads a status or random bytes, cut anywhere */
static void read_random_frames(void) {
    static const uint8_t types[] = {HEADERS, HEADERS, CONTINUATION, CONTINUATION, DATA, SETTINGS};
    static const uint32_t streams[] = {1, 1, 1, 0, 3};
    for (int round = 0; round < 50000; round++) {
        uint8_t buf[512];
        size_t n = 0;
        const int frames = (int)(next() % 6);
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
            n += frame(buf + n, types[next() % sizeof types], (uint8_t)next(),
                       streams[next() % COUNT(streams)], payload, len);
        }
        const size_t cut = n ? next() % (n + 1) : 0;
        uint8_t *copy = malloc(cut ? cut : 1);
        memcpy(copy, buf, cut);
        const int got = ml_h2_final_status(copy, cut, 1);
        CHECK(status_like(got) && (got < 100 || got > 199), "random frames %d: %d", round, got);
        free(copy);
    }
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

int main(void) {
    classify_every_reply();
    read_every_status();
    read_every_prefix();
    read_random_payloads();
    read_every_final_status();
    read_every_frames_prefix();
    read_random_frames();
    if (failures) {
        printf("%d failed\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
