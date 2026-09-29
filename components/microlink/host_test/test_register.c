/*
 * Host tests of what a registration was answered (ml_register.c): the
 * classification of a reply, and the :status of its HEADERS frame.
 * Run by run.sh with the host's C compiler.
 */
#include <stdio.h>
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

static int status_of(const uint8_t *p, size_t len, uint8_t flags) {
    return ml_h2_response_status(p, len, flags);
}

static void read_every_status(void) {
    /* RFC 7541 C.5.1: a literal with incremental indexing, plain "302" */
    const uint8_t c51[] = {0x48, 0x03, '3', '0', '2', 0x58, 0x07};
    CHECK(status_of(c51, sizeof c51, 0) == 302, "C.5.1");
    /* C.6.1 and C.6.2: the same, Huffman-coded "302" and "307" */
    const uint8_t c61[] = {0x48, 0x82, 0x64, 0x02};
    CHECK(status_of(c61, sizeof c61, 0) == 302, "C.6.1");
    const uint8_t c62[] = {0x48, 0x83, 0x64, 0x0e, 0xff};
    CHECK(status_of(c62, sizeof c62, 0) == 307, "C.6.2");
    /* Indexed from the static table */
    const struct { uint8_t byte; int status; } indexed[] = {
        {0x88, 200}, {0x89, 204}, {0x8a, 206}, {0x8b, 304}, {0x8c, 400}, {0x8d, 404}, {0x8e, 500},
    };
    for (size_t i = 0; i < sizeof indexed / sizeof indexed[0]; i++) {
        CHECK(status_of(&indexed[i].byte, 1, 0) == indexed[i].status, "indexed %02x", indexed[i].byte);
    }
    /* Huffman "401" (011010 00000 00001), with indexing, without, never indexed */
    const uint8_t h401[] = {0x48, 0x82, 0x68, 0x01};
    CHECK(status_of(h401, sizeof h401, 0) == 401, "huffman 401");
    const uint8_t plain401[] = {0x08, 0x03, '4', '0', '1'};
    CHECK(status_of(plain401, sizeof plain401, 0) == 401, "without indexing");
    const uint8_t never401[] = {0x18, 0x03, '4', '0', '1'};
    CHECK(status_of(never401, sizeof never401, 0) == 401, "never indexed");
    /* After dynamic table size updates, one of them multi-byte (4096) */
    const uint8_t updated[] = {0x20, 0x3f, 0xe1, 0x1f, 0x88};
    CHECK(status_of(updated, sizeof updated, 0) == 200, "size updates");
    /* PADDED and PRIORITY move the block */
    const uint8_t padded[] = {0x02, 0x88, 0x00, 0x00};
    CHECK(status_of(padded, sizeof padded, 0x08) == 200, "padded");
    const uint8_t priority[] = {0x00, 0x00, 0x00, 0x03, 0x10, 0x8d};
    CHECK(status_of(priority, sizeof priority, 0x20) == 404, "priority");
    const uint8_t both[] = {0x01, 0x00, 0x00, 0x00, 0x03, 0x10, 0x8c, 0x00};
    CHECK(status_of(both, sizeof both, 0x28) == 400, "padded and priority");
    /* What is not a status: another field first, letters, cut short, nothing */
    const uint8_t method[] = {0x82};
    CHECK(status_of(method, sizeof method, 0) == 0, "indexed :method");
    const uint8_t letters[] = {0x48, 0x03, 'a', 'b', 'c'};
    CHECK(status_of(letters, sizeof letters, 0) == 0, "letters");
    const uint8_t huffman_letters[] = {0x48, 0x81, 0x1f};  /* 'a' 00011, then padding */
    CHECK(status_of(huffman_letters, sizeof huffman_letters, 0) == 0, "huffman letters");
    const uint8_t cut[] = {0x48, 0x03, '4', '0'};
    CHECK(status_of(cut, sizeof cut, 0) == 0, "cut short");
    const uint8_t huffman_cut[] = {0x48, 0x81, 0x68};
    CHECK(status_of(huffman_cut, sizeof huffman_cut, 0) == 0, "huffman cut short");
    CHECK(status_of(NULL, 0, 0) == 0, "empty");
    const uint8_t bad_pad[] = {0x05, 0x88};
    CHECK(status_of(bad_pad, sizeof bad_pad, 0x08) == 0, "padding past the end");
    /* Huffman data after the three digits: more than 7 bits, or padding
     * that is not all ones */
    const uint8_t h401_more[] = {0x48, 0x83, 0x68, 0x01, 0xff};
    CHECK(status_of(h401_more, sizeof h401_more, 0) == 0, "huffman, a byte after the digits");
    const uint8_t h307_zero_pad[] = {0x48, 0x83, 0x64, 0x0e, 0xfe};
    CHECK(status_of(h307_zero_pad, sizeof h307_zero_pad, 0) == 0, "huffman, padding not all ones");
    const uint8_t h302_digit_more[] = {0x48, 0x83, 0x64, 0x02, 0x08};  /* then '1' */
    CHECK(status_of(h302_digit_more, sizeof h302_digit_more, 0) == 0, "huffman, a fourth digit");
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

int main(void) {
    classify_every_reply();
    read_every_status();
    read_every_final_status();
    if (failures) {
        printf("%d failed\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
