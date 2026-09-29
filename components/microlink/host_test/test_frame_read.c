/*
 * Host tests of reading a frame whole within a deadline (ml_frame_read.c),
 * against a simulated socket, clock and stop: fixed cases at the edges, and
 * random schedules of arrivals, closes, errors and stops.
 * Run by run.sh with the host's C compiler.
 */
#include <stdio.h>
#include <string.h>

#include "ml_frame_read.h"

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

#define ARRIVALS 16

/* A socket that receives `arrival[i].bytes` at `arrival[i].at`, closes (or
 * fails) at `end_at` once everything before has been read, and a stop that
 * comes at `stop_at` */
struct sim {
    uint64_t now;
    uint32_t timeout;      /* the socket's receive timeout now */
    struct {
        uint64_t at;
        size_t bytes;
    } arrival[ARRIVALS];
    int arrivals;
    int next;              /* the first arrival not wholly read */
    size_t taken;          /* of it */
    uint64_t end_at;       /* UINT64_MAX: never */
    bool end_is_error;
    uint64_t stop_at;
    const ml_frame_limits_t *limits;
    uint64_t deadline_seen;  /* the deadline, as the reads found it */
    int bad_timeouts;      /* timeouts set outside [tick, socket_ms], or not whole ticks */
    int reads;
};

static int sim_recv(void *ctx, uint8_t *buf, size_t len, bool *timed_out) {
    struct sim *s = (struct sim *)ctx;
    (void)buf;
    s->reads++;
    *timed_out = false;
    for (;;) {
        if (s->next < s->arrivals && s->arrival[s->next].at <= s->now) {
            size_t n = s->arrival[s->next].bytes - s->taken;
            if (n > len) n = len;
            s->taken += n;
            if (s->taken == s->arrival[s->next].bytes) {
                s->next++;
                s->taken = 0;
            }
            return (int)n;
        }
        const uint64_t until = s->now + s->timeout;
        const uint64_t arrives = s->next < s->arrivals ? s->arrival[s->next].at : UINT64_MAX;
        const uint64_t ends = s->next >= s->arrivals ? s->end_at : UINT64_MAX;
        if (arrives <= until && arrives <= ends) {
            s->now = arrives;
            continue;
        }
        if (ends <= until) {
            s->now = ends;
            return s->end_is_error ? -1 : 0;
        }
        s->now = until;
        *timed_out = true;
        return -1;
    }
}

static uint64_t sim_now(void *ctx) {
    return ((struct sim *)ctx)->now;
}

static bool sim_stopping(void *ctx) {
    struct sim *s = (struct sim *)ctx;
    return s->now >= s->stop_at;
}

static void sim_timeout(void *ctx, uint32_t ms) {
    struct sim *s = (struct sim *)ctx;
    const uint32_t tick = s->limits->tick_ms;
    const uint32_t socket_ticks = (s->limits->socket_ms + tick - 1) / tick * tick;
    if (ms != s->limits->socket_ms && (ms < tick || ms > socket_ticks || ms % tick != 0)) {
        s->bad_timeouts++;
    }
    s->timeout = ms;
}

static ml_frame_result_t run(struct sim *s, const ml_frame_limits_t *limits, size_t len,
                             uint64_t *deadline, size_t *got) {
    s->limits = limits;
    s->timeout = limits->socket_ms;
    const ml_frame_io_t io = {sim_recv, sim_now, sim_stopping, sim_timeout, s};
    uint8_t buf[256];
    return ml_frame_read(&io, limits, buf, len, deadline, got);
}

static const ml_frame_limits_t limits = {.socket_ms = 2000, .partial_ms = 3000, .tick_ms = 10};

static struct sim fresh(void) {
    struct sim s;
    memset(&s, 0, sizeof s);
    s.end_at = UINT64_MAX;
    s.stop_at = UINT64_MAX;
    return s;
}

static void edges(void) {
    size_t got;
    uint64_t deadline;
    struct sim s;

    /* Nothing comes: EMPTY after the socket's own timeout, nothing lost */
    s = fresh();
    deadline = 0;
    CHECK(run(&s, &limits, 10, &deadline, &got) == ML_FRAME_EMPTY && got == 0 && deadline == 0 &&
              s.now == 2000 && s.timeout == 2000,
          "empty");

    /* The frame in two parts, well within its time */
    s = fresh();
    s.arrival[0].at = 5;
    s.arrival[0].bytes = 3;
    s.arrival[1].at = 900;
    s.arrival[1].bytes = 7;
    s.arrivals = 2;
    deadline = 0;
    CHECK(run(&s, &limits, 10, &deadline, &got) == ML_FRAME_DONE && got == 10 && deadline == 3005 &&
              s.timeout == 2000,
          "two parts: deadline %llu", (unsigned long long)deadline);

    /* The last byte comes exactly at the deadline, while the read waits: in */
    s = fresh();
    s.arrival[0].at = 0;
    s.arrival[0].bytes = 1;
    s.arrival[1].at = 3000;
    s.arrival[1].bytes = 1;
    s.arrivals = 2;
    deadline = 0;
    CHECK(run(&s, &limits, 2, &deadline, &got) == ML_FRAME_DONE && got == 2, "byte at the deadline");

    /* One ms after it: the frame is given up at the deadline, no later than
     * a tick past it, and the socket's timeout is put back */
    s = fresh();
    s.arrival[0].at = 0;
    s.arrival[0].bytes = 1;
    s.arrival[1].at = 3001;
    s.arrival[1].bytes = 1;
    s.arrivals = 2;
    deadline = 0;
    CHECK(run(&s, &limits, 2, &deadline, &got) == ML_FRAME_TIMEOUT && got == 1 &&
              s.now >= 3000 && s.now < 3000 + limits.tick_ms && s.timeout == 2000,
          "a ms late: at %llu", (unsigned long long)s.now);

    /* A deadline already reached when a read of the frame's rest starts */
    s = fresh();
    s.now = 3000;
    deadline = 3000;
    CHECK(run(&s, &limits, 4, &deadline, &got) == ML_FRAME_TIMEOUT && got == 0 && s.reads == 0,
          "deadline reached before the read");

    /* A caller's deadline: the frame's rest is bounded by it, even with
     * nothing of the rest read yet */
    s = fresh();
    s.now = 1000;
    deadline = 1500;
    CHECK(run(&s, &limits, 4, &deadline, &got) == ML_FRAME_TIMEOUT && s.now >= 1500 &&
              s.now < 1500 + limits.tick_ms,
          "caller's deadline: at %llu", (unsigned long long)s.now);

    /* A stop mid-frame: given up at the first check after it */
    s = fresh();
    s.arrival[0].at = 0;
    s.arrival[0].bytes = 1;
    s.arrivals = 1;
    s.stop_at = 700;
    deadline = 0;
    CHECK(run(&s, &limits, 2, &deadline, &got) == ML_FRAME_STOPPED && got == 1 && s.now >= 700 &&
              s.timeout == 2000,
          "stop mid-frame");

    /* Without stop polling, a stop before the frame begins does not cut a
     * read short: the caller looks for it after an EMPTY */
    s = fresh();
    s.stop_at = 0;
    deadline = 0;
    CHECK(run(&s, &limits, 2, &deadline, &got) == ML_FRAME_EMPTY, "stop before the frame");

    /* With it, a map awaited for a minute gives way to a stop within a
     * poll: nothing lost, the socket's timeout put back */
    const ml_frame_limits_t polled = {.socket_ms = 60000, .partial_ms = 3000, .tick_ms = 10,
                                      .stop_poll_ms = 500};
    s = fresh();
    s.stop_at = 12345;
    deadline = 0;
    CHECK(run(&s, &polled, 2, &deadline, &got) == ML_FRAME_IDLE_STOP && got == 0 && deadline == 0 &&
              s.now >= 12345 && s.now < 12345 + 500 + 10 && s.timeout == 60000,
          "stop while a map is awaited: at %llu", (unsigned long long)s.now);
    /* and nothing coming for the whole minute is EMPTY, a minute on */
    s = fresh();
    deadline = 0;
    CHECK(run(&s, &polled, 2, &deadline, &got) == ML_FRAME_EMPTY && s.now >= 60000 &&
              s.now < 60000 + 10 && s.timeout == 60000,
          "a minute of nothing: at %llu", (unsigned long long)s.now);
    /* a frame that begins between polls is read as before */
    s = fresh();
    s.arrival[0].at = 20750;
    s.arrival[0].bytes = 2;
    s.arrivals = 1;
    deadline = 0;
    CHECK(run(&s, &polled, 2, &deadline, &got) == ML_FRAME_DONE && deadline == 20750 + 3000 &&
              s.timeout == 60000,
          "a frame between polls");

    /* Closed, and failed, mid-frame */
    s = fresh();
    s.arrival[0].at = 0;
    s.arrival[0].bytes = 1;
    s.arrivals = 1;
    s.end_at = 50;
    deadline = 0;
    CHECK(run(&s, &limits, 2, &deadline, &got) == ML_FRAME_CLOSED && got == 1 && s.timeout == 2000,
          "closed");
    s = fresh();
    s.arrival[0].at = 0;
    s.arrival[0].bytes = 1;
    s.arrivals = 1;
    s.end_at = 50;
    s.end_is_error = true;
    deadline = 0;
    CHECK(run(&s, &limits, 2, &deadline, &got) == ML_FRAME_ERROR && s.timeout == 2000, "error");

    /* The waits near a deadline are whole ticks: none is zero */
    const ml_frame_limits_t l = {.socket_ms = 2000, .partial_ms = 3000, .tick_ms = 10};
    CHECK(ml_frame_wait_ms(2999, 3000, &l) == 10, "1 ms left: a tick");
    CHECK(ml_frame_wait_ms(2990, 3000, &l) == 10, "a tick left");
    CHECK(ml_frame_wait_ms(2989, 3000, &l) == 20, "a tick and a ms left");
    CHECK(ml_frame_wait_ms(3000, 3000, &l) == 10, "none left: still a tick");
    CHECK(ml_frame_wait_ms(0, 3000, &l) == 2000, "no longer than the socket's own");
}

/* ---- random schedules ------------------------------------------------------ */

static uint32_t rng = 0x1234567;

static uint32_t next(void) {
    rng ^= rng << 13;
    rng ^= rng >> 17;
    rng ^= rng << 5;
    return rng;
}

static void random_schedules(void) {
    static const uint32_t ticks[] = {1, 10};
    int outcomes[ML_FRAME_ERROR + 1] = {0};
    for (int round = 0; round < 100000; round++) {
        const ml_frame_limits_t lim = {
            .socket_ms = 1 + next() % 5000,
            .partial_ms = 1 + next() % 4000,
            .tick_ms = ticks[next() % 2],
            .stop_poll_ms = next() & 1 ? 0 : 1 + next() % 1000,
        };
        struct sim s = fresh();
        const size_t len = 1 + next() % 64;
        s.arrivals = (int)(next() % ARRIVALS);
        uint64_t at = next() % 3000;
        size_t total = 0;
        for (int i = 0; i < s.arrivals; i++) {
            at += next() % 2000;
            s.arrival[i].at = at;
            s.arrival[i].bytes = 1 + next() % 16;
            total += s.arrival[i].bytes;
        }
        if (next() % 3 == 0) {
            s.end_at = at + next() % 3000;
            s.end_is_error = next() & 1;
        }
        if (next() % 3 == 0) s.stop_at = next() % 8000;
        /* Sometimes a read of a frame's rest, its deadline already set */
        uint64_t deadline = 0;
        if (next() % 4 == 0) deadline = 1 + next() % 3000;
        const uint64_t given = deadline;
        size_t got = 0;
        const ml_frame_result_t r = run(&s, &lim, len, &deadline, &got);
        outcomes[r]++;

        CHECK(s.timeout == lim.socket_ms, "round %d: timeout %u not put back", round, s.timeout);
        CHECK(s.bad_timeouts == 0, "round %d: a wait outside whole ticks", round);
        CHECK(got <= len && got <= total, "round %d: got %zu", round, got);
        switch (r) {
        case ML_FRAME_DONE:
            CHECK(got == len, "round %d: done at %zu/%zu", round, got, len);
            break;
        case ML_FRAME_EMPTY:
            /* Only when nothing of the frame was read, and it had not begun;
             * polled, only once the socket's whole timeout has gone */
            CHECK(got == 0 && given == 0 && deadline == 0, "round %d: empty with %zu", round, got);
            CHECK(lim.stop_poll_ms == 0 ||
                      (s.now >= lim.socket_ms && s.now < lim.socket_ms + lim.tick_ms),
                  "round %d: polled empty at %llu", round, (unsigned long long)s.now);
            break;
        case ML_FRAME_IDLE_STOP:
            /* Only polled, before the frame began, and within a poll of the stop */
            CHECK(got == 0 && given == 0 && deadline == 0 && lim.stop_poll_ms != 0 &&
                      s.now >= s.stop_at &&
                      s.now < s.stop_at + lim.stop_poll_ms + lim.tick_ms,
                  "round %d: idle stop at %llu (stop %llu)", round, (unsigned long long)s.now,
                  (unsigned long long)s.stop_at);
            break;
        case ML_FRAME_TIMEOUT:
            CHECK(deadline != 0 && s.now >= deadline && s.now < deadline + lim.tick_ms,
                  "round %d: timeout at %llu, deadline %llu", round, (unsigned long long)s.now,
                  (unsigned long long)deadline);
            break;
        case ML_FRAME_STOPPED:
            CHECK(deadline != 0 && s.now >= s.stop_at && s.now < deadline,
                  "round %d: stopped at %llu", round, (unsigned long long)s.now);
            break;
        case ML_FRAME_CLOSED:
        case ML_FRAME_ERROR:
            CHECK(s.now == s.end_at, "round %d: closed at %llu", round, (unsigned long long)s.now);
            break;
        }
        /* A deadline the read set is its first byte's time plus partial_ms */
        if (given == 0 && deadline != 0) {
            CHECK(deadline == s.arrival[0].at + lim.partial_ms, "round %d: deadline", round);
        }
        /* No spinning: a read that times out waited at least a tick, so
         * the reads are bounded by the frame's time in ticks */
        const uint64_t span = given ? given : lim.partial_ms;
        const uint32_t poll = (lim.stop_poll_ms + lim.tick_ms - 1) / lim.tick_ms * lim.tick_ms;
        const int idle_reads = lim.stop_poll_ms ? (int)(lim.socket_ms / poll) + 2 : 0;
        CHECK(s.reads <= s.arrivals + 4 + (int)(span / lim.tick_ms) + idle_reads,
              "round %d: %d reads (given %llu, partial %u, tick %u, arrivals %d)", round, s.reads,
              (unsigned long long)given, lim.partial_ms, lim.tick_ms, s.arrivals);
        /* Once begun, the frame never takes longer than its time and a tick */
        if (deadline != 0) {
            CHECK(s.now < deadline + lim.tick_ms || r == ML_FRAME_DONE, "round %d: overran", round);
        }
    }
    for (int r = ML_FRAME_DONE; r <= ML_FRAME_ERROR; r++) {
        CHECK(outcomes[r] > 100, "outcome %d reached %d times", r, outcomes[r]);
    }
}

int main(void) {
    edges();
    random_schedules();
    if (failures) {
        printf("%d failed\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
