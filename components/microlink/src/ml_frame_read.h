/**
 * @file ml_frame_read.h
 * @brief Reading one frame whole from a stream socket, within a deadline:
 *        pure logic over the caller's socket, clock and stop, built and
 *        tested on the host too
 *
 * No ESP-IDF call here: host_test/ builds this with the host's compiler.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* How a frame read ended */
typedef enum {
    ML_FRAME_DONE,      /* every byte asked for is in */
    ML_FRAME_EMPTY,     /* nothing of the frame came within the socket's timeout: read again */
    ML_FRAME_IDLE_STOP, /* a stop came before anything of the frame did: nothing lost */
    ML_FRAME_TIMEOUT,   /* the frame began and did not finish by its deadline: its stream is lost */
    ML_FRAME_STOPPED,   /* the frame began and a stop came: its stream is lost */
    ML_FRAME_CLOSED,    /* the connection closed */
    ML_FRAME_ERROR,     /* the socket failed otherwise (its errno says how) */
} ml_frame_result_t;

/* The caller's socket, clock and stop */
typedef struct {
    /* Read up to `len` bytes, waiting at most the socket's receive timeout:
     * > 0 the bytes read, 0 the connection closed, < 0 failed — with
     * *timed_out set when the timeout ran out */
    int (*recv)(void *ctx, uint8_t *buf, size_t len, bool *timed_out);
    uint64_t (*now_ms)(void *ctx);
    bool (*stopping)(void *ctx);
    /* Set the socket's receive timeout */
    void (*set_timeout)(void *ctx, uint32_t ms);
    void *ctx;
} ml_frame_io_t;

/* The frame read's limits */
typedef struct {
    uint32_t socket_ms;   /* the socket's own receive timeout, put back at the end */
    uint32_t partial_ms;  /* how long a frame begun has, from its first byte */
    uint32_t tick_ms;     /* the scheduler's tick: no read waits less than one */
    uint32_t stop_poll_ms; /* before the frame begins, a stop is looked for this
                            * often (0: only once the frame has begun) */
} ml_frame_limits_t;

/**
 * @brief Read exactly `len` bytes of a frame
 * @param deadline 0 until the frame has begun; set at its first byte to that
 *        byte's time plus `partial_ms` (a caller that read the frame's start
 *        passes the deadline that read set)
 *
 * Until the frame begins, the reads wait the socket's own timeout in all,
 * in slices of `stop_poll_ms` with a stop looked for before each: nothing
 * by the end of it is ML_FRAME_EMPTY, and a stop ML_FRAME_IDLE_STOP — the
 * two ends that lost nothing. Once it has begun, every read waits at most the time left
 * before the deadline, rounded up to whole ticks (so none waits zero ticks
 * and spins), and the deadline and a stop are checked after each read: the
 * frame ends ML_FRAME_TIMEOUT at the deadline itself, or ML_FRAME_STOPPED.
 * The socket's timeout is changed only while the frame is read, and put
 * back to `socket_ms` before this returns.
 */
ml_frame_result_t ml_frame_read(const ml_frame_io_t *io, const ml_frame_limits_t *limits,
                                uint8_t *buf, size_t len, uint64_t *deadline, size_t *got);

/**
 * @brief How long the next read of a frame begun may wait: what is left
 *        before the deadline, or the socket's own timeout if that is
 *        shorter, rounded up to whole ticks — at least one
 */
uint32_t ml_frame_wait_ms(uint64_t now, uint64_t deadline, const ml_frame_limits_t *limits);
