/**
 * @file ml_frame_read.c
 * @brief Reading one frame whole within a deadline (see ml_frame_read.h)
 */

#include "ml_frame_read.h"

uint32_t ml_frame_wait_ms(uint64_t now, uint64_t deadline, const ml_frame_limits_t *limits) {
    const uint64_t tick = limits->tick_ms ? limits->tick_ms : 1;
    uint64_t wait = deadline > now ? deadline - now : 0;
    if (wait > limits->socket_ms) wait = limits->socket_ms;
    wait = (wait + tick - 1) / tick * tick;
    if (wait < tick) wait = tick;
    return (uint32_t)wait;
}

ml_frame_result_t ml_frame_read(const ml_frame_io_t *io, const ml_frame_limits_t *limits,
                                uint8_t *buf, size_t len, uint64_t *deadline, size_t *got) {
    size_t recvd = 0;
    uint32_t timeout = limits->socket_ms;  /* the socket's, as it stands */
    ml_frame_result_t result = ML_FRAME_DONE;
    while (recvd < len) {
        if (*deadline != 0) {
            const uint64_t now = io->now_ms(io->ctx);
            if (now >= *deadline) {
                result = ML_FRAME_TIMEOUT;
                break;
            }
            if (io->stopping(io->ctx)) {
                result = ML_FRAME_STOPPED;
                break;
            }
            const uint32_t wait = ml_frame_wait_ms(now, *deadline, limits);
            if (wait != timeout) {
                io->set_timeout(io->ctx, wait);
                timeout = wait;
            }
        }
        bool timed_out = false;
        const int n = io->recv(io->ctx, buf + recvd, len - recvd, &timed_out);
        if (n > 0) {
            recvd += (size_t)n;
            if (*deadline == 0) {
                *deadline = io->now_ms(io->ctx) + limits->partial_ms;
            }
            continue;
        }
        if (n < 0 && timed_out) {
            if (*deadline == 0) {
                result = ML_FRAME_EMPTY;  /* nothing of the frame read */
                break;
            }
            continue;  /* the deadline, checked above, decides */
        }
        result = n == 0 ? ML_FRAME_CLOSED : ML_FRAME_ERROR;
        break;
    }
    if (timeout != limits->socket_ms) {
        io->set_timeout(io->ctx, limits->socket_ms);
    }
    *got = recvd;
    return result;
}
