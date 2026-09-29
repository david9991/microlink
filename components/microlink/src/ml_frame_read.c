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
    /* Until the frame begins: how long nothing may come in all */
    const uint64_t idle_until = *deadline == 0 ? io->now_ms(io->ctx) + limits->socket_ms : 0;
    while (recvd < len) {
        uint32_t wait = limits->socket_ms;
        const uint64_t now = io->now_ms(io->ctx);
        if (*deadline != 0) {
            if (now >= *deadline) {
                result = ML_FRAME_TIMEOUT;
                break;
            }
            if (io->stopping(io->ctx)) {
                result = ML_FRAME_STOPPED;
                break;
            }
            wait = ml_frame_wait_ms(now, *deadline, limits);
        } else if (limits->stop_poll_ms != 0) {
            if (now >= idle_until) {
                result = ML_FRAME_EMPTY;
                break;
            }
            if (io->stopping(io->ctx)) {
                result = ML_FRAME_IDLE_STOP;
                break;
            }
            const uint64_t slice_end = now + limits->stop_poll_ms;
            wait = ml_frame_wait_ms(now, slice_end < idle_until ? slice_end : idle_until, limits);
        }
        if (wait != timeout) {
            io->set_timeout(io->ctx, wait);
            timeout = wait;
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
            if (*deadline == 0 && limits->stop_poll_ms == 0) {
                result = ML_FRAME_EMPTY;  /* nothing of the frame read */
                break;
            }
            continue;  /* the deadline, or the idle time and a stop, decide above */
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
