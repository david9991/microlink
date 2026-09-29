/**
 * @file ml_h2_frame.h
 * @brief HTTP/2's frame types and flags (RFC 9113 section 6), for each
 *        MicroLink file that builds or reads frames. No ESP-IDF call: the
 *        host tests build with it too.
 */

#pragma once

/* Frame types */
#define H2_FRAME_DATA           0x00
#define H2_FRAME_HEADERS        0x01
#define H2_FRAME_RST_STREAM     0x03
#define H2_FRAME_SETTINGS       0x04
#define H2_FRAME_PING           0x06
#define H2_FRAME_GOAWAY         0x07
#define H2_FRAME_WINDOW_UPDATE  0x08
#define H2_FRAME_CONTINUATION   0x09

/* Frame flags, by the frames that carry them */
#define H2_FLAG_END_STREAM      0x01    /* DATA, HEADERS */
#define H2_FLAG_ACK             0x01    /* SETTINGS, PING */
#define H2_FLAG_END_HEADERS     0x04    /* HEADERS, CONTINUATION */
#define H2_FLAG_PADDED          0x08    /* DATA, HEADERS */
#define H2_FLAG_PRIORITY        0x20    /* HEADERS */
