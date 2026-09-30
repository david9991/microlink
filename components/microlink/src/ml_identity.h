/**
 * @file ml_identity.h
 * @brief A node's keys and the OS it reports, as NVS keeps them: read at
 *        a start, and what NVS holds none of made and saved
 *
 * Built and tested on the host too, against an NVS of the test's own
 * (host_test/): it calls nothing of ESP-IDF but NVS, the log and the
 * random number generator.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

/* The namespace the identity is kept in, and its keys */
#define ML_NVS_NAMESPACE       "microlink"
#define ML_NVS_KEY_MACHINE_PRI "machine_pri"
#define ML_NVS_KEY_MACHINE_PUB "machine_pub"
#define ML_NVS_KEY_WG_PRI      "wg_private"
#define ML_NVS_KEY_WG_PUB      "wg_public"
#define ML_NVS_KEY_DISCO_PRI   "disco_pri"
#define ML_NVS_KEY_DISCO_PUB   "disco_pub"
#define ML_NVS_KEY_AUTHORIZED  "authorized"   /* u8 1: a registration was authorised */
#define ML_NVS_KEY_OS          "hostinfo_os"  /* str: the OS the keys report (Hostinfo.OS) */

/* Where an instance holds its identity: six keys of 32 bytes, and the OS */
typedef struct {
    uint8_t *machine_private;
    uint8_t *machine_public;
    uint8_t *wg_private;
    uint8_t *wg_public;
    uint8_t *disco_private;
    uint8_t *disco_public;
    char *os;
    size_t os_size;
} ml_identity_t;

/**
 * @brief Load the node's identity from NVS, making and saving what NVS
 *        holds none of (ml_register_identity_plan)
 * @param id Where it goes
 * @param configured_os The OS a new machine key reports (ML_HOSTINFO_OS)
 * @param unstored_os The OS keys with none stored report
 *        (ML_HOSTINFO_OS_UNSTORED)
 * @return ESP_OK with the identity loaded. Anything else fails the start:
 *         NVS holds a key or an OS it cannot give — nothing is written —
 *         or what was made could not be saved whole, and no request may be
 *         sent on it.
 *
 * The keys are read through a handle that cannot write; one that can is
 * opened only when there is something to save
 * (ml_register_identity_saves). A public key is derived from its private
 * half. The stored half is read only to be compared: a difference is
 * logged as an error and nothing is written, since the node's key is then
 * not the one a build that read the stored half used.
 */
esp_err_t ml_identity_load(const ml_identity_t *id, const char *configured_os,
                           const char *unstored_os);
