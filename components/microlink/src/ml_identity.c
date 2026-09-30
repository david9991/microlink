/**
 * @file ml_identity.c
 * @brief A node's keys and the OS it reports, as NVS keeps them (see
 *        ml_identity.h)
 */

#include "ml_identity.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"

#include "ml_register.h"
#include "x25519.h"

static const char *TAG = "ml_identity";

static void generate_keypair(uint8_t *private_key, uint8_t *public_key) {
    esp_fill_random(private_key, 32);
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    x25519_base(public_key, private_key, 1);
}

/* Read a private key: what NVS answered (ml_register_kept) */
static ml_kept_t read_private_key(nvs_handle_t nvs, const char *name, uint8_t key[32]) {
    size_t len = 32;
    const esp_err_t err = nvs_get_blob(nvs, name, key, &len);
    return ml_register_kept(err, len, 32);
}

/* A key's public half as NVS holds it: read only to be compared */
typedef struct {
    bool read;
    uint8_t key[32];
} stored_public_t;

static void read_public_key(nvs_handle_t nvs, const char *name, stored_public_t *stored) {
    size_t len = sizeof(stored->key);
    const esp_err_t err = nvs_get_blob(nvs, name, stored->key, &len);
    stored->read = ml_register_kept(err, len, sizeof(stored->key)) == ML_KEPT_FOUND;
}

/* Say so when the public half NVS holds for a key that was read is not the
 * one its private half gives: the node goes on with the derived one, which
 * a build that read the stored half did not use — for the node key, the
 * control server then sees another node. Nothing is written. */
static void compare_public_key(const stored_public_t *stored, bool made, const uint8_t *derived,
                               const char *what) {
    if (!made && stored->read && memcmp(stored->key, derived, sizeof(stored->key)) != 0) {
        ESP_LOGE(TAG,
                 "The %s key's public half in NVS is not the one its private half gives: "
                 "the node uses the derived one (%02x%02x%02x%02x...), not the stored "
                 "(%02x%02x%02x%02x...); nothing is written",
                 what, derived[0], derived[1], derived[2], derived[3], stored->key[0],
                 stored->key[1], stored->key[2], stored->key[3]);
    }
}

static const char *kept_str(ml_kept_t kept) {
    return kept == ML_KEPT_FOUND ? "read" : kept == ML_KEPT_ABSENT ? "none" : "unreadable";
}

/* A key pair for this start: made, or its public half derived from the
 * private one NVS gave — never read, so a save cut short between the two
 * halves cannot leave a pair that does not match */
static void key_pair(bool make, uint8_t *private_key, uint8_t *public_key, const char *what) {
    if (make) {
        generate_keypair(private_key, public_key);
        ESP_LOGI(TAG, "Generated new %s key", what);
    } else {
        x25519_base(public_key, private_key, 1);
    }
}

/* One write of the identity's save (ml_register_identity_save) */
typedef struct {
    nvs_handle_t nvs;
    const ml_identity_t *id;
    ml_identity_write_t failed;  /* the write that failed, and why */
    esp_err_t err;
} identity_save_t;

static bool identity_write(void *ctx, ml_identity_write_t what) {
    identity_save_t *save = ctx;
    const ml_identity_t *id = save->id;
    esp_err_t err = ESP_FAIL;
    switch (what) {
    case ML_SAVE_UNAUTHORIZE:
        err = nvs_erase_key(save->nvs, ML_NVS_KEY_AUTHORIZED);
        if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;  /* none was recorded */
        break;
    case ML_SAVE_OS:
        err = nvs_set_str(save->nvs, ML_NVS_KEY_OS, id->os);
        break;
    case ML_SAVE_MACHINE_PUB:
        err = nvs_set_blob(save->nvs, ML_NVS_KEY_MACHINE_PUB, id->machine_public, 32);
        break;
    case ML_SAVE_MACHINE_PRI:
        err = nvs_set_blob(save->nvs, ML_NVS_KEY_MACHINE_PRI, id->machine_private, 32);
        break;
    case ML_SAVE_WG_PUB:
        err = nvs_set_blob(save->nvs, ML_NVS_KEY_WG_PUB, id->wg_public, 32);
        break;
    case ML_SAVE_WG_PRI:
        err = nvs_set_blob(save->nvs, ML_NVS_KEY_WG_PRI, id->wg_private, 32);
        break;
    case ML_SAVE_DISCO_PUB:
        err = nvs_set_blob(save->nvs, ML_NVS_KEY_DISCO_PUB, id->disco_public, 32);
        break;
    case ML_SAVE_DISCO_PRI:
        err = nvs_set_blob(save->nvs, ML_NVS_KEY_DISCO_PRI, id->disco_private, 32);
        break;
    case ML_SAVE_COMMIT:
        err = nvs_commit(save->nvs);
        break;
    }
    if (err != ESP_OK) {
        save->failed = what;
        save->err = err;
    }
    return err == ESP_OK;
}

esp_err_t ml_identity_load(const ml_identity_t *id, const char *configured_os,
                           const char *unstored_os) {
    ml_kept_t machine = ML_KEPT_ABSENT;
    ml_kept_t wg = ML_KEPT_ABSENT;
    ml_kept_t disco = ML_KEPT_ABSENT;
    ml_kept_t os = ML_KEPT_ABSENT;
    char stored_os[32] = "";
    stored_public_t machine_public = {0};
    stored_public_t wg_public = {0};
    stored_public_t disco_public = {0};

    /* Read through a handle that cannot write. No namespace yet: nothing kept. */
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(ML_NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        machine = read_private_key(nvs, ML_NVS_KEY_MACHINE_PRI, id->machine_private);
        wg = read_private_key(nvs, ML_NVS_KEY_WG_PRI, id->wg_private);
        disco = read_private_key(nvs, ML_NVS_KEY_DISCO_PRI, id->disco_private);
        read_public_key(nvs, ML_NVS_KEY_MACHINE_PUB, &machine_public);
        read_public_key(nvs, ML_NVS_KEY_WG_PUB, &wg_public);
        read_public_key(nvs, ML_NVS_KEY_DISCO_PUB, &disco_public);
        size_t os_len = sizeof(stored_os);
        err = nvs_get_str(nvs, ML_NVS_KEY_OS, stored_os, &os_len);
        os = ml_register_kept(err, os_len, 0);
        nvs_close(nvs);
    } else if (err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGE(TAG, "The keys cannot be read: NVS does not open (%s)", esp_err_to_name(err));
        return err;
    }

    const ml_identity_plan_t plan =
        ml_register_identity_plan(machine, wg, disco, os, stored_os, configured_os, unstored_os);
    if (plan.fail) {
        ESP_LOGE(TAG,
                 "NVS holds an identity it cannot give (machine key: %s, node key: %s, "
                 "DISCO key: %s, OS: %s): nothing is written, and the node does not start",
                 kept_str(machine), kept_str(wg), kept_str(disco), kept_str(os));
        return ESP_ERR_INVALID_STATE;
    }

    key_pair(plan.make_machine, id->machine_private, id->machine_public, "machine");
    key_pair(plan.make_wg, id->wg_private, id->wg_public, "WireGuard");
    key_pair(plan.make_disco, id->disco_private, id->disco_public, "DISCO");
    compare_public_key(&machine_public, plan.make_machine, id->machine_public, "machine");
    compare_public_key(&wg_public, plan.make_wg, id->wg_public, "WireGuard");
    compare_public_key(&disco_public, plan.make_disco, id->disco_public, "DISCO");
    snprintf(id->os, id->os_size, "%s", plan.os);
    ESP_LOGI(TAG, "Reports OS \"%s\": %s", id->os,
             plan.store_os        ? "the build's, stored with its new machine key"
             : os == ML_KEPT_FOUND && stored_os[0] ? "stored with its machine key"
                                  : "none is stored with its machine key (ML_HOSTINFO_OS_UNSTORED)");

    if (!ml_register_identity_saves(&plan)) {
        ESP_LOGI(TAG, "Keys loaded from NVS");
        return ESP_OK;
    }

    err = nvs_open(ML_NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "The new keys are not saved: NVS does not open (%s); the node does not start",
                 esp_err_to_name(err));
        return err;
    }
    identity_save_t save = {.nvs = nvs, .id = id};
    const bool saved = ml_register_identity_save(&plan, identity_write, &save);
    nvs_close(nvs);
    if (!saved) {
        ESP_LOGE(TAG, "The new keys are not saved: write %d failed (%s); the node does not start",
                 (int)save.failed, esp_err_to_name(save.err));
        return save.err;
    }
    ESP_LOGI(TAG, "Keys saved to NVS");
    return ESP_OK;
}
