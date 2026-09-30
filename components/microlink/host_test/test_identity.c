/*
 * Host tests of a node's identity as NVS keeps it (ml_identity.c): the
 * load, against an NVS of this file's own — what it reads, what it makes,
 * what it writes and in which order, and that it writes nothing at all when
 * NVS holds the keys, whole or not.
 * Run by run.sh with the host's C compiler.
 */
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "ml_identity.h"
#include "nvs.h"
#include "x25519.h"

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

/* ---- an NVS of the test's own ------------------------------------------- */

#define ENTRIES 12
#define RO 1u
#define RW 2u

typedef struct {
    char key[16];
    bool present;
    uint8_t data[40];
    size_t len;          /* a string's counts its NUL, as NVS counts it */
    esp_err_t read_err;  /* what a read of it returns instead, if not ESP_OK */
} entry_t;

static struct {
    bool has_namespace;
    entry_t entries[ENTRIES];
    esp_err_t open_ro_err;
    esp_err_t open_rw_err;
    int fail_write;      /* the write that fails, from 0; -1 for none */
    /* What the load did */
    int ro_opens;
    int rw_opens;
    int writes;
    char written[ENTRIES][16];
    bool committed;
    int open_handles;
} nvs;

static int errors_logged;

void ml_host_log(char level, const char *tag, const char *format, ...) {
    (void)tag;
    (void)format;
    if (level == 'E') errors_logged++;
}

const char *esp_err_to_name(esp_err_t err) {
    return err == ESP_OK ? "ESP_OK" : "an error";
}

/* Not random: each key made is different, and the same in every run */
static uint8_t next_byte = 1;

void esp_fill_random(void *buf, size_t len) {
    memset(buf, next_byte++, len);
}

static entry_t *find(const char *key) {
    for (int i = 0; i < ENTRIES; i++) {
        if (nvs.entries[i].key[0] && strcmp(nvs.entries[i].key, key) == 0) return &nvs.entries[i];
    }
    return NULL;
}

static entry_t *slot(const char *key) {
    entry_t *e = find(key);
    for (int i = 0; !e && i < ENTRIES; i++) {
        if (!nvs.entries[i].key[0]) {
            e = &nvs.entries[i];
            snprintf(e->key, sizeof e->key, "%s", key);
        }
    }
    return e;
}

static void put(const char *key, const void *data, size_t len) {
    entry_t *e = slot(key);
    e->present = true;
    e->len = len;
    memcpy(e->data, data, len);
    nvs.has_namespace = true;
}

esp_err_t nvs_open(const char *name_space, nvs_open_mode_t mode, nvs_handle_t *handle) {
    CHECK(strcmp(name_space, ML_NVS_NAMESPACE) == 0, "namespace %s", name_space);
    if (mode == NVS_READONLY) {
        nvs.ro_opens++;
        if (nvs.open_ro_err != ESP_OK) return nvs.open_ro_err;
        if (!nvs.has_namespace) return ESP_ERR_NVS_NOT_FOUND;
        *handle = RO;
    } else {
        nvs.rw_opens++;
        if (nvs.open_rw_err != ESP_OK) return nvs.open_rw_err;
        nvs.has_namespace = true;
        *handle = RW;
    }
    nvs.open_handles++;
    return ESP_OK;
}

void nvs_close(nvs_handle_t handle) {
    (void)handle;
    nvs.open_handles--;
}

static esp_err_t get(const char *key, void *out, size_t *len) {
    const entry_t *e = find(key);
    if (e && e->read_err != ESP_OK) return e->read_err;
    if (!e || !e->present) return ESP_ERR_NVS_NOT_FOUND;
    if (e->len > *len) return ESP_ERR_NVS_INVALID_LENGTH;
    memcpy(out, e->data, e->len);
    *len = e->len;
    return ESP_OK;
}

esp_err_t nvs_get_blob(nvs_handle_t handle, const char *key, void *out, size_t *len) {
    (void)handle;
    return get(key, out, len);
}

esp_err_t nvs_get_str(nvs_handle_t handle, const char *key, char *out, size_t *len) {
    (void)handle;
    return get(key, out, len);
}

/* One write: counted, in order, and failing when it is the one to fail */
static bool write_allowed(nvs_handle_t handle, const char *what) {
    CHECK(handle == RW, "%s written through a handle that cannot write", what);
    snprintf(nvs.written[nvs.writes < ENTRIES ? nvs.writes : ENTRIES - 1], 16, "%s", what);
    return nvs.writes++ != nvs.fail_write;
}

esp_err_t nvs_set_blob(nvs_handle_t handle, const char *key, const void *value, size_t len) {
    if (!write_allowed(handle, key)) return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
    put(key, value, len);
    return ESP_OK;
}

esp_err_t nvs_set_str(nvs_handle_t handle, const char *key, const char *value) {
    if (!write_allowed(handle, key)) return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
    put(key, value, strlen(value) + 1);
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char *key) {
    if (!write_allowed(handle, key)) return ESP_FAIL;
    entry_t *e = find(key);
    if (!e || !e->present) return ESP_ERR_NVS_NOT_FOUND;
    e->present = false;
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t handle) {
    if (!write_allowed(handle, "commit")) return ESP_FAIL;
    nvs.committed = true;
    return ESP_OK;
}

/* ---- the node ---------------------------------------------------------------- */

static struct {
    uint8_t machine_private[32], machine_public[32];
    uint8_t wg_private[32], wg_public[32];
    uint8_t disco_private[32], disco_public[32];
    char os[32];
} node;

static esp_err_t load(void) {
    memset(&node, 0xee, sizeof node);
    nvs.ro_opens = nvs.rw_opens = nvs.writes = 0;
    nvs.committed = false;
    memset(nvs.written, 0, sizeof nvs.written);
    errors_logged = 0;
    const ml_identity_t id = {
        .machine_private = node.machine_private,
        .machine_public = node.machine_public,
        .wg_private = node.wg_private,
        .wg_public = node.wg_public,
        .disco_private = node.disco_private,
        .disco_public = node.disco_public,
        .os = node.os,
        .os_size = sizeof node.os,
    };
    const esp_err_t err = ml_identity_load(&id, "freertos", "linux");
    CHECK(nvs.open_handles == 0, "%d handles left open", nvs.open_handles);
    return err;
}

static const char *const PRIVATE[3] = {ML_NVS_KEY_MACHINE_PRI, ML_NVS_KEY_WG_PRI, ML_NVS_KEY_DISCO_PRI};
static const char *const PUBLIC[3] = {ML_NVS_KEY_MACHINE_PUB, ML_NVS_KEY_WG_PUB, ML_NVS_KEY_DISCO_PUB};

/* A key as a node stores one: clamped, and its public half */
static void a_key(uint8_t seed, uint8_t private_key[32], uint8_t public_key[32]) {
    memset(private_key, seed, 32);
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    x25519_base(public_key, private_key, 1);
}

/* An NVS that holds an enrolled node: three key pairs, an authorisation,
 * and no OS — as a build before the OS was stored left it */
static void enrolled(void) {
    memset(&nvs, 0, sizeof nvs);
    nvs.fail_write = -1;
    for (int k = 0; k < 3; k++) {
        uint8_t private_key[32];
        uint8_t public_key[32];
        a_key((uint8_t)(0x41 + k), private_key, public_key);
        put(PRIVATE[k], private_key, 32);
        put(PUBLIC[k], public_key, 32);
    }
    put(ML_NVS_KEY_AUTHORIZED, "\x01", 1);
}

static void empty(void) {
    memset(&nvs, 0, sizeof nvs);
    nvs.fail_write = -1;
}

static bool holds(const char *key, const void *data, size_t len) {
    const entry_t *e = find(key);
    return e && e->present && e->len == len && memcmp(e->data, data, len) == 0;
}

/* What NVS holds, to see that a load left it as it was */
static entry_t before[ENTRIES];

static void remember(void) {
    memcpy(before, nvs.entries, sizeof before);
}

static bool untouched(void) {
    return memcmp(before, nvs.entries, sizeof before) == 0 && nvs.writes == 0 &&
           nvs.rw_opens == 0 && !nvs.committed;
}

static void an_enrolled_node_is_read_and_never_written(void) {
    enrolled();
    remember();
    CHECK(load() == ESP_OK, "an enrolled node loads");
    CHECK(untouched(), "it is written: %d writes, %d read-write opens", nvs.writes, nvs.rw_opens);
    CHECK(nvs.ro_opens == 1, "read-only opens: %d", nvs.ro_opens);
    /* Its keys are the ones NVS holds, the public halves derived */
    CHECK(holds(PRIVATE[0], node.machine_private, 32) && holds(PUBLIC[0], node.machine_public, 32),
          "machine key");
    CHECK(holds(PRIVATE[1], node.wg_private, 32) && holds(PUBLIC[1], node.wg_public, 32), "node key");
    CHECK(holds(PRIVATE[2], node.disco_private, 32) && holds(PUBLIC[2], node.disco_public, 32),
          "DISCO key");
    /* No OS stored: the one such keys report, and none is stored now */
    CHECK(strcmp(node.os, "linux") == 0, "reports %s", node.os);
    CHECK(!find(ML_NVS_KEY_OS), "an OS is stored");
    CHECK(errors_logged == 0, "%d errors logged", errors_logged);
    /* An OS stored with them is the one reported, whatever the build's */
    put(ML_NVS_KEY_OS, "zephyr", 7);
    remember();
    CHECK(load() == ESP_OK && strcmp(node.os, "zephyr") == 0, "stored OS: %s", node.os);
    CHECK(untouched(), "written with a stored OS");
    /* An OS stored empty is none stored */
    put(ML_NVS_KEY_OS, "", 1);
    remember();
    CHECK(load() == ESP_OK && strcmp(node.os, "linux") == 0, "empty OS: %s", node.os);
    CHECK(untouched(), "written with an empty OS");
}

static void what_nvs_cannot_give_fails_the_start_and_nothing_is_written(void) {
    static const uint8_t junk[33] = {7};
    /* Each private key: an NVS error, a key cut short, a key too long */
    for (int k = 0; k < 3; k++) {
        for (int how = 0; how < 4; how++) {
            enrolled();
            entry_t *e = find(PRIVATE[k]);
            switch (how) {
            case 0: e->read_err = ESP_FAIL; break;
            case 1: e->read_err = ESP_ERR_NVS_NOT_INITIALIZED; break;
            case 2: put(PRIVATE[k], junk, 31); break;
            case 3: put(PRIVATE[k], junk, 33); break;
            }
            remember();
            CHECK(load() != ESP_OK, "key %d, case %d: the start goes on", k, how);
            CHECK(untouched(), "key %d, case %d: %d writes, %d read-write opens", k, how, nvs.writes,
                  nvs.rw_opens);
            CHECK(errors_logged == 1, "key %d, case %d: %d errors logged", k, how, errors_logged);
        }
    }
    /* The OS: an NVS error, and one too long to be one this node stored */
    enrolled();
    put(ML_NVS_KEY_OS, "freertos", 9);
    find(ML_NVS_KEY_OS)->read_err = ESP_FAIL;
    remember();
    CHECK(load() != ESP_OK && untouched(), "an unreadable OS");
    enrolled();
    put(ML_NVS_KEY_OS, "an-operating-system-with-a-long-name", 37);
    remember();
    CHECK(load() != ESP_OK && untouched(), "an OS longer than any stored");
    /* NVS itself: not opening for anything but "no such namespace" */
    enrolled();
    nvs.open_ro_err = ESP_ERR_NVS_NOT_INITIALIZED;
    remember();
    CHECK(load() == ESP_ERR_NVS_NOT_INITIALIZED && untouched(), "NVS does not open");
    /* A key unreadable beside keys absent: still nothing is made */
    empty();
    put(PRIVATE[1], junk, 31);
    remember();
    CHECK(load() != ESP_OK && untouched(), "a short key among absent ones");
}

/* The writes of the last load, as one string */
static const char *order(void) {
    static char text[ENTRIES * 17];
    text[0] = '\0';
    for (int i = 0; i < nvs.writes && i < ENTRIES; i++) {
        strcat(text, nvs.written[i]);
        strcat(text, " ");
    }
    return text;
}

static void a_new_node_is_made_and_saved_whole(void) {
    empty();
    CHECK(load() == ESP_OK, "a new node loads");
    CHECK(nvs.ro_opens == 1 && nvs.rw_opens == 1, "opens: %d, %d", nvs.ro_opens, nvs.rw_opens);
    CHECK(strcmp(order(), "authorized hostinfo_os machine_pub machine_pri wg_public wg_private "
                          "disco_pub disco_pri commit ") == 0,
          "writes: %s", order());
    CHECK(nvs.committed, "not committed");
    CHECK(strcmp(node.os, "freertos") == 0 && holds(ML_NVS_KEY_OS, "freertos", 9), "OS %s", node.os);
    CHECK(holds(PRIVATE[0], node.machine_private, 32) && holds(PUBLIC[0], node.machine_public, 32) &&
              holds(PRIVATE[1], node.wg_private, 32) && holds(PUBLIC[1], node.wg_public, 32) &&
              holds(PRIVATE[2], node.disco_private, 32) && holds(PUBLIC[2], node.disco_public, 32),
          "the keys kept are not the keys made");
    CHECK(memcmp(node.machine_private, node.wg_private, 32) != 0, "one key made twice");
    uint8_t derived[32];
    x25519_base(derived, node.wg_private, 1);
    CHECK(memcmp(derived, node.wg_public, 32) == 0, "a public half that is not its private half's");
    /* The start after: the same node, read, and nothing written */
    uint8_t node_key[32];
    memcpy(node_key, node.wg_public, 32);
    remember();
    CHECK(load() == ESP_OK && untouched(), "the next start writes");
    CHECK(memcmp(node_key, node.wg_public, 32) == 0, "the node key changed");
    CHECK(strcmp(node.os, "freertos") == 0, "the next start reports %s", node.os);
}

static void a_missing_key_is_made_and_the_others_left(void) {
    static const char *const want[3] = {
        "authorized hostinfo_os machine_pub machine_pri commit ",
        "authorized wg_public wg_private commit ",
        "authorized disco_pub disco_pri commit ",
    };
    for (int k = 0; k < 3; k++) {
        enrolled();
        find(PRIVATE[k])->present = false;
        remember();
        CHECK(load() == ESP_OK, "key %d absent: the start fails", k);
        CHECK(strcmp(order(), want[k]) == 0, "key %d absent: writes %s", k, order());
        for (int other = 0; other < 3; other++) {
            if (other == k) continue;
            const entry_t *was = &before[find(PRIVATE[other]) - nvs.entries];
            CHECK(holds(PRIVATE[other], was->data, 32), "key %d absent: key %d rewritten", k, other);
        }
        /* The authorisation was the old keys' */
        CHECK(!find(ML_NVS_KEY_AUTHORIZED)->present, "key %d absent: still authorised", k);
        CHECK(strcmp(node.os, k == 0 ? "freertos" : "linux") == 0, "key %d absent: OS %s", k, node.os);
    }
}

static void a_save_that_fails_fails_the_start(void) {
    for (int fail = 0; fail < 9; fail++) {
        empty();
        nvs.fail_write = fail;
        CHECK(load() != ESP_OK, "write %d fails: the start goes on", fail);
        CHECK(nvs.writes == fail + 1, "write %d fails: %d writes", fail, nvs.writes);
        CHECK(!nvs.committed, "write %d fails: committed", fail);
        CHECK(errors_logged == 1, "write %d fails: %d errors logged", fail, errors_logged);
        /* A machine key NVS holds after it has its OS beside it */
        const entry_t *machine = find(PRIVATE[0]);
        CHECK(!(machine && machine->present) || holds(ML_NVS_KEY_OS, "freertos", 9),
              "write %d fails: a machine key without its OS", fail);
    }
    /* A handle that can write does not open: nothing is saved, the start fails */
    empty();
    nvs.open_rw_err = ESP_ERR_NVS_NOT_ENOUGH_SPACE;
    CHECK(load() == ESP_ERR_NVS_NOT_ENOUGH_SPACE && nvs.writes == 0, "no read-write handle");
}

int main(void) {
    an_enrolled_node_is_read_and_never_written();
    what_nvs_cannot_give_fails_the_start_and_nothing_is_written();
    a_new_node_is_made_and_saved_whole();
    a_missing_key_is_made_and_the_others_left();
    a_save_that_fails_fails_the_start();
    if (failures) {
        printf("%d failed\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
