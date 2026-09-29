/**
 * @file microlink.c
 * @brief MicroLink v2 - Public API and Task Orchestration
 *
 * Creates all FreeRTOS tasks, queues, and event groups.
 * Provides the public API that the application calls.
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "cJSON.h"
#include "mbedtls/platform_util.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include "lwip/sockets.h"

#ifdef CONFIG_ML_ENABLE_CELLULAR
#include "ml_cellular.h"
#endif

static const char *TAG = "microlink";

/* NVS keys */
#define NVS_NAMESPACE       "microlink"
#define NVS_KEY_MACHINE_PRI "machine_pri"
#define NVS_KEY_MACHINE_PUB "machine_pub"
#define NVS_KEY_WG_PRI      "wg_private"
#define NVS_KEY_WG_PUB      "wg_public"
#define NVS_KEY_DISCO_PRI   "disco_pri"
#define NVS_KEY_DISCO_PUB   "disco_pub"
#define NVS_KEY_AUTHORIZED  "authorized"   /* u8 1: a registration was authorised */

/* X25519 from x25519.h */
#include "x25519.h"

/* ============================================================================
 * Key Management (loaded once at init, read-only after)
 * ========================================================================== */

static void generate_keypair(uint8_t *private_key, uint8_t *public_key) {
    esp_fill_random(private_key, 32);
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    x25519_base(public_key, private_key, 1);
}

static esp_err_t load_or_generate_keys(microlink_t *ml) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "NVS open failed (%d), generating ephemeral keys", err);
        generate_keypair(ml->machine_private_key, ml->machine_public_key);
        generate_keypair(ml->wg_private_key, ml->wg_public_key);
        generate_keypair(ml->disco_private_key, ml->disco_public_key);
        return ESP_OK;
    }

    size_t key_len = 32;
    bool need_save = false;

    /* Machine key */
    if (nvs_get_blob(nvs, NVS_KEY_MACHINE_PRI, ml->machine_private_key, &key_len) != ESP_OK) {
        generate_keypair(ml->machine_private_key, ml->machine_public_key);
        need_save = true;
        ESP_LOGI(TAG, "Generated new machine key");
    } else {
        key_len = 32;
        nvs_get_blob(nvs, NVS_KEY_MACHINE_PUB, ml->machine_public_key, &key_len);
    }

    /* WireGuard key */
    key_len = 32;
    if (nvs_get_blob(nvs, NVS_KEY_WG_PRI, ml->wg_private_key, &key_len) != ESP_OK) {
        generate_keypair(ml->wg_private_key, ml->wg_public_key);
        need_save = true;
        ESP_LOGI(TAG, "Generated new WireGuard key");
    } else {
        key_len = 32;
        nvs_get_blob(nvs, NVS_KEY_WG_PUB, ml->wg_public_key, &key_len);
    }

    /* DISCO key */
    key_len = 32;
    if (nvs_get_blob(nvs, NVS_KEY_DISCO_PRI, ml->disco_private_key, &key_len) != ESP_OK) {
        generate_keypair(ml->disco_private_key, ml->disco_public_key);
        need_save = true;
        ESP_LOGI(TAG, "Generated new DISCO key");
    } else {
        key_len = 32;
        nvs_get_blob(nvs, NVS_KEY_DISCO_PUB, ml->disco_public_key, &key_len);
    }

    if (need_save) {
        nvs_set_blob(nvs, NVS_KEY_MACHINE_PRI, ml->machine_private_key, 32);
        nvs_set_blob(nvs, NVS_KEY_MACHINE_PUB, ml->machine_public_key, 32);
        nvs_set_blob(nvs, NVS_KEY_WG_PRI, ml->wg_private_key, 32);
        nvs_set_blob(nvs, NVS_KEY_WG_PUB, ml->wg_public_key, 32);
        nvs_set_blob(nvs, NVS_KEY_DISCO_PRI, ml->disco_private_key, 32);
        nvs_set_blob(nvs, NVS_KEY_DISCO_PUB, ml->disco_public_key, 32);
        /* New keys: whatever was authorised was the old ones */
        nvs_erase_key(nvs, NVS_KEY_AUTHORIZED);
        nvs_commit(nvs);
        ESP_LOGI(TAG, "Keys saved to NVS");
    } else {
        ESP_LOGI(TAG, "Keys loaded from NVS");
    }

    nvs_close(nvs);
    return ESP_OK;
}

/* ============================================================================
 * Identity: keys the control server has authorised
 * ========================================================================== */

void ml_identity_authorized(bool authorized) {
    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs) != ESP_OK) {
        return;
    }
    uint8_t held = 0;
    const bool was = nvs_get_u8(nvs, NVS_KEY_AUTHORIZED, &held) == ESP_OK && held == 1;
    esp_err_t err = ESP_OK;
    if (authorized && !was) {
        err = nvs_set_u8(nvs, NVS_KEY_AUTHORIZED, 1);
    } else if (!authorized && was) {
        err = nvs_erase_key(nvs, NVS_KEY_AUTHORIZED);
    }
    if (err == ESP_OK && authorized != was) {
        err = nvs_commit(nvs);
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Authorisation not recorded: %s", esp_err_to_name(err));
    }
    nvs_close(nvs);
}

bool microlink_has_machine_key(void) {
    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) {
        return false;
    }
    size_t key_len = 0;
    const bool has = nvs_get_blob(nvs, NVS_KEY_MACHINE_PRI, NULL, &key_len) == ESP_OK && key_len == 32;
    nvs_close(nvs);
    return has;
}

bool microlink_has_identity(void) {
    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) {
        return false;
    }
    size_t key_len = 0;
    uint8_t authorized = 0;
    const bool has = nvs_get_blob(nvs, NVS_KEY_MACHINE_PRI, NULL, &key_len) == ESP_OK &&
                     key_len == 32 &&
                     nvs_get_u8(nvs, NVS_KEY_AUTHORIZED, &authorized) == ESP_OK &&
                     authorized == 1;
    nvs_close(nvs);
    return has;
}

/* ============================================================================
 * cJSON PSRAM Hooks
 * ========================================================================== */

static void *cjson_psram_malloc(size_t size) {
    return ml_psram_malloc(size);
}

/* ============================================================================
 * Factory Reset
 * ========================================================================== */

esp_err_t microlink_factory_reset(void) {
    /* Erase key namespace */
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        err = nvs_erase_all(nvs);
        if (err == ESP_OK) {
            err = nvs_commit(nvs);
        }
        nvs_close(nvs);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Factory reset: keys not erased: %s", esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "Factory reset: keys erased");

    /* Erase cached peers */
    err = ml_peer_nvs_init();
    if (err == ESP_OK) {
        err = ml_peer_nvs_clear();
        ml_peer_nvs_deinit();
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Factory reset: cached peers not erased: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "Factory reset complete");
    return ESP_OK;
}

/* ============================================================================
 * Public API
 * ========================================================================== */

/* Empty a queue of received packets, freeing each one's data */
static void drain_rx_queue(QueueHandle_t q) {
    ml_rx_packet_t pkt;
    while (xQueueReceive(q, &pkt, 0) == pdTRUE) {
        free(pkt.data);
    }
}

/* Release what an instance holds, each part only if it was made, then wipe
 * the whole instance — its private keys and its auth key among it — and free
 * it: the end of microlink_destroy, and every way out of a microlink_init
 * that failed. */
static void instance_free(microlink_t *ml) {
    if (ml->peer_nvs_open) {
        ml_peer_nvs_deinit();
    }
    if (ml->config_httpd) {
        ml_config_httpd_deinit(ml->config_httpd);
    }
    /* The queues, and what is still in them: the tasks that would have
     * taken it have exited, and each item's data is the heap's */
    if (ml->derp_tx_queue) {
        ml_derp_tx_item_t item;
        while (xQueueReceive(ml->derp_tx_queue, &item, 0) == pdTRUE) {
            free(item.data);
        }
        vQueueDelete(ml->derp_tx_queue);
    }
    if (ml->disco_rx_queue) {
        drain_rx_queue(ml->disco_rx_queue);
        vQueueDelete(ml->disco_rx_queue);
    }
    if (ml->wg_rx_queue) {
        drain_rx_queue(ml->wg_rx_queue);
        vQueueDelete(ml->wg_rx_queue);
    }
    if (ml->stun_rx_queue) {
        drain_rx_queue(ml->stun_rx_queue);
        vQueueDelete(ml->stun_rx_queue);
    }
    if (ml->coord_cmd_queue) vQueueDelete(ml->coord_cmd_queue);
    if (ml->peer_update_queue) {
        ml_peer_update_t *update;
        while (xQueueReceive(ml->peer_update_queue, &update, 0) == pdTRUE) {
            free(update);
        }
        vQueueDelete(ml->peer_update_queue);
    }
    if (ml->events) vEventGroupDelete(ml->events);
    if (ml->task_exited) vSemaphoreDelete(ml->task_exited);
    if (ml->auth_lock) vSemaphoreDelete(ml->auth_lock);
    if (ml->peers_lock) vSemaphoreDelete(ml->peers_lock);
    mbedtls_platform_zeroize(ml, sizeof(*ml));
    free(ml);
}

microlink_t *microlink_init(const microlink_config_t *config) {
    if (!config || !config->auth_key) {
        ESP_LOGE(TAG, "Invalid config: auth_key required");
        return NULL;
    }
    if (strlen(config->auth_key) >= ML_AUTH_KEY_MAX) {
        ESP_LOGE(TAG, "Invalid config: auth_key longer than %d bytes", ML_AUTH_KEY_MAX - 1);
        return NULL;
    }

    /* Route cJSON to PSRAM */
    cJSON_Hooks hooks = {
        .malloc_fn = cjson_psram_malloc,
        .free_fn = free
    };
    cJSON_InitHooks(&hooks);

    /* Allocate context from PSRAM */
    microlink_t *ml = ml_psram_calloc(1, sizeof(microlink_t));
    if (!ml) {
        ESP_LOGE(TAG, "Failed to allocate context");
        return NULL;
    }

    /* Copy config — the auth key into the instance's own copy, the one it
     * reads from now on (microlink_set_auth_key replaces it) */
    ml->config = *config;
    strcpy(ml->auth_key, config->auth_key);
    ml->config.auth_key = NULL;
    if (ml->config.max_peers == 0) ml->config.max_peers = ML_MAX_PEERS;
    if (ml->config.max_peers > ML_MAX_PEERS) ml->config.max_peers = ML_MAX_PEERS;
    ml->config.enable_derp = true;  /* Always need DERP for relay */

    ml->state = ML_STATE_IDLE;
    ml->coord_sock = -1;
    ml->disco_sock4 = -1;
    ml->disco_sock6 = -1;
    ml->stun_sock = -1;
    ml->stun_sock6 = -1;
    ml->derp.sockfd = -1;

    /* Resolve timing (0 = use defaults from #defines) */
    ml->t_disco_heartbeat_ms = ml->config.disco_heartbeat_ms ? ml->config.disco_heartbeat_ms : ML_DISCO_HEARTBEAT_MS;
    ml->t_stun_interval_ms = ml->config.stun_interval_ms ? ml->config.stun_interval_ms : ML_STUN_RESTUN_INTERVAL_MS;
    ml->t_ctrl_watchdog_ms = ml->config.ctrl_watchdog_ms ? ml->config.ctrl_watchdog_ms : ML_CTRL_WATCHDOG_MS;

    /* Apply Kconfig priority peer if set and app didn't provide one */
    if (ml->config.priority_peer_ip == 0 && strlen(CONFIG_ML_PRIORITY_PEER_IP) > 0) {
        ml->config.priority_peer_ip = microlink_parse_ip(CONFIG_ML_PRIORITY_PEER_IP);
        if (ml->config.priority_peer_ip) {
            ESP_LOGI(TAG, "Priority peer from Kconfig: %s", CONFIG_ML_PRIORITY_PEER_IP);
        }
    }

    /* Load or generate persistent keys */
    if (load_or_generate_keys(ml) != ESP_OK) {
        instance_free(ml);
        return NULL;
    }

    /* Initialize peer NVS cache */
    ml_peer_nvs_init();
    ml->peer_nvs_open = true;

    /* Initialize HTTP config server (loads NVS peer allowlist + settings) */
    ml->config_httpd = ml_config_httpd_init();

    /* Override config with NVS-saved settings (web UI save → restart flow).
     * NVS settings take priority over Kconfig defaults.  Strings are copied
     * into ml->nvs_* buffers so the const char* pointers remain valid. */
    if (ml->config_httpd) {
        const char *nvs_auth = ml_config_get_auth_key(ml->config_httpd);
        if (nvs_auth) {
            mbedtls_platform_zeroize(ml->auth_key, sizeof(ml->auth_key));
            ml_copy_name(ml->auth_key, sizeof(ml->auth_key), nvs_auth);
            ESP_LOGI(TAG, "Auth key overridden from NVS (len=%d)", (int)strlen(nvs_auth));
        }
        /* Device name: full name takes priority, then prefix+MAC, then Kconfig */
        const char *nvs_full_name = ml_config_get_device_name_full(ml->config_httpd);
        if (nvs_full_name) {
            /* Full custom hostname (e.g. "sensor-tailscale") */
            strncpy(ml->nvs_device_name, nvs_full_name, sizeof(ml->nvs_device_name) - 1);
            ml->config.device_name = ml->nvs_device_name;
            ESP_LOGI(TAG, "Device name from NVS (full): %s", ml->nvs_device_name);
        } else {
            const char *nvs_prefix = ml_config_get_device_prefix(ml->config_httpd);
            if (nvs_prefix) {
                /* Device name = prefix + MAC suffix (e.g. "sensor-a1b2c3") */
                uint8_t mac[6];
                esp_read_mac(mac, ESP_MAC_WIFI_STA);
                snprintf(ml->nvs_device_name, sizeof(ml->nvs_device_name),
                         "%s-%02x%02x%02x", nvs_prefix, mac[3], mac[4], mac[5]);
                ml->config.device_name = ml->nvs_device_name;
                ESP_LOGI(TAG, "Device name from NVS (prefix): %s", ml->nvs_device_name);
            }
        }

        /* v2 overrides */
        uint8_t nvs_max = ml_config_get_max_peers(ml->config_httpd);
        if (nvs_max > 0 && nvs_max <= ML_MAX_PEERS) {
            ml->config.max_peers = nvs_max;
            ESP_LOGI(TAG, "Max peers overridden from NVS: %d", nvs_max);
        }
        uint16_t nvs_hb = ml_config_get_disco_heartbeat_ms(ml->config_httpd);
        if (nvs_hb > 0 && nvs_hb <= 60000) {
            ml->config.disco_heartbeat_ms = nvs_hb;
            ml->t_disco_heartbeat_ms = nvs_hb;
            ESP_LOGI(TAG, "DISCO heartbeat overridden from NVS: %dms", nvs_hb);
        }
        uint32_t nvs_pip = ml_config_get_priority_peer_ip(ml->config_httpd);
        if (nvs_pip > 0) {
            ml->config.priority_peer_ip = nvs_pip;
            char pip_str[16];
            microlink_ip_to_str(nvs_pip, pip_str);
            ESP_LOGI(TAG, "Priority peer overridden from NVS: %s", pip_str);
        }
        const char *nvs_ctrl = ml_config_get_ctrl_host(ml->config_httpd);
        if (nvs_ctrl) {
            strncpy(ml->ctrl_host, nvs_ctrl, sizeof(ml->ctrl_host) - 1);
            ESP_LOGI(TAG, "Control plane overridden from NVS: %s", ml->ctrl_host);
        }
        ml->debug_flags = ml_config_get_debug_flags(ml->config_httpd);
        if (ml->debug_flags) {
            ESP_LOGI(TAG, "Debug flags from NVS: 0x%02x", ml->debug_flags);
        }
    }

    /* Create event group */
    ml->events = xEventGroupCreate();
    if (!ml->events) {
        ESP_LOGE(TAG, "Failed to create event group");
        instance_free(ml);
        return NULL;
    }

    /* Counts the tasks that have exited, for stop */
    ml->task_exited = xSemaphoreCreateCounting(4, 0);
    if (!ml->task_exited) {
        ESP_LOGE(TAG, "Failed to create task exit semaphore");
        instance_free(ml);
        return NULL;
    }

    /* Guards the auth key between a registration and microlink_set_auth_key */
    ml->auth_lock = xSemaphoreCreateMutex();
    if (!ml->auth_lock) {
        ESP_LOGE(TAG, "Failed to create auth key lock");
        instance_free(ml);
        return NULL;
    }

    /* Guards the peer table between the WG manager and its readers */
    ml->peers_lock = xSemaphoreCreateMutex();
    if (!ml->peers_lock) {
        ESP_LOGE(TAG, "Failed to create peer table lock");
        instance_free(ml);
        return NULL;
    }

    /* Create queues */
    ml->derp_tx_queue = xQueueCreate(ML_DERP_TX_QUEUE_DEPTH, sizeof(ml_derp_tx_item_t));
    ml->disco_rx_queue = xQueueCreate(ML_DISCO_RX_QUEUE_DEPTH, sizeof(ml_rx_packet_t));
    ml->wg_rx_queue = xQueueCreate(ML_WG_RX_QUEUE_DEPTH, sizeof(ml_rx_packet_t));
    ml->stun_rx_queue = xQueueCreate(ML_STUN_RX_QUEUE_DEPTH, sizeof(ml_rx_packet_t));
    ml->coord_cmd_queue = xQueueCreate(ML_COORD_CMD_QUEUE_DEPTH, sizeof(ml_coord_cmd_t));
    ml->peer_update_queue = xQueueCreate(ML_PEER_UPDATE_QUEUE_DEPTH, sizeof(ml_peer_update_t *));

    if (!ml->derp_tx_queue || !ml->disco_rx_queue || !ml->wg_rx_queue ||
        !ml->stun_rx_queue || !ml->coord_cmd_queue || !ml->peer_update_queue) {
        ESP_LOGE(TAG, "Failed to create queues");
        instance_free(ml);
        return NULL;
    }

    ESP_LOGI(TAG, "MicroLink v2 initialized (max_peers=%d)", ml->config.max_peers);
    return ml;
}

esp_err_t microlink_start(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;
    if (ml->stopped) {
        /* Its shutdown bit, queues and sockets are what a stop left: an
         * instance starts once */
        ESP_LOGW(TAG, "Stopped: destroy this instance and init another");
        return ESP_ERR_INVALID_STATE;
    }
    if (ml->state != ML_STATE_IDLE) {
        ESP_LOGW(TAG, "Already started (state=%d)", ml->state);
        return ESP_ERR_INVALID_STATE;
    }

    ml->state = ML_STATE_WIFI_WAIT;

    /* Set WiFi TX power if configured */
    if (ml->config.wifi_tx_power_dbm > 0) {
        int8_t power_quarter_dbm = ml->config.wifi_tx_power_dbm * 4;
        esp_wifi_set_max_tx_power(power_quarter_dbm);
        ESP_LOGI(TAG, "WiFi TX power set to %d dBm", ml->config.wifi_tx_power_dbm);
    }

#ifdef CONFIG_ML_ZERO_COPY_WG
    /* Zero-copy mode: raw lwIP PCB replaces BSD socket for DISCO/WG UDP.
     * WG packets go directly to wireguardif_network_rx() from tcpip_thread.
     * DISCO packets go to SPSC ring buffer, STUN to existing queue. */
    if (ml_zerocopy_init(ml) != ESP_OK) {
        ESP_LOGE(TAG, "Zero-copy init failed, falling back to BSD socket");
        goto bsd_socket_fallback;
    }
    ESP_LOGI(TAG, "Zero-copy WG mode active (high-throughput)");
    goto skip_bsd_socket;

bsd_socket_fallback:
#endif
    /* Create DISCO/magicsock UDP socket (port 51820 = WireGuard standard)
     * This is the single socket for ALL direct UDP traffic: DISCO pings/pongs,
     * CallMeMaybe probes, and WireGuard encrypted data.
     * Matches v1 microlink_disco_init() and tailscale's pconn4. */
    ml->disco_sock4 = ml_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ml->disco_sock4 >= 0) {
        struct sockaddr_in bind_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(51820),
            .sin_addr.s_addr = INADDR_ANY,
        };
        if (ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            ESP_LOGW(TAG, "Failed to bind port 51820 (errno=%d), trying ephemeral", errno);
            bind_addr.sin_port = 0;
            ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
        }

        /* Mark packets as DSCP 46 (Expedited Forwarding) → WMM AC_VO.
         * WiFi APs with WMM use shorter contention windows for voice-priority
         * traffic, reducing jitter on WireGuard/DISCO UDP packets. */
        int tos = 0xB8;  /* DSCP 46 = EF, TOS byte = 46 << 2 = 184 */
        setsockopt(ml->disco_sock4, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

        /* Set non-blocking for select() in net_io */
        int flags = ml_fcntl(ml->disco_sock4, F_GETFL, 0);
        ml_fcntl(ml->disco_sock4, F_SETFL, flags | O_NONBLOCK);

        /* Record the actual bound port (getsockname not wrapped — AT sockets use stored port) */
        struct sockaddr_in local_addr;
        socklen_t addr_len = sizeof(local_addr);
        getsockname(ml->disco_sock4, (struct sockaddr *)&local_addr, &addr_len);
        ml->disco_local_port = ntohs(local_addr.sin_port);
        ESP_LOGI(TAG, "DISCO/magicsock UDP socket bound to port %d", ml->disco_local_port);
    } else {
        ESP_LOGE(TAG, "Failed to create DISCO socket: errno=%d", errno);
    }
#ifdef CONFIG_ML_ZERO_COPY_WG
skip_bsd_socket:
    ;
#endif

    /* Create tasks */
    BaseType_t ret;

    /* Every task created is counted, so stop waits for each one of them to
     * exit — also when a later one could not be created. */
    ret = xTaskCreatePinnedToCore(ml_net_io_task, "ml_net_io", ML_TASK_NET_IO_STACK,
                                   ml, ML_TASK_NET_IO_PRIO, &ml->net_io_task, ML_TASK_NET_IO_CORE);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create net_io task");
        return ESP_FAIL;
    }
    ml->tasks_started++;

    ret = xTaskCreatePinnedToCore(ml_derp_tx_task, "ml_derp_tx", ML_TASK_DERP_TX_STACK,
                                   ml, ML_TASK_DERP_TX_PRIO, &ml->derp_tx_task, ML_TASK_DERP_TX_CORE);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create derp_tx task");
        return ESP_FAIL;
    }
    ml->tasks_started++;

    ret = xTaskCreatePinnedToCore(ml_coord_task, "ml_coord", ML_TASK_COORD_STACK,
                                   ml, ML_TASK_COORD_PRIO, &ml->coord_task, ML_TASK_COORD_CORE);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create coord task");
        return ESP_FAIL;
    }
    ml->tasks_started++;

    ret = xTaskCreatePinnedToCore(ml_wg_mgr_task, "ml_wg_mgr", ML_TASK_WG_MGR_STACK,
                                   ml, ML_TASK_WG_MGR_PRIO, &ml->wg_mgr_task, ML_TASK_WG_MGR_CORE);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create wg_mgr task");
        return ESP_FAIL;
    }
    ml->tasks_started++;

    /* WiFi is expected to be connected before microlink_start() is called.
     * Signal the event so coord/wg_mgr tasks proceed immediately. */
    xEventGroupSetBits(ml->events, ML_EVT_WIFI_CONNECTED);

    /* Signal coord task to start connecting */
    ml_coord_cmd_t cmd = ML_CMD_CONNECT;
    xQueueSend(ml->coord_cmd_queue, &cmd, 0);

    /* Start HTTP config server (binds port 80, serves config page + REST API) */
    if (ml->config_httpd) {
        ml_config_httpd_start(ml->config_httpd, ml);
    }

    ESP_LOGI(TAG, "All tasks started");
    return ESP_OK;
}

esp_err_t microlink_rebind(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;
    if (ml->state == ML_STATE_IDLE) return ESP_ERR_INVALID_STATE;

    ESP_LOGI(TAG, "=== Rebinding to new network interface ===");

    /* Step 1: Invalidate socket FDs FIRST, then delay to let net_io_task's
     * select() cycle complete (50ms timeout). Only THEN close the old FDs.
     * Closing a socket while another thread has it in select() deadlocks
     * on lwIP's global socket lock. */
    int old_disco = ml->disco_sock4;
    int old_stun = ml->stun_sock;
    int old_stun6 = ml->stun_sock6;

    /* Invalidate — net_io_task will skip these on next iteration */
    ml->disco_sock4 = -1;
    ml->stun_sock = -1;
    ml->stun_sock6 = -1;

    /* Wait for net_io_task select() to cycle out (50ms timeout + margin) */
    vTaskDelay(pdMS_TO_TICKS(100));

    /* Now safe to close the old FDs */
    if (old_disco >= 0) ml_close_sock(old_disco);
    if (old_stun >= 0) ml_close_sock(old_stun);
    if (old_stun6 >= 0) ml_close_sock(old_stun6);
    ESP_LOGI(TAG, "Rebind: closed DISCO + STUN sockets");

    /* Step 2: Signal coord to reconnect. ML_CMD_FORCE_RECONNECT closes
     * the coord socket, resets Noise state, and re-enters the
     * STUN → DNS → TCP → Noise → Register → MapRequest flow.
     * Peers and WG state are preserved. */
    xEventGroupClearBits(ml->events, ML_EVT_COORD_REGISTERED);
    ml_coord_cmd_t cmd = ML_CMD_FORCE_RECONNECT;
    xQueueSend(ml->coord_cmd_queue, &cmd, pdMS_TO_TICKS(100));

    /* Step 3: Signal DERP to reconnect. ML_EVT_DERP_RECONNECT triggers
     * derp_tx_task to close TLS, then reconnect with full handshake.
     * Pending TX packets are drained but WG state is preserved. */
    xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECTED);
    xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);
    ESP_LOGI(TAG, "Rebind: signaled coord + DERP to reconnect");

    /* Step 4: Brief delay for coord/DERP to process reconnect signals */
    vTaskDelay(pdMS_TO_TICKS(200));

    /* Step 5: Recreate DISCO UDP socket on the new interface */
#ifdef CONFIG_ML_ZERO_COPY_WG
    ml_zerocopy_deinit(ml);
    if (ml_zerocopy_init(ml) == ESP_OK) {
        ESP_LOGI(TAG, "Rebind: zero-copy DISCO PCB recreated");
        goto rebind_wg_update;
    }
    ESP_LOGW(TAG, "Rebind: zero-copy init failed, using BSD socket fallback");
#endif
    ml->disco_sock4 = ml_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ml->disco_sock4 >= 0) {
        struct sockaddr_in bind_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(51820),
            .sin_addr.s_addr = INADDR_ANY,
        };
        if (ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            bind_addr.sin_port = 0;
            ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
        }
        int tos = 0xB8;
        setsockopt(ml->disco_sock4, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
        int flags = ml_fcntl(ml->disco_sock4, F_GETFL, 0);
        ml_fcntl(ml->disco_sock4, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in local_addr;
        socklen_t addr_len = sizeof(local_addr);
        getsockname(ml->disco_sock4, (struct sockaddr *)&local_addr, &addr_len);
        ml->disco_local_port = ntohs(local_addr.sin_port);
        ESP_LOGI(TAG, "Rebind: DISCO socket rebound to port %d", ml->disco_local_port);
    } else {
        ESP_LOGE(TAG, "Rebind: failed to create DISCO socket: errno=%d", errno);
    }

#ifdef CONFIG_ML_ZERO_COPY_WG
rebind_wg_update:
#endif
    /* Step 6: Update WG output mode for new transport */
    ml_wg_mgr_update_transport(ml);

    ESP_LOGI(TAG, "=== Rebind complete — waiting for coord+DERP reconnect ===");
    return ESP_OK;
}

esp_err_t microlink_stop(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;

    ESP_LOGI(TAG, "Stopping...");
    ml->stopped = true;
    xEventGroupSetBits(ml->events, ML_EVT_SHUTDOWN_REQUEST);

    /* Wake the coord task out of its reconnect back-off, which waits on its
     * command queue; every other wait of every task either watches
     * ML_EVT_SHUTDOWN_REQUEST or is bounded by a socket timeout. */
    ml_coord_cmd_t cmd = ML_CMD_DISCONNECT;
    if (ml->coord_cmd_queue) {  /* none when init failed before it was made */
        xQueueSend(ml->coord_cmd_queue, &cmd, 0);
    }

    /* Wait until every task started has exited: each gives task_exited just
     * before it deletes itself (so it must not be deleted here too). Nothing
     * the tasks use is freed or closed before then. */
    for (int left = ml->tasks_started; left > 0; left--) {
        while (xSemaphoreTake(ml->task_exited, pdMS_TO_TICKS(5000)) != pdTRUE) {
            ESP_LOGW(TAG, "Stopping: %d task(s) still finishing", left);
        }
    }
    ml->tasks_started = 0;

    ml->net_io_task = NULL;
    ml->derp_tx_task = NULL;
    ml->coord_task = NULL;
    ml->wg_mgr_task = NULL;

    /* Stop HTTP config server */
    if (ml->config_httpd) {
        ml_config_httpd_stop(ml->config_httpd);
    }

    /* Clean up zero-copy PCB if active: its callback was unregistered when
     * the WG manager unlinked the netif, and the PCB goes only now */
#ifdef CONFIG_ML_ZERO_COPY_WG
    ml_zerocopy_deinit(ml);
#endif

    /* Close sockets */
    if (ml->disco_sock4 >= 0) { ml_close_sock(ml->disco_sock4); ml->disco_sock4 = -1; }
    if (ml->stun_sock >= 0) { ml_close_sock(ml->stun_sock); ml->stun_sock = -1; }
    if (ml->stun_sock6 >= 0) { ml_close_sock(ml->stun_sock6); ml->stun_sock6 = -1; }

    ml->state = ML_STATE_IDLE;
    ESP_LOGI(TAG, "Stopped");
    return ESP_OK;
}

void microlink_destroy(microlink_t *ml) {
    if (!ml) return;

    microlink_stop(ml);

    /* The peer NVS cache, the HTTP config server, the queues and the
     * semaphores; then the instance, its keys wiped */
    instance_free(ml);
    ESP_LOGI(TAG, "Destroyed");
}

/* ============================================================================
 * State Queries
 * ========================================================================== */

microlink_state_t microlink_get_state(const microlink_t *ml) {
    return ml ? ml->state : ML_STATE_IDLE;
}

bool microlink_is_connected(const microlink_t *ml) {
    return ml && ml->state == ML_STATE_CONNECTED;
}

microlink_registration_t microlink_get_registration(const microlink_t *ml, bool *with_auth_key) {
    if (with_auth_key) {
        *with_auth_key = ml && ml->registration_with_key;
    }
    return ml ? ml->registration : ML_REGISTRATION_NONE;
}

uint32_t microlink_get_vpn_ip(const microlink_t *ml) {
    return ml ? ml->vpn_ip : 0;
}

int microlink_get_peer_count(const microlink_t *ml) {
    if (!ml) return 0;
    ml_peers_lock(ml);
    const int count = ml->peer_count;
    ml_peers_unlock(ml);
    return count;
}

esp_err_t microlink_get_peer_info(const microlink_t *ml, int index, microlink_peer_info_t *info) {
    if (!ml || !info || index < 0) {
        return ESP_ERR_INVALID_ARG;
    }
    /* The slot as one: its address with its own name */
    ml_peers_lock(ml);
    if (index >= ml->peer_count) {
        ml_peers_unlock(ml);
        return ESP_ERR_INVALID_ARG;
    }
    const ml_peer_t *p = &ml->peers[index];
    info->vpn_ip = p->vpn_ip;
    ml_copy_name(info->hostname, sizeof(info->hostname), p->hostname);
    memcpy(info->public_key, p->public_key, 32);
    info->online = p->active;
    info->direct_path = p->has_direct_path;
    ml_peers_unlock(ml);
    return ESP_OK;
}

/* ============================================================================
 * Send API
 * ========================================================================== */

esp_err_t microlink_send(microlink_t *ml, uint32_t dest_vpn_ip,
                          const uint8_t *data, size_t len) {
    if (!ml || !data || len == 0 || len > 1400) return ESP_ERR_INVALID_ARG;
    if (ml->state != ML_STATE_CONNECTED) return ESP_ERR_INVALID_STATE;

    /* Find peer by VPN IP: its key copied under the peer table's lock */
    uint8_t key[32];
    bool found = false;
    ml_peers_lock(ml);
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].vpn_ip == dest_vpn_ip && ml->peers[i].active) {
            memcpy(key, ml->peers[i].public_key, sizeof(key));
            found = true;
            break;
        }
    }
    ml_peers_unlock(ml);
    if (!found) return ESP_ERR_NOT_FOUND;
    /* TODO: Route through WireGuard tunnel */
    /* For now, queue via DERP as fallback */
    return ml_derp_queue_send(ml, key, data, len);
}

/* ============================================================================
 * Callbacks
 * ========================================================================== */

void microlink_set_state_callback(microlink_t *ml, microlink_state_cb_t cb, void *user_data) {
    if (ml) { ml->state_cb = cb; ml->state_cb_data = user_data; }
}

void microlink_set_peer_callback(microlink_t *ml, microlink_peer_cb_t cb, void *user_data) {
    if (ml) { ml->peer_cb = cb; ml->peer_cb_data = user_data; }
}

void microlink_set_data_callback(microlink_t *ml, microlink_data_cb_t cb, void *user_data) {
    if (ml) { ml->data_cb = cb; ml->data_cb_data = user_data; }
}

/* ============================================================================
 * Utilities
 * ========================================================================== */

void microlink_ip_to_str(uint32_t ip, char *buf) {
    snprintf(buf, 16, "%lu.%lu.%lu.%lu",
             (unsigned long)((ip >> 24) & 0xFF),
             (unsigned long)((ip >> 16) & 0xFF),
             (unsigned long)((ip >> 8) & 0xFF),
             (unsigned long)(ip & 0xFF));
}

uint32_t microlink_parse_ip(const char *ip_str) {
    if (!ip_str) return 0;
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

const char *microlink_default_device_name(void) {
    static char name[48] = {0};
    if (name[0] == 0) {
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_STA);

        /* Use ML_DEVICE_NAME as prefix if configured, otherwise "esp32" */
        const char *prefix = CONFIG_ML_DEVICE_NAME;
        if (!prefix || !prefix[0]) prefix = "esp32";
        snprintf(name, sizeof(name), "%s-%02x%02x%02x", prefix, mac[3], mac[4], mac[5]);
    }
    return name;
}

const char *microlink_imei_device_name(void) {
#ifdef CONFIG_ML_ENABLE_CELLULAR
    static char name[48] = {0};  /* prefix + "-" + 15-digit IMEI + null */
    const char *imei = ml_cellular_get_imei();
    if (imei && imei[0]) {
        const char *prefix = CONFIG_ML_DEVICE_NAME;
        if (!prefix || !prefix[0]) prefix = "esp32";
        snprintf(name, sizeof(name), "%s-%s", prefix, imei);
        return name;
    }
#endif
    return NULL;
}

int ml_connect_stoppable(microlink_t *ml, int sock, const struct sockaddr *addr,
                         socklen_t addrlen, uint32_t timeout_ms) {
#ifdef CONFIG_ML_ENABLE_CELLULAR
    /* An AT socket connects on the modem; its own timeout bounds it. */
    (void)ml;
    (void)timeout_ms;
    return ml_connect(sock, addr, addrlen);
#else
    const int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        return connect(sock, addr, addrlen);
    }
    int ret = connect(sock, addr, addrlen);
    if (ret < 0 && errno == EINPROGRESS) {
        ret = -1;
        errno = ETIMEDOUT;
        for (uint32_t waited = 0; waited < timeout_ms; waited += ML_STOP_POLL_MS) {
            if (ml_stopping(ml, 0)) {
                errno = ECANCELED;
                break;
            }
            fd_set writable;
            FD_ZERO(&writable);
            FD_SET(sock, &writable);
            struct timeval tv = { .tv_sec = 0, .tv_usec = ML_STOP_POLL_MS * 1000 };
            const int n = select(sock + 1, NULL, &writable, NULL, &tv);
            if (n < 0) {
                break;  /* errno is select's */
            }
            if (n > 0) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
                    ret = 0;
                } else {
                    errno = err != 0 ? err : ECONNREFUSED;
                }
                break;
            }
        }
    }
    const int saved = errno;
    fcntl(sock, F_SETFL, flags);
    errno = saved;
    return ret;
#endif
}

esp_err_t microlink_set_auth_key(microlink_t *ml, const char *auth_key) {
    if (!ml) return ESP_ERR_INVALID_ARG;
    const size_t len = auth_key ? strlen(auth_key) : 0;
    if (len >= sizeof(ml->auth_key)) return ESP_ERR_INVALID_SIZE;
    xSemaphoreTake(ml->auth_lock, portMAX_DELAY);
    mbedtls_platform_zeroize(ml->auth_key, sizeof(ml->auth_key));
    if (len > 0) memcpy(ml->auth_key, auth_key, len);
    xSemaphoreGive(ml->auth_lock);
    return ESP_OK;
}

bool microlink_map_applied(const microlink_t *ml) {
    return ml && ml->map_applied;
}

uint64_t ml_get_time_ms(void) {
    return (uint64_t)(esp_timer_get_time() / 1000ULL);
}

/* ============================================================================
 * MagicDNS — Resolve tailnet hostnames against peer list (ml_peer_table.c)
 * ========================================================================== */

uint32_t microlink_resolve(const microlink_t *ml, const char *hostname) {
    if (!ml) return 0;
    ml_peers_lock(ml);
    const uint32_t ip = ml_peers_resolve(ml->peers, ml->peer_count, ml->own_domain, hostname);
    ml_peers_unlock(ml);
    return ip;
}
