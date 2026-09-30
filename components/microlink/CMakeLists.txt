set(SRCS
    "src/microlink.c"
    "src/ml_coord.c"
    "src/ml_derp.c"
    "src/ml_net_io.c"
    "src/ml_wg_mgr.c"
    "src/ml_stun.c"
    "src/ml_noise.c"
    "src/ml_h2.c"
    "src/ml_register.c"
    "src/ml_identity.c"
    "src/ml_frame_read.c"
    "src/ml_udp.c"
    "src/ml_tcp.c"
    "src/ml_peer_nvs.c"
    "src/ml_peer_table.c"
    "src/ml_derp_node.c"
    "src/nacl_box.c"
    "src/x25519.c"
    "src/ml_zerocopy.c"
    "src/ml_cellular.c"
    "src/ml_at_socket.c"
    "src/ml_net_switch.c"
    "src/ml_config_httpd.c"
)

set(REQUIRES
    nvs_flash
    esp_wifi
    esp_netif
    esp_event
    esp_timer
    lwip
    mbedtls
    json
    driver
    esp_driver_tsens
    esp_http_server
)

# The DERP relay's certificate held to its CertName, against the bundle
if(CONFIG_ML_DERP_VERIFY_CERT)
    list(APPEND SRCS "src/ml_derp_cert.c")
endif()

idf_component_register(
    SRCS ${SRCS}
    INCLUDE_DIRS
        "include"
        "src"
    REQUIRES ${REQUIRES}
    PRIV_REQUIRES
        wireguard_lwip
)

# ML_LOG_LEVEL: MicroLink's log lines above it are compiled out.
target_compile_definitions(${COMPONENT_LIB} PRIVATE "LOG_LOCAL_LEVEL=${CONFIG_ML_LOG_LEVEL}")
