/**
 * @file ml_derp_cert.h
 * @brief A DERP relay's certificate held to its CertName: ESP-IDF's bundle
 *        check, with the name the map gives in place of the SNI's. Built
 *        with CONFIG_ML_DERP_VERIFY_CERT; host_test/ builds it against the
 *        host's mbedtls, with a bundle of its own.
 */

#pragma once

#include <stdint.h>

#include "mbedtls/x509_crt.h"

/* ESP-IDF's check of a certificate chain against its bundle, which
 * esp_crt_bundle_attach installs; esp_crt_bundle.c defines it, its header
 * does not declare it */
int esp_crt_verify_callback(void *buf, mbedtls_x509_crt *crt, int depth, uint32_t *flags);

/**
 * @brief mbedtls's verify callback for a relay whose certificate is for its
 *        CertName (`cert_name`, an ended string) rather than for the
 *        HostName the connection verifies
 *
 * At the leaf (depth 0) HostName's verdict is dropped before ESP-IDF's
 * check — which looks in the bundle only for a certificate whose one fault
 * is an issuer not trusted, so a leaf the bundle's root signed directly
 * would fail on HostName alone — and CertName's verdict is applied after.
 * Above the leaf it is ESP-IDF's check alone.
 */
int ml_derp_verify_cert_name(void *cert_name, mbedtls_x509_crt *crt, int depth, uint32_t *flags);
