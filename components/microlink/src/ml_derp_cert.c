/**
 * @file ml_derp_cert.c
 * @brief A DERP relay's certificate held to its CertName (see ml_derp_cert.h)
 */

#include "ml_derp_cert.h"

int ml_derp_verify_cert_name(void *cert_name, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    if (depth == 0) *flags &= ~MBEDTLS_X509_BADCERT_CN_MISMATCH;
    const int ret = esp_crt_verify_callback(NULL, crt, depth, flags);
    if (ret != 0 || depth != 0) return ret;
    uint32_t name_flags = 0;
    /* Only the name's verdict is taken from this: the chain is the bundle's */
    (void)mbedtls_x509_crt_verify(crt, crt, NULL, (const char *)cert_name, &name_flags, NULL, NULL);
    *flags |= name_flags & MBEDTLS_X509_BADCERT_CN_MISMATCH;
    return 0;
}
