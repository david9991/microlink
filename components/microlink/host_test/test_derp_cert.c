/*
 * Host tests of a DERP relay's certificate held to its CertName
 * (ml_derp_cert.c), against certificate chains mbedtls builds here: the
 * chain is verified as a TLS handshake verifies it — for the HostName
 * (the SNI), against esp_crt_bundle_attach's empty CA list — with the
 * callback under test in place of ESP-IDF's, and a bundle of one root.
 * Run by run.sh with the host's C compiler and mbedtls.
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <stdio.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#if defined(MBEDTLS_PSA_CRYPTO_C)
#include "psa/crypto.h"
#endif

#include "ml_derp_cert.h"

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

#define HOST_NAME "relay.example.com"   /* the SNI: what the handshake verifies */
#define CERT_NAME "derp.example.net"    /* what the certificates are for */

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context drbg;

/* The bundle: one root, found by the issuer's name as ESP-IDF's is */
static const mbedtls_x509_crt *bundle_root;

/* ESP-IDF's esp_crt_verify_callback (esp_crt_bundle.c), step for step, over
 * this file's bundle */
int esp_crt_verify_callback(void *buf, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    (void)buf;
    (void)depth;
    const uint32_t flags_filtered = *flags & ~(MBEDTLS_X509_BADCERT_BAD_MD);
    if (flags_filtered != MBEDTLS_X509_BADCERT_NOT_TRUSTED) return 0;
    const mbedtls_x509_crt *root = bundle_root;
    if (root->subject_raw.len == crt->issuer_raw.len &&
        memcmp(root->subject_raw.p, crt->issuer_raw.p, crt->issuer_raw.len) == 0) {
        unsigned char hash[MBEDTLS_MD_MAX_SIZE];
        const mbedtls_md_info_t *md = mbedtls_md_info_from_type(crt->sig_md);
        if (md && mbedtls_md(md, crt->tbs.p, crt->tbs.len, hash) == 0 &&
            mbedtls_pk_verify_ext(crt->sig_pk, crt->sig_opts,
                                  (mbedtls_pk_context *)&root->pk, crt->sig_md, hash,
                                  mbedtls_md_get_size(md), crt->sig.p, crt->sig.len) == 0) {
            *flags = 0;
            return 0;
        }
    }
    return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
}

static void new_key(mbedtls_pk_context *key) {
    mbedtls_pk_init(key);
    if (mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0 ||
        mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*key),
                            mbedtls_ctr_drbg_random, &drbg) != 0) {
        printf("FAIL: no key\n");
        failures++;
    }
}

/* A certificate for `subject`, signed by `issuer_key` as `issuer`, parsed
 * onto the end of `chain` */
static void new_cert(mbedtls_x509_crt *chain, mbedtls_pk_context *key, const char *subject,
                     mbedtls_pk_context *issuer_key, const char *issuer, int is_ca) {
    static unsigned char serial = 1;
    unsigned char der[2048];
    mbedtls_x509write_cert w;
    mbedtls_x509write_crt_init(&w);
    mbedtls_x509write_crt_set_version(&w, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&w, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&w, key);
    mbedtls_x509write_crt_set_issuer_key(&w, issuer_key);
    int ret = mbedtls_x509write_crt_set_subject_name(&w, subject);
    if (ret == 0) ret = mbedtls_x509write_crt_set_issuer_name(&w, issuer);
    if (ret == 0) ret = mbedtls_x509write_crt_set_serial_raw(&w, &serial, 1);
    if (ret == 0) ret = mbedtls_x509write_crt_set_validity(&w, "20000101000000", "20991231235959");
    if (ret == 0) ret = mbedtls_x509write_crt_set_basic_constraints(&w, is_ca, -1);
    const int len = ret == 0 ? mbedtls_x509write_crt_der(&w, der, sizeof der,
                                                         mbedtls_ctr_drbg_random, &drbg)
                             : ret;
    serial++;
    mbedtls_x509write_crt_free(&w);
    if (len <= 0 || mbedtls_x509_crt_parse_der(chain, der + sizeof der - len, (size_t)len) != 0) {
        printf("FAIL: no certificate for %s (%d)\n", subject, len);
        failures++;
    }
}

/* The chain verified as the handshake verifies it; its flags, and the
 * result in *ret */
static uint32_t verify(mbedtls_x509_crt *chain, const char *cert_name, int *ret) {
    mbedtls_x509_crt no_ca;  /* esp_crt_bundle_attach's CA list: one empty certificate */
    mbedtls_x509_crt_init(&no_ca);
    uint32_t flags = 0;
    *ret = mbedtls_x509_crt_verify(chain, &no_ca, NULL, HOST_NAME, &flags,
                                   ml_derp_verify_cert_name, (void *)cert_name);
    mbedtls_x509_crt_free(&no_ca);
    return flags;
}

int main(void) {
#if defined(MBEDTLS_PSA_CRYPTO_C)
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: PSA\n");
        return 1;
    }
#endif
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
        printf("FAIL: no random\n");
        return 1;
    }

    mbedtls_pk_context root_key, other_root_key, inter_key, leaf_key;
    new_key(&root_key);
    new_key(&other_root_key);
    new_key(&inter_key);
    new_key(&leaf_key);

    mbedtls_x509_crt root, via_inter, via_root, self_signed, via_other;
    mbedtls_x509_crt_init(&root);
    mbedtls_x509_crt_init(&via_inter);
    mbedtls_x509_crt_init(&via_root);
    mbedtls_x509_crt_init(&self_signed);
    mbedtls_x509_crt_init(&via_other);

    new_cert(&root, &root_key, "CN=Bundle Root", &root_key, "CN=Bundle Root", 1);
    bundle_root = &root;
    /* A leaf and the intermediate that signed it, the root in the bundle */
    new_cert(&via_inter, &leaf_key, "CN=" CERT_NAME, &inter_key, "CN=Intermediate", 0);
    new_cert(&via_inter, &inter_key, "CN=Intermediate", &root_key, "CN=Bundle Root", 1);
    /* A leaf the bundle's root signed directly */
    new_cert(&via_root, &leaf_key, "CN=" CERT_NAME, &root_key, "CN=Bundle Root", 0);
    /* A leaf that signed itself */
    new_cert(&self_signed, &leaf_key, "CN=" CERT_NAME, &leaf_key, "CN=" CERT_NAME, 0);
    /* A leaf a root outside the bundle signed */
    new_cert(&via_other, &leaf_key, "CN=" CERT_NAME, &other_root_key, "CN=Other Root", 0);

    int ret;
    uint32_t flags = verify(&via_inter, CERT_NAME, &ret);
    CHECK(ret == 0 && flags == 0,
          "leaf and intermediate, for its CertName, not the SNI: passes (%d, %#x)", ret,
          (unsigned)flags);
    flags = verify(&via_inter, "other.example.net", &ret);
    CHECK(ret != 0 && (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH),
          "leaf and intermediate, another CertName: fails on the name (%d, %#x)", ret,
          (unsigned)flags);
    flags = verify(&via_root, CERT_NAME, &ret);
    CHECK(ret == 0 && flags == 0,
          "a leaf the bundle's root signed, for its CertName: passes (%d, %#x)", ret,
          (unsigned)flags);
    flags = verify(&via_root, "other.example.net", &ret);
    CHECK(ret != 0 && (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH),
          "a leaf the bundle's root signed, another CertName: fails on the name (%d, %#x)",
          ret, (unsigned)flags);
    flags = verify(&self_signed, CERT_NAME, &ret);
    CHECK(ret != 0, "a self-signed leaf, for its CertName: fails (%d, %#x)", ret,
          (unsigned)flags);
    flags = verify(&via_other, CERT_NAME, &ret);
    CHECK(ret != 0, "a leaf of a root outside the bundle: fails (%d, %#x)", ret,
          (unsigned)flags);

    mbedtls_x509_crt_free(&root);
    mbedtls_x509_crt_free(&via_inter);
    mbedtls_x509_crt_free(&via_root);
    mbedtls_x509_crt_free(&self_signed);
    mbedtls_x509_crt_free(&via_other);
    mbedtls_pk_free(&root_key);
    mbedtls_pk_free(&other_root_key);
    mbedtls_pk_free(&inter_key);
    mbedtls_pk_free(&leaf_key);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
#if defined(MBEDTLS_PSA_CRYPTO_C)
    mbedtls_psa_crypto_free();
#endif
    if (failures) {
        printf("%d failed\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
