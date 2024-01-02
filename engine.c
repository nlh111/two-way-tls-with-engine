#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <mbedtls/asn1write.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/private_access.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <string.h>

static unsigned char dBuf[32] = {0x26, 0x26, 0xdf, 0x4d, 0x69, 0x7d, 0x0f, 0xed, 0x51, 0x11, 0x1c,
                                 0x53, 0xa1, 0xb2, 0x91, 0xb3, 0xb0, 0x41, 0xc9, 0xf6, 0x8f, 0x08,
                                 0xbf, 0x2a, 0x43, 0x37, 0x7b, 0xd1, 0xe1, 0x37, 0x5d, 0x0a};
static size_t dLen = 0;
static unsigned char QBuf[72] = {0x00};
static size_t QLen = 0;
EC_KEY_METHOD *ec_key_method = NULL;
static const char *engine_id = "tlsEngine";
static const char *engine_name = "tlsEngineHsm";

int eccKeyGen(EC_KEY *key)
{
    printf("mbedtls ecc key generation with mbedtls engine\n");
    int ret = 0;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_SECP256R1;
    const char *pers = "csrEngine";
    const EC_GROUP *group = NULL;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0)
    {
        printf("mbedtls_ctr_drbg_seed failed\n");
        return 0;
    }

    mbedtls_ecp_group_load(&grp, grp_id);
    ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        printf("mbedtls_ecp_gen_key failed\n");
        return 0;
    }

    ret = mbedtls_mpi_write_binary(&d, dBuf, 32);
    dLen = mbedtls_mpi_size(&d);

    ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &QLen, QBuf, sizeof(QBuf));
    if (ret != 0)
    {
        printf("mbedtls_ecp_point_write_binary failed\n");
        return 0;
    }

    group = EC_KEY_get0_group(key);

    // //not support with HSM
    // BIGNUM *d_bn = BN_bin2bn(dBuf, dLen, NULL);
    // if (EC_KEY_set_private_key(key, d_bn) != 1)
    // {
    //     printf("EC_KEY_set_private_key failed\n");
    //     return 0;
    // }
    // BN_free(d_bn);

    BIGNUM *Q_bn = BN_bin2bn(QBuf, QLen, NULL);
    EC_POINT *Q_point = EC_POINT_bn2point(group, Q_bn, NULL, NULL);
    if (EC_KEY_set_public_key(key, Q_point) != 1)
    {
        printf("EC_KEY_set_public_key failed\n");
        return 0;
    }

    printf("public key in mbedtls is:\n");
    for (int i = 0; i < QLen; i++)
    {
        printf("0x%02x,", QBuf[i]);
        if (i % 16 == 15)
            printf("\n");
    }
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    EC_POINT_free(Q_point);
    BN_free(Q_bn);
    printf("ECC key generation with mbedtls engine successfully\n");
    return 1;
}

int ecdsaSign(int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int *siglen,
              const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    printf("mbedtls ecdsa sign with mbedtls engine\n");
    printf("digest length is %d\n", dlen);
    int ret = 0;
    mbedtls_ecdsa_context ctx_sign;
    mbedtls_ecp_group grp;
    mbedtls_mpi r_mpi, s_mpi;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "csrEngine";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ecdsa_init(&ctx_sign);
    mbedtls_mpi_init(&r_mpi);
    mbedtls_mpi_init(&s_mpi);
    mbedtls_ecp_group_init(&grp);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0)
    {
        printf("mbedtls_ctr_drbg_seed failed\n");
        return 0;
    }

    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    ctx_sign.grp = grp;

    ret = mbedtls_mpi_read_binary(&ctx_sign.d, dBuf, sizeof(dBuf));
    if (ret != 0)
    {
        printf("mbedtls_mpi_read_binary failed\n");
        return 0;
    }

    unsigned char sigBuf[80] = {0x00};
    size_t sigResLen = 0;
    ret = mbedtls_ecdsa_write_signature(&ctx_sign, MBEDTLS_MD_SHA256, dgst, dlen, sigBuf, 80, &sigResLen,
                                        mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        printf("mbedtls_ecdsa_write_signature failed\n");
        return 0;
    }
    memcpy(sig, sigBuf, sigResLen);
    *siglen = sigResLen;
    printf("ecdsa signature is:\n");
    for (int i = 0; i < sigResLen; i++)
    {
        printf("0x%02x,", sig[i]);
        if (i % 16 == 15)
            printf("\n");
    }
    printf("\n");

    mbedtls_ecdsa_free(&ctx_sign);
    mbedtls_mpi_free(&r_mpi);
    mbedtls_mpi_free(&s_mpi);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return 1;
}

int loadCert(ENGINE *e, SSL *ssl, STACK_OF(X509_NAME) * ca_dn, X509 **pcert, EVP_PKEY **pkey, STACK_OF(X509) * *pother,
             UI_METHOD *ui_method, void *callback_data)
{
    printf("load cert with mbedtls engine\n");
    // load the client certificate
    BIO *bio = BIO_new_file("../certfile/client.crt", "r");
    if (bio == NULL)
    {
        printf("BIO_new_file failed\n");
        return 0;
    }
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (cert == NULL)
    {
        printf("PEM_read_bio_X509 failed\n");
        return 0;
    }
    BIO_free(bio);
    *pcert = cert;
    printf("load cert with mbedtls engine successfully\n");
    // print the client certificate with openssl
    // X509_print_fp(stdout, *pcert);

    return 1;
}

EVP_PKEY *loadPrivkey(ENGINE *e, const char *name, UI_METHOD *ui_method, void *callback_data)
{
    uint8_t buf[] = {0x04, 0x5e, 0xf0, 0x4a, 0xeb, 0x23, 0x21, 0xbc, 0x27, 0x5f, 0x46, 0xce, 0x50,
                     0xb7, 0xc7, 0xa1, 0x45, 0x60, 0x01, 0xea, 0x5d, 0xec, 0x4b, 0xc4, 0x52, 0x55,
                     0xb4, 0x2f, 0x1e, 0x80, 0x8d, 0x88, 0xb5, 0x33, 0xf0, 0x1c, 0x8c, 0x89, 0xc0,
                     0xec, 0x0e, 0x07, 0x56, 0x29, 0x21, 0x9f, 0x77, 0x40, 0x1f, 0x96, 0xcd, 0x46,
                     0xff, 0x39, 0x77, 0xc5, 0xa4, 0xe8, 0x61, 0xc0, 0x77, 0x2e, 0x8a, 0xe8, 0x92};
    size_t bufLen = sizeof(buf);

    printf("load privkey with mbedtls engine\n");
    // load the client private key
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL)
    {
        printf("EVP_PKEY_new failed\n");
        return NULL;
    }
    EC_KEY *ecKey = EC_KEY_new();
    if (ecKey == NULL)
    {
        printf("EC_KEY_new failed\n");
        return NULL;
    }
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (group == NULL)
    {
        printf("EC_GROUP_new_by_curve_name failed\n");
        return NULL;
    }
    EC_POINT *point = EC_POINT_new(group);
    if (point == NULL)
    {
        printf("EC_POINT_new failed\n");
        return NULL;
    }
    BIGNUM *bn = BN_bin2bn(buf, bufLen, NULL);
    if (bn == NULL)
    {
        printf("BN_bin2bn failed\n");
        return NULL;
    }
    if (EC_POINT_bn2point(group, bn, point, NULL) == NULL)
    {
        printf("EC_POINT_bn2point failed\n");
        return NULL;
    }
    if (EC_KEY_set_group(ecKey, group) == 0)
    {
        printf("EC_KEY_set_group failed\n");
        return NULL;
    }
    if (EC_KEY_set_public_key(ecKey, point) == 0)
    {
        printf("EC_KEY_set_public_key failed\n");
        return NULL;
    }
    if (EVP_PKEY_assign_EC_KEY(pkey, ecKey) == 0)
    {
        printf("EVP_PKEY_assign_EC_KEY failed\n");
        return NULL;
    }
    printf("load privkey with mbedtls engine successfully\n");
    return pkey;
}
static int bind(ENGINE *e, const char *id)
{
    EC_KEY_METHOD *ecKeyMethod = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    if (ecKeyMethod == NULL)
    {
        printf("EC_KEY_METHOD_new failed\n");
        return 0;
    }

    EC_KEY_METHOD_set_keygen(ecKeyMethod, eccKeyGen);
    EC_KEY_METHOD_set_sign(ecKeyMethod, ecdsaSign, NULL, NULL);
    if (!ENGINE_set_id(e, engine_id) || !ENGINE_set_name(e, engine_name))
    {
        printf("ENGINE_set_id or ENGINE_set_name failed\n");
        return 0;
    }
    if (!ENGINE_set_load_ssl_client_cert_function(e, loadCert))
    {
        printf("ENGINE_set_load_ssl_client_cert_function failed\n");
        return 0;
    }
    if (!ENGINE_set_load_privkey_function(e, loadPrivkey))
    {
        printf("ENGINE_set_load_privkey_function failed\n");
        return 0;
    }
    if (!ENGINE_set_EC(e, ecKeyMethod))
    {
        printf("ENGINE_set_EC failed\n");
        return 0;
    }
    if (!ENGINE_set_default_EC(e))
    {
        printf("ENGINE_set_default_EC failed\n");
        return 0;
    }
    // EC_KEY_METHOD_free(ecKeyMethod);
    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
