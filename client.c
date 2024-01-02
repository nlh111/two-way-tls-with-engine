#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define BUFSIZE 128

ENGINE *e = NULL;
int load_engine()
{
    OPENSSL_load_builtin_modules();
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL);

    char openssl_cnf_path[] = "../openssl.cnf";
    if (CONF_modules_load_file(openssl_cnf_path, "openssl_conf", 0) != 1)
    {
        printf("begin load engine error\n");
        fprintf(stderr, "OpenSSL failed to load required configuration\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    e = ENGINE_by_id("tlsEngine");
    if (!e)
    {
        printf("Failed to load engine\n");
        return 0;
    }

    if (!ENGINE_init(e))
    {
        printf("Failed to initialize engine\n");
        ENGINE_free(e);
        return 0;
    }

    return 1;
}

static SSL_CTX *get_client_context(const char *ca_pem, const char *cert_pem, const char *key_pem)
{
    SSL_CTX *ctx;
    X509 *cert;
    EVP_PKEY *key = NULL;

    /* Load openssl engine */
    if (!load_engine())
    {
        printf("load engine error\n");
        return NULL;
    }

    /* Create a generic context */
    if (!(ctx = SSL_CTX_new(TLS_client_method())))
    {
        fprintf(stderr, "Cannot create a client context\n");
        return NULL;
    }
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1)
    {
        printf("set min proto version error\n");
        goto fail;
    }

    /* Load the client's CA file location */
    if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1)
    {
        fprintf(stderr, "Cannot load client's CA file\n");
        goto fail;
    }

    /* Load the client's certificate with engine */
    if (!ENGINE_load_ssl_client_cert(e, NULL, NULL, &cert, NULL, NULL, NULL, NULL))
    {
        printf("load client cert error\n");
        goto fail;
    }

    if (SSL_CTX_use_certificate(ctx, cert) != 1)
    {
        printf("failed to use certificate");
        goto fail;
    }

    /* Load the client's key */
    // if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1)
    // {
    //     fprintf(stderr, "Cannot load client's key file\n");
    //     goto fail;
    // }
    if ((key = ENGINE_load_private_key(e, "ec_key", UI_OpenSSL(), NULL)) == NULL)
    {
        printf("load private key error\n");
        goto fail;
    }
    if (SSL_CTX_use_PrivateKey(ctx, key) != 1)
    {
        printf("use private key error\n");
        goto fail;
    }

    /* Verify that the client's certificate and the key match */
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        fprintf(stderr, "Client's certificate and key don't match\n");
        goto fail;
    }

    /*printf the key with pem format*/
    PEM_write_PUBKEY(stdout, key);

    /* We won't handle incomplete read/writes due to renegotiation */
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    /* Specify that we need to verify the server's certificate */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* We accept only certificates signed only by the CA himself */
    SSL_CTX_set_verify_depth(ctx, 1);

    /* Done, return the context */
    return ctx;

fail:
    SSL_CTX_free(ctx);
    X509_free(cert);
    EVP_PKEY_free(key);
    return NULL;
}

int client(const char *conn_str, const char *ca_pem, const char *cert_pem, const char *key_pem)
{
    static char buffer[BUFSIZE];
    SSL_CTX *ctx;
    BIO *sbio;
    SSL *ssl;
    size_t len;
    /* Failure till we know it's a success */
    int rc = -1;

    /* Initialize OpenSSL */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* Get a context */
    if (!(ctx = get_client_context(ca_pem, cert_pem, key_pem)))
    {
        return rc;
    }

    /* Get a BIO */
    if (!(sbio = BIO_new_ssl_connect(ctx)))
    {
        fprintf(stderr, "Could not get a BIO object from context\n");
        goto fail1;
    }

    /* Get the SSL handle from the BIO */
    BIO_get_ssl(sbio, &ssl);

    /* Connect to the server */
    if (BIO_set_conn_hostname(sbio, conn_str) != 1)
    {
        fprintf(stderr, "Could not connecto to the server\n");
        goto fail2;
    }

    /* Perform SSL handshake with the server */
    if (SSL_do_handshake(ssl) != 1)
    {
        fprintf(stderr, "SSL Handshake failed\n");
        goto fail2;
    }

    /* Verify that SSL handshake completed successfully */
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
        fprintf(stderr, "Verification of handshake failed\n");
        goto fail2;
    }

    /* Inform the user that we've successfully connected */
    printf("SSL handshake successful with %s\n", conn_str);

    /* Read a line from the user */
    if (!fgets(buffer, BUFSIZE, stdin))
    {
        fprintf(stderr, "Could not read input from the user\n");
        goto fail3;
    }

    /* Get the length of the buffer */
    len = strlen(buffer);

    /* Write the input onto the SSL socket */
    if ((rc = SSL_write(ssl, buffer, (int)len)) != len)
    {
        fprintf(stderr, "Cannot write to the server\n");
        goto fail3;
    }

    /* Read from the server */
    if ((rc = SSL_read(ssl, buffer, BUFSIZE)) < 0)
    {
        fprintf(stderr, "Cannot read from the server\n");
        goto fail3;
    }

    /* Check if we've got back what we sent? (Not perfect, but OK for us) */
    if (len == rc)
    {
        /* Print it on the screen again */
        printf("%s", buffer);
    }

    rc = 0;

    /* Cleanup and exit */
fail3:
    BIO_ssl_shutdown(sbio);
fail2:
    BIO_free_all(sbio);
fail1:
    SSL_CTX_free(ctx);
    return rc;
}

int main(int argc, char **argv)
{
    // set the server's hostname and certificate file
    const char *conn_str = "localhost:8000";
    char *ca = "../certfile/ca-chain.crt";
    char *cert = "../certfile/client.crt";
    char *key = "../certfile/client.key";
    client(conn_str, ca, cert, key);
    return 0;
}