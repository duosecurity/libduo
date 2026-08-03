/*
 * test-ca-pinning-store.c
 *
 * Verifies which trust store https_init() actually installs.
 *
 * test-disable-ca-pinning.c checks the return codes of the public API, but
 * those stay identical whether or not disable_ca_pinning is honoured - the
 * option could be ignored entirely and every one of those tests would still
 * pass.  This test inspects the SSL_CTX that https_init() built, so a
 * regression that silently keeps using the pinned bundle is caught.
 *
 * The trust store lives in a file-scope global inside https.c, so the
 * implementation is included directly rather than linked against libduo.a.
 * That keeps the test hook out of the shipped library.
 */

#include "config.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "https.c"

static int tests_run = 0;
static int tests_failed = 0;
static int tests_skipped = 0;

static void
check(const char *name, int passed, const char *detail)
{
        tests_run++;
        if (passed) {
                printf("PASS: %s\n", name);
        } else {
                tests_failed++;
                printf("FAIL: %s (%s)\n", name, detail ? detail : "no detail");
        }
}

/* X509_STORE_get0_objects() arrived in OpenSSL 1.1.0.  The library still
 * carries shims for older releases, so rather than break the build there, the
 * two tests that need to count certificates report themselves as skipped. */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
# define HAVE_TRUST_STORE_INSPECTION 1
#else
static void
skip(const char *name, const char *why)
{
        tests_skipped++;
        printf("SKIP: %s (%s)\n", name, why);
}
#endif

#ifdef HAVE_TRUST_STORE_INSPECTION
/* Number of certificates in the trust store https_init() just configured. */
static int
trust_store_size(void)
{
        X509_STORE *store;

        if (ctx == NULL || ctx->ssl_ctx == NULL) {
                return (-1);
        }
        if ((store = SSL_CTX_get_cert_store(ctx->ssl_ctx)) == NULL) {
                return (-1);
        }
        return (sk_X509_OBJECT_num(X509_STORE_get0_objects(store)));
}
#endif

/* Peer-verification mode of the context https_init() just configured. */
static int
verify_mode(void)
{
        if (ctx == NULL || ctx->ssl_ctx == NULL) {
                return (-1);
        }
        return (SSL_CTX_get_verify_mode(ctx->ssl_ctx));
}

#ifdef HAVE_TRUST_STORE_INSPECTION
/* Certificates in the bundle compiled into libduo, counted independently of
 * https_init() so the expected value is derived rather than hardcoded. */
static int
pinned_bundle_size(void)
{
        X509 *cert;
        BIO *bio;
        int n = 0;

        if ((bio = BIO_new_mem_buf((void *)CACERT_PEM, -1)) == NULL) {
                return (-1);
        }
        while ((cert = PEM_read_bio_X509(bio, NULL, 0, NULL)) != NULL) {
                X509_free(cert);
                n++;
        }
        BIO_free_all(bio);
        return (n);
}

/* Point OpenSSL's default verify paths at a trust store this test controls.
 *
 * The real system store is not usable as an expectation: a minimal container
 * has none, so its size would be 0 - which is also what a regression that never
 * installs the default paths produces.  Staging a file with a known number of
 * certificates makes the two distinguishable on any host.  A certificate from
 * the bundle is reused simply because one is already available; only the count
 * matters, and one is not fifteen.
 *
 * Returns the number of certificates staged, or -1 on failure.
 */
static int
stage_system_store(char *path, size_t pathlen)
{
        X509 *cert = NULL;
        BIO *in = NULL, *out = NULL;
        int fd, n = -1;

        snprintf(path, pathlen, "test-system-store.pem");
        if ((in = BIO_new_mem_buf((void *)CACERT_PEM, -1)) == NULL) {
                return (-1);
        }
        if ((cert = PEM_read_bio_X509(in, NULL, 0, NULL)) == NULL) {
                goto done;
        }
        if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600)) == -1) {
                goto done;
        }
        if ((out = BIO_new_fd(fd, BIO_CLOSE)) == NULL) {
                close(fd);
                goto done;
        }
        if (!PEM_write_bio_X509(out, cert)) {
                goto done;
        }
        BIO_free_all(out);
        out = NULL;
        n = 1;

        /* Both must be set: SSL_CERT_DIR is pointed at a directory that does
         * not exist so the hashed-directory lookup contributes nothing and the
         * host's real certificates cannot skew the count. */
        if (setenv("SSL_CERT_FILE", path, 1) != 0 ||
            setenv("SSL_CERT_DIR", "test-system-store.d", 1) != 0) {
                n = -1;
        }
done:
        if (cert != NULL) {
                X509_free(cert);
        }
        if (out != NULL) {
                BIO_free_all(out);
        }
        BIO_free_all(in);
        return (n);
}
#endif /* HAVE_TRUST_STORE_INSPECTION */

#define STORE_SKIP_REASON "needs OpenSSL 1.1.0 or later to inspect the store"

/* Pinning enabled must install exactly the bundled certificates. */
static void
test_pinned_store_is_the_bundle(void)
{
#ifndef HAVE_TRUST_STORE_INSPECTION
        skip("pinned store holds the bundled certificates",
            STORE_SKIP_REASON);
#else
        char buf[128];
        int expected, got;

        expected = pinned_bundle_size();
        if (https_init("test-agent/1.0", NULL, 0, NULL) != HTTPS_OK) {
                check("pinned store holds the bundled certificates", 0,
                    "https_init failed");
                return;
        }
        got = trust_store_size();
        snprintf(buf, sizeof(buf), "expected %d bundled certs, store has %d",
            expected, got);
        check("pinned store holds the bundled certificates",
            expected > 0 && got == expected, buf);
#endif
}

/* Disabling pinning must install the default verify paths, which the staging
 * helper above has pointed at a store of known size.  Asserting the exact count
 * catches both a regression that keeps using the pinned bundle and one that
 * installs no roots at all. */
static void
test_disabled_store_is_the_system_store(void)
{
#ifndef HAVE_TRUST_STORE_INSPECTION
        skip("disabled pinning installs the system trust store",
            STORE_SKIP_REASON);
#else
        char buf[128];
        char path[64];
        int staged, got;

        if ((staged = stage_system_store(path, sizeof(path))) < 0) {
                check("disabled pinning installs the system trust store", 0,
                    "could not stage a system trust store");
                return;
        }
        if (https_init("test-agent/1.0", NULL, 1, NULL) != HTTPS_OK) {
                check("disabled pinning installs the system trust store", 0,
                    "https_init failed");
                goto done;
        }
        got = trust_store_size();
        snprintf(buf, sizeof(buf), "expected %d staged certs, store has %d "
            "(bundle has %d)", staged, got, pinned_bundle_size());
        check("disabled pinning installs the system trust store",
            got == staged, buf);
done:
        /* Undo the staging so the later tests are not left pointing at a file
         * that is about to be deleted - they must not depend on the order they
         * run in. */
        unsetenv("SSL_CERT_FILE");
        unsetenv("SSL_CERT_DIR");
        unlink(path);
#endif
}

/* The security invariant: disabling pinning changes which roots are trusted, it
 * does not stop the peer certificate from being checked. */
static void
test_disabled_still_verifies_the_peer(void)
{
        char buf[128];
        int mode;

        if (https_init("test-agent/1.0", NULL, 1, NULL) != HTTPS_OK) {
                check("disabled pinning still verifies the peer", 0,
                    "https_init failed");
                return;
        }
        mode = verify_mode();
        snprintf(buf, sizeof(buf), "verify mode is %d, want SSL_VERIFY_PEER=%d",
            mode, SSL_VERIFY_PEER);
        check("disabled pinning still verifies the peer",
            mode == SSL_VERIFY_PEER, buf);
}

int
main(void)
{
        test_pinned_store_is_the_bundle();
        test_disabled_store_is_the_system_store();
        test_disabled_still_verifies_the_peer();

        printf("\n%d/%d tests passed", tests_run - tests_failed, tests_run);
        if (tests_skipped > 0) {
                printf(", %d skipped", tests_skipped);
        }
        printf("\n");

        return (tests_failed == 0) ? 0 : 1;
}
