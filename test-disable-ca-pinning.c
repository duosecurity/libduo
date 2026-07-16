/*
 * test-disable-ca-pinning.c
 *
 * Tests for the disable_ca_pinning option of duo_init() and https_init().
 */

#include "config.h"

#include <stdio.h>
#include <string.h>

#include "duo.h"
#include "https.h"

static int tests_run = 0;
static int tests_failed = 0;

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

/* The message the conflict check reports.  A bad cafile path fails with the
 * same HTTPS_ERR_CLIENT code, so tests match on the text to prove which of
 * the two checks actually rejected the call. */
#define CONFLICT_ERR "Cannot both disable CA pinning and provide a custom CA file"

/* https_geterr() clears the stored error, so it must only be called once per
 * https_init() - fetch it here and reuse the copy. */
static void
describe(char *buf, size_t buflen, HTTPScode want, HTTPScode got)
{
        const char *err = https_geterr();

        snprintf(buf, buflen, "expected %d, got %d (%s)", want, got,
            err != NULL ? err : "no error");
}

/* CA pinning is the default: the bundled bundle is used and init succeeds. */
static void
test_pinning_enabled_by_default(void)
{
        char buf[256];
        HTTPScode rc;

        rc = https_init("test-agent/1.0", NULL, 0, NULL);
        describe(buf, sizeof(buf), HTTPS_OK, rc);
        check("CA pinning enabled by default", rc == HTTPS_OK, buf);
}

/* Disabling pinning falls back to the system trust store and still succeeds. */
static void
test_disable_ca_pinning(void)
{
        char buf[256];
        HTTPScode rc;

        rc = https_init("test-agent/1.0", NULL, 1, NULL);
        describe(buf, sizeof(buf), HTTPS_OK, rc);
        check("disable_ca_pinning uses the system trust store",
            rc == HTTPS_OK, buf);
}

/* With pinning left enabled, a cafile is still honoured - and a bad path is
 * still reported, proving the new branch did not shadow the existing one. */
static void
test_cafile_still_honoured_when_pinning_enabled(void)
{
        char buf[256];
        HTTPScode rc;

        rc = https_init("test-agent/1.0", "/nonexistent/path.pem", 0, NULL);
        describe(buf, sizeof(buf), HTTPS_ERR_CLIENT, rc);
        check("a bad CA file path is still an error when pinning is enabled",
            rc == HTTPS_ERR_CLIENT, buf);
}

/* The option is reached through duo_init(), which is the entry point callers
 * actually use.  duo_init() does no network I/O, so the credentials below are
 * never validated - only the handle setup is under test. */
static void
test_duo_init_accepts_the_option(void)
{
        duo_t *duo;

        duo = duo_init("api-00000000.duosecurity.com", "ikey", "skey",
            "test-disable-ca-pinning/" PACKAGE_VERSION, NULL, 0, NULL);
        check("duo_init succeeds with CA pinning enabled", duo != NULL,
            "duo_init returned NULL");
        duo_close(duo);

        duo = duo_init("api-00000000.duosecurity.com", "ikey", "skey",
            "test-disable-ca-pinning/" PACKAGE_VERSION, NULL, 1, NULL);
        check("duo_init succeeds with CA pinning disabled", duo != NULL,
            "duo_init returned NULL");
        duo_close(duo);
}

/* duo_init() must propagate the conflict rather than hand back a usable
 * handle whose trust configuration is not what the caller asked for.
 *
 * Both spellings of a cafile are checked.  "" is the interesting one: it means
 * "skip verification entirely", so letting it through would leave the caller
 * with pinning disabled and no peer check at all - which is what disabling
 * pinning must never turn into. */
static void
test_duo_init_rejects_conflicting_options(void)
{
        static const char *cafiles[] = { "/some/ca.pem", "" };
        size_t i;

        for (i = 0; i < sizeof(cafiles) / sizeof(cafiles[0]); i++) {
                duo_t *duo;
                char buf[256];
                const char *err;

                duo = duo_init("api-00000000.duosecurity.com", "ikey", "skey",
                    "test-disable-ca-pinning/" PACKAGE_VERSION, cafiles[i], 1,
                    NULL);
                err = https_geterr();
                snprintf(buf, sizeof(buf), "cafile=\"%s\", handle=%s, err=%s",
                    cafiles[i], duo == NULL ? "NULL" : "non-NULL",
                    err != NULL ? err : "none");
                /* Matching the message rules out an unrelated failure - a
                 * missing cafile would fail the same way if the conflict went
                 * unnoticed. */
                check("duo_init rejects disable_ca_pinning with a cafile",
                    duo == NULL && err != NULL &&
                    strcmp(err, CONFLICT_ERR) == 0, buf);
                duo_close(duo);
        }
}

int
main(void)
{
        test_pinning_enabled_by_default();
        test_disable_ca_pinning();
        test_cafile_still_honoured_when_pinning_enabled();
        test_duo_init_accepts_the_option();
        test_duo_init_rejects_conflicting_options();

        printf("\n%d/%d tests passed\n", tests_run - tests_failed, tests_run);

        return (tests_failed == 0) ? 0 : 1;
}
