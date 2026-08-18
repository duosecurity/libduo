/*
 * test-useragent.c
 *
 * Verifies that the user agent string includes CA bundle version and
 * CA pinning status
 *
 */

#include "config.h"

#include <stdio.h>
#include <string.h>

#include "https.c"

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

/* Verify the user agent contains the CA bundle version token. */
static void
test_useragent_contains_ca_bundle_version(void)
{
        HTTPScode rc;
        char buf[512];

        rc = https_init("testprog (testhost) libduo/0.0 ca_bundle/1.0 (ca_pinning=enabled)",
            NULL, NULL, 0);
        if (rc != HTTPS_OK) {
                snprintf(buf, sizeof(buf), "https_init failed: %s",
                    https_geterr());
                check("useragent contains ca_bundle/1.0", 0, buf);
                return;
        }
        snprintf(buf, sizeof(buf), "got: %s", ctx->useragent);
        check("useragent contains ca_bundle/1.0",
            strstr(ctx->useragent, "ca_bundle/1.0") != NULL, buf);
}

/* Verify that when pinning is enabled, the user agent says so. */
static void
test_useragent_pinning_enabled(void)
{
        HTTPScode rc;
        char buf[512];

        rc = https_init("testprog (testhost) libduo/0.0 ca_bundle/1.0 (ca_pinning=enabled)",
            NULL, NULL, 0);
        if (rc != HTTPS_OK) {
                snprintf(buf, sizeof(buf), "https_init failed: %s",
                    https_geterr());
                check("useragent shows ca_pinning=enabled", 0, buf);
                return;
        }
        snprintf(buf, sizeof(buf), "got: %s", ctx->useragent);
        check("useragent shows ca_pinning=enabled",
            strstr(ctx->useragent, "(ca_pinning=enabled)") != NULL, buf);
}

/* Verify that when pinning is disabled, the user agent says so. */
static void
test_useragent_pinning_disabled(void)
{
        HTTPScode rc;
        char buf[512];

        rc = https_init("testprog (testhost) libduo/0.0 ca_bundle/1.0 (ca_pinning=disabled)",
            NULL, NULL, 1);
        if (rc != HTTPS_OK) {
                snprintf(buf, sizeof(buf), "https_init failed: %s",
                    https_geterr());
                check("useragent shows ca_pinning=disabled", 0, buf);
                return;
        }
        snprintf(buf, sizeof(buf), "got: %s", ctx->useragent);
        check("useragent shows ca_pinning=disabled",
            strstr(ctx->useragent, "(ca_pinning=disabled)") != NULL, buf);
}

/* Verify the full format includes progname prefix and all fields. */
static void
test_useragent_format_complete(void)
{
        HTTPScode rc;
        char buf[512];
        const char *expected = "myprog (myhost) libduo/1.0 ca_bundle/1.0 (ca_pinning=enabled)";

        rc = https_init(expected, NULL, NULL, 0);
        if (rc != HTTPS_OK) {
                snprintf(buf, sizeof(buf), "https_init failed: %s",
                    https_geterr());
                check("useragent full format is preserved", 0, buf);
                return;
        }
        snprintf(buf, sizeof(buf), "expected: %s, got: %s",
            expected, ctx->useragent);
        check("useragent full format is preserved",
            strcmp(ctx->useragent, expected) == 0, buf);
}

int
main(void)
{
        test_useragent_contains_ca_bundle_version();
        test_useragent_pinning_enabled();
        test_useragent_pinning_disabled();
        test_useragent_format_complete();

        printf("\n%d/%d tests passed\n", tests_run - tests_failed, tests_run);

        return (tests_failed == 0) ? 0 : 1;
}
