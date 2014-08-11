/*
 * test-duologin.c
 *
 * Copyright (c) 2010 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wordexp.h>

#include "duo.h"

int
main(int argc, char *argv[])
{
	duo_t *duo;
        struct duo_auth *auth;
        struct duo_factor *f;
	char *factor, *user, *apihost, *ikey, *skey, buf[128];
        int i;

        if (argc != 2) {
                fprintf(stderr, "usage: test-duologin <username>\n");
                exit(1);
        }
        user = argv[1];

	if ((apihost = getenv("DUO_API_HOST")) == NULL ||
            (ikey = getenv("DUO_IKEY")) == NULL ||
            (skey = getenv("DUO_SKEY")) == NULL) {
		fprintf(stderr, "missing DUO_API_HOST or DUO_IKEY or "
                    "DUO_SKEY environment\n");
		exit(1);
	}
	if ((duo = duo_init(apihost, ikey, skey,
                    "test-duoapi/" PACKAGE_VERSION, NULL, NULL)) == NULL) {
		fprintf(stderr, "duo_init failed\n");
		exit(1);
	}
	if (duo_set_timeout(duo, 20) != DUO_OK) {
		fprintf(stderr, "duo_set_timeout failed :(\n");
		exit(1);
	}
        /* Call /preauth */
        if ((auth = duo_auth_preauth(duo, user)) == NULL) {
                fprintf(stderr, "/preauth failed: %s\n", duo_get_error(duo));
                exit(1);
        }
        if (strcmp(auth->ok.preauth.result, "allow") == 0) {
                printf("skipping Duo auth\n");
                exit(0);
        } else if (strcmp(auth->ok.preauth.result, "deny") == 0) {
                printf("not allowed to authenticate\n");
                exit(1);
        } else if (strcmp(auth->ok.preauth.result, "enroll") == 0) {
                printf("%s\n", auth->ok.preauth.prompt.text);
                exit(1);
        } else if (strcmp(auth->ok.preauth.result, "auth") != 0) {
                fprintf(stderr, "bad result: [%s]\n", auth->ok.preauth.result);
                exit(1);
        }
        factor = NULL;
        while (factor == NULL) {
                /* Prompt for user input */
                printf("%s", auth->ok.preauth.prompt.text);
                fflush(stdout);
                if (fgets(buf, sizeof(buf), stdin) == NULL) {
                        exit(1);
                }
                strtok(buf, "\r\n");
                for (i = 0; i < auth->ok.preauth.prompt.factors_cnt; i++) {
                        f = &auth->ok.preauth.prompt.factors[i];
                        if (strcmp(buf, f->option) == 0) {
                                factor = strdup(f->label);
                                break;
                        }
                }
                if (factor == NULL)
                        factor = strdup(buf);
        }
        auth = duo_auth_free(auth);
        
        /* Call /auth */
        if ((auth = duo_auth_auth(duo, user, "prompt", "1.2.3.4",
                    (void *)factor)) == NULL) {
                fprintf(stderr, "/auth failed: %s\n", duo_get_error(duo));
                exit(1);
        }
        free(factor);
        
        if (strcmp(auth->ok.auth.result, "allow") == 0) {
                printf("%s\n", auth->ok.auth.status_msg);
                exit(0);
        }
        if (strcmp(auth->ok.auth.result, "deny") == 0) {
                printf("%s\n", auth->ok.auth.status_msg);
        } else {
                fprintf(stderr, "bad response [%s]\n", duo_get_response(duo));
        }
        duo_auth_free(auth);
        duo_close(duo);

        exit(1);
}
