/*
 * test-duoapi.c
 *
 * Copyright (c) 2010 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "duo.h"

static const char *
_duo_codename(duocode_t code)
{
        static const char *codenames[] = {
                "DUO_OK", "DUO_FAIL", "DUO_LIB_ERROR", "DUO_CONN_ERROR",
                "DUO_CLIENT_ERROR", "DUO_SERVER_ERROR"
        };
        if (!(code >= DUO_OK && code <= DUO_SERVER_ERROR)) {
                return "unknown";
        }
        return (codenames[code]);
}

static int
_parse_line(char *line, const char **method, const char **uri,
    struct duo_param *params, int params_sz)
{
        char *p = line;
        int i;

        strtok(line, "\r\n");

        if ((*method = strsep(&p, " ")) == NULL ||
            (*uri = strsep(&p, " \r\n")) == NULL) {
                return (-1);
        }
        for (i = 0; i < params_sz ; i++) {
                if ((params[i].key = strsep(&p, "=")) == NULL)
                        break;
                if ((params[i].value = strsep(&p, " \r\n")) == NULL)
                        return (-1);
        }
        return (i);
}

int
main(void)
{
	duo_t *duo;
	duocode_t code;
        struct duo_param params[16];
	char *apihost, *ikey, *skey, buf[256];
        const char *method, *uri, *body;
        int n;
        
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
        for (;;) {
                printf("duoapi> ");
                fflush(stdout);
                
                if (fgets(buf, sizeof(buf), stdin) == NULL)
                        break;

                if ((n = _parse_line(buf, &method, &uri, params,
                            sizeof(params) / sizeof(*params))) < 0) {
                        fprintf(stderr, "usage: GET|POST <uri> "
                            "[key=value ...]\n");
                        continue;
                }
                code = duo_call(duo, method, uri, params, n);
                body = duo_get_response(duo);
        
                if (code != DUO_OK) {
                        fprintf(stderr, "%s (%d): %s\n",
                            _duo_codename(code), code, duo_get_error(duo));
                }
                printf("%s%s", body ? body : "", body ? "\n" : "");
        }
        printf("\n");
        duo_close(duo);
		
        exit(0);
}
