/*
 * duo.c
 *
 * Copyright (c) 2013 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#include "config.h"

#include <sys/types.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>

#include "duo.h"
#include "https.h"
#include "parson.h"
#include "urlenc.h"

struct duo_ctx {
        https_t    *https;               /* HTTPS handle */
        char       *host;                /* host[:port] */
        char       *ikey;                /* integration key */
        char       *skey;                /* secret key */
        char        err[256];            /* error message */
        duocode_t   code;                /* last code */
        const char *body;                /* response body */
        int         https_timeout;       /* milliseconds timeout */
};

/* Initialize Duo API handle */
struct duo_ctx *
duo_init(const char *apihost, const char *ikey, const char *skey,
    const char *progname, const char *cafile, const char *proxy)
{
        struct duo_ctx *ctx;
        char useragent[128];

        if ((ctx = calloc(1, sizeof(*ctx))) == NULL ||
            (ctx->host = strdup(apihost)) == NULL ||
            (ctx->ikey = strdup(ikey)) == NULL ||
            (ctx->skey = strdup(skey)) == NULL) {
                return (duo_close(ctx));
        }
        if (snprintf(useragent, sizeof(useragent), "%s (%s) libduo/%s",
                progname, CANONICAL_HOST, PACKAGE_VERSION) >= sizeof(useragent)) {
                return (duo_close(ctx));
        }
        if (https_init(useragent, cafile, proxy) != HTTPS_OK) {
                ctx = duo_close(ctx);
        }
        ctx->https_timeout = DUO_NO_TIMEOUT;
        return (ctx);
}

duocode_t
duo_set_timeout(duo_t * const d, unsigned int seconds)
{
    /* set a floor on the timeout */
    if (seconds <= 0) {
        seconds = DUO_NO_TIMEOUT;
    } else {
        /* Set a ceiling on the timeout */
        const int max_timeout = 60*5;
        if (seconds > max_timeout) {
            seconds = max_timeout;
        }
        /* https_timeout is in milliseconds */
        d->https_timeout = seconds * 1000;
    }
    return DUO_OK;
}

static void
_duo_seterr(struct duo_ctx *ctx, const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vsnprintf(ctx->err, sizeof(ctx->err), fmt, ap);
        va_end(ap);
}

static int
__param_cmp(const void *a0, const void *b0)
{
        struct duo_param *a = (struct duo_param *)a0;
        struct duo_param *b = (struct duo_param *)b0;
        
        return (strcmp(a->key, b->key));
}

static char *
_params_to_qs(struct duo_param *params, int param_cnt)
{
        BIO *bio;
        char *p, *k, *v, *buf;
        int i, len;

        if ((bio = BIO_new(BIO_s_mem())) == NULL) {
                return (NULL);
        }
        qsort(params, param_cnt, sizeof(params[0]), __param_cmp);
        
        for (i = 0; i < param_cnt; i++) {
                k = urlenc_encode(params[i].key);
                v = urlenc_encode(params[i].value);
                BIO_printf(bio, "&%s=%s", k, v);
                free(k);
                free(v);
        }
        if ((len = BIO_get_mem_data(bio, &buf)) > 0 &&
            (p = malloc(len)) != NULL) {
                memcpy(p, buf + 1, len - 1);
                p[len - 1] = '\0';
        } else {
                p = strdup("");
        }
        BIO_free_all(bio);

        return (p);
}

/* Return proper HTTP headers to include for signed request */
char *
_sign_request(struct duo_ctx *ctx, const char *method, const char *uri,
    const char *qs)
{
        BIO *bio, *b64;
	HMAC_CTX hmac;
	unsigned char MD[SHA_DIGEST_LENGTH];
        char *p, *buf, date[128];
        time_t t;
        int i, len;

        t = time(NULL);
        strftime(date, sizeof(date), "%a, %d %b %Y %T %z", localtime(&t));
        
        /* Generate signature over the canonicalized request */
        HMAC_CTX_init(&hmac);
	HMAC_Init(&hmac, ctx->skey, strlen(ctx->skey), EVP_sha1());
        HMAC_Update(&hmac, (u_char *)date, strlen(date));
        HMAC_Update(&hmac, (u_char *)"\n", 1);
        HMAC_Update(&hmac, (u_char *)method, strlen(method));
        HMAC_Update(&hmac, (u_char *)"\n", 1);
        HMAC_Update(&hmac, (u_char *)ctx->host, strlen(ctx->host));
        HMAC_Update(&hmac, (u_char *)"\n", 1);
        HMAC_Update(&hmac, (u_char *)uri, strlen(uri));
        HMAC_Update(&hmac, (u_char *)"\n", 1);
        HMAC_Update(&hmac, (u_char *)qs, strlen(qs));
	HMAC_Final(&hmac, MD, NULL);
	HMAC_CTX_cleanup(&hmac);
        
        bio = BIO_new(BIO_s_mem());
        BIO_printf(bio, "Date: %s\r\n", date);
        BIO_puts(bio, "Authorization: Basic ");

        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
        BIO_push(b64, bio);
        BIO_printf(b64, "%s:", ctx->ikey);
        for (i = 0; i < sizeof(MD); i++) {
                BIO_printf(b64, "%02x", MD[i]);
        }
        (void)BIO_flush(b64);

        len = BIO_get_mem_data(bio, &buf);
        if ((p = malloc(len + 1)) != NULL) {
                memcpy(p, buf, len);
                p[len] = '\0';
        }
        BIO_free_all(b64);
        
        return (p);
}

static int
_parse_fail(JSON_Object *obj, struct duo_auth *auth)
{
        auth->stat = DUO_FAIL;
        auth->fail.code = json_object_get_number(obj, "code");
        auth->fail.message = json_object_get_string(obj, "message");
        auth->fail.message_detail = json_object_get_string(obj,
            "message_detail");

        return (auth->fail.code == 0 || auth->fail.message == NULL) ? -1 : 0;
}

duocode_t
duo_call(struct duo_ctx *ctx, const char *method, const char *uri,
    struct duo_param *params, int param_cnt)
{
        HTTPScode err;
        JSON_Value *json;
        JSON_Object *obj;
        struct duo_auth res;
        int i, http_code, len;
        char *qs, *hdrs;
        const char *p;

        /* Initialize our request */
        *ctx->err = '\0';
        ctx->body = NULL;
        
        /* Generate sorted query string for signing */
        if (params == NULL) {
                qs = strdup("");
        } else if ((qs = _params_to_qs(params, param_cnt)) == NULL) {
                return ((ctx->code = DUO_LIB_ERROR));
        }
        /* Generate headers for signed request */
        if ((hdrs = _sign_request(ctx, method, uri, qs)) == NULL) {
                free(qs);
                return (DUO_LIB_ERROR);
        }
        /* Execute API call */
        http_code = len = 0;
        for (i = 0; i < 3; i++) {
                if (ctx->https == NULL &&
                    (err = https_open(&ctx->https, ctx->host)) != HTTPS_OK) {
                        if (err == HTTPS_ERR_SERVER) {
                                sleep(1 << i);
                                continue;
                        }
                        break;
                }
                if (https_send(ctx->https,
                        method, uri, qs, hdrs) == HTTPS_OK &&
                    https_recv(ctx->https,
                        &http_code, &ctx->body, &len, ctx->https_timeout) == HTTPS_OK) {
                        break;
                }
                https_close(&ctx->https);
        }
        free(hdrs);
        free(qs);

        /* Check HTTP response */
        if (http_code == 0) {
                _duo_seterr(ctx, "Couldn't connect to %s: %s",
                    ctx->host, https_geterr());
                return ((ctx->code = DUO_CONN_ERROR));
        }
        if (ctx->body == NULL || strlen(ctx->body) != len) {
                _duo_seterr(ctx, "Invalid or empty response body");
                return ((ctx->code = DUO_SERVER_ERROR));
        }
        /* Caller parses successful response */
        if (http_code / 100 == 2) {
                return ((ctx->code = DUO_OK));
        }
        /* Try to parse API error response */
        if ((json = json_parse_string(ctx->body)) != NULL) {
                if (json_value_get_type(json) == JSONObject &&
                    (obj = json_value_get_object(json)) != NULL &&
                    (p = json_object_get_string(obj, "stat")) != NULL &&
                    strcmp(p, "FAIL") == 0) {
                        memset(&res, 0, sizeof(res));
                        if (_parse_fail(obj, &res) == 0) {
                                if (res.fail.message_detail != NULL) {
                                        _duo_seterr(ctx, "%d: %s: %s",
                                            res.fail.code, res.fail.message,
                                            res.fail.message_detail);
                                } else {
                                        _duo_seterr(ctx, "%d: %s",
                                            res.fail.code, res.fail.message);
                                }
                        }
                }
                json_value_free(json);
        } 
        /* Otherwise, set HTTP error message */
        if (!*ctx->err) {
                if (http_code / 100 == 4) {
                        if (http_code == 400) {
                                _duo_seterr(ctx,
                                    "HTTP 400: Invalid or missing parameters");
                        } else if (http_code == 401) {
                                _duo_seterr(ctx,
                                    "HTTP 401: Bad/missing Authorization or "
                                    "Date headers");
                        } else if (http_code == 405) {
                                _duo_seterr(ctx,
                                    "HTTP 405: Bad method for this endpoint");
                        } else {
                                _duo_seterr(ctx, "HTTP %d: Bad parameters",
                                    http_code);
                        }
                        return ((ctx->code = DUO_CLIENT_ERROR));
                }
                _duo_seterr(ctx, "HTTP %d", http_code);
        }
        return ((ctx->code = DUO_SERVER_ERROR));
}

static int
_parse_bypass_codes(JSON_Object *obj, union duo_auth_ok *ok)
{
        JSON_Array *codes;
        int i;
        
        if ((codes = json_object_get_array(obj, "codes")) == NULL)
                return (-1);
        
        ok->bypass_codes.expiration =
            json_object_get_number(obj, "expiration");
        
        ok->bypass_codes.codes_cnt = json_array_get_count(codes);
        if (ok->bypass_codes.codes_cnt > DUO_MAX_CODES)
                ok->bypass_codes.codes_cnt = DUO_MAX_CODES;
        
        for (i = 0; i < ok->bypass_codes.codes_cnt; i++) {
                ok->bypass_codes.codes[i] = json_array_get_string(codes, i);
        }
        return (0);
}

static int
_parse_enroll(JSON_Object *obj, union duo_auth_ok *ok)
{
        ok->enroll.activation_barcode =
            json_object_get_string(obj, "activation_barcode");
        ok->enroll.activation_code =
            json_object_get_string(obj, "activation_code");
        ok->enroll.expiration =
            json_object_get_number(obj, "expiration");
        ok->enroll.user_id =
            json_object_get_string(obj, "user_id");
        ok->enroll.username =
            json_object_get_string(obj, "username");
        return (0);
}

static int
_parse_preauth(JSON_Object *obj, union duo_auth_ok *ok)
{
        JSON_Array *devs, *caps;
        JSON_Object *dev, *facs;
        struct duo_device *d;
        struct duo_factor *f;
        int i, j, mask;
        const char *p;
        
        ok->preauth.result = json_object_get_string(obj, "result");
        ok->preauth.status_msg = json_object_get_string(obj, "status_msg");
        
        if (strcmp(ok->preauth.result, "auth") == 0) {
                ok->preauth.prompt.text = json_object_dotget_string(obj,
                    "prompt.text");
                if ((devs = json_object_get_array(obj, "devices")) == NULL ||
                    (facs = json_object_dotget_object(obj,
                        "prompt.factors")) == NULL) {
                        return (-1);
                }
                /* Parse devices */
                ok->preauth.devices_cnt = json_array_get_count(devs);
                if (ok->preauth.devices_cnt > DUO_MAX_DEVICES)
                        ok->preauth.devices_cnt = DUO_MAX_DEVICES;
                
                for (i = mask = 0; i < ok->preauth.devices_cnt; i++, mask = 0) {
                        d = &ok->preauth.devices[i];
                        dev = json_array_get_object(devs, i);
                        d->device = json_object_get_string(dev, "device");
                        d->display_name = json_object_get_string(dev,
                            "display_name");
                        d->name = json_object_get_string(dev, "name");
                        d->next_sms_passcode = json_object_get_string(dev,
                            "next_sms_passcode");
                        d->number = json_object_get_string(dev, "number");
                        d->type = json_object_get_string(dev, "type");
                        d->capabilities = 0;
                        caps = json_object_get_array(dev, "capabilities");
                        if (caps == NULL)
                                continue;
                        for (j = 0; j < json_array_get_count(caps); j++) {
                                p = json_array_get_string(caps, j);
                                if (strcmp(p, "push") == 0)
                                        mask |= DUO_DEVCAP_PUSH;
                                else if (strcmp(p, "phone") == 0)
                                        mask |= DUO_DEVCAP_PHONE;
                                else if (strcmp(p, "sms") == 0)
                                        mask |= DUO_DEVCAP_SMS;
                        }
                        d->capabilities = mask;
                }
                /* Parse factors */
                ok->preauth.prompt.factors_cnt = json_object_get_count(facs);
                if (ok->preauth.prompt.factors_cnt > DUO_MAX_FACTORS)
                        ok->preauth.prompt.factors_cnt = DUO_MAX_FACTORS;
                
                for (i = 0; i < ok->preauth.prompt.factors_cnt; i++) {
                        f = ok->preauth.prompt.factors + i;
                        f->option = json_object_get_name(facs, i);
                        f->label = json_object_get_string(facs, f->option);
                }
        } else if (strcmp(ok->preauth.result, "enroll") == 0) {
                ok->preauth.prompt.text = json_object_dotget_string(obj,
                    "prompt.text");
        }
        return (0);
}

static int
_parse_auth(JSON_Object *obj, union duo_auth_ok *ok)
{
        ok->auth.result = json_object_get_string(obj, "result");
        ok->auth.status = json_object_get_string(obj, "status");
        ok->auth.status_msg = json_object_get_string(obj, "status_msg");
        return (0);
}

struct _duo_auth_private {
        char *body;
        JSON_Value *json;
};

static struct duo_auth *
_duo_auth_call(struct duo_ctx *ctx, const char *method, const char *endpoint,
    struct duo_param *params, int cnt)
{
        char uri[128];
        duocode_t code;
        struct duo_auth *auth;
        struct _duo_auth_private *prv;
        JSON_Object *obj, *r;
        const char *p;

        snprintf(uri, sizeof(uri), "/auth/v2/%s", endpoint);
        
        if ((code = duo_call(ctx, method, uri, params, cnt)) != DUO_OK) {
                return (NULL);
        }
        if ((auth = calloc(1, sizeof(*auth))) == NULL ||
            (auth->__private = prv = calloc(1, sizeof(*prv))) == NULL ||
            (prv->body = strdup(ctx->body)) == NULL) {
                _duo_seterr(ctx, "Couldn't allocate result");
                ctx->code = DUO_LIB_ERROR;
                return (duo_auth_free(auth));
        }
        if ((prv->json = json_parse_string(prv->body)) == NULL ||
            json_value_get_type(prv->json) != JSONObject ||
            (obj = json_value_get_object(prv->json)) == NULL ||
            (p = json_object_get_string(obj, "stat")) == NULL) {
                _duo_seterr(ctx, "Invalid JSON response");
                ctx->code = DUO_SERVER_ERROR;
                return (duo_auth_free(auth));
        }
        ctx->code = DUO_LIB_ERROR;

        if (strcmp(p, "FAIL") == 0) {
                if (_parse_fail(obj, auth) == 0)
                        ctx->code = DUO_FAIL;
        } else if (strcmp(p, "OK") == 0) {
                if (strcmp("enroll_status", endpoint) == 0) {
                        auth->ok.enroll_status.response =
                            json_object_get_string(obj, "response");
                        ctx->code = DUO_OK;
                } else if ((r = json_object_get_object(obj, "response"))
                    != NULL) {
                        auth->stat = DUO_OK;
                        if (strcmp("ping", endpoint) == 0 ||
                            strcmp("check", endpoint) == 0) {
                                auth->ok.ping.time =
                                    json_object_get_number(r, "time");
                                ctx->code = DUO_OK;
                        } else if (strcmp("enroll", endpoint) == 0) {
                                if (_parse_enroll(r, &auth->ok) == 0)
                                        ctx->code = DUO_OK;
                        } else if (strcmp("bypass_codes", endpoint) == 0) {
                                if (_parse_bypass_codes(r, &auth->ok)
                                    == 0)
                                        ctx->code = DUO_OK;
                        } else if (strcmp("preauth", endpoint) == 0) {
                                if (_parse_preauth(r, &auth->ok) == 0)
                                        ctx->code = DUO_OK;
                        } else if (strcmp("auth", endpoint) == 0) {
                                if (_parse_auth(r, &auth->ok) == 0)
                                        ctx->code = DUO_OK;
                        }
                }
        }
        if (ctx->code == DUO_LIB_ERROR) {
                _duo_seterr(ctx, "Couldn't parse %s message", endpoint);
                auth = duo_auth_free(auth);
        }
        return (auth);
}

struct duo_auth *
duo_auth_ping(struct duo_ctx *ctx)
{
        return (_duo_auth_call(ctx, "GET", "ping", NULL, 0));
}

struct duo_auth *
duo_auth_check(struct duo_ctx *ctx)
{
        return (_duo_auth_call(ctx, "GET", "check", NULL, 0));
}

#define ADD_PARAM(prms, n, k, v) { 		\
    if (n < sizeof(prms) / sizeof(*prms)) {	\
        prms[n].key = k;			\
        prms[n++].value = v;			\
    }						\
}

struct duo_auth *
duo_auth_enroll(struct duo_ctx *ctx, const char *username,
    const char *valid_secs)
{
        struct duo_param params[2];
        int n = 0;

        if (username)
                ADD_PARAM(params, n, "username", username);
        if (valid_secs)
                ADD_PARAM(params, n, "valid_secs", valid_secs);
        
        return (_duo_auth_call(ctx, "POST", "enroll", params, n));
}

struct duo_auth *
duo_auth_enroll_status(struct duo_ctx *ctx, const char *user_id,
    const char *activation_code)
{
        struct duo_param params[2];
        int n = 0;

        if (user_id)
                ADD_PARAM(params, n, "user_id", user_id);
        if (activation_code)
                ADD_PARAM(params, n, "activation_code", activation_code);

        return (_duo_auth_call(ctx, "POST", "enroll_status", params, n));
}

struct duo_auth *
duo_auth_bypass_codes(struct duo_ctx *ctx, const char *username,
    const char *count, const char *valid_secs)
{
        struct duo_param params[3];
        int n = 0;

        if (username)
                ADD_PARAM(params, n, "username", username);
        if (count)
                ADD_PARAM(params, n, "count", count);
        if (valid_secs)
                ADD_PARAM(params, n, "valid_secs", valid_secs);

        return (_duo_auth_call(ctx, "POST", "bypass_codes", params, n));
}

struct duo_auth *
duo_auth_preauth(struct duo_ctx *ctx, const char *username)
{
        struct duo_param params[] = {
                { "username", username },
                { "text_prompt", "1" },
        };
        return (_duo_auth_call(ctx, "POST", "preauth", params,
                sizeof(params) / sizeof(*params)));
}

struct duo_auth *
duo_auth_auth(struct duo_ctx *ctx, const char *username, const char *factor,
    const char *ipaddr, const void *factor_arg)
{
        struct duo_param params[16];
        int n = 0;
        int https_timeout;
        struct duo_auth *retval;

        /* Disable timeout for this call */
        https_timeout = ctx->https_timeout;
        ctx->https_timeout = DUO_NO_TIMEOUT;
        if (username)
                ADD_PARAM(params, n, "username", username);
        if (factor)
                ADD_PARAM(params, n, "factor", factor);
        if (ipaddr)
                ADD_PARAM(params, n,"ipaddr", ipaddr);

        if (strcmp(factor, "push") == 0) {
                struct duo_push_params *pp =
                    (struct duo_push_params *)factor_arg;
                ADD_PARAM(params, n, "device", pp->device);
                if (pp->type != NULL)
                        ADD_PARAM(params, n, "type", pp->type);
                if (pp->display_username != NULL)
                        ADD_PARAM(params, n, "display_username",
                            pp->display_username);
                if (pp->pushinfo != NULL)
                        ADD_PARAM(params, n, "pushinfo", pp->pushinfo);
        } else if (strcmp(factor, "phone") == 0 ||
                   strcmp(factor, "sms") == 0) {
                ADD_PARAM(params, n, "device", (const char *)factor_arg);
        } else if (strcmp(factor, "passcode") == 0) {
                ADD_PARAM(params, n, "passcode", (const char *)factor_arg);
        } else if (strcmp(factor, "prompt") == 0) {
                ADD_PARAM(params, n, "prompt", (const char *)factor_arg);
        }
        retval = _duo_auth_call(ctx, "POST", "auth", params, n);
        ctx->https_timeout = https_timeout;
        return retval;
}

struct duo_auth *
duo_auth_free(struct duo_auth *auth)
{
        struct _duo_auth_private *prv;
        if (auth != NULL) {
                if (auth->__private != NULL) {
                        prv = (struct _duo_auth_private *)auth->__private;
                        if (prv->json)
                                json_value_free(prv->json);
                        if (prv->body)
                                free(prv->body);
                }
                free(auth);
        }
        return (NULL);
}

/* Retrieve the response from the last API call */
const char *
duo_get_response(struct duo_ctx *ctx)
{
        return (ctx->body);
}

/* Retrieve the error message from the last API call */
const char *
duo_get_error(struct duo_ctx *ctx)
{
        return (ctx->err[0] ? ctx->err : "OK");
}

/* Return the error code from the last API call */
duocode_t
duo_get_code(struct duo_ctx *ctx)
{
        return (ctx->code);
}

/* Close Duo API handle */
struct duo_ctx *
duo_close(struct duo_ctx *ctx)
{
        if (ctx != NULL) {
                if (ctx->https != NULL)
                        https_close(&ctx->https);
                free(ctx->host);
                free(ctx->ikey);
                free(ctx->skey);
                free(ctx);
        }
        return (NULL);
}
