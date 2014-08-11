/*
 * duo.h
 *
 * Copyright (c) 2013 Duo Security
 * All rights reserved, all wrongs reversed.
 */
  
#ifndef DUO_H
#define DUO_H

/* API status codes */
typedef enum {
        DUO_OK = 0,                     /* API success */
        DUO_FAIL,                       /* API error */
        DUO_LIB_ERROR,                  /* library error */
        DUO_CONN_ERROR,                 /* connection error */
        DUO_CLIENT_ERROR,               /* client HTTP error */
        DUO_SERVER_ERROR,               /* server HTTP error */
} duocode_t;

struct duo_param {
        const char	*key;
        const char	*value;
};

typedef struct duo_ctx duo_t;

/* Initialize Duo API handle */
duo_t	   *duo_init(const char *apihost, const char *ikey, const char *skey,
                const char *progname, const char *cafile, const char *proxy);

/* Configure a timeout on appropriate network operations.
 * Set seconds to the number of seconds to wait for network operations,
 * or 0 to disable timeouts.  The timeout is capped at 5 minutes.
 */
duocode_t duo_set_timeout(duo_t * const d, unsigned int seconds);

/* Execute low-level API call */
duocode_t   duo_call(duo_t *d, const char *method, const char *uri,
                struct duo_param *params, int param_cnt);

/* Retrieve the raw response body from the last API call */
const char *duo_get_response(duo_t *d);

/* Retrieve the error message from the last API call */
const char *duo_get_error(duo_t *d);

/* Retrieve the status code from the last API call */
duocode_t   duo_get_code(duo_t *d);

/* Close Duo API handle */
duo_t      *duo_close(duo_t *d);

/*
 * Duo Auth API
 */
struct duo_device {
        int capabilities; // bitmask of DUO_DEVCAP_*
        const char *device;
        const char *display_name;
        const char *name;
        const char *next_sms_passcode;
        const char *number;
        const char *type;
};

#define DUO_DEVCAP_PUSH   (1 << 0)
#define DUO_DEVCAP_PHONE  (1 << 1)
#define DUO_DEVCAP_SMS    (1 << 2)

struct duo_factor {
        const char *option;
        const char *label;
};

struct duo_push_params {
        const char *device;
        const char *type;
        const char *display_username;
        const char *pushinfo;
};

#define DUO_MAX_CODES   10
#define DUO_MAX_DEVICES 10
#define DUO_MAX_FACTORS 30

union duo_auth_ok {
        /* ping */
        struct {
                int time;
        } ping;
        /* check */
        struct {
                int time;
        } check;
        /* enroll_status */
        struct {
                const char *response;
        } enroll_status;
        /* enroll */
        struct {
                const char *activation_barcode;
                const char *activation_code;
                int expiration;
                const char *user_id;
                const char *username;
        } enroll;
        /* bypass_codes */
        struct {
                const char *codes[DUO_MAX_CODES];
                int codes_cnt;
                int expiration;
        } bypass_codes;
        /* preauth */
        struct {
                const char *result;
                const char *status_msg;
                struct duo_device devices[DUO_MAX_DEVICES];
                int devices_cnt;
                struct {
                        const char *text;
                        struct duo_factor factors[DUO_MAX_FACTORS];
                        int factors_cnt;
                } prompt;
        } preauth;
        /* auth */
        struct {
                const char *result;
                const char *status;
                const char *status_msg;
        } auth;
        /* XXX skip async, auth_status */
};

struct duo_auth_fail {
        int code;
        const char *message;
        const char *message_detail;
};

struct duo_auth {
        duocode_t stat;
        void *__private;
        struct duo_auth_fail fail;
        union duo_auth_ok ok;
};

struct duo_auth *duo_auth_ping(duo_t *d);

struct duo_auth *duo_auth_check(duo_t *d);

struct duo_auth *duo_auth_enroll(duo_t *d, const char *username,
    const char *valid_secs);

struct duo_auth *duo_auth_enroll_status(duo_t *d, const char *user_id,
    const char *activation_code);

struct duo_auth *duo_auth_bypass_codes(duo_t *d, const char *username,
    const char *count, const char *valid_secs);

struct duo_auth *duo_auth_preauth(duo_t *d, const char *username);

struct duo_auth *duo_auth_auth(duo_t *d, const char *username,
    const char *factor, const char *ipaddr, const void *factor_arg);

struct duo_auth *duo_auth_free(struct duo_auth *res);

#endif /* DUO_H */
