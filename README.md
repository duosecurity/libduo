# Overview

A Duo API implementation in C.

**Auth** - https://www.duosecurity.com/docs/authapi

**Admin** - https://www.duosecurity.com/docs/adminapi

**Accounts** - https://www.duosecurity.com/docs/accountsapi

# Installing

Requires SSL development headers (i.e. `libssl-dev`, `openssl-devel`, etc.)

```
$ git clone https://github.com/duosecurity/libduo.git
$ ./configure
$ make
```

# Testing

Auth:

```
$ DUO_API_HOST=<host-here> DUO_IKEY=<ikey-here> DUO_SKEY=<skey-here> ./test-duologin <username>
```

Admin:

```
$ DUO_API_HOST=<host-here> DUO_IKEY=<ikey-here> DUO_SKEY=<skey-here> ./test-duoapi
duoapi> GET /admin/v1/users [username=testuser]
{'response': [{'desktoptokens': [],
   'email': '',
   'groups': [],
   'last_login': 1455305274,
   'notes': '',
   'phones': [{'activated': True,
     'capabilities': ['push', 'sms', 'phone', 'mobile_otp'],
     'extension': '',
     'name': '',
     'number': '+1123456789',
     'phone_id': 'DPWDGGXXXXXXXXXXXXXX',
     'platform': 'Google Android',
     'postdelay': '',
     'predelay': '',
     'sms_passcodes_sent': True,
     'type': 'Mobile'}],
   'realname': '',
   'status': 'active',
   'tokens': [],
   'user_id': 'DU6XLKXXXXXXXXXXXXXX',
   'username': 'testuser'}],
 'stat': 'OK'}
```
