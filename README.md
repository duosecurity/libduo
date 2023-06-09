# Overview

[![Issues](https://img.shields.io/github/issues/duosecurity/libduo)](https://github.com/duosecurity/libduo/issues)
[![Forks](https://img.shields.io/github/forks/duosecurity/libduo)](https://github.com/duosecurity/libduo/network/members)
[![Stars](https://img.shields.io/github/stars/duosecurity/libduo)](https://github.com/duosecurity/libduo/stargazers)
[![License](https://img.shields.io/badge/License-View%20License-orange)](https://github.com/duosecurity/libduo/blob/master/LICENSE)

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

## TLS 1.2 and 1.3 Support

libduo uses the system's OpenSSL library for TLS operations. It will use the highest TLS version available when making API calls to Duo. TLS 1.2 support requires OpenSSL 1.0.1 or higher; TLS 1.3 support requires OpenSSL 1.1.1 or higher.

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

# Static Analysis

Install [cppcheck](http://cppcheck.sourceforge.net/)

```
$ cppcheck --quiet --force  --suppressions-list=.false_positive.txt --error-exitcode=1 .
```
.false_positive.txt is a list of errors that were found to not be errors when running the above command for Cppcheck.
