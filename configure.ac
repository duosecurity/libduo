# 
# Copyright (c) 2013 Duo Security
# All rights reserved, all wrongs reversed.

AC_INIT([libduo], [2.1.0], [duo_unix@duosecurity.com])
AC_CONFIG_SRCDIR([duo.c])
AC_LANG([C])

# Determine platform
AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([CANONICAL_HOST], ["${host}"], [Canonical host])
AC_AIX

AC_CONFIG_HEADER([config.h])
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AC_C_BIGENDIAN

# Checks for programs.
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_EGREP
AC_PATH_PROG([AR], [ar])

# Check for functions
AC_CHECK_FUNCS([getaddrinfo])

if test -z "$LD" ; then
        LD=$CC
fi
AC_SUBST([LD])

# Compiler options
if test "x$GCC" = "xyes"; then
   CFLAGS="$CFLAGS -Wall -D_FORTIFY_SOURCE=2"
   AC_MSG_NOTICE([Adding gcc options: $CFLAGS])
fi
GGL_CHECK_STACK_PROTECTOR([has_stack_protector=yes], [has_stack_protector=no])
# XXX - disable -fstack-protector due to missing libssp_nonshared
case "$host_os" in
     *aix*)
	AC_MSG_NOTICE([-fstack-protector disabled on AIX])
	has_stack_protector=no
	;;
     *sunos*)
	AC_MSG_NOTICE([-fstack-protector disabled on SunOS])
	has_stack_protector=no
	;;
     *solaris*)
	AC_MSG_NOTICE([-fstack-protector disabled on Solaris])
	has_stack_protector=no
	;;
esac
if test x$has_stack_protector = xyes; then
   CFLAGS="$CFLAGS -fstack-protector"
   AC_MSG_NOTICE([-fstack-protector enabled in CFLAGS])
fi

# Check for platform features
AC_C_BIGENDIAN
AC_C_CONST

# Check headers
AC_HEADER_STDC
AC_CHECK_HEADERS([inttypes.h limits.h memory.h stdint.h stdlib.h string.h unistd.h])

# Check OpenSSL
AX_CHECK_OPENSSL([], AC_MSG_FAILURE([OpenSSL not found]))

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
