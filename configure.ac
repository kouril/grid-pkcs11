dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.60)
AC_INIT([grid-pkcs11], 1.0, [daniel.kouril@cesnet.cz])
AC_CONFIG_SRCDIR([pkcs11_main.c])
AM_CONFIG_HEADER(config.h)

test -z "$CFLAGS" && CFLAGS="-g"

AM_INIT_AUTOMAKE([foreign no-dependencies 1.9])
AM_MAINTAINER_MODE

AC_USE_SYSTEM_EXTENSIONS

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CC_STDC

AC_PROG_LIBTOOL

AC_CONFIG_FILES(Makefile)

MYPROXY_FLAVOR=noflavor
AC_ARG_WITH(myproxy-flavor,
    [  --with-myproxy-flavor=FLAVOR	MyProxy/Globus flavor to use ('noflavor' is used by default)],
    [ MYPROXY_FLAVOR="$withval" ]
)


HAVE_MYPROXY=no
AC_ARG_WITH(myproxy,
    [  --with-myproxy=PATH	  Path to MyProxy directory],
    [ if test "x$withval" = "xyes" ; then
          AC_MSG_ERROR([--with-myproxy requires PATH argument])
      fi
      CPPFLAGS="-I${withval}/include/$MYPROXY_FLAVOR $CPPFLAGS"
      LDFLAGS="-L${withval}/lib $LDFLAGS"
      AC_CHECK_LIB(myproxy_$MYPROXY_FLAVOR, myproxy_init_client, ,
		   AC_MSG_ERROR([libmyproxy_$MYPROXY_FLAVOR not found]))
      HAVE_MYPROXY=yes
      AC_DEFINE([HAVE_MYPROXY], [1], [MyProxy support is enabled])
    ]
)

AM_CONDITIONAL([HAVE_MYPROXY], [test x$HAVE_MYPROXY = xyes])

AC_OUTPUT
