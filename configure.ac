dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.59)
AC_INIT([grid-pkcs11], 1.0, [daniel.kouril@cesnet.cz])
AC_CONFIG_SRCDIR([pkcs11_main.c])
AM_CONFIG_HEADER(config.h)

test -z "$CFLAGS" && CFLAGS="-g"

AM_INIT_AUTOMAKE([foreign no-dependencies 1.9])
AM_MAINTAINER_MODE

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CC_STDC

AC_PROG_LIBTOOL

AC_CONFIG_FILES(Makefile)

HAVE_MYPROXY=no
AC_ARG_WITH(myproxy,
    [  --with-myproxy=PATH	  Path to MyProxy directory],
    [ if test "x$withval" = "xyes" ; then
          AC_MSG_ERROR([--with-myproxy requires PATH argument])
      fi
      CPPFLAGS="-I${withval}/include/noflavor $CPPFLAGS"
      LDFLAGS="-L${withval}/lib $LDFLAGS"
      AC_CHECK_LIB(myproxy_noflavor, myproxy_init_client, ,
		   AC_MSG_ERROR([libmyproxy_noflavor not found]))
      HAVE_MYPROXY=yes
    ]
)

AM_CONDITIONAL([HAVE_MYPROXY], [test x$HAVE_MYPROXY = xyes])

AC_OUTPUT
