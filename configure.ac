#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# Copyright (C) 2022 Simo Sorce <simo@redhat.com>
#
# SPDX-License-Identifier: Apache-2.0

AC_PREREQ([2.71])
AC_INIT([pkcs11prov], [0.1], [simo@redhat.com])
AC_CONFIG_SRCDIR([src/provider.c])
AC_CONFIG_HEADERS([src/config.h])
AM_INIT_AUTOMAKE([foreign dist-xz])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG

# Checks for libraries.
PKG_CHECK_MODULES(
	[OPENSSL],
	[libcrypto >= 3.0.0],
	,
	[AC_MSG_ERROR([libcrypto >= 3.0.0 is required])]
)
AC_SUBST([SHARED_EXT], $(eval echo "${shrext_cmds}"))

# Try nss-softoken first as used on Fedora,
# fallback to "nss" as used on Debian
PKG_CHECK_EXISTS(
        [nss-softokn],
        [PKG_CHECK_VAR([SOFTOKENDIR], [nss-softokn], [libdir])],
        [PKG_CHECK_EXISTS(
                [nss],
                [PKG_CHECK_VAR([SOFTOKENDIR], [nss], [libdir], [AC_SUBST([SOFTOKEN_SUBDIR], "nss/")])]
        )]
)

AS_IF([test "x$SOFTOKENDIR" = "x"], [
  AC_MSG_WARN([Unable to identify softoken plugin path.])
])

# Checks for header files.
AC_CHECK_HEADERS([string.h dlfcn.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([strpbrk])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	tests/Makefile
])
AC_OUTPUT
