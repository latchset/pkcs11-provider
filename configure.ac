#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([pkcs11prov], [0.1], [simo@redhat.com])
AC_CONFIG_SRCDIR([src/provider.c])
AC_CONFIG_HEADERS([src/config.h])
AM_INIT_AUTOMAKE

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
])
AC_OUTPUT
