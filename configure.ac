#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([pkcs11-provider], [0.3], [simo@redhat.com])
AC_CONFIG_SRCDIR([src/provider.c])
AC_CONFIG_HEADERS([src/config.h])
AM_INIT_AUTOMAKE([foreign dist-xz -Wall -Werror])
AC_CONFIG_MACRO_DIRS([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR
LT_INIT
PKG_PROG_PKG_CONFIG

AX_CHECK_COMPILE_FLAG([-std=c11],
                      [CFLAGS="$CFLAGS -std=c11"],
                      AC_MSG_ERROR([C compiler must support at least C11 standard])
)

AX_VALGRIND_CHECK()

STD_CFLAGS="-Wall -Wextra -Wwrite-strings -Wpointer-arith -Wno-missing-field-initializers -Wformat -Wshadow"

# Temporarily disable unused parameter until the implementation is complete
STD_CFLAGS="$STD_CFLAGS -Wno-unused-parameter"

# These should be always errors
STD_CFLAGS="$STD_CFLAGS -Werror=implicit-function-declaration -Werror=missing-prototypes -Werror=format-security -Werror=parentheses -Werror=implicit -Werror=strict-prototypes"

# Don't enable warnings on VLA yet, but I would avoid using VLAs
# STD_CFLAGS"$STD_CFLAGS -Werror=vla"

AX_CHECK_COMPILE_FLAG([-fno-strict-aliasing],
		      [STD_CFLAGS="$STD_CFLAGS -fno-strict-aliasing"])
AX_CHECK_COMPILE_FLAG([-Werror -fno-delete-null-pointer-checks],
		      [STD_CFLAGS="$STD_CFLAGS -fno-delete-null-pointer-checks"])
AX_CHECK_COMPILE_FLAG([-fdiagnostics-show-option],
		      [STD_CFLAGS="$STD_CFLAGS -fdiagnostics-show-option"])

AC_SUBST([STD_CFLAGS])

AC_ARG_WITH([openssl],
  [AS_HELP_STRING([--with-openssl],[the path to the OpenSSL files])],
  [
      OPENSSL_DIR=${withval}
      case "$OPENSSL_DIR" in
        # Relative paths
        ./*|../*)  OPENSSL_DIR="`pwd`/$OPENSSL_DIR"
      esac
      if test -d "$OPENSSL_DIR/lib64"; then
        libcrypto_path="$OPENSSL_DIR/lib64"
      elif test -d "$OPENSSL_DIR/lib"; then
        libcrypto_path="$OPENSSL_DIR/lib"
      else
        # Built but not installed
        libcrypto_path="$OPENSSL_DIR"
      fi
      CFLAGS="-I$OPENSSL_DIR/include $CFLAGS"
      LDFLAGS="-L${libcrypto_path} ${LDFLAGS}"
      LIBS="$LIBS -L${libcrypto_path}"
      CRYPTO_LIBS="-lcrypto"
      OPENSSL_LIBS="-lcrypto -lssl"
      AC_MSG_WARN([Custom openssl located in $OPENSSL_DIR is used, lib version check is skipped])
  ],
  [
      # Checks for libraries.
      PKG_CHECK_MODULES(
        [CRYPTO],
        [libcrypto >= 3.0.7],
        ,
        [AC_MSG_ERROR([libcrypto >= 3.0.7 is required])]
      )
      PKG_CHECK_MODULES(
        [OPENSSL],
        [libcrypto >= 3.0.7, libssl],
        ,
        [AC_MSG_ERROR([libcrypto >= 3.0.7 is required])]
      )
  ])

address_sanitizer_path="no"
AC_MSG_CHECKING(for --with-address-sanitizer)
AC_ARG_WITH(address_sanitizer,
  AS_HELP_STRING([--with-address-sanitizer=yes|path_to_libasan.so],
                 [Enable Address Sanitizer @<:@default=no@:>@]),
  [
      address_sanitizer_path=${withval}
      CFLAGS="-fsanitize=address -fno-omit-frame-pointer $CFLAGS"
      LDFLAGS="-fsanitize=address $LDFLAGS"
  ],
  [
      address_sanitizer_path="no"
  ])
AS_IF([test "x$address_sanitizer_path" != "xno"],
      [AS_IF([test "x$address_sanitizer_path" == "xyes"],
             [address_sanitizer_path=`realpath $($CC -print-file-name=libasan.so)`],
             [])],
      [])

AC_MSG_RESULT($address_sanitizer_path)
AM_CONDITIONAL([ADDRESS_SANITIZER], [test x${address_sanitizer_path} != xno])
AC_SUBST(ADDRESS_SANITIZER_PATH, "$address_sanitizer_path")

AC_SUBST([SHARED_EXT], $(eval echo "${shrext_cmds}"))

# Check whether we have a p11-kit to use as a default PKCS#11 module
PKG_CHECK_EXISTS([p11-kit-1],
                 [PKG_CHECK_VAR([DEFAULT_PKCS11_MODULE],
                                [p11-kit-1],
                                [proxy_module])],
                 [AC_MSG_WARN([The P11-kit proxy is not available. No fallback PKCS11 module used.])])
if test "x$DEFAULT_PKCS11_MODULE" != "x"; then
    AC_DEFINE_UNQUOTED([DEFAULT_PKCS11_MODULE], "$DEFAULT_PKCS11_MODULE",
              [Default PKCS11 module])
fi


# Try nss-softoken first as used on Fedora,
# fallback to "nss" as used on Debian
PKG_CHECK_EXISTS(
        [nss-softokn],
        [PKG_CHECK_VAR([SOFTOKENDIR], [nss-softokn], [libdir])],
        [PKG_CHECK_EXISTS(
                [nss],
                [PKG_CHECK_VAR([SOFTOKENDIR], [nss], [libdir])]
        )]
)

if ! test -f $SOFTOKENDIR/libsoftokn3$SHARED_EXT; then
    if test -f $SOFTOKENDIR/nss/libsoftokn3$SHARED_EXT; then
        AC_SUBST([SOFTOKEN_SUBDIR], "nss/")
    else
        AC_MSG_WARN([Softoken library missing, tests will fail!])
    fi
fi

# find p11-kit-client to separate softhsm openssl context from our tests
PKG_CHECK_EXISTS([p11-kit-1],
                 [PKG_CHECK_VAR([P11_MODULE_PATH],
                                [p11-kit-1],
                                [p11_module_path])],
                 [AC_MSG_WARN([The p11-kit client not found. Can not run SoftHSM tests])])
if test "$P11_MODULE_PATH" != "" ; then
	# p11-kit-client is a module, so its name ends with .so also on macOS!
    AC_SUBST([P11KITCLIENTPATH], "$P11_MODULE_PATH/p11-kit-client.so")
fi

# Checks for header files.
AC_CHECK_HEADERS([dlfcn.h], , [AC_MSG_ERROR([<dlfcn.h> is not found])])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_BIGENDIAN
AC_C_INLINE
AC_TYPE_SIZE_T

AC_CONFIG_FILES([
	Makefile
	docs/Makefile
	src/Makefile
	tests/Makefile
])
AC_OUTPUT
