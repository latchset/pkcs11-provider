
AM_CFLAGS = $(STD_CFLAGS)

noinst_HEADERS = \
	asymmetric_cipher.h \
	debug.h \
	encoder.h \
	decoder.h \
	digests.h \
	exchange.h \
	kdf.h \
	keymgmt.h \
	pk11_uri.h \
	interface.h \
	objects.h \
	pkcs11.h \
	platform/endian.h \
	provider.h \
	random.h \
	session.h \
	signature.h \
	slot.h \
	store.h \
	util.h
pkcs11_LTLIBRARIES = pkcs11.la

SHARED_EXT=@SHARED_EXT@

pkcs11dir = $(libdir)/ossl-modules

pkcs11_la_SOURCES = \
	asymmetric_cipher.c \
	debug.c \
	encoder.c \
	decoder.c \
	digests.c \
	exchange.c \
	kdf.c \
	keymgmt.c \
	pk11_uri.c \
	interface.c \
	objects.c \
	provider.h \
	provider.c \
	random.c \
	session.c \
	signature.c \
	slot.c \
	store.c \
	tls.c \
	util.c \
	provider.exports \
	provider.map \
	$(NULL)

EXTRA_DIST = \
	interface.gen.c \
	encoder.gen.c \
	pk11_uri.gen.c \
	meson.build \
	$(NULL)

pkcs11_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_CFLAGS) -Wall -Werror
pkcs11_la_LIBADD = $(CRYPTO_LIBS)

pkcs11_la_LDFLAGS = \
	$(AM_LDFLAGS) -module \
	-shared -shrext $(SHARED_EXT) \
	-avoid-version \
	-export-symbols "$(srcdir)/provider.exports"

DISTCLEANFILES = \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in config.h.in
