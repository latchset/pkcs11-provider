
AM_CFLAGS = $(STD_CFLAGS)

noinst_HEADERS = pkcs11.h provider.h
pkcs11_LTLIBRARIES = pkcs11.la

SHARED_EXT=@SHARED_EXT@

pkcs11dir = $(libdir)/ossl-modules

pkcs11_la_SOURCES = \
	asymmetric_cipher.c \
	debug.c \
	encoder.c \
	digests.c \
	exchange.c \
	kdf.c \
	keymgmt.c \
	oasis/pkcs11.h \
	oasis/pkcs11f.h \
	oasis/pkcs11t.h \
	objects.c \
	pkcs11.h \
	platform/endian.h \
	provider.h \
	provider.c \
	session.c \
	signature.c \
	store.c \
	tls.c \
	util.c \
	provider.exports \
	$(NULL)

pkcs11_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_CFLAGS) -Wall -Werror
pkcs11_la_LIBADD = $(OPENSSL_LIBS)

pkcs11_la_LDFLAGS = \
	$(AM_LDFLAGS) -module \
	-shared -shrext $(SHARED_EXT) \
	-avoid-version \
	-export-symbols "$(srcdir)/provider.exports"

DISTCLEANFILES = \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in config.h.in
