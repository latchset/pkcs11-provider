
AM_CFLAGS = $(STD_CFLAGS)

noinst_HEADERS = pkcs11.h provider.h
lib_LTLIBRARIES = pkcs11_provider.la

SHARED_EXT=@SHARED_EXT@

pkcs11_provider_la_SOURCES = \
	asymmetric_cipher.c \
	debug.c \
	exchange.c \
	kdf.c \
	keymgmt.c \
	keys.c \
	oasis/pkcs11.h \
	oasis/pkcs11f.h \
	oasis/pkcs11t.h \
	pkcs11.h \
	platform/endian.h \
	provider.h \
	provider.c \
	signature.c \
	store.c \
	util.c \
	provider.exports \
	$(NULL)

pkcs11_provider_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_CFLAGS) -Wall -Werror
pkcs11_provider_la_LIBADD = $(OPENSSL_LIBS)

pkcs11_provider_la_LDFLAGS = \
	$(AM_LDFLAGS) -module \
	-shared -shrext $(SHARED_EXT) \
	-avoid-version \
	-export-symbols "$(srcdir)/provider.exports"


