
noinst_HEADERS = pkcs11.h provider.h
lib_LTLIBRARIES = pkcs11prov.la

SHARED_EXT=@SHARED_EXT@

pkcs11prov_la_SOURCES = \
	provider.c \
	provider_debug.c \
	provider_util.c \
	provider_keys.c \
	provider_store.c \
	provider_keymgmt.c \
	provider_exchange.c \
	provider_signature.c \
	provider_asym_cipher.c

pkcs11prov_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_CFLAGS)
pkcs11prov_la_LIBADD = $(OPENSSL_LIBS)

pkcs11prov_la_LDFLAGS = $(AM_LDFLAGS) -module -shared -shrext $(SHARED_EXT) \
	-avoid-version -export-symbols "$(srcdir)/provider.exports"


