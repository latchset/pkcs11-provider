## Copyright (C) 2022 Simo Sorce <simo@redhat.com>
##
## SPDX-License-Identifier: CC0-1.0

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
	provider.c \
	signature.c \
	store.c \
	util.c \
	$(NULL)

pkcs11_provider_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_CFLAGS) -fvisibility=hidden
pkcs11_provider_la_LIBADD = $(OPENSSL_LIBS)

pkcs11_provider_la_LDFLAGS = \
	$(AM_LDFLAGS) -module \
	-shared -shrext $(SHARED_EXT) \
	-avoid-version
