EXTRA_DIST = openssl.cnf.in

libspath=@abs_top_builddir@/src/.libs
testsblddir=@abs_top_builddir@/tests
testssrcdir=@abs_srcdir@

check_PROGRAMS = tsession tgenkey tlsctx tdigests treadkeys tfork pincache

tsession_SOURCES = tsession.c
tsession_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
tsession_LDADD = $(OPENSSL_LIBS)

tgenkey_SOURCES = tgenkey.c
tgenkey_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
tgenkey_LDADD = $(OPENSSL_LIBS)

tlsctx_SOURCES = tlsctx.c
tlsctx_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
tlsctx_LDADD = $(OPENSSL_LIBS)

tdigests_SOURCES = tdigests.c
tdigests_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
tdigests_LDADD = $(OPENSSL_LIBS)

treadkeys_SOURCES = treadkeys.c
treadkeys_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
treadkeys_LDADD = $(OPENSSL_LIBS)

tfork_SOURCES = tfork.c
tfork_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
tfork_LDADD = $(OPENSSL_LIBS)

pincache_SOURCES = pincache.c
pincache_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
pincache_LDADD = $(OPENSSL_LIBS)

tmp.softokn:
	LIBSPATH=$(libspath) \
	TESTSSRCDIR=$(testssrcdir) \
	TESTBLDDIR=$(testsblddir) \
	SHARED_EXT=$(SHARED_EXT) \
	SOFTOKNPATH="$(SOFTOKENDIR)/$(SOFTOKEN_SUBDIR)" \
	$(testssrcdir)/setup-softokn.sh > setup-softokn.log 2>&1
tmp.softhsm:
	LIBSPATH=$(libspath) \
	TESTSSRCDIR=$(testssrcdir) \
	TESTBLDDIR=$(testsblddir) \
	SHARED_EXT=$(SHARED_EXT) \
	P11KITCLIENTPATH="$(P11KITCLIENTPATH)" \
	$(testssrcdir)/setup-softhsm.sh > setup-softhsm.log 2>&1

dist_check_SCRIPTS = \
	helpers.sh setup-softhsm.sh setup-softokn.sh softhsm-proxy.sh \
	test-wrapper tbasic tcerts tecc tecdh tedwards tdemoca thkdf \
	toaepsha2 trsapss tdigest ttls tpubkey tfork turi

test_LIST = \
	basic-softokn basic-softhsm \
	pubkey-softokn pubkey-softhsm \
	certs-softokn certs-softhsm \
	ecc-softokn ecc-softhsm \
	edwards-softhsm \
	ecdh-softokn \
	democa-softokn democa-softhsm \
	digest-softokn digest-softhsm \
	fork-softokn fork-softhsm \
	oaepsha2-softokn \
	hkdf-softokn \
	rsapss-softokn \
	genkey-softokn genkey-softhsm \
	session-softokn session-softhsm \
	readkeys-softokn readkeys-softhsm \
	tls-softokn tls-softhsm \
	uri-softokn uri-softhsm

.PHONY: $(test_LIST)

TESTS = $(test_LIST)

$(TESTS): tmp.softokn tmp.softhsm

TESTS_ENVIRONMENT =     \
	LC_ALL="C"
LOG_COMPILER = $(testssrcdir)/test-wrapper

CLEANFILES = \
	setup-*.log \
	pinfile.txt

clean-local:
	rm -Rf tmp.softhsm
	rm -Rf tmp.softokn

DISTCLEANFILES = \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in
