EXTRA_DIST = openssl.cnf.in

libspath=@abs_top_builddir@/src/.libs
testsblddir=@abs_top_builddir@/tests
testssrcdir=@abs_srcdir@

check_PROGRAMS = tsession tgenkey ttls tdigests treadkeys

tsession_SOURCES = tsession.c
tsession_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
tsession_LDADD = $(OPENSSL_LIBS)

tgenkey_SOURCES = tgenkey.c
tgenkey_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
tgenkey_LDADD = $(OPENSSL_LIBS)

ttls_SOURCES = ttls.c
ttls_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
ttls_LDADD = $(OPENSSL_LIBS)

tdigests_SOURCES = tdigests.c
tdigests_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
tdigests_LDADD = $(OPENSSL_LIBS)

treadkeys_SOURCES = treadkeys.c
treadkeys_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
treadkeys_LDADD = $(OPENSSL_LIBS)

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
	test-wrapper tbasic tcerts tecc tecdh thkdf toaepsha2 trsapss

test_LIST = \
	basic-softokn basic-softhsm-proxy \
	certs-softokn certs-softhsm-proxy \
	ecc-softokn ecc-softhsm-proxy \
	ecdh-softokn \
	oaepsha2-softokn \
	hkdf-softokn \
	rsapss-softokn \
	digests-softokn digests-softhsm-proxy \
	genkey-softokn genkey-softhsm \
	session-softokn session-softhsm-proxy \
	readkeys-softokn readkeys-softhsm-proxy \
	tls-softokn tls-softhsm-proxy
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
