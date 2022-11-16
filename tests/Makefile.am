EXTRA_DIST = openssl.cnf.in

libspath=@abs_top_builddir@/src/.libs
testsdir=@abs_srcdir@

check_PROGRAMS = tsession tgenkey ttls tdigests

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

tmp.softokn:
	LIBSPATH=$(libspath) \
	TESTSDIR=$(testsdir) \
	SOFTOKNPATH="$(SOFTOKENDIR)/$(SOFTOKEN_SUBDIR)" \
	$(testsdir)/setup-softokn.sh > setup-softokn.log
tmp.softhsm:
	LIBSPATH=$(libspath) \
	TESTSDIR=$(testsdir) \
	P11KITCLIENTPATH="$(P11KITCLIENTPATH)" \
	$(testsdir)/setup-softhsm.sh > setup-softhsm.log

dist_check_SCRIPTS = \
	helpers.sh setup-softhsm.sh setup-softokn.sh softhsm-proxy.sh \
	test-wrapper tbasic teccsha2 thkdf toaepsha2 trsapss

test_LIST = \
	basic-softokn basic-softhsm-proxy \
	eccsha2-softokn \
	oaepsha2-softokn \
	hkdf-softokn \
	rsapss-softokn \
	digests-softokn digests-softhsm-proxy \
	genkey-softokn genkey-softhsm \
	session-softokn session-softhsm-proxy \
	tls-softokn tls-softhsm-proxy
.PHONY: $(test_LIST)

TESTS = $(test_LIST)

$(TESTS): tmp.softokn tmp.softhsm

TESTS_ENVIRONMENT =     \
	LC_ALL="C"
LOG_COMPILER = $(testsdir)/test-wrapper

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
