EXTRA_DIST = openssl.cnf.in test.sh common.sh setup-softhsm.sh setup-softokn.sh
noinst_DATA = openssl.cnf

libtoollibs=@abs_top_builddir@/src/.libs
testsdir=@abs_builddir@

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
	SOFTOKNPATH="$(SOFTOKENDIR)/$(SOFTOKEN_SUBDIR)" ./setup-softokn.sh > setup-softokn.log
tmp.softhsm:
	P11KITCLIENTPATH="$(P11KITCLIENTPATH)" ./setup-softhsm.sh > setup-softhsm.log

dist_check_SCRIPTS = \
	tbasic trsapss toaepsha2 thkdf teccsha2

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
LOG_COMPILER = ./test-wrapper

CLEANFILES = \
	openssl.cnf \
	openssl.cnf.softhsm \
	pinfile.txt

clean-local:
	rm -Rf tmp.softhsm
	rm -Rf tmp.softokn

DISTCLEANFILES = \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

edit_cmd = $(SED) \
    -e 's|@libtoollibs[@]|$(libtoollibs)|g' \
    -e 's|@testsdir[@]|$(testsdir)|g'

replace_script = \
    @rm -f $@ $@.tmp; \
    srcdir=''; \
        test -f ./$@.in || srcdir=$(srcdir)/; \
        $(edit_cmd) $${srcdir}$@.in >$@.tmp; \
    mv $@.tmp $@

openssl.cnf: openssl.cnf.in Makefile
	$(replace_script)
