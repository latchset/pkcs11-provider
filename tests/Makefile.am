EXTRA_DIST = openssl.cnf.in test.sh common.sh setup-softhsm.sh setup-softokn.sh
noinst_DATA = openssl.cnf

libtoollibs=@abs_top_builddir@/src/.libs
testsdir=@abs_top_builddir@/tests

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

dist_check_SCRIPTS = \
	test-softhsm.sh \
	test-softokn.sh

check_SCRIPTS = $(softokenpath)

test_LIST = \
	digests-softokn digests-softhsm \
	genkey-softokn genkey-softhsm-noproxy \
	tls-softokn tls-softhsm
.PHONY: $(test_LIST)

TESTS = $(dist_check_SCRIPTS) $(test_LIST)

TEST_EXTENSIONS = .sh
TESTS_ENVIRONMENT =     \
	OPENSSL_CONF="openssl.cnf" \
	P11KITCLIENTPATH="$(P11KITCLIENTPATH)" \
	PKCS11_PROVIDER_MODULE="$(SOFTOKENDIR)/$(SOFTOKEN_SUBDIR)libsoftokn3.so" \
	PKCS11_PROVIDER_DEBUG="file:tmp.softokn/p11prov-debug.log" \
	SOURCE_PATH='$(top_srcdir)' \
	TESTS_PATH='$(testsdir)' \
	LC_ALL="C"

LOG_COMPILER = $(testsdir)/test-wrapper

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
