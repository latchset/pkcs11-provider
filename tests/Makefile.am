EXTRA_DIST = openssl.cnf.in
noinst_DATA = openssl.cnf

softokenpath=@SOFTOKENDIR@/@SOFTOKEN_SUBDIR@libsoftokn3.so
libtoollibs=@abs_top_builddir@/src/.libs
testsdir=@abs_top_builddir@/tests

check_PROGRAMS = tsession tgenkey ttls

tsession_SOURCES = tsession.c
tsession_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
tsession_LDADD = $(OPENSSL_LIBS)

tgenkey_SOURCES = tgenkey.c
tgenkey_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
tgenkey_LDADD = $(OPENSSL_LIBS)

ttls_SOURCES = ttls.c
ttls_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
ttls_LDADD = $(OPENSSL_LIBS)

dist_check_SCRIPTS = \
	test.sh

check_SCRIPTS = $(softokenpath)

TESTS = $(dist_check_SCRIPTS) tgenkey ttls

TESTS_ENVIRONMENT =     \
	OPENSSL_CONF="openssl.cnf" \
	PKCS11_PROVIDER_DEBUG="file:tmp/p11prov-debug.log" \
	LC_ALL="C"

CLEANFILES = \
	openssl.cnf

clean-local:
	rm -Rf tmp
	rm -Rf tokens

DISTCLEANFILES = \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

edit_cmd = $(SED) \
    -e 's|@softokenpath[@]|$(softokenpath)|g' \
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
