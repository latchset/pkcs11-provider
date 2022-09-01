EXTRA_DIST = openssl.cnf.in
noinst_DATA = openssl.cnf

softokenpath=@SOFTOKENDIR@/@SOFTOKEN_SUBDIR@libsoftokn3.so
libtoollibs=@abs_top_builddir@/src/.libs
testsdir=@abs_top_builddir@/tests

dist_check_SCRIPTS = \
	test.sh

check_SCRIPTS = $(softokenpath)

TESTS = $(dist_check_SCRIPTS)

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
