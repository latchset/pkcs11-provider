EXTRA_DIST = openssl.cnf.in \
	lsan.supp \
	explicit_ec.key.der explicit_ec.pub.der

libspath=@abs_top_builddir@/src/.libs
testsblddir=@abs_top_builddir@/tests
testssrcdir=@abs_srcdir@

@VALGRIND_CHECK_RULES@
#VALGRIND_SUPPRESSIONS_FILES = $(top_srcdir)/tests/pkcs11-provider.supp
VALGRIND_FLAGS = --num-callers=30 -q --keep-debuginfo=yes

check_PROGRAMS = tsession tgenkey tlsctx tdigests treadkeys tcmpkeys tfork pincache

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

tcmpkeys_SOURCES = tcmpkeys.c
tcmpkeys_CFLAGS = $(STD_CFLAGS) $(OPENSSL_CFLAGS)
tcmpkeys_LDADD = $(OPENSSL_LIBS)

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
	toaepsha2 trsapss tdigest ttls tpubkey tfork turi trand tecxc \
	tcms

test_LIST = \
	basic-softokn.t basic-softhsm.t \
	pubkey-softokn.t pubkey-softhsm.t \
	certs-softokn.t certs-softhsm.t \
	ecc-softokn.t ecc-softhsm.t \
	edwards-softhsm.t \
	ecdh-softokn.t \
	democa-softokn.t democa-softhsm.t \
	digest-softokn.t digest-softhsm.t \
	fork-softokn.t fork-softhsm.t \
	oaepsha2-softokn.t \
	hkdf-softokn.t \
	rsapss-softokn.t \
	genkey-softokn.t genkey-softhsm.t \
	session-softokn.t session-softhsm.t \
	rand-softokn.t rand-softhsm.t \
	readkeys-softokn.t readkeys-softhsm.t \
	tls-softokn.t tls-softhsm.t \
	uri-softokn.t uri-softhsm.t \
	ecxc-softhsm.t \
	cms-softokn.t

.PHONY: $(test_LIST)

TESTS = $(test_LIST)

AM_TESTS_ENVIRONMENT =     \
	export LC_ALL='C';

TEST_EXTENSIONS = .t
T_LOG_COMPILER = $(testssrcdir)/test-wrapper

if ADDRESS_SANITIZER
# Avoids closing dlopened libraries for ASan to be able to print usable traces
FAKE_DLCLOSE=.libs/fake_dlclose.so
lib_LTLIBRARIES = fake_dlclose.la
fake_dlclose_la_SOURCES = fake_dlclose.c
fake_dlclose_la_CFLAGS = $(AM_CFLAGS) -Wall -Werror
fake_dlclose_la_LDFLAGS = $(AM_LDFLAGS) -module -shared -avoid-version

# LD_PRELOAD is needed before invoking openssl as it is not instrumented with
# asan and asan needs to be loaded as a firs dynamic library of the process.
AM_TESTS_ENVIRONMENT += \
	export ASAN_OPTIONS='fast_unwind_on_malloc=0'; \
	export LSAN_OPTIONS='suppressions=$(testssrcdir)/lsan.supp'; \
	export DLCLOSE='$(testsblddir)/$(FAKE_DLCLOSE)'; \
	export CHECKER='env LD_PRELOAD=$(ADDRESS_SANITIZER_PATH):$(testsblddir)/$(FAKE_DLCLOSE)';
endif

$(TESTS): tmp.softokn tmp.softhsm $(FAKE_DLCLOSE)

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
