Name:          pkcs11-provider
Version:       0.1
Release:       1%{?dist}
Summary:       A PKCS#11 provider for OpenSSL 3.0+
License:       Apache-2.0
URL:           https://github.com/latchset/pkcs11-provider
Source0:       %{url}/releases/download/v%{version}/%{name}-%{version}.tar.xz

BuildRequires: openssl-devel >= 3.0.5
BuildRequires: gcc
BuildRequires: autoconf-archive
BuildRequires: automake
BuildRequires: libtool
BuildRequires: make
# for tests
BuildRequires: nss-devel
BuildRequires: nss-softokn
BuildRequires: nss-softokn-devel
BuildRequires: nss-tools
BuildRequires: openssl
BuildRequires: softhsm
BuildRequires: opensc
BuildRequires: p11-kit-devel
BuildRequires: p11-kit-server
BuildRequires: gnutls-utils
BuildRequires: xz
BuildRequires: expect


%description
This is an Openssl 3.x provider to access Hardware or Software Tokens using
the PKCS#11 Cryptographic Token Interface.
This code targets version 3.0 of the interface but should be backwards
compatible to previous versions as well.


%prep
%autosetup -p1


%build
autoreconf -fi
%configure
%make_build


%install
%make_install


%check
# do not run them in parrallel with %{?_smp_mflags}
make check || if [ $? -ne 0 ]; then cat tests/*.log; exit 1; fi;


%files
%license COPYING
%{_mandir}/man7/*
%doc README.md
%{_libdir}/ossl-modules/pkcs11.so


%changelog
* Mon Oct 24 2022 Jakub Jelen <jjelen@redhat.com> - 0.1-1
+ Initial Fedora release
