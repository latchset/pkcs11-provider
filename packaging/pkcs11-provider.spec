#Enable gpg signature verification
%bcond_with gpgcheck

Name:          pkcs11-provider
Version:       0.3
Release:       1%{?dist}
Summary:       A PKCS#11 provider for OpenSSL 3.0+
License:       Apache-2.0
URL:           https://github.com/latchset/pkcs11-provider
Source0:       %{url}/releases/download/v%{version}/%{name}-%{version}.tar.xz
%if %{with gpgcheck}
Source1:       %{url}/releases/download/v%{version}/%{name}-%{version}.tar.xz.asc
Source2:       https://people.redhat.com/~ssorce/simo_redhat.asc
%endif

BuildRequires: openssl-devel >= 3.0.7
BuildRequires: gcc
BuildRequires: meson
%if %{with gpgcheck}
BuildRequires: gnupg2
%endif

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
%if %{with gpgcheck}
%{gpgverify} --keyring='%{SOURCE2}' --signature='%{SOURCE1}' --data='%{SOURCE0}'
%endif

%autosetup -p1


%build
%meson
%meson_build


%install
%meson_install


%check
# do not run them in parrallel with %{?_smp_mflags}
%meson_test --num-processes 1


%files
%license COPYING
%{_mandir}/man7/provider-pkcs11.*
%doc README.md
%{_libdir}/ossl-modules/pkcs11.so


%changelog
* Mon Jul 10 2023 Sahana Prasad <sahana@redhat.com> - 0.2-1
+ New upstream release

* Mon Oct 24 2022 Jakub Jelen <jjelen@redhat.com> - 0.1-1
+ Initial Fedora release
