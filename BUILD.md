## Build & Installation

### Prerequisites

This package requires the following:
- OpenSSL 3.0.7+ libraries and development headers
- OpenSSL tools (for testing)
- NSS softoken, tools and development headers (for testing)
- a C compiler that supports at least C11 semantics
- meson
- pkg-config
- p11-kit, p11-kit-server, p11-kit-devel, opensc and softhsm (for testing)

### Build

The usual command to build are:
- `meson setup builddir`
- `meson compile -C builddir`
- `meson test -C builddir`

To link with OpenSSL installed in a custom path, set
`PKG_CONFIG_PATH`, or `CFLAGS`/`LDFLAGS` envvars accordingly at the
`meson setup` step. For example, let's assume OpenSSL is installed
under an absolute path `$OPENSSL_DIR`.

If you rely on pkg-config, point `PKG_CONFIG_PATH` to a directory
where `libcrypto.pc` or `openssl.pc` can be found.

- `PKG_CONFIG_PATH="$OPENSSL_DIR/lib64/pkg-config" meson setup builddir`

Otherwise, you can set `CFLAGS`/`LDFLAGS`:

- `CFLAGS="-I$OPENSSL_DIR/include" LDFLAGS="-L$OPENSSL_DIR/lib64" meson setup builddir`

### Installation

The usual command to install is:

- `meson install -C builddir`

Or simply copy the `src/pkcs11.so` (or `src/pkcs11.dylib` on Mac) in the appropriate directory for your OpenSSL installation.
