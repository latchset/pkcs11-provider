pkcs11_provider_sources = [
  'asymmetric_cipher.c',
  'debug.c',
  'encoder.c',
  'decoder.c',
  'digests.c',
  'exchange.c',
  'kdf.c',
  'keymgmt.c',
  'pk11_uri.c',
  'interface.c',
  'objects.c',
  'provider.c',
  'random.c',
  'session.c',
  'signature.c',
  'slot.c',
  'store.c',
  'tls.c',
  'util.c',
]

pkcs11_provider_map = meson.current_source_dir() / 'provider.map'
pkcs11_provider_ldflags = cc.get_supported_link_arguments([
  '-Wl,--version-script,' + pkcs11_provider_map
])

pkcs11_provider = shared_module(
  'pkcs11',
  pkcs11_provider_sources,
  name_prefix: '',
  dependencies: [libcrypto],
  include_directories: [configinc],
  link_depends: [pkcs11_provider_map],
  link_args: pkcs11_provider_ldflags,
  install: true,
  install_dir: libdir / 'ossl-modules',
)
