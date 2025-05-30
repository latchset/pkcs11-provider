project(
  'pkcs11-provider', 'c',
  version: '1.0',
  meson_version: '>= 0.57',
  default_options: ['c_std=c11'],
)

version_arr = meson.project_version().split('.')
major_version = version_arr[0].to_int()
minor_version = version_arr[1].to_int()

cc = meson.get_compiler('c')

warning_c_args = [
  '-Wwrite-strings',
  '-Wpointer-arith',
  '-Wno-missing-field-initializers',
  '-Wformat',
  '-Wshadow',
  # Temporarily disable unused parameter until the implementation is complete
  '-Wno-unused-parameter',
  # These should be always errors
  '-Werror=implicit-function-declaration',
  '-Werror=missing-prototypes',
  '-Werror=format-security',
  '-Werror=parentheses',
  '-Werror=implicit',
  '-Werror=strict-prototypes',
]

extra_c_args = [
  '-fno-strict-aliasing',
  '-fno-delete-null-pointer-checks',
  '-fdiagnostics-show-option',
]

add_project_arguments(cc.get_supported_arguments(warning_c_args + extra_c_args),
                      language: 'c')

configinc = include_directories('.')

conf = configuration_data()

conf.set_quoted('PACKAGE_NAME', meson.project_name())
conf.set('PACKAGE_MAJOR', major_version)
conf.set('PACKAGE_MINOR', minor_version)

libcrypto = dependency('libcrypto', version: '>= 3.0.7', required: false)
if not libcrypto.found()
  libcrypto = dependency('libcrypto3', version: '>= 3.0.7', required: true)
endif
provider_path = libcrypto.get_variable(pkgconfig: 'modulesdir')
libssl = dependency('libssl', version: '>= 3.0.7', required: false)
if not libssl.found()
  libssl = dependency('libssl3', version: '>= 3.0.7', required: true, method: 'pkg-config')
endif

# Set build version and build info definitions
conf.set_quoted('P11PROV_VERSION', meson.project_version())
build_info = get_option('build_info')
if build_info == ''
  build_info = 'Built with OpenSSL version ' + libcrypto.version()
endif
conf.set_quoted('P11PROV_BUILDINFO', build_info)

host_system = host_machine.system()
if host_system == 'windows'
  shlext = '.dll'
elif host_system == 'darwin'
  # On macOS, loadable modules typically use .so as filename extension, but
  # both NSS softokn and OpenSSL providers ignore this rule and use .dylib for
  # loadable modules anyway. Note that p11-kit correctly uses .so, though, so
  # be careful when using this variable, as it might not be correct on macOS.
  shlext = '.dylib'
else
  shlext = '.so'
endif

if host_machine.endian() == 'big'
  conf.set('WORDS_BIGENDIAN', 1)
endif

p11_kit = dependency('p11-kit-1', required: false)
default_pkcs11_module = get_option('default_pkcs11_module')
if default_pkcs11_module == '' and p11_kit.found()
  default_pkcs11_module = p11_kit.get_variable(pkgconfig: 'proxy_module')
endif

if default_pkcs11_module != ''
  conf.set_quoted('DEFAULT_PKCS11_MODULE', default_pkcs11_module)
endif

headers = [
  'dlfcn.h',
]

foreach h : headers
  if cc.has_header(h)
    conf.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

configure_file(output: 'config.h', configuration: conf)

meson.add_dist_script('scripts/clean-dist.sh')

subdir('src')
subdir('docs')
subdir('tests')

