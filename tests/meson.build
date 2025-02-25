conf_env = environment({
  'LIBSPATH': meson.project_build_root() / 'src',
  'TESTSSRCDIR': meson.current_source_dir(),
  'TESTBLDDIR': meson.current_build_dir(),
  'SHARED_EXT': shlext,
})

if p11_kit.found()
  # p11-kit-client module doesn't support Windows, so hard-coding .so is fine
  p11_module_path = p11_kit.get_variable(pkgconfig: 'p11_module_path')
  p11_client_path = p11_module_path / 'p11-kit-client.so'
  conf_env.set('P11KITCLIENTPATH', p11_client_path)
endif

nss_softokn = dependency('nss-softokn', required: false)
if not nss_softokn.found()
  nss_softokn = dependency('nss', required: false)
endif
softokendir = ''
softokensubdir = ''
if nss_softokn.found()
  fs = import('fs')
  softokendir = nss_softokn.get_variable(pkgconfig: 'libdir')
  if fs.exists(softokendir / 'libsoftokn3@0@'.format(shlext))
    conf_env.set('SOFTOKNPATH', softokendir)
  elif fs.exists(softokendir / 'nss' / 'libsoftokn3@0@'.format(shlext))
    conf_env.set('SOFTOKNPATH', softokendir / 'nss')
  else
    warning('Softoken library missing, tests will be skipped!')
  endif
endif

if get_option('enable_explicit_EC_test')
  conf_env.set('ENABLE_EXPLICIT_EC_TEST', '1')
endif

test_env = environment({
  'TEST_PATH': meson.current_source_dir(),
  'TESTBLDDIR': meson.current_build_dir(),
})

if get_option('enable_explicit_EC_test')
  test_env.set('ENABLE_EXPLICIT_EC_TEST', '1')
endif

valgrind = find_program('valgrind', required: false)
if valgrind.found()
  add_test_setup('valgrind',
    exe_wrapper: [
      valgrind,
      '--num-callers=30',
      '-q',
      '--keep-debuginfo=yes',
    ],
    env: test_env,
    timeout_multiplier: 20,
  )
endif

setup_deps = []
if get_option('b_sanitize') == 'address'
  preload_libasan = get_option('preload_libasan')
  if preload_libasan == 'auto'
    preload_libasan = run_command(
      [cc.cmd_array()[0], '-print-file-name=libasan.so'],
      check: true,
      capture: true,
    ).stdout().strip()
  endif

  # Avoids closing dlopened libraries for ASan to be able to print usable traces
  fake_dlclose = shared_library(
    'fake_dlclose',
    'fake_dlclose.c',
    name_prefix: '',
  )
  setup_deps += [fake_dlclose]

  preload_env_var = 'LD_PRELOAD'
  if host_machine.system() == 'darwin'
    preload_env_var = 'DYLD_INSERT_LIBRARIES'
  endif

  # LD_PRELOAD is needed before invoking openssl as it is not instrumented with
  # asan and asan needs to be loaded as a first dynamic library of the process.
  if preload_libasan != 'no'
    checker = 'env @0@=@1@:@2@'.format(preload_env_var, preload_libasan, fake_dlclose.full_path())
  else
    checker = 'env @0@=@1@'.format(preload_env_var, fake_dlclose.full_path())
  endif

  add_env = {
    'ASAN_OPTIONS': 'fast_unwind_on_malloc=0:detect_leaks=1',
    'LSAN_OPTIONS': 'suppressions=@0@/lsan.supp'.format(meson.current_source_dir()),
    'FAKE_DLCLOSE': fake_dlclose.full_path(),
    'CHECKER': checker,
  }

  foreach name, value : add_env
    conf_env.set(name, value)
    test_env.set(name, value)
  endforeach
endif

test_programs = {
  'tsession': ['tsession.c'],
  'tgenkey': ['tgenkey.c', 'util.c'],
  'tlsctx': ['tlsctx.c', 'util.c'],
  'tlssetkey': ['tlssetkey.c', 'util.c'],
  'tdigests': ['tdigests.c'],
  'treadkeys': ['treadkeys.c'],
  'tcmpkeys': ['tcmpkeys.c', 'util.c'],
  'tfork': ['tfork.c', 'util.c'],
  'tpkey': ['tpkey.c', 'util.c'],
  'pincache': ['pincache.c'],
  'ccerts': ['ccerts.c', 'util.c'],
}

test_executables = []
foreach t, sources : test_programs
  t = executable(t, sources,
                 build_by_default: false,
                 include_directories: [configinc],
                 dependencies: [libcrypto, libssl])
  test_executables += [t]
endforeach

setup_script=find_program('setup.sh')
all_suites=['softokn', 'softhsm', 'kryoptic', 'kryoptic.nss']
foreach suite : all_suites
  test(
    'setup',
    setup_script,
    args: suite,
    suite: suite,
    env: conf_env,
    is_parallel: false,
    depends: setup_deps,
  )
endforeach

tests = {
  'basic': {'suites': all_suites},
  'pubkey': {'suites': all_suites},
  'certs': {'suites': all_suites},
  'ecc': {'suites': all_suites},
  'edwards': {'suites': ['softhsm', 'kryoptic', 'kryoptic.nss']},
  'ecdh': {'suites': ['softokn', 'kryoptic', 'kryoptic.nss']},
  'democa': {'suites': all_suites, 'is_parallel': false},
  'digest': {'suites': all_suites},
  'fork': {'suites': all_suites},
  'oaepsha2': {'suites': ['softokn', 'kryoptic', 'kryoptic.nss']},
  'hkdf': {'suites': ['softokn', 'kryoptic', 'kryoptic.nss']},
  'imported' : {'suites': ['softokn', 'kryoptic', 'kryoptic.nss']},
  'rsa': {'suites': all_suites},
  'rsapss': {'suites': all_suites},
  'rsapssam': {'suites': ['softhsm', 'kryoptic']},
  'genkey': {'suites': all_suites},
  'pkey': {'suites': all_suites},
  'session': {'suites': all_suites},
  'rand': {'suites': all_suites},
  'readkeys': {'suites': all_suites},
  'tls': {'suites': all_suites, 'is_parallel': false, 'timeout': 60},
  'tlsfuzzer': {'suites': all_suites, 'timeout': 90},
  'uri': {'suites': all_suites, 'timeout': 90},
  'ecxc': {'suites': ['softhsm', 'kryoptic', 'kryoptic.nss']},
  'cms': {'suites': ['softokn', 'kryoptic', 'kryoptic.nss']},
  'pinlock': {'suites': ['kryoptic']},
}

test_wrapper = find_program('test-wrapper')

foreach t, extra_args : tests
  is_parallel = extra_args.get('is_parallel', true)
  timeout = extra_args.get('timeout', 30)
  foreach suite : extra_args.get('suites', [])
    test(
      t,
      test_wrapper,
      args: '@0@-@1@.t'.format(t, suite),
      suite: suite,
      env: test_env,
      depends: test_executables,
      is_parallel: false,
      timeout: timeout,
    )
  endforeach
endforeach
