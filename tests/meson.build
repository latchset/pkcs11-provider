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

setup_script=find_program('setup.sh')
foreach suite : ['softokn', 'softhsm', 'kryoptic']
  test(
    'setup',
    setup_script,
    args: suite,
    suite: suite,
    env: conf_env,
    is_parallel: false,
  )
endforeach

test_env = environment({
  'TEST_PATH': meson.current_source_dir(),
  'TESTBLDDIR': meson.current_build_dir(),
})

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

  test_env.set('ASAN_OPTIONS', 'fast_unwind_on_malloc=0')
  test_env.set('LSAN_OPTIONS', 'suppressions=@0@/lsan.supp'.format(meson.current_source_dir()))
  test_env.set('FAKE_DLCLOSE', fake_dlclose.full_path())

  preload_env_var = 'LD_PRELOAD'
  if host_machine.system() == 'darwin'
    preload_env_var = 'DYLD_INSERT_LIBRARIES'
  endif

  # LD_PRELOAD is needed before invoking openssl as it is not instrumented with
  # asan and asan needs to be loaded as a first dynamic library of the process.
  if preload_libasan != 'no'
    test_env.set('CHECKER', 'env @0@=@1@:@2@'.format(preload_env_var, preload_libasan, fake_dlclose.full_path()))
  else
    test_env.set('CHECKER', 'env @0@=@1@'.format(preload_env_var, fake_dlclose.full_path()))
  endif
endif

test_programs = {
  'tsession': ['tsession.c'],
  'tgenkey': ['tgenkey.c'],
  'tlsctx': ['tlsctx.c', 'util.c'],
  'tlssetkey': ['tlssetkey.c', 'util.c'],
  'tdigests': ['tdigests.c'],
  'treadkeys': ['treadkeys.c'],
  'tcmpkeys': ['tcmpkeys.c', 'util.c'],
  'tfork': ['tfork.c'],
  'pincache': ['pincache.c'],
}

test_executables = []
foreach t, sources : test_programs
  t = executable(t, sources,
                 build_by_default: false,
                 include_directories: [configinc],
                 dependencies: [libcrypto, libssl])
  test_executables += [t]
endforeach

tests = {
  'basic': {'suites': ['softokn', 'softhsm', 'kryoptic']},
  'pubkey': {'suites': ['softokn', 'softhsm', 'kryoptic']},
  'certs': {'suites': ['softokn', 'softhsm', 'kryoptic']},
  'ecc': {'suites': ['softokn', 'softhsm', 'kryoptic']},
  'edwards': {'suites': ['softhsm', 'kryoptic']},
  'ecdh': {'suites': ['softokn', 'kryoptic']},
  'democa': {'suites': ['softokn', 'softhsm', 'kryoptic'], 'is_parallel': false},
  'digest': {'suites': ['softokn', 'softhsm', 'kryoptic']},
  'fork': {'suites': ['softokn', 'softhsm', 'kryoptic']},
  'oaepsha2': {'suites': ['softokn', 'kryoptic']},
  'hkdf': {'suites': ['softokn', 'kryoptic']},
  'imported' : {'suites': ['softokn', 'kryoptic']},
  'rsapss': {'suites': ['softokn', 'softhsm', 'kryoptic']},
  'rsapssam': {'suites': ['softhsm']},
  'genkey': {'suites': ['softokn', 'softhsm', 'kryoptic']},
  'session': {'suites': ['softokn', 'softhsm', 'kryoptic']},
  'rand': {'suites': ['softokn', 'softhsm', 'kryoptic']},
  'readkeys': {'suites': ['softokn', 'softhsm', 'kryoptic']},
  'tls': {'suites': ['softokn', 'softhsm', 'kryoptic'], 'is_parallel': false},
  'uri': {'suites': ['softokn', 'softhsm', 'kryoptic']},
  'ecxc': {'suites': ['softhsm', 'kryoptic']},
  'cms': {'suites': ['softokn', 'kryoptic']},
  'pinlock': {'suites': ['kryoptic']},
}

test_wrapper = find_program('test-wrapper')

foreach t, extra_args : tests
  is_parallel = extra_args.get('is_parallel', true)
  foreach suite : extra_args.get('suites', [])
    test(
      t,
      test_wrapper,
      args: '@0@-@1@.t'.format(t, suite),
      suite: suite,
      env: test_env,
      depends: test_executables,
      is_parallel: false,
    )
  endforeach
endforeach
