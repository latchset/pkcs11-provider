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
    warning('Softoken library missing, tests will fail!')
  endif
endif

softoken_conf = custom_target(
  'generate softoken configuration',
  output: 'tmp.softokn.log',
  env: conf_env,
  command: [
    find_program('setup-softokn.sh'),
  ],
  capture: true,
)

softhsm_conf = custom_target(
  'generate softhsm configuration',
  output: 'tmp.softhsm.log',
  env: conf_env,
  command: [
    find_program('setup-softhsm.sh'),
  ],
  capture: true,
)

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
  fake_dlclose = shared_module(
    'fake_dlclose',
    'fake_dlclose.c',
    name_prefix: '',
  )

  test_env.set('ASAN_OPTIONS', 'fast_unwind_on_malloc=0')
  test_env.set('LSAN_OPTIONS', 'suppressions=@0@/lsan.supp'.format(meson.current_source_dir()))
  test_env.set('FAKE_DLCLOSE', fake_dlclose.full_path())
  # LD_PRELOAD is needed before invoking openssl as it is not instrumented with
  # asan and asan needs to be loaded as a first dynamic library of the process.
  if preload_libasan != 'no'
    test_env.set('CHECKER', 'env LD_PRELOAD=@0@:@1@'.format(preload_libasan, fake_dlclose.full_path()))
  else
    test_env.set('CHECKER', 'env LD_PRELOAD=@0@'.format(fake_dlclose.full_path()))
  endif
endif

test_programs = [
  'tsession',
  'tgenkey',
  'tlsctx',
  'tdigests',
  'treadkeys',
  'tcmpkeys',
  'tfork',
  'pincache',
]

foreach t : test_programs
  executable(t, '@0@.c'.format(t),
             include_directories: [configinc],
             dependencies: [libcrypto, libssl])
endforeach

tests = {
  'basic': {'suites': ['softokn', 'softhsm']},
  'pubkey': {'suites': ['softokn', 'softhsm']},
  'certs': {'suites': ['softokn', 'softhsm']},
  'ecc': {'suites': ['softokn', 'softhsm']},
  'edwards': {'suites': ['softhsm']},
  'ecdh': {'suites': ['softokn']},
  'democa': {'suites': ['softokn', 'softhsm'], 'is_parallel': false},
  'digest': {'suites': ['softokn', 'softhsm']},
  'fork': {'suites': ['softokn', 'softhsm']},
  'oaepsha2': {'suites': ['softokn']},
  'hkdf': {'suites': ['softokn']},
  'rsapss': {'suites': ['softokn']},
  'genkey': {'suites': ['softokn', 'softhsm']},
  'session': {'suites': ['softokn', 'softhsm']},
  'rand': {'suites': ['softokn', 'softhsm']},
  'readkeys': {'suites': ['softokn', 'softhsm']},
  'tls': {'suites': ['softokn', 'softhsm'], 'is_parallel': false},
  'uri': {'suites': ['softokn', 'softhsm']},
  'ecxc': {'suites': ['softhsm']},
  'cms': {'suites': ['softokn']},
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
      depends: [softoken_conf, softhsm_conf],
      env: test_env,
      is_parallel: is_parallel,
    )
  endforeach
endforeach
