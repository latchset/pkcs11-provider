Tests are currently available for two different software token implementations,
NSS's softokn and softhsm (with some limitations).

The easiest way to configure things to run manual tests is to simply execute this command from project's root directory:
```bash
meson test -C builddir
```
The 'builddir' argument is the name of the build directory, if you built in another directory you'll have to provide the name of the build directory here. This command will create a temporary directory for each token being tested.

If you want to manually test some commands against one of the supported software tokens, execute the test suite first and then source the necessary environment variables via:
```bash
$ source tests/tmp.<softokn|softhsm>/testvars
```

Then code can be executed like:
```bash
$ openssl pkey -in $ECPUBURI -pubin -pubout -out ecout.pub
```
