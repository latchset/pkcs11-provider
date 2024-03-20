# CLI tool uri2pem.py

Simple tool to create PEM files for PKCS#11 URI
Usage:

    python uri2pem.py --help
    python uri2pem.py 'pkcs11:token=MyToken;object=MyObject;type=private'
    python uri2pem.py --bypass 'someBogusURI'
    # output
    python uri2pem.py --out mykey.pem 'pkcs11:token=MyToken;object=MyObject;type=private'
    # verification, if token is available, requires --out <filename>
    python uri2pem.py --verify --out mykey.pem 'pkcs11:token=MyToken;object=MyObject;type=private'

The tool doesn't validate the argument for a valid PKCS#11 URI

## Tests

If you run `make check` the tool has a test suite that will run
against NSS softoken in `../tests/tmp.softokn/tests`.

The test suite enables `pkcs11-module-encode-provider-uri-to-pem = true`.
