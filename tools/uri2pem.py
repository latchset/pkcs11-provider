"""
Copyright (C) 2024 S-P Chan <shihping.chan@gmail.com>
SPDX-License-Identifier: Apache-2.0
"""

"""
CLI tool to create pkcs11-provider pem files from a key uri
Requirements: asn1crypto

Installation:
    pip install asn1crypto
    dnf install python3-asn1crypto

Usage:
    python uri2pem.py 'pkcs11:URI-goes-here'
"""

import sys
from asn1crypto.core import Sequence, VisibleString, UTF8String
from asn1crypto import pem


class Pkcs11PrivateKey(Sequence):
    _fields = [("desc", VisibleString), ("uri", UTF8String)]


def uri2pem(uri: str, bypass: bool = False) -> bytes:
    if not bypass:
        if not (uri.startswith("pkcs11:") and "type=private" in uri):
            print(f"Error: uri({uri}) not a valid PKCS#11 URI")
            sys.exit(1)
        if not ("object=" in uri or "id=" in uri):
            print(f"Error: uri({uri}) does not specify an object by label or id")
            sys.exit(1)

    data = Pkcs11PrivateKey(
        {
            "desc": VisibleString("PKCS#11 Provider URI v1.0"),
            "uri": UTF8String(uri),
        }
    )
    return pem.armor("PKCS#11 PROVIDER URI", data.dump())


if __name__ == "__main__":
    import argparse
    import pathlib
    import subprocess

    parser = argparse.ArgumentParser()
    parser.add_argument("--bypass", action='store_true', help='skip basic URI checks')
    parser.add_argument("--verify", action='store_true', help='verify PEM file with OpenSSL; requires --out to be specified')
    parser.add_argument("--out", action='store', help='output to PEM file, otherwise to stdout', metavar='OUTPUT_FILE')
    parser.add_argument("keyuri", action='store', help='the PKCS#11 key URI to encode')

    opts = parser.parse_args()
    if opts.verify and not opts.out:
        print(f"{sys.argv[0]}: --verify option requires --out <filename> to be specified")
        sys.exit(1)

    data = uri2pem(opts.keyuri, bypass=opts.bypass)
    if opts.out:
        out_file = pathlib.Path(opts.out)
        out_file.write_bytes(data)
    else:
        print(data.decode("ascii"), end="")

    if opts.verify:
        print("===== OpenSSL pkey output =====")
        ret = subprocess.run(["openssl", "pkey", "-in", str(out_file), "-pubout"])
        print("===== END =====")
        if ret.returncode != 0:
            print(f"{sys.argv[0]}: verification of private key PEM({str(out_file)}) failed")
        else:
            print(f"{sys.argv[0]}: verification of private key PEM({str(out_file)}) OK")
