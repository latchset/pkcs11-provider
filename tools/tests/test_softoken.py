"""
Copyright (C) 2024 S-P Chan <shihping.chan@gmail.com>
SPDX-License-Identifier: Apache-2.0
"""

import os
import pathlib
import subprocess
import sys
import random
import string
import re

from asn1crypto import pem
from .. import uri2pem

tokens = pathlib.Path("../tests/tmp.softokn/tokens/key4.db")


if not tokens.exists():
    print("Run 'make check' first to create a NSS softoken in tests/tmp.softokn/tokens")
    raise SystemExit(1)


P11_TOKEN = "".join(random.choices(string.ascii_letters, k=12))
P11_OBJECT = "".join(random.choices(string.ascii_letters, k=12))
KEY_URI = f"pkcs11:token={P11_TOKEN};object={P11_OBJECT};type=private"
KEY_DESC = "PKCS#11 Provider URI v1.0"


def test_roundtrip(tmp_path):

    pem_bytes = uri2pem.uri2pem(KEY_URI)
    # asn1crypto does not like '#' in PEM labels
    pem_replace = pem_bytes.decode("ascii").replace("#", "0")

    # read back the object
    der_bytes = pem.unarmor(pem_replace.encode("ascii"), multiple=False)
    key = uri2pem.Pkcs11PrivateKey.load(der_bytes[2])

    assert key["desc"].native == KEY_DESC
    assert key["uri"].native == KEY_URI


def test_asn1parse(tmp_path):
    pem_bytes = uri2pem.uri2pem(KEY_URI)
    pem_file = pathlib.Path(tmp_path / "test_asn1parse.pem")
    pathlib.Path(tmp_path / "test_asn1parse.pem").write_bytes(pem_bytes)
    ret = subprocess.run(
        ["openssl", "asn1parse", "-in", str(pem_file)], capture_output=True, text=True
    )

    assert ret.returncode == 0
    assert "SEQUENCE" in ret.stdout and KEY_DESC in ret.stdout and KEY_URI in ret.stdout


def test_storeutl(tmp_path):
    ret = subprocess.run(
        ["openssl", "storeutl", "-text", "pkcs11:"],
        capture_output=True,
        text=True,
        env={"OPENSSL_CONF": "./openssl-tools.cnf"}
    )

    assert ret.returncode == 0

    private_key = None
    for line in ret.stdout.splitlines():
        if m := re.match("URI (pkcs11.*type=private)$", line):
            private_key = m.group(1)
            break

    assert private_key

    data = uri2pem.uri2pem(private_key)
    private_key_pem = pathlib.Path(tmp_path / "private_key.pem")
    private_key_pem.write_bytes(data)

    ret = subprocess.run(
        ["openssl", "pkey", "-in", str(private_key_pem)],
        capture_output=True,
        text=True,
        env={"OPENSSL_CONF": "./openssl-tools.cnf"}
    )

    assert ret.returncode == 0
