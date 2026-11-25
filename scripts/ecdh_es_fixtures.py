#!/usr/bin/env python3
"""Reproduce the vendored RFC 7518 Appendix C fixture of crates/jose-ecdh-es.

Usage (run with an isolated interpreter, from the repository root):

    python3 -I scripts/ecdh_es_fixtures.py fetch DOWNLOAD_DIR   # download the pinned RFC text
    python3 -I scripts/ecdh_es_fixtures.py extract DOWNLOAD_DIR OUT_DIR
    python3 -I scripts/ecdh_es_fixtures.py check DOWNLOAD_DIR   # diff against the vendored copy

`fetch` is the only step that touches the network. `extract` and `check` verify the SHA-256 of
the RFC text against the pin below before reading it. The tests never hit the network; they
read the committed output of `extract`.

Extraction: Appendix C ("Example ECDH-ES Key Agreement Computation") of RFC 7518. Both JWKs
are copied member by member (each value is checked to appear verbatim, quoted, in the
appendix); the protected header, Z, OtherInfo, the round 1 hash input and the derived key are
parsed from the printed JSON / octet arrays. The script also checks the appendix against
itself: the header's `epk` is Alice's public key, the round 1 input is
`[0,0,0,1] || Z || OtherInfo`, SHA-256 of it starts with the derived key, and the derived key's
base64url is the printed `VqqN6vgjbSBcIijNcacQGg`.
"""

import base64
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

RFC_FILE = "rfc7518.txt"
RFC_URL = "https://www.rfc-editor.org/rfc/rfc7518.txt"
RFC_SHA256 = "9a9ae524b09ea700ad3f189bac115df95ba69af84b26ffdbe3cdfb8d2152b1fc"
FIXTURE = "rfc7518_appendix_c.json"
VENDORED = Path("crates/jose-ecdh-es/tests/fixtures")

APPENDIX_START = "Appendix C.  Example ECDH-ES Key Agreement Computation"
APPENDIX_END = "\nAcknowledgements\n"
HEADER_START = '{"alg":"ECDH-ES"'
HEADER_END = "}\n     }"
JWK_MEMBERS = ("kty", "crv", "x", "y", "d")
PUBLIC_MEMBERS = ("kty", "crv", "x", "y")
ROUND_1 = [0, 0, 0, 1]
PRINTED_KEY_B64 = "VqqN6vgjbSBcIijNcacQGg"

ALICE = dict(zip(JWK_MEMBERS, (
    "EC", "P-256",
    "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
    "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
    "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
)))
BOB = dict(zip(JWK_MEMBERS, (
    "EC", "P-256",
    "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
    "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
    "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
)))


def read_pinned(download_dir):
    data = (Path(download_dir) / RFC_FILE).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != RFC_SHA256:
        sys.exit(f"{RFC_FILE}: SHA-256 {digest} != pinned {RFC_SHA256}")
    return data.decode("ascii")


def octets_after(text, marker):
    start = text.index("[", text.index(marker))
    return [int(n) for n in re.findall(r"\d+", text[start:text.index("]", start)])]


def build(download_dir):
    rfc = read_pinned(download_dir)
    appendix = rfc[rfc.index(APPENDIX_START):rfc.index(APPENDIX_END)]
    for jwk in (ALICE, BOB):
        for value in jwk.values():
            assert f'"{value}"' in appendix, value
    start = appendix.index(HEADER_START)
    header = json.loads(appendix[start:appendix.index(HEADER_END, start) + len(HEADER_END)])
    z = octets_after(appendix, "example, Z is following")
    other_info = octets_after(appendix, "in an OtherInfo value of:")
    round1 = octets_after(appendix, "round 1 hash input of:")
    key = octets_after(appendix, "hash output is:")
    key_b64 = base64.urlsafe_b64encode(bytes(key)).rstrip(b"=").decode()
    assert header["epk"] == {m: ALICE[m] for m in PUBLIC_MEMBERS}
    assert round1 == ROUND_1 + z + other_info
    assert hashlib.sha256(bytes(round1)).digest()[:len(key)] == bytes(key)
    assert key_b64 == PRINTED_KEY_B64 and PRINTED_KEY_B64 in appendix
    fixture = {
        "source": "RFC 7518 Appendix C (Example ECDH-ES Key Agreement Computation)",
        "alice_ephemeral_jwk": ALICE,
        "bob_jwk": BOB,
        "protected_header": header,
        "apu_utf8": "Alice",
        "apv_utf8": "Bob",
        "z": z,
        "other_info": other_info,
        "round1_hash_input": round1,
        "derived_key": key,
        "derived_key_base64url": key_b64,
    }
    return json.dumps(fixture, indent=2) + "\n"


def main(argv):
    if len(argv) == 3 and argv[1] == "fetch":
        out = Path(argv[2])
        out.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(RFC_URL) as response:
            (out / RFC_FILE).write_bytes(response.read())
        read_pinned(out)
    elif len(argv) == 4 and argv[1] == "extract":
        (Path(argv[3]) / FIXTURE).write_text(build(argv[2]))
    elif len(argv) == 3 and argv[1] == "check":
        if (VENDORED / FIXTURE).read_text() != build(argv[2]):
            sys.exit(f"{VENDORED / FIXTURE} differs from a fresh extraction")
        print(f"{FIXTURE}: identical")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
