#!/usr/bin/env python3
"""Reproduce the vendored fixtures of crates/jose-ecdh-es.

Usage (run with an isolated interpreter, from the repository root):

    python3 -I scripts/ecdh_es_fixtures.py fetch DOWNLOAD_DIR   # download the pinned sources
    python3 -I scripts/ecdh_es_fixtures.py extract DOWNLOAD_DIR OUT_DIR
    python3 -I scripts/ecdh_es_fixtures.py check DOWNLOAD_DIR   # diff against the vendored copy

`fetch` is the only step that touches the network. `extract` and `check` verify the SHA-256 of
every source against the pins below before reading it. The tests never hit the network; they
read the committed output of `extract`.

Extractions:
  * RFC 7518 Appendix C ("Example ECDH-ES Key Agreement Computation"). Both JWKs are copied
    member by member (each value is checked to appear verbatim, quoted, in the appendix); the
    protected header, Z, OtherInfo, the round 1 hash input and the derived key are parsed from
    the printed JSON / octet arrays. The appendix is checked against itself: the header's `epk`
    is Alice's public key, the round 1 input is `[0,0,0,1] || Z || OtherInfo`, SHA-256 of it
    starts with the derived key, and the derived key's base64url is the printed
    `VqqN6vgjbSBcIijNcacQGg`.
  * OpenID4VP 1.0 §8.3 (the encrypted Authorization Response example). From the artwork blocks
    `section-8.3-8` (compact JWE, display line breaks removed), `-10` (the recipient JWK with
    `d`), `-12` (the printed decoded protected header) and `-14` (the printed payload), HTML
    entities unescaped. Checked: the JWE's own protected header decodes to the printed header,
    the JWK's public members equal the `kid` "ac" key of the request example (`-6`), and the
    JWE has five segments with an empty Encrypted Key.
"""

import base64
import hashlib
import html
import json
import re
import sys
import urllib.request
from pathlib import Path

VENDORED = Path("crates/jose-ecdh-es/tests/fixtures")

RFC_FILE = "rfc7518.txt"
OID4VP_FILE = "openid-4-verifiable-presentations-1_0.html"
SOURCES = {
    RFC_FILE: (
        "https://www.rfc-editor.org/rfc/rfc7518.txt",
        "9a9ae524b09ea700ad3f189bac115df95ba69af84b26ffdbe3cdfb8d2152b1fc",
    ),
    OID4VP_FILE: (
        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html",
        "e4f0abc689afd0a4f6c41b83954d7f970c5263a26143ad861216aea9918993bb",
    ),
}
RFC_FIXTURE = "rfc7518_appendix_c.json"
OID4VP_FIXTURE = "openid4vp_1_0_section_8_3_example.json"

APPENDIX_START = "Appendix C.  Example ECDH-ES Key Agreement Computation"
APPENDIX_END = "\nAcknowledgements\n"
HEADER_START = '{"alg":"ECDH-ES"'
HEADER_END = "}\n     }"
JWK_MEMBERS = ("kty", "crv", "x", "y", "d")
PUBLIC_MEMBERS = ("kty", "crv", "x", "y")
ROUND_1 = [0, 0, 0, 1]
PRINTED_KEY_B64 = "VqqN6vgjbSBcIijNcacQGg"
COMPACT_SEGMENTS = 5

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


def read_pinned(download_dir, name):
    data = (Path(download_dir) / name).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SOURCES[name][1]:
        sys.exit(f"{name}: SHA-256 {digest} != pinned {SOURCES[name][1]}")
    return data.decode("utf-8")


def octets_after(text, marker):
    start = text.index("[", text.index(marker))
    return [int(n) for n in re.findall(r"\d+", text[start:text.index("]", start)])]


def build_rfc7518(download_dir):
    rfc = read_pinned(download_dir, RFC_FILE)
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


def artwork(page, element_id):
    """The unescaped text of the first <pre> inside the element with id `element_id`."""
    start = page.index(f'id="{element_id}"')
    pre = page.index("<pre>", start) + len("<pre>")
    return html.unescape(re.sub(r"<[^>]*>", "", page[pre:page.index("</pre>", pre)]))


def b64url_json(segment):
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def build_oid4vp(download_dir):
    page = read_pinned(download_dir, OID4VP_FILE)
    response = artwork(page, "section-8.3-8")
    compact = re.sub(r"\s+", "", re.search(r'"response"\s*:\s*"([^"]+)"', response).group(1))
    recipient_jwk = json.loads(artwork(page, "section-8.3-10"))
    header = json.loads(artwork(page, "section-8.3-12"))
    payload = json.loads(artwork(page, "section-8.3-14"))
    request = json.loads(artwork(page, "section-8.3-6"))
    segments = compact.split(".")
    assert len(segments) == COMPACT_SEGMENTS and segments[1] == ""
    assert b64url_json(segments[0]) == header
    advertised = [k for k in request["client_metadata"]["jwks"]["keys"] if k.get("kid") == "ac"]
    assert len(advertised) == 1
    assert {k: v for k, v in recipient_jwk.items() if k != "d"} == advertised[0]
    fixture = {
        "source": "OpenID for Verifiable Presentations 1.0, Section 8.3 (encrypted response example)",
        "jwe_compact": compact,
        "recipient_jwk": recipient_jwk,
        "decoded_protected_header": header,
        "payload": payload,
    }
    return json.dumps(fixture, indent=2) + "\n"


BUILDERS = {RFC_FIXTURE: build_rfc7518, OID4VP_FIXTURE: build_oid4vp}


def main(argv):
    if len(argv) == 3 and argv[1] == "fetch":
        out = Path(argv[2])
        out.mkdir(parents=True, exist_ok=True)
        for name, (url, _) in SOURCES.items():
            with urllib.request.urlopen(url) as response:
                (out / name).write_bytes(response.read())
            read_pinned(out, name)
    elif len(argv) == 4 and argv[1] == "extract":
        for name, build in BUILDERS.items():
            (Path(argv[3]) / name).write_text(build(argv[2]))
    elif len(argv) == 3 and argv[1] == "check":
        for name, build in BUILDERS.items():
            if (VENDORED / name).read_text() != build(argv[2]):
                sys.exit(f"{VENDORED / name} differs from a fresh extraction")
            print(f"{name}: identical")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
