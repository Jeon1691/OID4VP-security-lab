#!/usr/bin/env python3
"""Reproduce the vendored HPKE / JOSE-HPKE fixtures of crates/jose-hpke (IMP-004, IMP-005).

Usage (run with an isolated interpreter, from the repository root):

    python3 -I scripts/hpke_fixtures.py fetch DOWNLOAD_DIR   # download the pinned sources
    python3 -I scripts/hpke_fixtures.py extract DOWNLOAD_DIR OUT_DIR
    python3 -I scripts/hpke_fixtures.py check DOWNLOAD_DIR   # diff against the vendored copy

`fetch` is the only step that touches the network. `extract` and `check` verify the SHA-256 of
every source file against the pins below before reading it, so a moved tag or a tampered
download fails loudly instead of silently producing different fixtures. The tests themselves
never hit the network; they read the committed output of `extract`.

Subsets:
  * RFC 9180 (CFRG test-vectors.json): the single vector with mode_base (0), kem_id 0x0010
    DHKEM(P-256, HKDF-SHA256), kdf_id 0x0001 HKDF-SHA256, aead_id 0x0001 AES-128-GCM, copied
    unchanged. Every scalar field and the published encryptions/exports are cross-checked
    against the RFC 9180 text, Appendix A.3.1.
  * draft-ietf-jose-hpke-encrypt-22 (examples/jose-vectors.json at the -22 tag): the HPKE-0
    vector (decryptable) plus HPKE-0-KE and HPKE-7 (used as official negative inputs), copied
    unchanged. The HPKE-0 compact JWE is cross-checked against Figure 3 of the I-D text. The
    expected plaintext is not in the I-D text or jose-vectors.json; it is taken verbatim from
    scripts/jwe.js (the generator at the same tag) and stored next to the vectors.
"""

import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

CFRG_COMMIT = "5f503c564da00b0687b3de75f1dfbdfc4079ad31"
JOSE_TAG_COMMIT = "2fa0c6b2b6d82013aa87a6d83c121de6f2fec3f0"  # tag draft-ietf-jose-hpke-encrypt-22

SOURCES = {
    "test-vectors.json": (
        f"https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/{CFRG_COMMIT}/test-vectors.json",
        "61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6",
    ),
    "rfc9180.txt": (
        "https://www.rfc-editor.org/rfc/rfc9180.txt",
        "f45a8b7c30231b26d668b1e8168074e5ab514b174d656b67e859895117f1f8f6",
    ),
    "jose-vectors.json": (
        f"https://raw.githubusercontent.com/ietf-wg-jose/draft-ietf-jose-hpke-encrypt/{JOSE_TAG_COMMIT}/examples/jose-vectors.json",
        "235fade8057e5e114d3e6b6e39c7187509178f148e0518a4117e8a3d3c1c3884",
    ),
    "jwe.js": (
        f"https://raw.githubusercontent.com/ietf-wg-jose/draft-ietf-jose-hpke-encrypt/{JOSE_TAG_COMMIT}/scripts/jwe.js",
        "0c14056c28cf35b4c269173bb8af67b4f2accb658b9d4cabd4711cd4babd6eff",
    ),
    "draft-ietf-jose-hpke-encrypt-22.txt": (
        "https://www.ietf.org/archive/id/draft-ietf-jose-hpke-encrypt-22.txt",
        "6e9c0df346df528d3c5dad1dea1a221716bd614dd2ec2357b3f531664f00b8cc",
    ),
}

# RFC 9180 §5 Table 1 / §7.1-7.3 registry values for the HPKE-0 suite.
MODE_BASE = 0
KEM_DHKEM_P256_HKDF_SHA256 = 0x0010
KDF_HKDF_SHA256 = 0x0001
AEAD_AES_128_GCM = 0x0001

JOSE_ALGS = ("HPKE-0", "HPKE-0-KE", "HPKE-7")

RFC9180_OUT = "rfc9180_base_p256_sha256_aes128gcm.json"
JOSE_OUT = "jose_hpke_22_vectors.json"


def die(msg):
    sys.exit(f"hpke_fixtures: {msg}")


def fetch(download_dir):
    download_dir.mkdir(parents=True, exist_ok=False)
    for name, (url, _) in SOURCES.items():
        with urllib.request.urlopen(url) as resp:  # noqa: S310 (pinned https URLs only)
            (download_dir / name).write_bytes(resp.read())
    load_sources(download_dir)
    print(f"fetched {len(SOURCES)} files into {download_dir}")


def load_sources(download_dir):
    data = {}
    for name, (_, want) in SOURCES.items():
        raw = (download_dir / name).read_bytes()
        got = hashlib.sha256(raw).hexdigest()
        if got != want:
            die(f"{name}: sha256 {got} != pinned {want}")
        data[name] = raw
    return data


def rfc9180_section_a31(rfc_text):
    start = rfc_text.index("\nA.3.1.  Base Setup Information")
    end = rfc_text.index("\nA.3.2.  PSK Setup Information")
    section = rfc_text[start:end]
    # Drop page footers/headers so hex values folded across a page break still join up.
    section = re.sub(r"(?m)^Barnes, et al\..*$|^RFC 9180 .*$|\f", "", section)
    return re.sub(r"\s+", "", section)


def extract_rfc9180(src):
    vectors = json.loads(src["test-vectors.json"])
    subset = [
        v
        for v in vectors
        if v["mode"] == MODE_BASE
        and v["kem_id"] == KEM_DHKEM_P256_HKDF_SHA256
        and v["kdf_id"] == KDF_HKDF_SHA256
        and v["aead_id"] == AEAD_AES_128_GCM
    ]
    if len(subset) != 1:
        die(f"expected exactly one RFC 9180 base P-256 vector, found {len(subset)}")
    vec = subset[0]

    text = rfc9180_section_a31(src["rfc9180.txt"].decode("utf-8-sig"))
    scalar_fields = [k for k, val in vec.items() if isinstance(val, str)]
    published = [vec[k] for k in scalar_fields]
    # The RFC text prints a sample of the encryptions (sequence numbers 0, 1, 2, 4, 255, 256)
    # and all exports; every printed value must equal the JSON.
    for seq in (0, 1, 2, 4, 255, 256):
        enc = vec["encryptions"][seq]
        published += [enc["pt"], enc["aad"], enc["nonce"], enc["ct"]]
    published += [e["exported_value"] for e in vec["exports"]]
    for value in published:
        if value and value not in text:
            die(f"RFC 9180 A.3.1 text does not contain JSON value {value[:16]}...")
    return subset


def unfold_rfc8792(lines):
    out = ""
    for line in lines:
        stripped = line.strip()
        if stripped.endswith("\\"):
            out += stripped[:-1]
        else:
            out += stripped
    return out


def draft_figure(draft_text, caption):
    lines = draft_text.splitlines()
    end = next(i for i, line in enumerate(lines) if line.strip() == caption)
    start = max(i for i in range(end) if "line wrapping per RFC 8792" in lines[i])
    return unfold_rfc8792(line for line in lines[start + 1 : end] if line.strip())


def extract_jose(src):
    vectors = {v["alg"]: v for v in json.loads(src["jose-vectors.json"])}
    subset = [vectors[alg] for alg in JOSE_ALGS]

    draft = src["draft-ietf-jose-hpke-encrypt-22.txt"].decode("utf-8")
    figure3 = draft_figure(draft, "Figure 3: HPKE-0 JWE Compact Serialization")
    if figure3 != vectors["HPKE-0"]["compact"]:
        die("draft-22 Figure 3 does not match jose-vectors.json HPKE-0 compact")
    if vectors["HPKE-0"]["jwk"]["d"] not in draft:
        die("draft-22 Figure 1 does not contain the HPKE-0 private key")

    match = re.search(r'const plaintext =\s*"([^"\\]*)";', src["jwe.js"].decode("utf-8"))
    if not match:
        die("could not find the plaintext literal in scripts/jwe.js")
    return {
        "source": {
            "jose_vectors": SOURCES["jose-vectors.json"][0],
            "plaintext": SOURCES["jwe.js"][0],
            "hpke_info": "empty octet string (jwe.js passes no info; draft-22 §5 default)",
        },
        "plaintext": match.group(1),
        "vectors": subset,
    }


def render(obj):
    return json.dumps(obj, indent=2, ensure_ascii=True) + "\n"


def outputs(download_dir):
    src = load_sources(download_dir)
    return {
        RFC9180_OUT: render(extract_rfc9180(src)),
        JOSE_OUT: render(extract_jose(src)),
    }


def main(argv):
    if len(argv) == 3 and argv[1] == "fetch":
        fetch(Path(argv[2]))
    elif len(argv) == 4 and argv[1] == "extract":
        out_dir = Path(argv[3])
        for name, text in outputs(Path(argv[2])).items():
            (out_dir / name).write_text(text, encoding="ascii")
            print(f"{name} sha256={hashlib.sha256(text.encode()).hexdigest()}")
    elif len(argv) == 3 and argv[1] == "check":
        vendored = Path(__file__).resolve().parent.parent / "crates/jose-hpke/tests/fixtures"
        for name, text in outputs(Path(argv[2])).items():
            if (vendored / name).read_text(encoding="ascii") != text:
                die(f"{name} differs from the vendored fixture")
        print("vendored fixtures match the pinned sources")
    else:
        die(__doc__.split("\n\n")[1])


if __name__ == "__main__":
    main(sys.argv)
