#!/usr/bin/env python3
"""Reproduce the SYNTHETIC conformance-mode X.509 fixtures of crates/lab-server.

Usage (run with an isolated interpreter, from the repository root):

    python3 -I scripts/conformance_fixtures.py generate OUT_DIR [--dns NAME ...]
    python3 -I scripts/conformance_fixtures.py check      # regenerate and diff the committed set

Needs only the Python standard library and OpenSSL >= 3.2 on PATH (`-sigopt nonce-type:1`,
deterministic ECDSA per RFC 6979, and `-not_before` / `-not_after`). Nothing touches the network.

Output (docs/adr/0002-conformance-mode.md):
  * conformance_ca.pem          trust anchor certificate (P-256, self-signed, CA:TRUE pathlen 0).
                                This is what the OIDF suite gets as
                                `client.request_object_trust_anchor_pem` (HAIP plan) and what test
                                clients trust for TLS. It is never sent in `x5c` (HAIP 1.0 §5).
  * conformance_leaf.pem        leaf certificate issued by that CA: P-256, CA:FALSE,
                                digitalSignature, serverAuth, SAN = the --dns names (default
                                host.docker.internal and localhost). It is the lab's TLS
                                certificate and the one `x5c` entry of its Request Objects.
  * conformance_leaf.key.pem    the leaf private key, PKCS#8 PEM (TLS, rustls).
  * conformance_leaf.jwk        the same key as an EC P-256 private JWK (Request Object signing,
                                `--signing-key`).
  * conformance_fixtures.json   derived values: x509_san_dns / x509_hash client ids, SANs,
                                validity, SHA-256 of every file.

Reproducibility: both private scalars are derived from fixed labels (SHA-256, reduced into
[1, n-1]), every certificate field is fixed (serials, names, validity, extensions), and ECDSA
signatures are deterministic, so the same inputs give byte-identical output. Because the
scalars follow from public labels, ANYONE can recompute these private keys: the material is
synthetic by construction and must never be trusted outside this lab. The CA private key is not
written to OUT_DIR at all.
"""

import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

COMMITTED = Path("crates/lab-server/tests/fixtures")
DEFAULT_DNS = ["host.docker.internal", "localhost"]
# Labels the two private scalars are derived from. Changing one changes every fixture.
CA_KEY_LABEL = b"OID4VP-security-lab SYNTHETIC conformance CA key v1"
LEAF_KEY_LABEL = b"OID4VP-security-lab SYNTHETIC conformance leaf key v1"
# Order of the P-256 base point (SEC 2 v2 §2.4.2).
P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
P256_SCALAR_BYTES = 32
# SEC1 ECPrivateKey (RFC 5915 §3) for P-256 without the optional public key:
# SEQUENCE(49) { INTEGER 1, OCTET STRING(32) d, [0] { OID prime256v1 } }.
SEC1_PREFIX = bytes.fromhex("30310201010420")
SEC1_SUFFIX = bytes.fromhex("a00a06082a8648ce3d030107")
# An uncompressed P-256 public key in a SubjectPublicKeyInfo ends with 0x04 || x || y.
SPKI_POINT_BYTES = 1 + 2 * P256_SCALAR_BYTES
# Fixed certificate fields. Validity is long so the committed set outlives the lab work; the
# lab checks the chain against the current time at start.
CA_SUBJECT = "/O=OID4VP security lab/CN=SYNTHETIC conformance CA - never trust"
LEAF_ORG = "/O=OID4VP security lab SYNTHETIC conformance Verifier"
CA_SERIAL = "1"
LEAF_SERIAL = "2"
CA_NOT_BEFORE = "20261101000000Z"
CA_NOT_AFTER = "20361101000000Z"
LEAF_NOT_BEFORE = "20261101000000Z"
LEAF_NOT_AFTER = "20311101000000Z"
OUTPUT_FILES = [
    "conformance_ca.pem",
    "conformance_leaf.pem",
    "conformance_leaf.key.pem",
    "conformance_leaf.jwk",
]
MANIFEST = "conformance_fixtures.json"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def scalar(label: bytes) -> bytes:
    value = int.from_bytes(hashlib.sha256(label).digest(), "big") % (P256_ORDER - 1) + 1
    return value.to_bytes(P256_SCALAR_BYTES, "big")


def openssl(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(["openssl", *args], input=data, check=True, capture_output=True).stdout


def write_key(d: bytes, pem_path: Path) -> bytes:
    """Writes `d` as PKCS#8 PEM; returns 0x04 || x || y.

    `openssl ec` derives the public point and writes it into the ECPrivateKey (RFC 5915
    `publicKey`), which ring (rustls) requires; `openssl pkey` then wraps it as PKCS#8.
    """
    sec1 = openssl("ec", "-inform", "DER", "-outform", "DER", data=SEC1_PREFIX + d + SEC1_SUFFIX)
    pem = openssl("pkey", "-inform", "DER", "-outform", "PEM", data=sec1)
    pem_path.write_bytes(pem)
    spki = openssl("pkey", "-in", str(pem_path), "-pubout", "-outform", "DER")
    point = spki[-SPKI_POINT_BYTES:]
    assert point[0] == 0x04, "uncompressed point expected"
    return point


def extensions(dns: list[str]) -> str:
    san = ",".join(f"DNS:{name}" for name in dns)
    return f"""[req]
distinguished_name = dn
prompt = no
[dn]
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[v3_leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = {san}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""


def der_of_pem(path: Path) -> bytes:
    return openssl("x509", "-in", str(path), "-outform", "DER")


def generate(out: Path, dns: list[str]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        cnf = tmp / "openssl.cnf"
        cnf.write_text(extensions(dns))
        ca_key = tmp / "ca.key.pem"
        write_key(scalar(CA_KEY_LABEL), ca_key)
        leaf_key = out / "conformance_leaf.key.pem"
        point = write_key(scalar(LEAF_KEY_LABEL), leaf_key)
        deterministic = ["-sha256", "-sigopt", "nonce-type:1"]
        ca = out / "conformance_ca.pem"
        openssl("req", "-x509", "-new", "-config", str(cnf), "-key", str(ca_key), "-subj",
                CA_SUBJECT, "-set_serial", CA_SERIAL, "-not_before", CA_NOT_BEFORE, "-not_after",
                CA_NOT_AFTER, "-extensions", "v3_ca", *deterministic, "-out", str(ca))
        csr = tmp / "leaf.csr"
        openssl("req", "-new", "-config", str(cnf), "-key", str(leaf_key), "-subj",
                f"{LEAF_ORG}/CN={dns[0]}", "-out", str(csr))
        leaf = out / "conformance_leaf.pem"
        openssl("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                "-set_serial", LEAF_SERIAL, "-not_before", LEAF_NOT_BEFORE, "-not_after",
                LEAF_NOT_AFTER, "-extfile", str(cnf), "-extensions", "v3_leaf", *deterministic,
                "-out", str(leaf))
        openssl("verify", "-CAfile", str(ca), "-x509_strict", "-attime", "1800000000", str(leaf))
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(point[1:1 + P256_SCALAR_BYTES]),
        "y": b64url(point[1 + P256_SCALAR_BYTES:]),
        "d": b64url(scalar(LEAF_KEY_LABEL)),
    }
    (out / "conformance_leaf.jwk").write_text(json.dumps(jwk, indent=2) + "\n")
    leaf_der = der_of_pem(out / "conformance_leaf.pem")
    manifest = {
        "synthetic": "Lab-only test material. The private keys follow from public labels in "
                     "scripts/conformance_fixtures.py; never trust this CA anywhere else.",
        "generator": "scripts/conformance_fixtures.py",
        "dns_names": dns,
        "client_id_x509_san_dns": f"x509_san_dns:{dns[0]}",
        "client_id_x509_hash": "x509_hash:" + b64url(hashlib.sha256(leaf_der).digest()),
        "leaf_validity": [LEAF_NOT_BEFORE, LEAF_NOT_AFTER],
        "ca_validity": [CA_NOT_BEFORE, CA_NOT_AFTER],
        "sha256": {name: hashlib.sha256((out / name).read_bytes()).hexdigest()
                   for name in OUTPUT_FILES},
    }
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")


def check() -> int:
    committed = json.loads((COMMITTED / MANIFEST).read_text())
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp)
        generate(fresh, committed["dns_names"])
        bad = [name for name in [*OUTPUT_FILES, MANIFEST]
               if (fresh / name).read_bytes() != (COMMITTED / name).read_bytes()]
    for name in bad:
        print(f"differs: {COMMITTED / name}")
    print("conformance fixtures: " + ("MISMATCH" if bad else "reproduced byte for byte"))
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if shutil.which("openssl") is None:
        print("openssl not found", file=sys.stderr)
        return 2
    if argv[:1] == ["check"] and len(argv) == 1:
        return check()
    if argv[:1] == ["generate"] and len(argv) >= 2:
        rest = argv[2:]
        dns = [name for flag, name in zip(rest[::2], rest[1::2]) if flag == "--dns"]
        if len(rest) % 2 or len(dns) * 2 != len(rest):
            print(__doc__, file=sys.stderr)
            return 2
        generate(Path(argv[1]), dns or DEFAULT_DNS)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
