#!/usr/bin/env python3
"""Reproduce the SYNTHETIC conformance-mode X.509 fixtures of crates/lab-server.

Usage (run with an isolated interpreter, from the repository root):

    python3 -I scripts/conformance_fixtures.py generate OUT_DIR [--dns NAME ...]
    python3 -I scripts/conformance_fixtures.py check      # regenerate and diff the committed set

Needs only the Python standard library and OpenSSL >= 3.4 on PATH: deterministic ECDSA
(`-sigopt nonce-type:1`, RFC 6979) arrived in OpenSSL 3.2.0 and the `-not_before` /
`-not_after` options of `req` and `x509` in 3.4.0 (OpenSSL CHANGES.md, "Changes between 3.1 and
3.2.0" and "Changes between 3.3 and 3.4.0"). With an older OpenSSL, or LibreSSL, `check` prints
a SKIP line and exits 0 (CI runners such as ubuntu-24.04 ship OpenSSL 3.0); `generate` refuses.
Nothing touches the network.

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
  * conformance_wildcard_leaf.pem  negative-test leaf from the same CA and key whose only SAN is
                                `*.<parent of the first --dns name>`: valid for that host in TLS
                                terms, but no dNSName entry equals it (x509_san_dns must refuse).
  * conformance_foreign_ca.pem  negative-test trust anchor: another self-signed CA that issued
                                nothing here (the leaf must not chain to it).
  * status_ca.pem               trust anchor of Status List Tokens (P-256, self-signed, CA:TRUE
                                pathlen 0): a CA of its own, separate from the Verifier's, as
                                draft-ietf-oauth-status-list-14 §11.3 has a Certificate Authority
                                vouch for the Status Issuer. Never sent in `x5c`.
  * status_signer.pem           Status List Token signing certificate issued by that CA: P-256,
                                CA:FALSE, digitalSignature, no extended key usage (§10 leaves
                                id-kp-oauthStatusSigning TBD; the lab refuses any EKU) and no SAN.
  * status_signer.jwk           its private key as an EC P-256 JWK (tests sign lists with it).
  * conformance_fixtures.json   derived values: x509_san_dns / x509_hash client ids, SANs,
                                validity, SHA-256 of every file.

Reproducibility: every private scalar is derived from a fixed label (SHA-256, reduced into
[1, n-1]), every certificate field is fixed (serials, names, validity, extensions), and ECDSA
signatures are deterministic, so the same inputs give byte-identical output. Because the
scalars follow from public labels, ANYONE can recompute these private keys: the material is
synthetic by construction and must never be trusted outside this lab. No CA private key is
written to OUT_DIR.
"""

import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

COMMITTED = Path("crates/lab-server/tests/fixtures")
DEFAULT_DNS = ["host.docker.internal", "localhost"]
# Labels the private scalars are derived from. Changing one changes the fixtures it signs.
CA_KEY_LABEL = b"OID4VP-security-lab SYNTHETIC conformance CA key v1"
LEAF_KEY_LABEL = b"OID4VP-security-lab SYNTHETIC conformance leaf key v1"
FOREIGN_CA_KEY_LABEL = b"OID4VP-security-lab SYNTHETIC conformance foreign CA key v1"
STATUS_CA_KEY_LABEL = b"OID4VP-security-lab SYNTHETIC status list CA key v1"
STATUS_SIGNER_KEY_LABEL = b"OID4VP-security-lab SYNTHETIC status list signer key v1"
# Oldest OpenSSL with both deterministic ECDSA (3.2.0) and -not_before / -not_after (3.4.0).
MIN_OPENSSL = (3, 4, 0)
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
FOREIGN_CA_SUBJECT = "/O=OID4VP security lab/CN=SYNTHETIC foreign CA - negative tests only"
STATUS_CA_SUBJECT = "/O=OID4VP security lab/CN=SYNTHETIC status list CA - never trust"
STATUS_SIGNER_SUBJECT = "/O=OID4VP security lab SYNTHETIC Status Issuer/CN=SYNTHETIC status list signer"
LEAF_ORG = "/O=OID4VP security lab SYNTHETIC conformance Verifier"
CA_SERIAL = "1"
LEAF_SERIAL = "2"
WILDCARD_LEAF_SERIAL = "3"
FOREIGN_CA_SERIAL = "4"
STATUS_CA_SERIAL = "5"
STATUS_SIGNER_SERIAL = "6"
CA_NOT_BEFORE = "20261101000000Z"
CA_NOT_AFTER = "20361101000000Z"
LEAF_NOT_BEFORE = "20261101000000Z"
LEAF_NOT_AFTER = "20311101000000Z"
# The moment the generated chain is verified at: 2027-01-15T08:00:00Z, inside both validity
# windows above (and independent of the generating machine's clock).
VERIFY_AT_UNIX = "1800000000"
OUTPUT_FILES = [
    "conformance_ca.pem",
    "conformance_leaf.pem",
    "conformance_leaf.key.pem",
    "conformance_leaf.jwk",
    "conformance_wildcard_leaf.pem",
    "conformance_foreign_ca.pem",
    "status_ca.pem",
    "status_signer.pem",
    "status_signer.jwk",
]
MANIFEST = "conformance_fixtures.json"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def scalar(label: bytes) -> bytes:
    value = int.from_bytes(hashlib.sha256(label).digest(), "big") % (P256_ORDER - 1) + 1
    return value.to_bytes(P256_SCALAR_BYTES, "big")


def openssl(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(["openssl", *args], input=data, check=True, capture_output=True).stdout


def openssl_too_old() -> str | None:
    """Why this OpenSSL cannot reproduce the fixtures, or None if it can."""
    version = openssl("version").decode().strip()
    match = re.match(r"OpenSSL (\d+)\.(\d+)\.(\d+)", version)
    if match is None or tuple(int(part) for part in match.groups()) < MIN_OPENSSL:
        return f"needs OpenSSL >= {'.'.join(map(str, MIN_OPENSSL))}, found {version!r}"
    return None


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


def extensions(dns: list[str], wildcard: str) -> str:
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
[v3_status_signer]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[v3_wildcard_leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:{wildcard}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""


def private_jwk(point: bytes, label: bytes) -> dict:
    """The EC P-256 private JWK of the key derived from `label` (public point `point`)."""
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(point[1:1 + P256_SCALAR_BYTES]),
        "y": b64url(point[1 + P256_SCALAR_BYTES:]),
        "d": b64url(scalar(label)),
    }


def der_of_pem(path: Path) -> bytes:
    return openssl("x509", "-in", str(path), "-outform", "DER")


def self_signed_ca(cnf: Path, key: Path, subject: str, serial: str, out: Path) -> None:
    openssl("req", "-x509", "-new", "-config", str(cnf), "-key", str(key), "-subj", subject,
            "-set_serial", serial, "-not_before", CA_NOT_BEFORE, "-not_after", CA_NOT_AFTER,
            "-extensions", "v3_ca", "-sha256", "-sigopt", "nonce-type:1", "-out", str(out))


def issue_leaf(cnf: Path, csr: Path, ca: Path, ca_key: Path, serial: str, section: str,
               out: Path) -> None:
    openssl("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
            "-set_serial", serial, "-not_before", LEAF_NOT_BEFORE, "-not_after", LEAF_NOT_AFTER,
            "-extfile", str(cnf), "-extensions", section, "-sha256", "-sigopt", "nonce-type:1",
            "-out", str(out))
    openssl("verify", "-CAfile", str(ca), "-x509_strict", "-attime", VERIFY_AT_UNIX, str(out))


def generate(out: Path, dns: list[str]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    wildcard = "*." + dns[0].split(".", 1)[1]
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        cnf = tmp / "openssl.cnf"
        cnf.write_text(extensions(dns, wildcard))
        ca_key = tmp / "ca.key.pem"
        write_key(scalar(CA_KEY_LABEL), ca_key)
        leaf_key = out / "conformance_leaf.key.pem"
        point = write_key(scalar(LEAF_KEY_LABEL), leaf_key)
        ca = out / "conformance_ca.pem"
        self_signed_ca(cnf, ca_key, CA_SUBJECT, CA_SERIAL, ca)
        csr = tmp / "leaf.csr"
        openssl("req", "-new", "-config", str(cnf), "-key", str(leaf_key), "-subj",
                f"{LEAF_ORG}/CN={dns[0]}", "-out", str(csr))
        issue_leaf(cnf, csr, ca, ca_key, LEAF_SERIAL, "v3_leaf", out / "conformance_leaf.pem")
        issue_leaf(cnf, csr, ca, ca_key, WILDCARD_LEAF_SERIAL, "v3_wildcard_leaf",
                   out / "conformance_wildcard_leaf.pem")
        foreign_key = tmp / "foreign_ca.key.pem"
        write_key(scalar(FOREIGN_CA_KEY_LABEL), foreign_key)
        self_signed_ca(cnf, foreign_key, FOREIGN_CA_SUBJECT, FOREIGN_CA_SERIAL,
                       out / "conformance_foreign_ca.pem")
        status_ca_key = tmp / "status_ca.key.pem"
        write_key(scalar(STATUS_CA_KEY_LABEL), status_ca_key)
        status_ca = out / "status_ca.pem"
        self_signed_ca(cnf, status_ca_key, STATUS_CA_SUBJECT, STATUS_CA_SERIAL, status_ca)
        signer_key = tmp / "status_signer.key.pem"
        signer_point = write_key(scalar(STATUS_SIGNER_KEY_LABEL), signer_key)
        signer_csr = tmp / "status_signer.csr"
        openssl("req", "-new", "-config", str(cnf), "-key", str(signer_key), "-subj",
                STATUS_SIGNER_SUBJECT, "-out", str(signer_csr))
        issue_leaf(cnf, signer_csr, status_ca, status_ca_key, STATUS_SIGNER_SERIAL,
                   "v3_status_signer", out / "status_signer.pem")
    (out / "conformance_leaf.jwk").write_text(
        json.dumps(private_jwk(point, LEAF_KEY_LABEL), indent=2) + "\n")
    (out / "status_signer.jwk").write_text(
        json.dumps(private_jwk(signer_point, STATUS_SIGNER_KEY_LABEL), indent=2) + "\n")
    leaf_der = der_of_pem(out / "conformance_leaf.pem")
    manifest = {
        "synthetic": "Lab-only test material. The private keys follow from public labels in "
                     "scripts/conformance_fixtures.py; never trust this CA anywhere else.",
        "generator": "scripts/conformance_fixtures.py",
        "dns_names": dns,
        "wildcard_leaf_san": wildcard,
        "client_id_x509_san_dns": f"x509_san_dns:{dns[0]}",
        "client_id_x509_hash": "x509_hash:" + b64url(hashlib.sha256(leaf_der).digest()),
        "leaf_validity": [LEAF_NOT_BEFORE, LEAF_NOT_AFTER],
        "ca_validity": [CA_NOT_BEFORE, CA_NOT_AFTER],
        "sha256": {name: hashlib.sha256((out / name).read_bytes()).hexdigest()
                   for name in OUTPUT_FILES},
    }
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")


def check() -> int:
    too_old = openssl_too_old()
    if too_old:
        print(f"conformance fixtures: SKIP ({too_old}); the committed set is not re-derived")
        return 0
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
        if argv[:1] == ["check"]:
            print("conformance fixtures: SKIP (openssl not found)")
            return 0
        print("openssl not found", file=sys.stderr)
        return 2
    if argv[:1] == ["check"] and len(argv) == 1:
        return check()
    if argv[:1] == ["generate"] and len(argv) >= 2:
        too_old = openssl_too_old()
        if too_old:
            print(too_old, file=sys.stderr)
            return 2
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
