#!/usr/bin/env python3
"""Run one OIDF conformance plan (C3 plain or C4 HAIP) against the lab's conformance mode.

Usage (repository root, suite stack up per tools/oidf-suite/README.md §2):

    python3 -I tools/oidf-suite/driver/run_plan.py run --plan c3|c4 --out OUT_DIR
    python3 -I tools/oidf-suite/driver/run_plan.py summarize RUN_DIR   # RUN_DIR/{c3,c4} -> RUN_DIR

`run` does, in order (README §5e):
  0. records the tree state (tracked changes, untracked files among the lab's build inputs)
     and builds the lab itself (`cargo build -p lab-server --features conformance --locked`),
     so the binary it runs belongs to the commit it records;
  1. renders tools/oidf-suite/config/<name>.local.json (git-ignored, mode 0600, deleted when
     the run ends) from the committed
     placeholder template: a fresh random alias, the synthetic reader CA as trust anchor, the
     synthetic issuer key (`crates/lab-server/tests/fixtures/lab_issuer.jwk`) as
     `credential.signing_jwk`, and an `x5c` with a throwaway self-signed certificate for that
     key (made with `openssl req`, never trusted by anything: the lab trusts the issuer key);
  2. starts the lab in conformance mode, bound to 127.0.0.1, public origin
     https://host.docker.internal:<port>, with the committed synthetic conformance fixtures, the
     issuer's public key, the DCQL query the suite answers (`urn:eudi:pid:1`, given_name,
     family_name, birthdate), a time box, and for C4 `x509_hash` plus a response
     `redirect_uri`;
  3. creates the plan, then for every module, one at a time: starts it, creates a lab session
     (POST /lab/v1/sessions over HTTPS, the lab's certificate checked against the synthetic CA
     with SNI host.docker.internal, connected to 127.0.0.1), GETs the suite's authorization
     endpoint with that session's client_id + request_uri, polls the module, and when the module
     waits for a screenshot uploads a PNG rendering of the lab's result endpoint JSON for that
     session (what the lab itself reports: pending / consumed with the committed claims);
     then fetches the final status, result and log;
  4. writes OUT_DIR: results.json, manifest.json, sanitized per-module logs (every private JWK
     `d`, and the issuer's private scalar wherever it appears, replaced by "REDACTED"), the
     uploaded PNGs, the sanitized rendered config and the lab's console log. Every file is
     then checked for any encoding of the issuer key (JWK, standard base64 and hex of the
     scalar, its RFC 5915 DER in base64, a PEM `PRIVATE KEY` header); a hit stops the run with
     an error. The raw plan export (zip, holds the issuer private key) goes to
     tools/oidf-suite/ (git-ignored, mode 0600); only its SHA-256 goes into the manifest;
  5. stops the lab, also on failure. No module starts after a deadline below the lab's time
     box. The suite stack is left to the operator (`docker compose down`).

OUT_DIR must not exist or be empty. Only the Python standard library and OpenSSL (for the issuer
`x5c`) are used. Suite: https://localhost:8443 only; lab: 127.0.0.1 only; synthetic data only.
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import platform
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SUITE_DIR = ROOT / "tools" / "oidf-suite"
FIXTURES = ROOT / "crates" / "lab-server" / "tests" / "fixtures"
LAB_BIN = ROOT / "target" / "debug" / "lab-server"
DOCKER = ["docker", "--context", "orbstack"]
# docker-compose.yml: nginx publishes the suite on host loopback only.
SUITE = "https://localhost:8443"
# How the suite container reaches host 127.0.0.1 on OrbStack (README §3); the leaf SAN.
LAB_HOST = "host.docker.internal"
LAB_BIND_IP = "127.0.0.1"
# Unprivileged port outside the suite's 8443/8444 and the probe's 18443.
DEFAULT_LAB_PORT = 18444
# Time box of the lab server for one plan run (ADR 0002: at most two hours for this run; a plan
# takes minutes).
LAB_MAX_RUNTIME_SECS = 3600
# The driver stops starting modules this long before the lab's time box ends, leaving room for
# the module in flight, the export and the shutdown.
DRIVER_DEADLINE_MARGIN_SECS = 300
DRIVER_DEADLINE_SECS = LAB_MAX_RUNTIME_SECS - DRIVER_DEADLINE_MARGIN_SECS
# The driver builds the lab itself, so the binary it runs is the one of the commit it records.
LAB_BUILD = ["cargo", "build", "-p", "lab-server", "--features", "conformance", "--locked"]
# Untracked files here would change the lab build without showing in `git status` of tracked files.
LAB_INPUT_PATHS = ["crates", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
# Owner read/write only: the rendered suite config holds the issuer private key.
PRIVATE_FILE_MODE = 0o600
# What the suite's mock wallet presents (README §5a): the PID type and three top-level claims.
DCQL_VCT = "urn:eudi:pid:1"
DCQL_CLAIMS = ("given_name", "family_name", "birthdate")
DCQL_ID = "pid"
# C4: the lab's response redirect_uri. A lab-owned https URL on the public origin; the lab serves
# nothing there (404) and the suite never fetches it, it only lists it (README §5d).
REDIRECT_PATH = "/lab/v1/complete"
LAB_READY_MARKER = "lab-server listening on "
LAB_READY_TIMEOUT_SECS = 30
LAB_STOP_TIMEOUT_SECS = 10
SESSIONS_PATH = "/lab/v1/sessions"
# Random bytes in each alias suffix (16 hex characters, README §2).
ALIAS_SUFFIX_BYTES = 8
# /api/runner/{id}/wait-state clamps its long poll to 30 s (README §5e).
WAIT_MS = 30000
MAX_WAITS = 6
# Slack over the server-side long poll for the client read timeout.
CLIENT_TIMEOUT_SLACK_SECS = 30
# The suite's own HTTP client gives up after 60 s (README §5e); the authorize GET contains both
# of its requests to the lab.
AUTHORIZE_TIMEOUT_SECS = 120
LAB_TIMEOUT_SECS = 30
# Issuer x5c certificate: only has to outlive the run.
ISSUER_CERT_DAYS = "2"
ISSUER_CERT_SUBJECT = "/CN=SYNTHETIC OID4VP lab issuer - never trust"
REDACTED = "REDACTED"
# Any JWK private member that may appear in a suite log; only EC keys are expected.
PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "k")
PRIVATE_D_PATTERN = re.compile(r'(\\?"d\\?"\s*:\s*\\?")[A-Za-z0-9_-]{20,}')
# Never in an evidence file, whatever the encoding (allowlist check after the redaction above).
PEM_PRIVATE_KEY_MARKER = "PRIVATE KEY"
# A base64 fragment this long cannot occur by chance; used for the line-wrapped PEM body.
MIN_FRAGMENT_CHARS = 32
# Compact JWE: five base64url parts, so four dots (RFC 7516 §7.1); a JSON header starts with
# `{"`, which base64url-encodes to "ey".
JWE_COMPACT_DOTS = 4
JSON_OBJECT_B64U_PREFIX = "ey"

PLANS = {
    "c3": {
        "plan_name": "oid4vp-1final-verifier-test-plan",
        "template": "c3-plain",
        "alias_prefix": "oid4vp-lab-c3-",
        "client_id_prefix": "x509_san_dns",
        "redirect": False,
    },
    "c4": {
        "plan_name": "oid4vp-1final-verifier-haip-test-plan",
        "template": "c4-haip",
        "alias_prefix": "oid4vp-lab-c4-",
        "client_id_prefix": "x509_hash",
        "redirect": True,
    },
}

# Expected outcome per module (suffix after `oid4vp-1final-verifier-`) and the lab test that
# covers the same check (docs/interop/oidf-conformance-plan.md §2.3).
HOLDER = "crates/lab-server/tests/holder_binding_e2e.rs"
CONF = "crates/lab-server/tests/conformance_mode_e2e.rs"
EXPECTED = {
    "happy-flow": ("REVIEW", CONF, "conformance_round_trip_over_https_commits_with_x509_san_dns"),
    "minimal-cnf-jwk": ("REVIEW", HOLDER, "credential_with_minimal_cnf_jwk_is_accepted"),
    "request-uri-fetched-twice": ("REVIEW", "crates/lab-server/tests/signed_request_object_e2e.rs",
                                  "served_request_object_is_signed_once_and_never_changes"),
    "present-credential-without-status": (
        "REVIEW", HOLDER, "honest_sd_jwt_kb_presentation_commits_only_the_requested_claims"),
    "request-uri-method-post": ("SKIPPED", None, None),
    "invalid-kb-jwt-signature": ("PASSED", HOLDER, "kb_jwt_with_corrupted_signature_is_rejected"),
    "invalid-credential-signature": ("PASSED", HOLDER, "issuer_jwt_with_corrupted_signature_is_rejected"),
    "invalid-sd-hash": ("PASSED", HOLDER, "kb_jwt_with_wrong_sd_hash_is_rejected"),
    "invalid-kb-jwt-nonce": ("PASSED", HOLDER, "kb_jwt_with_wrong_nonce_is_rejected"),
    "invalid-kb-jwt-aud": ("PASSED", HOLDER, "kb_jwt_with_wrong_aud_is_rejected"),
    "kb-jwt-iat-in-past": ("PASSED", HOLDER, "kb_jwt_with_stale_iat_is_rejected"),
    "kb-jwt-iat-in-future": ("PASSED", HOLDER, "kb_jwt_with_future_iat_is_rejected"),
    "wrong-vct": ("PASSED", "crates/lab-server/src/sd_jwt.rs",
                  "sd_jwt_vc_profile_enforces_vct_and_exactly_the_requested_claims"),
    "present-revoked-credential": ("FAILED", None, None),
}
HAPPY_FLOW_C4_TEST = "conformance_round_trip_with_x509_hash_a256gcm_and_redirect_uri"
MODULE_PREFIX = "oid4vp-1final-verifier-"
EXPECTED_NOTES = {
    "REVIEW": "positive module: REVIEW after the screenshot upload is its best result (not PASSED)",
    "SKIPPED": "the lab sends no request_uri_method=post, so the suite skips this module",
    "FAILED": "expected: the lab has no status-list support, and the module fails any verifier "
              "that does not fetch the status list",
}
# Suite conditions whose finding has a known lab-side cause.
KNOWN_FINDINGS = {
    "EnsureVerifierFetchedRevocationList": "the lab does not fetch status lists, out of lab scope",
}

# The suite's nginx serves a throwaway self-signed certificate on host loopback (README §2).
SUITE_TLS = ssl.create_default_context()
SUITE_TLS.check_hostname = False
SUITE_TLS.verify_mode = ssl.CERT_NONE


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- PNG rendering (stdlib only) ---------------------------------------------------------------

# Classic 5x7 bitmap font for ASCII 0x20-0x7E, one byte per column, bit 0 = top row.
FONT_5X7 = bytes.fromhex(
    "0000000000" "00005f0000" "0007000700" "147f147f14" "242a7f2a12" "2313086462" "3649552250"
    "0005030000" "001c224100" "0041221c00" "082a1c2a08" "08083e0808" "0050300000" "0808080808"
    "0060600000" "2010080402" "3e5149453e" "00427f4000" "4261514946" "2141454b31" "1814127f10"
    "2745454539" "3c4a494930" "0171090503" "3649494936" "064949291e" "0036360000" "0056360000"
    "0008142241" "1414141414" "4122140800" "0201510906" "324979413e" "7e1111117e" "7f49494936"
    "3e41414122" "7f4141221c" "7f49494941" "7f09090101" "3e41415132" "7f0808087f" "00417f4100"
    "2040413f01" "7f08142241" "7f40404040" "7f0204027f" "7f0408107f" "3e4141413e" "7f09090906"
    "3e4151215e" "7f09192946" "4649494931" "01017f0101" "3f4040403f" "1f2040201f" "7f2018207f"
    "6314081463" "0304780403" "6151494543" "00007f4141" "0204081020" "41417f0000" "0402010204"
    "4040404040" "0001020400" "2054545478" "7f48444438" "3844444420" "384444487f" "3854545418"
    "087e090102" "081454543c" "7f08040478" "00447d4000" "2040443d00" "007f102844" "00417f4000"
    "7c04180478" "7c08040478" "3844444438" "7c14141408" "081414187c" "7c08040408" "4854545420"
    "043f444020" "3c4040207c" "1c2040201c" "3c4030403c" "4428102844" "0c5050503c" "4464544c44"
    "0008364100" "00007f0000" "0041360800" "0201020402"
)
GLYPH_COLUMNS = 5
GLYPH_ROWS = 7
FIRST_GLYPH = 0x20
LAST_GLYPH = 0x7E
# One blank column and two blank rows between glyphs; every font pixel drawn as SCALE x SCALE.
CELL_WIDTH = GLYPH_COLUMNS + 1
CELL_HEIGHT = GLYPH_ROWS + 2
SCALE = 2
MARGIN = 8
WRAP_COLUMNS = 110
INK, PAPER = 0, 255
# PNG (W3C PNG Specification, Second Edition / ISO/IEC 15948): signature §5.2; IHDR §11.2.2
# with bit depth 8, colour type 0 (greyscale) and compression method, filter method and
# interlace method all 0; filter type 0 (None) before each scanline §9.2; iTXt §11.3.4.5 =
# keyword, NUL, compression
# flag 0, compression method 0, empty language tag + NUL, empty translated keyword + NUL, text.
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_GRAYSCALE_8BIT = (8, 0)
PNG_COMPRESSION_FILTER_INTERLACE = (0, 0, 0)
PNG_FILTER_NONE = b"\x00"
PNG_ITXT_KEYWORD = b"Description"
PNG_ITXT_UNCOMPRESSED_NO_LANGUAGE = b"\x00" + b"\x00\x00" + b"\x00" + b"\x00"
PNG_MAX_COMPRESSION = 9
# The suite accepts images up to 500 KB (README §5d).
MAX_UPLOAD_BYTES = 500 * 1024


def png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def render_png(lines: list, text_chunk: str) -> bytes:
    """Grayscale PNG of `lines` in the 5x7 font, plus the full text as a PNG iTXt chunk."""
    wrapped = []
    for line in lines:
        line = "".join(c if FIRST_GLYPH <= ord(c) <= LAST_GLYPH else "?" for c in line)
        wrapped.extend([line[i:i + WRAP_COLUMNS] for i in range(0, len(line), WRAP_COLUMNS)] or [""])
    columns = max(len(line) for line in wrapped)
    width = (2 * MARGIN + columns * CELL_WIDTH) * SCALE
    height = (2 * MARGIN + len(wrapped) * CELL_HEIGHT) * SCALE
    pixels = [bytearray([PAPER]) * width for _ in range(height)]
    for row, line in enumerate(wrapped):
        for col, char in enumerate(line):
            glyph = FONT_5X7[(ord(char) - FIRST_GLYPH) * GLYPH_COLUMNS:][:GLYPH_COLUMNS]
            for gx, bits in enumerate(glyph):
                for gy in range(GLYPH_ROWS):
                    if bits >> gy & 1:
                        x0 = (MARGIN + col * CELL_WIDTH + gx) * SCALE
                        y0 = (MARGIN + row * CELL_HEIGHT + gy) * SCALE
                        for dy in range(SCALE):
                            pixels[y0 + dy][x0:x0 + SCALE] = bytes([INK]) * SCALE
    raw = b"".join(PNG_FILTER_NONE + bytes(r) for r in pixels)
    depth, colour = PNG_GRAYSCALE_8BIT
    header = struct.pack(">IIBBBBB", width, height, depth, colour, *PNG_COMPRESSION_FILTER_INTERLACE)
    itxt = PNG_ITXT_KEYWORD + PNG_ITXT_UNCOMPRESSED_NO_LANGUAGE + text_chunk.encode()
    return (PNG_SIGNATURE + png_chunk(b"IHDR", header) + png_chunk(b"iTXt", itxt)
            + png_chunk(b"IDAT", zlib.compress(raw, PNG_MAX_COMPRESSION)) + png_chunk(b"IEND", b""))


# --- HTTP ---------------------------------------------------------------------------------------

def suite_api(method: str, path: str, body=None, ctype="application/json"):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    headers = {"Content-Type": ctype} if data is not None else {}
    req = urllib.request.Request(SUITE + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, context=SUITE_TLS,
                                timeout=WAIT_MS / 1000 + CLIENT_TIMEOUT_SLACK_SECS) as resp:
        text = resp.read().decode()
        return json.loads(text) if text else None


def suite_bytes(path: str) -> bytes:
    with urllib.request.urlopen(SUITE + path, context=SUITE_TLS,
                                timeout=WAIT_MS / 1000 + CLIENT_TIMEOUT_SLACK_SECS) as resp:
        return resp.read()


def wait_state(test_id: str, states: str):
    for _ in range(MAX_WAITS):
        reply = suite_api("GET", f"/api/runner/{test_id}/wait-state?states={states}&timeoutMs={WAIT_MS}")
        if reply and "state" in reply:
            return reply["state"]
    return None


class LabClient:
    """HTTPS to the lab on 127.0.0.1:<port> under its public name (SNI and Host
    host.docker.internal), the certificate checked against the synthetic CA."""

    def __init__(self, port: int, ca_file: Path):
        self.port = port
        self.tls = ssl.create_default_context(cafile=str(ca_file))
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_3
        self.last_tls = None

    def request(self, method: str, url_or_path: str, body: bytes = b""):
        parsed = urllib.parse.urlsplit(url_or_path)
        if parsed.scheme and (parsed.hostname != LAB_HOST or parsed.port != self.port):
            raise ValueError(f"not a lab URL: {url_or_path}")
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        raw = socket.create_connection((LAB_BIND_IP, self.port), timeout=LAB_TIMEOUT_SECS)
        sock = self.tls.wrap_socket(raw, server_hostname=LAB_HOST)
        self.last_tls = {"version": sock.version(), "cipher": sock.cipher()[0], "alpn": sock.selected_alpn_protocol()}
        conn = http.client.HTTPConnection(LAB_HOST, self.port, timeout=LAB_TIMEOUT_SECS)
        conn.sock = sock
        try:
            headers = {"Host": f"{LAB_HOST}:{self.port}"}
            if method == "POST":
                headers["Content-Type"] = "application/json"
            conn.request(method, path, body=body if method == "POST" else None, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()


# --- configuration ------------------------------------------------------------------------------

# RFC 5915 §3 ECPrivateKey ::= SEQUENCE { version INTEGER (1), privateKey OCTET STRING,
# [0] parameters (the named curve), [1] publicKey BIT STRING }, DER (X.690) for P-256:
DER_SEQUENCE = b"\x30"
DER_VERSION_1 = bytes.fromhex("020101")  # INTEGER, length 1, value 1 (ecPrivkeyVer1)
DER_P256_SCALAR = b"\x04\x20"  # OCTET STRING of 32 bytes
DER_PARAMETERS_P256 = b"\xa0\x0a" + bytes.fromhex("06082a8648ce3d030107")  # [0] OID prime256v1 (RFC 5480 §2.1.1.1)
# [1] { BIT STRING, 66 bytes: 0 unused bits, 0x04 uncompressed point (SEC 1 §2.3.3), X, Y }
DER_PUBLIC_KEY_P256 = b"\xa1\x44\x03\x42\x00\x04"
# DER short-form length: one byte, below 0x80 (X.690 §8.1.3.4).
DER_SHORT_LENGTH_LIMIT = 0x80


def sec1_der(jwk: dict) -> bytes:
    """RFC 5915 ECPrivateKey DER of an EC P-256 JWK (fixed-length encoding for P-256)."""
    d, x, y = (b64u_dec(jwk[k]) for k in ("d", "x", "y"))
    body = DER_VERSION_1 + DER_P256_SCALAR + d + DER_PARAMETERS_P256 + DER_PUBLIC_KEY_P256 + x + y
    if len(body) >= DER_SHORT_LENGTH_LIMIT:
        raise ValueError("ECPrivateKey body does not fit a DER short-form length")
    return DER_SEQUENCE + bytes([len(body)]) + body


def forbidden_forms(jwk: dict) -> list:
    """Every encoding of the issuer private key the driver refuses to write as evidence."""
    d = b64u_dec(jwk["d"])
    der = sec1_der(jwk)
    der_b64 = base64.b64encode(der).decode()
    return [PEM_PRIVATE_KEY_MARKER, jwk["d"], base64.b64encode(d).decode(), base64.b64encode(d).decode().rstrip("="),
            d.hex(), d.hex().upper(), der_b64, base64.urlsafe_b64encode(der).decode().rstrip("="),
            der_b64[:MIN_FRAGMENT_CHARS]]


def assert_clean(text: str, forms: list, where):
    hits = [i for i, form in enumerate(forms) if form in text]
    if hits:
        raise SystemExit(f"refusing to write {where}: private key material (form #{hits[0]}) left after redaction")


def issuer_x5c(jwk: dict) -> str:
    """A throwaway self-signed certificate for the synthetic issuer key, base64 DER."""
    with tempfile.TemporaryDirectory() as tmp:
        key = Path(tmp) / "issuer.key.pem"
        pem = base64.encodebytes(sec1_der(jwk)).decode()
        key.write_text(f"-----BEGIN EC PRIVATE KEY-----\n{pem}-----END EC PRIVATE KEY-----\n")
        der = subprocess.run(
            ["openssl", "req", "-x509", "-new", "-key", str(key), "-subj", ISSUER_CERT_SUBJECT,
             "-days", ISSUER_CERT_DAYS, "-sha256", "-outform", "DER"],
            check=True, capture_output=True).stdout
    return base64.b64encode(der).decode()


def render_config(plan: dict, alias: str, issuer_jwk: dict, anchor_pem: str) -> dict:
    template = json.loads((SUITE_DIR / "config" / f"{plan['template']}.config.json").read_text())
    template["alias"] = alias
    template["client"]["request_object_trust_anchor_pem"] = anchor_pem
    jwk = template["credential"]["signing_jwk"]
    for member in ("x", "y", "d"):
        jwk[member] = issuer_jwk[member]
    jwk["x5c"] = [issuer_x5c(issuer_jwk)]
    if "LAB:" in json.dumps(template):
        raise SystemExit("config template still has a LAB: placeholder")
    return template


def redact(value, secret: str):
    """Every private JWK member and the issuer's private scalar, wherever they appear."""
    if isinstance(value, dict):
        is_jwk = "kty" in value
        return {k: (REDACTED if is_jwk and k in PRIVATE_JWK_MEMBERS else redact(v, secret))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secret) for v in value]
    if isinstance(value, str):
        value = value.replace(secret, REDACTED)
        return PRIVATE_D_PATTERN.sub(lambda m: m.group(1) + REDACTED, value)
    return value


def write_json(path: Path, value, issuer_jwk: dict):
    """Redacts (denylist), then refuses any known encoding of the issuer key (allowlist)."""
    text = json.dumps(redact(value, issuer_jwk["d"]), indent=1, sort_keys=False) + "\n"
    assert_clean(text, forbidden_forms(issuer_jwk), path)
    path.write_text(text)


# --- lab process --------------------------------------------------------------------------------

def start_lab(plan: dict, port: int, alias: str, log_path: Path):
    origin = f"https://{LAB_HOST}:{port}"
    args = [
        str(LAB_BIN), "--mode", "conformance",
        "--signing-key", str(FIXTURES / "conformance_leaf.jwk"),
        "--issuer-key", str(FIXTURES / "lab_issuer.pub.jwk"),
        "--tls-cert", str(FIXTURES / "conformance_leaf.pem"),
        "--tls-key", str(FIXTURES / "conformance_leaf.key.pem"),
        "--trust-anchor", str(FIXTURES / "conformance_ca.pem"),
        "--public-origin", origin,
        "--bind", f"{LAB_BIND_IP}:{port}",
        "--client-id-prefix", plan["client_id_prefix"],
        "--max-runtime-secs", str(LAB_MAX_RUNTIME_SECS),
        "--credential-query-id", DCQL_ID,
        "--vct", DCQL_VCT,
        "--claims", ",".join(DCQL_CLAIMS),
        "--authorization-endpoint", f"{SUITE}/test/a/{alias}/authorize",
    ]
    if plan["redirect"]:
        args += ["--response-redirect-uri", origin + REDIRECT_PATH]
    log = log_path.open("w")
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            env={"PATH": os.environ.get("PATH", "")})
    ready = threading.Event()

    def pump():
        for line in proc.stdout:
            log.write(line.replace(str(ROOT), "."))
            log.flush()
            if line.startswith(LAB_READY_MARKER):
                ready.set()
        log.close()

    threading.Thread(target=pump, daemon=True).start()
    if not ready.wait(LAB_READY_TIMEOUT_SECS):
        proc.kill()
        raise SystemExit(f"lab did not start; see {log_path}")
    cmdline = " ".join(a.replace(str(ROOT) + "/", "") for a in args)
    return proc, cmdline


def stop_lab(proc):
    proc.terminate()
    try:
        proc.wait(LAB_STOP_TIMEOUT_SECS)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# --- provenance ---------------------------------------------------------------------------------

def command(args: list) -> str:
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True, cwd=ROOT).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as e:
        return f"unavailable: {e}"


def suite_images() -> dict:
    images = {}
    for service in ("server", "nginx", "mongodb"):
        container = f"oidf-suite-{service}-1"
        image_id = command(DOCKER + ["inspect", "--format", "{{.Image}}", container])
        images[service] = {
            "container": container,
            "image_id": image_id,
            "repo_digests": json.loads(command(DOCKER + ["image", "inspect", "--format",
                                                         "{{json .RepoDigests}}", image_id]) or "null"),
        }
    return images


def lab_tree_state() -> dict:
    """Tracked changes anywhere, and untracked files among the lab's build inputs."""
    tracked = command(["git", "status", "--porcelain", "--untracked-files=no"])
    untracked = command(["git", "ls-files", "--others", "--exclude-standard", "--"] + LAB_INPUT_PATHS)
    return {"tracked_changes": tracked.splitlines(), "untracked_lab_inputs": untracked.splitlines()}


def build_lab() -> dict:
    """Builds the lab binary from the working tree, so it matches the commit recorded."""
    subprocess.run(LAB_BUILD, check=True, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"built_by_driver": True, "build_command": " ".join(LAB_BUILD)}


def manifest(plan_key: str, plan: dict, variant: dict, alias: str, plan_id: str, lab_cmd: str,
             started: str, export_sha: str, build: dict, tree: dict) -> dict:
    return {
        "what": "OIDF conformance suite run against the lab's conformance mode (local, synthetic data)",
        "not_a_certification": "nothing was submitted to the OpenID Foundation",
        "stage": plan_key.upper(),
        "started_utc": started,
        "finished_utc": utc_now(),
        "lab": {
            "commit": command(["git", "rev-parse", "HEAD"]),
            "dirty": bool(tree["tracked_changes"] or tree["untracked_lab_inputs"]),
            "tree": tree,
            "cargo_lock_sha256": sha256_file(ROOT / "Cargo.lock"),
            "binary": "target/debug/lab-server",
            "build": build,
            "binary_sha256": sha256_file(LAB_BIN),
            "command": lab_cmd,
            "rustc": command(["rustc", "--version"]),
        },
        "suite": {
            "base_url": SUITE,
            "compose_file": "tools/oidf-suite/docker-compose.yml",
            "compose_file_sha256": sha256_file(SUITE_DIR / "docker-compose.yml"),
            "images": suite_images(),
            # The JVM that made the TLS 1.3 handshakes with the lab (java -version prints to stderr).
            "java": command(DOCKER + ["exec", "oidf-suite-server-1", "sh", "-c", "java -version 2>&1"]),
            "plan_name": plan["plan_name"],
            "variant": variant,
            "plan_id": plan_id,
            "alias": alias,
            "export_zip_sha256": export_sha,
            "export_zip_note": "raw export kept out of git (holds the synthetic issuer private key)",
        },
        "driver": {"path": "tools/oidf-suite/driver/run_plan.py",
                   "sha256": sha256_file(Path(__file__).resolve())},
        "host": {
            "os": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "docker": command(DOCKER + ["version", "--format", "client {{.Client.Version}}, server {{.Server.Version}}"]),
            "orbstack": command(["orb", "version"]).splitlines()[0] if command(["orb", "version"]) else "",
            "openssl": command(["openssl", "version"]),
        },
    }


# --- the run ------------------------------------------------------------------------------------

def findings(log: list) -> list:
    return [{"src": e.get("src"), "result": e.get("result"), "msg": e.get("msg")}
            for e in log if e.get("result") in ("FAILURE", "WARNING")]


def response_jwe_header(log: list):
    """The protected header of the suite's encrypted response, if its log shows it."""
    for entry in log:
        for value in entry.values():
            if (isinstance(value, str) and value.count(".") == JWE_COMPACT_DOTS
                    and value.startswith(JSON_OBJECT_B64U_PREFIX)):
                try:
                    header = json.loads(b64u_dec(value.split(".")[0]))
                except ValueError:
                    continue
                if "enc" in header and "epk" in header:
                    return {k: header[k] for k in ("alg", "enc", "kid") if k in header}
    return None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """The authorize GET must be answered by the suite itself: a 3xx is an error, not followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


SUITE_NO_REDIRECT = urllib.request.build_opener(urllib.request.HTTPSHandler(context=SUITE_TLS), NoRedirect)


def run_module(module: str, plan_id: str, lab: LabClient, out: Path, issuer_jwk: dict) -> dict:
    short = module.removeprefix(MODULE_PREFIX)
    test_id = suite_api("POST", "/api/runner?" + urllib.parse.urlencode({"test": module, "plan": plan_id}))["id"]
    state = wait_state(test_id, "WAITING,FINISHED,INTERRUPTED")
    runner = suite_api("GET", f"/api/runner/{test_id}")
    endpoint = runner["exposed"]["authorization_endpoint"]
    record = {"module": module, "test_id": test_id, "authorization_endpoint": endpoint}
    if state != "WAITING":
        record["note"] = f"module did not wait for an authorization request (state {state})"
    else:
        status, body = lab.request("POST", SESSIONS_PATH)
        if status != http.client.CREATED:
            raise SystemExit(f"lab session not created: {status} {body!r}")
        session = json.loads(body)
        authz = session["authorization_request"]
        if not (authz.startswith(endpoint + "?") and endpoint.startswith(SUITE + "/")):
            raise SystemExit(f"lab authorization_request {authz} is not for {endpoint} on {SUITE}")
        record.update(session_id=session["session_id"], client_id=session["client_id"],
                      lab_tls=lab.last_tls)
        started = time.monotonic()
        with SUITE_NO_REDIRECT.open(authz, timeout=AUTHORIZE_TIMEOUT_SECS) as resp:
            if resp.url != authz:
                raise SystemExit(f"authorize GET ended at {resp.url}, not {authz}")
            record["authorize_status"] = resp.status
        record["authorize_seconds"] = round(time.monotonic() - started, 2)
        state = wait_state(test_id, "WAITING,FINISHED,INTERRUPTED")
        result_status, result_body = lab.request("GET", session["result_uri"])
        lab_result = json.loads(result_body) if result_status == http.client.OK else None
        record["lab_result"] = lab_result
        runner = suite_api("GET", f"/api/runner/{test_id}")
        if state == "WAITING" and runner.get("browser", {}).get("uploadsRequired", 0) > 0:
            placeholder = next(e["upload"] for e in suite_api("GET", f"/api/log/{test_id}") if "upload" in e)
            text = json.dumps(lab_result, indent=2)
            lines = [f"OID4VP security lab - conformance mode - result for module {short}",
                     f"GET https://{LAB_HOST}:{lab.port}/lab/v1/results/<result token> at {utc_now()}",
                     f"session {session['session_id']}, client_id {session['client_id']}",
                     "(the lab's own result endpoint for this session, rendered by run_plan.py;"
                     " synthetic data)", ""] + text.splitlines()
            png = render_png(lines, "\n".join(lines))
            if len(png) > MAX_UPLOAD_BYTES:
                raise SystemExit(f"screenshot for {module} is {len(png)} bytes")
            (out / "screenshots").mkdir(exist_ok=True)
            (out / "screenshots" / f"{short}.png").write_bytes(png)
            data_url = "data:image/png;base64," + base64.b64encode(png).decode()
            suite_api("POST", f"/api/log/{test_id}/images/{placeholder}", data_url.encode(), "text/plain")
            record["screenshot"] = f"screenshots/{short}.png"
            state = wait_state(test_id, "FINISHED,INTERRUPTED")
        elif state == "WAITING":
            record["note"] = "module still WAITING without a screenshot request; stopped by the driver"
            suite_api("DELETE", f"/api/runner/{test_id}")
            state = wait_state(test_id, "FINISHED,INTERRUPTED")
    info = suite_api("GET", f"/api/info/{test_id}")
    log = suite_api("GET", f"/api/log/{test_id}")
    write_json(out / "logs" / f"{short}.json", log, issuer_jwk)
    expected, test_file, test_name = EXPECTED.get(short, (None, None, None))
    record.update(final_state=state, status=info.get("status"), result=info.get("result"),
                  expected=expected, as_expected=info.get("result") == expected,
                  findings=findings(log), response_jwe=response_jwe_header(log),
                  log=f"logs/{short}.json", lab_test=test_name and {"file": test_file, "test": test_name})
    return record


def cmd_run(args):
    plan = PLANS[args.plan]
    out = Path(args.out)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise SystemExit(f"{out} exists and is not an empty directory; pick a new run directory")
    if suite_api("GET", "/api/currentuser") is None:
        raise SystemExit("suite not answering on " + SUITE)
    tree = lab_tree_state()
    build = build_lab()
    (out / "logs").mkdir(parents=True)
    started = utc_now()
    issuer_jwk = json.loads((FIXTURES / "lab_issuer.jwk").read_text())
    alias = plan["alias_prefix"] + secrets.token_hex(ALIAS_SUFFIX_BYTES)
    anchor = (FIXTURES / "conformance_ca.pem").read_text()
    config = render_config(plan, alias, issuer_jwk, anchor)
    write_json(out / "config.sanitized.json", config, issuer_jwk)
    variant = json.loads((SUITE_DIR / "config" / f"{plan['template']}.variant.json").read_text())
    # The rendered config (issuer private key) exists only for the run: 0600, deleted at the end.
    local = SUITE_DIR / "config" / f"{plan['template']}.local.json"
    local.unlink(missing_ok=True)
    fd = os.open(local, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_FILE_MODE)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(config, indent=1) + "\n")

    results = {"plan": plan["plan_name"], "variant": variant, "alias": alias, "modules": []}
    export_sha = None
    proc = None
    try:
        proc, lab_cmd = start_lab(plan, args.lab_port, alias, out / "lab-console.log")
        deadline = time.monotonic() + DRIVER_DEADLINE_SECS
        lab = LabClient(args.lab_port, FIXTURES / "conformance_ca.pem")
        status, _ = lab.request("GET", "/health")
        if status != http.client.OK:
            raise SystemExit("lab /health did not answer 200")
        query = urllib.parse.urlencode({"planName": plan["plan_name"], "variant": json.dumps(variant)})
        created = suite_api("POST", f"/api/plan?{query}", config)
        plan_id = created["id"]
        results["plan_id"] = plan_id
        modules = [m["testModule"] for m in created["modules"]]
        for module in modules:
            if time.monotonic() > deadline:
                raise SystemExit(f"driver deadline ({DRIVER_DEADLINE_SECS} s) passed before {module}")
            record = run_module(module, plan_id, lab, out, issuer_jwk)
            results["modules"].append(record)
            print(f"{module}: {record['status']} {record['result']} (expected {record['expected']})", flush=True)
        # The export holds the issuer private key too: owner-only, git-ignored, kept for review.
        export = SUITE_DIR / f"{plan['template']}-{alias}.zip"
        fd = os.open(export, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "wb") as f:
            f.write(suite_bytes(f"/api/plan/export/{plan_id}"))
        export_sha = sha256_file(export)
    finally:
        if proc is not None:
            stop_lab(proc)
        local.unlink(missing_ok=True)
    write_json(out / "results.json", results, issuer_jwk)
    write_json(out / "manifest.json",
               manifest(args.plan, plan, variant, alias, results.get("plan_id"), lab_cmd, started, export_sha,
                        build, tree),
               issuer_jwk)
    forms = forbidden_forms(issuer_jwk)
    for path in sorted(p for p in out.rglob("*") if p.is_file()):
        assert_clean(path.read_bytes().decode("latin-1"), forms, path)
    print(f"evidence in {out}; raw export (git-ignored, mode 0600) in {SUITE_DIR.relative_to(ROOT)}/")


# --- summary ------------------------------------------------------------------------------------

def explain(sources: list) -> str:
    return ", ".join(f"{s} ({KNOWN_FINDINGS[s]})" if s in KNOWN_FINDINGS else s for s in sources)


def cmd_summarize(args):
    run = Path(args.run_dir)
    plans = {k: json.loads((run / k / "results.json").read_text()) for k in PLANS if (run / k).is_dir()}
    manifests = {k: json.loads((run / k / "manifest.json").read_text()) for k in plans}
    commits = {m["lab"]["commit"] for m in manifests.values()}
    if len(commits) != 1:
        raise SystemExit(f"plans ran at different lab commits: {commits}")
    (run / "results.json").write_text(json.dumps(
        {k: [{key: m.get(key) for key in ("module", "status", "result", "expected", "as_expected",
                                          "findings", "response_jwe", "lab_test", "log", "screenshot")}
             for m in p["modules"]] for k, p in plans.items()}, indent=1) + "\n")
    (run / "manifest.json").write_text(json.dumps(
        {"lab_commit": commits.pop(), "plans": {k: f"{k}/manifest.json" for k in plans},
         "summarized_with_driver_sha256": sha256_file(Path(__file__).resolve()),
         "files_sha256": {str(p.relative_to(run)): sha256_file(p) for p in sorted(run.rglob("*"))
                          if p.is_file() and not (p.parent == run and p.name in ("manifest.json", "summary.md"))}},
        indent=1) + "\n")
    depth = "../" * (len(run.resolve().relative_to(ROOT).parts))
    lines = ["# OIDF conformance run: lab conformance mode", "",
             "Local run of the OpenID Foundation conformance suite (prebuilt images, OrbStack) against",
             "the lab Verifier's time-boxed conformance mode, synthetic data only. **This is not a",
             "certification and nothing was submitted to the OpenID Foundation.** REVIEW is not PASSED:",
             "it is the best result a positive module can reach, after a human-checkable screenshot",
             "(here a rendering of the lab's own result endpoint JSON for that session).",
             "The suite has no OpenID4VP 1.1 or HPKE plan: the lab's primary HPKE-0 path is not covered.", ""]
    for key, plan in plans.items():
        mani = manifests[key]
        lines += [f"## {key.upper()}: `{plan['plan']}`", "",
                  f"Variant `{json.dumps(plan['variant'])}`, alias `{plan['alias']}`, lab commit "
                  f"`{mani['lab']['commit'][:12]}` (dirty: {mani['lab']['dirty']}).", "",
                  "| Module | Status | Result | Expected | Reason (non-PASSED) | Lab test |",
                  "| --- | --- | --- | --- | --- | --- |"]
        for m in plan["modules"]:
            short = m["module"].removeprefix(MODULE_PREFIX)
            reason = ""
            if m["result"] != "PASSED":
                reason = EXPECTED_NOTES.get(m["result"], "") if m["as_expected"] else "UNEXPECTED"
                warn = sorted({f["src"] for f in m["findings"] if f["result"] == "WARNING"})
                fail = sorted({f["src"] for f in m["findings"] if f["result"] == "FAILURE"})
                if fail:
                    reason += f"; FAILURE: {explain(fail)}"
                if warn:
                    reason += f"; WARNING: {explain(warn)}"
            test = m.get("lab_test")
            if test and short == "happy-flow" and key == "c4":
                test = {"file": CONF, "test": HAPPY_FLOW_C4_TEST}
            link = f"[`{test['test']}`]({depth}{test['file']})" if test else "none"
            lines.append(f"| [{short}]({key}/{m['log']}) | {m['status']} | {m['result']} | "
                         f"{m['expected']} | {reason.strip('; ')} | {link} |")
        jwes = [m["response_jwe"] for m in plan["modules"] if m.get("response_jwe")]
        algs = sorted({f"{j.get('alg')} / {j.get('enc')}" for j in jwes})
        kids = {j.get("kid") for j in jwes}
        tls = {json.dumps(m["lab_tls"], sort_keys=True) for m in plan["modules"] if m.get("lab_tls")}
        lines += ["", f"Encrypted responses in the suite log: {len(jwes)}, `alg` / `enc` {', '.join(algs) or 'none'}, "
                      f"{len(kids)} distinct `kid` values (one fresh lab key per session).",
                  "Suite (JVM in the server container) to lab: every `request_uri` GET and `response_uri` POST "
                  "completed over the lab's TLS 1.3-only listener (see the HTTP entries in each log).",
                  f"Driver to lab: {', '.join(sorted(tls))}.", ""]
    (run / "summary.md").write_text("\n".join(lines))
    print(f"wrote {run}/summary.md, results.json, manifest.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run")
    run.add_argument("--plan", choices=sorted(PLANS), required=True)
    run.add_argument("--out", required=True)
    run.add_argument("--lab-port", type=int, default=DEFAULT_LAB_PORT)
    run.set_defaults(func=cmd_run)
    summarize = sub.add_parser("summarize")
    summarize.add_argument("run_dir")
    summarize.set_defaults(func=cmd_summarize)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
