"""Suite-observation stand-in. NOT a verifier, NOT the lab.

It never checks a presentation. For each module it serves one signed Request Object, decrypts
the suite's ECDH-ES response to record its shape, and answers by module name: 200 for positive
modules, 400 for negative ones. What it shows is the suite's own behaviour (request-object
checks, the credential it builds, the JWE header, the POST body, how results are reached), as
recorded in tools/oidf-suite/README.md. Synthetic keys only, generated fresh per run and never
written outside OUT_DIR. Binds 127.0.0.1 only; the suite container reaches it as
host.docker.internal.

Usage (suite up, see README §2):
  uv run --with cryptography==46.0.3 python -I tools/oidf-suite/standin/standin.py \
      --plan plain|haip --out OUT_DIR [--san-mismatch] [--reuse-enc-key] [--no-redirect-uri] MODULE...
OUT_DIR must not exist yet (or be empty): every run gets its own directory.

Experiment switches (each makes the stand-in deliberately wrong in one way):
  --san-mismatch     request-object leaf SAN is DNS:san-mismatch.invalid only (plain plan)
  --reuse-enc-key    one response-encryption key for every module of the run
  --no-redirect-uri  answer positive modules with 200 {} even under HAIP
"""
import argparse
import base64
import datetime
import hashlib
import http.server
import json
import os
import secrets
import ssl
import threading
import time
import urllib.parse
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

SUITE = "https://localhost:8443"
# Unprivileged port outside the suite's 8443/8444; also used by scripts/oidf_suite_probe.sh.
STUB_PORT = 18443
# How the suite container reaches host 127.0.0.1 on OrbStack (README §3).
HOST_ALIAS = "host.docker.internal"
MISMATCHED_SAN = "san-mismatch.invalid"
# OID4VP 1.0 Final §13.3: at least 16 fresh random bytes.
NONCE_BYTES = 16
# Random bytes behind each JWK kid; only uniqueness within a request matters.
KID_BYTES = 8
# Random bytes in each alias suffix (16 hex characters).
ALIAS_SUFFIX_BYTES = 8
P256_COORD_BYTES = 32
# Certificates only have to outlive the run; backdating absorbs container clock skew.
CERT_DAYS = 2
CERT_BACKDATE = datetime.timedelta(minutes=5)
REQUEST_OBJECT_TTL_SECONDS = 300
# /api/runner/{id}/wait-state clamps its long poll to 30 s (TestRunner WAIT_STATE_MAX_TIMEOUT_MS).
WAIT_MS = 30000
MAX_WAITS = 6
# Slack over the server-side wait for the HTTP read timeout.
CLIENT_TIMEOUT_SLACK_SECONDS = 30
ENC_KEY_BITS = {"A128GCM": 128, "A256GCM": 256}
GCM_TAG_BYTES = 16
BITS_PER_BYTE = 8
# RFC 7518 §4.6.2 Concat KDF: 32-bit big-endian length prefixes and round counter.
KDF_WORD_BYTES = 4
# 1x1 transparent PNG: automation stand-in for a screenshot. It is NOT evidence of anything.
PNG_1X1 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
# Per-connection socket deadline, covering the TLS handshake and each read: a peer that stalls
# ties up only its own worker thread, and only this long. The suite's own client times out at
# 60 s, so 10 s is ample for a well-behaved peer on loopback.
CONNECTION_TIMEOUT_SECONDS = 10
# Module-name fragments of the negative modules (answered with 400).
NEGATIVE = ("invalid", "iat-in", "wrong-vct", "revoked")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # the suite's nginx serves a throwaway self-signed certificate


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwk_pub(key) -> dict:
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": b64u(n.x.to_bytes(P256_COORD_BYTES, "big")),
            "y": b64u(n.y.to_bytes(P256_COORD_BYTES, "big"))}


def jwk_priv(key) -> dict:
    d = key.private_numbers().private_value.to_bytes(P256_COORD_BYTES, "big")
    return {**jwk_pub(key), "d": b64u(d)}


def sign_jwt(key, header: dict, claims: dict) -> str:
    si = b64u(json.dumps(header, separators=(",", ":")).encode()) + "." + \
         b64u(json.dumps(claims, separators=(",", ":")).encode())
    r, s = decode_dss_signature(key.sign(si.encode(), ec.ECDSA(hashes.SHA256())))
    return si + "." + b64u(r.to_bytes(P256_COORD_BYTES, "big") + s.to_bytes(P256_COORD_BYTES, "big"))


def make_cert(subject_cn, key, issuer_cn, issuer_key, ca: bool, sans=()):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - CERT_BACKDATE)
         .not_valid_after(now + datetime.timedelta(days=CERT_DAYS))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    usage = dict(digital_signature=not ca, content_commitment=False, key_encipherment=False,
                 data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                 encipher_only=False, decipher_only=False)
    b = b.add_extension(x509.KeyUsage(**usage), critical=True)
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def concat_kdf(z: bytes, enc: str, apu: bytes, apv: bytes) -> bytes:
    bits = ENC_KEY_BITS[enc]
    word = lambda n: n.to_bytes(KDF_WORD_BYTES, "big")  # noqa: E731
    other = b"".join(word(len(x)) + x for x in (enc.encode(), apu, apv)) + word(bits)
    out, counter = b"", 1
    while len(out) * BITS_PER_BYTE < bits:
        out += hashlib.sha256(word(counter) + z + other).digest()
        counter += 1
    return out[: bits // BITS_PER_BYTE]


def decrypt_ecdh_es(jwe: str, priv):
    ph, ek, iv, ct, tag = jwe.split(".")
    hdr = json.loads(b64u_dec(ph))
    epk = hdr["epk"]
    pub = ec.EllipticCurvePublicNumbers(int.from_bytes(b64u_dec(epk["x"]), "big"),
                                        int.from_bytes(b64u_dec(epk["y"]), "big"), ec.SECP256R1()).public_key()
    cek = concat_kdf(priv.exchange(ec.ECDH(), pub), hdr["enc"],
                     b64u_dec(hdr.get("apu", "")), b64u_dec(hdr.get("apv", "")))
    if ek or len(b64u_dec(tag)) != GCM_TAG_BYTES:
        raise ValueError("not a direct ECDH-ES / AES-GCM JWE")
    return hdr, AESGCM(cek).decrypt(b64u_dec(iv), b64u_dec(ct) + b64u_dec(tag), ph.encode())


def dissect_sdjwt(s: str) -> dict:
    parts = s.split("~")
    iss = parts[0].split(".")
    kb = parts[-1].split(".") if parts[-1] else None
    return {"issuer_jwt_header": json.loads(b64u_dec(iss[0])),
            "issuer_jwt_payload": json.loads(b64u_dec(iss[1])),
            "disclosures": [json.loads(b64u_dec(d)) for d in parts[1:-1]],
            "kb_jwt_header": json.loads(b64u_dec(kb[0])) if kb else None,
            "kb_jwt_payload": json.loads(b64u_dec(kb[1])) if kb else None}


class Pki:
    """Synthetic reader CA, request-object leaf and SD-JWT issuer, fresh per run."""

    def __init__(self, leaf_sans):
        ca_cn = "Synthetic Lab Reader CA"
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca = make_cert(ca_cn, self.ca_key, ca_cn, self.ca_key, True)
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        self.leaf = make_cert(leaf_sans[0], self.leaf_key, ca_cn, self.ca_key, False, sans=leaf_sans)
        self.tls_key = ec.generate_private_key(ec.SECP256R1())
        self.tls = make_cert(HOST_ALIAS, self.tls_key, ca_cn, self.ca_key, False, sans=(HOST_ALIAS, "localhost"))
        self.iss_key = ec.generate_private_key(ec.SECP256R1())
        self.iss_cert = make_cert("Synthetic Lab Issuer", self.iss_key, ca_cn, self.ca_key, False)

    def leaf_der(self):
        return self.leaf.public_bytes(serialization.Encoding.DER)


SESSIONS: dict = {}
CAPTURES: list = []
LOCK = threading.Lock()


class TlsThreadingServer(http.server.ThreadingHTTPServer):
    """TLS server whose handshake runs in the per-connection worker thread, under a deadline.

    Wrapping the listening socket would make accept() do the handshake on the single accept
    loop, so one stalled peer would block every other connection.
    """

    def __init__(self, address, handler, ssl_context):
        super().__init__(address, handler)
        self.ssl_context = ssl_context

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(CONNECTION_TIMEOUT_SECONDS)
        return self.ssl_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr


class Handler(http.server.BaseHTTPRequestHandler):
    timeout = CONNECTION_TIMEOUT_SECONDS

    def setup(self):
        # Runs in the worker thread; the socket deadline set in get_request bounds the handshake.
        self.request.do_handshake()
        super().setup()

    def log_message(self, *args):
        pass

    def _send(self, code, body: bytes, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        sess = SESSIONS.get(self.path.rsplit("/", 1)[-1])
        if not (self.path.startswith("/request/") and sess):
            self._send(404, b"not found", "text/plain")
            return
        with LOCK:
            sess["request_fetches"] = sess.get("request_fetches", 0) + 1
            sess["request_fetch_headers"] = dict(self.headers)
        self._send(200, sess["request_object"].encode(), "application/oauth-authz-req+jwt")

    def do_POST(self):
        sid = self.path.rsplit("/", 1)[-1]
        sess = SESSIONS.get(sid)
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        if not (self.path.startswith("/response/") and sess):
            self._send(404, b"not found", "text/plain")
            return
        form = urllib.parse.parse_qs(raw, keep_blank_values=True)
        cap = {"module": sess["module"], "content_type": self.headers.get("Content-Type"),
               "form_keys": sorted(form), "headers": dict(self.headers)}
        try:
            hdr, pt = decrypt_ecdh_es(form["response"][0], sess["enc_key"])
            payload = json.loads(pt)
            cap.update(jwe_protected_header=hdr, response_keys=sorted(payload),
                       state_matches=payload.get("state") == sess["state"],
                       credential={k: [dissect_sdjwt(c) for c in v] for k, v in payload.get("vp_token", {}).items()})
        except (KeyError, ValueError) as e:  # observation only
            cap["decrypt_error"] = repr(e)
        with LOCK:
            CAPTURES.append(cap)
        if any(t in sess["module"] for t in NEGATIVE):
            self._send(400, b'{"error":"invalid_request"}', "application/json")
        elif sess["with_redirect_uri"]:
            body = {"redirect_uri": f"https://{HOST_ALIAS}:{STUB_PORT}/done/{sid}"}
            self._send(200, json.dumps(body).encode(), "application/json")
        else:
            self._send(200, b"{}", "application/json")


def api(method, path, body=None, ctype="application/json"):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    headers = {"Content-Type": ctype} if data is not None else {}
    req = urllib.request.Request(SUITE + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, context=CTX, timeout=WAIT_MS / 1000 + CLIENT_TIMEOUT_SLACK_SECONDS) as r:
        txt = r.read().decode()
        return json.loads(txt) if txt else None


def wait_state(tid, states):
    for _ in range(MAX_WAITS):
        r = api("GET", f"/api/runner/{tid}/wait-state?states={states}&timeoutMs={WAIT_MS}")
        if r and "state" in r:
            return r["state"]
    return None


def request_object(pki, sid, nonce, state, enc_pub_jwk, client_id):
    now = int(time.time())
    claims = {
        "client_id": client_id,
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "response_uri": f"https://{HOST_ALIAS}:{STUB_PORT}/response/{sid}",
        "nonce": nonce,
        "state": state,
        "aud": "https://self-issued.me/v2",
        "iat": now,
        "exp": now + REQUEST_OBJECT_TTL_SECONDS,
        "dcql_query": {"credentials": [{
            "id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]},
            "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}, {"path": ["birthdate"]}]}]},
        "client_metadata": {
            "jwks": {"keys": [enc_pub_jwk]},
            "vp_formats_supported": {"dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"]}},
            "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"],
        },
    }
    header = {"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": [base64.b64encode(pki.leaf_der()).decode()]}
    return sign_jwt(pki.leaf_key, header, claims)


def enc_key_pair():
    key = ec.generate_private_key(ec.SECP256R1())
    return key, {**jwk_pub(key), "kid": secrets.token_urlsafe(KID_BYTES), "alg": "ECDH-ES", "use": "enc"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", choices=("plain", "haip"), required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--san-mismatch", action="store_true")
    ap.add_argument("--reuse-enc-key", action="store_true")
    ap.add_argument("--no-redirect-uri", action="store_true")
    ap.add_argument("modules", nargs="+")
    args = ap.parse_args()
    # Each run gets its own directory, as scripts/bench.sh does: a rerun must not overwrite
    # results.json or leave stale module logs from an earlier run next to the new ones.
    if os.path.exists(args.out) and (not os.path.isdir(args.out) or os.listdir(args.out)):
        ap.exit(2, f"--out {args.out} already exists and is not an empty directory; pick a new run directory\n")
    os.makedirs(args.out, exist_ok=True)

    haip = args.plan == "haip"
    pki = Pki((MISMATCHED_SAN,) if args.san_mismatch else (HOST_ALIAS, "localhost"))
    client_id = (f"x509_hash:{b64u(hashlib.sha256(pki.leaf_der()).digest())}" if haip
                 else f"x509_san_dns:{HOST_ALIAS}")

    tls_dir = os.path.join(args.out, "tls")
    os.makedirs(tls_dir, exist_ok=True)
    cert_path, key_path = os.path.join(tls_dir, "cert.pem"), os.path.join(tls_dir, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(pki.tls.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(pki.tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert_path, key_path)
    srv = TlsThreadingServer(("127.0.0.1", STUB_PORT), Handler, sctx)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    config = {"alias": f"standin-{args.plan}-{secrets.token_hex(ALIAS_SUFFIX_BYTES)}",
              "description": "suite-observation stand-in (not a verifier), synthetic data",
              "client": {"request_object_trust_anchor_pem": pki.ca.public_bytes(serialization.Encoding.PEM).decode()},
              "credential": {"signing_jwk": {**jwk_priv(pki.iss_key), "alg": "ES256", "x5c": [
                  base64.b64encode(pki.iss_cert.public_bytes(serialization.Encoding.DER)).decode()]}}}
    if haip:
        plan_name = "oid4vp-1final-verifier-haip-test-plan"
        variant = {"credential_format": "sd_jwt_vc", "response_mode": "direct_post.jwt"}
    else:
        plan_name = "oid4vp-1final-verifier-test-plan"
        variant = {"vp_profile": "plain_vp", "credential_format": "sd_jwt_vc", "client_id_prefix": "x509_san_dns",
                   "request_method": "request_uri_signed", "response_mode": "direct_post.jwt"}
        config["client"]["client_id"] = HOST_ALIAS
    q = urllib.parse.urlencode({"planName": plan_name, "variant": json.dumps(variant)})
    plan_id = api("POST", f"/api/plan?{q}", config)["id"]
    results = {"plan_id": plan_id, "plan": plan_name, "variant": variant, "client_id": client_id,
               "experiments": {k: getattr(args, k) for k in ("san_mismatch", "reuse_enc_key", "no_redirect_uri")},
               "leaf_sans": list(pki.leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                                 .value.get_values_for_type(x509.DNSName)),
               "modules": {}}
    shared_key = enc_key_pair()

    for module in args.modules:
        tid = api("POST", "/api/runner?" + urllib.parse.urlencode({"test": module, "plan": plan_id}))["id"]
        wait_state(tid, "WAITING,FINISHED,INTERRUPTED")
        authz = api("GET", f"/api/runner/{tid}")["exposed"]["authorization_endpoint"]
        sid = secrets.token_urlsafe(NONCE_BYTES)
        enc_key, enc_pub = shared_key if args.reuse_enc_key else enc_key_pair()
        state = secrets.token_urlsafe(NONCE_BYTES)
        SESSIONS[sid] = {"module": module, "enc_key": enc_key, "state": state,
                         "with_redirect_uri": haip and not args.no_redirect_uri,
                         "request_object": request_object(pki, sid, secrets.token_urlsafe(NONCE_BYTES),
                                                          state, enc_pub, client_id)}
        query = urllib.parse.urlencode({"client_id": client_id,
                                        "request_uri": f"https://{HOST_ALIAS}:{STUB_PORT}/request/{sid}"})
        t0 = time.time()
        with urllib.request.urlopen(f"{authz}?{query}", context=CTX,
                                    timeout=WAIT_MS / 1000 + CLIENT_TIMEOUT_SLACK_SECONDS) as r:
            authz_status = r.status
        authz_seconds = round(time.time() - t0, 2)
        st = wait_state(tid, "WAITING,FINISHED,INTERRUPTED")
        uploaded = None
        if st == "WAITING" and api("GET", f"/api/runner/{tid}").get("browser", {}).get("uploadsRequired", 0) > 0:
            uploaded = next(e["upload"] for e in api("GET", f"/api/log/{tid}") if "upload" in e)
            api("POST", f"/api/log/{tid}/images/{uploaded}", f"data:image/png;base64,{PNG_1X1}".encode(), "text/plain")
            st = wait_state(tid, "FINISHED,INTERRUPTED")
        info = api("GET", f"/api/info/{tid}")
        log = api("GET", f"/api/log/{tid}")
        findings = [{"src": e.get("src"), "msg": e.get("msg"), "result": e.get("result")}
                    for e in log if e.get("result") in ("FAILURE", "WARNING")]
        results["modules"][module] = {"test_id": tid, "authorization_endpoint": authz, "authz_get_status": authz_status,
                                      "authz_get_seconds": authz_seconds, "final_state": st,
                                      "status": info.get("status"), "result": info.get("result"),
                                      "uploaded_placeholder": uploaded,
                                      "request_fetches": SESSIONS[sid].get("request_fetches"),
                                      "request_fetch_headers": SESSIONS[sid].get("request_fetch_headers"),
                                      "failures_and_warnings": findings}
        with open(os.path.join(args.out, f"log-{module}.json"), "w") as f:
            json.dump(log, f, indent=1)
        print(module, info.get("status"), info.get("result"),
              [(x["src"], x["result"]) for x in findings], flush=True)

    results["captures"] = CAPTURES
    with open(os.path.join(args.out, "results.json"), "w") as f:
        json.dump(results, f, indent=1)
    srv.shutdown()


if __name__ == "__main__":
    main()
