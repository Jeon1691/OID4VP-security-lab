#!/usr/bin/env bash
# Reachability probe for the self-hosted OIDF conformance suite (tools/oidf-suite/README.md).
#
# Starts a throwaway HTTPS server bound to host 127.0.0.1 with a fresh self-signed certificate,
# then asks the running suite server container to fetch it through each Docker host alias.
# Prints one line per alias: "<alias> reachable" or "<alias> unreachable". The server and its
# key are removed on exit. Nothing leaves this machine.
#
# Usage: scripts/oidf_suite_probe.sh [SERVER_CONTAINER]
set -euo pipefail

CONTAINER="${1:-oidf-suite-server-1}"
DOCKER=(docker --context "${DOCKER_CONTEXT:-orbstack}")
# Unprivileged port, outside the suite's own 8443/8444; override if it is taken.
PROBE_PORT="${PROBE_PORT:-18443}"
# The certificate only has to outlive this run.
CERT_DAYS=1
# Seconds to wait for the listener to come up, and for each fetch from the container.
LISTEN_WAIT_SECONDS=10
FETCH_TIMEOUT_SECONDS=5
# Host aliases Docker Desktop / OrbStack inject into containers.
ALIASES=(host.docker.internal host.orb.internal)
MARKER="oidf-suite-probe-ok"

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# True if the body served at URL (fetched by the given curl command) contains MARKER. The body is
# captured first so that pipefail cannot turn an early-exiting grep into a false negative.
serves_marker() {
  local body
  body="$("$@" 2>/dev/null || true)"
  [[ "$body" == *"$MARKER"* ]]
}

SANS="DNS:localhost"
for alias in "${ALIASES[@]}"; do
  SANS+=",DNS:${alias}"
done

openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days "$CERT_DAYS" \
  -subj "/CN=localhost" -addext "subjectAltName=${SANS}" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
mkdir "$WORK/www"
printf '%s\n' "$MARKER" >"$WORK/www/index.html"

python3 -I - "$WORK/cert.pem" "$WORK/key.pem" "$WORK/www" "$PROBE_PORT" <<'PY' &
import functools, http.server, ssl, sys
cert, key, root, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=root)
httpd = http.server.HTTPServer(("127.0.0.1", port), handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
SERVER_PID=$!

for _ in $(seq 1 "$LISTEN_WAIT_SECONDS"); do
  serves_marker curl -sk "https://127.0.0.1:${PROBE_PORT}/" && break
  sleep 1
done
serves_marker curl -sk "https://127.0.0.1:${PROBE_PORT}/" || {
  echo "probe server did not come up on 127.0.0.1:${PROBE_PORT}" >&2
  exit 1
}
echo "probe server listening on 127.0.0.1:${PROBE_PORT} only"

for alias in "${ALIASES[@]}"; do
  # -k: the suite's own HTTP client trusts all certificates (AbstractCondition trust-all manager).
  if serves_marker "${DOCKER[@]}" exec "$CONTAINER" curl -sk --max-time "$FETCH_TIMEOUT_SECONDS" \
    "https://${alias}:${PROBE_PORT}/"; then
    echo "${alias} reachable"
  else
    echo "${alias} unreachable"
  fi
done
