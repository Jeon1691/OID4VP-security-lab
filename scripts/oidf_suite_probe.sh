#!/usr/bin/env bash
# Reachability probe for the self-hosted OIDF conformance suite (tools/oidf-suite/README.md).
#
# Starts a throwaway HTTPS server bound to host 127.0.0.1 with a fresh self-signed certificate,
# then asks the running suite server container to fetch it through each Docker host alias.
# Prints one line per alias: "<alias> reachable" or "<alias> unreachable". The server and its
# key are removed on exit. Nothing leaves this machine.
#
# Exit status: 0 every alias reachable, 1 at least one alias unreachable,
#              2 the probe itself could not run (bad PROBE_PORT, no curl in the container,
#                probe server did not start).
#
# Usage: scripts/oidf_suite_probe.sh [SERVER_CONTAINER]
set -euo pipefail

CONTAINER="${1:-oidf-suite-server-1}"
DOCKER=(docker --context "${DOCKER_CONTEXT:-orbstack}")
# Unprivileged port, outside the suite's own 8443/8444; override if it is taken.
PROBE_PORT="${PROBE_PORT:-18443}"
# The certificate only has to outlive this run.
CERT_DAYS=1
# Number of polls, and the pause between them, while the probe server starts (10 s in all).
LISTEN_POLLS=10
POLL_INTERVAL_SECONDS=1
# Per-fetch limit for the request made from inside the container.
FETCH_TIMEOUT_SECONDS=5
# Host aliases Docker Desktop / OrbStack inject into containers.
ALIASES=(host.docker.internal host.orb.internal)
MARKER="oidf-suite-probe-ok"
EXIT_UNREACHABLE=1
EXIT_PROBE_ERROR=2

if [[ ! "$PROBE_PORT" =~ ^[0-9]+$ ]]; then
  echo "PROBE_PORT must be a port number, got '${PROBE_PORT}'" >&2
  exit "$EXIT_PROBE_ERROR"
fi

if ! "${DOCKER[@]}" exec "$CONTAINER" curl --version >/dev/null; then
  echo "cannot run curl in container '${CONTAINER}' (is the suite up?)" >&2
  exit "$EXIT_PROBE_ERROR"
fi

WORK="$(mktemp -d)"
SERVER_PID=""
# shellcheck disable=SC2329  # invoked by the EXIT trap below
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# True if the output of the given command contains MARKER. The output is captured first, so
# pipefail cannot turn an early-exiting grep into a false negative. The command's stderr goes to
# $WORK/fetch.err so that a failure can be shown rather than silently dropped.
serves_marker() {
  local body
  body="$("$@" 2>"$WORK/fetch.err" || true)"
  [[ "$body" == *"$MARKER"* ]]
}

SANS="DNS:localhost"
for alias in "${ALIASES[@]}"; do
  SANS+=",DNS:${alias}"
done

openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days "$CERT_DAYS" \
  -subj "/CN=localhost" -addext "subjectAltName=${SANS}" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>"$WORK/openssl.err" || {
  cat "$WORK/openssl.err" >&2
  exit "$EXIT_PROBE_ERROR"
}
mkdir "$WORK/www"
printf '%s\n' "$MARKER" >"$WORK/www/index.html"

# The server's access log goes to $WORK/server.log and is printed if the probe fails.
python3 -I - "$WORK/cert.pem" "$WORK/key.pem" "$WORK/www" "$PROBE_PORT" 2>"$WORK/server.log" <<'PY' &
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

up=false
for _ in $(seq 1 "$LISTEN_POLLS"); do
  if serves_marker curl -sk "https://127.0.0.1:${PROBE_PORT}/"; then
    up=true
    break
  fi
  sleep "$POLL_INTERVAL_SECONDS"
done
if [[ "$up" != true ]]; then
  echo "probe server did not come up on 127.0.0.1:${PROBE_PORT}" >&2
  cat "$WORK/server.log" >&2
  exit "$EXIT_PROBE_ERROR"
fi
echo "probe server listening on 127.0.0.1:${PROBE_PORT} only"

status=0
for alias in "${ALIASES[@]}"; do
  # -k: the suite's own HTTP client trusts all certificates (AbstractCondition trust-all manager).
  if serves_marker "${DOCKER[@]}" exec "$CONTAINER" curl -sSk --max-time "$FETCH_TIMEOUT_SECONDS" \
    "https://${alias}:${PROBE_PORT}/"; then
    echo "${alias} reachable"
  else
    echo "${alias} unreachable"
    sed "s/^/  ${alias}: /" "$WORK/fetch.err" >&2
    status="$EXIT_UNREACHABLE"
  fi
done
exit "$status"
