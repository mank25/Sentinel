#!/usr/bin/env bash
#
# Start the whole Sentinel stack inside one container.
#
#   TrueForge      :8790   the agent harness (npm @truefoundry/trueforge)
#   Sentinel MCP   :8791   the read-only evidence tools, over authenticated HTTP
#   Console        $PORT   the only thing published to the outside world
#
# Only the console is exposed. TrueForge holds the model-provider API key and
# has no authentication of its own, and the MCP server serves login histories,
# so both stay on loopback where nothing outside the container can reach them.
#
set -euo pipefail

PORT="${PORT:-7860}"
# "localhost", not "127.0.0.1": TrueForge binds whatever localhost resolves
# to, and in a Debian container that is ::1 (IPv6) only. Dialling 127.0.0.1
# gets connection-refused against a server that is running perfectly.
export TRUEFORGE_BASE_URL="${TRUEFORGE_BASE_URL:-http://localhost:8790}"
export SENTINEL_MCP_URL="${SENTINEL_MCP_URL:-http://127.0.0.1:8791/mcp}"
export SENTINEL_MCP_HOST="${SENTINEL_MCP_HOST:-127.0.0.1}"
export TRUEFORGE_MODEL="${TRUEFORGE_MODEL:-google-gemini/gemini-3-6-flash}"

# The two services need to agree on a bearer token. Generating it here means
# a deployment needs no secret for it -- it never leaves the container.
export SENTINEL_MCP_TOKEN="${SENTINEL_MCP_TOKEN:-$(openssl rand -hex 24)}"

# The console is about to be reachable from the internet, and every one of its
# routes can start an investigation or approve containment. Requiring a token
# is not optional here; generate one if the operator did not supply one, and
# print it so they can build the URL.
if [ -z "${SENTINEL_CONSOLE_TOKEN:-}" ]; then
  export SENTINEL_CONSOLE_TOKEN="$(openssl rand -hex 24)"
  echo "=================================================================="
  echo "  No SENTINEL_CONSOLE_TOKEN was set, so one was generated."
  echo "  It changes on every restart. Set it as a secret to pin it."
  echo "=================================================================="
fi

log() { echo "[entrypoint] $*"; }

# Reap children if the container is stopped, so a restart is clean.
cleanup() { log "shutting down"; kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

log "starting TrueForge on 8790"
# PORT is the console's port and TrueForge reads it as its own default, so
# unset it for this child rather than relying on --port to win.
( unset PORT; exec trueforge --port 8790 ) > /tmp/trueforge.log 2>&1 &

log "seeding the demo incident"
python3 data/init_db.py --reset

log "starting the Sentinel MCP server on 8791"
python3 mcp/sentinel_mcp/http_server.py > /tmp/mcp.log 2>&1 &

# Blocks until TrueForge answers, then configures the model provider from
# $GEMINI_API_KEY. Exits with an actionable message if the key is missing.
python3 deploy/bootstrap.py

log "readiness"
python3 -m sentinel.preflight || {
  log "readiness checks failed -- see the arrows above"
  echo "--- trueforge.log ---"; tail -30 /tmp/trueforge.log || true
  echo "--- mcp.log ---";       tail -30 /tmp/mcp.log || true
  exit 1
}

echo
echo "=================================================================="
echo "  Sentinel console is live on port ${PORT}"
echo "  Open:  https://<your-host>/?token=${SENTINEL_CONSOLE_TOKEN}"
echo "=================================================================="
echo

# Foreground: this process is the container's lifetime.
exec python3 -m ui.server \
  --host 0.0.0.0 \
  --port "${PORT}" \
  --token "${SENTINEL_CONSOLE_TOKEN}"
