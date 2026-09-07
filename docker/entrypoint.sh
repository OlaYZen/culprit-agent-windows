#!/bin/sh
# Turn the container's environment into the agent's CLI arguments, so the image
# is configured the Docker way (env vars) without changing agent.py.
set -e

# The token may be given directly (CULPRIT_TOKEN) or read from a file
# (CULPRIT_TOKEN_FILE) — the Docker-secrets / shared-volume pattern. The demo
# host enrolls this agent at startup and writes the token to a shared volume,
# so wait briefly for it to appear.
if [ -z "${CULPRIT_TOKEN:-}" ] && [ -n "${CULPRIT_TOKEN_FILE:-}" ]; then
  i=0
  while [ ! -s "$CULPRIT_TOKEN_FILE" ] && [ "$i" -lt 90 ]; do
    sleep 1
    i=$((i + 1))
  done
  CULPRIT_TOKEN="$(cat "$CULPRIT_TOKEN_FILE" 2>/dev/null || true)"
fi

if [ -z "${CULPRIT_HOST:-}" ] || [ -z "${CULPRIT_TOKEN:-}" ]; then
  echo "error: set CULPRIT_HOST (e.g. http://host:8787) and CULPRIT_TOKEN" >&2
  echo "       (the agent token 'name.secret' from the host's Nodes view), or" >&2
  echo "       CULPRIT_TOKEN_FILE pointing at a file that holds the token" >&2
  exit 1
fi

set -- python -m culprit.agent --host "$CULPRIT_HOST" --token "$CULPRIT_TOKEN"

[ -n "${CULPRIT_INTERVAL:-}" ]  && set -- "$@" --interval "$CULPRIT_INTERVAL"
[ -n "${CULPRIT_LOG_LEVEL:-}" ] && set -- "$@" --log-level "$CULPRIT_LOG_LEVEL"
case "${CULPRIT_INSECURE:-}" in
  1|true|TRUE|yes|on) set -- "$@" --insecure ;;
esac

exec "$@"
