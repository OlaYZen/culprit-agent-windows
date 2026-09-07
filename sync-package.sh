#!/usr/bin/env bash
# Refresh this bundle's culprit/ from the host repo's package, so the
# self-contained agent stays in sync after edits to shared code (collectors,
# sampler, db, state, config, linux, util). Host-only modules
# (main.py/auth.py/nodes.py/__main__.py) are never copied; the agent-only
# agent.py and updater.py are preserved.
#
# The host repo (github.com/OlaYZen/culprit) is expected as a SIBLING checkout,
# so its package is ../culprit/culprit. Override with CULPRIT_SRC=/path/to/culprit
# (the package dir) if it lives elsewhere. Run from anywhere.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
src="${CULPRIT_SRC:-$here/../culprit/culprit}"

# Guard against the classic footgun: pointing at the repo ROOT instead of the
# package would rsync the whole host repo (web/, tools/, data/, .git) into
# culprit/. A real package has collectors/ and sampler.py at its top.
if [ ! -d "$src/collectors" ] || [ ! -f "$src/sampler.py" ]; then
    echo "error: '$src' is not the culprit package (no collectors/ + sampler.py)." >&2
    echo "       Clone github.com/OlaYZen/culprit next to this repo, or set" >&2
    echo "       CULPRIT_SRC=/path/to/culprit/culprit" >&2
    exit 1
fi

rsync -a --delete \
  --exclude='main.py' --exclude='auth.py' --exclude='nodes.py' \
  --exclude='__main__.py' --exclude='agent.py' --exclude='updater.py' \
  --exclude='expect.py' --exclude='notify.py' --exclude='verdict.py' \
  --exclude='coroner.py' --exclude='fleetmap.py' --exclude='portnames.py' --exclude='changelog.py' \
  --exclude='__init__.py' \
  --exclude='__pycache__' --exclude='*.pyc' \
  "$src/" "$here/culprit/"
echo "synced $src -> $here/culprit (agent.py/updater.py preserved, host-only files skipped)"
