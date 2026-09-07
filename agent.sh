#!/usr/bin/env bash
# culprit agent. Three steps, always in this order:
#   1. install    -- create the venv (psutil only)
#   2. configure  -- the host URL and this node's token, asked for interactively
#                    and saved to agent.json (chmod 600), so nothing is typed again
#
# Nothing is written into this checkout. The venv, the config and the flight
# recorder live in the running user's XDG directories (root's own under sudo):
#   venv      ~/.local/share/culprit-agent/venv
#   config    ~/.config/culprit-agent/agent.json
#   recorder  ~/.local/share/culprit-agent/flight-recorder.json.gz
# so `git pull` keeps working for whoever cloned it, sudo or not.
#   3. run it     -- either set it up as a systemd service (default, it asks),
#                    or with --run start it here in the foreground
#
#   ./agent.sh                     # install, ask for host + token if not saved,
#                                  #   then OFFER a systemd service (start on boot,
#                                  #   auto-restart). Run under sudo for a SYSTEM
#                                  #   service as root (full process attribution);
#                                  #   without sudo it is a USER service.
#   ./agent.sh --run               # install if needed, then run HERE (foreground).
#                                  #   Needs a saved config, or the arguments below
#   ./agent.sh --run <url> <token> # ...for example with them given here
#   ./agent.sh --configure         # (re)enter host + token, save, nothing else
#   ./agent.sh --install-only      # venv only -- no prompts, no run (CI / images)
#
# The token comes from the host: Nodes > "Generate token" in the dashboard, or
# `python -m culprit agents add <name>` on the host machine. It looks like
# <name>.<secret>; the name before the dot is how this node appears in the fleet.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$(pwd)"
PYTHON="${PYTHON:-python3}"

# ---- where the agent keeps its files: never in the checkout -----------------
# The home comes from the password database for the *effective* user, not
# $HOME: sudo may or may not reset $HOME, the system unit sets none, and both
# must land on the same files. XDG variables are honoured when set. The
# resolved paths are exported so the Python side (and the generated unit)
# agree with this script exactly.
OWN_HOME="$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f6)"
OWN_HOME="${OWN_HOME:-$HOME}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$OWN_HOME/.config}/culprit-agent"
DATA_DIR="${CULPRIT_AGENT_DATA:-${XDG_DATA_HOME:-$OWN_HOME/.local/share}/culprit-agent}"
VENV="$DATA_DIR/venv"
export CULPRIT_AGENT_CONFIG="${CULPRIT_AGENT_CONFIG:-$CONFIG_DIR/agent.json}"
export CULPRIT_AGENT_DATA="$DATA_DIR"
PY="$VENV/bin/python"

usage() {
    cat <<'USAGE'
culprit agent -- install, save the host + token, then run it as a systemd
service or in the foreground. It samples this machine and pushes reports to
the culprit host; it has no dashboard and opens no ports.

Usage:
  ./agent.sh                     install if needed, ask for the host URL and
                                 token if none is saved, then offer to set up a
                                 systemd service (start on boot, auto-restart)
  ./agent.sh --run [url token]   install if needed, then run here in the
                                 foreground (no service prompt)
  ./agent.sh --configure         (re)enter the host URL and token, save, exit
  ./agent.sh --install-only      install only -- no prompts, no run (CI)
  ./agent.sh -h, --help          show this help

Host and token can also be given on the command line, positionally or as
flags, in any mode; they are saved to ~/.config/culprit-agent/agent.json
either way (root's own ~ under sudo). Nothing is written into this checkout:
the venv and the flight recorder live in ~/.local/share/culprit-agent.
  ./agent.sh http://192.168.1.1:8787 web-01.<secret>
  ./agent.sh --host https://hub:8787 --token web-01.<secret> --insecure

Options passed through to the agent in --run mode: --interval N (seconds
between reports), --log-level debug|info|warning|error, --insecure (do not
verify the host's TLS certificate; saved).

Privilege: run it with sudo and the service is a SYSTEM unit running as root,
which is what reads other users' processes, descriptors and ports. Without
sudo it is a USER unit that sees your own processes fully and others partly.
USAGE
}

# ---- mode + config arguments + passthrough ------------------------------------
MODE="service"
HOST_URL=""
TOKEN=""
INSECURE=""
INTERVAL=""
ARGS=()
expect=""
for arg in "$@"; do
    if [ -n "$expect" ]; then
        case "$expect" in
            host) HOST_URL="$arg" ;;
            token) TOKEN="$arg" ;;
            interval) INTERVAL="$arg" ;;
            passthrough) ARGS+=("$arg") ;;
        esac
        expect=""
        continue
    fi
    case "$arg" in
        -h|--help)               usage; exit 0 ;;
        --run|run)               MODE="run" ;;
        --configure|configure)   MODE="configure" ;;
        --install-only|--no-run) MODE="install" ;;
        --insecure)              INSECURE="yes" ;;
        --host)                  expect="host" ;;
        --host=*)                HOST_URL="${arg#--host=}" ;;
        --token)                 expect="token" ;;
        --token=*)               TOKEN="${arg#--token=}" ;;
        --interval)              expect="interval" ;;
        --interval=*)            INTERVAL="${arg#--interval=}" ;;
        --log-level)             ARGS+=("$arg"); expect="passthrough" ;;
        http://*|https://*)      HOST_URL="$arg" ;;
        *.*)                     TOKEN="$arg" ;;   # <name>.<secret>
        *)                       ARGS+=("$arg") ;;
    esac
done
if [ -n "$expect" ]; then
    echo "error: --$expect needs a value" >&2
    exit 2
fi
if [ -n "$HOST_URL" ] && [[ "$HOST_URL" != http://* && "$HOST_URL" != https://* ]]; then
    echo "error: the host must be the culprit host's URL, e.g. http://192.168.1.1:8787" >&2
    echo "       (this node's name is the part of the token before the dot)" >&2
    exit 2
fi
if [ -n "$TOKEN" ] && [[ "$TOKEN" != ?*.?* ]]; then
    echo "error: a token looks like <name>.<secret> (Nodes > Generate token on the host)" >&2
    exit 2
fi

# ==============================================================================
# 1. INSTALL  (every mode needs the venv + psutil)
# ==============================================================================
if ! command -v "$PYTHON" >/dev/null; then
    echo "error: python3 not found. Install it (e.g. sudo apt install python3-venv)." >&2
    exit 1
fi
# The agent is psutil + stdlib and runs on 3.10 (Ubuntu 22.04's python3); the
# host's 3.11 floor is FastAPI's, not ours.
if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "error: Python 3.10+ required, found $("$PYTHON" --version)." >&2
    echo "       (PYTHON=/path/to/python3.10 ./agent.sh to use another interpreter)" >&2
    exit 1
fi

# Bring the venv to a known-good state: it exists AND psutil imports. This is
# deliberately not a "does the .venv folder exist" check. A venv can be left
# half-built by an interrupted first run, by `python -m venv` failing on a host
# that lacks python3-venv/ensurepip (it still leaves a bin/python behind, with
# no working pip), or by being copied in from another machine -- and trusting
# the folder then skips setup forever and fails at runtime with
# `ModuleNotFoundError: No module named 'psutil'`. So: try to install the deps;
# if that cannot succeed, rebuild the venv from scratch once; only then give up.
ensure_deps() {
    "$PY" -c 'import psutil' 2>/dev/null && return 0
    echo "installing agent dependencies (psutil)..."
    "$PY" -m pip install --quiet --upgrade pip 2>/dev/null || return 1
    "$PY" -m pip install --quiet -r requirements-agent.txt 2>/dev/null || return 1
    "$PY" -c 'import psutil' 2>/dev/null
}
make_venv() {
    echo "creating agent virtual environment in $VENV (psutil only)..."
    mkdir -p "$DATA_DIR" && chmod 700 "$DATA_DIR" 2>/dev/null || true
    "$PYTHON" -m venv "$VENV"
}
venv_help() {
    echo "error: venv creation failed -- on Debian/Ubuntu: sudo apt install python3-venv" >&2
}

if [ ! -x "$PY" ]; then
    make_venv || { venv_help; exit 1; }
fi
if ! ensure_deps; then
    echo "existing venv is incomplete; rebuilding it from scratch..."
    rm -rf "$VENV"
    make_venv || { venv_help; exit 1; }
    ensure_deps || {
        echo "error: could not install psutil into the agent venv." >&2
        echo "       Check network access (pip needs to reach PyPI), then rerun." >&2
        echo "       Offline hosts: 'sudo apt install python3-psutil' and recreate" >&2
        echo "       the venv with '$PYTHON -m venv --system-site-packages $VENV'." >&2
        exit 1
    }
fi
if ! "$PY" -c 'import culprit.agent' 2>/dev/null; then
    echo "error: the culprit package in this folder does not import; the checkout is incomplete." >&2
    exit 1
fi

# ---- leftovers from earlier versions, which wrote into the checkout ---------
# An old .venv here is no longer used; agent.json and data/ are moved to
# their XDG homes by the Python side on first load. Under sudo, an earlier
# version also made the whole checkout root's, which broke `git pull` for
# the person who cloned it: that is repaired here, once, and never redone.
if [ -d "$HERE/.venv" ]; then
    if rm -rf "$HERE/.venv" 2>/dev/null; then
        echo "  removed the old .venv from the checkout (the venv now lives in $VENV)"
    else
        echo "  note: the old .venv in the checkout is no longer used but could not be removed"
        echo "        (owned by someone else); remove it with: sudo rm -rf $HERE/.venv"
    fi
fi
"$PY" - <<'EOF'
from culprit.agent import migrate_legacy_files
migrate_legacy_files()       # moves a legacy agent.json / data/ out of the checkout
EOF
[ -d "$HERE/data" ] && rmdir "$HERE/data" 2>/dev/null || true
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] \
        && [ "$(stat -c %U "$HERE/.git" 2>/dev/null)" = "root" ]; then
    chown -R "$SUDO_USER:$(id -gn "$SUDO_USER")" "$HERE" 2>/dev/null || true
    echo "  repaired: an earlier version had made this checkout root's; it is $SUDO_USER's again"
    echo "            (git pull works as $SUDO_USER now; a sudo git pull would make it root's again)"
fi

# ==============================================================================
# 2. CONFIGURE  (host URL + token, saved to agent.json)
# ==============================================================================
configured() {
    "$PY" - <<'EOF'
import sys
from culprit.agent import load_agent_config
cfg = load_agent_config()
sys.exit(0 if cfg.get("host_url") and cfg.get("token") else 1)
EOF
}
show_config() {
    "$PY" - <<'EOF'
from culprit.agent import CONFIG_PATH, load_agent_config
cfg = load_agent_config()
name = str(cfg.get("token", "")).partition(".")[0] or "?"
tls = "" if cfg.get("verify_tls", True) else " (TLS verification off)"
print(f"  node '{name}' -> {cfg.get('host_url')}{tls}   [{CONFIG_PATH}]")
EOF
}
save_config() {   # url token insecure interval
    "$PY" - "$1" "$2" "$3" "$4" <<'EOF'
import sys
from culprit.agent import CONFIG_PATH, load_agent_config, save_agent_config
url, token, insecure, interval = sys.argv[1:5]
cfg = load_agent_config()
if url:
    cfg["host_url"] = url.rstrip("/")
if token:
    cfg["token"] = token
if insecure:
    cfg["verify_tls"] = False
if interval:
    cfg["report_interval"] = max(0.5, float(interval))
save_agent_config(cfg)
print(f"  saved {CONFIG_PATH} (mode 600)")
EOF
}
# Reachability + token check without registering anything: the host validates
# the token before it parses the body, so a deliberately invalid body ("[]")
# answers 401 for a bad token and 400 for a good one, and folds nothing in.
check_host() {
    "$PY" - <<'EOF'
import gzip, ssl, sys, urllib.error, urllib.request
from culprit.agent import load_agent_config
cfg = load_agent_config()
url = cfg["host_url"].rstrip("/")
ctx = None
if url.startswith("https") and not cfg.get("verify_tls", True):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    urllib.request.urlopen(url + "/api/healthz", timeout=6, context=ctx).read()
except urllib.error.HTTPError as exc:
    print(f"  host reachable ({url}) but /api/healthz answered {exc.code}; continuing")
except Exception as exc:  # noqa: BLE001
    hint = ""
    if "CERTIFICATE_VERIFY_FAILED" in str(exc):
        hint = " -- a self-signed certificate? rerun with --insecure"
    print(f"  warning: cannot reach {url}: {exc}{hint}")
    print("           (the config is saved anyway; the agent keeps retrying once it runs)")
    sys.exit(0)
request = urllib.request.Request(
    url + "/api/agents/report", data=gzip.compress(b"[]"), method="POST",
    headers={"Authorization": f"Bearer {cfg['token']}",
             "Content-Type": "application/json", "Content-Encoding": "gzip"})
try:
    urllib.request.urlopen(request, timeout=6, context=ctx).read()
    print(f"  host reachable and the token is accepted ({url})")
except urllib.error.HTTPError as exc:
    if exc.code == 401:
        print("  warning: the host REJECTED this token (401). Generate a new one under")
        print("           Nodes on the host and rerun ./agent.sh --configure")
    elif exc.code == 400:
        print(f"  host reachable and the token is accepted ({url})")
    else:
        print(f"  host reachable ({url}); the report endpoint answered {exc.code}")
except Exception as exc:  # noqa: BLE001
    print(f"  warning: {url} answered the health check but not the report endpoint: {exc}")
EOF
}
prompt_config() {
    local url token insecure ans
    echo
    echo "The agent needs to know where the culprit host is and who this node is."
    echo "  Get a token on the host: Nodes > 'Generate token' in the dashboard, or"
    echo "  'python -m culprit agents add <name>'. It looks like <name>.<secret>."
    echo
    while :; do
        read -rp "  Culprit host URL (e.g. http://192.168.1.1:8787): " url || return 1
        url="${url## }"; url="${url%% }"
        [[ "$url" == http://* || "$url" == https://* ]] && break
        echo "  -> the URL must start with http:// or https:// (the name is not the host)"
    done
    while :; do
        read -rp "  Agent token (<name>.<secret>): " token || return 1
        token="${token## }"; token="${token%% }"
        [[ "$token" == ?*.?* ]] && break
        echo "  -> a token looks like <name>.<secret>; paste the whole thing"
    done
    insecure=""
    if [[ "$url" == https://* ]]; then
        read -rp "  Does the host use a self-signed certificate (skip TLS verification)? [y/N] " ans || true
        case "${ans:-n}" in [yY]*) insecure="yes" ;; esac
    fi
    save_config "$url" "$token" "$insecure" ""
    check_host
}

# Anything given on the command line is saved first, in every mode.
if [ -n "$HOST_URL" ] || [ -n "$TOKEN" ] || [ -n "$INSECURE" ] || [ -n "$INTERVAL" ]; then
    if { [ -n "$HOST_URL" ] && [ -z "$TOKEN" ]; } || { [ -z "$HOST_URL" ] && [ -n "$TOKEN" ]; }; then
        if ! configured; then
            echo "error: give both the host URL and the token (or neither, to be asked)." >&2
            exit 2
        fi
    fi
    save_config "$HOST_URL" "$TOKEN" "$INSECURE" "$INTERVAL"
    if [ -n "$HOST_URL" ] || [ -n "$TOKEN" ]; then
        check_host
    fi
fi

if [ "$MODE" = "install" ]; then
    echo
    echo "setup done."
    if configured; then show_config; fi
    echo "  run it here:         ./agent.sh --run"
    echo "  set up as a service: ./agent.sh        (asks for host + token, then enables + starts it)"
    exit 0
fi

if [ "$MODE" = "configure" ]; then
    if [ -z "$HOST_URL" ] && [ -z "$TOKEN" ]; then
        if [ ! -t 0 ]; then
            echo "error: --configure needs a terminal; pass the values instead:" >&2
            echo "       ./agent.sh --configure <url> <token>" >&2
            exit 2
        fi
        prompt_config || exit 1
    fi
    echo
    show_config
    if [ "$(id -u)" -eq 0 ] && systemctl is-active --quiet culprit-agent 2>/dev/null; then
        echo "  the running service picks it up on restart:  sudo systemctl restart culprit-agent"
    elif systemctl --user is-active --quiet culprit-agent 2>/dev/null; then
        echo "  the running service picks it up on restart:  systemctl --user restart culprit-agent"
    fi
    exit 0
fi

# Without a saved config, --run needs the arguments; the default mode asks.
if ! configured; then
    if [ "$MODE" = "run" ]; then
        if [ -t 0 ]; then
            prompt_config || exit 1
        else
            echo "error: no host/token saved. Give them on the command line:" >&2
            echo "       ./agent.sh --run http://<culprit-host>:8787 <name>.<secret>" >&2
            exit 2
        fi
    elif [ -t 0 ]; then
        echo
        read -rp "No host/token saved yet. Enter them now? [Y/n] " reply || true
        case "${reply:-y}" in
            [nN]*)
                echo "  skipped. Without a saved config the agent needs them as arguments:"
                echo "    ./agent.sh --run http://<culprit-host>:8787 <name>.<secret>"
                echo "  or come back with:  ./agent.sh --configure"
                exit 0 ;;
            *) prompt_config || exit 1 ;;
        esac
    else
        echo
        echo "non-interactive shell and no host/token saved -- not prompting."
        echo "  save them:  ./agent.sh --install-only http://<culprit-host>:8787 <name>.<secret>"
        echo "  run it:     ./agent.sh --run"
        exit 0
    fi
fi

# ==============================================================================
# 3a. RUN  -- foreground
# ==============================================================================
if [ "$MODE" = "run" ]; then
    show_config
    exec "$PY" -m culprit.agent "${ARGS[@]+"${ARGS[@]}"}"
fi

# ==============================================================================
# 3b. SERVICE (default) -- ask, then install + enable + start the unit.
#     Root -> a SYSTEM unit (full attribution); otherwise a USER unit.
# ==============================================================================
AS_ROOT=0
[ "$(id -u)" -eq 0 ] && AS_ROOT=1
if [ "$AS_ROOT" -eq 1 ]; then
    UNIT="/etc/systemd/system/culprit-agent.service"
    SYSCTL=(systemctl)
    SCOPE="system service (as root)"
else
    UNIT="$HOME/.config/systemd/user/culprit-agent.service"
    SYSCTL=(systemctl --user)
    SCOPE="user service (as $USER)"
fi

setup_service() {
    local owner_note=""
    if [ "$AS_ROOT" -eq 1 ]; then
        # Root reads every process's descriptors and IO: that is the point
        # of running it this way. Root's files live under root's own home;
        # the checkout stays whoever's it was, root only reads it.
        :
    else
        owner_note="  note: as $USER it sees your own processes fully and other users' partly
        (no per-process IO or descriptor counts for them). Run ./agent.sh under
        sudo instead for a root service with full attribution."
    fi
    mkdir -p "$(dirname "$UNIT")"
    cat > "$UNIT" <<UNIT
[Unit]
Description=culprit monitoring agent (reports to the culprit host)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$HERE
Environment=CULPRIT_AGENT_CONFIG=$CULPRIT_AGENT_CONFIG
Environment=CULPRIT_AGENT_DATA=$CULPRIT_AGENT_DATA
ExecStart=$PY -m culprit.agent
Restart=always
RestartSec=10

[Install]
WantedBy=$([ "$AS_ROOT" -eq 1 ] && echo multi-user.target || echo default.target)
UNIT

    "${SYSCTL[@]}" daemon-reload
    "${SYSCTL[@]}" enable --now culprit-agent
    if [ "$AS_ROOT" -eq 0 ] && ! loginctl enable-linger "$USER" >/dev/null 2>&1; then
        echo "  note: run 'sudo loginctl enable-linger $USER' so it starts on boot / survives logout"
    fi
    echo
    sleep 1
    if "${SYSCTL[@]}" is-active --quiet culprit-agent; then
        echo "  culprit-agent.service is installed and running -- $SCOPE."
    else
        echo "  culprit-agent.service installed but not active -- check: ${SYSCTL[*]} status culprit-agent"
    fi
    show_config
    echo "  manage:  ${SYSCTL[*]} status|restart|stop culprit-agent"
    echo "  logs:    journalctl $([ "$AS_ROOT" -eq 1 ] || echo --user) -u culprit-agent -f"
    [ -z "$owner_note" ] || echo "$owner_note"
}

if [ ! -t 0 ]; then
    echo
    echo "non-interactive shell -- not prompting."
    show_config
    echo "  run it:              ./agent.sh --run"
    echo "  set up the service:  re-run ./agent.sh from a terminal"
    exit 0
fi

echo
show_config
if "${SYSCTL[@]}" is-active --quiet culprit-agent 2>/dev/null; then
    # A service is already running -- default to NO so a stray Enter never
    # restarts it out from under you.
    read -rp "A culprit-agent $SCOPE is already running. Reconfigure and restart it? [y/N] " reply || true
    case "${reply:-n}" in
        [yY]*) setup_service ;;
        *) echo "  left as-is. (edit $UNIT to change it)" ;;
    esac
else
    read -rp "Set up the agent as a systemd $SCOPE (start on boot, auto-restart)? [Y/n] " reply || true
    case "${reply:-y}" in
        [nN]*) echo "  skipped. start it any time with:  ./agent.sh --run" ;;
        *) setup_service ;;
    esac
fi
