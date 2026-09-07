"""Self-update: git-pull this checkout and restart, on the host's say-so.

The agent never decides *when* to update, nor whether one is even worth
trying -- that is the host's call (a manual click or its daily schedule,
gated by comparing this agent's reported version against the version.json
GitHub publishes, checked once for the whole fleet rather than once per
agent -- see culprit/nodes.py's NodeRegistry.refresh_remote_version on the
host). This module only answers what the host cannot know from outside the
machine, and does the update itself:

    capability()  can this install even be updated this way, and why not
    perform()      actually git-pull + reinstall + ask for a restart -- to
                   origin/<branch> by default, or to a commit the host names
                   (`ref`), which is how a downgrade works: the host resolves
                   a version to the newest commit that carried it and sends
                   that sha; this side only checks the commit is real and on
                   the branch it tracks before resetting to it

Deliberately the "quickest dirtiest way": a real git clone with a working
`origin` remote is the whole mechanism, restarted via a clean process exit
that leans on the systemd unit's own `Restart=always` (see agent.sh). No
`systemctl` shell-out, no separate installer, no version-number gate on the
apply step -- perform() always resets to whatever origin/<branch> actually
has (or to the exact commit it was given), regardless of what any version
string claims. SUPPORTS_REF is reported to the host as `update_refs`, so a
host never sends a ref to an agent that would silently ignore it and update
to the tip instead.

Every git call passes `-c safe.directory=<ROOT>`: a system service (`sudo
./agent.sh`) runs as root over a checkout some other user cloned, and git
2.35.2+ refuses to touch a repository it does not own ("detected dubious
ownership") unless told to trust that exact path. Without this, every git
call here fails and _run()'s caller would misreport *why* -- e.g. a dubious-
ownership error surfacing as "no origin remote configured", which is not
what is actually wrong. _run() returns the tool's own stderr on failure for
exactly this reason: a guessed reason is worse than none.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys

from . import config as config_module

log = logging.getLogger("culprit.agent.updater")

_GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}  # never hang on a prompt

# This build honours an "update" command's `ref`. Reported in every agent
# meta so the host can refuse a version change for an older agent instead of
# sending a ref it would ignore.
SUPPORTS_REF = True
_SHA = re.compile(r"^[0-9a-f]{7,40}$")


def _git(*args: str, timeout: float) -> tuple[bool, str]:
    """A `git -c safe.directory=<ROOT> <args>` call in the checkout.
    (True, stdout) on success; (False, message) naming exactly why not --
    the executable missing, a timeout, or git's own stderr verbatim."""
    argv = ["git", "-c", f"safe.directory={config_module.ROOT}", *args]
    try:
        completed = subprocess.run(
            argv, cwd=config_module.ROOT, env=_GIT_ENV,
            capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return False, "git is not installed on this machine"
    except subprocess.TimeoutExpired:
        return False, f"git {args[0]} timed out after {timeout:.0f}s"
    except OSError as exc:
        return False, str(exc)
    if completed.returncode != 0:
        message = completed.stderr.strip().splitlines()[0] if completed.stderr.strip() else \
            f"git {args[0]} exited {completed.returncode}"
        return False, message[:300]
    return True, completed.stdout


def _pip(*args: str, timeout: float) -> tuple[bool, str]:
    argv = [sys.executable, "-m", "pip", *args]
    try:
        completed = subprocess.run(
            argv, cwd=config_module.ROOT, capture_output=True, text=True,
            timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    if completed.returncode != 0:
        return False, completed.stderr.strip()[:300] or f"pip exited {completed.returncode}"
    return True, completed.stdout


def head_branch() -> str | None:
    """The branch the checkout is on, read straight from .git/HEAD -- a file
    read, no subprocess, so every report can carry it and a `git checkout`
    done by hand shows on the host with the next report rather than at the
    next capability check. None when there is no checkout, HEAD is detached,
    or the file cannot be read."""
    git_dir = config_module.ROOT / ".git"
    try:
        if git_dir.is_file():
            # A worktree: ".git" is a pointer file to the real git dir.
            pointer = git_dir.read_text(encoding="utf-8").strip()
            if not pointer.startswith("gitdir:"):
                return None
            git_dir = (config_module.ROOT / pointer[len("gitdir:"):].strip()).resolve()
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if head.startswith("ref: refs/heads/"):
        return head[len("ref: refs/heads/"):] or None
    return None


def current_branch() -> str:
    """The checkout's branch to reset to in perform(), or "main" when there
    is no .git to ask (a Docker or cp -r deployment, which capability()
    already refuses before this is ever called)."""
    if not (config_module.ROOT / ".git").exists():
        return "main"
    branch = head_branch()
    if branch:
        return branch
    ok, out = _git("rev-parse", "--abbrev-ref", "HEAD", timeout=10)
    return out.strip() if ok and out.strip() else "main"


def capability() -> tuple[bool, str | None]:
    """(capable, reason) -- every blocker is named exactly, never silent."""
    if os.environ.get("CULPRIT_AGENT_DOCKER"):
        return False, "running in a container image; rebuild/pull the image instead"
    if not config_module.get().allow_remote_update:
        return False, "remote updates disabled on this agent (allow_remote_update is false)"
    if not os.environ.get("CULPRIT_AGENT_MANAGED"):
        return False, ("not started by the scheduled task (started via --run); "
                       "nothing would bring it back up after the restart")
    if not (config_module.ROOT / ".git").is_dir():
        return False, "checkout has no .git (deployed with cp -r, not git clone)"
    ok, out = _git("remote", "get-url", "origin", timeout=10)
    if not ok:
        return False, out
    if not out.strip():
        return False, "no 'origin' remote configured"
    ok, out = _git("status", "--porcelain", timeout=15)
    if not ok:
        return False, out
    if out.strip():
        return False, "the checkout has local modifications (git status is not clean)"
    return True, None


def _cmd_err(cmd_id, status: int, message: str) -> dict:
    return {"id": cmd_id, "ok": False, "status": status, "error": message}


_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")


def perform(cmd_id, ref: str | None = None, branch: str | None = None) -> dict:
    """Run the update. Returns the {"id", "ok", ...} shape agent.py's other
    command results use, plus "restart": True when the caller should exit
    once this result has been posted back. Never raises.

    `branch` is the line the host wants this agent on (its Settings say
    which); without one the checkout's own branch is kept. A branch other
    than the current one is switched to with `git checkout -B` onto
    origin/<branch>, after the fetch has shown origin actually has it. The
    repository is never chosen by the host: origin stays whatever this
    checkout was cloned from.

    `ref` names the commit to end up on (a sha, from the host's mirror of
    this repository); without one the target is origin/<branch>. A ref is
    accepted only when it is a commit git knows after the fetch and lies on
    origin/<branch>'s history -- a downgrade to an older release, never a
    jump to some unrelated commit."""
    capable, reason = capability()
    if not capable:
        return _cmd_err(cmd_id, 409, reason or "not capable")
    if ref is not None and not _SHA.match(str(ref)):
        return _cmd_err(cmd_id, 400, "ref must be a commit sha")
    if branch is not None and not _BRANCH.match(str(branch)):
        return _cmd_err(cmd_id, 400, "branch is not a valid branch name")

    ok, out = _git("rev-parse", "HEAD", timeout=10)
    if not ok:
        return _cmd_err(cmd_id, 500, f"git rev-parse HEAD failed: {out}")
    from_sha = out.strip()

    ok, out = _git("fetch", "--quiet", "origin", timeout=60)
    if not ok:
        return _cmd_err(cmd_id, 502, f"git fetch failed: {out}")

    was_on = current_branch()
    branch = branch or was_on
    ok, out = _git("rev-parse", "--verify", "--quiet", f"refs/remotes/origin/{branch}", timeout=10)
    if not ok or not out.strip():
        return _cmd_err(cmd_id, 404, f"origin has no branch '{branch}'")
    if branch != was_on:
        # Switch lines: a local branch of that name tracking origin's, reset
        # to it. The working tree is clean (capability() checked), so nothing
        # is lost by the switch.
        ok, out = _git("checkout", "--quiet", "-B", branch, f"origin/{branch}", timeout=30)
        if not ok:
            return _cmd_err(cmd_id, 500, f"git checkout -B {branch} origin/{branch} failed: {out}")
    target = f"origin/{branch}"
    if ref is not None:
        ok, out = _git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", timeout=10)
        if not ok or not out.strip():
            return _cmd_err(cmd_id, 404, f"commit {ref[:12]} is not in this checkout even after fetching")
        target = out.strip()
        ok, _ = _git("merge-base", "--is-ancestor", target, f"origin/{branch}", timeout=10)
        if not ok:
            return _cmd_err(cmd_id, 409, f"commit {ref[:12]} is not on origin/{branch}; refusing to leave the branch")
    ok, out = _git("reset", "--hard", "--quiet", target, timeout=30)
    if not ok:
        return _cmd_err(cmd_id, 500, f"git reset --hard {target[:12]} failed: {out}")

    ok, out = _git("rev-parse", "HEAD", timeout=10)
    to_sha = out.strip() if ok else from_sha

    if to_sha == from_sha:
        return {"id": cmd_id, "ok": True,
                "result": {"updated": False, "sha": to_sha[:12], "pinned": ref is not None,
                           "branch": branch}}

    ok, out = _pip("install", "--quiet", "-r", "requirements-agent.txt", timeout=180)
    if not ok:
        # Revert: disk must keep matching what's actually running.
        _git("reset", "--hard", "--quiet", from_sha, timeout=30)
        return _cmd_err(
            cmd_id, 500,
            f"pip install failed after updating to {to_sha[:12]}: {out}; "
            f"reverted to {from_sha[:12]}")

    return {"id": cmd_id, "ok": True,
            "result": {"updated": True, "from_sha": from_sha[:12],
                       "to_sha": to_sha[:12], "pinned": ref is not None,
                       "branch": branch, "switched_from": was_on if was_on != branch else None},
            "restart": True}
