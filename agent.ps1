<#
.SYNOPSIS
    culprit agent for Windows -- install, save the host + token, then run it as a
    scheduled task (start on boot, auto-restart) or in the foreground.

.DESCRIPTION
    Three steps, always in this order:
      1. install    -- create the venv (psutil + pywin32) outside the checkout
      2. configure  -- the host URL and this node's token, asked for interactively
                       and saved to agent.json, so nothing is typed again
      3. run it     -- either as a scheduled task (default, it asks), or with
                       -Run start it here in the foreground

    Nothing is written into this checkout, so `git pull` -- and the host's
    remote update, which is a git reset -- keep working. Elevated (an
    Administrator PowerShell), the venv, config and flight recorder live under
    %ProgramData%\culprit-agent and the task runs as SYSTEM at boot, which is
    what reads the Security event log, other users' processes and the SMART
    bit. Unelevated, they live in your own profile (%LOCALAPPDATA% /
    %APPDATA%) and the task runs as you at sign-in: it sees your own
    processes fully, other users' partly, and -- unlike the SYSTEM task -- it
    can see your windows, so "not responding" detection works.

    The token comes from the host: Nodes > "Generate token" in the dashboard,
    or `python -m culprit agents add <name>` on the host machine. It looks like
    <name>.<secret>; the name before the dot is how this node appears in the fleet.

.PARAMETER Run
    Install if needed, then run here in the foreground (no task prompt).
.PARAMETER Configure
    (Re)enter the host URL and token, save, and restart the task if one exists.
.PARAMETER InstallOnly
    Venv only -- no prompts, no run (CI / images).
.PARAMETER Host
    The culprit host URL, e.g. https://hub:8787 (saved).
.PARAMETER Token
    This node's token, <name>.<secret> (saved).
.PARAMETER Insecure
    Do not verify the host's TLS certificate (self-signed; saved).
.PARAMETER Interval
    Seconds between reports (default 1; saved).
.PARAMETER LogLevel
    debug | info | warning | error, passed to the agent in -Run mode.

.EXAMPLE
    .\agent.ps1
.EXAMPLE
    .\agent.ps1 -Run -Host http://192.168.1.1:8787 -Token web-01.<secret>
.EXAMPLE
    .\agent.ps1 -Configure
#>
[CmdletBinding()]
param(
    [switch]$Run,
    [switch]$Configure,
    [switch]$InstallOnly,
    [Alias('Host')][string]$HostUrl,
    [string]$Token,
    [switch]$Insecure,
    [double]$Interval,
    [ValidateSet('debug', 'info', 'warning', 'error')]
    [string]$LogLevel = 'info',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root      = $PSScriptRoot
$TaskName  = 'culprit-agent'
$ReqFile   = Join-Path $Root 'requirements-agent.txt'
$MinPython = [version]'3.10'

# Positional leftovers: a URL and a <name>.<secret>, the way agent.sh takes them.
foreach ($arg in @($Rest)) {
    if ($arg -match '^https?://') { $HostUrl = $arg }
    elseif ($arg -match '^[^.\s]+\.[^\s]+$') { $Token = $arg }
    elseif ($arg -in '--run', 'run') { $Run = $true }
    elseif ($arg -in '--configure', 'configure') { $Configure = $true }
    elseif ($arg -in '--install-only', '--no-run') { $InstallOnly = $true }
    elseif ($arg -eq '--insecure') { $Insecure = $true }
}

function Write-Step { param($m) Write-Host "  ->  $m" -ForegroundColor Cyan }
function Write-Good { param($m) Write-Host "  OK  $m" -ForegroundColor Green }
function Write-Warn2 { param($m) Write-Host "  !   $m" -ForegroundColor Yellow }
function Write-Bad { param($m) Write-Host "  X   $m" -ForegroundColor Red }

$Elevated = ([Security.Principal.WindowsPrincipal] `
             [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---- where the agent keeps its files: never in the checkout -----------------
if ($Elevated) {
    $DataDir   = Join-Path $env:ProgramData 'culprit-agent'
    $ConfigDir = $DataDir
    $Scope     = 'SYSTEM task (runs at boot as SYSTEM: full process, port and event-log access)'
} else {
    $DataDir   = Join-Path $env:LOCALAPPDATA 'culprit-agent'
    $ConfigDir = Join-Path $env:APPDATA 'culprit-agent'
    $Scope     = "user task (runs at your sign-in as $env:USERNAME)"
}
$VenvDir    = Join-Path $DataDir 'venv'
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'
$ConfigFile = Join-Path $ConfigDir 'agent.json'
$StampFile  = Join-Path $VenvDir '.requirements.sha256'

function Get-Sha256 {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $sha = $null; $stream = $null
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $stream = [System.IO.File]::OpenRead($Path)
        return -join ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') })
    } catch { return '' } finally {
        if ($stream) { $stream.Dispose() }
        if ($sha) { $sha.Dispose() }
    }
}

# Prefer the py launcher: on Windows it knows about every installed version,
# whereas `python` may be the Microsoft Store stub that opens the Store.
function Resolve-Python {
    $candidates = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        try {
            $listed = @(& py -0p 2>$null)
            foreach ($line in $listed) {
                if ("$line" -match '([A-Za-z]:\\[^\s]+python\.exe)') { $candidates += $Matches[1] }
            }
        } catch { }
    }
    foreach ($name in 'python', 'python3') {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) { $candidates += $cmd.Source }
    }
    foreach ($exe in ($candidates | Select-Object -Unique)) {
        if (-not (Test-Path $exe)) { continue }
        try {
            $raw = @(& $exe --version 2>&1) -join ' '
            if ("$raw" -notmatch 'Python\s+(\d+)\.(\d+)') { continue }
            $ver = [version]("{0}.{1}" -f $Matches[1], $Matches[2])
            if ($ver -ge $MinPython) { return [pscustomobject]@{ Path = $exe; Version = $ver } }
        } catch { continue }
    }
    return $null
}

# Run a Python snippet from a temp file: Windows PowerShell 5.1 mangles quotes
# and parentheses inside `-c` arguments to native executables.
function Invoke-Snippet {
    param([string]$Code, [string[]]$Arguments = @())
    $file = Join-Path ([System.IO.Path]::GetTempPath()) "culprit-agent-$PID-$(Get-Random).py"
    Set-Content -Path $file -Value $Code -Encoding utf8
    try {
        $env:PYTHONPATH = $Root
        & $VenvPython $file @Arguments
        return $LASTEXITCODE
    } finally {
        Remove-Item Env:\PYTHONPATH -ErrorAction SilentlyContinue
        Remove-Item $file -ErrorAction SilentlyContinue
    }
}

# ---- 1. install ---------------------------------------------------------------
function Install-Agent {
    if (-not (Test-Path $ReqFile)) { Write-Bad "requirements-agent.txt not found in $Root"; exit 1 }
    $stamped = if (Test-Path $StampFile) { (Get-Content $StampFile -Raw).Trim() } else { '' }
    $current = Get-Sha256 -Path $ReqFile
    if ((Test-Path $VenvPython) -and $current -and $current -eq $stamped) {
        Write-Good "venv ready at $VenvDir"
        return
    }
    Write-Step 'Looking for Python'
    $python = Resolve-Python
    if (-not $python) {
        Write-Bad "No Python $MinPython or newer found on PATH."
        Write-Host '      Install it from https://www.python.org/downloads/windows/' -ForegroundColor Gray
        Write-Host '      (tick "Add python.exe to PATH" in the installer)' -ForegroundColor Gray
        exit 1
    }
    Write-Good "Python $($python.Version) at $($python.Path)"
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    if (-not (Test-Path $VenvPython)) {
        Write-Step "Creating the venv in $VenvDir"
        & $python.Path -m venv $VenvDir
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $VenvPython)) {
            Write-Bad 'venv creation failed.'
            Write-Host '      If Python came from the Microsoft Store, install it from' -ForegroundColor Gray
            Write-Host '      python.org instead - the Store build restricts venv.'    -ForegroundColor Gray
            exit 1
        }
    }
    Write-Step 'Installing requirements (psutil, pywin32)'
    $pipArgs = @('-m', 'pip', 'install', '--disable-pip-version-check', '--quiet')
    & $VenvPython @pipArgs '--upgrade' 'pip' | Out-Null
    # --only-binary keeps this a no-compiler install; both packages ship wheels.
    & $VenvPython @pipArgs '--only-binary=:all:' '-r' $ReqFile
    if ($LASTEXITCODE -ne 0) {
        Write-Warn2 'Wheel-only install failed; retrying and allowing source builds'
        & $VenvPython @pipArgs '-r' $ReqFile
        if ($LASTEXITCODE -ne 0) { Write-Bad 'Dependency installation failed.'; exit 1 }
    }
    # pywin32's post-install step registers its DLLs; harmless when repeated.
    $post = Join-Path $VenvDir 'Scripts\pywin32_postinstall.py'
    if (Test-Path $post) { & $VenvPython $post -install -quiet 2>$null | Out-Null }
    Write-Step 'Verifying imports'
    $code = Invoke-Snippet -Code @'
import importlib, sys
missing = []
for module in ("psutil", "win32pdh", "win32evtlog", "win32gui", "win32com.client",
               "win32service", "win32ts", "win32job"):
    try:
        importlib.import_module(module)
    except Exception as exc:
        missing.append(f"{module} ({exc})")
import culprit.agent  # noqa: F401  -- the package itself
if missing:
    print("DEGRADED: " + "; ".join(missing))
    sys.exit(2)
print("ALL_OK " + sys.version.split()[0])
'@
    if ($code -eq 2) {
        Write-Warn2 'Installed, but some pywin32 modules are unavailable; those panels will say so.'
    } elseif ($code -ne 0) {
        Write-Bad 'Import verification failed.'; exit 1
    } else {
        Write-Good 'All imports resolve'
    }
    if ($current) { Set-Content -Path $StampFile -Value $current -Encoding ascii }
}

# ---- 2. configure -------------------------------------------------------------
$ConfigSnippet = @'
import json, os, sys
from pathlib import Path
path = Path(sys.argv[1]); url, token, insecure, interval = sys.argv[2:6]
cfg = {"host_url": "", "token": "", "report_interval": 1.0, "verify_tls": True}
if path.exists():
    try:
        cfg.update({k: v for k, v in json.loads(path.read_text()).items() if k in cfg})
    except (OSError, ValueError):
        pass
if url: cfg["host_url"] = url.rstrip("/")
if token: cfg["token"] = token
if insecure == "1": cfg["verify_tls"] = False
if interval: cfg["report_interval"] = max(0.5, float(interval))
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(cfg, indent=2) + "\n")
print(f"  saved {path}")
'@

$ShowSnippet = @'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    cfg = json.loads(path.read_text())
except (OSError, ValueError):
    print("  no configuration saved yet"); sys.exit(1)
name = str(cfg.get("token", "")).partition(".")[0] or "?"
tls = "" if cfg.get("verify_tls", True) else " (TLS verification off)"
print(f"  node '{name}' -> {cfg.get('host_url')}{tls}   [{path}]")
sys.exit(0 if cfg.get("host_url") and cfg.get("token") else 1)
'@

# Reachability + token check without registering anything: the host validates
# the token before it parses the body, so a deliberately invalid body ("[]")
# answers 401 for a bad token and 400 for a good one, and folds nothing in.
$CheckSnippet = @'
import gzip, json, ssl, sys, urllib.error, urllib.request
from pathlib import Path
cfg = json.loads(Path(sys.argv[1]).read_text())
url = cfg["host_url"].rstrip("/")
ctx = None
if url.startswith("https") and not cfg.get("verify_tls", True):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    urllib.request.urlopen(url + "/api/healthz", timeout=6, context=ctx).read()
except urllib.error.HTTPError as exc:
    print(f"  host reachable ({url}) but /api/healthz answered {exc.code}; continuing")
except Exception as exc:
    hint = " -- a self-signed certificate? rerun with -Insecure" if "CERTIFICATE_VERIFY_FAILED" in str(exc) else ""
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
        print("           Nodes on the host and rerun .\\agent.ps1 -Configure")
    elif exc.code == 400:
        print(f"  host reachable and the token is accepted ({url})")
    else:
        print(f"  host reachable ({url}); the report endpoint answered {exc.code}")
except Exception as exc:
    print(f"  warning: {url} answered the health check but not the report endpoint: {exc}")
'@

function Test-Configured {
    $null = Invoke-Snippet -Code $ShowSnippet -Arguments @($ConfigFile) 6>$null
    return ($LASTEXITCODE -eq 0)
}
function Show-Config { $null = Invoke-Snippet -Code $ShowSnippet -Arguments @($ConfigFile) }
function Save-Config {
    param([string]$Url, [string]$Tok, [bool]$NoVerify, [string]$Every)
    New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
    $null = Invoke-Snippet -Code $ConfigSnippet -Arguments @($ConfigFile, $Url, $Tok, $(if ($NoVerify) { '1' } else { '0' }), $Every)
    if ($Elevated) {
        # The token lives in here: SYSTEM and Administrators only.
        try {
            $acl = Get-Acl $ConfigDir
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($who in 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators') {
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $who, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
                $acl.AddAccessRule($rule)
            }
            Set-Acl $ConfigDir $acl
        } catch { Write-Warn2 "could not tighten the ACL on $ConfigDir: $_" }
    }
}
function Test-Host { $null = Invoke-Snippet -Code $CheckSnippet -Arguments @($ConfigFile) }

function Read-Config {
    Write-Host ''
    Write-Host 'The agent needs the culprit host and this node''s token.' -ForegroundColor White
    Write-Host '  (token: Nodes > "Generate token" on the host dashboard; it looks like <name>.<secret>)' -ForegroundColor DarkGray
    $url = Read-Host '  host URL (e.g. http://192.168.1.1:8787)'
    $tok = Read-Host '  token'
    if (-not $url -or -not $tok) { Write-Bad 'both are required'; exit 1 }
    $noVerify = $Insecure.IsPresent
    if ($url -like 'https://*' -and -not $noVerify) {
        $ans = Read-Host '  is the host''s certificate self-signed (skip TLS verification)? [y/N]'
        if ($ans -match '^[yY]') { $noVerify = $true }
    }
    Save-Config -Url $url -Tok $tok -NoVerify $noVerify -Every "$Interval"
    Test-Host
}

# ---- 3. the scheduled task ----------------------------------------------------
function Get-AgentTask { Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue }

function Install-Task {
    $arguments = "-m culprit.agent --managed --config `"$ConfigFile`" --data `"$DataDir`""
    $action = New-ScheduledTaskAction -Execute $VenvPython -Argument $arguments -WorkingDirectory $Root
    # Restart on failure is what makes the host's remote update possible: the
    # agent exits after a git reset and the task brings the new code back up.
    $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Days 3650) -MultipleInstances IgnoreNew `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    if ($Elevated) {
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    } else {
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
    }
    $existing = Get-AgentTask
    if ($existing) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
        -Principal $principal -Description 'culprit monitoring agent (reports to the culprit host)' | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 2
    $task = Get-AgentTask
    if ($task -and $task.State -eq 'Running') {
        Write-Good "task '$TaskName' is installed and running -- $Scope."
    } else {
        Write-Warn2 "task '$TaskName' installed but not running -- check: Get-ScheduledTaskInfo $TaskName"
    }
    Show-Config
    Write-Host "  manage:  Start-ScheduledTask / Stop-ScheduledTask -TaskName $TaskName" -ForegroundColor DarkGray
    Write-Host "  logs:    the agent writes to stdout; enable the Task Scheduler history, or run .\agent.ps1 -Run to watch it" -ForegroundColor DarkGray
    if (-not $Elevated) {
        Write-Host "  note: as $env:USERNAME it sees your own processes fully and other users' partly," -ForegroundColor DarkGray
        Write-Host "        and cannot read the Security event log. Run agent.ps1 from an Administrator" -ForegroundColor DarkGray
        Write-Host "        PowerShell for a SYSTEM task with full attribution." -ForegroundColor DarkGray
    }
}

# ---- main -----------------------------------------------------------------------
Write-Host ''
Write-Host 'culprit agent (Windows)' -ForegroundColor White
Write-Host '=======================' -ForegroundColor DarkGray

Install-Agent
if ($InstallOnly) { Write-Good 'installed; nothing started.'; exit 0 }

if ($HostUrl -or $Token -or $Insecure -or $Interval) {
    Save-Config -Url $HostUrl -Tok $Token -NoVerify $Insecure.IsPresent -Every "$Interval"
}
if ($Configure) {
    Read-Config
    if (Get-AgentTask) {
        Write-Step 'Restarting the task with the new configuration'
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Start-ScheduledTask -TaskName $TaskName
    }
    exit 0
}
if (-not (Test-Configured)) {
    if ($Run -and -not [Environment]::UserInteractive) {
        Write-Bad 'no host/token configured. Run: .\agent.ps1 -Run -Host <url> -Token <name>.<secret>'
        exit 1
    }
    Read-Config
} elseif ($HostUrl -or $Token) {
    Test-Host
}

if ($Run) {
    Write-Host ''
    Show-Config
    Write-Host '  press Ctrl+C to stop' -ForegroundColor DarkGray
    Write-Host ''
    $env:PYTHONUNBUFFERED = '1'
    Push-Location $Root
    try {
        & $VenvPython -m culprit.agent --config $ConfigFile --data $DataDir --log-level $LogLevel
        exit $LASTEXITCODE
    } finally { Pop-Location }
}

Write-Host ''
Show-Config
$task = Get-AgentTask
if ($task -and $task.State -eq 'Running') {
    # A task is already running -- default to NO so a stray Enter never
    # restarts it out from under you.
    $reply = Read-Host "A culprit-agent task is already running. Reconfigure and restart it? [y/N]"
    if ($reply -match '^[yY]') { Install-Task } else { Write-Host "  left as-is." }
} else {
    $reply = Read-Host "Set up the agent as a scheduled task -- $Scope -- (start on boot, auto-restart)? [Y/n]"
    if ($reply -match '^[nN]') { Write-Host '  skipped. start it any time with:  .\agent.ps1 -Run' } else { Install-Task }
}
