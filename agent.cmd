@echo off
REM Double-clickable launcher for agent.ps1.
REM
REM Exists because a default Windows install refuses to run .ps1 files
REM (execution policy Restricted), and because double-clicking a .ps1 opens it
REM in Notepad rather than running it. This wrapper bypasses the policy for this
REM one invocation only -- it does not change any machine setting.

setlocal
cd /d "%~dp0"

where pwsh.exe >nul 2>nul
if %ERRORLEVEL%==0 (
    pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0agent.ps1" %*
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0agent.ps1" %*
)

REM Pause only when launched from Explorer, so a failure is readable instead of
REM the window vanishing. Started from a console, %CMDCMDLINE% has no /c.
echo %CMDCMDLINE% | find /i "/c" >nul
if %ERRORLEVEL%==0 (
    echo.
    pause
)
endlocal
