@echo off


::=========================================================
::
::   PKeyMaster
::   Homepage  : https://ntriver.org
::   GitHub    : https://github.com/ntriver-org/PKeyMaster
::
::=========================================================


::========================================================================================================================================

setlocal EnableExtensions DisableDelayedExpansion

::  Clean env - don't inherit potentially misconfigured system values

set "PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"

set "sysPath=%SystemRoot%\System32"
set "Path=%SystemRoot%\System32;%SystemRoot%;%SystemRoot%\System32\Wbem;%SystemRoot%\System32\WindowsPowerShell\v1.0\"
if exist "%SystemRoot%\Sysnative\reg.exe" (
    set "sysPath=%SystemRoot%\Sysnative"
    set "Path=%SystemRoot%\Sysnative;%SystemRoot%;%SystemRoot%\Sysnative\Wbem;%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\;%Path%"
)

set "ComSpec=%sysPath%\cmd.exe"
set "PSModulePath=%ProgramFiles%\WindowsPowerShell\Modules;%sysPath%\WindowsPowerShell\v1.0\Modules"

::========================================================================================================================================

::  Prevent infinite re-launch loops

set "relaunchX64="
set "relaunchArm32="
set "scriptFile=%~f0"
for %%A in (%*) do (
    if /i "%%~A"=="relaunchX64" set "relaunchX64=1"
    if /i "%%~A"=="relaunchArm32" set "relaunchArm32=1"
)

::  Re-launch via native cmd.exe if we're x86 on x64/ARM64
::  (Sysnative = real System32 from the WOW64 redirector)

if exist "%SystemRoot%\Sysnative\cmd.exe" if not defined relaunchX64 (
    setlocal EnableDelayedExpansion
    start "" "%SystemRoot%\Sysnative\cmd.exe" /c ""!scriptFile!" %* relaunchX64"
    exit /b
)

::  Re-launch via ARM32 cmd.exe if we're x64 on ARM64

if exist "%SystemRoot%\SysArm32\cmd.exe" if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" if not defined relaunchArm32 (
    setlocal EnableDelayedExpansion
    start "" "%SystemRoot%\SysArm32\cmd.exe" /c ""!scriptFile!" %* relaunchArm32"
    exit /b
)

::========================================================================================================================================

set "helpUrl=https://ntriver.org/"
title PKeyMaster-Launcher

::  Null service must be running for null redirection

if exist "%sysPath%\sc.exe" "%sysPath%\sc.exe" query Null | find /i "RUNNING"
if %errorlevel% NEQ 0 (
    echo:
    echo Null service is not running, script may crash...
    echo:
    echo:
    echo Help link - %helpUrl%fix-service
    echo:
    echo:
    ping 127.0.0.1 -n 20
)
cls

::========================================================================================================================================

echo:
set "winBuild=1"
for /f "tokens=2 delims=[]" %%G in ('ver') do for /f "tokens=2,3,4 delims=. " %%H in ("%%~G") do set "winBuild=%%J"

if %winBuild% EQU 1 (
    echo Failed to detect Windows build number.
    goto done
)

if %winBuild% LSS 6001 (
    echo Unsupported OS version detected [%winBuild%].
    echo PKeyMaster is supported on Windows Vista SP1 and later Windows versions.
    goto done
)

::========================================================================================================================================

set "psError="
set "psPath=%sysPath%\WindowsPowerShell\v1.0\powershell.exe"

if not exist "%sysPath%\WindowsPowerShell\v1.0\Modules" (
    set "psError=PowerShell 1.0 is installed on your system."
)

if not exist "%psPath%" (
    set "psError=PowerShell is not installed on your system."
)

if defined psError (
    echo %psError%
    echo Install PowerShell 2.0 or higher version using the following URL.
    echo:
    echo Help link - %helpUrl%windows-powershell-downloads
    goto done
)

::========================================================================================================================================

::  Set paths and enable delayed expansion

set "scriptDir=%~dp0"
if "%scriptDir:~-1%"=="\" set "scriptDir=%scriptDir:~0,-1%"
set "tempDir=%LOCALAPPDATA%\Temp"

setlocal EnableDelayedExpansion

::========================================================================================================================================

::  Detect direct-from-archive launch

echo "!scriptFile!" | find /i "!tempDir!" 1>nul && (
    if /i not "!scriptDir!" == "!tempDir!" (
        echo The script was launched from the temp folder.
        echo You are most likely running the script directly from the archive file.
        echo:
        echo Extract the archive file and launch the script from the extracted folder.
        goto done
    )
)

::========================================================================================================================================

if not exist "!scriptDir!\BIN\Scripts\Launcher.ps1" (
    echo Launcher.ps1 file not found in "\BIN\Scripts" folder.
    goto done
)

"%psPath%" -STA -NoProfile -ExecutionPolicy Bypass -Command ^& "Set-Location -LiteralPath ($env:scriptDir); .\BIN\Scripts\Launcher.ps1 -Launcher"

if %errorlevel% NEQ 0 goto done
exit /b

::========================================================================================================================================

:done

echo:
echo Help link - %helpUrl%troubleshoot
echo:
echo Press any key to exit...
pause 1>nul
exit /b

::========================================================================================================================================
