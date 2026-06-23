<#
.SYNOPSIS
    Main launcher for the PKeyMaster suite.

.DESCRIPTION
    Validates the operating environment, checks for updates, verifies file
    integrity via checksums.sha256, then launches the GUI.

.PARAMETER Launcher
    Minimizes the console window before launching the GUI. Intended for callers
    that do not want the PowerShell window to stay visible.

.NOTES
    Compatible with PowerShell 2.0 and later. Requires .NET Framework 3.5 or later.
    Requires the full PKeyMaster file layout in the expected directory structure.
#>
[CmdletBinding()]
param(
    [switch]$Launcher
)

# ===============================================================================================================================
# Initialization
# ===============================================================================================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$GuiPath = Join-Path $ScriptRoot 'BIN\Scripts\GUI.ps1'
$ChecksumFile = Join-Path $ScriptRoot 'checksums.sha256'
$BaseUrl = 'https://ntriver.org/'
$GitUrl = 'https://github.com/ntriver-org/PKeyMaster'
$Version = '0.1'

# Pick the right system folder - avoids 32-bit emulation on 64-bit systems
$SysPath = if (Test-Path "$env:SystemRoot\Sysnative") { "$env:SystemRoot\Sysnative" } else { "$env:SystemRoot\System32" }

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function Show-Msg([string]$Url = '') {
    if ($Url) {
        Write-Host ''
        Write-Host 'Help links:'
        Write-Host 'Website : ' -NoNewline
        Write-Host $Url -ForegroundColor Green
        Write-Host 'GitHub  : ' -NoNewline
        Write-Host $GitUrl -ForegroundColor Green
    }
    Write-Host "`nPress any key to exit..."
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
}

# ===============================================================================================================================

$build = [System.Environment]::OSVersion.Version.Build
if ($build -lt 6001) {
    Write-Host ""
    Write-Host "Unsupported OS version detected [$build]." -ForegroundColor Yellow
    Write-Host "PKeyMaster is supported on Windows Vista SP1 and later Windows versions." -ForegroundColor Yellow
    Show-Msg "${BaseUrl}troubleshoot"
    return
}

# ===============================================================================================================================
# Update check
# ===============================================================================================================================

$UpdateAvail = $false
$VerFlat = $Version -replace '\.', ''
$Mirrors = @(
    ([uri]$BaseUrl).Host
)

foreach ($Mirror in $Mirrors) {
    try {
        $null = [System.Net.Dns]::GetHostAddresses($Mirror)
        try { $null = [System.Net.Dns]::GetHostAddresses("updatecheckpkeymaster${VerFlat}.${Mirror}") }
        catch { $UpdateAvail = $true }
        break
    }
    catch { }
}

if ($UpdateAvail) {
    Write-Host '________________________________________________'
    Write-Host ''
    Write-Host "  Your version of PKeyMaster [$Version] is outdated." -ForegroundColor Yellow
    Write-Host '________________________________________________'
    Write-Host ''
    Write-Host '[1] Get Latest PKeyMaster'
    Write-Host '[0] Continue Anyway'
    Write-Host ''

    $choice = $null
    Write-Host 'Choose a menu option using your keyboard [1,0] : ' -ForegroundColor Green -NoNewline
    while (@('0', '1') -notcontains $choice) {
        $choice = ($host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')).Character.ToString()
    }
    Write-Host ''
    Write-Host ''

    if ($choice -eq '1') {
        Start-Process $BaseUrl
        Start-Process $GitUrl
        return
    }
}

# ===============================================================================================================================
# Path validation
# ===============================================================================================================================

# Make sure the path only has safe ASCII characters
$SafePathPattern = '^[a-zA-Z0-9 \\:\._\-]+$'
if ($ScriptRoot -notmatch $SafePathPattern) {
    Write-Host "ERROR: The folder path contains non-standard characters." -ForegroundColor Red
    Write-Host "Current Path: $ScriptRoot"
    Write-Host ""
    Write-Host "To ensure reliability, please move PKeyMaster to a path containing only" -ForegroundColor Green
    Write-Host "standard letters, numbers, spaces, dots, underscores, or hyphens." -ForegroundColor Green
    Write-Host "Example: D:\Tools\PKeyMaster" -ForegroundColor Green
    Show-Msg "${BaseUrl}troubleshoot"
    return
}

# Check required files exist.
foreach ($Path in @($GuiPath, $ChecksumFile)) {
    if (-not (Test-Path $Path)) {
        Write-Host "ERROR: Missing file: $Path" -ForegroundColor Red
        Show-Msg "${BaseUrl}troubleshoot"
        return
    }
}

# Check Desktop path (used for creating logs in scripts)

$DesktopPath = [Environment]::GetFolderPath("Desktop")
if (-not (Test-Path $DesktopPath)) {
    Write-Host "ERROR: Desktop path does not exist: $DesktopPath" -ForegroundColor Red
    Show-Msg "${BaseUrl}troubleshoot"
    return
}
$DesktopTestFile = Join-Path $DesktopPath ".pkeymaster_writetest"
try {
    [IO.File]::WriteAllText($DesktopTestFile, "test")
    Remove-Item $DesktopTestFile -Force
}
catch {
    Write-Host "ERROR: Desktop path is not writable: $DesktopPath" -ForegroundColor Red
    Show-Msg "${BaseUrl}troubleshoot"
    return
}

# ===============================================================================================================================
# Environment validation
# ===============================================================================================================================

# Full Language Mode required for Reflection / P/Invoke.
if ($ExecutionContext.SessionState.LanguageMode.value__ -ne 0) {
    Write-Host "ERROR: PowerShell is not running in Full Language Mode (Current: $($ExecutionContext.SessionState.LanguageMode))." -ForegroundColor Red
    Show-Msg "${BaseUrl}fix-powershell"
    return
}

# Must be Windows PowerShell, not PowerShell Core.
if ($PSEdition -eq 'Core') {
    Write-Host "ERROR: Windows PowerShell is needed for the script, but it seems to be running with PowerShell Core." -ForegroundColor Red
    Show-Msg "${BaseUrl}troubleshoot"
    return
}

# Verify .NET 3.5+ works.
$NetOk = $false
try {
    $null = [System.Reflection.Assembly]::LoadWithPartialName('System.Core')
    $null = [System.Linq.Enumerable].GetMethods()
    $NetOk = $true
}
catch { $NetOk = $false }

if (-not $NetOk) {
    if ([Environment]::Version.Major -eq 2) {
        Write-Host "ERROR: .NET 3.5 Framework is corrupt or missing. Aborting..." -ForegroundColor Red
        # Check for Embedded SKU to provide specific advice
        if (Test-Path "$SysPath\spp\tokens\skus\Security-SPP-Component-SKU-Embedded") {
            Write-Host "Recommendation: Install .NET Framework 4.8 and Windows Management Framework 5.1" -ForegroundColor Green
        }
        Show-Msg "${BaseUrl}dotnet-framework-downloads"
    }
    else {
        Write-Host "ERROR: .NET seems to be broken in your system. Aborting..." -ForegroundColor Red
        Show-Msg "${BaseUrl}troubleshoot"
    }
    return
}

# WinForms requires STA (Single-Threaded Apartment) mode.
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    Write-Host "ERROR: PowerShell is not running in STA mode." -ForegroundColor Red
    Write-Host "Please launch PKeyMaster using PKeyMaster.cmd." -ForegroundColor Green
    Show-Msg "${BaseUrl}troubleshoot"
    return
}

# ===============================================================================================================================
# TLS 1.2 Check
# ===============================================================================================================================

# Check for TLS 1.2 support, otherwise fallback to wget.
# TLS 1.2 support in PowerShell:
#   Windows 8 / Server 2012 and later - Can be enabled with a command.
#   Windows 7 / Server 2008 R2 - Can be enabled with .NET Framework 4.5+, WMF 3.0+, and KB4474419 (other methods are available, but this is the most reliable approach).
#   Windows Vista / Server 2008 - Although TLS 1.2 can be enabled, it does not support the modern cipher suites required by visualsupport.microsoft.com.

$WgetPath = Join-Path $ScriptRoot 'BIN\wget.exe'
$Tls12Available = $false

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    if ($build -ge 9200) {
        $Tls12Available = $true
    }
    elseif ($build -eq 7601) {
        if (Get-HotFix -Id KB4474419 -ErrorAction SilentlyContinue) {
            $Tls12Available = $true
        }
    }
}
catch { }
if (-not $Tls12Available -and -not (Test-Path $WgetPath)) {
    Write-Host '__________________________________________________________'
    Write-Host ''
    Write-Host '  wget.exe not found in the BIN folder.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  CID with Visual API needs TLS 1.2, which is not'
    Write-Host '  enabled by default in older Windows versions.'
    Write-Host '  Download wget.exe (x86) and place it in the BIN folder.' -ForegroundColor Yellow
    Write-Host '__________________________________________________________'
    Write-Host ''
    Write-Host '[1] Open wget download page'
    Write-Host '[2] Continue anyway'
    Write-Host ''

    $choice = $null
    Write-Host 'Choose a menu option using your keyboard [1,2] : ' -ForegroundColor Green -NoNewline
    while (@('1', '2') -notcontains $choice) {
        $choice = ($host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')).Character.ToString()
    }
    Write-Host ''
    Write-Host ''

    if ($choice -eq '1') {
        Start-Process 'https://eternallybored.org/misc/wget/'
        return
    }
}

# ===============================================================================================================================
# Integrity Validation
# ===============================================================================================================================

Write-Host "Verifying files integrity..."
$ChecksumLines = Get-Content -LiteralPath $ChecksumFile | Where-Object { $_.Trim() -ne '' }
$Mismatches = @()

$sha256 = [System.Security.Cryptography.SHA256]::Create()

foreach ($Line in $ChecksumLines) {
    if ($Line -match '^([a-fA-F0-9]{64})\s+\*(.+)$') {
        $ExpectedHash = $matches[1].ToLower()
        $RelativePath = $matches[2]
        $FilePath = Join-Path $ScriptRoot $RelativePath

        if (-not (Test-Path $FilePath)) {
            $Mismatches += $RelativePath
        }
        else {
            $stream = $null
            try {
                $stream = [System.IO.File]::OpenRead($FilePath)
                $hashBytes = $sha256.ComputeHash($stream)
                $hashString = [System.BitConverter]::ToString($hashBytes).Replace('-', '').ToLower()
                if ($hashString -ne $ExpectedHash) {
                    $Mismatches += $RelativePath
                }
            }
            catch {
                $Mismatches += $RelativePath
            }
            finally {
                if ($stream) { $stream.Close() }
            }
        }
    }
}

$sha256.Clear()

if ($Mismatches.Count -gt 0) {
    Write-Host "WARNING: The following files are missing or modified:" -ForegroundColor Yellow
    foreach ($m in $Mismatches) { Write-Host "  $m" -ForegroundColor Red }
    Write-Host '__________________________________________________________'
}

if ($Mismatches.Count -gt 0) {
    Write-Host ""
    Write-Host '[1] Get Original Files'
    Write-Host '[2] Continue Anyway'
    Write-Host '[3] Exit'
    Write-Host ''
    $ans = $null
    Write-Host 'Choose a menu option using your keyboard [1,2,3] : ' -ForegroundColor Green -NoNewline
    while (@('1', '2', '3') -notcontains $ans) {
        $ans = ($host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')).Character.ToString()
    }
    Write-Host ''
    if ($ans -eq '1') {
        Start-Process $BaseUrl
        Start-Process $GitUrl
        return
    }
    if ($ans -eq '3') { return }
}
else {
    Write-Host "All files are successfully verified."
}

# ===============================================================================================================================
# Window minimization and GUI launch
# ===============================================================================================================================

Write-Host ""
Write-Host "Launching PKeyMaster GUI..."

# Minimize the launcher window.
# Set a known title, find the handle, call ShowWindow via P/Invoke.
try {
    if ($Launcher) {
        $host.UI.RawUI.WindowTitle = 'PKeyMaster-Launcher'
        $p = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like '*PKeyMaster-Launcher' } | Select-Object -First 1
        if ($p -and $p.MainWindowHandle -ne [IntPtr]::Zero) {
            $TB = [AppDomain]::CurrentDomain.DefineDynamicAssembly((Get-Random), 1).DefineDynamicModule((Get-Random), $False).DefineType((Get-Random))
            [void]$TB.DefinePInvokeMethod('ShowWindow', 'user32.dll', 22, 1, [bool], @([IntPtr], [int]), 1, 4).SetImplementationFlags(128)
            [void]$TB.CreateType()::ShowWindow($p.MainWindowHandle, 6)
        }
    }
}
catch { }

# Launch the GUI within the current process
. $GuiPath
