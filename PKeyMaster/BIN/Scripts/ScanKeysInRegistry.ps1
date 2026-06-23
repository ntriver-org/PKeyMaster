<#
.SYNOPSIS
    Scans the Windows registry for Digital Product ID values.

.DESCRIPTION
    Uses .NET iterative traversal to find DigitalProductId and DigitalProductId4
    binary values in the registry. Parses and decodes them to show embedded
    product keys, Product IDs, and integrity check results.

.PARAMETER Windows
    Scan Windows-related registry paths.

.PARAMETER Office
    Scan Office (MSI version) registry paths.

.PARAMETER Other
    Scan all other HKLM paths, excluding Windows and Office.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\DigitalProductId.ps1 for DPID parsing.
    Requires Libs\Common.ps1 for shared helper functions.

.EXAMPLE
    .\ScanKeysInRegistry.ps1 -Windows -Office
#>
[CmdletBinding()]
param(
    [switch]$Windows,
    [switch]$Office,
    [switch]$Other
)

# ===============================================================================================================================
# Initialization & dependencies
# ===============================================================================================================================

$VerifyHash = $true

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "." }

$commonPath = Join-Path $scriptDir "libs\Common.ps1"
if (Test-Path $commonPath) { . $commonPath }
$digitalPidPath = Join-Path $scriptDir "libs\DigitalProductId.ps1"
if (Test-Path $digitalPidPath) { . $digitalPidPath }

# Default to Windows + Office if no mode specified
if (-not ($Windows -or $Office -or $Other)) {
    $Windows = $true; $Office = $true
}

# Paths that Windows/Office modes already cover - excluded from Other mode
$ExcludedPrefixes = @(
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Registration",
    "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion",
    "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Registration",
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office",
    "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Office"
)

if ([Environment]::OSVersion.Version.Build -lt 6001) {
    $ExcludedPrefixes += "HKEY_LOCAL_MACHINE\SYSTEM\WPA"
}

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function Format-RegistryKeyResult {
    # Build a formatted string from a parsed DPID result.
    param([string]$Path, [string]$ValueName, [psobject]$ParsedObj)
    
    $f = "{0,-18}: {1}"
    Write-Output ($f -f "Registry Path", ($Path -replace '^HKEY_LOCAL_MACHINE', 'HKLM'))
    Write-Output ($f -f "Value", $ValueName)
    if ($null -ne $ParsedObj.BlobSize) { Write-Output ($f -f "BlobSize", $ParsedObj.BlobSize) }
    if ($null -ne $ParsedObj.UISize) { Write-Output ($f -f "UISize", $ParsedObj.UISize) }
    if ($null -ne $ParsedObj.MajorVersion) { Write-Output ($f -f "DPID Version", $ParsedObj.MajorVersion) }
    if ($ParsedObj.ProductKey) { Write-Color ($f -f "Product Key", $ParsedObj.ProductKey) "BgGreen" }
    if ($ParsedObj.ProductId) { Write-Output ($f -f "Product ID", $ParsedObj.ProductId) }
    if ($ParsedObj.AdvancedPid) { Write-Output ($f -f "Extended PID", $ParsedObj.AdvancedPid) }
    if ($ParsedObj.ActivationId) { Write-Output ($f -f "Activation ID", $ParsedObj.ActivationId) }
    if ($ParsedObj.EditionType) { Write-Output ($f -f "Edition", $ParsedObj.EditionType) }
    if ($ParsedObj.EditionId) { Write-Output ($f -f "Part number", $ParsedObj.EditionId) }
    if ($ParsedObj.KeyType) { Write-Output ($f -f "Key Type", $ParsedObj.KeyType) }
    if ($null -ne $ParsedObj.Lt) { Write-Output ($f -f "License Type", $ParsedObj.Lt) }
    if ($ParsedObj.EULA) { Write-Output ($f -f "EULA", $ParsedObj.EULA) }
    if ($null -ne $ParsedObj.KeyIndex) { Write-Output ($f -f "Group ID", $ParsedObj.KeyIndex) }
    if ($ParsedObj.OemId) { Write-Output ($f -f "Oem Id", $ParsedObj.OemId) }
    if ($null -ne $ParsedObj.IsUpgrade) {
        Write-Output ($f -f "Upgrade Key", $(if ($ParsedObj.IsUpgrade -eq 1) { "Yes" } else { "No" }))
    }
    if ($ParsedObj.Time) { Write-Output ($f -f "Install Time", $ParsedObj.Time) }
    if ($ParsedObj.CRC32Check) { Write-Output ($f -f "CRC32 Check", $ParsedObj.CRC32Check) }
    if ($ParsedObj.CDKey256HashCheck) { Write-Output ($f -f "CDKeySHA256 Check", $ParsedObj.CDKey256HashCheck) }
    if ($ParsedObj.Hash256Check) { Write-Output ($f -f "SHA256 Check", $ParsedObj.Hash256Check) }
}

# ===============================================================================================================================

function Invoke-RegScan {
    # Walks registry paths with a stack, looking for DigitalProductId blobs to decode.
    param(
        [string[]]$QueryPaths,
        [string[]]$ExcludePrefixes,
        [Microsoft.Win32.RegistryKey]$BaseKey
    )

    # Seed the stack with normalized relative paths
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    foreach ($path in $QueryPaths) {
        $relPath = $path -replace '^HKEY_LOCAL_MACHINE\\?|^HKLM\\?', ''
        if ($relPath -match '^HKEY_LOCAL_MACHINE$|^HKLM$') { $relPath = '' }
        $stack.Push($relPath)
    }

    $processed = @{}

    while ($stack.Count -gt 0) {
        $currentPath = $stack.Pop()
        $fullPath = if ($currentPath) { "HKEY_LOCAL_MACHINE\$currentPath" } else { "HKEY_LOCAL_MACHINE" }

        # Skip excluded prefixes (e.g. paths covered by another scan mode)
        if ($ExcludePrefixes) {
            $excluded = $false
            foreach ($prefix in $ExcludePrefixes) {
                if ($fullPath -eq $prefix -or $fullPath.StartsWith($prefix + '\')) {
                    $excluded = $true; break
                }
            }
            if ($excluded) { continue }
        }

        # Skip already-visited paths to avoid duplicates
        if ($processed.ContainsKey($fullPath)) { continue }
        $processed[$fullPath] = $true

        $key = $null
        try {
            # Open the key (root BaseKey is passed directly to avoid double-closing)
            if ($currentPath -eq '') {
                $key = $BaseKey
            }
            else {
                $key = $BaseKey.OpenSubKey($currentPath, $false)
            }

            if (-not $key) { continue }

            # Check for DPID values and decode any blobs found
            foreach ($valName in @("DigitalProductId", "DigitalProductId4")) {
                $blob = $key.GetValue($valName, $null)
                if ($blob -is [byte[]]) {
                    $parsed = Get-DigitalProductId -Blob $blob -VerifyHash:$VerifyHash
                    if ($parsed) {
                        Write-Output ""
                        Format-RegistryKeyResult -Path $fullPath -ValueName $valName -ParsedObj $parsed
                        Write-Output ""
                        Write-Output "--------------------------------------------------------"
                        $script:FoundAny = $true
                    }
                }
            }

            # Push subkeys onto the stack for continued traversal
            foreach ($sub in $key.GetSubKeyNames()) {
                $nextPath = if ($currentPath -eq '') { $sub } else { "$currentPath\$sub" }
                $stack.Push($nextPath)
            }
        }
        catch {}
        finally {
            if ($key -and $key -ne $BaseKey) { $key.Close() }
        }
    }
}

# ===============================================================================================================================
# Main execution
# ===============================================================================================================================

$script:FoundAny = $false

# Open a 64-bit registry view on systems that support it; fall back to the default hive on older versions
$viewType = "Microsoft.Win32.RegistryView" -as [type]
$baseKey = $null
if ($viewType) {
    try {
        $registry64 = [Enum]::Parse($viewType, "Registry64")
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $registry64)
    }
    catch {}
}
if (-not $baseKey) {
    $baseKey = [Microsoft.Win32.Registry]::LocalMachine
}

# ===============================================================================================================================

try {
    # Windows paths: CurrentVersion, IE Registration, and WPA (XP/2003 only)
    if ($Windows) {
        Write-Output "Scanning registry for Windows product keys..."
        $winPaths = @(
            'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion',
            'HKLM\SOFTWARE\Microsoft\Internet Explorer\Registration',
            'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion',
            'HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Registration'
        )
        if ([Environment]::OSVersion.Version.Build -lt 6001) {
            $winPaths += 'HKLM\SYSTEM\WPA'
        }
        Invoke-RegScan -QueryPaths $winPaths -BaseKey $baseKey
    }

    # Office paths: MSI-based installations only
    if ($Office) {
        Write-Output "Scanning registry for Office (MSI version) product keys..."
        Invoke-RegScan -QueryPaths @(
            'HKLM\SOFTWARE\Microsoft\Office',
            'HKLM\SOFTWARE\WOW6432Node\Microsoft\Office'
        ) -BaseKey $baseKey
    }

    # Other: full HKLM scan excluding paths already covered above
    if ($Other) {
        Write-Output "Scanning registry for Microsoft product keys other than Windows/Office..."
        Invoke-RegScan -QueryPaths @('HKLM') `
            -ExcludePrefixes $ExcludedPrefixes `
            -BaseKey $baseKey
    }
}
finally {
    if ($baseKey -and $viewType -and $baseKey -ne [Microsoft.Win32.Registry]::LocalMachine) {
        $baseKey.Close()
    }
}

# ===============================================================================================================================
# Results
# ===============================================================================================================================

Write-Output ""
if (-not $script:FoundAny) { 
    if ($Windows) {
        Write-Color "No keys found." "BgRed"
    }
    else {
        Write-Color "No keys found." "FgYellow"
    }
}
else {
    Write-Color "Note: Keys ending with 'BBBBB' are cleared (MAK or manual clear)." "FgYellow"
}
Write-Output "Done."
Write-Output ""

# ===============================================================================================================================
