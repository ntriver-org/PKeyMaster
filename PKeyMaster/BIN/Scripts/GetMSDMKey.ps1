<#
.SYNOPSIS
    Retrieves the MSDM (OEM BIOS/UEFI embedded) product key.

.DESCRIPTION
    Queries SoftwareLicensingService WMI for OA3 (OEM Activation 3) properties,
    which include the product key embedded in BIOS/UEFI by the manufacturer.
    Available on Windows 8.1+.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Windows 8.1+ (build 9600+).
    Requires Libs\WmiSppError.ps1 for WMI error formatting.
    Requires Libs\Common.ps1 for shared helper functions.

.EXAMPLE
    .\GetMSDMKey.ps1
#>

# ===============================================================================================================================
# Initialization & setup
# ===============================================================================================================================

$_scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $_scriptDir) { $_scriptDir = "." }
$wmiSppError = Join-Path $_scriptDir 'Libs\WmiSppError.ps1'
$commonPath = Join-Path $_scriptDir 'libs\Common.ps1'
if (Test-Path $commonPath) { . $commonPath }

Write-Output 'Checking MSDM (BIOS/UEFI) key...'
Write-Output ''

# ===============================================================================================================================
# OS version check
# ===============================================================================================================================

$buildNumber = [System.Environment]::OSVersion.Version.Build

if ($buildNumber -lt 9600) {
    Write-Color 'This option is not available on Windows versions lower than 8.1' "BgRed"
    return
}

# ===============================================================================================================================
# WMI query
# ===============================================================================================================================

$spp = $null

try {
    $query = "SELECT * FROM SoftwareLicensingService"
    $spp = ([wmisearcher]$query).Get() | Select-Object -First 1
}
catch {
    & $wmiSppError -Exception $_.Exception
    return
}

if (-not $spp) {
    Write-Color "Error: SoftwareLicensingService could not be queried." "BgRed"
    return
}

# ===============================================================================================================================
# OA3 property extraction
# ===============================================================================================================================

$f = "{0,-35}: {1}"
$hasKey = $false

# Enumerate all OA3 properties (OA3xOriginalProductKey, OA3xOriginalProductKeyDescription, etc.)
foreach ($prop in $spp.Properties) {
    if ($prop.Name -match '^OA3') {
        $val = $prop.Value
        if ($val) {
            if ($prop.Name -eq 'OA3xOriginalProductKey') {
                $hasKey = $true
            }
        }
        else {
            $val = "N/A"
        }
        Write-Output ($f -f $prop.Name, $val)
    }
}

# ===============================================================================================================================
# Result
# ===============================================================================================================================

Write-Output ""
if ($hasKey) {
    Write-Color "Result: MSDM key found in BIOS/UEFI." "BgGreen"
}
else {
    Write-Color "Result: No MSDM key found in BIOS/UEFI." "FgYellow"
}
Write-Output ""

# ===============================================================================================================================
