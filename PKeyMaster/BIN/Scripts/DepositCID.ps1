<#
.SYNOPSIS
    Deposits a Confirmation ID (CID) to activate an installed Windows or Office product.

.DESCRIPTION
    Locates an installed product by WMI class name, Activation ID, and Installation ID,
    then calls 'DepositOfflineConfirmationId' to deposit the Confirmation ID and activate it.

.PARAMETER ClassName
    The WMI class name representing the product (e.g., SoftwareLicensingProduct or OfficeSoftwareProtectionProduct).

.PARAMETER ActivationId
    The unique GUID string representing the product's Activation ID.

.PARAMETER InstallationId
    The 54 or 63-digit Installation ID associated with the product.

.PARAMETER ConfirmationId
    The Confirmation ID to deposit into the system.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\WmiSppError.ps1 for WMI error formatting.
    Requires Libs\Common.ps1 for shared helper functions.

.EXAMPLE
    .\DepositCID.ps1 -ClassName "SoftwareLicensingProduct" -ActivationId "xxxxx-..." -InstallationId "1234..." -ConfirmationId "9876..."
#>
param(
    [string]$ClassName = '',
    [string]$ActivationId = '',
    [string]$InstallationId = '',
    [string]$ConfirmationId = ''
)

# ===============================================================================================================================
# Initialization & setup
# ===============================================================================================================================

$_scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $_scriptDir) { $_scriptDir = "." }
$wmiSppError = Join-Path $_scriptDir 'Libs\WmiSppError.ps1'
$commonPath = Join-Path $_scriptDir 'libs\Common.ps1'
if (Test-Path $commonPath) { . $commonPath }

# Standard output formatter
$f = "{0,-18}: {1}"

function Test-IsAdministrator {
    $isAdmin = (New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    return $isAdmin
}

$BuildNumber = [System.Environment]::OSVersion.Version.Build
$osppDll = 'C:\Program Files\Common Files\microsoft shared\OfficeSoftwareProtectionPlatform\OSPPC.DLL'
$RequiresAdmin = (($BuildNumber -lt 9200) -or (Test-Path $osppDll))
if ($RequiresAdmin -and -not (Test-IsAdministrator)) {
    Write-Color "Admin rights are required on Windows 7/Vista or when OSPP Office is installed." "BgRed"
    Write-Color "Run this script as Administrator and try again." "BgRed"
    Write-Output ""
    return
}

# ===============================================================================================================================
# Parameter validation
# ===============================================================================================================================

if (-not $ConfirmationId) { 
    Write-Color ($f -f "Error", "-ConfirmationId is required.") "BgRed"
    return 
}

if (-not $ClassName) { 
    Write-Color ($f -f "Error", "-ClassName is required.") "BgRed"
    return 
}

if (-not $ActivationId) { 
    Write-Color ($f -f "Error", "-ActivationId is required.") "BgRed"
    return 
}

if (-not $InstallationId) { 
    Write-Color ($f -f "Error", "-InstallationId is required.") "BgRed"
    return 
}

if ($InstallationId -notmatch '^\d+$') { 
    Write-Color ($f -f "Error", "-InstallationId must be digits only.") "BgRed"
    return 
}

if ($ConfirmationId -notmatch '^\d+$') { 
    Write-Color ($f -f "Error", "-ConfirmationId must be digits only.") "BgRed"
    return 
}

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

Write-Output ""
Write-Output "--- Deposit Confirmation ID ---"
Write-Output ""
Write-Output ($f -f "Class Name", $ClassName)
Write-Output ($f -f "Activation ID", $ActivationId)
Write-Output ($f -f "Installation ID", $InstallationId)
Write-Output ($f -f "Confirmation ID", $ConfirmationId)

# ===============================================================================================================================
# Product lookup via WMI
# ===============================================================================================================================

$product = $null

try {
    # Query WMI for the product matching Activation ID and Installation ID
    $query = "SELECT * FROM $ClassName WHERE ID = '$ActivationId' AND OfflineInstallationId = '$InstallationId'"
    $product = ([wmisearcher]$query).Get() | Select-Object -First 1
}
catch {
    & $wmiSppError -Exception $_.Exception
    return
}

if (-not $product) {
    Write-Output ""
    Write-Color ($f -f "Error", "The specified installed product could not be found.") "BgRed"
    return
}

# ===============================================================================================================================
# Confirmation ID deposition
# ===============================================================================================================================

$returnValue = -1

try {
    # Deposit the confirmation ID via WMI
    $result = $product.DepositOfflineConfirmationId($InstallationId, $ConfirmationId)

    $returnValue = [int]$result.ReturnValue
}
catch {
    # Output detailed error using our library if the WMI method throws an exception
    & $wmiSppError -Exception $_.Exception
    return
}

# ===============================================================================================================================
# Result evaluation
# ===============================================================================================================================

Write-Output ($f -f "Return Value", $returnValue)

if ($returnValue -eq 0) {
    Write-Color ($f -f "Result", "Confirmation ID deposited successfully.") "BgGreen"
}
else {
    Write-Color ($f -f "Result", "Failed to deposit Confirmation ID.") "BgRed"
}

# ===============================================================================================================================
