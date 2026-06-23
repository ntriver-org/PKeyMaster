<#
.SYNOPSIS
    Discovers installed products eligible for phone activation and retrieves their CIDs.

.DESCRIPTION
    Queries WMI for installed but unactivated Windows/Office products with a partial
    product key. Checks each for phone activation eligibility via the SL API, then
    automatically retrieves the CID using GetCID.ps1.

.PARAMETER ExportLogs
    Enables saving of CID retrieval results and raw API payloads to disk.

.PARAMETER PassThru
    Returns structured PSObjects for each discovered product (used by the GUI to populate
    the installed products dropdown).

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\WmiSppError.ps1 for WMI error formatting.
    Requires GetCID.ps1 for Confirmation ID retrieval.
    Requires Libs\Common.ps1 for shared helper functions.

.EXAMPLE
    .\GetIidCid.ps1 -PassThru

.EXAMPLE
    .\GetIidCid.ps1 -ExportLogs
#>
param(
    [switch]$ExportLogs,
    [switch]$PassThru
)

# ===============================================================================================================================
# Initialization & dependencies
# ===============================================================================================================================

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "." }
$commonPath = Join-Path $scriptDir "libs\Common.ps1"
if (Test-Path $commonPath) { . $commonPath }

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function Get-SlInteropType([string]$LibraryName) {
    # Build a .NET type with P/Invoke for the given SL library (slc.dll or OSPPC.dll).
    if (-not $LibraryName -or $LibraryName -match '^\s*$') { return $null }

    $TB = [AppDomain]::CurrentDomain.DefineDynamicAssembly((Get-Random), 1).DefineDynamicModule((Get-Random), $False).DefineType((Get-Random))

    [void]$TB.DefinePInvokeMethod('SLOpen', $LibraryName, 22, 1, [int], @([IntPtr].MakeByRefType()), 1, 4).SetImplementationFlags(128)
    [void]$TB.DefinePInvokeMethod('SLClose', $LibraryName, 22, 1, [int], @([IntPtr]), 1, 4).SetImplementationFlags(128)
    [void]$TB.DefinePInvokeMethod('SLGetProductSkuInformation', $LibraryName, 22, 1, [int], @([IntPtr], [Guid].MakeByRefType(), [string], [uint32].MakeByRefType(), [uint32].MakeByRefType(), [IntPtr].MakeByRefType()), 1, 4).SetImplementationFlags(128)

    return $TB.CreateType()
}

# ===============================================================================================================================

function Test-PhoneActivationSupport([string]$LibraryName, [string]$Id) {
    # Does the product support phone activation? Checks for PHONE/PUBLIC EUL.

    try { $skuGuid = [Guid]$Id } catch { return $false }

    $api = Get-SlInteropType $LibraryName
    if (-not $api) { return $false }

    $handle = [IntPtr]::Zero
    try {
        if ($api::SLOpen([ref]$handle) -ne 0 -or $handle -eq [IntPtr]::Zero) { return $false }

        $cb = $dt = [uint32]0
        $buf = [IntPtr]::Zero

        return ($api::SLGetProductSkuInformation($handle, [ref]$skuGuid, 'msft:sl/EUL/PHONE/PUBLIC', [ref]$cb, [ref]$dt, [ref]$buf) -eq 0)
    }
    catch {
        return $false
    }
    finally {
        if ($handle -ne [IntPtr]::Zero) { try { $api::SLClose($handle) | Out-Null } catch {} }
    }
}

# ===============================================================================================================================

function Test-IsAdministrator {
    $isAdmin = (New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    return $isAdmin
}

# ===============================================================================================================================
# Initialization & setup
# ===============================================================================================================================

Write-Output "Get IID/CID of Unactivated Products Eligible For Phone (CID) Activation:"
Write-Output ""

$f = "{0,-18}: {1}"
$_scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$getCidScript = Join-Path $_scriptDir "GetCID.ps1"
$wmiSppError = Join-Path $_scriptDir "Libs\WmiSppError.ps1"

# WMI queries for Windows (SoftwareLicensingProduct) and Office (OfficeSoftwareProtectionProduct)
# Identify the correct system directory (handling 32-bit vs 64-bit redirection)
$SysPath = if (Test-Path "$env:SystemRoot\Sysnative") { "$env:SystemRoot\Sysnative" } else { "$env:SystemRoot\System32" }
$slcDll = "$SysPath\slc.dll"
$osppDll = 'C:\Program Files\Common Files\microsoft shared\OfficeSoftwareProtectionPlatform\OSPPC.DLL'
$BuildNumber = [System.Environment]::OSVersion.Version.Build
$RequiresAdmin = (($BuildNumber -lt 9200) -or (Test-Path $osppDll))
if ($RequiresAdmin -and -not (Test-IsAdministrator)) {
    Write-Color "Admin rights are required on Windows 7/Vista or when OSPP Office is installed." "BgRed"
    Write-Color "Run this script as Administrator and try again." "BgRed"
    Write-Output ""
    if ($PassThru) {
        return @()
    }
    return
}

$queries = @()
if (Test-Path $slcDll) {
    $queries += @{
        ClassName = 'SoftwareLicensingProduct'
        Library   = 'slc.dll'
        Query     = 'SELECT Name, ID, OfflineInstallationId FROM SoftwareLicensingProduct WHERE LicenseStatus<>1 AND PartialProductKey is not NULL'
    }
}
if (Test-Path $osppDll) {
    $queries += @{
        ClassName = 'OfficeSoftwareProtectionProduct'
        Library   = $osppDll
        Query     = 'SELECT Name, ID, OfflineInstallationId FROM OfficeSoftwareProtectionProduct WHERE LicenseStatus<>1 AND PartialProductKey is not NULL'
    }
}

$found = $false
$foundProducts = New-Object System.Collections.Generic.List[object]
$wmiErrors = New-Object System.Collections.Generic.List[object]

# ===============================================================================================================================
# Product discovery & CID retrieval
# ===============================================================================================================================

foreach ($q in $queries) {
    $items = $null

    try {
        $searcher = [wmisearcher]$q.Query
        $results = $searcher.Get()
        
        # Enumerate to trigger potential WMI COM exceptions before processing
        $enumerated = @()
        foreach ($i in $results) { $enumerated += $i }
        $items = $enumerated
    }
    catch {
        # Capture WMI errors (e.g. OSPP class not registered) for reporting at the end
        $errData = & $wmiSppError -Exception $_.Exception -PassThru
        $errObj = $null
        foreach ($e in $errData) { 
            if ($e -and $e.PSObject.Properties['ErrorCode']) { 
                $errObj = $e
                break 
            } 
        }
        
        if ($errObj) {
            $wmiErrors.Add((New-Object PSObject -Property @{
                        ClassName    = $q.ClassName
                        ErrorCode    = $errObj.ErrorCode
                        ErrorMessage = $errObj.ErrorMessage
                    }))
        }
        continue
    }

    if (-not $items) { continue }

    foreach ($item in $items) {
        $iid = ""
        if ($item.OfflineInstallationId) { $iid = $item.OfflineInstallationId -replace '\D', '' }
        if ($iid -notmatch '^\d{50}$|^\d{54}$|^\d{59}$|^\d{63}$') { continue }

        if (Test-PhoneActivationSupport $q.Library $item.ID) {
            $found = $true

            # Retrieve CID via GetCID.ps1
            $cidOut = @(& $getCidScript -InstallationId $iid -PassThru -ExportLogs:$ExportLogs)
            $cidResult = $null
            if ($cidOut.Count -gt 0) { $cidResult = $cidOut[-1] }

            # Build the display string for the Confirmation ID
            if ($cidResult -and $cidResult.CID) {
                $displayCid = $cidResult.CID
            }
            elseif ($cidResult) {
                if ($cidResult.ErrorCode) {
                    $displayCid = "{0} ({1})" -f $cidResult.ErrorCode, $cidResult.ErrorDetail
                }
                else {
                    $displayCid = $cidResult.ErrorDetail
                }
            }
            else {
                $displayCid = "Failed"
            }

            Write-Output ($f -f "Product Name", $item.Name)
            Write-Output ($f -f "Class Name", $q.ClassName)
            Write-Output ($f -f "Activation ID", $item.ID)
            Write-Output ($f -f "Installation ID", $iid)
            if ($cidResult -and $cidResult.CID) {
                Write-Color ($f -f "Confirmation ID", $displayCid) "BgGreen"
            }
            else {
                Write-Color ($f -f "Confirmation ID", $displayCid) "BgRed"
            }
            if ($ExportLogs) {
                Write-Output ($f -f "Logs saved to", (Join-Path ([Environment]::GetFolderPath("Desktop")) "PKeyMaster-Logs\GetCID"))
            }
            Write-Output ""

            # Build PassThru object for GUI consumption
            if ($PassThru) {
                $foundProducts.Add((New-Object PSObject -Property @{
                            Name           = $item.Name
                            DisplayName    = $item.Name
                            Id             = $item.ID
                            InstallationId = $iid
                            ClassName      = $q.ClassName
                            CID            = if ($cidResult) { $cidResult.CID } else { $null }
                            ErrorCode      = if ($cidResult) { $cidResult.ErrorCode } else { $null }
                            ErrorDetail    = if ($cidResult) { $cidResult.ErrorDetail } else { $null }
                        }))
            }
        }
    }
}

# ===============================================================================================================================
# Results summary
# ===============================================================================================================================

if (-not $found) {
    Write-Color "No such products were found." "FgYellow"
}

if ($wmiErrors.Count -gt 0) {
    Write-Output ""
    Write-Color "--- Query Errors ---" "BgRed"
    foreach ($err in $wmiErrors) {
        Write-Color ($f -f $err.ClassName, ('0x{0:X8} - {1}' -f $err.ErrorCode, $err.ErrorMessage)) "BgRed"
    }
}

# ===============================================================================================================================
# Object return (PassThru)
# ===============================================================================================================================

if ($PassThru) {
    return $foundProducts
}

# ===============================================================================================================================
