<#
.SYNOPSIS
    Looks up product details by Activation ID or Part Number.

.DESCRIPTION
    Looks up product licensing details using an Activation ID (GUID) or a
    Part Number / SKU (PKPN) across local PKeyConfig files, falling back to
    the Microsoft Store Display Catalog API when not found locally.

.PARAMETER ActivationId
    The Activation ID GUID to look up (e.g. '4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c').

.PARAMETER PartNumber
    The product part number or SKU to look up (e.g. '[TH]X19-98841', 'X21-83697').

.PARAMETER Id
    Positional search string; automatically detected as an Activation ID (if GUID) or Part Number.

.PARAMETER PassThru
    Returns a custom PowerShell object containing the matched product properties instead of only writing to the console.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Common.psm1 and Libs\Network.psm1.

.EXAMPLE
    .\ActivationId-PartNumber.ps1 -ActivationId "4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c"
.EXAMPLE
    .\ActivationId-PartNumber.ps1 -PartNumber "[TH]X19-98841"
.EXAMPLE
    .\ActivationId-PartNumber.ps1 "ceae6266-8034-48db-92e4-fc94eb11742f"
.EXAMPLE
    .\ActivationId-PartNumber.ps1 "X21-83697"
#>
param(
    [string]$Id,
    [string]$ActivationId,
    [string]$PartNumber,
    [switch]$PassThru
)

# ===============================================================================================================================
# Initialization & dependencies
# ===============================================================================================================================

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "." }
Import-Module "$scriptDir\..\Libs\Common.psm1"
Import-Module "$scriptDir\..\Libs\Network.psm1"

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function Get-StoreTitleByToken($token) {
    if (-not (Get-Command Invoke-GetTextRequest -ErrorAction SilentlyContinue)) { return $null }
    $url = "https://displaycatalog.mp.microsoft.com/v7.0/products/lookup?alternateId=LegacyTokenIdentifier&value=${token}&market=US&languages=en-us"
    $res = Invoke-GetTextRequest $url $null "" "" "json"
    if ($res -and $res.Body) {
        try {
            $obj = Read-Json $res.Body
            if ($obj -and $obj.Products -and $obj.Products.Count -gt 0) {
                return $obj.Products[0].LocalizedProperties[0].ProductTitle
            }
        }
        catch {}
    }
    return $null
}

# ===============================================================================================================================
# Parameter detection
# ===============================================================================================================================

if ($ActivationId) {
    try { $targetActId = ([guid]$ActivationId.Trim()).ToString() }
    catch {
        Write-Color "'$ActivationId' is not a valid Activation ID." "BgRed"
        return
    }
}
elseif ($PartNumber) {
    $targetPartNum = $PartNumber.Trim()
    if ($targetPartNum -notmatch '^[^-]+-[^-]+$') {
        Write-Color "'$PartNumber' is not a valid Part Number." "BgRed"
        return
    }
}
elseif ($Id) {
    $cleanId = $Id.Trim()
    try { $targetActId = ([guid]$cleanId).ToString() }
    catch {
        if ($cleanId -match '^[^-]+-[^-]+$') {
            $targetPartNum = $cleanId
        }
        else {
            Write-Color "'$Id' is not a valid Activation ID or Part Number." "BgRed"
            return
        }
    }
}
else {
    Write-Color "Please provide an -ActivationId or -PartNumber to look up." "BgRed"
    return
}

# ===============================================================================================================================
# Product lookup
# ===============================================================================================================================

$result = $null

$baseConfigsDir = Join-Path $scriptDir "..\..\PKeyConfigs"
$configsMap = Get-PKeyConfigsMap
if ($baseConfigsDir -and (Test-Path -LiteralPath $baseConfigsDir) -and $configsMap) {
    foreach ($entry in ($configsMap | Where-Object { $_.Profile -notmatch "custom" })) {
        $configPath = Join-Path $baseConfigsDir $entry.Path.TrimStart('\')
        if (-not (Test-Path -LiteralPath $configPath)) { continue }

        $info = if ($targetPartNum) {
            Get-PKeyConfigInfo -FilePath $configPath -PartNumber $targetPartNum
        }
        else {
            Get-PKeyConfigInfo -FilePath $configPath -ActivationId $targetActId
        }

        if ($info -and $info.Description) {
            $result = New-Object PSObject -Property @{
                Profile      = $entry.Profile
                Description  = $info.Description
                Edition      = $info.Edition
                KeyType      = $info.KeyType
                EULA         = $info.EULA
                PartNumber   = $info.PartNumber
                AlgorithmId  = $info.AlgorithmId
                ActivationId = $info.ActivationId.Trim('{', '}')
                IsValid      = $info.IsValid
                IsRandomized = $info.IsRandomized
                ConfigFile   = $entry.Path.TrimStart('\')
                Source       = "PKeyConfigs"
            }
            break
        }
    }
}

if (-not $result) {
    $token = if ($targetPartNum) { $targetPartNum } else { $targetActId }
    $title = Get-StoreTitleByToken $token
    if ($title) {
        $result = New-Object PSObject -Property @{
            Description  = $title
            PartNumber   = $targetPartNum
            ActivationId = $targetActId
            Source       = "Store API"
            IsOnline     = $true
        }
    }
}

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

if (-not $result) {
    Write-Color "No matching product details found." "BgRed"
    return
}

$f = "{0,-18}: {1}"

Write-Output ""
if ($result.IsOnline) {
    if ($result.PartNumber) {
        Write-Output ($f -f "Part number", $result.PartNumber)
    }
    else {
        Write-Output ($f -f "Activation ID", $result.ActivationId)
    }
    Write-Color ($f -f "Product Name", $result.Description) "BgGreen"
}
else {
    Write-ProductDetails $result $f
}
if ($result.Source) { Write-Output ($f -f "Source", $result.Source) }
Write-Output ""

# ===============================================================================================================================
# Object return (PassThru)
# ===============================================================================================================================

if ($PassThru) { return $result }

# ===============================================================================================================================
