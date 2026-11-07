<#
.SYNOPSIS
    Encodes and decodes Microsoft ActConfig IDs.

.DESCRIPTION
    Encodes Activation ID (ActId), Upgrade flag, Group ID, Key ID, and Security into
    an ActConfig ID (PKey2005 or PKey2009), or decodes an existing ActConfig ID to show its details.

.PARAMETER Encode
    Encodes Activation ID (ActId), Upgrade flag, Group ID, Key ID, and Security into an ActConfig ID.

.PARAMETER Decode
    Decodes an ActConfig ID string to show its details.

.PARAMETER ActConfigId
    The ActConfig ID string to decode (e.g., 'msft2009:GUID&Base64...' or 'msft2005:GUID&Base64...').

.PARAMETER ActId
    The Activation ID GUID (e.g., '55c92734-d682-4d71-983e-d6ec3f16059f').

.PARAMETER Upgrade
    Upgrade flag ($true / $false).

.PARAMETER Group
    The group ID (required for PKey2009).

.PARAMETER Serial
    The product key serial number (Key ID).

.PARAMETER Security
    The security value.

.PARAMETER Algorithm
    The algorithm type: 'PKey2005' or 'PKey2009'.

.PARAMETER GetProductDetails
    Queries the PKeyConfigsMap and PreVistaRanges database to retrieve and display matching product details.

.PARAMETER PassThru
    Returns a custom PowerShell object with the properties instead of just writing to the console.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Common.psm1 for shared helper functions.

.EXAMPLE
    .\ActConfigId.ps1 -Decode -ActConfigId "msft2009:55c92734-d682-4d71-983e-d6ec3f16059f&Kpq3jjQAWBTMftxHAA=="
.EXAMPLE
    .\ActConfigId.ps1 -Decode -ActConfigId "msft2009:55c92734-d682-4d71-983e-d6ec3f16059f&Kpq3jjQAWBTMftxHAA==" -GetProductDetails
.EXAMPLE
    .\ActConfigId.ps1 -Encode -Algorithm "PKey2009" -ActId "55c92734-d682-4d71-983e-d6ec3f16059f" -Group 105 -Serial 123456789 -Security 9876543210123
#>
param(
    [switch]$Encode,
    [switch]$Decode,

    [string]$ActConfigId,

    [string]$ActId,
    [bool]$Upgrade = $false,
    $Group = $null,
    [long]$Serial = 0,
    [long]$Security = 0,
    [string]$Algorithm,
    [switch]$GetProductDetails,
    [switch]$PassThru
)

# ===============================================================================================================================
# Initialization & dependencies
# ===============================================================================================================================

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "." }
Import-Module "$scriptDir\..\Libs\Common.psm1"

# ===============================================================================================================================
# Helper bit-manipulation functions
# ===============================================================================================================================

function Get-BitField($Data, $Offset, $Length) {
    [int64]$result = 0
    [int64]$mask = 1
    $powers = @(1, 2, 4, 8, 16, 32, 64, 128)
    for ($bit = 0; $bit -lt $Length; $bit++) {
        $byteIndex = [int][Math]::Floor(($Offset + $bit) / 8)
        $bitIndex = ($Offset + $bit) % 8
        if (($Data[$byteIndex] -band $powers[$bitIndex]) -ne 0) {
            $result = $result -bor $mask
        }
        $mask = $mask * 2
    }
    return $result
}

function Write-BitField($Data, $Offset, $Length, [uint64]$Value) {
    [uint64]$valueMask = 1
    $powers = @(1, 2, 4, 8, 16, 32, 64, 128)
    for ($bit = 0; $bit -lt $Length; $bit++) {
        if (($Value -band $valueMask) -ne 0) {
            $byteIndex = [int][Math]::Floor(($Offset + $bit) / 8)
            $bitIndex = ($Offset + $bit) % 8
            $Data[$byteIndex] = [byte]($Data[$byteIndex] -bor $powers[$bitIndex])
        }
        $valueMask = $valueMask * 2
    }
}

# ===============================================================================================================================
# Encode / Decode processing
# ===============================================================================================================================

if (-not $Encode -and -not $Decode) {
    Write-Color "Please specify either -Encode or -Decode." "BgRed"
    return
}

$mode = if ($Encode) { "Encode" } else { "Decode" }
$guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

if ($mode -eq "Decode") {
    if (-not $ActConfigId) {
        Write-Color "'$ActConfigId' is not a valid ActConfig ID." "BgRed"
        return
    }

    $cleanActConfigId = $ActConfigId.Trim()
    if ($cleanActConfigId -notmatch "^(msft2005|msft2009):($guidPattern)&([A-Za-z0-9+/=]+)$") {
        Write-Color "'$ActConfigId' is not a valid ActConfig ID." "BgRed"
        return
    }

    $Algorithm = $matches[1]
    $ActId = $matches[2].ToLower()
    $base64 = $matches[3]
    $ActConfigId = $cleanActConfigId

    try {
        $data = [Convert]::FromBase64String($base64)
    }
    catch {
        Write-Color "'$ActConfigId' is not a valid ActConfig ID." "BgRed"
        return
    }

    $expectedLen = if ($Algorithm -eq "msft2009") { 13 } else { 12 }
    if (-not ($data -is [byte[]]) -or $data.Length -ne $expectedLen) {
        Write-Color "'$ActConfigId' is not a valid ActConfig ID." "BgRed"
        return
    }

    $Upgrade = ([int](Get-BitField $data 0 1) -eq 1)
    $Serial = Get-BitField $data 1 30

    if ($Algorithm -eq "msft2005") {
        $Group = $null
        $Security = Get-BitField $data 31 20
    }
    else {
        $Group = [int](Get-BitField $data 31 20)
        $Security = Get-BitField $data 51 53
    }
}
else {
    if (-not $Algorithm -or ($Algorithm -notmatch "2005|2009")) {
        Write-Color "Please specify -Algorithm ('PKey2005' or 'PKey2009') to encode an ActConfig ID." "BgRed"
        return
    }
    if (-not $ActId -or -not $PSBoundParameters.ContainsKey('Security')) {
        Write-Color "Please provide -ActId and -Security to encode an ActConfig ID." "BgRed"
        return
    }

    $cleanActId = $ActId.Trim()
    if ($cleanActId -notmatch "^$guidPattern$") {
        Write-Color "'$ActId' is not a valid Activation ID." "BgRed"
        return
    }
    $ActId = $cleanActId.ToLower()
    $is2009 = ($Algorithm -match "2009")

    if ($is2009) {
        if (-not $PSBoundParameters.ContainsKey('Group') -or $null -eq $Group) {
            Write-Color "Please provide -Group to encode a PKey2009 ActConfig ID." "BgRed"
            return
        }
        $Algorithm = "msft2009"
        $data = New-Object byte[] 13
        $upgVal = if ($Upgrade) { 1 } else { 0 }
        Write-BitField $data 0 1 ([uint64]$upgVal)
        Write-BitField $data 1 30 ([uint64][int64]$Serial)
        Write-BitField $data 31 20 ([uint64][int64]$Group)
        Write-BitField $data 51 53 ([uint64][int64]$Security)
        $ActConfigId = "msft2009:{0}&{1}" -f $ActId, [Convert]::ToBase64String($data)
    }
    else {
        $Algorithm = "msft2005"
        $data = New-Object byte[] 12
        $upgVal = if ($Upgrade) { 1 } else { 0 }
        Write-BitField $data 0 1 ([uint64]$upgVal)
        Write-BitField $data 1 30 ([uint64][int64]$Serial)
        Write-BitField $data 31 20 ([uint64][int64]$Security)
        $ActConfigId = "msft2005:{0}&{1}" -f $ActId, [Convert]::ToBase64String($data)
        $Group = $null
    }
}

$productDetails = if ($GetProductDetails -and $null -ne $Group) { Get-ProductDetails -GroupId $Group -KeyId $Serial -SkipPreVista } else { $null }

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

$f = "{0,-18}: {1}"

Write-Output ""
Write-Color ($f -f "ActConfig ID", $ActConfigId) "BgGreen"
Write-Output ($f -f "Algorithm", $Algorithm)
Write-Output ($f -f "Activation ID", $ActId)
Write-Output ($f -f "Upgrade", $(if ($Upgrade) { "Yes" } else { "No" }))
if ($null -ne $Group) {
    Write-Output ($f -f "Group ID", ("{0} (0x{0:X})" -f $Group))
}
Write-Output ($f -f "Key ID", ("{0} (0x{0:X})" -f $Serial))
if ($null -ne $Security) {
    Write-Output ($f -f "Security", ("{0} (0x{0:X})" -f $Security))
}
if ($GetProductDetails -and $productDetails) {
    Write-Output ""
    Write-ProductDetails $productDetails $f -Exclude "ActivationId"
}
Write-Output ""

# ===============================================================================================================================
# Object return (PassThru)
# ===============================================================================================================================

if ($PassThru) {
    New-Object PSObject -Property @{
        ActConfigId    = $ActConfigId
        Algorithm      = $Algorithm
        ActivationId   = $ActId
        Upgrade        = [bool]$Upgrade
        Group          = $Group
        Serial         = $Serial
        Security       = $Security
        ProductDetails = $productDetails
    }
}

# ===============================================================================================================================
