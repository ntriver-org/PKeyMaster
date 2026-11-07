<#
.SYNOPSIS
    Encodes and decodes Microsoft Label IDs.

.DESCRIPTION
    Encodes Group ID and Key ID into a Microsoft Label ID (GGGGG-CCC-SSS-SSS),
    or decodes an existing Label ID back into its Group ID and Key ID.

.PARAMETER Encode
    Encodes Group ID and Key ID into a Label ID.

.PARAMETER Decode
    Decodes a Label ID into its Group ID and Key ID.

.PARAMETER LabelId
    The Label ID string to decode (e.g. '03308-000-000-000').

.PARAMETER GroupId
    The group ID (Bink ID).

.PARAMETER Serial
    The product key serial number (Key ID).

.PARAMETER GetProductDetails
    Queries the PKeyConfigsMap and PreVistaRanges database to retrieve and display matching product details.

.PARAMETER PassThru
    Returns a custom PowerShell object with LabelId, Algorithm, GroupId, Serial, and ProductDetails instead of just writing to the console.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Common.psm1 for shared helper functions.

.EXAMPLE
    .\LabelId.ps1 -Encode -GroupId 3308 -Serial 0
.EXAMPLE
    .\LabelId.ps1 -Decode -LabelId "03308-000-000-000"
.EXAMPLE
    .\LabelId.ps1 -Decode -LabelId "03308-000-000-000" -GetProductDetails
#>
param(
    [switch]$Encode,
    [switch]$Decode,

    [string]$LabelId,
    [int]$GroupId = 0,
    [long]$Serial = 0,
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
# Encode / Decode processing
# ===============================================================================================================================

if (-not $Encode -and -not $Decode) {
    Write-Color "Please specify either -Encode or -Decode." "BgRed"
    return
}

$mode = if ($Encode) { "Encode" } else { "Decode" }

if ($mode -eq "Encode") {
    if ($Serial -lt 0 -or $Serial -gt 999999999) {
        Write-Color "Serial must be between 0 and 999999999." "BgRed"
        return
    }
    if ($GroupId -lt 0 -or $GroupId -gt 99999) {
        Write-Color "Group ID must be between 0 and 99999." "BgRed"
        return
    }

    $LabelId = "{0:00000}-{1:000-000-000}" -f $GroupId, $Serial
}
else {
    $cleanLabelId = if ($LabelId) { $LabelId.Trim() } else { "" }
    if (-not $cleanLabelId) {
        Write-Color "Please provide -LabelId to decode." "BgRed"
        return
    }
    if ($cleanLabelId -notmatch '^(\d{5})-(\d{3}-\d{3}-\d{3})$') {
        Write-Color "'$LabelId' is not a valid Label ID." "BgRed"
        return
    }

    $GroupId = [int]$matches[1]
    $Serial = [long]($matches[2] -replace '-')
    $LabelId = $cleanLabelId
}

# ===============================================================================================================================
# Product Details retrieval
# ===============================================================================================================================

$candidates = @()

if ($GetProductDetails) {
    # Group ID 2 exists in both PKey980 (Windows 98) and PKey2005 (Windows Redpill)
    if ($GroupId -eq 2) {
        $dPre = Get-ProductDetails -GroupId $GroupId -KeyId $Serial -SkipVistaAndLater
        if ($dPre -and $dPre.Matches) {
            $algoPre = if ($dPre.AlgorithmId -match "986") { "PKey986" } else { "PKey980" }
            $candidates += @{ Algorithm = $algoPre; ProductDetails = $dPre }
        }

        $dPost = Get-ProductDetails -GroupId $GroupId -KeyId $Serial -SkipPreVista
        if ($dPost -and $dPost.Description) {
            $algoPost = if ($dPost.AlgorithmId -match "2009") { "PKey2009" } else { "PKey2005" }
            $candidates += @{ Algorithm = $algoPost; ProductDetails = $dPost }
        }
    }
    else {
        $d = Get-ProductDetails -GroupId $GroupId -KeyId $Serial
        if ($d -and ($d.Description -or $d.Matches)) {
            $algo = if ($d.AlgorithmId -match "2009") { "PKey2009" }
            elseif ($d.AlgorithmId -match "2005") { "PKey2005" }
            elseif ($d.AlgorithmId -match "986") { "PKey986" }
            else { "PKey980" }
            $candidates += @{ Algorithm = $algo; ProductDetails = $d }
        }
    }
}

if ($candidates.Count -eq 0) {
    $candidates = @( @{ Algorithm = $null; ProductDetails = $null } )
}

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

$f = "{0,-18}: {1}"
$lineSeparator = @(
    "",
    "______________________________________________________________"
)

for ($i = 0; $i -lt $candidates.Count; $i++) {
    $c = $candidates[$i]

    if ($i -gt 0) {
        Write-Output $lineSeparator
    }

    Write-Output ""
    if ($candidates.Count -gt 1) {
        Write-Color "[$($c.Algorithm)]" "FgYellow"
    }
    Write-Color ($f -f "Label ID", $LabelId) "BgGreen"
    Write-Output ($f -f "Group ID", ("{0} (0x{0:X})" -f $GroupId))
    Write-Output ($f -f "Key ID", ("{0} (0x{0:X})" -f $Serial))
    if ($c.ProductDetails) {
        Write-Output ""
        Write-ProductDetails $c.ProductDetails $f -Exclude "LabelId"
    }
}
Write-Output ""

# ===============================================================================================================================
# Object return (PassThru)
# ===============================================================================================================================

if ($PassThru) {
    $results = @()
    foreach ($c in $candidates) {
        $results += New-Object PSObject -Property @{
            LabelId        = $LabelId
            Algorithm      = $c.Algorithm
            GroupId        = $GroupId
            Serial         = $Serial
            ProductDetails = $c.ProductDetails
        }
    }
    if ($results.Count -eq 1) { $results[0] } else { $results }
}

# ===============================================================================================================================
