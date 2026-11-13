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
    The group ID (Bink ID). Supports values from 0 to 999999.

.PARAMETER Serial
    The product key serial number (Key ID).

.PARAMETER GetProductDetails
    Queries the PKeyConfigsMap and PreVistaRanges database to retrieve and display matching product details.

.PARAMETER PassThru
    Returns a custom PowerShell object with LabelId, Algorithm, GroupId, Serial, Note, and ProductDetails instead of just writing to the console.

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
    if ($GroupId -lt 0 -or $GroupId -gt 999999) {
        Write-Color "Group ID must be between 0 and 999999." "BgRed"
        return
    }

    $labelGroupId = [int]($GroupId % 100000)
    $encodeNote = if ($GroupId -gt 99999) {
        "Only the last 5 digits of the Group ID are encoded."
    }
    $LabelId = "{0:00000}-{1:000-000-000}" -f $labelGroupId, $Serial
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
    # 1. Pre-Vista (PKey980 / PKey986): valid for Group IDs 0..137
    if ($GroupId -le 137) {
        $dPre = Get-ProductDetails -GroupId $GroupId -KeyId $Serial -Algorithm "PKey980"
        if ($dPre -and $dPre.AlgorithmId -and ($dPre.Matches.Count -gt 0 -or $dPre.Description)) {
            $algoPre = if ($dPre.AlgorithmId -match "986") { "PKey986" } else { "PKey980" }
            $candidates += @{
                Algorithm      = $algoPre
                GroupId        = $GroupId
                ProductDetails = $dPre
            }
        }
    }

    # 2. PKey2005: valid for standard 1-to-3 digit Group IDs (<= 999)
    if ($GroupId -le 999) {
        $d2005 = Get-ProductDetails -GroupId $GroupId -KeyId $Serial -Algorithm "PKey2005"
        if ($d2005 -and $d2005.AlgorithmId -and $d2005.Description) {
            $candidates += @{
                Algorithm      = "PKey2005"
                GroupId        = $GroupId
                ProductDetails = $d2005
            }
        }
    }

    # 3. PKey2009: handles 6-digit Group IDs (100000..100063 and 999999) as well as standard Group IDs
    $g2009 = if ($GroupId -le 63) { 100000 + $GroupId } elseif ($GroupId -eq 99999) { 999999 } else { $GroupId }
    $d2009 = Get-ProductDetails -GroupId $g2009 -KeyId $Serial -Algorithm "PKey2009"
    if ($d2009 -and $d2009.AlgorithmId -and $d2009.Description) {
        $candidates += @{
            Algorithm      = "PKey2009"
            GroupId        = $g2009
            ProductDetails = $d2009
            Note           = if ($g2009 -gt 99999) { "Only the last 5 digits of the Group ID are encoded." }
        }
    }
}

if ($candidates.Count -eq 0) {
    $candidates = @( @{
            Algorithm      = $null
            GroupId        = $GroupId
            ProductDetails = $null
            Note           = $encodeNote
        } )
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
    $displayGid = if ($null -ne $c.GroupId) { $c.GroupId } else { $GroupId }
    Write-Output ($f -f "Group ID", ("{0} (0x{0:X})" -f $displayGid))
    Write-Output ($f -f "Key ID", ("{0} (0x{0:X})" -f $Serial))
    if ($c.Note) {
        Write-Color ($f -f "Note", $c.Note) "BgGray"
    }
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
        $displayGid = if ($null -ne $c.GroupId) { $c.GroupId } else { $GroupId }
        $results += New-Object PSObject -Property @{
            LabelId        = $LabelId
            Algorithm      = $c.Algorithm
            GroupId        = $displayGid
            Serial         = $Serial
            Note           = $c.Note
            ProductDetails = $c.ProductDetails
        }
    }
    if ($results.Count -eq 1) { $results[0] } else { $results }
}

# ===============================================================================================================================
