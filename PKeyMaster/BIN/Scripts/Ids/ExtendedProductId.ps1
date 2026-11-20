<#
.SYNOPSIS
    Encodes and decodes Microsoft Extended Product ID (EPID / Advanced PID).

.DESCRIPTION
    Encodes product key details (MPC, Group ID, Serial, and License Type) into a
    Microsoft Extended Product ID (EPID), or decodes an existing EPID string to show its details.

.PARAMETER Encode
    Encodes product key details into a Microsoft Extended Product ID.

.PARAMETER Decode
    Decodes an Extended Product ID string to show its details.

.PARAMETER ExtendedProductId
    The Extended Product ID string to decode (e.g. '00000-00105-123-456789-02-1033-19045.0000-3042026').

.PARAMETER GroupId
    The group ID (Bink ID). Supports values from 0 to 999999.

.PARAMETER Serial
    The product key serial number (Key ID).

.PARAMETER LicenseType
    The numeric License Type code.

.PARAMETER MPC
    Microsoft Product Code prefix (default: '00000').

.PARAMETER GetProductDetails
    Queries the PKeyConfigsMap and PreVistaRanges database to retrieve and display matching product details.

.PARAMETER PassThru
    Returns a custom PowerShell object with the Extended Product ID properties and Algorithm instead of just writing to the console.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Common.psm1 for shared helper functions.

.EXAMPLE
    .\ExtendedProductId.ps1 -Encode -GroupId 105 -Serial 123456789 -LicenseType 2
.EXAMPLE
    .\ExtendedProductId.ps1 -Decode -ExtendedProductId "00000-00105-123-456789-02-1033-19045.0000-3042026"
.EXAMPLE
    .\ExtendedProductId.ps1 -Decode -ExtendedProductId "00000-00105-123-456789-02-1033-19045.0000-3042026" -GetProductDetails
#>
param(
    [switch]$Encode,
    [switch]$Decode,

    [string]$ExtendedProductId,

    [int]$GroupId = 0,
    [long]$Serial = 0,
    [int]$LicenseType = 0,
    [string]$MPC = "00000",
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
# Helper lookups
# ===============================================================================================================================

function Get-LicenseTypeName([int]$Code) {
    switch ($Code) {
        0 { return "Retail" }
        1 { return "Retail:Upgrade" }
        2 { return "OEM" }
        3 { return "Volume" }
        4 { return "PGS:TB" }
        6 { return "MSDN (Channel 335)" }
        default { return "Unknown" }
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

if ($mode -eq "Decode") {
    $cleanEpid = if ($ExtendedProductId) { $ExtendedProductId.Trim() } else { "" }
    if (-not $cleanEpid) {
        Write-Color "Please provide -ExtendedProductId to decode." "BgRed"
        return
    }
    $pattern = '^(\d{5})-(\d{5})-(\d{3})-(\d{6})-(\d{2})-(\d+)-(\d+(?:\.\d+)?)-(\d{7})$'

    if ($cleanEpid -notmatch $pattern) {
        Write-Color "'$ExtendedProductId' is not a valid Extended Product ID." "BgRed"
        return
    }

    $MPC = $matches[1]
    $GroupId = [int]$matches[2]
    $channel = [int]$matches[3]
    $sequence = [int]$matches[4]
    $LicenseType = [int]$matches[5]
    $LangId = [int]$matches[6]
    $OSBuild = $matches[7]
    $dayOfYear = [int]$matches[8].Substring(0, 3)
    $year = [int]$matches[8].Substring(3, 4)

    $Serial = [long]$channel * 1000000 + $sequence
    $Date = try { (Get-Date -Year $year -Month 1 -Day 1).AddDays($dayOfYear - 1) } catch { }
    $ExtendedProductId = $cleanEpid
}
else {
    if ($Serial -lt 0 -or $Serial -gt 999999999) {
        Write-Color "Serial must be between 0 and 999999999." "BgRed"
        return
    }
    if ($GroupId -lt 0 -or $GroupId -gt 999999) {
        Write-Color "Group ID must be between 0 and 999999." "BgRed"
        return
    }
    if (@(0, 1, 2, 3, 4, 6) -notcontains $LicenseType) {
        Write-Color "License Type must be 0, 1, 2, 3, 4, or 6." "BgRed"
        return
    }
    if (-not $MPC -or $MPC.Trim() -notmatch '^\d{5}$') {
        Write-Color "MPC must be a 5-digit numeric string." "BgRed"
        return
    }

    $MPC = $MPC.Trim()

    $LangId = try { [System.Globalization.CultureInfo]::InstalledUICulture.LCID } catch { 1033 }
    $buildInt = [Environment]::OSVersion.Version.Build
    $OSBuild = "{0:D4}.0000" -f $buildInt
    $Date = Get-Date

    $channel = [int]([Math]::Floor($Serial / 1000000))
    $sequence = [int]($Serial % 1000000)
    $dayOfYear = [int]$Date.DayOfYear
    $year = [int]$Date.Year

    $epidGroupId = [int]($GroupId % 100000)
    $encodeNote = if ($GroupId -gt 99999) {
        "Only the last 5 digits of the Group ID are encoded."
    }

    $ExtendedProductId = "{0}-{1:D5}-{2:D3}-{3:D6}-{4:D2}-{5:D4}-{6}-{7:D3}{8:D4}" -f (
        $MPC,
        $epidGroupId,
        $channel,
        $sequence,
        $LicenseType,
        $LangId,
        $OSBuild,
        $dayOfYear,
        $year
    )
}

$ltName = Get-LicenseTypeName $LicenseType
$langName = try { [System.Globalization.CultureInfo]::GetCultureInfo($LangId).DisplayName } catch { "Unknown" }

# ===============================================================================================================================
# Product Details retrieval
# ===============================================================================================================================

$candidates = @()

if ($GetProductDetails) {
    # 1. Pre-Vista (PKey980 / PKey986): valid for Group IDs 0..137
    if ($GroupId -le 137) {
        $algoPre = if ($GroupId -ge 0x40) { "PKey986" } else { "PKey980" }
        $dPre = Get-ProductDetails -GroupId $GroupId -KeyId $Serial -Algorithm $algoPre
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
    Write-Color ($f -f "Extended PID", $ExtendedProductId) "BgGreen"
    Write-Output ($f -f "MPC", $MPC)
    $displayGid = if ($null -ne $c.GroupId) { $c.GroupId } else { $GroupId }
    Write-Output ($f -f "Group ID", ("{0} (0x{0:X})" -f $displayGid))
    Write-Output ($f -f "Key ID", ("{0} (0x{0:X})" -f $Serial))
    Write-Output ($f -f "License Type", ("{0} ({1})" -f $LicenseType, $ltName))
    Write-Output ($f -f "Language ID", ("{0} ({1})" -f $LangId, $langName))
    Write-Output ($f -f "OS Build", $OSBuild)
    Write-Output ($f -f "Date", "$(if ($Date) { $Date.ToString('yyyy-MM-dd ') })(Day $dayOfYear, $year)")
    if ($c.Note) {
        Write-Color ($f -f "Note", $c.Note) "BgGray"
    }
    if ($c.ProductDetails) {
        Write-Output ""
        Write-ProductDetails $c.ProductDetails $f
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
            ExtendedProductId = $ExtendedProductId
            Algorithm         = $c.Algorithm
            MPC               = $MPC
            GroupId           = $displayGid
            Serial            = $Serial
            LicenseType       = $LicenseType
            LicenseTypeName   = $ltName
            LangId            = $LangId
            Language          = $langName
            OSBuild           = $OSBuild
            BuildNumber       = $OSBuild
            DayOfYear         = $dayOfYear
            Year              = $year
            Date              = $Date
            Note              = $c.Note
            ProductDetails    = $c.ProductDetails
        }
    }
    if ($results.Count -eq 1) { $results[0] } else { $results }
}

# ===============================================================================================================================
