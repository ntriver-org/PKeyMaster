<#
.SYNOPSIS
    Decodes or encodes Microsoft Product IDs across supported licensing algorithms.

.DESCRIPTION
    Encodes and decodes Microsoft Product IDs (PIDs) for Windows 98, Office 2000,
    and all later products. This includes PKey980, PKey986, PKey2005, PKey2009 algorithms.

.PARAMETER Encode
    Encodes the given licensing parameters into a Product ID.

.PARAMETER Decode
    Decodes the given Product ID string into licensing components.

.PARAMETER ProductId
    The Product ID string to decode.

.PARAMETER Algorithm
    The algorithm to use ('PKey2009', 'PKey2005', 'PKey980', 'PKey986', 'Pre-2009').

.PARAMETER GroupId
    The group / BINK ID (0 to 999999).

.PARAMETER Serial
    The product key serial number (Key ID).

.PARAMETER IsOem
    Indicates whether the key is an OEM key ($true / $false).

.PARAMETER LegacyOem
    Uses the legacy Pre-PKey2009 OEM format (MPC-OEM-00CCCSM-SSSSS) omitting Group ID instead of the newer MPC-OEM-GGCCCSM-SSSSS format.

.PARAMETER IsUpgrade
    Indicates whether the key is an upgrade key ($true / $false). Applicable to PKey2009.

.PARAMETER MPC
    Microsoft Product Code prefix (default: '00000').

.PARAMETER GetProductDetails
    Queries the PKeyConfigsMap and PreVistaRanges database to retrieve and display matching product details.

.PARAMETER PassThru
    Returns a custom PowerShell object with the Product ID properties instead of just writing to the console.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Common.psm1 for shared helper functions.

.EXAMPLE
    .\ProductId.ps1 -Encode -Algorithm "PKey2009" -GroupId 1050 -Serial 123456789
.EXAMPLE
    .\ProductId.ps1 -Encode -Algorithm "PKey2009" -GroupId 1050 -Serial 123456789 -IsOem $true -IsUpgrade $true
.EXAMPLE
    .\ProductId.ps1 -Decode -ProductId "00105-01234-56789-AA456"
.EXAMPLE
    .\ProductId.ps1 -Decode -ProductId "00105-01234-56789-AA456" -GetProductDetails
#>
param(
    [switch]$Encode,
    [switch]$Decode,

    [string]$ProductId,

    [string]$Algorithm,
    [int]$GroupId = 0,
    [long]$Serial = 0,
    [bool]$IsOem = $false,
    [switch]$LegacyOem,
    [bool]$IsUpgrade = $false,
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
# Mod7 Check Digit helpers
# ===============================================================================================================================

function Add-Mod7CheckDigit([long]$Value) {
    $sum = 0
    $temp = $Value
    while ($temp -gt 0) {
        $sum += [int]($temp % 10)
        $temp = [Math]::Floor($temp / 10)
    }
    return ($Value * 10) + (7 - ($sum % 7))
}

function Test-Mod7CheckDigit([long]$FullValue) {
    $sum = 0
    $temp = $FullValue
    while ($temp -gt 0) {
        $sum += [int]($temp % 10)
        $temp = [Math]::Floor($temp / 10)
    }
    return ($sum % 7) -eq 0
}

# ===============================================================================================================================
# Encode / Decode processing
# ===============================================================================================================================

if (-not $Encode -and -not $Decode) {
    Write-Color "Please specify either -Encode or -Decode." "BgRed"
    return
}

if ($Decode) {
    if (-not $ProductId) {
        Write-Color "Please provide -ProductId to decode." "BgRed"
        return
    }
    $ProductId = $ProductId.Trim().ToUpper()

    # Pattern 1: PKey2009 (GGGGG-GSSSS-SSSSS-TAGTRAILER e.g. 00105-01234-56789-AA456 or 00105-01234-56789-AAOEM)
    if ($ProductId -match '^(\d{5})-(\d)(\d{4})-(\d{5})-(A[AB])(\d{3}|OEM)$') {
        $is2009 = $true
        $GroupId = [int]($matches[1] + $matches[2])
        $Serial = [long]($matches[3] + $matches[4])
        $IsUpgrade = ($matches[5] -eq "AB")
        $IsOem = ($matches[6] -eq "OEM")
        $randomValue = if ($IsOem) { $null } else { [int]$matches[6] }
        $MPC = $null
        $candidates = @( @{ Algorithm = "PKey2009"; GroupId = $GroupId; Note = $null } )
    }
    # Pattern 2: Pre-PKey2009 OEM (MPC-OEM-GGCCCSM-SSSSS or MPC-OEM-00CCCSM-SSSSS)
    elseif ($ProductId -match '^(\d{5})-OEM-((\d{2})(\d{3})(\d)\d)-(\d{5})$') {
        $is2009 = $false
        $IsOem = $true
        $MPC = $matches[1]
        $mod7Valid = Test-Mod7CheckDigit ([long]$matches[2])
        $isLegacyOem = ($matches[3] -eq "00")
        $groupPart = if ($isLegacyOem) { $null } else { [int]$matches[3] }
        $channelId = [int]$matches[4]
        $sequence = [int]($matches[5] + $matches[6])
        $randomValue = $null
    }
    # Pattern 3: Pre-PKey2009 Non-OEM (MPC-CCC-SSSSSSM-GGRRR e.g. 00000-123-4567893-42456)
    elseif ($ProductId -match '^(\d{5})-(\d{3})-((\d{6})\d)-(\d{2})(\d{3})$') {
        $is2009 = $false
        $IsOem = $false
        $MPC = $matches[1]
        $channelId = [int]$matches[2]
        $mod7Valid = Test-Mod7CheckDigit ([long]$matches[3])
        $sequence = [int]$matches[4]
        $groupPart = [int]$matches[5]
        $randomValue = [int]$matches[6]
    }
    else {
        Write-Color "'$ProductId' is not a valid Product ID." "BgRed"
        return
    }

    # Resolve Pre-PKey2009 candidates
    if (-not $is2009) {
        $Serial = [long]$channelId * 1000000 + $sequence

        if ($isLegacyOem) {
            $candidates = @( @{
                    Algorithm = "PKey980"
                    GroupId   = $null
                    Note      = "Legacy OEM format - Group ID is not encoded."
                } )
        }
        else {
            $baseGroup = $groupPart * 2
            $fromCidServer = ($randomValue -eq 0 -and $MPC -ne "00000")
            $cidNote = if ($fromCidServer) { "This PID was likely generated by the CID server." } else { $null }

            $cand980 = @{
                Algorithm = if ($baseGroup -ge 0x40) { "PKey986" } else { "PKey980" }
                GroupId   = if ($IsOem -or $fromCidServer) { $baseGroup + 1 } else { $baseGroup }
                Note      = $cidNote
            }
            $cand2005 = @{
                Algorithm = "PKey2005"
                GroupId   = if ($baseGroup -eq 2) { 2 } elseif (@(4, 6, 8, 12) -contains $baseGroup) { $baseGroup + 200 } else { $baseGroup }
                Note      = $cidNote
            }

            $doubtful = @(2, 4, 6, 8, 12)
            if ($doubtful -contains $baseGroup) {
                $candidates = @($cand980, $cand2005)
            }
            else {
                $isP2005 = ($baseGroup -ge 138)
                $configsMap = Get-PKeyConfigsMap
                if (-not $isP2005 -and $configsMap) {
                    $gStr = [string]$baseGroup
                    foreach ($entry in $configsMap) {
                        if ($entry.Algorithms -and $entry.Algorithms.ContainsKey("PKey2005")) {
                            if ($entry.Algorithms["PKey2005"].ContainsKey($gStr)) {
                                $isP2005 = $true
                                break
                            }
                        }
                    }
                }
                if ($isP2005) {
                    $candidates = @($cand2005)
                }
                else {
                    $candidates = @($cand980)
                }
            }
        }
    }
}
else {
    if (-not $Algorithm) {
        Write-Color "Please specify -Algorithm ('PKey2009', 'PKey2005', 'PKey980', 'PKey986', 'Pre-2009') to encode a Product ID." "BgRed"
        return
    }
    if ($Serial -lt 0 -or $Serial -gt 999999999) {
        Write-Color "Serial must be between 0 and 999999999." "BgRed"
        return
    }
    if ($GroupId -lt 0 -or $GroupId -gt 999999) {
        Write-Color "Group ID must be between 0 and 999999." "BgRed"
        return
    }
    if ($Algorithm -match "Pre-?2009|2005|980|986" -and (-not $MPC -or $MPC.Trim() -notmatch '^\d{5}$')) {
        Write-Color "MPC must be a 5-digit numeric string." "BgRed"
        return
    }

    $randVal = [int]([Math]::Abs([Environment]::TickCount / 10) % 1000)

    if ($Algorithm -match "Pre-?2009|2005|980|986") {
        $is2009 = $false
        $groupPart = [int]([Math]::Floor($GroupId / 2) % 100)
        $channelId = [int]([Math]::Floor($Serial / 1000000) % 1000)
        $sequence = [int]($Serial % 1000000)
        $mod7Valid = $true

        if ($IsOem) {
            # Layout: MPC-OEM-GGCCCSM-SSSSS (or MPC-OEM-00CCCSM-SSSSS if LegacyOem)
            $seqStr = "{0:D6}" -f $sequence
            $oemGroup = if ($LegacyOem) { 0 } else { $groupPart }
            $baseNumber = [long]("{0:D2}{1:D3}{2}" -f $oemGroup, $channelId, $seqStr.Substring(0, 1))
            $baseWithCheck = Add-Mod7CheckDigit $baseNumber

            $ProductId = "{0}-OEM-{1:D7}-{2}" -f $MPC, $baseWithCheck, $seqStr.Substring(1, 5)
        }
        else {
            # Layout: MPC-CCC-SSSSSSM-GGRRR
            $seqWithCheck = Add-Mod7CheckDigit $sequence
            $ProductId = "{0}-{1:D3}-{2:D7}-{3:D2}{4:D3}" -f $MPC, $channelId, $seqWithCheck, $groupPart, $randVal
        }
    }
    elseif ($Algorithm -match "2009") {
        $is2009 = $true
        $grpStr = "{0:D6}" -f $GroupId
        $serStr = "{0:D9}" -f $Serial
        $tag = if ($IsUpgrade) { "AB" } else { "AA" }
        $trailer = if ($IsOem) { "OEM" } else { "{0:D3}" -f $randVal }

        # Layout: GGGGG-GSSSS-SSSSS-TAGTRAILER
        $ProductId = "{0}-{1}{2}-{3}-{4}{5}" -f $grpStr.Substring(0, 5), $grpStr.Substring(5, 1), $serStr.Substring(0, 4), $serStr.Substring(4, 5), $tag, $trailer
    }
    else {
        Write-Color "'$Algorithm' is not a recognized algorithm ('PKey2009', 'PKey2005', 'PKey980', 'PKey986', 'Pre-2009')." "BgRed"
        return
    }

    $randomValue = if ($IsOem) { $null } else { $randVal }
    $candidates = @( @{ Algorithm = $Algorithm; GroupId = $GroupId; Note = $null } )
}

# Product Details retrieval
foreach ($c in $candidates) {
    $c.ProductDetails = if ($GetProductDetails) {
        Get-ProductDetails -GroupId $c.GroupId -KeyId $Serial -Algorithm $c.Algorithm
    }
    else { $null }
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
    Write-Color ($f -f "Product ID", $ProductId) "BgGreen"
    if ($MPC -and -not $is2009) { Write-Output ($f -f "MPC", $MPC) }
    if ($null -ne $c.GroupId) { Write-Output ($f -f "Group ID", ("{0} (0x{0:X})" -f $c.GroupId)) }
    Write-Output ($f -f "Key ID", ("{0} (0x{0:X})" -f $Serial))
    if ($c.Algorithm -notmatch "2005|2009") {
        if ($null -ne $channelId) { Write-Output ($f -f "Channel ID", ("{0} (0x{0:X})" -f $channelId)) }
        if ($null -ne $sequence) { Write-Output ($f -f "Sequence", ("{0} (0x{0:X})" -f $sequence)) }
    }
    if ($is2009) {
        Write-Output ($f -f "OEM", $(if ($IsOem) { "Yes" } else { "No" }))
        Write-Output ($f -f "Upgrade", $(if ($IsUpgrade) { "Yes" } else { "No" }))
    }
    if ($null -ne $randomValue) { Write-Output ($f -f "Random", $randomValue) }
    if ($null -ne $mod7Valid) {
        if ($mod7Valid) { Write-Output ($f -f "Mod7 Check", "Valid") } else { Write-Color ($f -f "Mod7 Check", "Invalid") "BgRed" }
    }
    if ($c.Note) {
        Write-Color ($f -f "Note", $c.Note) "BgGray"
    }
    if ($c.ProductDetails) {
        Write-Output ""
        Write-ProductDetails $c.ProductDetails $f -Exclude "ChannelId", "Sequence"
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
            ProductId      = $ProductId
            Algorithm      = $c.Algorithm
            GroupId        = $c.GroupId
            Serial         = $Serial
            ChannelId      = if ($c.Algorithm -notmatch "2005|2009") { $channelId } else { $null }
            Sequence       = if ($c.Algorithm -notmatch "2005|2009") { $sequence } else { $null }
            IsOEM          = if ($is2009) { [bool]$IsOem } else { $null }
            IsUpgrade      = if ($is2009) { [bool]$IsUpgrade } else { $null }
            Random         = $randomValue
            Mod7Valid      = $mod7Valid
            Note           = $c.Note
            ProductDetails = $c.ProductDetails
        }
    }
    if ($results.Count -eq 1) { $results[0] } else { $results }
}

# ===============================================================================================================================
