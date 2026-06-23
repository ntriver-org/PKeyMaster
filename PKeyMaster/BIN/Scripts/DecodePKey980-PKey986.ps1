<#
.SYNOPSIS
    Decodes Pre-Vista (Windows 98 to XP - Office 2000 to 2007 - etc) (Bink1998 & Bink2002) product keys.

.DESCRIPTION
    Decodes pre-Vista 25-character product keys using their BINK ID. Extracts Channel ID,
    Sequence, Hash, Signature, and Upgrade flag from the Base24-decoded byte fields.
    Key validity is not verified.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Common.ps1 for shared helper functions.

.PARAMETER productKey
    The 25-character product key to decode.

.PARAMETER binkIdHex
    The BINK ID in hex format (e.g., '0x40', '2A', '0x1C') associated with the product.

.PARAMETER PassThru
    Returns a custom PowerShell object with the decoded properties instead of just writing to the console.

.EXAMPLE
    .\DecodePKey980-PKey986.ps1 -productKey "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" -binkIdHex "0x40"
#>
param(
    [Parameter(Mandatory = $true)][string]$productKey,
    [Parameter(Mandatory = $true)][string]$binkIdHex,
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
# Product key validation & cleanup
# ===============================================================================================================================

$productKey = $productKey.Trim().ToUpper()
$binkIdHex = $binkIdHex.Trim()
$group = '[BCDFGHJKMPQRTVWXY2346789]{5}'

if ($productKey -notmatch "^$group-$group-$group-$group-$group$") {
    Write-Color "'$productKey' is not a valid product key format." "BgRed"
    return
}

if ($binkIdHex -notmatch '^(?i)(0x)?[0-9a-f]+$') {
    Write-Color "'$binkIdHex' is not a valid BINK ID hex value." "BgRed"
    return
}

$cleanKey = $productKey.Replace('-', '')
$alphabet = 'BCDFGHJKMPQRTVWXY2346789'

# ===============================================================================================================================
# Base24 decoding
# ===============================================================================================================================

# Decode Base24 key into a 16-byte array
$kb = New-Object byte[] 16
foreach ($ch in $cleanKey.ToCharArray()) {
    $carry = $alphabet.IndexOf($ch)
    for ($i = 0; $i -lt 16; $i++) {
        $total = $kb[$i] * 24 + $carry
        $kb[$i] = [byte]($total -band 255)
        $carry = [int][Math]::Floor($total / 256)
    }
}

# ===============================================================================================================================
# Bit parsing & decoding
# ===============================================================================================================================

# Determine BINK format (Bink1998 or Bink2002) and extract fields by shift + mask
$binkId = if ($binkIdHex -match '^0x') { [int]$binkIdHex } else { [int]"0x$binkIdHex" }
$is2002 = $binkId -ge 0x40

[int64] $lo = [System.BitConverter]::ToInt64($kb, 0)
[int64] $mi = if ($is2002) { [System.BitConverter]::ToInt64($kb, 5) } else { [System.BitConverter]::ToInt64($kb, 7) }
[int64] $hi = [System.BitConverter]::ToInt64($kb, 8)

$upg = [int]($lo -band 0x1)

if ($is2002) {
    # Bink2002 format (Server 2003)
    $serial = $null
    $channel = ([int64][Math]::Floor($lo / 2)) -band 0x3FF
    $seq = $null
    $hash = ([int64][Math]::Floor($lo / [Math]::Pow(2, 11))) -band 0x7FFFFFFF
    $sig = ([int64][Math]::Floor($mi / 4)) -band 0x3FFFFFFFFFFFFFFF
    $auth = ([int64][Math]::Floor($hi / [Math]::Pow(2, 40))) -band 0x3FF
    $fmt = "Bink2002"
}
else {
    # Bink1998 format (Windows 98 / ME / 2000 / XP)
    $serial = ([int64][Math]::Floor($lo / 2)) -band 0x3FFFFFFF
    $channel = [int64][Math]::Floor($serial / 1000000)
    $seq = $serial % 1000000
    $hash = ([int64][Math]::Floor($lo / [Math]::Pow(2, 31))) -band 0xFFFFFFF
    $sig = ([int64][Math]::Floor($mi / 8)) -band 0xFFFFFFFFFFFFFF
    $auth = $null
    $fmt = "Bink1998"
}

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

$upgText = if ($upg -eq 1) { "Yes" } else { "No" }
$f = "{0,-18}: {1}"

Write-Output ""
Write-Output ($f -f "Product Key", $productKey)
Write-Output ($f -f "BINK ID", ("0x{0:X2} ({1})" -f $binkId, $fmt))
Write-Output ($f -f "Upgrade", $upgText)
if (-not $is2002) { Write-Output ($f -f "Serial", $serial) }
Write-Output ($f -f "Channel ID", $channel)
if (-not $is2002) { Write-Output ($f -f "Sequence", $seq) }
Write-Output ($f -f "Hash", $hash)
Write-Output ($f -f "Signature", $sig)
if ($is2002) { Write-Output ($f -f "Auth", $auth) }
Write-Output ""
Write-Output "Note: Key is decoded but not verified."

# ===============================================================================================================================
# Object return (PassThru)
# ===============================================================================================================================

if ($PassThru) {
    New-Object PSObject -Property @{
        Key       = $productKey
        BinkId    = "0x$($binkId.ToString('X2'))"
        Format    = $fmt
        Serial    = $serial
        Channel   = $channel
        Sequence  = $seq
        Hash      = $hash
        Auth      = $auth
        Signature = $sig
        Upgrade   = $upg
    }
}

# ===============================================================================================================================
