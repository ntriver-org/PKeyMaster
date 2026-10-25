<#
.SYNOPSIS
    Decodes Windows 8+ and Office 2013+ (PKey2009) product keys.

.DESCRIPTION
    Decodes PKey2009-format product keys (Windows 8+, Office 2013+) by unpacking the Base24
    sequence. Uses the position of 'N' to realign the base conversion. Extracts Group ID,
    Serial, Security, Upgrade, and Extra, and validates the CRC checksum.

.PARAMETER Key
    The 25-character product key to decode (must contain an 'N').

.PARAMETER PassThru
    Returns a custom PowerShell object with the decoded properties instead of just writing to the console.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Common.psm1 for shared helper functions.

.EXAMPLE
    .\DecodePKey2009.ps1 -Key "XXXXN-XXXXX-XXXXX-XXXXX-XXXXX"
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Key,
    [switch]$PassThru
)

# ===============================================================================================================================
# Initialization & dependencies
# ===============================================================================================================================

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "." }
Import-Module "$scriptDir\Libs\Common.psm1"

# ===============================================================================================================================
# Product key validation & cleanup
# ===============================================================================================================================

# PKey2009 keys always contain an 'N' - validate that
$Key = $Key.Trim().ToUpper()
$group = '[BCDFGHJKMPQRTVWXY2346789N]{5}'

if ($Key -notmatch "^$group-$group-$group-$group-$group$" -or $Key.IndexOf('N') -lt 0) {
    Write-Color "'$Key' is not a valid PKey2009 key." "BgRed"
    return
}

$cleanKey = $Key.Replace('-', '')
$alphabet = 'BCDFGHJKMPQRTVWXY2346789'

# ===============================================================================================================================
# Base24 decoding
# ===============================================================================================================================

# The position of 'N' in the key is used as the first digit; the rest follow in order
$digits = @([int]$cleanKey.IndexOf('N'))
foreach ($ch in $cleanKey.ToCharArray()) {
    if ($ch -ne 'N') { $digits += [int]$alphabet.IndexOf($ch) }
}

$kb = New-Object byte[] 16
foreach ($d in $digits) {
    $carry = $d
    for ($i = 0; $i -lt 16; $i++) {
        $total = $kb[$i] * 24 + $carry
        $kb[$i] = [byte]($total -band 255)
        $carry = [int][Math]::Floor($total / 256)
    }
}

# ===============================================================================================================================
# Bit parsing & decoding
# ===============================================================================================================================

function Get-Bits($Data, $Offset, $Length) {
    [int64]$result = 0
    [int64]$mask = 1
    $bitPowers = @(1, 2, 4, 8, 16, 32, 64, 128)
    for ($bit = 0; $bit -lt $Length; $bit++) {
        $byteIndex = [int][Math]::Floor(($Offset + $bit) / 8)
        $bitIndex = ($Offset + $bit) % 8
        if (($Data[$byteIndex] -band $bitPowers[$bitIndex]) -ne 0) {
            $result = $result -bor $mask
        }
        $mask = $mask * 2
    }
    return $result
}

function Set-Bits($Data, $Offset, [int64]$Value, $Length) {
    $bitPowers = @(1, 2, 4, 8, 16, 32, 64, 128)
    [int64]$mask = 1
    for ($bit = 0; $bit -lt $Length; $bit++) {
        $byteIndex = [int][Math]::Floor(($Offset + $bit) / 8)
        $bitIndex = ($Offset + $bit) % 8
        if (($Value -band $mask) -ne 0) {
            $Data[$byteIndex] = [byte]($Data[$byteIndex] -bor $bitPowers[$bitIndex])
        }
        $mask = $mask * 2
    }
}

$grp = Get-Bits $kb 0 20
$ser = Get-Bits $kb 20 30
$sec = Get-Bits $kb 50 53
$csum = Get-Bits $kb 103 10
$upg = Get-Bits $kb 113 1
$ext = Get-Bits $kb 114 1

# ===============================================================================================================================
# CRC checksum validation
# ===============================================================================================================================

$mask32 = [int64]([Math]::Pow(2, 32)) - 1
$bit31 = [int64]([Math]::Pow(2, 31))
$poly = [int64]79764919

$crcTable = New-Object System.Int64[] 256
for ($i = 0; $i -lt 256; $i++) {
    [int64]$cval = [int64]($i * [Math]::Pow(2, 24))
    for ($b = 0; $b -lt 8; $b++) {
        if ($cval -band $bit31) {
            $cval = [int64](($cval * 2) -bxor $poly)
            $cval = $cval -band $mask32
        }
        else {
            $cval = [int64](($cval * 2) -band $mask32)
        }
    }
    $crcTable[$i] = $cval
}

function Get-PKey2009Checksum([byte[]]$Data) {
    [int64]$crc = $mask32
    foreach ($b in $Data) {
        [int64]$idx = ([int64][Math]::Truncate($crc / 16777216)) -bxor $b
        $idx = $idx -band 255
        $crc = ([int64]($crc * 256)) -bxor $crcTable[$idx]
        $crc = $crc -band $mask32
    }
    return [int](($crc -bxor $mask32) -band 1023)
}

$checkBytes = New-Object byte[] 16
Set-Bits $checkBytes   0 $grp 20
Set-Bits $checkBytes  20 $ser 30
Set-Bits $checkBytes  50 $sec 53
Set-Bits $checkBytes 113 $upg  1
Set-Bits $checkBytes 114 $ext  1
$expected = Get-PKey2009Checksum $checkBytes
$valid = ($csum -eq [int64]$expected)

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

$upgText = if ($upg -eq 1) { "Yes" } else { "No" }
$csumStatus = if ($valid) { "Valid" } else { "Invalid" }
$csumText = "$csum ($csumStatus)"
$f = "{0,-18}: {1}"

Write-Output ""
Write-Output ($f -f "Product Key", $Key)
Write-Output ($f -f "Group", $grp)
Write-Output ($f -f "Serial", $ser)
Write-Output ($f -f "Security", $sec)
if ($valid) {
    Write-Output ($f -f "Checksum", $csumText)
}
else {
    Write-Color ($f -f "Checksum", $csumText) "BgRed"
}
Write-Output ($f -f "Upgrade", $upgText)
Write-Output ($f -f "Extra", $ext)
Write-Output ""

# ===============================================================================================================================
# Object return (PassThru)
# ===============================================================================================================================

if ($PassThru) {
    New-Object PSObject -Property @{
        Key           = $Key
        Group         = $grp
        Serial        = $ser
        Security      = $sec
        Checksum      = $csum
        ChecksumValid = $valid
        Upgrade       = $upg
        Extra         = $ext
    }
}

# ===============================================================================================================================
