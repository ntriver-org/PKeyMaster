<#
.SYNOPSIS
    Decodes Windows 8+ and Office 2013+ (PKey2009) product keys.

.DESCRIPTION
    Decodes PKey2009-format product keys (Windows 8+, Office 2013+) by unpacking the Base24
    sequence. Uses the position of 'N' to realign the base conversion. Extracts Group ID,
    Serial, Security, Upgrade, and Extra. Key validity is not verified.

.PARAMETER Key
    The 25-character product key to decode (must contain an 'N').

.PARAMETER PassThru
    Returns a custom PowerShell object with the decoded properties instead of just writing to the console.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Common.ps1 for shared helper functions.

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
$commonPath = Join-Path $scriptDir "libs\Common.ps1"
if (Test-Path $commonPath) { . $commonPath }

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

# Read the decoded buffer as three 64-bit words and extract fields by shift + mask
[int64] $lo = [System.BitConverter]::ToInt64($kb, 0)
[int64] $mi = [System.BitConverter]::ToInt64($kb, 6)
[int64] $hi = [System.BitConverter]::ToInt64($kb, 8)

$grp = $lo -band 0xFFFFF
$ser = ([int64][Math]::Floor($lo / [Math]::Pow(2, 20))) -band 0x3FFFFFFF
$sec = ([int64][Math]::Floor($mi / 4)) -band 0x1FFFFFFFFFFFFF
$csum = ([int64][Math]::Floor($hi / [Math]::Pow(2, 39))) -band 0x3FF
$upg = ([int64][Math]::Floor($hi / [Math]::Pow(2, 49))) -band 0x1
$ext = ([int64][Math]::Floor($hi / [Math]::Pow(2, 50))) -band 0x1

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

$upgText = if ($upg -eq 1) { "Yes" } else { "No" }
$f = "{0,-18}: {1}"

Write-Output ""
Write-Output ($f -f "Product Key", $Key)
Write-Output ($f -f "Group", $grp)
Write-Output ($f -f "Serial", $ser)
Write-Output ($f -f "Security", $sec)
Write-Output ($f -f "Checksum", $csum)
Write-Output ($f -f "Upgrade", $upgText)
Write-Output ($f -f "Extra", $ext)
Write-Output ""
Write-Output "Note: Key is decoded but not verified."

# ===============================================================================================================================
# Object return (PassThru)
# ===============================================================================================================================

if ($PassThru) {
    New-Object PSObject -Property @{
        Key      = $Key
        Group    = $grp
        Serial   = $ser
        Security = $sec
        Checksum = $csum
        Upgrade  = $upg
        Extra    = $ext
    }
}

# ===============================================================================================================================
