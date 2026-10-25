<#
.SYNOPSIS
    Common helper functions and shared caches for PKeyMaster.

.DESCRIPTION
    PowerShell script module providing shared utilities across PKeyMaster scripts,
    including ANSI/VT and GUI color formatting (Write-Color), binary key extraction
    (Find-KeysInFile), native SPP/WMI error message resolution, and global data caches.
    This module is intended to be imported via Import-Module, not executed directly.

.NOTES
    Compatible with PowerShell 2.0 and later.
#>

# ===============================================================================================================================
# ANSI / VT support detection
# ===============================================================================================================================

$script:AnsiSupported = $false
$script:ColorLineBuffer = ""
if ([System.Environment]::OSVersion.Version.Build -ge 10586) {
    $forceV2 = (Get-ItemProperty -Path 'HKCU:\Console' -Name 'ForceV2' -ErrorAction SilentlyContinue).ForceV2
    if ($null -eq $forceV2 -or $forceV2 -ne 0) {
        $script:AnsiSupported = $true
    }
}

# Color name -> @(AnsiCode, GUI-ForegroundColor, GUI-BackgroundColor)
$script:ColorMap = @{
    'BgRed'    = @("41;97", "White", "DarkRed")
    'BgGray'   = @("100;97", "White", "Gray")
    'BgGreen'  = @("42;97", "White", "Green")
    'BgBlue'   = @("44;97", "White", "Blue")
    'BgWhite'  = @("107;91", "Red", "White")
    'FgRed'    = @("40;91", "Red", "Black")
    'FgWhite'  = @("40;37", "Gray", "Black")
    'FgGreen'  = @("40;92", "Green", "Black")
    'FgYellow' = @("40;93", "Yellow", "Black")
}

# ===============================================================================================================================
# Write-Color
# Usage:  Write-Color "text" "BgRed"
#         Write-Color "label: " "BgGray" -NoNewline; Write-Color "value" "FgGreen"
# ===============================================================================================================================

function Write-Color {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Text,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateSet('BgRed', 'BgGray', 'BgGreen', 'BgBlue', 'BgWhite', 'FgRed', 'FgWhite', 'FgGreen', 'FgYellow')]
        [string]$Color,

        [Parameter(Mandatory = $false)]
        [switch]$NoNewline
    )

    $colorData = $script:ColorMap[$Color]
    $piece = ""

    if ($global:IsGuiRunspace) {
        $piece = "[c:$($colorData[1]):$($colorData[2])]$Text"
    }
    elseif ($script:AnsiSupported) {
        $piece = "$([char]27)[$($colorData[0])m$Text$([char]27)[0m"
    }
    else {
        $piece = $Text
    }

    if ($NoNewline) {
        $script:ColorLineBuffer += $piece
    }
    else {
        $fullLine = $script:ColorLineBuffer + $piece
        $script:ColorLineBuffer = ""
        Write-Output $fullLine
    }
}

# ===============================================================================================================================
# Find-KeysInFile
# Read file in chunks and extract unique keys matching a regex across multiple encodings (ASCII, UTF-8, Unicode, BigEndianUnicode).
# ===============================================================================================================================

function Find-KeysInFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$FilePath,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Pattern
    )

    $keys = @()
    $fs = $null
    try { 
        $fileInfo = New-Object System.IO.FileInfo($FilePath)
        if ($fileInfo.Length -eq 0) { return $keys }
        $fs = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    }
    catch {
        if ($fs) { $fs.Dispose() }
        return @()
    }

    $chunkSize = 8MB
    $overlapSize = 256
    $buffer = New-Object byte[] ($chunkSize + $overlapSize)
    $carry = 0
    $seen = @{}

    try {
        while ($true) {
            $read = 0
            while ($read -lt $chunkSize) {
                $n = $fs.Read($buffer, $carry + $read, $chunkSize - $read)
                if ($n -eq 0) { break }
                $read += $n
            }
            if ($read -eq 0 -and $carry -eq 0) { break }
            $totalBytes = $carry + $read

            # By reading as ASCII and removing null characters, we can scan UTF-8, Unicode, and BigEndianUnicode in a single pass
            $text = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $totalBytes).Replace("`0", "")
            foreach ($m in [regex]::Matches($text.ToUpper(), $Pattern)) {
                $val = $m.Value
                if (-not $seen.ContainsKey($val)) {
                    $seen[$val] = $true
                    $hash = @{}
                    foreach ($c in $val.ToCharArray()) { if ($c -ne '-') { $hash[$c] = $true } }
                    if ($hash.Count -ge 3) { $keys += $val }
                }
            }

            if ($read -lt $chunkSize) { break }

            # Retain overlap bytes to catch keys spanning chunk boundaries (UTF-16 key is 58 bytes)
            $carry = [Math]::Min($overlapSize, $totalBytes)
            [System.Buffer]::BlockCopy($buffer, $totalBytes - $carry, $buffer, 0, $carry)
        }
    }
    catch { }
    finally {
        if ($fs) { $fs.Dispose() }
    }

    return $keys
}

# ===============================================================================================================================
# WMI / SPP Error Resolution
# ===============================================================================================================================

function Get-WmiSppError {
    [CmdletBinding()]
    param(
        [int]$ErrorCode = 0,
        [Exception]$Exception = $null
    )

    if ($ErrorCode -eq 0 -and -not $Exception) { return $null }

    # Resolve HRESULT from exception if provided
    $hres = $ErrorCode
    if ($Exception) {
        $ex = if ($Exception.InnerException) { $Exception.InnerException } else { $Exception }
        $hres = [System.Runtime.InteropServices.Marshal]::GetHRForException($ex)
    }

    $msg = ''

    if ($hres -ne 0) {
        # Build interop type once per session to avoid recompiling
        $typeName = 'SPPInterop'
        $interopType = $typeName -as [type]

        if (-not $interopType) {
            $TB = [AppDomain]::CurrentDomain.DefineDynamicAssembly((Get-Random), 1).DefineDynamicModule((Get-Random), $False).DefineType($typeName)
            [void]$TB.DefinePInvokeMethod('LoadLibrary', 'kernel32.dll', 22, 1, [IntPtr], @([string]), 1, 4).SetImplementationFlags(128)
            [void]$TB.DefinePInvokeMethod('FreeLibrary', 'kernel32.dll', 22, 1, [bool], @([IntPtr]), 1, 4).SetImplementationFlags(128)
            [void]$TB.DefinePInvokeMethod('FormatMessage', 'kernel32.dll', 22, 1, [int], @([int], [IntPtr], [int], [int], [System.Text.StringBuilder], [int], [IntPtr]), 1, 4).SetImplementationFlags(128)
            $interopType = $TB.CreateType()
        }

        # Walk licensing and system DLLs to find the error description
        $searchDlls = @('slc.dll', 'sppc.dll', 'wmiutils.dll', 'KernelBase.dll')
        foreach ($dll in $searchDlls) {
            $hMod = $interopType::LoadLibrary($dll)
            if ($hMod -eq [IntPtr]::Zero) { continue }

            $sb = New-Object System.Text.StringBuilder 1024
            # Flags: FORMAT_MESSAGE_FROM_HMODULE (0x800) | FORMAT_MESSAGE_IGNORE_INSERTS (0x200)
            $res = $interopType::FormatMessage(0x00000A00, $hMod, $hres, 0, $sb, $sb.Capacity, [IntPtr]::Zero)
            $interopType::FreeLibrary($hMod) | Out-Null

            if ($res -gt 0) {
                $msg = $sb.ToString().Trim()
                break
            }
        }
    }

    # Fallback to raw exception message if native resolution failed
    if (-not $msg -and $Exception) {
        $ex = if ($Exception.InnerException) { $Exception.InnerException } else { $Exception }
        $msg = $ex.Message
    }

    return New-Object PSObject -Property @{
        ErrorCode    = $hres
        ErrorMessage = $msg
    }
}

# ===============================================================================================================================

function Write-WmiSppError {
    [CmdletBinding()]
    param(
        [int]$ErrorCode = 0,
        [Exception]$Exception = $null
    )

    $errObj = Get-WmiSppError -ErrorCode $ErrorCode -Exception $Exception
    if (-not $errObj) { return }

    $f = '{0,-18}: {1}'
    Write-Color ($f -f 'Error Code', ('0x{0:X8}' -f $errObj.ErrorCode)) "BgRed"
    Write-Color ($f -f 'Error Message', $errObj.ErrorMessage) "BgRed"
    Write-Output ""
}

# ===============================================================================================================================
# JSON Serializer Global Cache
# ===============================================================================================================================

if (-not $global:JsonSerializer) {
    try {
        Add-Type -AssemblyName System.Web.Extensions | Out-Null
        $global:JsonSerializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $global:JsonSerializer.MaxJsonLength = [int]::MaxValue
    }
    catch { }
}

# ===============================================================================================================================
# PKeyConfigsMap JSON Global Cache
# ===============================================================================================================================

if (-not $global:PKeyConfigsMap) {
    $jsonPath = Join-Path $PSScriptRoot "..\..\PKeyConfigsMap.json"

    if (Test-Path $jsonPath) {
        $global:PKeyConfigsMap = $global:JsonSerializer.DeserializeObject([System.IO.File]::ReadAllText($jsonPath))
    }
}

# ===============================================================================================================================
# PreVistaRanges CSV Global Cache
# ===============================================================================================================================

if (-not $global:PreVistaRanges) {
    $preVistaCsvPath = Join-Path $PSScriptRoot "..\..\PreVistaRanges.csv"

    if (Test-Path $preVistaCsvPath) {
        $global:PreVistaRanges = @((Get-Content -LiteralPath $preVistaCsvPath) | Where-Object { $_ -notmatch '^\s*sep\s*=' } | ConvertFrom-Csv)
    }
}

# ===============================================================================================================================
