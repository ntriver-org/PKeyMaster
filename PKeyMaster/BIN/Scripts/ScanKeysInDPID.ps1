<#
.SYNOPSIS
    Scans files for Digital Product ID (DPID) binary blobs.

.DESCRIPTION
    Searches files or folders for Digital Product ID structures (v2, v3, v4)
    by reading raw bytes and parsing hex-encoded text. Valid DPIDs are decoded
    and displayed with product key, Product ID, and integrity check results.

.PARAMETER File
    Path to a single file to scan.

.PARAMETER Folder
    Path to a folder to scan.

.PARAMETER Recurse
    Recursively scan subdirectories when using -Folder.

.PARAMETER IncludeExtensions
    Filter files by wildcard pattern (e.g., "*.reg", "*.dat").

.PARAMETER Logs
    Enables saving of decoded DPID output to disk.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\DigitalProductId.ps1 for DPID parsing.
    Requires Libs\Common.ps1 for shared helper functions.

.EXAMPLE
    .\ScanKeysInDPID.ps1 -File "C:\backup.reg"

.EXAMPLE
    .\ScanKeysInDPID.ps1 -Folder "C:\Backups" -Recurse -Logs
#>
[CmdletBinding()]
param(
    [string]   $File,
    [string]   $Folder,
    [switch]   $Recurse,
    [string[]] $IncludeExtensions,
    [switch]   $Logs
)

# ===============================================================================================================================
# Initialization & dependencies
# ===============================================================================================================================

$VerifyHash = $true

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "." }
$commonPath = Join-Path $scriptDir "libs\Common.ps1"
if (Test-Path $commonPath) { . $commonPath }
$libsPath = Join-Path $scriptDir "Libs\DigitalProductId.ps1"
if (Test-Path $libsPath) { . $libsPath }

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function Find-DPIDInFile {
    # Search file for DPID blobs - raw bytes and hex-encoded text.
    param([string]$FilePath)
    $objects = @()
    try {
        $fileInfo = New-Object System.IO.FileInfo($FilePath)
        if ($fileInfo.Length -eq 0 -or $fileInfo.Length -gt 100MB) { return $objects }

        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -eq 50 -or $bytes.Length -eq 164 -or $bytes.Length -eq 1272) {
            if (Get-DigitalProductId -Blob $bytes -VerifyHash:$VerifyHash) {
                $objects += , $bytes
            }
        }

        $text = [System.IO.File]::ReadAllText($FilePath)
        $text = $text -replace "\\\r?\n\s*", ""
        foreach ($m in [regex]::Matches($text, '(?:hex:\s*)?((?:[0-9a-fA-F]{2}[,\s]+)+[0-9a-fA-F]{2})')) {
            $strArr = $m.Groups[1].Value.Split(@(',', ' ', "`t", "`r", "`n"), [System.StringSplitOptions]::RemoveEmptyEntries)
            
            $isValid = $false
            if ($strArr.Count -eq 50) { $isValid = $true }
            elseif ($strArr.Count -ge 164 -and $strArr.Count -le 4096 -and $strArr[0] -eq 'a4' -and $strArr[1] -eq '00' -and $strArr[2] -eq '00' -and $strArr[3] -eq '00') { $isValid = $true }
            elseif ($strArr.Count -ge 1272 -and $strArr.Count -le 4096 -and $strArr[0] -eq 'f8' -and $strArr[1] -eq '04' -and $strArr[2] -eq '00' -and $strArr[3] -eq '00') { $isValid = $true }
            
            if (-not $isValid) { continue }

            $hexBytes = New-Object byte[] $strArr.Count
            for ($i = 0; $i -lt $strArr.Count; $i++) {
                $hexBytes[$i] = [Convert]::ToByte($strArr[$i], 16)
            }
            if (Get-DigitalProductId -Blob $hexBytes -VerifyHash:$VerifyHash) {
                $objects += , $hexBytes
            }
        }
    }
    catch { }
    return $objects
}

# ===============================================================================================================================

$global:savedFiles = @()
$base = Join-Path ([Environment]::GetFolderPath("Desktop")) "PKeyMaster-Logs"
$logRoot = Join-Path $base ("ScanDPID\" + (Get-Date -Format "yyyy-MM-dd_HH-mm-ss_fff"))

function Invoke-DPIDFileScan {
    # Scan a file for DPIDs, print results, optionally save them.
    param([string]$FilePath)
    
    $blobs = @(Find-DPIDInFile -FilePath $FilePath)
    if ($blobs.Count -eq 0) { return }

    $global:filesWithObjects++
    $global:totalObjects += $blobs.Count

    $formattedStrs = @()
    for ($i = 0; $i -lt $blobs.Count; $i++) { 
        $str = Get-DigitalProductIdDisplay -Blob $blobs[$i] -VerifyHash:$VerifyHash
        $block = "[$FilePath]`r`n$str"
        $block += "`r`n`r`n--------------------------------------------------------------------------------`r`n"
        Write-Output $block
        $formattedStrs += $block
    }

    if ($Logs) {
        if (-not (Test-Path $logRoot)) { New-Item -ItemType Directory -Path $logRoot -Force | Out-Null }
        $fullPath = [System.IO.Path]::GetFullPath($FilePath)
        $safeName = $fullPath -replace '[:\\/]', '-'
        $outPath = Join-Path $logRoot "$safeName.txt"
        $formattedStrs | Out-File $outPath -Encoding UTF8
        $global:savedFiles += $outPath
    }

}

# ===============================================================================================================================
# Main execution
# ===============================================================================================================================

$sw = [System.Diagnostics.Stopwatch]::StartNew()

if ($File) {
    if (-not (Test-Path $File -PathType Leaf -ErrorAction SilentlyContinue)) {
        Write-Color "Error: File does not exist: $File" "BgRed"; return
    }

    Write-Output "File    : $([System.IO.Path]::GetFileName($File))"
    Write-Output "Scanning, please wait..."
    Write-Output ""

    $global:totalObjects = 0
    $global:filesWithObjects = 0
    Invoke-DPIDFileScan -FilePath $File

    $sw.Stop()
    Write-Output "File    : $([System.IO.Path]::GetFileName($File))"
    Write-Output "DPIDs   : $($global:totalObjects)"
    Write-Output ("Time    : {0:N3} s" -f $sw.Elapsed.TotalSeconds)

}
elseif ($Folder) {
    if (-not (Test-Path $Folder -PathType Container -ErrorAction SilentlyContinue)) {
        Write-Color "Error: Folder does not exist: $Folder" "BgRed"; return
    }

    Write-Output "Folder  : $Folder"
    Write-Output "Recurse : $(if ($Recurse) { 'Yes' } else { 'No' })"
    Write-Output "Filter  : $(if ($IncludeExtensions) { $IncludeExtensions -join ', ' } else { '(all files)' })"
    Write-Output "Scanning, please wait..."
    Write-Output ""

    $patterns = @($IncludeExtensions | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() })
    $fileCount = 0
    $global:filesWithObjects = 0
    $global:totalObjects = 0

    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Folder)

    while ($stack.Count -gt 0) {
        $currentDir = $stack.Pop()

        try {
            foreach ($f in [System.IO.Directory]::GetFiles($currentDir)) {
                $name = [System.IO.Path]::GetFileName($f)

                if ($patterns.Count -gt 0) {
                    $matched = $false
                    foreach ($p in $patterns) { if ($name -like $p) { $matched = $true; break } }
                    if (-not $matched) { continue }
                }

                $fileCount++
                Invoke-DPIDFileScan -FilePath $f
            }
        }
        catch { }

        if ($Recurse) {
            try {
                foreach ($sub in [System.IO.Directory]::GetDirectories($currentDir)) { $stack.Push($sub) }
            }
            catch { }
        }
    }

    $sw.Stop()
    Write-Output "Files scanned      : $fileCount"
    Write-Output "Files with DPIDs   : $($global:filesWithObjects)"
    Write-Output "Total DPIDs        : $($global:totalObjects)"
    Write-Output ("Time               : {0:N3} s" -f $sw.Elapsed.TotalSeconds)

}
else {
    Write-Color "Error: Specify -File or -Folder." "BgRed"
}

# ===============================================================================================================================
# Log summary
# ===============================================================================================================================

if ($global:savedFiles.Count -gt 0) {
    Write-Output ""
    Write-Output "Logs saved to      : $logRoot"
}

Write-Output ""

# ===============================================================================================================================
