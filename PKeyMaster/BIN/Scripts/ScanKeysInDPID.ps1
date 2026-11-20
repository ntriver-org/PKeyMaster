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
    Requires Libs\DigitalProductId.psm1 for DPID parsing.
    Requires Libs\Common.psm1 for shared helper functions.

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
Import-Module "$scriptDir\Libs\Common.psm1"
Import-Module "$scriptDir\Libs\DigitalProductId.psm1"

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

$lineSeparator = "________________________________________________________________________________`r`n"

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
            $strArr = $m.Groups[1].Value.Split([char[]]@(',', ' ', "`t", "`r", "`n"), [System.StringSplitOptions]::RemoveEmptyEntries)
            
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

function Invoke-DPIDFileScan {
    # Scan a file for DPIDs, print results, optionally save them.
    param(
        [string]$FilePath,
        [hashtable]$Tracker,
        [string]$LogRoot = ''
    )
    
    $blobs = @(Find-DPIDInFile -FilePath $FilePath)
    if ($blobs.Count -eq 0) { return }

    $Tracker.Files++
    $Tracker.Total += $blobs.Count

    $formattedStrs = @()
    for ($i = 0; $i -lt $blobs.Count; $i++) { 
        $str = Get-DigitalProductIdDisplay -Blob $blobs[$i] -VerifyHash:$VerifyHash
        $block = "[$FilePath]`r`n$str`r`n"
        $block += $lineSeparator
        Write-Output $block
        $formattedStrs += $block
    }

    if ($Logs -and $LogRoot) {
        if (-not (Test-Path $LogRoot)) { New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null }
        $fullPath = [System.IO.Path]::GetFullPath($FilePath)
        $safeName = $fullPath -replace '[:\\/]', '-'
        $outPath = Join-Path $LogRoot "$safeName.txt"
        $formattedStrs | Out-File $outPath -Encoding UTF8
        $Tracker.SavedFiles++
    }
}

# ===============================================================================================================================
# Main execution
# ===============================================================================================================================

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$f = "{0,-18}: {1}"

$tracker = @{
    Total      = 0
    Files      = 0
    SavedFiles = 0
}
$logRoot = if ($Logs) {
    Join-Path ([Environment]::GetFolderPath("Desktop")) ("PKeyMaster-Logs\ScanDPID\" + (Get-Date -Format "yyyy-MM-dd_HH-mm-ss_fff"))
} else { '' }

if ($File -and $Folder) {
    Write-Color "Error: Specify either -File or -Folder, not both." "BgRed"; return
}
if (-not $File -and -not $Folder) {
    Write-Color "Error: Specify -File or -Folder." "BgRed"; return
}

$isFolder = [bool]$Folder
$target = if ($isFolder) { $Folder } else { $File }
$pathType = if ($isFolder) { 'Container' } else { 'Leaf' }

if (-not (Test-Path -LiteralPath $target -PathType $pathType -ErrorAction SilentlyContinue)) {
    Write-Color ("Error: {0} does not exist: {1}" -f $(if ($isFolder) { 'Folder' } else { 'File' }), $target) "BgRed"; return
}

$targetPath = (Resolve-Path -LiteralPath $target).ProviderPath

if ($isFolder) {
    Write-Output ($f -f "Folder", $Folder)
    Write-Output ($f -f "Recurse", $(if ($Recurse) { 'Yes' } else { 'No' }))
    Write-Output ($f -f "Filter", $(if ($IncludeExtensions) { $IncludeExtensions -join ', ' } else { '(all files)' }))
}
else {
    Write-Output ($f -f "File", $([System.IO.Path]::GetFileName($targetPath)))
}

Write-Output ""
Write-Output "Scanning, please wait..."
Write-Output $lineSeparator

if (-not $isFolder) {
    Invoke-DPIDFileScan -FilePath $targetPath -Tracker $tracker -LogRoot $logRoot

    $sw.Stop()
    Write-Output ($f -f "File", $([System.IO.Path]::GetFileName($targetPath)))
    Write-Output ($f -f "DPIDs", $tracker.Total)
    Write-Output ($f -f "Time", ("{0:N3} s" -f $sw.Elapsed.TotalSeconds))
}
else {
    $patterns = @($IncludeExtensions | ForEach-Object { $_ -split '[,;]+' } | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() })
    $fileCount = 0

    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($targetPath)

    while ($stack.Count -gt 0) {
        $currentDir = $stack.Pop()

        try {
            foreach ($file in [System.IO.Directory]::GetFiles($currentDir)) {
                $name = [System.IO.Path]::GetFileName($file)

                if ($patterns.Count -gt 0) {
                    $matched = $false
                    foreach ($p in $patterns) { if ($name -like $p) { $matched = $true; break } }
                    if (-not $matched) { continue }
                }

                $fileCount++
                Invoke-DPIDFileScan -FilePath $file -Tracker $tracker -LogRoot $logRoot
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
    Write-Output ($f -f "Files scanned", $fileCount)
    Write-Output ($f -f "Files with DPIDs", $tracker.Files)
    Write-Output ($f -f "Total DPIDs", $tracker.Total)
    Write-Output ($f -f "Time", ("{0:N3} s" -f $sw.Elapsed.TotalSeconds))
}

# ===============================================================================================================================
# Log summary
# ===============================================================================================================================

if ($tracker.SavedFiles -gt 0) {
    Write-Output ($f -f "Logs", $logRoot)
    if (Test-Path $logRoot -PathType Container) {
        Invoke-Item -LiteralPath $logRoot
    }
}

Write-Output ""

# ===============================================================================================================================
