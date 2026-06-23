<#
.SYNOPSIS
    Scans files for 5x5 product keys.

.DESCRIPTION
    Searches a file or folder for 5x5 product keys by reading raw bytes as
    UTF-8, Unicode, and Big-Endian Unicode. Unique keys are extracted per source file.

.PARAMETER File
    Path to a single file to scan.

.PARAMETER Folder
    Path to a folder to scan.

.PARAMETER Recurse
    Recursively scan subdirectories when using -Folder.

.PARAMETER IncludeExtensions
    Filter files by wildcard pattern (e.g., "*.txt", "*.reg").

.PARAMETER Logs
    Enables saving of found keys to disk.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Common.ps1 for shared helper functions.

.EXAMPLE
    .\ScanKeysInFiles.ps1 -Folder "C:\Backups" -Recurse -Logs
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

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "." }
$commonPath = Join-Path $scriptDir "libs\Common.ps1"
if (Test-Path $commonPath) { . $commonPath }

# ===============================================================================================================================
# Constants & helpers
# ===============================================================================================================================

# 5x5 key regex (case-insensitive, includes N for PKey2009)
$KEY_PATTERN = '(?i)[BCDFGHJKMPQRTVWXY2346789N]{5}(-[BCDFGHJKMPQRTVWXY2346789N]{5}){4}'

function Find-KeysInFile {
    # Read file in multiple encodings and extract unique 5x5 keys via regex.
    param([string]$FilePath)

    $keys = @()
    try { 
        $fileInfo = New-Object System.IO.FileInfo($FilePath)
        if ($fileInfo.Length -eq 0 -or $fileInfo.Length -gt 100MB) { return $keys }
        $bytes = [System.IO.File]::ReadAllBytes($FilePath) 
    }
    catch { return @() }

    $seen = @{}
    
    # By reading as ASCII and removing null characters, we can scan UTF-8, Unicode, and BigEndianUnicode in a single pass
    $text = [System.Text.Encoding]::ASCII.GetString($bytes).Replace("`0", "")
    foreach ($m in [regex]::Matches($text, $KEY_PATTERN)) {
        $key = $m.Value.ToUpper()
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $hash = @{}
            foreach ($c in $key.ToCharArray()) { if ($c -ne '-') { $hash[$c] = $true } }
            if ($hash.Count -ge 3) { $keys += $key }
        }
    }
    return $keys
}

# ===============================================================================================================================

function Invoke-FileKeyScan {
    # Scan a file for keys, print them, and optionally save them.
    param([string]$FilePath)
    
    $keys = @(Find-KeysInFile -FilePath $FilePath)
    if ($keys.Count -eq 0) { return }

    $global:filesWithKeys++
    $global:totalKeys += $keys.Count

    Write-Output "[$FilePath]"
    foreach ($k in $keys) { Write-Output $k }
    Write-Output ""

    if ($Logs) {
        if (-not (Test-Path $logRoot)) { New-Item -ItemType Directory -Path $logRoot -Force | Out-Null }
        $fullPath = [System.IO.Path]::GetFullPath($FilePath)
        $safeName = $fullPath -replace '[:\\/]', '-'
        $outPath = Join-Path $logRoot "$safeName.txt"
        ($keys -join "`r`n") | Out-File $outPath -Encoding UTF8
        $global:savedFiles += $outPath
    }
}

# ===============================================================================================================================

# Main execution
# ===============================================================================================================================

$sw = [System.Diagnostics.Stopwatch]::StartNew()

$global:savedFiles = @()
$base = Join-Path ([Environment]::GetFolderPath("Desktop")) "PKeyMaster-Logs"
$logRoot = Join-Path $base ("ScanKeys\" + (Get-Date -Format "yyyy-MM-dd_HH-mm-ss_fff"))

if ($File) {

    if (-not (Test-Path $File -PathType Leaf -ErrorAction SilentlyContinue)) {
        Write-Color "Error: File does not exist: $File" "BgRed"; return
    }

    Write-Output "File    : $([System.IO.Path]::GetFileName($File))"
    Write-Output "Scanning, please wait..."
    Write-Output ""

    $global:totalKeys = 0
    $global:filesWithKeys = 0
    Invoke-FileKeyScan -FilePath $File

    $sw.Stop()
    Write-Output ""
    Write-Output "File  : $([System.IO.Path]::GetFileName($File))"
    Write-Output "Keys  : $($global:totalKeys)"
    Write-Output ("Time  : {0:N3} s" -f $sw.Elapsed.TotalSeconds)

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
    $global:filesWithKeys = 0
    $global:totalKeys = 0

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
                Invoke-FileKeyScan -FilePath $f
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
    Write-Output ""
    Write-Output "Files scanned   : $fileCount"
    Write-Output "Files with keys : $($global:filesWithKeys)"
    Write-Output "Total keys      : $($global:totalKeys)"
    Write-Output ("Time            : {0:N3} s" -f $sw.Elapsed.TotalSeconds)

}
else {
    Write-Color "Error: Specify -File or -Folder." "BgRed"
}

# ===============================================================================================================================
# Log summary
# ===============================================================================================================================

if ($global:savedFiles.Count -gt 0) {
    Write-Output ""
    Write-Output "Logs saved to   : $logRoot"
}

Write-Output ""

# ===============================================================================================================================
