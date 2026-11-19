<#
.SYNOPSIS
    Scans files for 5x5 product keys.

.DESCRIPTION
    Searches a file or folder for 5x5 product keys by reading raw bytes as
    UTF-8, Unicode, and Big-Endian Unicode, or by decrypting SPP trusted store files.
    Unique keys are extracted per source file.

.PARAMETER File
    Path to a single file to scan.

.PARAMETER Folder
    Path to a folder to scan.

.PARAMETER TrustedStore
    Scans files as SPP trusted store files (e.g. data.dat).

.PARAMETER Recurse
    Recursively scan subdirectories when using -Folder.

.PARAMETER IncludeExtensions
    Filter files by wildcard pattern (e.g., "*.txt", "*.reg").

.PARAMETER Logs
    Enables saving of found keys to disk.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Common.psm1 for shared helper functions.

.EXAMPLE
    .\ScanKeysInFiles.ps1 -Folder "C:\Backups" -Recurse -Logs

.EXAMPLE
    .\ScanKeysInFiles.ps1 -File "C:\Windows\System32\spp\store\2.0\data.dat" -TrustedStore -Logs

.EXAMPLE
    .\ScanKeysInFiles.ps1 -Folder "C:\Backups\spp" -TrustedStore -Recurse -Logs
#>
[CmdletBinding()]
param(
    [string]   $File,
    [string]   $Folder,
    [switch]   $TrustedStore,
    [switch]   $Recurse,
    [string[]] $IncludeExtensions,
    [switch]   $Logs
)

# ===============================================================================================================================
# Initialization & dependencies
# ===============================================================================================================================

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "." }
Import-Module "$scriptDir\Libs\Common.psm1"

# ===============================================================================================================================
# Constants & helpers
# ===============================================================================================================================

# 5x5 key regex (case-insensitive, includes N for PKey2009, Z for redeem keys)
$KeyChars = 'BCDFGHJKMPQRTVWXY2346789N'
$KEY_PATTERN = "(?i)([$KeyChars]{5}-){4}[$KeyChars]{4}[${KeyChars}Z]"

function Invoke-FileKeyScan {
    # Scan a file for keys, print them, and optionally save them.
    param([string]$FilePath)

    if ($TrustedStore) {
        $results = @(Invoke-PassThruScript "ScanKeysInTrustedStore.ps1" @{ StorePath = $FilePath })
        $Keys = @($results | ForEach-Object { $_.ProductKey } | Where-Object { $_ } | Select-Object -Unique)
    }
    else {
        $Keys = @(Find-KeysInFile -FilePath $FilePath -Pattern $KEY_PATTERN)
    }
    if ($Keys.Count -eq 0) { return }

    $script:filesWithKeys++
    $script:totalKeys += $Keys.Count

    Write-Output "[$FilePath]"
    foreach ($k in $Keys) { Write-Output $k }
    Write-Output ""

    if ($Logs) {
        if (-not (Test-Path $logRoot)) { New-Item -ItemType Directory -Path $logRoot -Force | Out-Null }
        $fullPath = [System.IO.Path]::GetFullPath($FilePath)
        $safeName = $fullPath -replace '[:\\/]', '-'
        $outPath = Join-Path $logRoot "$safeName.txt"
        ($Keys -join "`r`n") | Out-File $outPath -Encoding UTF8
        $script:savedFiles += $outPath
    }
}

# ===============================================================================================================================
# Main execution
# ===============================================================================================================================

$sw = [System.Diagnostics.Stopwatch]::StartNew()

$script:savedFiles = @()
$script:totalKeys = 0
$script:filesWithKeys = 0
$base = Join-Path ([Environment]::GetFolderPath("Desktop")) "PKeyMaster-Logs"
$logRoot = Join-Path $base ("ScanKeys\" + (Get-Date -Format "yyyy-MM-dd_HH-mm-ss_fff"))

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
    if ($TrustedStore -and (-not $PSBoundParameters.ContainsKey('IncludeExtensions'))) {
        $IncludeExtensions = @('*.dat', '*.C7483456-A289-439d-8115-601632D005A0')
    }
    Write-Output "Folder  : $Folder"
    Write-Output "Recurse : $(if ($Recurse) { 'Yes' } else { 'No' })"
    Write-Output "Filter  : $(if ($IncludeExtensions) { $IncludeExtensions -join ', ' } else { '(all files)' })"
}
else {
    Write-Output "File    : $([System.IO.Path]::GetFileName($targetPath))"
}

if ($TrustedStore -and ($targetPath -like "$env:SystemRoot\System32*" -or $targetPath -like "$env:SystemRoot\Sysnative*")) {
    Write-Color "Note    : Store files on the live system may be locked." "FgYellow"
    Write-Color "          Use 'Get Installed Windows/Office Keys' option instead." "FgYellow"
}

Write-Output "Scanning, please wait..."
Write-Output ""

$script:totalKeys = 0
$script:filesWithKeys = 0

if (-not $isFolder) {
    Invoke-FileKeyScan -FilePath $targetPath

    $sw.Stop()
    Write-Output ""
    Write-Output "File  : $([System.IO.Path]::GetFileName($targetPath))"
    Write-Output "Keys  : $($script:totalKeys)"
    Write-Output ("Time  : {0:N3} s" -f $sw.Elapsed.TotalSeconds)
}
else {
    $patterns = @($IncludeExtensions | ForEach-Object { $_ -split '[,;]+' } | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() })
    $fileCount = 0

    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($targetPath)

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
    Write-Output "Files with keys : $($script:filesWithKeys)"
    Write-Output "Total keys      : $($script:totalKeys)"
    Write-Output ("Time            : {0:N3} s" -f $sw.Elapsed.TotalSeconds)
}

# ===============================================================================================================================
# Log summary
# ===============================================================================================================================

if ($script:savedFiles.Count -gt 0) {
    Write-Output ""
    Write-Output "Logs saved to   : $logRoot"
    if (Test-Path $logRoot -PathType Container) {
        Invoke-Item -LiteralPath $logRoot
    }
}

Write-Output ""

# ===============================================================================================================================
