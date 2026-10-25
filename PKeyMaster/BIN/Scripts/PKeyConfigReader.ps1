<#
.SYNOPSIS
    Reads PKeyConfig (.xrm-ms / .xml / .xrm) files and exports configuration and key-range data to CSV.

.DESCRIPTION
    Parses PKeyConfig files and exports configuration/key-range data to CSV.
    Output goes to Desktop\PKeyMaster-Logs\PKeyConfigs\<timestamp>.

.PARAMETER File
    Path to a single PKeyConfig file.

.PARAMETER Folder
    Path to a folder containing PKeyConfig files.

.PARAMETER Recurse
    (Batch) Recursively search the folder for PKeyConfig files.

.EXAMPLE
    # Export a single PKeyConfig to CSV (saved to Desktop\PKeyMaster-Logs)
    .\PKeyConfigReader.ps1 -File "C:\pkeyconfig.xrm-ms"

.EXAMPLE
    # Batch export all PKeyConfig files in a folder
    .\PKeyConfigReader.ps1 -Folder "C:\PKeyConfigs\" -Recurse

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Common.psm1 for shared helper functions.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$File = '',

    [string]$Folder = '',

    [switch]$Recurse
)

# ===============================================================================================================================
# Initialization & dependencies
# ===============================================================================================================================

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "." }
Import-Module "$scriptDir\Libs\Common.psm1"

# ===============================================================================================================================
# CSV export helpers
# ===============================================================================================================================

# Format a CSV-safe quoted row from an array of values.
function Format-CsvRow([string[]]$Values) {
    $escaped = foreach ($v in $Values) {
        '"{0}"' -f ($v -replace '"', '""')
    }
    return ($escaped -join ',')
}

# ===============================================================================================================================

function Invoke-ExportCsv([string]$FilePath, [string]$OutPath) {
    $xml = Read-PKeyConfigXml $FilePath
    if (-not $xml) { return $null }

    # Build a lookup of ActConfigId -> Configuration properties
    $configs = New-Object System.Collections.Specialized.OrderedDictionary
    foreach ($cfg in @($xml.SelectNodes("//*[local-name()='Configuration']"))) {
        $id = Get-NodeText $cfg 'ActConfigId'
        if (-not $id) { continue }
        $configs[$id] = @{
            RefGroupId         = Get-NodeText $cfg 'RefGroupId'
            EditionId          = Get-NodeText $cfg 'EditionId'
            ProductDescription = Get-NodeText $cfg 'ProductDescription'
            ProductKeyType     = Get-NodeText $cfg 'ProductKeyType'
            IsRandomized       = Get-NodeText $cfg 'IsRandomized'
        }
    }

    # Build a lookup of GroupId -> AlgorithmId
    $algoMap = @{}
    foreach ($pk in @($xml.SelectNodes("//*[local-name()='PublicKey']"))) {
        $gid = Get-NodeText $pk 'GroupId'
        if ($gid) { $algoMap[$gid] = Get-NodeText $pk 'AlgorithmId' }
    }

    # Build a lookup of ActConfigId -> list of KeyRange objects
    $rangeMap = @{}
    foreach ($kr in @($xml.SelectNodes("//*[local-name()='KeyRange']"))) {
        $refId = Get-NodeText $kr 'RefActConfigId'
        if (-not $refId) { continue }
        if (-not $rangeMap.ContainsKey($refId)) { $rangeMap[$refId] = New-Object 'System.Collections.Generic.List[object]' }

        $startVal = 0L
        $endVal = 0L
        $s = Get-NodeText $kr 'Start'
        if ($s) { $startVal = [long]$s }
        $e = Get-NodeText $kr 'End'
        if ($e) { $endVal = [long]$e }

        $rangeMap[$refId].Add(@{
                PartNumber = Get-NodeText $kr 'PartNumber'
                EulaType   = Get-NodeText $kr 'EulaType'
                IsValid    = Get-NodeText $kr 'IsValid'
                Start      = $startVal
                End        = $endVal
                TotalKeys  = ($endVal - $startVal + 1L)
            })
    }

    # Build CSV output
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add("sep=,")
    $headers = @("ActConfigID", "RefGroupID", "AlgorithmId", "EditionID", "ProductDescription", "ProductKeyType", "IsRandomized", "PartNumber", "EULAType", "IsValid", "Start", "End", "Total Keys")
    $lines.Add((Format-CsvRow $headers))

    # 7 empty columns used for continuation rows and subtotal rows
    $emptyPrefix = @("", "", "", "", "", "", "")

    foreach ($id in $configs.Keys) {
        $cfg = $configs[$id]
        $refGroupId = if ($cfg.RefGroupId) { $cfg.RefGroupId } else { '' }
        $algoId = if ($algoMap.ContainsKey($refGroupId)) { $algoMap[$refGroupId] } else { '' }

        if (-not $rangeMap.ContainsKey($id) -or $rangeMap[$id].Count -eq 0) {
            # Configuration without key ranges
            $row = @($id, $refGroupId, $algoId, $cfg.EditionId, $cfg.ProductDescription, $cfg.ProductKeyType, $cfg.IsRandomized, '', '', '', '', '', '0')
            $lines.Add((Format-CsvRow $row))
            $lines.Add((Format-CsvRow ($emptyPrefix + @("", "", "", "", "[SUBTOTAL]", "0"))))
            continue
        }

        $ranges = $rangeMap[$id]
        $subtotal = 0L
        $firstRow = $true

        foreach ($kr in $ranges) {
            $subtotal += $kr.TotalKeys
            $rangeFields = @($kr.PartNumber, $kr.EulaType, $kr.IsValid, [string]$kr.Start, [string]$kr.End, [string]$kr.TotalKeys)

            if ($firstRow) {
                $row = @($id, $refGroupId, $algoId, $cfg.EditionId, $cfg.ProductDescription, $cfg.ProductKeyType, $cfg.IsRandomized) + $rangeFields
                $firstRow = $false
            }
            else {
                $row = $emptyPrefix + $rangeFields
            }
            $lines.Add((Format-CsvRow $row))
        }

        # Subtotal row
        $lines.Add((Format-CsvRow ($emptyPrefix + @("", "", "", "", "[SUBTOTAL]", [string]$subtotal))))
    }

    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllLines($OutPath, [string[]]$lines, $utf8Bom)
    return ($lines.Count - 2)
}

# ===============================================================================================================================
# Main execution (Export mode)
# ===============================================================================================================================

if (-not $File -and -not $Folder) {
    Write-Color 'Specify -File or -Folder to export.' "BgRed"
    return
}

$files = @()
$basePath = ''

if ($File) {
    $resolvedPath = [System.IO.Path]::GetFullPath($File)
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) { Write-Color "File not found: $resolvedPath" "BgRed"; return }
    $files = @(Get-Item -LiteralPath $resolvedPath)
}
elseif ($Folder) {
    $resolvedPath = [System.IO.Path]::GetFullPath($Folder)
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Container)) { Write-Color "Folder not found: $resolvedPath" "BgRed"; return }
    $basePath = $resolvedPath.TrimEnd('\') + '\'
    
    $files += @(Get-ChildItem -LiteralPath $resolvedPath -Recurse:$Recurse -ErrorAction SilentlyContinue |
        Where-Object { (-not $_.PSIsContainer) -and ($_.Name -like '*.xrm-ms' -or $_.Name -like '*.xml' -or $_.Name -like '*.xrm') } |
        Sort-Object FullName)
}

if ($files.Count -eq 0) { Write-Color "No valid PKeyConfig files found." "BgRed"; return }

# Output directory: Desktop\PKeyMaster-Logs\PKeyConfigs\<timestamp>
$outputDir = Join-Path ([Environment]::GetFolderPath('Desktop')) ("PKeyMaster-Logs\PKeyConfigs\" + (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss_fff'))
if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }

$pad = -10
Write-Output ""
$sourceStr = if ($File) { [System.IO.Path]::GetFullPath($File) } else { [System.IO.Path]::GetFullPath($Folder) }
Write-Output ("{0,$pad}: {1}" -f "Source", $sourceStr)
if ($Folder) {
    $recurseStr = if ($Recurse) { "Yes" } else { "No" }
    Write-Output ("{0,$pad}: {1}" -f "Recurse", $recurseStr)
}
Write-Output ("{0,$pad}: {1}" -f "Output", $outputDir)
Write-Output ("{0,$pad}: {1}" -f "Files", $files.Count)
Write-Output ""

# ===============================================================================================================================
# File processing
# ===============================================================================================================================

Write-Output "Processing..."

$successCount = 0
$failureCount = 0

foreach ($f in $files) {
    # Preserve relative directory structure in output
    $targetDir = $outputDir
    if ($basePath -and $f.FullName.StartsWith($basePath, [StringComparison]::OrdinalIgnoreCase)) {
        $relPath = $f.FullName.Substring($basePath.Length)
        $relDir = [System.IO.Path]::GetDirectoryName($relPath)
        if ($relDir) {
            $targetDir = Join-Path $outputDir $relDir
            if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
        }
    }

    $randNum = Get-Random -Minimum 1000 -Maximum 10000
    $targetPath = Join-Path $targetDir ('{0}-Random{1}.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($f.Name), $randNum)

    try {
        $res = Invoke-ExportCsv $f.FullName $targetPath
        if ($null -ne $res) {
            $successCount++
            Write-Output ("{0,$pad}: {1}" -f "Success", $f.FullName)
        }
        else {
            $failureCount++
            Write-Color ("{0,$pad}: {1} (Invalid PKeyConfig)" -f "Failed", $f.FullName) "BgRed"
        }
    }
    catch {
        $failureCount++
        Write-Color ("{0,$pad}: {1} ({2})" -f "Failed", $f.FullName, $_.Exception.Message) "BgRed"
    }
}

# ===============================================================================================================================
# Summary
# ===============================================================================================================================

Write-Output ""
if ($failureCount -gt 0) {
    Write-Color ("{0,$pad}: Success {1}, Failed {2}" -f "Summary", $successCount, $failureCount) "BgRed"
}
else {
    Write-Color ("{0,$pad}: Success {1}, Failed {2}" -f "Summary", $successCount, $failureCount) "BgGreen"
}
Write-Output ""
if ($successCount -gt 0 -and (Test-Path $outputDir -PathType Container)) {
    Invoke-Item -LiteralPath $outputDir
}

# ===============================================================================================================================
