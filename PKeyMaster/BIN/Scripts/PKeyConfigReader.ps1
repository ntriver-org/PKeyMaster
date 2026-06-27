<#
.SYNOPSIS
    Reads PKeyConfig (.xrm-ms / .xml / .xrm) files and either looks up key metadata or exports data to CSV.

.DESCRIPTION
    Two modes:

    1. GetKeyInfo Mode (-GetKeyInfo)
       Looks up an ActConfigId in a PKeyConfig file and returns product description,
       edition, key type, and algorithm. Used by KeyCheckerPidGenX.ps1 via -PassThru.

    2. Export Mode (default)
       Parses PKeyConfig files and exports configuration/key-range data to CSV.
       Output goes to Desktop\PKeyMaster-Logs\PKeyConfigs\<timestamp>.

.PARAMETER File
    Path to a single PKeyConfig file.

.PARAMETER Folder
    Path to a folder containing PKeyConfig files.

.PARAMETER Recurse
    (Export mode, batch) Recursively search the folder for PKeyConfig files.

.PARAMETER GetKeyInfo
    Switch to enable GetKeyInfo mode.

.PARAMETER ActConfigId
    (GetKeyInfo mode) The Activation Config ID (GUID) to look up.

.PARAMETER GroupId
    (GetKeyInfo mode) Optional Group ID to resolve the Algorithm ID.

.PARAMETER PassThru
    (GetKeyInfo mode) Returns a PSObject instead of printing to console.

.EXAMPLE
    # Look up key info (used by KeyCheckerPidGenX.ps1)
    .\PKeyConfigReader.ps1 -GetKeyInfo -File "C:\PKeyConfigs\pkeyconfig.xrm-ms" -ActConfigId "{guid}" -GroupId 123 -PassThru

.EXAMPLE
    # Export a single PKeyConfig to CSV (saved to Desktop\PKeyMaster-Logs)
    .\PKeyConfigReader.ps1 -File "C:\pkeyconfig.xrm-ms"

.EXAMPLE
    # Batch export all PKeyConfig files in a folder
    .\PKeyConfigReader.ps1 -Folder "C:\PKeyConfigs\" -Recurse

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Common.ps1 for shared helper functions.
#>

[CmdletBinding(DefaultParameterSetName = 'Export')]
param(
    [Parameter(ParameterSetName = 'Export', Position = 0)]
    [Parameter(ParameterSetName = 'GetKeyInfo')]
    [string]$File = '',

    [Parameter(ParameterSetName = 'Export')]
    [string]$Folder = '',

    [Parameter(ParameterSetName = 'Export')]
    [switch]$Recurse,

    [Parameter(ParameterSetName = 'GetKeyInfo', Mandatory = $true)]
    [switch]$GetKeyInfo,

    [Parameter(ParameterSetName = 'GetKeyInfo', Mandatory = $true)]
    [string]$ActConfigId,

    [Parameter(ParameterSetName = 'GetKeyInfo')]
    [uint32]$GroupId = 0,

    [Parameter(ParameterSetName = 'GetKeyInfo')]
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
# XML helpers
# ===============================================================================================================================

# Read a .xrm-ms file, decode the base64 pkeyConfigData, return the inner XML.
function Read-PKeyConfigXml {
    param([string]$FilePath)
    $script:Script_ReadPKeyConfigXmlError = $null
    if (-not (Test-Path -LiteralPath $FilePath)) { $script:Script_ReadPKeyConfigXmlError = "File not found: $FilePath"; return $null }

    $raw = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::UTF8).TrimStart([char]0xFEFF)
    [xml]$xrm = $raw

    $binNode = $xrm.SelectSingleNode("//*[local-name()='infoBin' and @name='pkeyConfigData']")
    if (-not $binNode) { $script:Script_ReadPKeyConfigXmlError = "Not a valid PKeyConfig file (missing pkeyConfigData): $FilePath"; return $null }

    $bytes = [Convert]::FromBase64String($binNode.InnerText.Trim())
    $xmlStr = [System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
    return [xml]$xmlStr
}

# ===============================================================================================================================

function Test-PKeyConfigFile {
    # True if the file has a valid pkeyConfigData element.
    param([string]$FilePath)
    try {
        $raw = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::UTF8)
        if ($raw.IndexOf('pkeyConfigData') -lt 0) { return $false }
        return ($raw -match '<[^>]*infoBin[^>]+name\s*=\s*["'']pkeyConfigData["'']')
    }
    catch { return $false }
}

# ===============================================================================================================================

function Get-NodeText($Node, $LocalName) {
    $n = $Node.SelectSingleNode("*[local-name()='$LocalName']")
    if ($n) { return $n.InnerText.Trim() }
    return ''
}

# ===============================================================================================================================
# GetKeyInfo mode
# ===============================================================================================================================

# Look up Description, Edition, KeyType, Algorithm for an ActConfigId + GroupId
function Get-PKeyInfo {
    param(
        [string]$FilePath,
        [string]$ActConfigId,
        [uint32]$GroupId
    )

    $xml = Read-PKeyConfigXml $FilePath
    if (-not $xml) { if ($script:Script_ReadPKeyConfigXmlError) { Write-Output $script:Script_ReadPKeyConfigXmlError }; return $null }
    # Find the Configuration node matching our ActConfigId
    $desc = ''
    $ed = ''
    $ktype = ''
    $needle = $ActConfigId.Trim().Trim('{', '}').ToLower()

    foreach ($cfg in @($xml.SelectNodes("//*[local-name()='Configuration']"))) {
        $n = $cfg.SelectSingleNode("*[local-name()='ActConfigId']")
        if ($n -and $n.InnerText.Trim().Trim('{', '}').ToLower() -eq $needle) {
            $desc = Get-NodeText $cfg 'ProductDescription'
            $ed = Get-NodeText $cfg 'EditionId'
            $ktype = Get-NodeText $cfg 'ProductKeyType'
            break
        }
    }

    # Look up the AlgorithmId from the matching PublicKey
    $algId = ''
    if ($null -ne $GroupId) {
        $gStr = [string]$GroupId
        foreach ($pk in @($xml.SelectNodes("//*[local-name()='PublicKey']"))) {
            $gn = $pk.SelectSingleNode("*[local-name()='GroupId']")
            $an = $pk.SelectSingleNode("*[local-name()='AlgorithmId']")
            if ($gn -and $gn.InnerText.Trim() -eq $gStr -and $an) {
                $algId = $an.InnerText.Trim()
                break
            }
        }
    }

    return New-Object PSObject -Property @{
        Description = $desc
        Edition     = $ed
        KeyType     = $ktype
        Algorithm   = $algId
    }
}

# ===============================================================================================================================
# CSV export helpers
# ===============================================================================================================================

# Format a CSV-safe quoted row from an array of values.
function Format-CsvRow([string[]]$Values) {
    return (($Values | ForEach-Object { '"{0}"' -f ($_ -replace '"', '""') }) -join ',')
}

# ===============================================================================================================================

function Invoke-ExportCsv([string]$FilePath, [string]$OutPath) {
    $xml = Read-PKeyConfigXml $FilePath
    if (-not $xml) { if ($script:Script_ReadPKeyConfigXmlError) { Write-Output $script:Script_ReadPKeyConfigXmlError }; return $null }
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
            IsRandomized       = (Get-NodeText $cfg 'IsRandomized').ToUpper()
        }
    }

    # Build a lookup of GroupId -> AlgorithmId
    $algoMap = @{}
    foreach ($pk in @($xml.SelectNodes("//*[local-name()='PublicKey']"))) {
        $gid = Get-NodeText $pk 'GroupId'
        if ($gid) { $algoMap[$gid] = Get-NodeText $pk 'AlgorithmId' }
    }

    # Build a lookup of ActConfigId -> list of KeyRange objects
    $rangeMap = New-Object System.Collections.Specialized.OrderedDictionary
    foreach ($kr in @($xml.SelectNodes("//*[local-name()='KeyRange']"))) {
        $refId = Get-NodeText $kr 'RefActConfigId'
        if (-not $refId) { continue }
        if (-not $rangeMap.Contains($refId)) { $rangeMap[$refId] = New-Object 'System.Collections.Generic.List[PSObject]' }

        $startVal = 0L; $endVal = 0L
        $s = Get-NodeText $kr 'Start'; if ($s) { $startVal = [long]$s }
        $e = Get-NodeText $kr 'End'; if ($e) { $endVal = [long]$e }

        $rangeMap[$refId].Add((New-Object PSObject -Property @{
                    PartNumber = Get-NodeText $kr 'PartNumber'
                    EulaType   = Get-NodeText $kr 'EulaType'
                    IsValid    = Get-NodeText $kr 'IsValid'
                    Start      = $startVal
                    End        = $endVal
                    TotalKeys  = $endVal - $startVal + 1L
                }))
    }

    # Build CSV output
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $headers = @("ActConfigID", "RefGroupID", "AlgorithmId", "EditionID", "ProductDescription", "ProductKeyType", "IsRandomized", "PartNumber", "EULAType", "IsValid", "Start", "End", "Total Keys")
    $lines.Add((Format-CsvRow $headers))

    # 7 empty columns used for continuation rows and subtotal rows
    $emptyPrefix = @("", "", "", "", "", "", "")

    foreach ($id in $rangeMap.Keys) {
        try { [System.Windows.Forms.Application]::DoEvents() } catch { }

        $ranges = $rangeMap[$id]
        $cfg = if ($configs.Contains($id)) { $configs[$id] } else { @{} }
        $refGroupId = if ($cfg.RefGroupId) { $cfg.RefGroupId } else { '' }
        $algoId = if ($algoMap.ContainsKey($refGroupId)) { $algoMap[$refGroupId] } else { '' }

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
    [System.IO.File]::WriteAllText($OutPath, ($lines -join "`r`n"), $utf8Bom)
    return ($lines.Count - 1)
}

# ===============================================================================================================================
# Main execution
# ===============================================================================================================================

if ($GetKeyInfo) {
    # --- GetKeyInfo mode: look up key metadata and return ---
    try {
        if (-not $File) { Write-Color "File parameter is required for GetKeyInfo." "BgRed"; return }
        $outObj = Get-PKeyInfo -FilePath $File -ActConfigId $ActConfigId -GroupId $GroupId
        if ($PassThru) { return $outObj }
        $outObj | Format-List
    }
    catch {
        if ($PassThru) { return $null }
        Write-Color $_.Exception.Message "BgRed"
        return
    }
    return
}

# ===============================================================================================================================
# Export mode
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
    if (-not (Test-PKeyConfigFile $resolvedPath)) { Write-Color "Not a valid PKeyConfig file (missing pkeyConfigData): $resolvedPath" "BgRed"; return }
    $files += Get-Item -LiteralPath $resolvedPath
}
elseif ($Folder) {
    $resolvedPath = [System.IO.Path]::GetFullPath($Folder)
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Container)) { Write-Color "Folder not found: $resolvedPath" "BgRed"; return }
    $basePath = $resolvedPath.TrimEnd('\') + '\'
    
    $files += @(Get-ChildItem -LiteralPath $resolvedPath -Recurse:$Recurse -ErrorAction SilentlyContinue |
        Where-Object { (-not $_.PSIsContainer) -and ($_.Name -like '*.xrm-ms' -or $_.Name -like '*.xml' -or $_.Name -like '*.xrm') -and (Test-PKeyConfigFile $_.FullName) } |
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

# ===============================================================================================================================
