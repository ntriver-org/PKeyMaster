<#
.SYNOPSIS
    Retrieves Confirmation IDs (CIDs) for one or more Installation IDs (IIDs).

.DESCRIPTION
    Takes a single Installation ID or a text file with multiple IIDs, then queries
    Microsoft's BatchApi (with VisualApi fallback) to get Confirmation IDs.
    Results can be exported to timestamped or caller-specified log folders.

.PARAMETER InstallationId
    A single Installation ID string (50, 54, 59, or 63 digits, dashes allowed).

.PARAMETER IidFile
    Path to a text file containing one or more Installation IDs.

.PARAMETER LogPath
    Optional base folder for log output. Used only with -ExportLogs.

    Example:
        -ExportLogs -LogPath "D:\Logs"
        Saves logs under: D:\Logs\GetCID\<timestamp>

    If omitted, the base folder is Desktop\PKeyMaster-Logs, so logs are saved under:
        Desktop\PKeyMaster-Logs\GetCID\<timestamp>

.PARAMETER ExactLogPath
    Uses -LogPath as the final log root instead of appending GetCID\<timestamp>.
    This option only has effect when -ExportLogs and -LogPath are supplied.

    Example:
        -ExportLogs -LogPath "D:\Logs\CurrentIID" -ExactLogPath
        Saves logs directly under: D:\Logs\CurrentIID

    In file mode, per-IID subfolders are still created under the exact path to avoid
    overwriting each IID's logs.

.PARAMETER ExportLogs
    Enables saving result files and raw API payload logs to disk.

    Examples:
        -ExportLogs
        Saves under: Desktop\PKeyMaster-Logs\GetCID\<timestamp>

        -ExportLogs -LogPath "D:\Logs"
        Saves under: D:\Logs\GetCID\<timestamp>

        -ExportLogs -LogPath "D:\Logs\CurrentIID" -ExactLogPath
        Saves directly under: D:\Logs\CurrentIID

.PARAMETER PassThru
    Returns structured PSObjects instead of only writing to the console.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires GetCidBatchApi.ps1 and GetCidVisualApi.ps1 for CID retrieval.
    Requires Libs\Common.ps1 for shared helper functions.

.EXAMPLE
    .\GetCID.ps1 -InstallationId "123456789012345678901234567890123456789012345678901234"

.EXAMPLE
    .\GetCID.ps1 -IidFile "C:\iids.txt" -ExportLogs
#>
[CmdletBinding()]
param(
    [string]$InstallationId = '',
    [string]$IidFile = '',
    [string]$LogPath = '',
    [switch]$ExactLogPath,
    [switch]$ExportLogs,
    [switch]$PassThru
)

# ===============================================================================================================================
# Initialization & setup
# ===============================================================================================================================

$_scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $_scriptDir) { $_scriptDir = "." }

$commonPath = Join-Path $_scriptDir "libs\Common.ps1"
if (Test-Path $commonPath) { . $commonPath }
$batchApiScript = Join-Path $_scriptDir "GetCidBatchApi.ps1"
$visualApiScript = Join-Path $_scriptDir "GetCidVisualApi.ps1"

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function Remove-OutputMarkup([string]$Line) {
    if ($null -eq $Line) { return "" }
    return ($Line -replace '\x1b\[[0-9;]*m', '' -replace '\[c:[^\]]+\]', '')
}

# ===============================================================================================================================

function Add-IidToCsv([string[]]$OutputLines, [string[]]$Columns, [string]$CsvPath) {
    # Parse "Key : Value" output lines into a CSV row.
    # Write the header on first call.

    $writeHeader = -not (Test-Path $CsvPath)
    if ($writeHeader) {
        $headerLine = ($Columns | ForEach-Object { '"{0}"' -f ($_ -replace '"', '""') }) -join ","
        $headerLine | Out-File $CsvPath -Encoding UTF8
    }

    $obj = @{}
    foreach ($col in $Columns) { $obj[$col] = "" }

    foreach ($line in $OutputLines) {
        $line = Remove-OutputMarkup $line
        if ($line -match "^(.+?)\s*:\s*(.*)$") {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim()
            
            if ($obj.ContainsKey($key)) {
                if ($obj[$key] -eq "") {
                    $obj[$key] = $val
                }
                else {
                    $obj[$key] += " | " + $val
                }
            }
        }
    }

    $rowValues = @()
    foreach ($col in $Columns) {
        $val = $obj[$col]
        if ($null -eq $val) { $val = "" }
        $escaped = $val -replace '"', '""'
        if ($val -match '^\d{12,}$') {
            $rowValues += '="{0}"' -f $escaped
        }
        else {
            $rowValues += '"{0}"' -f $escaped
        }
    }
    $rowLine = $rowValues -join ","
    $rowLine | Out-File $CsvPath -Encoding UTF8 -Append
}

# ===============================================================================================================================

function Get-IidFromText([string]$Text) {
    # Extract unique 50/54/59/63-digit IIDs from text.
    $clean = $Text -replace '-', ''
    [regex]::Matches($clean, '\b\d{50}\b|\b\d{54}\b|\b\d{59}\b|\b\d{63}\b') |
    ForEach-Object { $_.Value } |
    Select-Object -Unique
}

# ===============================================================================================================================

function Format-Iid([string]$IID) {
    if (-not $IID) { return "" }
    return ($IID -replace '\D', '')
}

# ===============================================================================================================================

# Call a CID script and wrap the result with timing info.
function Invoke-CidApi([string]$ScriptPath, [string]$IID, [string]$LogFolder) {
    $queryStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    if ($ExportLogs) {
        $apiOut = @(& $ScriptPath -InstallationId $IID -LogPath $LogFolder -PassThru)
    }
    else {
        $apiOut = @(& $ScriptPath -InstallationId $IID -PassThru)
    }
    $queryStopwatch.Stop()

    $apiObj = $null
    $apiLines = @()

    if ($apiOut.Count -gt 0) {
        $apiObj = $apiOut[-1]
        if ($apiOut.Count -gt 1) { $apiLines = $apiOut[0..($apiOut.Count - 2)] }
        if ($apiLines.Count -gt 0) { $apiLines = @($apiLines | Where-Object { $_ -notmatch '^Log Status\s*:' }) }
        if ($apiLines.Count -gt 0) { $apiLines += ($f -f "Query Time", ("{0:N3} s" -f $queryStopwatch.Elapsed.TotalSeconds)) }
    }

    return New-Object PSObject -Property @{
        Object = $apiObj
        Lines  = $apiLines
    }
}

# ===============================================================================================================================
# CSV column definitions
# ===============================================================================================================================

$csvCols = @("Installation ID", "API Source", "Confirmation ID", "Error Code", "Error Detail", "Query Time")

# ===============================================================================================================================
# Input resolution
# ===============================================================================================================================

$lineSeparator = @(
    "",
    "--------------------------------------------------------------"
)

$f = "{0,-18}: {1}"

$iidsToCheck = @()

# Log folder setup
$logRoot = ""

if ($ExportLogs) {
    if ($ExactLogPath -and $LogPath) {
        $logRoot = $LogPath
    }
    else {
        $base = $LogPath
        if (-not $base) {
            $base = Join-Path ([Environment]::GetFolderPath("Desktop")) "PKeyMaster-Logs"
        }
        $logRoot = Join-Path $base ("GetCID\" + (Get-Date -Format "yyyy-MM-dd_HH-mm-ss_fff"))
    }
    if (-not (Test-Path $logRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    }
    if (-not (Test-Path $logRoot -PathType Container)) {
        Write-Color "Failed to create log folder: $logRoot" "BgRed"
        return
    }
}

if ($IidFile) {
    $batchStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $resolvedFile = [System.IO.Path]::GetFullPath($IidFile)

    if (-not (Test-Path $resolvedFile -PathType Leaf)) {
        Write-Color "File not found or not a file: $resolvedFile" "BgRed"
        return 
    }

    # By reading as ASCII and removing null characters, we can scan UTF-8, Unicode, and BigEndianUnicode in a single pass
    $bytes = [System.IO.File]::ReadAllBytes($resolvedFile)
    $content = [System.Text.Encoding]::ASCII.GetString($bytes).Replace("`0", "")
    $extracted = @(Get-IidFromText $content | Select-Object -Unique)

    if ($extracted.Count -eq 0) { 
        Write-Color "No valid Installation IDs found in: $resolvedFile" "BgRed"
        return 
    }

    Write-Output ($f -f "Source", $resolvedFile)
    Write-Output ($f -f "IIDs Found", $extracted.Count)
    Write-Output $lineSeparator
    $iidsToCheck = $extracted
}
elseif ($InstallationId) {
    $clean = Format-Iid $InstallationId

    if ($clean.Length -ne 50 -and $clean.Length -ne 54 -and $clean.Length -ne 59 -and $clean.Length -ne 63) {
        Write-Color "Invalid Installation ID length ($($clean.Length)). Must be 50, 54, 59, or 63 digits." "BgRed"
        return
    }

    $iidsToCheck = @($clean)
}
else {
    Write-Color "Provide -InstallationId or -IidFile." "BgRed"
    return
}

# ===============================================================================================================================
# Main processing loop
# ===============================================================================================================================

$passThruObjects = @()

$randNum = Get-Random -Minimum 1000 -Maximum 10000

foreach ($iid in $iidsToCheck) {
    if (-not $IidFile) {
        Write-Output ($f -f "Checking IID", $iid)
    }

    # Per-IID log folder
    $iidFolder = ""
    if ($ExportLogs) {
        if ($ExactLogPath -and -not $IidFile) {
            $iidFolder = $logRoot
        }
        else {
            $iidFolder = Join-Path $logRoot $iid
        }
        if (-not (Test-Path $iidFolder -PathType Container)) {
            New-Item -ItemType Directory -Path $iidFolder -Force | Out-Null
        }
        if (-not (Test-Path $iidFolder -PathType Container)) {
            Write-Color "Failed to create log folder: $iidFolder" "BgRed"
            return
        }
    }

    # Try BatchApi
    $batchResult = Invoke-CidApi $batchApiScript $iid $iidFolder
    $batchObj = $batchResult.Object
    $batchLines = @($batchResult.Lines)

    # Fallback to VisualApi if BatchApi did not succeed
    $visualObj = $null
    $visualLines = @()

    if (-not $batchObj -or $batchObj.Result -ne "SUCCESS") {
        $visualResult = Invoke-CidApi $visualApiScript $iid $iidFolder
        $visualObj = $visualResult.Object
        $visualLines = @($visualResult.Lines)
    }

    # Combine output from both APIs so both are visible on console and in logs
    $allLines = @()
    if ($batchLines.Count -gt 0) { $allLines += $batchLines }
    if ($visualLines.Count -gt 0) { $allLines += $visualLines }

    # Final result object: prefer VisualApi when it ran, otherwise keep BatchApi.
    $finalObj = if ($visualObj) { $visualObj } else { $batchObj }

    if ($IidFile) { $allLines += $lineSeparator }

    # Console output
    $allLines | Write-Output

    # Build PassThru object
    if ($PassThru) {
        $passThruObjects += New-Object PSObject -Property @{
            InstallationId    = $iid
            BatchResult       = if ($batchObj) { $batchObj.Result } else { $null }
            BatchCID          = if ($batchObj) { $batchObj.CID } else { $null }
            BatchErrorCode    = if ($batchObj) { $batchObj.ErrorCode } else { $null }
            BatchErrorDetail  = if ($batchObj) { $batchObj.ErrorDetail } else { $null }
            VisualResult      = if ($visualObj) { $visualObj.Result } else { $null }
            VisualCID         = if ($visualObj) { $visualObj.CID } else { $null }
            VisualErrorCode   = if ($visualObj) { $visualObj.ErrorCode } else { $null }
            VisualErrorDetail = if ($visualObj) { $visualObj.ErrorDetail } else { $null }
            Result            = if ($finalObj) { $finalObj.Result } else { $null }
            CID               = if ($finalObj) { $finalObj.CID } else { $null }
            ErrorCode         = if ($finalObj) { $finalObj.ErrorCode } else { $null }
            ErrorDetail       = if ($finalObj) { $finalObj.ErrorDetail } else { $null }
        }
    }

    # File logging
    if ($ExportLogs) {
        # Strip ANSI escape codes and any GUI color tags for clean file output
        $cleanLines = $allLines | ForEach-Object { Remove-OutputMarkup $_ }

        # Save the combined console output
        if ($cleanLines) { ($cleanLines -join "`r`n") | Out-File (Join-Path $iidFolder "CidInfo.txt") -Encoding UTF8 }

        # In batch file mode, also append to the combined all-IIDs summary files
        if ($IidFile) {
            $allTxt = Join-Path $logRoot "CidInfoAll.txt"
            $allCsv = Join-Path $logRoot ("CidInfoAll-Random{0}.csv" -f $randNum)
            $cleanLines | Out-File $allTxt -Encoding UTF8 -Append

            # Write one CSV row per API used - BatchApi always, VisualApi only when it was a fallback
            Add-IidToCsv $batchLines $csvCols $allCsv
            if ($visualObj) {
                Add-IidToCsv $visualLines $csvCols $allCsv
            }
        }
    }
}

# ===============================================================================================================================
# Batch summary
# ===============================================================================================================================

if ($IidFile -or ($ExportLogs -and $logRoot)) {
    Write-Output ""
    if ($IidFile) {
        $batchStopwatch.Stop()
        $elapsed = $batchStopwatch.Elapsed
        Write-Output ($f -f "Total Batch Time", ("{0} min {1} sec" -f [Math]::Floor($elapsed.TotalMinutes), $elapsed.Seconds))
    }
    if ($ExportLogs -and $logRoot) {
        Write-Output ($f -f "Logs Saved To", $logRoot)
    }
}

Write-Output ""

# ===============================================================================================================================
# Object return (PassThru)
# ===============================================================================================================================

if ($PassThru) {
    return $passThruObjects
}

# ===============================================================================================================================
