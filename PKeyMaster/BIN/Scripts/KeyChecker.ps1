<#
.SYNOPSIS
    Routes product key checks to the appropriate backend (PidGenX or Pre-98).

.DESCRIPTION
    Accepts a single product key or a file of them, auto-detects the format
    (5x5, OEM, 10-digit, 11-digit), and dispatches to KeyCheckerPidGenX.ps1
    or KeyCheckerPre98.ps1. Results go to timestamped or caller-specified log folders.

.PARAMETER ProductKey
    A single product key string to check.

.PARAMETER KeyFile
    Path to a file containing one or more product keys.

.PARAMETER PKeyConfigPath
    Manual path to a specific PKeyConfig file (overrides auto-search).

.PARAMETER ProfileName
    Manual profile name to display (used with PKeyConfigPath).

.PARAMETER KeyCertification
    Enables key certification via the SL certification service.

.PARAMETER KeyActivation
    Enables key activation via the SL activation service.

.PARAMETER MAKCount
    Enables MAK remaining count query.

.PARAMETER GetInstallationId
    Enables Installation ID retrieval via GetPKeyData.

.PARAMETER GetConfirmationId
    Enables Confirmation ID retrieval via the BatchApi, with VisualApi fallback.

.PARAMETER KeyCheckMode
    Routing mode: "Automatic" (default), "PidGenX", or "Pre-98".

.PARAMETER LogPath
    Optional base folder for log output. Used only with -ExportLogs.

    Example:
        -ExportLogs -LogPath "D:\Logs"
        Saves logs under: D:\Logs\KeyChecker\<timestamp>

    If omitted, the base folder is Desktop\PKeyMaster-Logs, so logs are saved under:
        Desktop\PKeyMaster-Logs\KeyChecker\<timestamp>

.PARAMETER ExactLogPath
    Uses -LogPath as the final log root instead of appending KeyChecker\<timestamp>.
    This option only has effect when -ExportLogs and -LogPath are supplied.

    Example:
        -ExportLogs -LogPath "D:\Logs\CurrentKey" -ExactLogPath
        Saves logs directly under: D:\Logs\CurrentKey

    In file mode, per-key subfolders are still created under the exact path to avoid
    overwriting each key's logs.

.PARAMETER ExportLogs
    Enables saving result files and API payload logs to disk.

    Examples:
        -ExportLogs
        Saves under: Desktop\PKeyMaster-Logs\KeyChecker\<timestamp>

        -ExportLogs -LogPath "D:\Logs"
        Saves under: D:\Logs\KeyChecker\<timestamp>

        -ExportLogs -LogPath "D:\Logs\CurrentKey" -ExactLogPath
        Saves directly under: D:\Logs\CurrentKey

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires KeyCheckerPidGenX.ps1 and KeyCheckerPre98.ps1 for key checking.
    Requires Libs\Common.ps1 for shared helper functions.

.EXAMPLE
    .\KeyChecker.ps1 -ProductKey "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"

.EXAMPLE
    .\KeyChecker.ps1 -KeyFile "C:\keys.txt" -ExportLogs -KeyCertification
#>
[CmdletBinding()]
param(
    [string]$ProductKey = '',
    [string]$KeyFile = '',
    [string]$PKeyConfigPath = '',
    [string]$ProfileName = '',
    [switch]$KeyCertification,
    [switch]$KeyActivation,
    [switch]$MAKCount,
    [switch]$GetInstallationId,
    [switch]$GetConfirmationId,
    [ValidateSet('Automatic', 'PidGenX', 'Pre-98')]
    [string]$KeyCheckMode = 'Automatic',
    [string]$LogPath = '',
    [switch]$ExactLogPath,
    [switch]$ExportLogs
)

# ===============================================================================================================================
# Initialization & setup
# ===============================================================================================================================

$_scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $_scriptDir) { $_scriptDir = "." }

$commonPath = Join-Path $_scriptDir "libs\Common.ps1"
if (Test-Path $commonPath) { . $commonPath }

$pidGenXScript = Join-Path $_scriptDir "KeyCheckerPidGenX.ps1"
$pre98Script = Join-Path $_scriptDir "KeyCheckerPre98.ps1"

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function Remove-OutputMarkup([string]$Line) {
    if ($null -eq $Line) { return "" }
    return ($Line -replace '\x1b\[[0-9;]*m', '' -replace '\[c:[^\]]+\]', '')
}

# ===============================================================================================================================

function Add-KeyToCsv([string[]]$OutputLines, [string[]]$Columns, [string]$CsvPath) {
    # Parse "Key : Value" lines into a CSV row.
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
# CSV column definitions
# ===============================================================================================================================

$colsPre98 = @("Product Key", "Result", "Product Match", "Query Time")

$colsPidGenX = @(
    "Product Key", "Profile", "Result", "PidGenX ErrorCode",
    "Product ID", "Extended PID", "Installation ID", "ActConfig ID", "Activation ID",
    "Description", "Edition", "Part number", "Label ID", "Key Type", "EULA",
    "Algorithm ID", "Group ID", "Key ID", "Channel ID", "Sequence",
    "Bink", "Hash", "Auth", "Signature",
    "License Type", "Upgrade Key", "Product Match",
    "PKey2009 Security", "PKey2009 Extra",
    "Key Certification", "Cert Error Code", "Cert Error Msg",
    "Key Activation", "Act Error Code", "Act Error Msg",
    "MAK Count", "MAK Error Code", "MAK Error Msg",
    "CID Batch Api", "Batch Error Code", "Batch Error Msg",
    "CID Visual Api", "Visual Error Code", "Visual Error Msg",
    "Query Time"
)

# ===============================================================================================================================
# Key format regex patterns
# ===============================================================================================================================

# Standard 5x5 key (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)
$Win5x5 = '([BCDFGHJKMNPQRTVWXY2346789]{5}-){4}[BCDFGHJKMNPQRTVWXY2346789]{5}'

# Pre-98 OEM key format (12345-OEM-1234567-12345)
$PreOEM = '(?<![0-9])[0-9]{5}-OEM-[0-9]{7}-[0-9]{5}(?![0-9])'

# Pre-98 11-digit format (1234-1234567)
$Pre11 = '(?<![0-9])[0-9]{4}-[0-9]{7}(?![0-9])'

# Pre-98 10-digit format (ABC-1234567)
$Pre10 = '(?<![A-Za-z0-9])[A-Za-z0-9]{3}-[0-9]{7}(?![0-9])'

$regexPre98 = "$PreOEM|$Pre11|$Pre10"
$regexAll = "$Win5x5|$PreOEM|$Pre11|$Pre10"

# ===============================================================================================================================

# Return the right regex for this key checking mode.
function Get-KeyRegex([string]$Mode) {
    if ($Mode -eq 'PidGenX') { return $Win5x5 }
    if ($Mode -eq 'Pre-98') { return $regexPre98 }
    return $regexAll
}

# ===============================================================================================================================

function Get-KeyFromText([string]$Text, [string]$Mode) {
    # Extract unique product keys from text using the chosen scan mode.
    $regex = Get-KeyRegex $Mode
    $found = @()
    foreach ($m in [regex]::Matches($Text.ToUpper(), $regex)) {
        $val = $m.Value
        $hash = @{}
        foreach ($c in $val.ToCharArray()) { if ($c -ne '-') { $hash[$c] = $true } }
        if ($hash.Count -ge 3) { $found += $val }
    }
    $found | Select-Object -Unique
}

# ===============================================================================================================================

function Format-Key([string]$Key) {
    # Normalize a key into its canonical form.
    if (-not $Key) { return "" }

    $keyUpper = $Key.ToUpper()
    if ($keyUpper -match $regexAll) { return $matches[0] }

    return ($keyUpper -replace '[^A-Z0-9-]', '').Trim()
}

# ===============================================================================================================================

# Returns "PidGenX", "Pre98", or "Invalid" based on format.
function Get-KeyFormat([string]$Key) {
    if ($Key -match $Win5x5) { return "PidGenX" }
    if ($Key -match "(?:$regexPre98)") { return "Pre98" }
    return "Invalid"
}

# ===============================================================================================================================

function Resolve-KeyRoute([string]$Key, [string]$Mode) {
    # Normalize the key and pick the right backend.
    $normalizedKey = Format-Key $Key
    $keyFormat = Get-KeyFormat $normalizedKey
    $keyType = "Invalid"
    $result = ""

    if ($keyFormat -eq "Invalid") {
        $result = "Invalid key format"
    }
    elseif ($Mode -eq 'Automatic') {
        $keyType = $keyFormat
    }
    elseif ($Mode -eq 'PidGenX' -and $keyFormat -eq "PidGenX") {
        $keyType = $keyFormat
    }
    elseif ($Mode -eq 'Pre-98' -and $keyFormat -eq "Pre98") {
        $keyType = $keyFormat
    }
    else {
        $result = "Incorrect mode is selected"
    }

    return New-Object PSObject -Property @{
        Key    = $normalizedKey
        Type   = $keyType
        Result = $result
    }
}

# ===============================================================================================================================
# Input resolution
# ===============================================================================================================================

$lineSeparator = @(
    "",
    "--------------------------------------------------------------"
)

$f = "{0,-18}: {1}"

$keysToCheck = @()

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
        $logRoot = Join-Path $base ("KeyChecker\" + (Get-Date -Format "yyyy-MM-dd_HH-mm-ss_fff"))
    }
    if (-not (Test-Path $logRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    }
    if (-not (Test-Path $logRoot -PathType Container)) {
        Write-Color "Failed to create log folder: $logRoot" "BgRed"
        return
    }
}

if ($KeyFile) {
    $batchStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $resolvedKeyFile = [System.IO.Path]::GetFullPath($KeyFile)

    if (-not (Test-Path $resolvedKeyFile -PathType Leaf)) {
        Write-Color "File not found or not a file: $resolvedKeyFile" "BgRed"
        return
    }

    $fileInfo = Get-Item -LiteralPath $resolvedKeyFile
    if ($fileInfo.Length -gt 100MB) {
        Write-Color "File is larger than 100 MB: $resolvedKeyFile" "BgRed"
        return
    }

    # By reading as ASCII and removing null characters, we can scan UTF-8, Unicode, and BigEndianUnicode in a single pass
    $bytes = [System.IO.File]::ReadAllBytes($resolvedKeyFile)
    $content = [System.Text.Encoding]::ASCII.GetString($bytes).Replace("`0", "")
    $extracted = @(Get-KeyFromText $content $KeyCheckMode | Select-Object -Unique)

    if ($extracted.Count -eq 0) {
        Write-Color "No product keys matching the selected mode were found in the selected file." "BgRed"
        return
    }
    
    Write-Output ($f -f "Source", $resolvedKeyFile)
    Write-Output ($f -f "Keys Found", $extracted.Count)
    Write-Output $lineSeparator
    
    $keysToCheck = $extracted

}
elseif ($ProductKey) {
    $keysToCheck = @($ProductKey)

}
else {
    Write-Color "Either -ProductKey or -KeyFile is required." "BgRed"
    return
}

# ===============================================================================================================================
# PidGenX parameter passdown
# ===============================================================================================================================

$pidGenXParams = @{}
if ($PKeyConfigPath) { $pidGenXParams['ManualPKeyConfigPath'] = $PKeyConfigPath }
if ($ProfileName) { $pidGenXParams['ManualProfileName'] = $ProfileName }
if ($KeyCertification) { $pidGenXParams['KeyCertification'] = $true }
if ($KeyActivation) { $pidGenXParams['KeyActivation'] = $true }
if ($MAKCount) { $pidGenXParams['MAKCount'] = $true }
if ($GetInstallationId) { $pidGenXParams['GetInstallationId'] = $true }
if ($GetConfirmationId) { $pidGenXParams['GetConfirmationId'] = $true }

# ===============================================================================================================================
# Main processing loop
# ===============================================================================================================================

$randNum = Get-Random -Minimum 1000 -Maximum 10000

foreach ($rawKey in $keysToCheck) {
    $route = Resolve-KeyRoute $rawKey $KeyCheckMode
    $k = $route.Key
    $ExecutedType = $route.Type

    if (-not $KeyFile) {
        Write-Output "Checking Key: $k"
    }
    
    $output = @()

    if ($ExecutedType -eq "Invalid") {
        $output = @(
            (""),
            ($f -f "Product Key", $k),
            $(Write-Color ($f -f "Result", $route.Result) "BgRed")
        )
    }

    # Per-key log folder
    if ($ExportLogs) {
        if ($ExactLogPath -and -not $KeyFile) {
            $keyFolder = $logRoot
        }
        else {
            $keyFolder = Join-Path $logRoot $k
        }
        if (-not (Test-Path $keyFolder -PathType Container)) {
            New-Item -ItemType Directory -Path $keyFolder -Force | Out-Null
        }
        if (-not (Test-Path $keyFolder -PathType Container)) {
            Write-Color "Failed to create log folder: $keyFolder" "BgRed"
            return
        }
        $pidGenXParams['LogFolder'] = $keyFolder
    }

    # Execute the appropriate backend script
    if ($ExecutedType -eq "Pre98" -or $ExecutedType -eq "PidGenX") {
        $queryStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        if ($ExecutedType -eq "Pre98") {
            $output = @(& $pre98Script -Key $k)
        }
        elseif ($ExecutedType -eq "PidGenX") {
            $pidGenXParams['ProductKey'] = $k
            $output = @(& $pidGenXScript @pidGenXParams)
        }
        
        $queryStopwatch.Stop()
        if ($output.Count -gt 0) {
            $output += ($f -f "Query Time", ("{0:N3} s" -f $queryStopwatch.Elapsed.TotalSeconds))
        }
    }

    # Console output and file logging
    if ($output) {
        $displayOutput = if ($KeyFile) {
            $output + $lineSeparator
        }
        else {
            $output
        }

        $displayOutput | Write-Output

        if ($ExportLogs) {
            # Strip ANSI escape codes and any GUI color tags for clean file output
            $cleanOutput = $output | ForEach-Object { Remove-OutputMarkup $_ }
            $cleanDisplayOutput = $displayOutput | ForEach-Object { Remove-OutputMarkup $_ }

            # Save per-key result
            $keyinfoPath = Join-Path $keyFolder "KeyInfo.txt"
            $cleanOutput | Out-File -FilePath $keyinfoPath -Encoding UTF8

            # In batch mode, also append to combined summary files
            if ($KeyFile) {
                $targetTxt = Join-Path $logRoot "KeyInfo$ExecutedType.txt"
                $targetCsv = Join-Path $logRoot ("KeyInfo{0}-Random{1}.csv" -f $ExecutedType, $randNum)
                
                $cleanDisplayOutput | Out-File -FilePath $targetTxt -Encoding UTF8 -Append
                
                if ($ExecutedType -eq "Pre98") {
                    Add-KeyToCsv $cleanOutput $colsPre98 $targetCsv
                }
                elseif ($ExecutedType -eq "PidGenX") {
                    Add-KeyToCsv $cleanOutput $colsPidGenX $targetCsv
                }
            }
        }
    }
}

# ===============================================================================================================================
# Batch summary
# ===============================================================================================================================

if ($KeyFile -or ($ExportLogs -and $logRoot)) {
    Write-Output ""
    if ($KeyFile) {
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
