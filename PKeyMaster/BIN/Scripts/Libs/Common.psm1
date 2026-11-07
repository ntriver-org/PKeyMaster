<#
.SYNOPSIS
    Common helper functions and shared caches for PKeyMaster.

.DESCRIPTION
    PowerShell script module providing shared utilities across PKeyMaster scripts,
    including ANSI/VT and GUI color formatting (Write-Color), binary key extraction
    (Find-KeysInFile), native SPP/WMI error message resolution, PKeyConfig metadata
    resolution (Get-PKeyConfigInfo), and global data caches.
    This module is intended to be imported via Import-Module, not executed directly.

.NOTES
    Compatible with PowerShell 2.0 and later.
#>

# ===============================================================================================================================
# ANSI / VT support detection
# ===============================================================================================================================

$global:AnsiSupported = $false
$global:ColorLineBuffer = ""
if ([System.Environment]::OSVersion.Version.Build -ge 10586) {
    $forceV2 = (Get-ItemProperty -Path 'HKCU:\Console' -Name 'ForceV2' -ErrorAction SilentlyContinue).ForceV2
    if ($null -eq $forceV2 -or $forceV2 -ne 0) {
        $global:AnsiSupported = $true
    }
}

# Color name -> @(AnsiCode, GUI-ForegroundColor, GUI-BackgroundColor)
$global:ColorMap = @{
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

    $colorData = $global:ColorMap[$Color]
    $piece = ""

    if ($global:IsGuiRunspace) {
        $piece = "[c:$($colorData[1]):$($colorData[2])]$Text"
    }
    elseif ($global:AnsiSupported) {
        $piece = "$([char]27)[$($colorData[0])m$Text$([char]27)[0m"
    }
    else {
        $piece = $Text
    }

    if ($NoNewline) {
        $global:ColorLineBuffer += $piece
    }
    else {
        $fullLine = $global:ColorLineBuffer + $piece
        $global:ColorLineBuffer = ""
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
# PKeyConfig XML & Metadata helpers
# ===============================================================================================================================

function Read-PKeyConfigXml {
    param([string]$FilePath)

    if (-not (Test-Path -LiteralPath $FilePath)) {
        return $null
    }

    $xr = $null
    try {
        $xr = [System.Xml.XmlReader]::Create($FilePath)
        $base64 = $null
        while ($xr.Read()) {
            if ($xr.NodeType -eq [System.Xml.XmlNodeType]::Element -and 
                $xr.LocalName -eq 'infoBin' -and 
                $xr.GetAttribute('name') -eq 'pkeyConfigData') {
                $base64 = $xr.ReadElementContentAsString()
                break
            }
        }

        if (-not $base64) {
            return $null
        }

        $bytes = [Convert]::FromBase64String($base64.Trim())
        $xmlStr = [System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
        return [xml]$xmlStr
    }
    catch {
        return $null
    }
    finally {
        if ($xr) { $xr.Close() }
    }
}

function Get-NodeText($Node, $LocalName) {
    $n = $Node.SelectSingleNode("*[local-name()='$LocalName']")
    if ($n) { return $n.InnerText.Trim() }
    return ''
}

function Get-PKeyConfigInfo {
    [CmdletBinding(DefaultParameterSetName = 'ByKeyId')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$FilePath,

        [Parameter(ParameterSetName = 'ByKeyId', Mandatory = $true)]
        [uint32]$GroupId,

        [Parameter(ParameterSetName = 'ByKeyId', Mandatory = $true)]
        [int64]$KeyId,

        [Parameter(ParameterSetName = 'ByActId', Mandatory = $true)]
        [string]$ActivationId,

        [Parameter(ParameterSetName = 'ByPartNumber', Mandatory = $true)]
        [string]$PartNumber
    )

    $xml = Read-PKeyConfigXml $FilePath
    if (-not $xml) { return $null }

    $matchedCfg = $null
    $eula = ''
    $partNum = ''
    $isValid = ''

    if ($PsCmdlet.ParameterSetName -eq 'ByActId') {
        $target = $ActivationId.Trim().Trim('{', '}').ToLower()
        if (-not $target) { return $null }

        foreach ($cfg in @($xml.SelectNodes("//*[local-name()='Configuration']"))) {
            if ((Get-NodeText $cfg 'ActConfigId').Trim().Trim('{', '}').ToLower() -eq $target) {
                $matchedCfg = $cfg
                break
            }
        }
    }
    elseif ($PsCmdlet.ParameterSetName -eq 'ByPartNumber') {
        $target = ($PartNumber.Trim() -replace '^\[[^\]]*\]\s*' -split ':')[0].Trim().ToLower()
        if (-not $target) { return $null }

        $refActId = ''
        foreach ($kr in @($xml.SelectNodes("//*[local-name()='KeyRange']"))) {
            $pn = ((Get-NodeText $kr 'PartNumber').Trim() -replace '^\[[^\]]*\]\s*' -split ':')[0].Trim().ToLower()
            if ($pn -eq $target) {
                $refActId = (Get-NodeText $kr 'RefActConfigId').Trim().Trim('{', '}').ToLower()
                $eula = Get-NodeText $kr 'EulaType'
                $partNum = Get-NodeText $kr 'PartNumber'
                $isValid = Get-NodeText $kr 'IsValid'
                break
            }
        }

        if (-not $refActId) { return $null }

        foreach ($cfg in @($xml.SelectNodes("//*[local-name()='Configuration']"))) {
            if ((Get-NodeText $cfg 'ActConfigId').Trim().Trim('{', '}').ToLower() -eq $refActId) {
                $matchedCfg = $cfg
                break
            }
        }
    }
    else {
        $gStr = [string]$GroupId
        foreach ($cfg in @($xml.SelectNodes("//*[local-name()='Configuration']"))) {
            if ((Get-NodeText $cfg 'RefGroupId') -ne $gStr) { continue }
            $needle = (Get-NodeText $cfg 'ActConfigId').Trim().Trim('{', '}').ToLower()

            foreach ($kr in @($xml.SelectNodes("//*[local-name()='KeyRange']"))) {
                if ((Get-NodeText $kr 'RefActConfigId').Trim().Trim('{', '}').ToLower() -eq $needle) {
                    $start = [int64](Get-NodeText $kr 'Start')
                    $end = [int64](Get-NodeText $kr 'End')
                    if ($KeyId -ge $start -and $KeyId -le $end) {
                        $matchedCfg = $cfg
                        $eula = Get-NodeText $kr 'EulaType'
                        $partNum = Get-NodeText $kr 'PartNumber'
                        $isValid = Get-NodeText $kr 'IsValid'
                        # Revoked keys take precedence in overlapping ranges; stop immediately so a broader 'true' cannot override it.
                        if ($isValid -eq 'false') { break }
                    }
                }
            }
            if ($matchedCfg) { break }
        }
    }

    if (-not $matchedCfg) { return $null }

    $refGroupId = Get-NodeText $matchedCfg 'RefGroupId'
    $algId = ''
    if ($refGroupId) {
        foreach ($pk in @($xml.SelectNodes("//*[local-name()='PublicKey']"))) {
            if ((Get-NodeText $pk 'GroupId') -eq $refGroupId) {
                $algId = Get-NodeText $pk 'AlgorithmId'
                break
            }
        }
    }

    return New-Object PSObject -Property @{
        Description  = Get-NodeText $matchedCfg 'ProductDescription'
        Edition      = Get-NodeText $matchedCfg 'EditionId'
        EULA         = $eula
        KeyType      = Get-NodeText $matchedCfg 'ProductKeyType'
        PartNumber   = $partNum
        AlgorithmId  = $algId
        ActivationId = Get-NodeText $matchedCfg 'ActConfigId'
        IsValid      = $isValid
    }
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
# PreVista Product Match Query
# ===============================================================================================================================

# Look up Group ID + Key ID in PreVistaRanges.csv for product editions and return an array of matched descriptions.

function Get-PreVistaProductMatch($GroupId, $KeyId) {

    if ($null -eq $GroupId -or $null -eq $KeyId -or -not $global:PreVistaRanges) { return @() }

    $gStr = [string][int]$GroupId
    $kId = [int64]$KeyId
    $editionMatches = @{}

    foreach ($row in $global:PreVistaRanges) {
        if ($row.BinkID_Dec -ne $gStr) { continue }

        $min = ([int64]$row.Channel_Min * 1000000) + [int64]$row.Sequence_Min
        $max = ([int64]$row.Channel_Max * 1000000) + [int64]$row.Sequence_Max

        if ($kId -ge $min -and $kId -le $max) {
            $ed = $row.Edition.Trim()
            if (-not $editionMatches.ContainsKey($ed)) {
                $editionMatches[$ed] = @{ Licenses = @(); Stages = @() }
            }
            if ($row.License -and $row.License -ne "N/A" -and $editionMatches[$ed].Licenses -notcontains $row.License) {
                $editionMatches[$ed].Licenses += $row.License
            }
            if ($row.Stage -and $row.Stage -ne "N/A" -and $editionMatches[$ed].Stages -notcontains $row.Stage) {
                $editionMatches[$ed].Stages += $row.Stage
            }
        }
    }

    return @(foreach ($ed in ($editionMatches.Keys | Sort-Object)) {
            $tags = @($editionMatches[$ed].Licenses | Sort-Object) + @($editionMatches[$ed].Stages | Sort-Object)
            if ($tags) { "$ed (" + ($tags -join ") (") + ")" } else { $ed }
        })
}

# ===============================================================================================================================
# Product Details Lookup & Display
# ===============================================================================================================================

# Searches PKeyConfigsMap.json (falling back to PreVistaRanges.csv) for product details using Group ID and Key ID.

function Get-ProductDetails($GroupId, $KeyId, [switch]$SkipPreVista, [switch]$SkipVistaAndLater) {
    if ($null -eq $GroupId -or $null -eq $KeyId) { return $null }

    $gId = [int]$GroupId
    $kId = [int64]$KeyId
    $channel = [int64][Math]::Floor($kId / 1000000)
    $seq = [int64]($kId % 1000000)
    $labelId = "{0:D5}-{1:D3}-{2:D3}-{3:D3}" -f $gId, $channel, [int]([Math]::Floor($seq / 1000)), [int]($seq % 1000)

    $pkeyConfigsDir = Join-Path $PSScriptRoot "..\..\PKeyConfigs"
    if (-not $SkipVistaAndLater -and $global:PKeyConfigsMap -and (Test-Path $pkeyConfigsDir)) {
        $gStr = [string]$GroupId

        foreach ($entry in ($global:PKeyConfigsMap | Where-Object { $_.Profile -notmatch "custom" })) {
            if (-not $entry.Algorithms) { continue }
            $matched = $false
            foreach ($algoGroups in $entry.Algorithms.Values) {
                if ($algoGroups -and $algoGroups.ContainsKey($gStr)) {
                    foreach ($range in $algoGroups[$gStr]) {
                        if ($kId -ge $range[0] -and $kId -le $range[1]) { $matched = $true; break }
                    }
                }
                if ($matched) { break }
            }

            if ($matched) {
                $cfgPath = Join-Path $pkeyConfigsDir $entry.Path.TrimStart('\')
                if (Test-Path $cfgPath) {
                    $info = Get-PKeyConfigInfo -FilePath $cfgPath -GroupId $GroupId -KeyId $KeyId
                    if ($info -and $info.Description -and $info.Description -ne "CustomMade") {
                        return New-Object PSObject -Property @{
                            Profile      = $entry.Profile
                            Description  = $info.Description
                            Edition      = $info.Edition
                            KeyType      = $info.KeyType
                            EULA         = $info.EULA
                            PartNumber   = $info.PartNumber
                            AlgorithmId  = $info.AlgorithmId
                            ActivationId = if ($info.ActivationId) { $info.ActivationId.Trim('{', '}').ToLower() } else { '' }
                            LabelId      = $labelId
                        }
                    }
                }
            }
        }
    }

    if (-not $SkipPreVista) {
        $preVistaMatches = @(Get-PreVistaProductMatch $GroupId $KeyId)
        if ($preVistaMatches.Count -gt 0) {
            $is2002 = $gId -ge 0x40

            return New-Object PSObject -Property @{
                Matches     = $preVistaMatches
                Bink        = if ($is2002) { "Bink2002" } else { "Bink1998" }
                ChannelId   = $channel
                Sequence    = $seq
                AlgorithmId = if ($is2002) { "msft:rm/algorithm/pkey/986" } else { "msft:rm/algorithm/pkey/980" }
                LabelId     = $labelId
            }
        }
    }

    return New-Object PSObject -Property @{
        LabelId = $labelId
    }
}

function Write-ProductDetails($ProductDetails, $f, [string[]]$Exclude = @()) {

    if (-not $ProductDetails) { return }

    if ($ProductDetails.Matches) {
        foreach ($m in $ProductDetails.Matches) {
            Write-Color ($f -f "Product Match", $m) "BgGreen"
        }
        if ($ProductDetails.Bink -and ($Exclude -notcontains "Bink")) { Write-Output ($f -f "Bink", $ProductDetails.Bink) }
        if ($null -ne $ProductDetails.ChannelId -and ($Exclude -notcontains "ChannelId")) { Write-Output ($f -f "Channel ID", ("{0} (0x{0:X})" -f $ProductDetails.ChannelId)) }
        if ($null -ne $ProductDetails.Sequence -and ($Exclude -notcontains "Sequence")) { Write-Output ($f -f "Sequence", ("{0} (0x{0:X})" -f $ProductDetails.Sequence)) }
        if ($ProductDetails.LabelId -and ($Exclude -notcontains "LabelId")) { Write-Output ($f -f "Label ID", $ProductDetails.LabelId) }
        if ($ProductDetails.AlgorithmId -and ($Exclude -notcontains "AlgorithmId")) { Write-Output ($f -f "Algorithm ID", $ProductDetails.AlgorithmId) }
    }
    else {
        if ($ProductDetails.Profile -and ($Exclude -notcontains "Profile")) { Write-Output ($f -f "Profile", $ProductDetails.Profile) }
        if ($ProductDetails.Description -and ($Exclude -notcontains "Description")) { Write-Color ($f -f "Description", $ProductDetails.Description) "BgGreen" }
        if ($ProductDetails.Edition -and ($Exclude -notcontains "Edition")) { Write-Output ($f -f "Edition", $ProductDetails.Edition) }
        if ($ProductDetails.KeyType -and ($Exclude -notcontains "KeyType")) { Write-Output ($f -f "Key Type", $ProductDetails.KeyType) }
        if ($ProductDetails.EULA -and ($Exclude -notcontains "EULA")) { Write-Output ($f -f "EULA", $ProductDetails.EULA) }
        if ($ProductDetails.PartNumber -and ($Exclude -notcontains "PartNumber")) { Write-Output ($f -f "Part number", $ProductDetails.PartNumber) }
        if ($ProductDetails.LabelId -and ($Exclude -notcontains "LabelId")) { Write-Output ($f -f "Label ID", $ProductDetails.LabelId) }
        if ($ProductDetails.AlgorithmId -and ($Exclude -notcontains "AlgorithmId")) { Write-Output ($f -f "Algorithm ID", $ProductDetails.AlgorithmId) }
        if ($ProductDetails.ActivationId -and ($Exclude -notcontains "ActivationId")) { Write-Output ($f -f "Activation ID", $ProductDetails.ActivationId) }
    }
}

# ===============================================================================================================================
# Script Execution Helpers
# ===============================================================================================================================

# Run a script with PassThru and return the result object.
function Invoke-PassThruScript([string]$ScriptPath, [hashtable]$Params = @{}) {
    $path = Join-Path (Split-Path -Parent $PSScriptRoot) $ScriptPath
    if (-not (Test-Path $path)) {
        if (Test-Path $ScriptPath) { $path = $ScriptPath } else { return $null }
    }

    & $path @Params -PassThru 2>$null | Where-Object { $_ -is [System.Management.Automation.PSCustomObject] }
}

# ===============================================================================================================================

