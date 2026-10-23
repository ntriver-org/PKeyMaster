<#
.SYNOPSIS
    Checks a product key using PidGenX and retrieves detailed metadata.

.DESCRIPTION
    This script loads the PidGenX DLL, iterates through PKeyConfig files to find a
    matching configuration, and extracts full key metadata including Product ID,
    Extended PID, Activation ID, key type, algorithm, and decoded bit fields.
    Optionally performs certification, activation, MAK count, and CID retrieval.

.PARAMETER ProductKey
    The 5x5 product key to check.

.PARAMETER ManualPKeyConfigPath
    Manual path to a specific PKeyConfig file (overrides auto-search).

.PARAMETER ManualProfileName
    Manual profile name to display (used with ManualPKeyConfigPath).

.PARAMETER GetInstallationId
    Enables Installation ID retrieval via GetPKeyData.

.PARAMETER KeyCertification
    Enables key certification via the SL certification service.

.PARAMETER KeyActivation
    Enables key activation via the SL activation service.

.PARAMETER CheckRedeemKey
    Enables redeem key validation via Microsoft licensing endpoint.

.PARAMETER MAKCount
    Enables MAK remaining count query.

.PARAMETER GetConfirmationId
    Enables Confirmation ID retrieval via the BatchApi, fallbacks to VisualApi.

.PARAMETER LogFolder
    Path to save DPID binary dumps and API request/response logs.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Windows Vista SP1+ (build 6001+).
    Requires pidgenx64.dll or pidgenx32.dll in the BIN directory.
    Requires Libs\DigitalProductId.ps1, PKeyConfigReader.ps1,
    KeyCertification.ps1, KeyActivation.ps1, MakCount.ps1, GetCID.ps1,
    DecodePKey2009.ps1, DecodePKey980-PKey986.ps1 for optional features.
    Requires PKeyConfigsMap.json and PreVistaRanges.csv in the application root.
    Requires Libs\Common.ps1 for shared helper functions.

.EXAMPLE
    .\KeyCheckerPidGenX.ps1 -ProductKey "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ProductKey,
    
    [Parameter(Mandatory = $false, Position = 1)]
    [string]$ManualPKeyConfigPath,

    [Parameter(Mandatory = $false)]
    [string]$ManualProfileName,

    [switch]$GetInstallationId,
    [switch]$KeyCertification,
    [switch]$KeyActivation,
    [switch]$CheckRedeemKey,
    [switch]$MAKCount,
    [switch]$GetConfirmationId,
    [string]$LogFolder
)

# ===============================================================================================================================
# Initialization & dependencies
# ===============================================================================================================================

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "." }

$dllDir = Split-Path -Parent $scriptDir
$dllName = if ([IntPtr]::Size -eq 8) { "pidgenx64.dll" } else { "pidgenx32.dll" }
$dllPath = Join-Path $dllDir $dllName

$digitalPidPath = Join-Path $scriptDir "libs\DigitalProductId.ps1"
$commonPath = Join-Path $scriptDir "libs\Common.ps1"
$readerPath = Join-Path $scriptDir "PKeyConfigReader.ps1"
if (Test-Path $digitalPidPath) { . $digitalPidPath }
if (Test-Path $commonPath) { . $commonPath }

$f = "{0,-18}: {1}"

# ===============================================================================================================================
# P/Invoke type compilation
# ===============================================================================================================================

if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM') {
    Write-Color "PidGenX script is not supported on Windows ARM32 systems." "BgRed"
    return
}

if (-not $Script:PidGenXNativeType) {
    if (-not (Test-Path $dllPath)) {
        Write-Color "PidGenX DLL not found: $dllPath" "BgRed"
        return
    }

    try {
        $TB = [AppDomain]::CurrentDomain.DefineDynamicAssembly((Get-Random), 1).DefineDynamicModule((Get-Random), $False).DefineType('NativeMethods')

        $iidParams = @([string], [string], [string], [string], [UInt64], [string].MakeByRefType(), [string].MakeByRefType(), [string].MakeByRefType(), [string].MakeByRefType(), [IntPtr])

        [void]$TB.DefinePInvokeMethod('PidGenX', $dllPath, 22, 1, [int], @([string], [string], [string], [string], [IntPtr], [IntPtr], [IntPtr]), 1, 3).SetImplementationFlags(128)
        [void]$TB.DefinePInvokeMethod('GetPKeyData', $dllPath, 22, 1, [int], $iidParams, 1, 3).SetImplementationFlags(128)
        [void]$TB.DefinePInvokeMethod('GetModuleHandle', 'kernel32.dll', 22, 1, [IntPtr], @([string]), 1, 3).SetImplementationFlags(128)

        $Script:PidGenXNativeType = $TB.CreateType()
    }
    catch {
        Write-Color "Failed to initialize native methods: $($_.Exception.Message)" "BgRed"
        return
    }
}

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function Write-ProductMatch($GroupId, $KeyId, $f, $scriptDir) {
    # Look up Group ID + Key ID in PreVistaRanges.csv for product editions.
    if ($null -eq $GroupId -or $null -eq $KeyId -or -not $global:PreVistaRanges) { return }

    $editionMatches = @{}
    foreach ($row in $global:PreVistaRanges) {
        if (-not $row.BinkID_Dec -or [int]$row.BinkID_Dec -ne $GroupId) { continue }

        $min = ([int64]$row.Channel_Min * 1000000) + [int64]$row.Sequence_Min
        $max = ([int64]$row.Channel_Max * 1000000) + [int64]$row.Sequence_Max
        
        if ($KeyId -ge $min -and $KeyId -le $max) {
            $ed = $row.Edition.Trim()
            if (-not $editionMatches.ContainsKey($ed)) { $editionMatches[$ed] = @{ 'Licenses' = @(); 'Stages' = @() } }
            
            $lic = $row.License.Trim()
            if ($lic -and $lic -ne "N/A" -and $editionMatches[$ed]['Licenses'] -notcontains $lic) { $editionMatches[$ed]['Licenses'] += $lic }
            
            $stg = $row.Stage.Trim()
            if ($stg -and $stg -ne "N/A" -and $editionMatches[$ed]['Stages'] -notcontains $stg) { $editionMatches[$ed]['Stages'] += $stg }
        }
    }

    if ($editionMatches.Count -gt 0) {
        $sortedEditions = $editionMatches.Keys | Sort-Object
        foreach ($ed in $sortedEditions) {
            $tags = @()
            $licenses = $editionMatches[$ed]['Licenses'] | Sort-Object
            $stages = $editionMatches[$ed]['Stages'] | Sort-Object
            
            if ($licenses) { $tags += $licenses }
            if ($stages) { $tags += $stages }
            
            $m = $ed
            if ($tags.Count -gt 0) {
                $m += " (" + ($tags -join ") (") + ")"
            }
            Write-Color ($f -f "Product Match", $m) "BgGreen"
        }
    }
}

# ===============================================================================================================================

# Run a script with PassThru and return the result objects.
function Invoke-PassThruScript([string]$ScriptPath, [hashtable]$Params) {
    if (-not (Test-Path $ScriptPath)) { return @() }

    $callParams = @{}
    foreach ($key in $Params.Keys) {
        $callParams[$key] = $Params[$key]
    }
    $callParams['PassThru'] = $true

    return @(& $ScriptPath @callParams 2>$null)
}

# ===============================================================================================================================

function Invoke-CheckRedeemKey($RedeemKey, $LogFolder, $f, $scriptDir) {
    # Run CheckRedeemKey.ps1 and show the redeem-key status.
    $redeemScript = Join-Path $scriptDir "CheckRedeemKey.ps1"
    $params = @{ RedeemKey = $RedeemKey }
    if ($LogFolder) { $params['LogPath'] = $LogFolder }
    $redeemOutput = Invoke-PassThruScript $redeemScript $params
    if (-not $redeemOutput) { return }
    $redeemObj = $redeemOutput[-1]
    if (-not $redeemObj -or -not $redeemObj.Status) { return }

    Write-Output ""
    if ($redeemObj.Status -eq "Valid") {
        Write-Color ($f -f "Redeem Key Status", $redeemObj.Status) "BgGreen"
    }
    else {
        Write-Color ($f -f "Redeem Key Status", $redeemObj.Status) "BgRed"
    }
    if ($redeemObj.Pkpn) {
        if ($redeemObj.Product) {
            Write-Color ($f -f "Redeem Product", $redeemObj.Product) "BgGreen"
        }
        Write-Output ($f -f "Redeem Acid", $redeemObj.Acid)
        Write-Output ($f -f "Redeem GroupId", $redeemObj.GroupId)
        Write-Output ($f -f "Redeem Pkpn", $redeemObj.Pkpn)
    }
}

# ===============================================================================================================================

function Invoke-KeyCertification($ProductKey, $ActConfigId, $LogFolder, $f, $scriptDir) {
    # Run KeyCertification.ps1 and display the result.
    $certScript = Join-Path $scriptDir "KeyCertification.ps1"
    $params = @{ ProductKey = $ProductKey; ActConfigId = $ActConfigId }
    if ($LogFolder) { $params['LogPath'] = $LogFolder }
    $certOutput = Invoke-PassThruScript $certScript $params
    if (-not $certOutput) { return }
    $certObj = $certOutput[-1]
    if (-not $certObj -or -not $certObj.Status) { return }
    
    if ($certObj.Status -eq "Succeeded") {
        if ($script:SubActionLastState -eq 'error') { Write-Output "" }
        $script:SubActionLastState = 'success'
        Write-Color ($f -f "Key Certification", $certObj.Status) "BgGreen"
    }
    else {
        if ($script:SubActionLastState) { Write-Output "" }
        $script:SubActionLastState = 'error'
        Write-Color ($f -f "Key Certification", $certObj.Status) "BgRed"
        Write-Color ($f -f "Cert Error Code", $certObj.ErrorCode) "BgRed"
        Write-Color ($f -f "Cert Error Msg", $certObj.ErrorDetail) "BgRed"
    }
}

# ===============================================================================================================================

function Invoke-KeyActivation($ProductKey, $ActConfigId, $LogFolder, $f, $scriptDir) {
    # Run KeyActivation.ps1 and display the result.
    $actScript = Join-Path $scriptDir "KeyActivation.ps1"
    $params = @{ ProductKey = $ProductKey; ActConfigId = $ActConfigId }
    if ($LogFolder) { $params['LogPath'] = $LogFolder }
    $actOutput = Invoke-PassThruScript $actScript $params
    if (-not $actOutput) { return }
    $actObj = $actOutput[-1]
    if (-not $actObj -or -not $actObj.Status) { return }
    
    if ($actObj.Status -eq "Succeeded") {
        if ($script:SubActionLastState -eq 'error') { Write-Output "" }
        $script:SubActionLastState = 'success'
        Write-Color ($f -f "Key Activation", $actObj.Status) "BgGreen"
    }
    else {
        if ($script:SubActionLastState) { Write-Output "" }
        $script:SubActionLastState = 'error'
        Write-Color ($f -f "Key Activation", $actObj.Status) "BgRed"
        Write-Color ($f -f "Act Error Code", $actObj.ErrorCode) "BgRed"
        Write-Color ($f -f "Act Error Msg", $actObj.ErrorDetail) "BgRed"
    }
}

# ===============================================================================================================================

function Invoke-MakCount($AdvancedPid, $LogFolder, $f, $scriptDir) {
    # Run MakCount.ps1 and show the remaining activation count.
    $makScript = Join-Path $scriptDir "MakCount.ps1"
    $params = @{ AdvancedPid = $AdvancedPid }
    if ($LogFolder) { $params['LogPath'] = $LogFolder }
    $makOutput = Invoke-PassThruScript $makScript $params
    if (-not $makOutput) { return }
    $makObj = $makOutput[-1]
    if (-not $makObj -or -not $makObj.Result) { return }
    
    if ($makObj.Result -eq "SUCCESS") {
        if ($script:SubActionLastState -eq 'error') { Write-Output "" }
        $script:SubActionLastState = 'success'
        Write-Color ($f -f "MAK Count", $makObj.RemainingCount) "BgGreen"
    }
    else {
        if ($script:SubActionLastState) { Write-Output "" }
        $script:SubActionLastState = 'error'
        Write-Color ($f -f "MAK Count", $makObj.RemainingCount) "BgRed"
        Write-Color ($f -f "MAK Error Code", $makObj.ErrorCode) "BgRed"
        Write-Color ($f -f "MAK Error Msg", $makObj.ErrorDetail) "BgRed"
    }
}

# ===============================================================================================================================

function Invoke-GetConfirmationId($IID, $LogFolder, $f, $scriptDir) {
    # Run GetCID.ps1 to get a CID for this IID.
    $getCidScript = Join-Path $scriptDir "GetCID.ps1"
    $params = @{ InstallationId = $IID }
    if ($LogFolder) {
        $params['ExportLogs'] = $true
        $params['LogPath'] = $LogFolder
        $params['ExactLogPath'] = $true
    }
    $cidOutput = Invoke-PassThruScript $getCidScript $params
    
    if (-not $cidOutput) { return }
    $cidObj = $cidOutput[-1]
    
    if ($cidObj) {
        if ($cidObj.BatchResult) {
            if ($cidObj.BatchResult -eq "SUCCESS") {
                if ($script:SubActionLastState -eq 'error') { Write-Output "" }
                $script:SubActionLastState = 'success'
                Write-Color ($f -f "CID Batch Api", $cidObj.BatchCID) "BgGreen"
            }
            else {
                if ($script:SubActionLastState) { Write-Output "" }
                $script:SubActionLastState = 'error'
                Write-Color ($f -f "CID Batch Api", "Failed") "BgRed"
                Write-Color ($f -f "Batch Error Code", $cidObj.BatchErrorCode) "BgRed"
                Write-Color ($f -f "Batch Error Msg", $cidObj.BatchErrorDetail) "BgRed"
            }
        }

        if ($cidObj.VisualResult) {
            if ($cidObj.VisualResult -eq "SUCCESS") {
                if ($script:SubActionLastState -eq 'error') { Write-Output "" }
                $script:SubActionLastState = 'success'
                Write-Color ($f -f "CID Visual Api", $cidObj.VisualCID) "BgGreen"
            }
            else {
                if ($script:SubActionLastState) { Write-Output "" }
                $script:SubActionLastState = 'error'
                Write-Color ($f -f "CID Visual Api", "Failed") "BgRed"
                Write-Color ($f -f "Visual Error Code", $cidObj.VisualErrorCode) "BgRed"
                Write-Color ($f -f "Visual Error Msg", $cidObj.VisualErrorDetail) "BgRed"
            }
        }
    }
}

# ===============================================================================================================================

function Read-PidGenXPKey2005Security {
    # Read the PKey2005 security value captured by the patched PIDGenX DLL.
    # This offset must be verified if PIDGenX is updated.
    $securityOffset = if ([IntPtr]::Size -eq 8) { 0xAF900 } else { 0x8F600 }
    $hModule = $Script:PidGenXNativeType::GetModuleHandle($dllName)
    if ($hModule -eq [IntPtr]::Zero) { return $null }

    $securityPtr = [IntPtr]($hModule.ToInt64() + $securityOffset)
    try { return [System.Runtime.InteropServices.Marshal]::ReadInt32($securityPtr) }
    catch { return $null }
}

# ===============================================================================================================================

# ActConfig ID helpers

function Set-ActConfigBits($Data, $Offset, $Length, $Value) {
    [uint64]$valueMask = 1
    for ($bit = 0; $bit -lt $Length; $bit++) {
        if (($Value -band $valueMask) -ne 0) {
            $byteIndex = [int][Math]::Floor(($Offset + $bit) / 8)
            $bitIndex = ($Offset + $bit) % 8
            $Data[$byteIndex] = [byte]($Data[$byteIndex] -bor [int][Math]::Pow(2, $bitIndex))
        }
        $valueMask = $valueMask * 2
    }
}

function Get-PKey2005ActConfigId($SkuId, $Upgrade, $Serial, $Security) {
    if ($null -eq $Security -or -not $SkuId) { return "" }

    $data = New-Object byte[] 12
    Set-ActConfigBits $data 0 1 ([uint64]$Upgrade)
    Set-ActConfigBits $data 1 30 ([uint64][int64]$Serial)
    Set-ActConfigBits $data 31 20 ([uint64][int64]$Security)

    return "msft2005:{0}&{1}" -f $SkuId, [Convert]::ToBase64String($data)
}

function Get-PKey2009ActConfigId($SkuId, $Upgrade, $Serial, $Group, $Security) {
    if ($null -eq $Security -or -not $SkuId) { return "" }

    $data = New-Object byte[] 13
    Set-ActConfigBits $data 0 1 ([uint64]$Upgrade)
    Set-ActConfigBits $data 1 30 ([uint64][int64]$Serial)
    Set-ActConfigBits $data 31 20 ([uint64][int64]$Group)
    Set-ActConfigBits $data 51 53 ([uint64][int64]$Security)

    return "msft2009:{0}&{1}" -f $SkuId, [Convert]::ToBase64String($data)
}

# ===============================================================================================================================

function Invoke-GetInstallationId($Key, $Config) {
    # Get IID from GetPKeyData for this key and config.
    $IID = ""
    $Edition = ""
    $Channel = ""
    $Partnum = ""
    $HWID = 0

    # Call GetPKeyData
    $hr = $Script:PidGenXNativeType::GetPKeyData($Key, $Config, "00000", $null, $HWID, [ref]$IID, [ref]$Edition, [ref]$Channel, [ref]$Partnum, [IntPtr]::Zero)

    if ($hr -eq 0 -and $IID) {
        return $IID
    }
    return ""
}

# ===============================================================================================================================

function Add-Mod7CheckDigit {
    param([long]$Value)

    $sum = 0
    $temp = $Value
    while ($temp -gt 0) {
        $sum += [int]($temp % 10)
        $temp = [Math]::Floor($temp / 10)
    }

    return ($Value * 10) + (7 - ($sum % 7))
}

# ===============================================================================================================================

function Get-LicenseType {
    param(
        [string]$KeyType = "",
        [Parameter(Mandatory = $true)][bool]$IsUpgrade,
        [Parameter(Mandatory = $true)][string]$AlgorithmId,
        [Parameter(Mandatory = $true)][long]$Serial,
        [Parameter(Mandatory = $true)][int]$GroupId
    )

    if ($AlgorithmId -match "980|986") {
        if ($GroupId % 2 -ne 0) { return 2 }

        $channelId = [int]([Math]::Floor($Serial / 1000000) % 1000)
        if ($channelId -eq 270) { return 3 }
        if ($channelId -eq 335) { return 6 }

        if ($IsUpgrade) { return 1 }
        return 0
    }

    if ($AlgorithmId -match "2005|2009") {
        switch -Wildcard ($KeyType) {
            "OEM*" { return 2 }
            "Volume*" { return 3 }
            "Retail*" { if ($IsUpgrade) { return 1 } return 0 }
            "PGS:TB*" { return 4 }
            default { return 0 }
        }
    }
}

# ===============================================================================================================================

function Get-ProductId {
    param(
        [Parameter(Mandatory = $true)][string]$Algorithm,
        [Parameter(Mandatory = $true)][int]$GroupId,
        [Parameter(Mandatory = $true)][long]$Serial,
        [Parameter(Mandatory = $true)][bool]$IsOem,
        [Parameter(Mandatory = $true)][bool]$IsUpgrade
    )

    $random = [int]([Math]::Abs([Environment]::TickCount / 10) % 1000)

    if ($Algorithm -match "2009") {
        $groupHigh = [int]([Math]::Floor($GroupId / 10) % 100000)
        $groupLow = [int]($GroupId % 10)
        $serialMid = [int]([Math]::Floor($Serial / 100000) % 10000)
        $serialLow = [int]($Serial % 100000)
        $tag = if ($IsUpgrade) { "AB" } else { "AA" }

        if ($IsOem) {
            return "{0:D5}-{1:D1}{2:D4}-{3:D5}-{4}OEM" -f $groupHigh, $groupLow, $serialMid, $serialLow, $tag
        }
        else {
            return "{0:D5}-{1:D1}{2:D4}-{3:D5}-{4}{5:D3}" -f $groupHigh, $groupLow, $serialMid, $serialLow, $tag, $random
        }
    }
    else {
        $mpc = "00000"
        $groupPart = [int]([Math]::Floor($GroupId / 2) % 100)
        $channelId = [int]([Math]::Floor($Serial / 1000000) % 1000)
        $sequence = [int]($Serial % 1000000)

        if ($IsOem) {
            $seqHighDigit = [int]([Math]::Floor($sequence / 100000) % 10)
            $baseNumber = (($groupPart * 1000 + $channelId) * 10) + $seqHighDigit
            $baseWithCheck = Add-Mod7CheckDigit -Value $baseNumber
            $sequenceLow = [int]($sequence % 100000)

            return "{0}-OEM-{1:D7}-{2:D5}" -f $mpc, $baseWithCheck, $sequenceLow
        }
        else {
            $seqWithCheck = Add-Mod7CheckDigit -Value $sequence
            $groupWithRandom = [int]($groupPart * 1000 + $random)

            return "{0}-{1:D3}-{2:D7}-{3:D5}" -f $mpc, $channelId, $seqWithCheck, $groupWithRandom
        }
    }
}

# ===============================================================================================================================

function Get-ExtendedProductId {
    param(
        [Parameter(Mandatory = $true)][int]$GroupId,
        [Parameter(Mandatory = $true)][long]$Serial,
        [Parameter(Mandatory = $true)][int]$LicenseType
    )

    $mpc = "00000"
    $channelId = [int]([Math]::Floor($Serial / 1000000) % 1000)
    $sequence = [int]($Serial % 1000000)
    $groupPart = [int]($GroupId % 100000)
    $buildNumber = [Environment]::OSVersion.Version.Build
    $currentDate = Get-Date

    $langId = try { [System.Globalization.CultureInfo]::InstalledUICulture.LCID } catch { 1033 }

    $dayOfYear = [int]$currentDate.DayOfYear
    $year = [int]$currentDate.Year

    return "{0}-{1:D5}-{2:D3}-{3:D6}-{4:D2}-{5:D4}-{6:D4}.0000-{7:D3}{8:D4}" -f (
        $mpc,
        $groupPart,
        $channelId,
        $sequence,
        $LicenseType,
        $langId,
        $buildNumber,
        $dayOfYear,
        $year
    )
}

# ===============================================================================================================================

function Show-RedeemKeyStatus {
    param(
        [string]$AlgorithmId = $algorithmId,
        [string]$Eula = '',
        [int]$GroupId = 0
    )

    if ($CheckRedeemKey) {
        Invoke-CheckRedeemKey $ProductKey $LogFolder $f $scriptDir
    }
    elseif (-not $AlgorithmId -or $Eula -eq "ltPIN" -or $GroupId -eq 28) {
        Write-Output ""
        Write-Color ($f -f "Tip", "This may be a Redeem key. Enable Redeem Status for details.") "FgYellow"
    }
}

# ===============================================================================================================================
# Main execution
# ===============================================================================================================================

if (-not (Test-Path $dllPath)) { Write-Color "PidGenX DLL not found: $dllPath" "BgRed"; return }
if (-not $global:PKeyConfigsMap) { Write-Color "PKeyConfigsMap cache not found." "BgRed"; return }

# ===============================================================================================================================

# If manual path is specified, check only the specified pkeyconfig with PidGenX
# If manual path is not specified, check only the two custom pkeyconfigs for PKey2005 and PKey980-986 with PidGenX (PKey2009 keys are decoded manually)

$configTargets = @()

if ($ProductKey -notmatch 'Z') {
    if (-not $ManualPKeyConfigPath) {
        if ($ProductKey -notmatch 'N') {
            $pkeyConfigsDir = Join-Path (Split-Path -Parent $scriptDir) "PKeyConfigs"
            $customProfiles = @($global:PKeyConfigsMap | Where-Object { $_.Profile -match "custom" })
            foreach ($entry in $customProfiles) {
                $relativePath = $entry.Path.TrimStart('\')
                $configTargets += Join-Path $pkeyConfigsDir $relativePath
            }
        }
    }
    else {
        $configTargets += $ManualPKeyConfigPath
    }
}

# ===============================================================================================================================

# Here we are checking the key with the pkeyconfig files (see above) by passing it to PidGenX
# Only Group ID, Key ID, and IsUpgrade are extracted here; the rest of the info will be calculated manually or fetched directly from pkeyconfig

$hr = $null

if ($configTargets.Count -gt 0) {

    # Allocate DPID4 buffer

    $d4 = New-Object byte[] 1272; $d4[0] = 0xF8; $d4[1] = 0x04
    $gh4 = [System.Runtime.InteropServices.GCHandle]::Alloc($d4, "Pinned")

    try {
        foreach ($currentPath in $configTargets) {
            if (-not (Test-Path $currentPath)) { continue }

            # Call PidGenX
            $hr = $Script:PidGenXNativeType::PidGenX($ProductKey, $currentPath, "00000", "", [IntPtr]::Zero, [IntPtr]::Zero, $gh4.AddrOfPinnedObject())

            if ($hr -eq 0) {
                $parsedDpid4 = Get-DigitalProductIdV4 $d4
                if ($parsedDpid4 -and $parsedDpid4.AdvancedPid) {
                    $preAdvPid = $parsedDpid4.AdvancedPid
                    $preAdvPidParts = $preAdvPid -split '-'
                    if ($preAdvPidParts.Count -ge 4) {
                        $groupId = [int]$preAdvPidParts[1]
                        $keyId = [int64]($preAdvPidParts[2] + $preAdvPidParts[3])
                        $isUpgrade = ($parsedDpid4.IsUpgrade -eq 1)
                        if (-not $ManualPKeyConfigPath) {
                            $algoKey = if ($currentPath -match '980|986') { 'PKey986-980' } else { 'PKey2005' }
                        }
                        break
                    }
                }
            }
        }
    }
    finally {
        if ($gh4) { $gh4.Free() }
    }
}

# ===============================================================================================================================

# Decode PKey2009 key

if ($ProductKey -match 'N' -and $ProductKey -notmatch 'Z') {
    $decodeScript = Join-Path $scriptDir "DecodePKey2009.ps1"
    if (Test-Path $decodeScript) {
        $decodeOutput = @(& $decodeScript -Key $ProductKey -PassThru 2>$null)
        if ($decodeOutput) {
            # Last item in the array is the data object
            $dataObj = $decodeOutput[-1]
            if ($dataObj -and $dataObj.ChecksumValid) {
                $groupId = $dataObj.Group
                $keyId = $dataObj.Serial
                $isUpgrade = $dataObj.Upgrade
                $algoKey = 'PKey2009'
                $pkey2009DecodedSecurity = $dataObj.Security
                $pkey2009DecodedExtra = $dataObj.Extra
            }
        }
    }
}

# ===============================================================================================================================

# Search PKeyConfig file from PKeyConfigsMap.json map using GroupId and KeyId

$matchedConfigPath = $null
$matchedProfileName = $null

if ($null -ne $groupId -and $null -ne $keyId) {
    if (-not $ManualPKeyConfigPath) {
        if ($algoKey) {
            $pkeyConfigsDir = Join-Path (Split-Path -Parent $scriptDir) "PKeyConfigs"
            $gStr = [string]$groupId
            $configsMap = @($global:PKeyConfigsMap | Where-Object { $_.Profile -notmatch "custom" }) + @($global:PKeyConfigsMap | Where-Object { $_.Profile -match "custom" })
            foreach ($entry in $configsMap) {
                $foundInEntry = $false
                if ($entry.Algorithms -and $entry.Algorithms.ContainsKey($algoKey)) {
                    $algoGroups = $entry.Algorithms[$algoKey]
                    if ($algoGroups -and $algoGroups.ContainsKey($gStr)) {
                        foreach ($range in $algoGroups[$gStr]) {
                            if ($keyId -ge $range[0] -and $keyId -le $range[1]) {
                                $foundInEntry = $true
                                break
                            }
                        }
                    }
                }
                if ($foundInEntry) {
                    $matchedConfigPath = Join-Path $pkeyConfigsDir $entry.Path.TrimStart('\')
                    $matchedProfileName = $entry.Profile
                    break
                }
            }
        }
    }
    else {
        $matchedConfigPath = $ManualPKeyConfigPath
        $matchedProfileName = if ($ManualProfileName) { $ManualProfileName } else { $ManualPKeyConfigPath }
    }
}

# ===============================================================================================================================

# Get info from PKeyConfig file

if ($matchedConfigPath -and (Test-Path $matchedConfigPath)) {
    $infoOutput = @(& $readerPath -GetKeyInfo -File $matchedConfigPath -GroupId $groupId -KeyId $keyId -PassThru 2>$null)
    if ($infoOutput) {
        $info = $infoOutput[-1]
        $algorithmId = $info.AlgorithmId
        if ($info.Description -ne "CustomMade") {
            $description = $info.Description
            $edition = $info.Edition
            $eula = $info.EULA
            $keyType = $info.KeyType
            $partNumber = $info.PartNumber
            $activationId = if ($info.ActivationId) { $info.ActivationId.Trim('{', '}').ToLower() }
            $isValid = $info.IsValid
        }
    }
}

# ===============================================================================================================================

# If no matching PKeyConfig found or info could not be retrieved, exit the script

if (-not $algorithmId) {
    $resultText = if ($null -ne $pkey2009DecodedSecurity -or ($null -ne $hr -and $hr -eq 0)) {
        "Valid key, but matching profile not found"
    }
    elseif ($ProductKey -match 'Z$') {
        "Likely a redeem key"
    }
    else {
        "Invalid key, or matching profile not found"
    }

    Write-Output ""
    Write-Output ($f -f "Product Key", $ProductKey)
    Write-Color ($f -f "Result", $resultText) "BgGray"

    if ($null -ne $pkey2009DecodedSecurity) {
        Write-Output ($f -f "Upgrade Key", $(if ($isUpgrade) { "Yes" } else { "No" }))
        Write-Output ($f -f "Group ID", ("{0} (0x{0:X})" -f $groupId))
        Write-Output ($f -f "Key ID", ("{0} (0x{0:X})" -f $keyId))
        Write-Output ($f -f "Security", ("{0} (0x{0:X})" -f $pkey2009DecodedSecurity))
        Write-Output ($f -f "PKey2009 Extra", ("{0} (0x{0:X})" -f $pkey2009DecodedExtra))
        Write-Output ($f -f "Algorithm ID", "msft:rm/algorithm/pkey/2009")
    }

    Show-RedeemKeyStatus
    return
}

# ===============================================================================================================================

# PKey980/986 Bink and Cryptography

if ($algorithmId -match "980|986") {
    $bink = if ($algorithmId -match "980") { "Bink1998" } else { "Bink2002" }
    $channel = [int64][Math]::Floor($keyId / 1000000)
    $seq = $keyId % 1000000

    $decode980Script = Join-Path $scriptDir "DecodePKey980-PKey986.ps1"
    if (Test-Path $decode980Script) {
        $decodeOutput = @(& $decode980Script -productKey $ProductKey -binkIdHex ("0x{0:X}" -f $groupId) -PassThru 2>$null)
        if ($decodeOutput) {
            $dataObj = $decodeOutput[-1]
            if ($dataObj) {
                $decodeHash = $dataObj.Hash
                $decodeAuth = $dataObj.Auth
                $decodeSig = $dataObj.Signature
            }
        }
    }
}

# ===============================================================================================================================

# PKey2005/2009 ActConfig ID and Installation ID

if ($algorithmId -match "2005|2009") {
    if ($algorithmId -match "2005") {
        $pkey2005Security = Read-PidGenXPKey2005Security
        $pkActConfigId = Get-PKey2005ActConfigId $activationId $isUpgrade $keyId $pkey2005Security
    }
    elseif ($algorithmId -match "2009") {
        $pkActConfigId = Get-PKey2009ActConfigId $activationId $isUpgrade $keyId $groupId $pkey2009DecodedSecurity
    }
    if ($GetInstallationId -or $GetConfirmationId) {
        $iid = Invoke-GetInstallationId $ProductKey $matchedConfigPath
    }
}

# ===============================================================================================================================

# Calculate License Type, Product ID, and Extended PID

if ($keyType -or ($algorithmId -match "980|986")) {
    $lt = Get-LicenseType -KeyType $keyType -IsUpgrade $isUpgrade -AlgorithmId $algorithmId -Serial $keyId -GroupId $groupId
    $isOem = ($lt -eq 2)
    $advPid = Get-ExtendedProductId -GroupId $groupId -Serial $keyId -LicenseType $lt
    if ($advPid -and $advPid.Length -ge 22) {
        $labelId = $advPid.Substring(6, 13) + "-" + $advPid.Substring(19, 3)
    }
    $productId = Get-ProductId -Algorithm $algorithmId -GroupId $groupId -Serial $keyId -IsOem $isOem -IsUpgrade $isUpgrade
}

# ===============================================================================================================================

# Output Result

Write-Output ""
Write-Output ($f -f "Product Key", $ProductKey)
if ($matchedProfileName) { Write-Output ($f -f "Profile", $matchedProfileName) }
if ("$isValid" -eq "false") { Write-Color ($f -f "Result", "Blocked in PKeyConfig") "BgRed" }

# Summary Block

if ($algorithmId -match "980|986" -and -not $description) {
    Write-ProductMatch $groupId $keyId $f $scriptDir
}
else {
    if ($description) { Write-Color ($f -f "Description", $description) "BgGreen" }
    if ($edition) { Write-Output ($f -f "Edition", $edition) }
    if ($keyType) { Write-Output ($f -f "Key Type", $keyType) }
    if ($eula) { Write-Output ($f -f "EULA", $eula) }
}
Write-Output ($f -f "Upgrade Key", $(if ($isUpgrade) { "Yes" } else { "No" }))

Write-Output ""

# Crypto & Algorithm-specific block

if ($bink) { Write-Output ($f -f "Bink", $bink) }
if ($null -ne $groupId) { Write-Output ($f -f "Group ID", ("{0} (0x{0:X})" -f $groupId)) }
if ($null -ne $keyId) { Write-Output ($f -f "Key ID", ("{0} (0x{0:X})" -f $keyId)) }
if ($null -ne $channel) { Write-Output ($f -f "Channel ID", ("{0} (0x{0:X})" -f $channel)) }
if ($null -ne $seq) { Write-Output ($f -f "Sequence", ("{0} (0x{0:X})" -f $seq)) }
if ($null -ne $decodeHash) { Write-Output ($f -f "Hash", ("{0} (0x{0:X})" -f $decodeHash)) }
if ($null -ne $decodeAuth) { Write-Output ($f -f "Auth", ("{0} (0x{0:X})" -f $decodeAuth)) }
if ($null -ne $decodeSig) { Write-Output ($f -f "Signature", ("{0} (0x{0:X})" -f $decodeSig)) }
if ($null -ne $pkey2009DecodedSecurity) { Write-Output ($f -f "Security", ("{0} (0x{0:X})" -f $pkey2009DecodedSecurity)) }
if ($null -ne $pkey2009DecodedExtra) { Write-Output ($f -f "PKey2009 Extra", ("{0} (0x{0:X})" -f $pkey2009DecodedExtra)) }
if ($null -ne $pkey2005Security) { Write-Output ($f -f "Security", ("{0} (0x{0:X})" -f $pkey2005Security)) }

Write-Output ""

# IDs & Licensing details

if ($null -ne $lt) { Write-Output ($f -f "License Type", $lt) }
if ($partNumber) { Write-Output ($f -f "Part number", $partNumber) }
if ($labelId) { Write-Output ($f -f "Label ID", $labelId) }
if ($productId) { Write-Output ($f -f "Product ID", $productId) }
if ($algorithmId) { Write-Output ($f -f "Algorithm ID", $algorithmId) }
if ($activationId) { Write-Output ($f -f "Activation ID", $activationId) }
if ($advPid) { Write-Output ($f -f "Extended PID", $advPid) }
if ($iid) { Write-Output ($f -f "Installation ID", $iid) }
if ($pkActConfigId) { Write-Output ($f -f "ActConfig ID", $pkActConfigId) }

# Sub-actions (Cert, Act, Mak, Cid)

if ($algorithmId -match "2005|2009") {
    $doCert = $KeyCertification -and $pkActConfigId
    $doAct = $KeyActivation -and $pkActConfigId
    $doMak = $MAKCount -and $keyType -match "Volume:MAK"
    $doCid = $GetConfirmationId -and $iid

    if ($doCert -or $doAct -or $doMak -or $doCid) {
        Write-Output ""
    }

    $script:SubActionLastState = $null

    if ($doCert) { Invoke-KeyCertification $ProductKey $pkActConfigId $LogFolder $f $scriptDir }
    if ($doAct) { Invoke-KeyActivation $ProductKey $pkActConfigId $LogFolder $f $scriptDir }
    if ($doMak) { Invoke-MakCount $advPid $LogFolder $f $scriptDir }
    if ($doCid) { Invoke-GetConfirmationId $iid $LogFolder $f $scriptDir }
}

Show-RedeemKeyStatus -AlgorithmId $algorithmId -Eula $eula -GroupId $groupId

# ===============================================================================================================================
