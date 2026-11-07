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

.PARAMETER RedeemStatus
    Enables redeem key validation via Microsoft licensing endpoint.

.PARAMETER MAKCount
    Enables MAK remaining count query.

.PARAMETER GetConfirmationId
    Enables Confirmation ID retrieval via the VisualApi, fallbacks to BatchApi.

.PARAMETER LogFolder
    Path to save DPID binary dumps and API request/response logs.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Windows Vista SP1+ (build 6001+).
    Requires pidgenx64.dll or pidgenx32.dll in the BIN directory.
    Requires Libs\DigitalProductId.psm1,
    KeyCertification.ps1, KeyActivation.ps1, MakCount.ps1, RedeemStatus.ps1, GetCID.ps1,
    DecodePKey2009.ps1, DecodePKey980-PKey986.ps1, Ids\*.ps1 for features.
    Requires PKeyConfigsMap.json and PreVistaRanges.csv in the application root.
    Requires Libs\Common.psm1 for shared helper functions.

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
    [switch]$RedeemStatus,
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

Import-Module "$scriptDir\Libs\Common.psm1"
Import-Module "$scriptDir\Libs\DigitalProductId.psm1"

$f = "{0,-18}: {1}"

# ===============================================================================================================================
# P/Invoke type compilation
# ===============================================================================================================================

if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM') {
    Write-Color "PidGenX script is not supported on Windows ARM32 systems." "BgRed"
    return
}

if (-not $global:PidGenXNativeType) {
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

        $global:PidGenXNativeType = $TB.CreateType()
    }
    catch {
        Write-Color "Failed to initialize native methods: $($_.Exception.Message)" "BgRed"
        return
    }
}
$Script:PidGenXNativeType = $global:PidGenXNativeType

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function Invoke-RedeemStatus($RedeemKey, $LogFolder, $f, $scriptDir) {
    # Run RedeemStatus.ps1 and show the redeem-key status.
    $params = @{ RedeemKey = $RedeemKey }
    if ($LogFolder) { $params['LogPath'] = $LogFolder }
    $redeemObj = Invoke-PassThruScript "RedeemStatus.ps1" $params
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
        if ($redeemObj.Note) {
            Write-Output ($f -f "Redeem Note", $redeemObj.Note)
        }
    }
}

# ===============================================================================================================================

function Invoke-KeyCertification($ProductKey, $ActConfigId, $LogFolder, $f, $scriptDir) {
    # Run KeyCertification.ps1 and display the result.
    $params = @{ ProductKey = $ProductKey; ActConfigId = $ActConfigId }
    if ($LogFolder) { $params['LogPath'] = $LogFolder }
    $certObj = Invoke-PassThruScript "KeyCertification.ps1" $params
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
    $params = @{ ProductKey = $ProductKey; ActConfigId = $ActConfigId }
    if ($LogFolder) { $params['LogPath'] = $LogFolder }
    $actObj = Invoke-PassThruScript "KeyActivation.ps1" $params
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
    $params = @{ AdvancedPid = $AdvancedPid }
    if ($LogFolder) { $params['LogPath'] = $LogFolder }
    $makObj = Invoke-PassThruScript "MakCount.ps1" $params
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
    $params = @{ InstallationId = $IID }
    if ($LogFolder) {
        $params['ExportLogs'] = $true
        $params['LogPath'] = $LogFolder
        $params['ExactLogPath'] = $true
        $params['NoOpenFolder'] = $true
    }
    $cidObj = Invoke-PassThruScript "GetCID.ps1" $params
    
    if ($cidObj) {
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

function Show-RedeemKeyStatus {
    param(
        [string]$AlgorithmId = $algorithmId,
        [string]$Eula = '',
        [int]$GroupId = 0
    )

    if ($RedeemStatus) {
        Invoke-RedeemStatus $ProductKey $LogFolder $f $scriptDir
    }
    elseif (-not $AlgorithmId -or $Eula -eq "ltPIN" -or $GroupId -eq 28) {
        Write-Output ""
        Write-Color ($f -f "Tip", "This may be a Redeem key. Enable Redeem Status for details.") "FgYellow"
    }
}

# ===============================================================================================================================
# Main execution
# ===============================================================================================================================

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
    $dataObj = Invoke-PassThruScript "DecodePKey2009.ps1" @{ Key = $ProductKey }
    if ($dataObj -and $dataObj.ChecksumValid) {
        $groupId = $dataObj.Group
        $keyId = $dataObj.Serial
        $isUpgrade = $dataObj.Upgrade
        $algoKey = 'PKey2009'
        $pkey2009DecodedSecurity = $dataObj.Security
        $pkey2009DecodedExtra = $dataObj.Extra
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
    $info = Get-PKeyConfigInfo -FilePath $matchedConfigPath -GroupId $groupId -KeyId $keyId
    if ($info) {
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

    $dataObj = Invoke-PassThruScript "DecodePKey980-PKey986.ps1" @{ productKey = $ProductKey; binkIdHex = ("0x{0:X}" -f $groupId) }
    if ($dataObj) {
        $decodeHash = $dataObj.Hash
        $decodeAuth = $dataObj.Auth
        $decodeSig = $dataObj.Signature
    }
}

# ===============================================================================================================================

# PKey2005/2009 ActConfig ID and Installation ID

if ($algorithmId -match "2005|2009") {
    $actParams = if ($algorithmId -match "2005") {
        $pkey2005Security = Read-PidGenXPKey2005Security
        @{ Encode = $true; Algorithm = "PKey2005"; ActId = $activationId; Upgrade = $isUpgrade; Serial = $keyId; Security = $pkey2005Security }
    }
    else {
        @{ Encode = $true; Algorithm = "PKey2009"; ActId = $activationId; Upgrade = $isUpgrade; Serial = $keyId; Group = $groupId; Security = $pkey2009DecodedSecurity }
    }
    $actObj = Invoke-PassThruScript "Ids\ActConfigId.ps1" $actParams
    if ($actObj -and $actObj.ActConfigId) { $pkActConfigId = $actObj.ActConfigId }
    if ($GetInstallationId -or $GetConfirmationId) {
        $iid = Invoke-GetInstallationId $ProductKey $matchedConfigPath
    }
}

# ===============================================================================================================================

# Calculate Label ID, License Type, Product ID, and Extended PID

# Label ID
if ($null -ne $groupId -and $null -ne $keyId) {
    $labelId = "{0:00000}-{1:000-000-000}" -f [int]$groupId, [int64]$keyId
}

# License Type, Extended PID, and Product ID
if ($keyType -or ($algorithmId -match "980|986")) {
    $lt = Get-LicenseType -KeyType $keyType -IsUpgrade $isUpgrade -AlgorithmId $algorithmId -Serial $keyId -GroupId $groupId
    $isOem = ($lt -eq 2)

    # Extended PID
    $epidObj = Invoke-PassThruScript "Ids\ExtendedProductId.ps1" @{ Encode = $true; GroupId = $groupId; Serial = $keyId; LicenseType = $lt }
    if ($epidObj) { $advPid = $epidObj.ExtendedProductId }

    # Product ID
    $prodObj = Invoke-PassThruScript "Ids\ProductId.ps1" @{ Encode = $true; Algorithm = $algorithmId; GroupId = $groupId; Serial = $keyId; IsOem = $isOem; IsUpgrade = $isUpgrade }
    if ($prodObj) { $productId = $prodObj.ProductId }
}

# ===============================================================================================================================

# Output Result

Write-Output ""
Write-Output ($f -f "Product Key", $ProductKey)
if ($matchedProfileName) { Write-Output ($f -f "Profile", $matchedProfileName) }
if ("$isValid" -eq "false") { Write-Color ($f -f "Result", "Blocked in PKeyConfig") "BgRed" }

# Summary Block

if ($algorithmId -match "980|986" -and -not $description) {
    $productMatches = @(Get-PreVistaProductMatch -GroupId $groupId -KeyId $keyId)
    foreach ($m in $productMatches) {
        Write-Color ($f -f "Product Match", $m) "BgGreen"
    }
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
