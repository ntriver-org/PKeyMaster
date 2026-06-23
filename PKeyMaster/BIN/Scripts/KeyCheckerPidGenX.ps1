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
    Requires PKeyConfigsMap.csv and PreVistaRanges.csv in the application root.
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

# ===============================================================================================================================
# P/Invoke type compilation
# ===============================================================================================================================

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

# Patched memory offsets (must be verified if pidgenx DLL is updated)

$captureOffset = if ([IntPtr]::Size -eq 8) { 0xAF6F8 } else { 0x8F4C2 }
$captureSize = if ([IntPtr]::Size -eq 8) { 512 }     else { 256 }

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function Write-ProductMatch($GroupId, $KeyId, $f, $scriptDir) {
    # Look up Group ID + Key ID in PreVistaRanges.csv for product editions.
    if ($null -eq $KeyId) { return }
    
    $csvPath = Join-Path (Split-Path -Parent $scriptDir) "PreVistaRanges.csv"
    if (-not (Test-Path $csvPath)) { return }

    $editionMatches = @{}
    foreach ($row in (Import-Csv $csvPath)) {
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
            Write-Output ($f -f "Product Match", $m)
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

function Invoke-KeyCertification($ProductKey, $ActConfigId, $LogFolder, $f, $scriptDir) {
    # Run KeyCertification.ps1 and display the result.
    $certScript = Join-Path $scriptDir "KeyCertification.ps1"
    $params = @{ ProductKey = $ProductKey; ActConfigId = $ActConfigId }
    if ($LogFolder) { $params['LogPath'] = $LogFolder }
    $certOutput = Invoke-PassThruScript $certScript $params
    if (-not $certOutput) { return }
    $certObj = $certOutput[-1]
    if (-not $certObj -or -not $certObj.Result) { return }
    
    if ($certObj.Result -eq "SUCCESS") {
        Write-Color ($f -f "Key Certification", "Valid") "BgGreen"
    }
    else {
        Write-Color ($f -f "Key Certification", "Failed") "BgRed"
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
    if (-not $actObj -or -not $actObj.Result) { return }
    
    if ($actObj.Result -eq "SUCCESS") {
        Write-Color ($f -f "Key Activation", "Succeeded") "BgGreen"
    }
    else {
        Write-Color ($f -f "Key Activation", "Failed") "BgRed"
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
        Write-Color ($f -f "MAK Count", $makObj.RemainingCount) "BgGreen"
    }
    else {
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
                Write-Color ($f -f "CID Batch Api", $cidObj.BatchCID) "BgGreen"
            }
            else {
                Write-Color ($f -f "CID Batch Api", "Failed") "BgRed"
                Write-Color ($f -f "Batch Error Code", $cidObj.BatchErrorCode) "BgRed"
                Write-Color ($f -f "Batch Error Msg", $cidObj.BatchErrorDetail) "BgRed"
            }
        }

        if ($cidObj.VisualResult) {
            if ($cidObj.VisualResult -eq "SUCCESS") {
                Write-Color ($f -f "CID Visual Api", $cidObj.VisualCID) "BgGreen"
            }
            else {
                Write-Color ($f -f "CID Visual Api", "Failed") "BgRed"
                Write-Color ($f -f "Visual Error Code", $cidObj.VisualErrorCode) "BgRed"
                Write-Color ($f -f "Visual Error Msg", $cidObj.VisualErrorDetail) "BgRed"
            }
        }
    }
}

# ===============================================================================================================================

function Read-ActConfigId {
    # Read ActConfigId from a patched memory offset in the PIDGenX DLL.
    $hModule = $Script:PidGenXNativeType::GetModuleHandle($dllName)
    if ($hModule -eq [IntPtr]::Zero) { return "" }

    $bufferPtr = [IntPtr]($hModule.ToInt64() + $captureOffset)
    $builder = New-Object System.Text.StringBuilder
    for ($index = 0; $index -lt $captureSize; $index++) {
        $val = [System.Runtime.InteropServices.Marshal]::ReadInt16($bufferPtr, ($index * 2))
        if ($val -eq 0) { break }
        $null = $builder.Append([char]$val)
    }
    
    $result = $builder.ToString().Trim()
    if ($result -match '^(?i)msft200[59]:[^\s]+$') { return $result }
    return ""
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
# Main execution
# ===============================================================================================================================

$f = "{0,-18}: {1}"
if (-not (Test-Path $dllPath)) { Write-Color "PidGenX DLL not found: $dllPath" "BgRed"; return }

# Determine PKey2009 vs Non-PKey2009

$isPKey2009 = $ProductKey -match 'N'

if ($isPKey2009) {
    $decodeScript = Join-Path $scriptDir "DecodePKey2009.ps1"
    if (Test-Path $decodeScript) {
        $decodeOutput = @(& $decodeScript -Key $ProductKey -PassThru 2>$null)
        if ($decodeOutput) {
            # Last item in the array is the data object
            $dataObj = $decodeOutput[-1]
            if ($dataObj) {
                $pkey2009DecodedGroup = $dataObj.Group
                $pkey2009DecodedSerial = $dataObj.Serial
                $pkey2009DecodedSecurity = $dataObj.Security
                $pkey2009DecodedUpgrade = $dataObj.Upgrade
                $pkey2009DecodedExtra = $dataObj.Extra
            }
        }
    }
}

# ===============================================================================================================================

# Auto-search: find matching PKeyConfig files

$configTargets = @()
$targetProfileNames = @()

if (-not $ManualPKeyConfigPath) {

    $csvPath = Join-Path (Split-Path -Parent $scriptDir) "PKeyConfigsMap.csv"
    if (-not (Test-Path $csvPath)) {
        Write-Color "PKeyConfigsMap.csv not found: $csvPath" "BgRed"
        return
    }

    $configsMap = Import-Csv $csvPath

    $sortedRows = @()
    if ($isPKey2009) {
        for ($p = 1; $p -le 4; $p++) {
            $sortedRows += @($configsMap | Where-Object { [int]$_.PKey2009Priority -eq $p })
        }
    }
    else {
        for ($p = 1; $p -le 4; $p++) {
            $sortedRows += @($configsMap | Where-Object { [int]$_.'PKey986-980Priority' -eq $p })
        }
        for ($p = 1; $p -le 4; $p++) {
            $sortedRows += @($configsMap | Where-Object { [int]$_.PKey2005Priority -eq $p })
        }
    }

    if ($sortedRows.Count -eq 0) {
        Write-Color "No valid pkeyconfig files found in priority list for this key type." "BgRed"
        return
    }

    $pkeyConfigsDir = Join-Path (Split-Path -Parent $scriptDir) "PKeyConfigs"
    foreach ($row in $sortedRows) {
        $configTargets += Join-Path $pkeyConfigsDir $row.Path
        $targetProfileNames += $row.Profile
    }
}
else {
    $configTargets += $ManualPKeyConfigPath
    $targetProfileNames += if ($ManualProfileName) { $ManualProfileName } else { $ManualPKeyConfigPath }
}

# ===============================================================================================================================

# Allocate DPID buffers (pinned for P/Invoke)

$d2 = New-Object byte[] 50
$d3 = New-Object byte[] 164; $d3[0] = 0xA4
$d4 = New-Object byte[] 1272; $d4[0] = 0xF8; $d4[1] = 0x04

$gh2 = [System.Runtime.InteropServices.GCHandle]::Alloc($d2, "Pinned")
$gh3 = [System.Runtime.InteropServices.GCHandle]::Alloc($d3, "Pinned")
$gh4 = [System.Runtime.InteropServices.GCHandle]::Alloc($d4, "Pinned")

$matchFound = $false
$hr = $null

# PidGenX iteration: try each config until a match is found

try {
    for ($i = 0; $i -lt $configTargets.Count; $i++) {
        $currentPath = $configTargets[$i]
        $currentProfile = $targetProfileNames[$i]

        if (-not (Test-Path $currentPath)) { continue }

        # Call PidGenX
        $hr = $Script:PidGenXNativeType::PidGenX($ProductKey, $currentPath, "00000", "", $gh2.AddrOfPinnedObject(), $gh3.AddrOfPinnedObject(), $gh4.AddrOfPinnedObject())
        
        if ($hr -eq 0) {
            if ($LogFolder -and (Test-Path $LogFolder)) {
                try {
                    [System.IO.File]::WriteAllBytes((Join-Path $LogFolder "DPID2.bin"), $d2)
                    [System.IO.File]::WriteAllBytes((Join-Path $LogFolder "DPID3.bin"), $d3)
                    [System.IO.File]::WriteAllBytes((Join-Path $LogFolder "DPID4.bin"), $d4)
                }
                catch {}
            }
            # Parse DPID (Core Metadata)
            $parsedDpid3 = Get-DigitalProductIdV3 $d3
            $parsedDpid4 = Get-DigitalProductIdV4 $d4
            $activationId = $parsedDpid4.ActivationId
            $groupId = $parsedDpid3.KeyIndex

            # PKeyConfigReader matches this DPID activation GUID against the config XML ActConfigId node.
            $infoOutput = @(& $readerPath -GetKeyInfo -File $currentPath -ActConfigId $activationId -GroupId $groupId -PassThru 2>$null)
            $info = if ($infoOutput) { $infoOutput[-1] } else { New-Object PSObject -Property @{ Description = ''; Edition = ''; KeyType = ''; Algorithm = '' } }

            # Extract Label ID and Key ID from Advanced PID
            $advPid = $parsedDpid4.AdvancedPid
            $labelId = ""
            $keyId = 0
            if ($advPid -and $advPid.Length -ge 22) {
                $labelId = $advPid.Substring(6, 13) + "-" + $advPid.Substring(19, 3)
                $keyIdStr = $advPid.Substring(12, 3) + $advPid.Substring(16, 6)
                $keyId = [int64]$keyIdStr
            }

            $isTestKey = ($info.Description -eq "TEST" -and $info.Edition -eq "TEST" -and $info.Algorithm -notmatch "2005|2009")

            $pkActConfigId = ""
            $iid = ""
            if (-not $isTestKey) {
                # Parse and Capture
                if ($info.Algorithm -match "2005|2009") {
                    $pkActConfigId = Read-ActConfigId
                    if ($GetInstallationId -or $GetConfirmationId) {
                        $iid = Invoke-GetInstallationId $ProductKey $currentPath
                    }
                }
            }
            
            # Part number at offset 888 = EditionId
            $partNumber = $parsedDpid4.EditionId

            # Output Result
            Write-Output ""
            Write-Output ($f -f "Product Key", $ProductKey)
            Write-Output ($f -f "Profile", $currentProfile)
            Write-Color ($f -f "Result", "Specified key is valid") "BgGreen"
            Write-Output ($f -f "Product ID", $parsedDpid3.ProductId)
            Write-Output ($f -f "Extended PID", $advPid)

            if (-not $isTestKey) {
                if ($iid) {
                    Write-Output ($f -f "Installation ID", $iid)
                }
                if ($pkActConfigId) {
                    Write-Output ($f -f "ActConfig ID", $pkActConfigId)
                }
                Write-Output ($f -f "Activation ID", $activationId)
                Write-Output ($f -f "Description", $info.Description)
                Write-Output ($f -f "Edition", $info.Edition)
                Write-Output ($f -f "Part number", $partNumber)
                Write-Output ($f -f "Label ID", $labelId)
                Write-Output ($f -f "Key Type", $info.KeyType)
                if ($parsedDpid4.EULA) {
                    Write-Output ($f -f "EULA", $parsedDpid4.EULA)
                }
            }

            Write-Output ($f -f "Algorithm ID", $info.Algorithm)
            Write-Output ($f -f "Group ID", ("{0} (0x{0:X})" -f $groupId))
            Write-Output ($f -f "Key ID", ("{0} (0x{0:X})" -f $keyId))

            $channel = $null
            $seq = $null
            if ($info.Algorithm -match "980|986") {
                $channel = [int64][Math]::Floor($keyId / 1000000)
                $seq = $keyId % 1000000
                Write-Output ($f -f "Channel ID", $channel)
                Write-Output ($f -f "Sequence", $seq)

                $decode980Script = Join-Path $scriptDir "DecodePKey980-PKey986.ps1"
                if (Test-Path $decode980Script) {
                    $decodeOutput = @(& $decode980Script -productKey $ProductKey -binkIdHex ("0x{0:X}" -f $groupId) -PassThru 2>$null)
                    if ($decodeOutput) {
                        $dataObj = $decodeOutput[-1]
                        if ($dataObj) {
                            if ($null -ne $dataObj.Format) { Write-Output ($f -f "Bink", $dataObj.Format) }
                            if ($null -ne $dataObj.Hash) { Write-Output ($f -f "Hash", $dataObj.Hash) }
                            if ($null -ne $dataObj.Auth) { Write-Output ($f -f "Auth", $dataObj.Auth) }
                            if ($null -ne $dataObj.Signature) { Write-Output ($f -f "Signature", $dataObj.Signature) }
                        }
                    }
                }
            }
            Write-Output ($f -f "License Type", $parsedDpid3.Lt)
            Write-Output ($f -f "Upgrade Key", $(if ($parsedDpid4.IsUpgrade -eq 1) { "Yes" } else { "No" }))
            if ($isTestKey) {
                Write-ProductMatch $groupId $keyId $f $scriptDir
            }

            if (-not $isTestKey) {
                if ($isPKey2009 -and $null -ne $pkey2009DecodedGroup) {
                    Write-Output ($f -f "PKey2009 Security", $pkey2009DecodedSecurity)
                    Write-Output ($f -f "PKey2009 Extra", $pkey2009DecodedExtra)
                }
                
                $runAnyApi = ($KeyCertification -and $pkActConfigId) -or ($KeyActivation -and $pkActConfigId) -or ($MAKCount -and $info.KeyType -match "Volume:MAK") -or ($GetConfirmationId -and $iid)
                if ($runAnyApi) { Write-Output "" }

                if ($KeyCertification -and $pkActConfigId) {
                    Invoke-KeyCertification $ProductKey $pkActConfigId $LogFolder $f $scriptDir
                }

                if ($KeyActivation -and $pkActConfigId) {
                    Invoke-KeyActivation $ProductKey $pkActConfigId $LogFolder $f $scriptDir
                }

                if ($MAKCount -and $info.KeyType -match "Volume:MAK") {
                    Invoke-MakCount $parsedDpid4.AdvancedPid $LogFolder $f $scriptDir
                }

                if ($GetConfirmationId -and $iid) {
                    Invoke-GetConfirmationId $iid $LogFolder $f $scriptDir
                }
            }
            $matchFound = $true
            break
        }
    }

    if (-not $matchFound) {
        $resultText = "Failed (No matching configuration found)"
        $hrHex = ""
        if ($null -ne $hr) {
            $resultText = switch ($hr) {
                -2147024809 { 'The parameter is incorrect' }
                -1979645695 { "Specified key is either invalid or couldn't find a matching profile" }
                -1979645951 { "Specified key is valid but couldn't find a matching profile" }
                -2147024894 { "Can't find specified pkeyconfig file" }
                -2147024893 { 'Specified pkeyconfig path does not exist' }
                15 { 'Specified key is blacklisted' }
                default {
                    'Error: 0x{0:X8}' -f [int]$hr
                }
            }
            $hrHex = "0x{0:X8}" -f [int]$hr
        }

        Write-Output ""
        Write-Output ($f -f "Product Key", $ProductKey)
        Write-Color ($f -f "Result", $resultText) "BgRed"
        if ($hrHex) {
            Write-Color ($f -f "PidGenX ErrorCode", ("{0} ({1})" -f $hr, $hrHex)) "BgRed"
        }
        if ($hr -eq -1979645951 -and $null -ne $pkey2009DecodedGroup) {
            Write-Output ($f -f "Algorithm ID", "msft:rm/algorithm/pkey/2009")
            Write-Output ($f -f "Group ID", ("{0} (0x{0:X})" -f $pkey2009DecodedGroup))
            Write-Output ($f -f "Key ID", ("{0} (0x{0:X})" -f $pkey2009DecodedSerial))
            Write-Output ($f -f "Upgrade Key", $(if ($pkey2009DecodedUpgrade -eq 1) { "Yes" } else { "No" }))
            Write-Output ($f -f "PKey2009 Security", $pkey2009DecodedSecurity)
            Write-Output ($f -f "PKey2009 Extra", $pkey2009DecodedExtra)
        }
    }
}
finally {
    if ($gh2) { $gh2.Free() }
    if ($gh3) { $gh3.Free() }
    if ($gh4) { $gh4.Free() }
}

# ===============================================================================================================================
