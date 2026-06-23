<#
.SYNOPSIS
    Shared library for parsing and validating Digital Product IDs (DPID).

.DESCRIPTION
    This script provides helper functions to extract binary data, convert raw key bytes
    to 5x5 product keys (Base24), verify CRC32 and SHA256 integrity hashes, and parse
    the various DPID versions (v2, v3, v4) used across Windows and Office.

.NOTES
    Compatible with PowerShell 2.0 and later.
#>

# ===============================================================================================================================
# Binary extraction helpers
# ===============================================================================================================================

function Get-Bytes {
    # Extract a sub-array of bytes from a blob.
    param([byte[]]$Blob, [int]$Offset, [int]$Count)
    $bytes = New-Object byte[] $Count
    [Array]::Copy($Blob, $Offset, $bytes, 0, $Count)
    return $bytes
}

# ===============================================================================================================================

function Get-Ascii {
    # Decode a null-terminated ASCII string from bytes.
    param([byte[]]$Blob, [int]$Offset, [int]$MaxLen)
    return [System.Text.Encoding]::ASCII.GetString($Blob, $Offset, $MaxLen).Split([char]0)[0].Trim()
}

# ===============================================================================================================================

function Get-Unicode {
    # Decode a null-terminated Unicode string from bytes.
    param([byte[]]$Blob, [int]$Offset, [int]$MaxLen)
    return [System.Text.Encoding]::Unicode.GetString($Blob, $Offset, $MaxLen).Split([char]0)[0].Trim()
}

# ===============================================================================================================================

function Get-UInt16 {
    # 2 bytes to uint16.
    param([byte[]]$Blob, [int]$Offset)
    return [BitConverter]::ToUInt16($Blob, $Offset)
}

# ===============================================================================================================================

function Get-UInt32 {
    # 4 bytes to uint32.
    param([byte[]]$Blob, [int]$Offset)
    return [BitConverter]::ToUInt32($Blob, $Offset)
}

# ===============================================================================================================================
# Key conversion (Base24)
# ===============================================================================================================================

function ConvertFrom-DigitalProductId {
    # 15 bytes -> 25-char product key (handles PKey2009 'N' injection).
    [OutputType([string])]
    param([byte[]]$KeyBytes)

    if (-not $KeyBytes -or $KeyBytes.Length -lt 15) { return '' }

    $bytes = New-Object byte[] 15
    [Array]::Copy($KeyBytes, 0, $bytes, 0, 15)

    # Detect PKey2009 'N' injection flag
    $byte14 = $bytes[14]
    $injectN = [Math]::Truncate($byte14 / 8) -band 1
    $bytes[14] = $byte14 -band 0xF7

    $alphabet = 'BCDFGHJKMPQRTVWXY2346789'
    $key = ''
    $lastRemainder = 0

    # Base24 conversion loop
    for ($i = 24; $i -ge 0; $i--) {
        $remainder = 0
        for ($j = 14; $j -ge 0; $j--) {
            $remainder = ($remainder * 256) -bxor $bytes[$j]
            $bytes[$j] = [Math]::Truncate($remainder / 24)
            $remainder = $remainder % 24
        }
        $key = $alphabet[$remainder] + $key
        $lastRemainder = $remainder
    }

    # Inject 'N' if flag was set (Windows 8+)
    if ($injectN -eq 1) {
        $key = $key.Substring(1).Insert($lastRemainder, 'N')
    }

    return $key.Insert(20, '-').Insert(15, '-').Insert(10, '-').Insert(5, '-')
}

# ===============================================================================================================================
# Integrity verification
# ===============================================================================================================================

function Get-CRC32 {
    # Standard CRC32 on a byte array.
    param([byte[]]$Bytes)
    $poly = [Convert]::ToUInt32(3988292384)
    $crc = [Convert]::ToUInt32(4294967295)
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
        $crc = $crc -bxor $Bytes[$i]
        for ($j = 0; $j -lt 8; $j++) {
            if (($crc -band 1) -eq 1) {
                $crc = [Convert]::ToUInt32([Math]::Truncate($crc / 2)) -bxor $poly
            }
            else {
                $crc = [Convert]::ToUInt32([Math]::Truncate($crc / 2))
            }
        }
    }
    return $crc
}

# ===============================================================================================================================

function Test-CRC32 {
    # Check CRC32 in a DPID v3 blob.
    param([byte[]]$Blob)
    if ($Blob.Length -lt 164) { return 'N/A' }
    $d = Get-Bytes $Blob 0 160
    $computed = Get-CRC32 -Bytes $d
    $stored = [BitConverter]::ToUInt32($Blob, 160)
    return $(if ($computed -eq $stored) { 'Pass' } else { 'Fail' })
}

# ===============================================================================================================================

function Test-CDKey256Hash {
    # SHA256 of the CDKey bytes (offset 824) in a DPID v4 blob.
    param([byte[]]$Blob)
    if ($Blob.Length -lt 856) { return 'N/A' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $ckb = Get-Bytes $Blob 808 16
    $computed = $sha.ComputeHash($ckb)
    $stored = Get-Bytes $Blob 824 32
    if ([BitConverter]::ToString($computed) -eq [BitConverter]::ToString($stored)) { return 'Pass' }
    return 'Fail'
}

# ===============================================================================================================================

function Test-Hash256 {
    # SHA256 integrity hash (offset 856) in a DPID v4 blob.
    param([byte[]]$Blob)
    if ($Blob.Length -lt 888) { return 'N/A' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $copy = $Blob.Clone()
    # The hash field itself is zeroed out during computation
    [Array]::Clear($copy, 856, 32)
    $computed = $sha.ComputeHash($copy)
    $stored = Get-Bytes $Blob 856 32
    if ([BitConverter]::ToString($computed) -eq [BitConverter]::ToString($stored)) { return 'Pass' }
    return 'Fail'
}

# ===============================================================================================================================
# DPID parsing (v2/v3/v4)
# ===============================================================================================================================

function Get-DigitalProductId2 {
    # Parse a DPID v2 blob.
    param([byte[]]$Blob)
    if (-not $Blob -or $Blob.Length -lt 2) { return $null }

    $productId = Get-Unicode -Blob $Blob -Offset 0 -MaxLen $Blob.Length
    if ($productId.Split('-').Length -ne 4) { return $null }
    return New-Object PSObject -Property @{
        BlobSize         = $Blob.Length
        ProductId        = $productId
        ProductId_Offset = "[0-$($Blob.Length - 1)]"
        MajorVersion     = 2
    }
}

# ===============================================================================================================================

function Get-DigitalProductIdV3 {
    # Parse a 164-byte DPID v3 blob.
    param([byte[]]$Blob, [switch]$VerifyHash)
    if (-not $Blob -or $Blob.Length -lt 8) { return $null }

    $uiSize = Get-UInt32 $Blob 0
    if ($uiSize -ne 164) { return $null }

    $cdKeyBytes = Get-Bytes $Blob 52 16
    $obj = New-Object PSObject -Property @{
        BlobSize                        = $Blob.Length
        ProductKey                      = ConvertFrom-DigitalProductId $cdKeyBytes
        UISize                          = $uiSize
        UISize_Offset                   = '[0-3]'
        MajorVersion                    = Get-UInt16 $Blob 4
        MajorVersion_Offset             = '[4-5]'
        MinorVersion                    = Get-UInt16 $Blob 6
        MinorVersion_Offset             = '[6-7]'
        ProductId                       = Get-Ascii $Blob 8 24
        ProductId_Offset                = '[8-31]'
        KeyIndex                        = Get-UInt32 $Blob 32
        KeyIndex_Offset                 = '[32-35]'
        EditionId                       = Get-Ascii $Blob 36 16
        EditionId_Offset                = '[36-51]'
        CDKeyBytes                      = [string]::Join(', ', (Get-Bytes $Blob 52 16))
        CDKeyBytes_Offset               = '[52-67]'
        CloneStatus                     = Get-UInt32 $Blob 68
        CloneStatus_Offset              = '[68-71]'
        Time                            = [System.DateTime]::new(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc).AddSeconds((Get-UInt32 $Blob 72)).ToString('yyyy-MM-dd HH:mm:ss')
        Time_Offset                     = '[72-75]'
        Random                          = Get-UInt32 $Blob 76
        Random_Offset                   = '[76-79]'
        Lt                              = Get-UInt32 $Blob 80
        Lt_Offset                       = '[80-83]'
        LicenseData0                    = Get-UInt32 $Blob 84
        LicenseData0_Offset             = '[84-87]'
        LicenseData1                    = Get-UInt32 $Blob 88
        LicenseData1_Offset             = '[88-91]'
        OemId                           = Get-Ascii $Blob 92 8
        OemId_Offset                    = '[92-99]'
        BundleId                        = Get-UInt32 $Blob 100
        BundleId_Offset                 = '[100-103]'
        HardwareIdStatic                = Get-Ascii $Blob 104 8
        HardwareIdStatic_Offset         = '[104-111]'
        HardwareIdTypeStatic            = Get-UInt32 $Blob 112
        HardwareIdTypeStatic_Offset     = '[112-115]'
        BiosChecksumStatic              = Get-UInt32 $Blob 116
        BiosChecksumStatic_Offset       = '[116-119]'
        VolumeSerialStatic              = Get-UInt32 $Blob 120
        VolumeSerialStatic_Offset       = '[120-123]'
        TotalRamStatic                  = Get-UInt32 $Blob 124
        TotalRamStatic_Offset           = '[124-127]'
        VideoBiosChecksumStatic         = Get-UInt32 $Blob 128
        VideoBiosChecksumStatic_Offset  = '[128-131]'
        HardwareIdDynamic               = Get-Ascii $Blob 132 8
        HardwareIdDynamic_Offset        = '[132-139]'
        HardwareIdTypeDynamic           = Get-UInt32 $Blob 140
        HardwareIdTypeDynamic_Offset    = '[140-143]'
        BiosChecksumDynamic             = Get-UInt32 $Blob 144
        BiosChecksumDynamic_Offset      = '[144-147]'
        VolumeSerialDynamic             = Get-UInt32 $Blob 148
        VolumeSerialDynamic_Offset      = '[148-151]'
        TotalRamDynamic                 = Get-UInt32 $Blob 152
        TotalRamDynamic_Offset          = '[152-155]'
        VideoBiosChecksumDynamic        = Get-UInt32 $Blob 156
        VideoBiosChecksumDynamic_Offset = '[156-159]'
        CRC32                           = Get-UInt32 $Blob 160
        CRC32_Offset                    = '[160-163]'
    }
    if ($VerifyHash) {
        $obj | Add-Member -MemberType NoteProperty -Name 'CRC32Check' -Value (Test-CRC32 $Blob)
    }
    return $obj
}

# ===============================================================================================================================

function Get-DigitalProductIdV4 {
    # Parse a 1272-byte DPID v4 blob.
    param([byte[]]$Blob, [switch]$VerifyHash)
    if (-not $Blob -or $Blob.Length -lt 8) { return $null }

    $uiSize = Get-UInt32 $Blob 0
    if ($uiSize -ne 1272) { return $null }

    $cdKeyBytes = Get-Bytes $Blob 808 16
    $obj = New-Object PSObject -Property @{
        BlobSize             = $Blob.Length
        ProductKey           = ConvertFrom-DigitalProductId $cdKeyBytes
        UISize               = $uiSize
        UISize_Offset        = '[0-3]'
        MajorVersion         = Get-UInt16 $Blob 4
        MajorVersion_Offset  = '[4-5]'
        MinorVersion         = Get-UInt16 $Blob 6
        MinorVersion_Offset  = '[6-7]'
        AdvancedPid          = Get-Unicode $Blob 8 128
        AdvancedPid_Offset   = '[8-135]'
        ActivationId         = Get-Unicode $Blob 136 128
        ActivationId_Offset  = '[136-263]'
        OemId                = Get-Unicode $Blob 264 16
        OemId_Offset         = '[264-279]'
        EditionType          = Get-Unicode $Blob 280 520
        EditionType_Offset   = '[280-799]'
        IsUpgrade            = $(if ($Blob.Length -gt 800) { [byte]$Blob[800] } else { $null })
        IsUpgrade_Offset     = '[800-800]'
        ReservedBytes        = [string]::Join(', ', (Get-Bytes $Blob 801 7))
        ReservedBytes_Offset = '[801-807]'
        CDKeyBytes           = [string]::Join(', ', (Get-Bytes $Blob 808 16))
        CDKeyBytes_Offset    = '[808-823]'
        CDKey256Hash         = [string]::Join(', ', (Get-Bytes $Blob 824 32))
        CDKey256Hash_Offset  = '[824-855]'
        Hash256              = [string]::Join(', ', (Get-Bytes $Blob 856 32))
        Hash256_Offset       = '[856-887]'
        EditionId            = Get-Unicode $Blob 888 128
        EditionId_Offset     = '[888-1015]'
        KeyType              = Get-Unicode $Blob 1016 128
        KeyType_Offset       = '[1016-1143]'
        EULA                 = Get-Unicode $Blob 1144 128
        EULA_Offset          = '[1144-1271]'
    }
    if ($VerifyHash) {
        $obj | Add-Member -MemberType NoteProperty -Name 'CDKey256HashCheck' -Value (Test-CDKey256Hash $Blob)
        $obj | Add-Member -MemberType NoteProperty -Name 'Hash256Check' -Value (Test-Hash256 $Blob)
    }
    return $obj
}

# ===============================================================================================================================

function Get-DigitalProductId {
    # Auto-detect DPID version by blob size and parse it.
    param([byte[]]$Blob, [switch]$VerifyHash)
    if (-not $Blob) { return $null }

    if ($Blob.Length -ge 1272) {
        if ((Get-UInt32 $Blob 0) -eq 1272) { return Get-DigitalProductIdV4 -Blob $Blob -VerifyHash:$VerifyHash }
    }

    if ($Blob.Length -ge 164) {
        if ((Get-UInt32 $Blob 0) -eq 164) { return Get-DigitalProductIdV3 -Blob $Blob -VerifyHash:$VerifyHash }
    }

    if ($Blob.Length -eq 50) {
        return Get-DigitalProductId2 -Blob $Blob
    }
    
    return $null
}

# ===============================================================================================================================
# Formatting & display
# ===============================================================================================================================

function Get-DigitalProductIdFormatted {
    # Turns a parsed DPID object into a readable offset:property:value listing.
    param([psobject]$Obj)
    if (-not $Obj) { return "" }
    
    # Filter to get main properties and sort by their corresponding _Offset value
    $sortedProps = $Obj.psobject.properties | Where-Object { $_.Name -notmatch '_Offset$' } | Sort-Object {
        $off = $Obj."$($_.Name)_Offset"
        if ($off -match '\[(\d+)-') { return [int]$matches[1] }
        return -1
    }
    
    # Calculate padding for alignment
    $maxOffLen = 11
    $maxPropLen = 24
    foreach ($p in $sortedProps) {
        $off = $Obj."$($p.Name)_Offset"
        if ($off -and $off.Length -gt $maxOffLen) { $maxOffLen = $off.Length }
        if ($p.Name.Length -gt $maxPropLen) { $maxPropLen = $p.Name.Length }
    }

    # Generate formatted lines (foreach directly emits to array, avoiding slow += operations)
    $lines = foreach ($p in $sortedProps) {
        $off = $Obj."$($p.Name)_Offset"
        if (-not $off) { $off = "[-]" }
        
        "{0} : {1} : {2}" -f $off.PadLeft($maxOffLen), $p.Name.PadRight($maxPropLen), $p.Value
    }
    
    return ($lines -join "`r`n")
}

# ===============================================================================================================================

function Get-DigitalProductIdDisplay {
    # Parse a blob and return formatted output.
    param([byte[]]$Blob, [switch]$VerifyHash)
    if (-not $Blob) { return "" }
    
    $obj = Get-DigitalProductId -Blob $Blob -VerifyHash:$VerifyHash
    if (-not $obj) { return "" }
    
    return Get-DigitalProductIdFormatted -Obj $obj
}

# ===============================================================================================================================
