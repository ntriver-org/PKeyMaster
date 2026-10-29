<#
.SYNOPSIS
    Checks the status of a Microsoft redeem key.

.DESCRIPTION
    Queries a Microsoft licensing endpoint to determine the status of a
    redeem key and resolves its associated product name.
    This check does not redeem a key or make any change to its balance.

.PARAMETER RedeemKey
    Redeem key to check. The key is sent in uppercase.

.PARAMETER LogPath
    Optional folder path where this script saves the request and response payloads.

.PARAMETER PassThru
    Returns a structured PSObject for the submitted redeem key.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Network.psm1 for HTTP communication.
    Requires Libs\Common.psm1 for shared helper functions.

.EXAMPLE
    .\RedeemStatus.ps1 -RedeemKey "XXXXN-XXXXX-XXXXX-XXXXX-XXXXX"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$RedeemKey,
    [string]$LogPath,
    [switch]$PassThru
)

# ===============================================================================================================================
# Initialization & dependencies
# ===============================================================================================================================

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "." }
Import-Module "$scriptDir\Libs\Common.psm1"
Import-Module "$scriptDir\Libs\Network.psm1"

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function New-ResponseObject {
    # Standard redeem-key validation response object.
    return @{
        Status         = "Failed"
        RequestFull    = ""
        ResponseFull   = ""
        RequestDetails = ""
        Acid           = $null
        GroupId        = $null
        Pkpn           = $null
        Product        = $null
    }
}

# ===============================================================================================================================
# Fetch Xbox/Store product name
# ===============================================================================================================================

# To resolve product names from Pkpn (Product Key Part Number), the script connects to:
# - Official Microsoft Store catalog (displaycatalog.mp.microsoft.com) for modern Store products and packages.
# - 3rd-party database (dbox.tools) for old Xbox 360 title IDs, as Microsoft no longer lists them in their store catalog.
#
# The script is connecting to a 3rd-party database (dbox.tools). Is it safe?
# Yes.
# - Only public Title IDs are queried.
# - Responses are parsed strictly as JSON to read the title for display; nothing is executed on your system.

function Invoke-ProductApi([string]$url, [string]$prefix) {
    $res = Invoke-GetTextRequest $url $null "" "" "json"

    if ($LogPath) {
        $uri = New-Object System.Uri($url)
        $logObj = @{
            RequestFull    = ""
            ResponseFull   = $res.Body
            RequestDetails = "GET $url HTTP/1.1`r`nConnection: Keep-Alive`r`nHost: $($uri.Host)`r`n"
        }
        Write-ApiLogs $LogPath $prefix $logObj | Out-Null
    }

    if ($res.Body) {
        try {
            return $global:JsonSerializer.DeserializeObject($res.Body)
        }
        catch {}
    }
    return $null
}

function Get-DBoxTitle([string]$id) {
    if ($id -eq "FFFE07D1") { return "Xbox LIVE" }
    $obj = Invoke-ProductApi "https://dbox.tools/api/title_ids/$id" "RedeemStatusProductName_DBox"
    if ($obj -and $obj.name) { return $obj.name }
    return $null
}

function Get-StoreTitle([string]$id) {
    $obj = Invoke-ProductApi "https://displaycatalog.mp.microsoft.com/v7.0/products/${id}?market=US&languages=en-us" "RedeemStatusProductName_Store"
    if ($obj -and $obj.Product) {
        return $obj.Product.LocalizedProperties[0].ProductTitle
    }
    return $null
}

function Get-StoreTitleByGuid([string]$guid) {
    $obj = Invoke-ProductApi "https://displaycatalog.mp.microsoft.com/v7.0/products/lookup?alternateId=LegacyXboxProductId&value=${guid}&market=US&languages=en-us" "RedeemStatusProductName_Store"
    if ($obj -and $obj.Products -and $obj.Products.Count -gt 0) {
        return $obj.Products[0].LocalizedProperties[0].ProductTitle
    }
    return $null
}

function Get-StoreTitleByToken([string]$token) {
    $obj = Invoke-ProductApi "https://displaycatalog.mp.microsoft.com/v7.0/products/lookup?alternateId=LegacyTokenIdentifier&value=${token}&market=US&languages=en-us" "RedeemStatusProductName_Store"
    if ($obj -and $obj.Products -and $obj.Products.Count -gt 0) {
        return $obj.Products[0].LocalizedProperties[0].ProductTitle
    }
    return $null
}

function Resolve-ProductName([string]$pkpn) {
    if (-not $pkpn -or -not $pkpn.Trim()) { return $null }

    # 1. Modern Store ID (e.g. 9NT30FM6PVWS/0010)
    if ($pkpn -match '^([A-Z0-9]{12})(?:/[A-Z0-9]{4})?$') {
        return (Get-StoreTitle $matches[1].ToUpper())
    }

    # 2. Product GUID
    if ($pkpn -match '^[0-9A-F-]{36}$') {
        # 2a. Modern Store DLC / Package GUID
        $title = Get-StoreTitleByGuid $pkpn
        if ($title) { return $title }

        # 2b. Legacy Title ID GUID (ends with 8-character Title ID)
        return (Get-DBoxTitle $pkpn.Substring($pkpn.Length - 8).ToUpper())
    }

    # 3. Legacy 64-bit Decimal (High 32 bits = Title ID)
    if ($pkpn -match '^\d+$') {
        try {
            $hex = ([UInt64]$pkpn).ToString("X16")
            return (Get-DBoxTitle $hex.Substring(0, 8))
        }
        catch { }
    }

    # 4. Legacy Token Identifier (e.g. X21-75511, X23-97249)
    if ($pkpn -match '^[^-]+-[^-]+$') {
        $title = Get-StoreTitleByToken $pkpn
        if ($title) { return $title }
    }

    # 5. Retail SKU (e.g. UGP-00031)
    if ($pkpn -match '^UGP-') { return "Xbox Game Pass Ultimate" }
    if ($pkpn -match '^GPS-') { return "Xbox Game Pass Premium" } # Formerly Game Pass Standard
    if ($pkpn -match '^XGP-') { return "Xbox Game Pass for Console" }
    if ($pkpn -match '^PGP-') { return "PC Game Pass" }
    if ($pkpn -match '^GLD-') { return "Xbox Live Gold" }
    if ($pkpn -match '^MCT-') { return "Minecraft Realms Plus" }
    if ($pkpn -match '^LPI-') { return "Minecraft Marketplace Pass" }

    return $null
}

# ===============================================================================================================================

function Resolve-PKeyConfigProductName([string]$ActivationId, [string]$PartNumber) {
    if (-not $global:PKeyConfigsMap) { return $null }
    if (-not $ActivationId -and -not $PartNumber) { return $null }

    $baseConfigsDir = Join-Path (Split-Path -Parent $scriptDir) "PKeyConfigs"

    foreach ($entry in $global:PKeyConfigsMap) {
        $configPath = Join-Path $baseConfigsDir $entry.Path.TrimStart('\')
        if (-not (Test-Path -LiteralPath $configPath)) { continue }

        $info = if ($PartNumber) {
            Get-PKeyConfigInfo -FilePath $configPath -PartNumber $PartNumber
        }
        else {
            Get-PKeyConfigInfo -FilePath $configPath -ActivationId $ActivationId
        }

        if ($info -and $info.Description) {
            return $info.Description
        }
    }

    return $null
}

# ===============================================================================================================================

function Invoke-RedeemKeyRequest($Key) {
    # Query the Microsoft licensing endpoint to check the status of a redeem key.
    $out = New-ResponseObject

    $correlationId = [System.Guid]::NewGuid().ToString().ToUpper()
    $url = "https://licensing.m365.svc.cloud.microsoft/olsc/olsconfig.svc/pin/v3/${Key}?id=$correlationId"
    $userAgent = "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Excel 16.0.20520; Pro)"
    $contentType = "application/json"
    $uri = New-Object System.Uri($url)
    $out.RequestFull = ""
    $out.RequestDetails = @"
GET $url HTTP/1.1
Connection: Keep-Alive
Content-Type: $contentType
User-Agent: $userAgent
Host: $($uri.Host)
"@

    $res = Invoke-GetTextRequest $url $null $contentType $userAgent "json"
    $responseFull = $res.Body.Trim()
    $msg = $res.Error.Trim()

    if (-not $responseFull) {
        $out.Status = if ($msg) { "Failed: $msg" } else { "Failed: No server response" }
        return $out
    }

    $out.ResponseFull = $responseFull
    if (-not (Test-Json $responseFull)) {
        $out.Status = if ($msg) { "Failed: $msg" } else { "Failed: Unrecognized response format from server" }
        return $out
    }

    try {
        $json = $global:JsonSerializer.DeserializeObject($responseFull)
        if (-not $json) {
            $out.Status = "Failed: JSON parse returned null"
            return $out
        }

        $result = [string]$json["Result"]
        $pkpn = $json["Pkpn"]
        $acid = $json["Acid"]
        $groupId = $json["GroupId"]

        $hasPkpn = ($null -ne $pkpn) -and (([string]$pkpn).Trim() -ne "") -and (([string]$pkpn).Trim() -ne "null")

        if ($hasPkpn) {
            $out.Pkpn = [string]$pkpn
            $out.Product = Resolve-ProductName $out.Pkpn
        }
        if ($acid -and ([string]$acid).Trim() -ne "null") { $out.Acid = [string]$acid }
        if ($null -ne $groupId) { $out.GroupId = $groupId }

        if (-not $out.Product -and $out.Acid -and ($out.Acid -notmatch '99999999-9999-9999-9999-999999999999')) {
            $out.Product = Resolve-PKeyConfigProductName -ActivationId $out.Acid
        }

        if (-not $out.Product -and $out.Pkpn -and ($out.Pkpn -match '^[^-]+-[^-]+$')) {
            $out.Product = Resolve-PKeyConfigProductName -PartNumber $out.Pkpn
        }

        if ($result -eq "Valid") {
            $out.Status = "Valid"
        }
        elseif ($result -eq "Used") {
            $out.Status = "Already redeemed"
        }
        elseif ($result -eq "InvalidToken") {
            if ($hasPkpn) {
                $out.Status = "Expired or already redeemed"
            }
            else {
                $out.Status = "Not a redeem key"
            }
        }
        elseif ($result -eq "InvalidFormat") {
            $out.Status = "Invalid key format"
        }
        else {
            $out.Status = if ($result) { "Unknown status ($result)" } else { "Unknown status" }
        }

        return $out
    }
    catch {
        $exMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        $out.Status = "Failed: $exMsg"
        return $out
    }
}

# ===============================================================================================================================
# Main execution
# ===============================================================================================================================

$cleanKey = $RedeemKey.Trim().ToUpper()
$res = $null
if (-not (Get-Command Invoke-GetTextRequest -ErrorAction SilentlyContinue)) {
    $res = New-ResponseObject
    $res.Status = "Failed: Network module not loaded"
}
else {
    $res = Invoke-RedeemKeyRequest $cleanKey
}

$logStatus = Write-ApiLogs $LogPath "RedeemStatus" $res

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

$f = "{0,-18}: {1}"
Write-Output ""
Write-Output ($f -f "Redeem Key", $cleanKey)

if ($res.Status -eq "Valid") {
    Write-Color ($f -f "Status", $res.Status) "BgGreen"
}
else {
    Write-Color ($f -f "Status", $res.Status) "BgRed"
}
if ($res.Pkpn) {
    if ($res.Product) {
        Write-Color ($f -f "Product", $res.Product) "BgGreen"
    }
    Write-Output ($f -f "Acid", $res.Acid)
    Write-Output ($f -f "GroupId", $res.GroupId)
    Write-Output ($f -f "Pkpn", $res.Pkpn)
}
if ($logStatus) {
    if ($logStatus -match '^Failed') {
        Write-Color ($f -f "Log Status", $logStatus) "BgRed"
    }
    else {
        Write-Output ($f -f "Log Status", $logStatus)
    }
}
Write-Output ""

# ===============================================================================================================================
# Object return (PassThru)
# ===============================================================================================================================

if ($PassThru) {
    New-Object PSObject -Property @{
        RedeemKey      = $cleanKey
        Status         = $res.Status
        LogPath        = $LogPath
        LogStatus      = $logStatus
        RequestFull    = $res.RequestFull
        ResponseFull   = $res.ResponseFull
        RequestDetails = $res.RequestDetails
        Acid           = $res.Acid
        GroupId        = $res.GroupId
        Pkpn           = $res.Pkpn
        Product        = $res.Product
    }
}

# ===============================================================================================================================
