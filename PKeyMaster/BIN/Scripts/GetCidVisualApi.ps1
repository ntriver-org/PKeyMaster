<#
.SYNOPSIS
    Retrieves a Confirmation ID (CID) from the Microsoft VisualSupport API.

.DESCRIPTION
    Sends an Installation ID to Microsoft's VisualSupport API. Tries a local Bearer
    token from CidToken.txt first, otherwise fetches one from cidtoken.ntriver.org/token.json.
    Generates a DPoP JWT signed with an ephemeral ECDSA P-256 key and POSTs the request as JSON.

    Note: Microsoft doesn't tie the CID to the token, so random or shared tokens are fine.

    Requires Libs\Network.psm1 for HTTP communication (GET and POST).

.PARAMETER InstallationId
    The Installation ID string (50, 54, 59, or 63 digits).

.PARAMETER LogPath
    Optional folder path where this script saves VisualApi request/response payloads.

.PARAMETER PassThru
    Returns a structured PSObject with all request/response data.

.NOTES
    Compatible with PowerShell 2.0 and later. Requires .NET Framework 3.5 or later.
    Requires Libs\Network.psm1 for HTTP communication.
    Optionally reads BIN\CidToken.txt for a local Bearer token.
    Requires Libs\Common.psm1 for shared helper functions.

.EXAMPLE
    .\GetCidVisualApi.ps1 -InstallationId "123456789012345678901234567890123456789012345678901234"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$InstallationId,
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
    # Standard VisualApi response object.
    return @{
        Success        = $false
        CID            = $null
        ProductName    = $null
        ProductId      = $null
        ErrorCode      = $null
        ErrorMessage   = $null
        RequestFull    = ""
        ResponseFull   = ""
        Token          = $null
        RequestDetails = ""
    }
}

# ===============================================================================================================================

function Get-AccessToken {
    # Get a Bearer token - local file first, then shared token server.
    $out = @{
        Success = $false
        Token   = $null
        Error   = $null
        Raw     = $null
    }

    function Test-AccessTokenFormat([string]$Token) {
        if ($Token.Length -gt 8192) { return $false }
        if ($Token -match '^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){2}$') { return $true }

        if ($Token -match '^[A-Za-z0-9+/]+={0,2}$' -and ($Token.Length % 4 -eq 0)) { return $true }

        return $false
    }

    $tokenPath = Join-Path (Split-Path -Parent $scriptDir) "CidToken.txt"
    if (Test-Path $tokenPath) {
        $localToken = ((Get-Content $tokenPath) -join "").Trim()
        if ($localToken.Length -gt 0) {
            $out.Raw = $localToken
            if (-not (Test-AccessTokenFormat $localToken)) {
                $out.Error = "Token field is not a valid access token format"
                return $out
            }

            $out.Success = $true
            $out.Token = $localToken
            return $out
        }
    }

    # The script is connecting to https://cidtoken.ntriver.org/token.json to get a shared token. Is it safe?
    # Yes.
    # - The script does not execute the token on your system, it only sends it as a header value to Microsoft's server to get the CID.
    # - The response is parsed as JSON only, and the token format is validated against the expected JWT character set and structure, so it cannot alter HTTP header syntax or inject additional headers.
    # - Microsoft does not link the IID or the retrieved CID to the token's account, so a shared token works fine.
    $res = Invoke-GetTextRequest "https://cidtoken.ntriver.org/token.json" $null "" "" "json"
    $ResponseFull = $res.Body.Trim()
    $msg = $res.Error.Trim()
    if (-not $ResponseFull) {
        $out.Error = if ($msg) { "$msg" } else { "No token server response" }
        return $out
    }

    $out.Raw = $ResponseFull

    if (-not (Test-Json $ResponseFull)) {
        $out.Error = if ($msg) { "$msg" } else { "Unrecognized response format from token server" }
        return $out
    }

    try {
        $tokenJson = $global:JsonSerializer.DeserializeObject($ResponseFull)
        $token = $tokenJson["token"]
        if ($token) {
            if (-not (Test-AccessTokenFormat $token)) {
                $out.Error = "Token field is not a valid access token format"
                return $out
            }

            $out.Success = $true
            $out.Token = $token
            return $out
        }
    }
    catch { }

    $out.Error = if ($msg) { "$msg" } else { "Token field not found in response" }
    return $out
}

# ===============================================================================================================================

function ConvertTo-Base64Url($Bytes) {
    # URL-safe Base64: no padding, - instead of +, _ instead of /.
    return [Convert]::ToBase64String($Bytes).TrimEnd('=') -replace '\+', '-' -replace '/', '_'
}

# ===============================================================================================================================

function Get-NetworkUtcTime {
    # Fetch UTC time from Microsoft NCSI to handle out-of-sync system clocks.
    # Falls back to local clock if the network request fails.
    # Microsoft DPoP tolerance is [-10s, +5s]; +3s gives slow connections extra time before the token expires.
    $resp = $null
    try {
        $req = [System.Net.HttpWebRequest]::Create("http://www.msftconnecttest.com/connecttest.txt")
        $req.Method = "HEAD"
        $req.Timeout = 3000
        $req.KeepAlive = $false
        $req.Proxy = $null

        $resp = $req.GetResponse()
        $dateStr = $resp.Headers["Date"]
        if ($dateStr) {
            $serverUtc = [DateTime]::Parse($dateStr).ToUniversalTime().AddSeconds(3)
            return [int64]($serverUtc - [DateTime]'1970-01-01').TotalSeconds
        }
    }
    catch { }
    finally {
        if ($resp) { $resp.Close() }
    }

    return [int64]([DateTime]::UtcNow.AddSeconds(3) - [DateTime]'1970-01-01').TotalSeconds
}

# ===============================================================================================================================

function New-VisualApiDpopToken($Url, $Method) {
    # Build a DPoP JWT with ephemeral ECDSA P-256 key.

    Add-Type -AssemblyName System.Core | Out-Null
    $ecdsa = New-Object System.Security.Cryptography.ECDsaCng(256)
    
    try {
        # Export the public key components (X and Y coordinates) from the ECC key blob
        $blob = $ecdsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
        $x = New-Object byte[] 32
        $y = New-Object byte[] 32
        [Array]::Copy($blob, 8, $x, 0, 32)
        [Array]::Copy($blob, 40, $y, 0, 32)

        # Build the JWT header (with embedded JWK) and payload
        $jwk = '{"kty":"EC","crv":"P-256","x":"' + (ConvertTo-Base64Url $x) + '","y":"' + (ConvertTo-Base64Url $y) + '"}'
        $hdr = '{"alg":"ES256","typ":"dpop+jwt","jwk":' + $jwk + '}'
        $iat = Get-NetworkUtcTime
        $pld = '{"htu":"' + $Url + '","htm":"' + $Method + '","jti":"' + ([Guid]::NewGuid().ToString()) + '","iat":' + $iat + '}'

        # Sign the header.payload with ECDSA
        $unsignedJwt = (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($hdr))) + '.' + (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($pld)))
        $sig = $ecdsa.SignData([Text.Encoding]::UTF8.GetBytes($unsignedJwt))

        return $unsignedJwt + '.' + (ConvertTo-Base64Url $sig)
    }
    finally {
        $ecdsa.Clear()
    }
}

# ===============================================================================================================================

function Get-ProductNameFromPid($InstallationId, $ProductId) {
    if (-not $InstallationId -or -not $ProductId) { return $null }

    # Only 63-digit IIDs correspond to PKey2009 keys
    $cleanIid = $InstallationId -replace '\D', ''
    if ($cleanIid.Length -ne 63) { return $null }

    # Product ID for PKey2009 format: XXXXX-XXXXX-XXXXX-XXXXX
    if ($ProductId -notmatch '^\d{5}-\d{5}-\d{5}-') { return $null }

    $parts = $ProductId -split '-'
    if ($parts.Count -lt 3) { return $null }

    $groupId = ([int]$parts[0] * 10) + [int]($parts[1].Substring(0, 1))
    $serialMid = [int]($parts[1].Substring(1, 4))
    $serialLow = [int]$parts[2]
    $keyId = ([long]$serialMid * 100000) + [long]$serialLow

    if (-not $global:PKeyConfigsMap) { return $null }

    $algoKey = "PKey2009"
    $gStr = [string]$groupId
    $pkeyConfigsDir = Join-Path (Split-Path -Parent $scriptDir) "PKeyConfigs"
    $matchedConfigPath = $null

    $configsMap = @($global:PKeyConfigsMap | Where-Object { $_.Profile -notmatch "custom" })
    foreach ($entry in $configsMap) {
        if ($entry.Algorithms -and $entry.Algorithms.ContainsKey($algoKey)) {
            $algoGroups = $entry.Algorithms[$algoKey]
            if ($algoGroups -and $algoGroups.ContainsKey($gStr)) {
                foreach ($range in $algoGroups[$gStr]) {
                    if ($keyId -ge $range[0] -and $keyId -le $range[1]) {
                        $matchedConfigPath = Join-Path $pkeyConfigsDir $entry.Path.TrimStart('\')
                        break
                    }
                }
            }
        }
        if ($matchedConfigPath) { break }
    }

    if ($matchedConfigPath -and (Test-Path $matchedConfigPath)) {
        $info = Get-PKeyConfigInfo -FilePath $matchedConfigPath -GroupId $groupId -KeyId $keyId
        if ($info -and $info.Description -and $info.Description -ne "CustomMade") {
            return $info.Description
        }
    }

    return $null
}

# ===============================================================================================================================
# Core API function
# ===============================================================================================================================

function Invoke-VisualApiRequest($InstallationId) {
    # Send IID to VisualSupport API, pull CID from JSON.
    $out = New-ResponseObject

    $cleanIID = $InstallationId -replace '\D', ''
    if ($cleanIID.Length -ne 50 -and $cleanIID.Length -ne 54 -and $cleanIID.Length -ne 59 -and $cleanIID.Length -ne 63) {
        $out.ErrorMessage = "Invalid IID length ($($cleanIID.Length)). Must be 50, 54, 59, or 63 digits."
        return $out
    }

    $url = "https://visualsupport.microsoft.com/api/productActivation/validateIID"
    $numDigits = [int]($cleanIID.Length / 9)
    $body = '{"IID":"' + $cleanIID + '","ProductType":"windows","productGroup":"Windows","productName":"Windows 11","numberOfDigits":' + $numDigits + ',"Country":"USA","Region":"NOAM","InstalledDevices":1,"OverrideStatusCode":"MUL","InitialReasonCode":"45164"}'
    $out.RequestFull = $body

    # Fetch a live Bearer access token
    $tokenResult = Get-AccessToken
    $out.Token = $tokenResult.Raw
    if (-not $tokenResult.Success) {
        $out.ErrorMessage = "Failed to obtain access token: $($tokenResult.Error)"
        return $out
    }

    # Generate DPoP token and build request headers
    $dpop = New-VisualApiDpopToken "/api/productActivation/validateIID" "POST"
    $hdrs = @{
        Authorization  = "Bearer $($tokenResult.Token)"
        DPoP           = $dpop
        "x-session-id" = ("app_" + [Guid]::NewGuid().ToString("N"))
    }
    $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    $contentType = "application/json; charset=utf-8"
    $contentLength = [Text.Encoding]::UTF8.GetByteCount($body)
    $uri = New-Object System.Uri($url)
    $out.RequestDetails = @"
POST $url HTTP/1.1
Host: $($uri.Host)
Connection: close
Content-Type: $contentType
User-Agent: $userAgent
Authorization: $($hdrs.Authorization)
DPoP: $($hdrs.DPoP)
x-session-id: $($hdrs['x-session-id'])
Content-Length: $contentLength

Body:
$body
"@
    
    $res = Invoke-PostTextRequest $url $body $hdrs $contentType $userAgent "json"
    $ResponseFull = $res.Body.Trim()
    $msg = $res.Error.Trim()

    if (-not $ResponseFull) {
        $out.ErrorMessage = if ($msg) { "$msg" } else { "No server response" }
        return $out
    }

    $out.ResponseFull = $ResponseFull

    if (-not (Test-Json $ResponseFull)) {
        $out.ErrorMessage = if ($msg) { "$msg" } else { "Unrecognized response format from server" }
        return $out
    }
    
    try {
        # Parse the JSON response
        $json = $global:JsonSerializer.DeserializeObject($ResponseFull)

        $productName = [string]$json["productName"]
        if ($productName -and $productName.Trim() -and $productName.Trim() -ne "unknown") {
            $out.ProductName = $productName.Trim()
        }

        $productId = [string]$json["pid"]
        if ($productId -and $productId.Trim()) {
            $out.ProductId = $productId.Trim()
        }

        # Resolve exact Product Name (Description) from PKeyConfig for PKey2009 (63-digit IID)
        if ($out.ProductId) {
            $resolvedDesc = Get-ProductNameFromPid $InstallationId $out.ProductId
            if ($resolvedDesc) {
                $out.ProductName = $resolvedDesc
            }
        }

        $cid = $json["cid"]
        if ($cid) {
            $out.Success = $true
            $out.CID = $cid
            return $out
        }
        
        # Check for structured error response
        $reasonCode = $json["reasonCode"]
        $message = $json["message"]
        if ($reasonCode -or $message) {
            if ($reasonCode) { $out.ErrorCode = $reasonCode }
            if ($message) { $out.ErrorMessage = $message } else { $out.ErrorMessage = "Error $reasonCode" }
            return $out
        }

        $out.ErrorMessage = "CID or ErrorCode node not found in response"
        return $out
    }
    catch {
        $exMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        $out.ErrorMessage = "JSON parse error: $exMsg"
        return $out
    }
}

# ===============================================================================================================================
# Main execution
# ===============================================================================================================================

if (-not (Get-Command Invoke-PostTextRequest -ErrorAction SilentlyContinue)) {
    $res = New-ResponseObject
    $res.ErrorMessage = "Network module not loaded"
}
else {
    $res = Invoke-VisualApiRequest $InstallationId
}

if (-not $res.ErrorCode) { $res.ErrorCode = "N/A" }
if (-not $res.ErrorMessage) { $res.ErrorMessage = "N/A" }
$logStatus = Write-ApiLogs $LogPath "CID_VisualApi" $res

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

$f = "{0,-18}: {1}"
Write-Output ""
Write-Output ($f -f "API Source", "VisualApi")
Write-Output ($f -f "Installation ID", $InstallationId)
if ($res.ProductName) {
    Write-Output ($f -f "Product Name", $res.ProductName)
}
if ($res.ProductId) {
    Write-Output ($f -f "Product ID", $res.ProductId)
}

if ($res.Success) {
    Write-Color ($f -f "Confirmation ID", $res.CID) "BgGreen"
}
else {
    Write-Color ($f -f "Confirmation ID", "Failed") "BgRed"
    Write-Color ($f -f "Error Code", $res.ErrorCode) "BgRed"
    Write-Color ($f -f "Error Detail", $res.ErrorMessage) "BgRed"
}
if ($logStatus) {
    if ($logStatus -match '^Failed') {
        Write-Color ($f -f "Log Status", $logStatus) "BgRed"
    }
    else {
        Write-Output ($f -f "Log Status", $logStatus)
    }
}

# ===============================================================================================================================
# Object return (PassThru)
# ===============================================================================================================================

if ($PassThru) {
    New-Object PSObject -Property @{
        InstallationId = $InstallationId
        Result         = if ($res.Success) { "SUCCESS" } else { "FAILED" }
        CID            = $res.CID
        ProductName    = $res.ProductName
        ProductId      = $res.ProductId
        LogPath        = $LogPath
        LogStatus      = $logStatus
        ErrorCode      = $res.ErrorCode
        ErrorDetail    = $res.ErrorMessage
        RequestFull    = $res.RequestFull
        ResponseFull   = $res.ResponseFull
        Token          = $res.Token
        RequestDetails = $res.RequestDetails
    }
}

# ===============================================================================================================================
