<#
.SYNOPSIS
    Retrieves a Confirmation ID (CID) from the Microsoft VisualSupport API.

.DESCRIPTION
    Sends an Installation ID to Microsoft's VisualSupport API. Tries a local Bearer
    token from CidToken.txt first, otherwise fetches one from cidtoken.ntriver.org/token.json.
    Generates a DPoP JWT signed with an ephemeral ECDSA P-256 key and POSTs the request as JSON.

    Note: Microsoft doesn't tie the CID to the token, so random or shared tokens are fine.

    Requires Libs\Network.ps1 for HTTP communication (GET and POST).

.PARAMETER InstallationId
    The Installation ID string (50, 54, 59, or 63 digits).

.PARAMETER LogPath
    Optional folder path where this script saves VisualApi request/response payloads.

.PARAMETER PassThru
    Returns a structured PSObject with all request/response data.

.NOTES
    Compatible with PowerShell 2.0 and later. Requires .NET Framework 3.5 or later.
    Requires Libs\Network.ps1 for HTTP communication.
    Optionally reads BIN\CidToken.txt for a local Bearer token.
    Requires Libs\Common.ps1 for shared helper functions.

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
$networkPath = Join-Path $scriptDir "libs\Network.ps1"
if (Test-Path $networkPath) { . $networkPath }
$commonPath = Join-Path $scriptDir "libs\Common.ps1"
if (Test-Path $commonPath) { . $commonPath }

Add-Type -AssemblyName System.Web.Extensions | Out-Null
$jsonSerializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function New-ResponseObject {
    # Standard VisualApi response object.
    return @{
        Success        = $false
        CID            = $null
        ErrorCode      = $null
        ErrorMessage   = $null
        RequestFull    = ""
        ResponseFull   = ""
        Token          = $null
        RequestDetails = ""
    }
}

# ===============================================================================================================================

function Write-ApiLogs($LogPath, $Prefix, $Obj) {
    # Dump request/response payloads to disk.
    if (-not $LogPath) { return $null }

    try {
        if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
        if (-not (Test-Path $LogPath)) { return "Failed to create log folder" }

        $count = 0
        if ($Obj.RequestFull) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Request_BodyFull.json") -Value $Obj.RequestFull -Encoding UTF8; $count++ }
        if ($Obj.Token) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Token.txt") -Value $Obj.Token -Encoding UTF8; $count++ }
        if ($Obj.ResponseFull) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Response_BodyFull.json") -Value $Obj.ResponseFull -Encoding UTF8; $count++ }
        if ($Obj.RequestDetails) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Request_Details.txt") -Value $Obj.RequestDetails -Encoding UTF8; $count++ }

        if ($count -gt 0) { return "Saved to $LogPath" }
        return "No payloads to save"
    }
    catch {
        $exMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        return "Failed: $exMsg"
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
    $res = Invoke-GetTextRequest "https://cidtoken.ntriver.org/token.json" $null "" "json"
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
        $tokenJson = $jsonSerializer.DeserializeObject($ResponseFull)
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
        $iat = [int64]([DateTime]::UtcNow - [DateTime]'1970-01-01').TotalSeconds
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
        $json = $jsonSerializer.DeserializeObject($ResponseFull)

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
