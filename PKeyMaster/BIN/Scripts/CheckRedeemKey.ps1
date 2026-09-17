<#
.SYNOPSIS
    Checks whether a Microsoft redeem key is valid.

.DESCRIPTION
    Sends a redeem key to Microsoft's signup validation endpoint and displays
    its status, description, and allowed regions.
    This check does not redeem a key or make any change to its balance.

.PARAMETER RedeemKey
    Redeem key to check. The key is sent in uppercase.

.PARAMETER LogPath
    Optional folder path where this script saves redeem-key request and response payloads.

.PARAMETER PassThru
    Returns a structured PSObject for the submitted redeem key.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Network.ps1 for HTTP communication.
    Requires Libs\Common.ps1 for shared helper functions.

.EXAMPLE
    .\CheckRedeemKey.ps1 -RedeemKey "XXXXN-XXXXX-XXXXX-XXXXX-XXXXX"
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
    # Standard redeem-key validation response object.
    return @{
        Status         = "Failed"
        Description    = $null
        AllowedRegions = $null
        ErrorCode      = $null
        ErrorMessage   = $null
        RequestFull    = ""
        ResponseFull   = ""
        RequestDetails = ""
    }
}

# ===============================================================================================================================

function Write-ApiLogs($LogPath, $Prefix, $Obj) {
    # Dump request/response JSON to disk.
    if (-not $LogPath) { return $null }

    try {
        if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
        if (-not (Test-Path $LogPath)) { return "Failed to create log folder" }

        $count = 0
        if ($Obj.RequestFull) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Request_BodyFull.json") -Value $Obj.RequestFull -Encoding UTF8; $count++ }
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

function Invoke-RedeemKeyRequest($Key) {
    # Send a redeem key to the Microsoft signup validation service.
    $out = New-ResponseObject

    $body = @"
{"keys":["$Key"]}
"@

    $url = "https://signup.microsoft.com/api/signupservice/validatePrepaidKeys?culture=en-us&api-version=1"
    $contentType = "application/json; charset=utf-8"
    $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    $contentLength = [Text.Encoding]::UTF8.GetByteCount($body)
    $uri = New-Object System.Uri($url)
    $out.RequestFull = $body
    $out.RequestDetails = @"
POST $url HTTP/1.1
Host: $($uri.Host)
Connection: close
Content-Type: $contentType
User-Agent: $userAgent
Content-Length: $contentLength

Body:
$body
"@

    $res = Invoke-PostTextRequest $url $body $null $contentType $userAgent "json"
    $responseFull = $res.Body.Trim()
    $msg = $res.Error.Trim()

    if (-not $responseFull) {
        $out.ErrorMessage = if ($msg) { "$msg" } else { "No server response" }
        return $out
    }

    $out.ResponseFull = $responseFull
    if (-not (Test-Json $responseFull)) {
        $out.ErrorMessage = if ($msg) { "$msg" } else { "Unrecognized response format from server" }
        return $out
    }

    try {
        $json = $jsonSerializer.DeserializeObject($responseFull)
        $validationResult = $json["prepaidKeysValidationResult"]
        $descriptionResult = $json["prepaidKeysDescriptionResult"]
        if ($descriptionResult) {
            $out.Description = (($descriptionResult["description"] -replace '<[^>]+>', ' ') -replace '\s+', ' ').Trim()
        }

        $allowedRegions = $json["allowedRegions"]
        if ($allowedRegions) {
            $regionNames = @()
            foreach ($region in $allowedRegions.Values) {
                if ($region) { $regionNames += [string]$region }
            }
            $out.AllowedRegions = $regionNames -join ", "
        }

        $status = if ($validationResult) { @($validationResult["tokenStatus"])[0] } else { $null }
        if ($status) {
            $out.ErrorCode = $status["statusCode"]
            $out.Status = switch ($out.ErrorCode) {
                0 { "Key can be redeemed" }
                5 { "Key already redeemed" }
                7 { "Invalid key format" }
                1 { "Not a redeem key (Xbox not checked)" }
                6 { "Scrapped redeem key" }
                default { "Unknown status" }
            }
            if ($out.ErrorCode -ne 0) {
                $out.ErrorMessage = $status["tokenValidationMessage"]
                if (-not $out.ErrorMessage) { $out.ErrorMessage = "Token validation message not found in response" }
            }
            return $out
        }

        $out.ErrorCode = $json["responseCode"]
        $out.ErrorMessage = $json["message"]
        if (-not $out.ErrorMessage) { $out.ErrorMessage = "Token status not found in response" }
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

$cleanKey = $RedeemKey.Trim().ToUpper()
$res = $null
if (-not (Get-Command Invoke-PostTextRequest -ErrorAction SilentlyContinue)) {
    $res = New-ResponseObject
    $res.ErrorMessage = "Network module not loaded"
}
else {
    $res = Invoke-RedeemKeyRequest $cleanKey
}

if ($null -eq $res.ErrorCode) { $res.ErrorCode = "N/A" }
if (-not $res.ErrorMessage) { $res.ErrorMessage = "N/A" }
$logStatus = Write-ApiLogs $LogPath "CheckRedeemKey" $res

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

$f = "{0,-18}: {1}"
Write-Output ""
Write-Output ($f -f "Redeem Key", $cleanKey)

if ($res.ErrorCode -eq 0) {
    Write-Color ($f -f "Status", $res.Status) "BgGreen"
    if ($res.Description) { Write-Output ($f -f "Description", $res.Description) }
    if ($res.AllowedRegions) { Write-Output ($f -f "Allowed Regions", $res.AllowedRegions) }
}
else {
    Write-Color ($f -f "Status", $res.Status) "BgRed"
    Write-Color ($f -f "Error Code", $res.ErrorCode) "BgRed"
    Write-Color ($f -f "Error Msg", $res.ErrorMessage) "BgRed"
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
        Description    = $res.Description
        AllowedRegions = $res.AllowedRegions
        LogPath        = $LogPath
        LogStatus      = $logStatus
        ErrorCode      = $res.ErrorCode
        ErrorDetail    = $res.ErrorMessage
        RequestFull    = $res.RequestFull
        ResponseFull   = $res.ResponseFull
        RequestDetails = $res.RequestDetails
    }
}

# ===============================================================================================================================
