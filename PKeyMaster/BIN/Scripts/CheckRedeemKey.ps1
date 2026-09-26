<#
.SYNOPSIS
    Checks the status of a Microsoft redeem key.

.DESCRIPTION
    Queries a Microsoft licensing endpoint to determine the status of a
    redeem key.
    This check does not redeem a key or make any change to its balance.

.PARAMETER RedeemKey
    Redeem key to check. The key is sent in uppercase.

.PARAMETER LogPath
    Optional folder path where this script saves the request and response payloads.

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
        RequestFull    = ""
        ResponseFull   = ""
        RequestDetails = ""
        Acid           = $null
        GroupId        = $null
        Pkpn           = $null
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
        $json = $jsonSerializer.DeserializeObject($responseFull)
        if (-not $json) {
            $out.Status = "Failed: JSON parse returned null"
            return $out
        }

        $result = [string]$json["Result"]
        $pkpn = $json["Pkpn"]
        $acid = $json["Acid"]
        $groupId = $json["GroupId"]

        $hasPkpn = ($null -ne $pkpn) -and (([string]$pkpn).Trim() -ne "") -and (([string]$pkpn).Trim() -ne "null")

        if ($hasPkpn) { $out.Pkpn = [string]$pkpn }
        if ($acid -and ([string]$acid).Trim() -ne "null") { $out.Acid = [string]$acid }
        if ($null -ne $groupId) { $out.GroupId = $groupId }

        if ($result -eq "Valid") {
            $out.Status = "Key can be redeemed"
        }
        elseif ($result -eq "Used") {
            $out.Status = "Key already redeemed"
        }
        elseif ($result -eq "InvalidToken") {
            if ($hasPkpn) {
                $out.Status = "Scrapped redeem key"
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

$logStatus = Write-ApiLogs $LogPath "CheckRedeemKey" $res

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

$f = "{0,-18}: {1}"
Write-Output ""
Write-Output ($f -f "Redeem Key", $cleanKey)

if ($res.Status -eq "Key can be redeemed") {
    Write-Color ($f -f "Status", $res.Status) "BgGreen"
}
else {
    Write-Color ($f -f "Status", $res.Status) "BgRed"
}
if ($res.Pkpn) {
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
    }
}

# ===============================================================================================================================
