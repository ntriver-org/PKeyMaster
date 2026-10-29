<#
.SYNOPSIS
    Retrieves a Confirmation ID (CID) from the Microsoft BatchActivation SOAP API.

.DESCRIPTION
    Sends an Installation ID and Advanced PID to Microsoft's BatchActivation web
    service and retrieves the Confirmation ID. Uses an HMAC-SHA256 signed SOAP
    envelope sent via HTTP POST.

.PARAMETER InstallationId
    The Installation ID string (54 or 63 digits).

.PARAMETER AdvancedPid
    The Advanced PID string used in the activation request.
    Defaults to a generic Windows PID if not specified.

.PARAMETER LogPath
    Optional folder path where this script saves BatchApi request/response payloads.

.PARAMETER PassThru
    Returns a structured PSObject with all request/response data.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Network.psm1 for HTTP communication.
    Requires Libs\Common.psm1 for shared helper functions.

.EXAMPLE
    .\GetCidBatchApi.ps1 -InstallationId "123456789012345678901234567890123456789012345678901234"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$InstallationId,
    [string]$AdvancedPid = '00000-00138-207-109016-00-1033-26100.0000-0922026',
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

function Get-BatchActivationHashKey {
    # HMAC-SHA256 key for BatchActivation.
    return [byte[]](
        254, 49, 152, 117, 251, 72, 132, 134, 156, 243, 241, 206, 153, 168, 144, 100,
        171, 87, 31, 202, 71, 4, 80, 88, 48, 36, 226, 20, 98, 135, 121, 160
    )
}

# ===============================================================================================================================

function New-ResponseObject {
    # Standard BatchActivation response object.
    return @{
        Success        = $false
        CID            = $null
        ErrorCode      = $null
        ErrorMessage   = $null
        RequestInner   = ""
        ResponseInner  = ""
        RequestFull    = ""
        ResponseFull   = ""
        RequestDetails = ""
    }
}

# ===============================================================================================================================

function Submit-BatchActivationRequest([string]$RequestFull, [string]$RequestInner) {
    # Send SOAP and parse the response.
    $out = New-ResponseObject
    $out.RequestInner = $RequestInner
    $out.RequestFull = $RequestFull

    $url = "https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx"
    $action = "http://www.microsoft.com/BatchActivationService/BatchActivate"
    $userAgent = "Mozilla/4.0 (compatible; MSIE 6.0; MS Web Services Client Protocol 2.0.50727.5420)"
    $contentType = "text/xml; charset=utf-8"
    $headers = @{ SOAPAction = $action }
    $out.RequestDetails = Format-RequestDetails "POST" $url $RequestFull $headers $contentType $userAgent

    $res = Invoke-PostTextRequest $url $RequestFull $headers $contentType $userAgent "xml"

    $ResponseFull = $res.Body.Trim()
    $msg = $res.Error.Trim()

    if (-not $ResponseFull) {
        $out.ErrorMessage = if ($msg) { "$msg" } else { "No server response" }
        return $out
    }

    $out.ResponseFull = $ResponseFull

    if (-not (Test-Xml $ResponseFull)) {
        $out.ErrorMessage = if ($msg) { "$msg" } else { "Unrecognized response format from server" }
        return $out
    }

    try {
        [xml]$doc = $ResponseFull
        
        $responseXmlNode = $doc.SelectSingleNode("//*[local-name()='ResponseXml']")
        if ($responseXmlNode) {
            $inner = $responseXmlNode.InnerText
            $out.ResponseInner = $inner
            [xml]$innerDoc = $inner
            $cidNode = $innerDoc.SelectSingleNode("//*[local-name()='CID']")
            $eNode = $innerDoc.SelectSingleNode("//*[local-name()='ErrorCode']")

            if ($eNode) {
                $errCode = $eNode.InnerText
                $out.ErrorCode = $errCode
                $out.ErrorMessage = switch ($errCode) {
                    '0x67' { 'The product key has been blocked' }
                    '0xD5' { 'ROT activation override limit reached' }
                    '0x68' { 'Unsupported or generated product key' }
                    '0x71' { 'The key has exceeded its activation limit' }
                    '0x7F' { 'The MAK key has exceeded its activation limit' }
                    '0xD6' { 'DMAK activation override limit reached' }
                    '0x86' { 'The key is valid but its type is unsupported' }
                    '0x90' { 'Invalid Installation ID' }
                    '0xC004C017' { 'The product key has been blocked for this geographic location' }
                    '0x80131600' { 'Invalid AdvancedPid or a server error' }
                    default { "The remote server reported an error ($errCode)" }
                }
                return $out
            }
            elseif ($cidNode) {
                $out.Success = $true
                $out.CID = $cidNode.InnerText
                return $out
            }
            else {
                $out.ErrorMessage = "CID or ErrorCode node not found in response"
                return $out
            }
        }

        $out.ErrorMessage = "Unexpected SOAP response format"
        return $out
    }
    catch {
        $exMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        $out.ErrorMessage = "XML parse error: $exMsg"
        return $out
    }
}

# ===============================================================================================================================

function Invoke-BatchActivationRequest($InstallationId, $AdvancedPid) {
    # Build request, call BatchActivation, extract CID.
    $out = New-ResponseObject

    $cleanIID = $InstallationId -replace '\D', ''
    if ($cleanIID.Length -ne 54 -and $cleanIID.Length -ne 63) {
        $out.ErrorMessage = "Invalid IID length ($($cleanIID.Length)). Must be 54 or 63 digits."
        return $out
    }

    $requestInner = @"
<ActivationRequest xmlns="http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0">
  <VersionNumber>2.0</VersionNumber>
  <RequestType>1</RequestType>
  <Requests>
    <Request><PID>$AdvancedPid</PID><IID>$cleanIID</IID></Request>
  </Requests>
</ActivationRequest>
"@

    $xmlBytes = [System.Text.Encoding]::Unicode.GetBytes($requestInner)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = Get-BatchActivationHashKey
    $digest = [Convert]::ToBase64String($hmac.ComputeHash($xmlBytes))
    $req64 = [Convert]::ToBase64String($xmlBytes)

    $requestFull = @"
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <BatchActivate xmlns="http://www.microsoft.com/BatchActivationService">
      <request>
        <Digest>$digest</Digest>
        <RequestXml>$req64</RequestXml>
      </request>
    </BatchActivate>
  </soap:Body>
</soap:Envelope>
"@

    return Submit-BatchActivationRequest $requestFull $requestInner
}

# ===============================================================================================================================
# Main execution
# ===============================================================================================================================

if (-not (Get-Command Invoke-PostTextRequest -ErrorAction SilentlyContinue)) {
    $res = New-ResponseObject
    $res.ErrorMessage = "Network module not loaded"
}
else {
    $res = Invoke-BatchActivationRequest $InstallationId $AdvancedPid
}

if (-not $res.ErrorCode) { $res.ErrorCode = "N/A" }
if (-not $res.ErrorMessage) { $res.ErrorMessage = "N/A" }
$logStatus = Write-ApiLogs $LogPath "CID_BatchApi" $res

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

$f = "{0,-18}: {1}"
Write-Output ""
Write-Output ($f -f "API Source", "BatchApi")
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
        AdvancedPid    = $AdvancedPid
        Result         = if ($res.Success) { "SUCCESS" } else { "FAILED" }
        CID            = $res.CID
        LogPath        = $LogPath
        LogStatus      = $logStatus
        ErrorCode      = $res.ErrorCode
        ErrorDetail    = $res.ErrorMessage
        RequestInner   = $res.RequestInner
        ResponseInner  = $res.ResponseInner
        RequestFull    = $res.RequestFull
        ResponseFull   = $res.ResponseFull
        RequestDetails = $res.RequestDetails
    }
}

# ===============================================================================================================================
