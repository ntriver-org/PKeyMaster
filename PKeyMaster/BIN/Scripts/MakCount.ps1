<#
.SYNOPSIS
    Queries the remaining activation count for a MAK (Multiple Activation Key).

.DESCRIPTION
    Sends the Advanced PID to Microsoft's BatchActivation SOAP service with
    RequestType 2 (MAK count query). Signs the SOAP envelope with HMAC-SHA256
    and reads the ActivationRemaining count from the response.

.PARAMETER AdvancedPid
    The Advanced PID (Extended PID) of the MAK key to query.

.PARAMETER LogPath
    Optional folder path where this script saves MAK count request/response payloads.

.PARAMETER PassThru
    Returns a structured PSObject with the result and raw SOAP payloads.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Network.psm1 for HTTP communication.
    Requires Libs\Common.psm1 for shared helper functions.

.EXAMPLE
    .\MakCount.ps1 -AdvancedPid "XXXXX-XXXXX-XXX-XXXXXX-XX-XXXX-XXXX.0000-XXXXXXX"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$AdvancedPid,
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
    # HMAC-SHA256 key for the BatchActivation SOAP digest.
    return [byte[]](
        254, 49, 152, 117, 251, 72, 132, 134, 156, 243, 241, 206, 153, 168, 144, 100,
        171, 87, 31, 202, 71, 4, 80, 88, 48, 36, 226, 20, 98, 135, 121, 160
    )
}

# ===============================================================================================================================

function New-ResponseObject {
    # Standard response object for BatchActivation.
    return @{
        Success        = $false
        ErrorCode      = $null
        ErrorMessage   = $null
        RemainingCount = $null
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
            $cNode = $innerDoc.SelectSingleNode("//*[local-name()='ActivationRemaining']")
            $eNode = $innerDoc.SelectSingleNode("//*[local-name()='ErrorCode']")

            if ($eNode) {
                $errCode = $eNode.InnerText
                if ($cNode) { $out.RemainingCount = $cNode.InnerText }
                $out.ErrorCode = $errCode
                $out.ErrorMessage = switch ($errCode) {
                    '0x67' { 'The product key has been blocked' }
                    '0x86' { 'Unsupported product key' }
                    default { "The remote server reported an error ($errCode)" }
                }
                return $out
            }
            elseif ($cNode -and $cNode.InnerText -eq '0') {
                $out.RemainingCount = '0'
                $out.ErrorMessage = "MAK activation limit reached"
                return $out
            }
            elseif ($cNode) {
                $out.Success = $true
                $out.RemainingCount = $cNode.InnerText
                return $out
            }
            else {
                $out.ErrorMessage = "Count or ErrorCode node not found in response"
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

function Invoke-BatchActivationRequest($AdvancedPid) {
    # Build + sign + send the MAK count request (RequestType 2 = remaining activations).
    
    $requestInner = @"
<ActivationRequest xmlns="http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0">
  <VersionNumber>2.0</VersionNumber>
  <RequestType>2</RequestType>
  <Requests>
    <Request>
      <PID>$AdvancedPid</PID>
    </Request>
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
    $res = Invoke-BatchActivationRequest $AdvancedPid
}

if (-not $res.ErrorCode) { $res.ErrorCode = "N/A" }
if (-not $res.ErrorMessage) { $res.ErrorMessage = "N/A" }
if (-not $res.RemainingCount) { $res.RemainingCount = "N/A" }
$logStatus = Write-ApiLogs $LogPath "MakCount" $res

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

$f = "{0,-18}: {1}"
Write-Output ""
Write-Output ($f -f "Advanced PID", $AdvancedPid)

if ($res.Success) {
    Write-Color ($f -f "Result", "Success") "BgGreen"
    Write-Color ($f -f "Remaining Count", $res.RemainingCount) "BgGreen"
}
else {
    Write-Color ($f -f "Result", "Failed") "BgRed"
    Write-Color ($f -f "Remaining Count", $res.RemainingCount) "BgRed"
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
Write-Output ""

# ===============================================================================================================================
# Object return (PassThru)
# ===============================================================================================================================

if ($PassThru) {
    New-Object PSObject -Property @{
        AdvancedPid    = $AdvancedPid
        Result         = if ($res.Success) { "SUCCESS" } else { "FAILED" }
        LogPath        = $LogPath
        LogStatus      = $logStatus
        RemainingCount = $res.RemainingCount
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
