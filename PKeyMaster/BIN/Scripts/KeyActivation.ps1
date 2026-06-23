<#
.SYNOPSIS
    Performs online product key activation against the Microsoft SL activation service.

.DESCRIPTION
    Builds a SOAP request to Microsoft's SLActivateProduct endpoint to consume
    an activation slot. Uses randomized hardware binding, a PublishLicense.xml
    template, and the key's ActConfigId.

.PARAMETER ProductKey
    The 25-character product key to activate.

.PARAMETER ActConfigId
    The Activation Configuration ID associated with the product key (from PidGenX).

.PARAMETER ConfigExt
    The configuration extension appended to the activation URL.
    Defaults to "Retail".

.PARAMETER LogPath
    Optional folder path where this script saves activation request/response payloads.

.PARAMETER PassThru
    Returns a structured PSObject with the activation result and raw SOAP payloads.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Network.ps1 for HTTP communication.
    Requires BIN\PublishLicense.xml for the activation request template.
    Requires Libs\Common.ps1 for shared helper functions.

.EXAMPLE
    .\KeyActivation.ps1 -ProductKey "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" -ActConfigId "msft2009:..."
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ProductKey,
    [Parameter(Mandatory = $true, Position = 1)]
    [string]$ActConfigId,
    [string]$ConfigExt = "Retail",
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

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function HtmlEncode([string]$s) {
    # Escape XML special chars for SOAP.
    if (-not $s) { return "" }
    return $s -replace '&', '&amp;' -replace '"', '&quot;' -replace '<', '&lt;' -replace '>', '&gt;'
}

# ===============================================================================================================================

function New-Binding {
    # Random hardware binding blob.
    # 24-byte fixed header + 18 random bytes.
    $hex = '2A0000000100020001000100000000000000010001000100'
    $pre = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $hex.Length; $i += 2) {
        $pre[$i / 2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
    }
    $rnd = New-Object byte[] 18
    (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($rnd)
    [Convert]::ToBase64String([byte[]]($pre + $rnd))
}

# ===============================================================================================================================

function Get-PublishLicenseXml {
    # Read PublishLicense.xml from BIN.
    $path = Join-Path (Split-Path $scriptDir) "PublishLicense.xml"
    if (Test-Path $path) {
        return [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8).Trim()
    }
    return $null
}

# ===============================================================================================================================

function New-ResponseObject {
    # Standard activation response object.
    return @{
        Success        = $false
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

function Write-ApiLogs($LogPath, $Prefix, $Obj) {
    # Dump request/response XML to disk.
    if (-not $LogPath) { return $null }

    try {
        if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
        if (-not (Test-Path $LogPath)) { return "Failed to create log folder" }

        $count = 0
        if ($Obj.RequestInner) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Request_BodyInner.xml") -Value $Obj.RequestInner -Encoding UTF8; $count++ }
        if ($Obj.ResponseInner) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Response_BodyInner.xml") -Value $Obj.ResponseInner -Encoding UTF8; $count++ }
        if ($Obj.RequestFull) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Request_BodyFull.xml") -Value $Obj.RequestFull -Encoding UTF8; $count++ }
        if ($Obj.ResponseFull) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Response_BodyFull.xml") -Value $Obj.ResponseFull -Encoding UTF8; $count++ }
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

function Submit-KeyActivationRequest([string]$RequestFull, [string]$RequestInner, [string]$ConfigExt) {
    # Send SOAP and parse the response.
    $out = New-ResponseObject
    $out.RequestInner = $RequestInner
    $out.RequestFull = $RequestFull

    $url = "https://activation.sls.microsoft.com/SLActivateProduct/SLActivateProduct.asmx?configextension=$ConfigExt"
    $action = "http://microsoft.com/SL/ProductActivationService/IssueToken"
    $userAgent = "SLSSoapClient"
    $contentType = "text/xml; charset=utf-8"
    $headers = @{ SOAPAction = $action }
    $contentLength = [Text.Encoding]::UTF8.GetByteCount($RequestFull)
    $uri = New-Object System.Uri($url)
    $out.RequestDetails = @"
POST $url HTTP/1.1
Host: $($uri.Host)
Connection: close
Content-Type: $contentType
User-Agent: $userAgent
SOAPAction: $($headers.SOAPAction)
Content-Length: $contentLength

Body:
$RequestFull
"@
    
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
        $fault = $doc.SelectSingleNode("//*[local-name()='Body']/*[local-name()='Fault']")
        if ($fault) {
            $hr = $fault.SelectSingleNode("*[local-name()='detail']/*[local-name()='HRESULT']")
            $msgNode = $fault.SelectSingleNode("*[local-name()='detail']/*[local-name()='Messages']/*[local-name()='Message']")
            $out.ErrorCode = if ($hr) { $hr.InnerText } else { $null }
            $out.ErrorMessage = if ($msgNode) { $msgNode.InnerText } else { $null }
            return $out
        }

        $valNode = $doc.SelectSingleNode("//*[local-name()='Body']/*[local-name()='RequestSecurityTokenResponse']/*[local-name()='RequestedSecurityToken']/*[local-name()='TmsResponseToken']/*[local-name()='Values']/*[local-name()='TokenEntry']/*[local-name()='Value']")
        if ($valNode) {
            $valText = $valNode.InnerText.Trim()
            $out.ResponseInner = $valText
            
            if (Test-Xml $valText) {
                $out.Success = $true
                return $out
            }
            if ($valText -match "^0x") {
                $out.ErrorCode = $valText
                $out.ErrorMessage = "Blocked"
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

function Invoke-KeyActivationRequest($ProductKey, $ActConfigId, $ConfigExt) {
    # Assemble and send the activation SOAP envelope.
    $out = New-ResponseObject

    $requestInner = Get-PublishLicenseXml
    if (-not $requestInner) {
        $out.ErrorMessage = "PublishLicense.xml not found in BIN directory"
        return $out
    }
    
    $cleanKey = $ProductKey.ToUpper()
    
    # Detect algorithm from prefix (msft2005 vs msft2009)
    $algorithm = "2009"
    if ($ActConfigId -match "msft2005") { $algorithm = "2005" }

    $encodedPl = HtmlEncode $requestInner
    $binding = New-Binding
    $encodedActConfigId = HtmlEncode $ActConfigId
    $localNow = [DateTime]::Now.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $utcNow = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $storeId = [guid]::NewGuid().ToString()

    $requestFull = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <soap:Body>
        <RequestSecurityToken xmlns="http://schemas.xmlsoap.org/ws/2004/04/security/trust">
            <TokenType>ProductActivation</TokenType>
            <RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</RequestType>
            <UseKey>
                <Values xmlns:q1="http://schemas.xmlsoap.org/ws/2004/04/security/trust" soapenc:arrayType="q1:TokenEntry[1]">
                    <TokenEntry><Name>PublishLicense</Name><Value>$encodedPl</Value></TokenEntry>
                </Values>
            </UseKey>
            <Claims>
                <Values xmlns:q1="http://schemas.xmlsoap.org/ws/2004/04/security/trust" soapenc:arrayType="q1:TokenEntry[14]">
                    <TokenEntry><Name>BindingType</Name><Value>msft:rm/algorithm/hwid/4.0</Value></TokenEntry>
                    <TokenEntry><Name>Binding</Name><Value>$binding</Value></TokenEntry>
                    <TokenEntry><Name>ProductKey</Name><Value>$cleanKey</Value></TokenEntry>
                    <TokenEntry><Name>ProductKeyType</Name><Value>msft:rm/algorithm/pkey/$algorithm</Value></TokenEntry>
                    <TokenEntry><Name>ProductKeyActConfigId</Name><Value>$encodedActConfigId</Value></TokenEntry>
                    <TokenEntry><Name>otherInfoPublic.licenseCategory</Name><Value>msft:sl/EUL/ACTIVATED/PUBLIC</Value></TokenEntry>
                    <TokenEntry><Name>otherInfoPrivate.licenseCategory</Name><Value>msft:sl/EUL/ACTIVATED/PRIVATE</Value></TokenEntry>
                    <TokenEntry><Name>otherInfoPublic.sysprepAction</Name><Value>rearm</Value></TokenEntry>
                    <TokenEntry><Name>otherInfoPrivate.sysprepAction</Name><Value>rearm</Value></TokenEntry>
                    <TokenEntry><Name>ClientInformation</Name><Value>SystemUILanguageId=1033;UserUILanguageId=1033;GeoId=244</Value></TokenEntry>
                    <TokenEntry><Name>ClientSystemTime</Name><Value>$localNow</Value></TokenEntry>
                    <TokenEntry><Name>ClientSystemTimeUtc</Name><Value>$utcNow</Value></TokenEntry>
                    <TokenEntry><Name>otherInfoPublic.secureStoreId</Name><Value>$storeId</Value></TokenEntry>
                    <TokenEntry><Name>otherInfoPrivate.secureStoreId</Name><Value>$storeId</Value></TokenEntry>
                </Values>
            </Claims>
        </RequestSecurityToken>
    </soap:Body>
</soap:Envelope>
"@

    return Submit-KeyActivationRequest $requestFull $requestInner $ConfigExt
}

# ===============================================================================================================================
# Main execution
# ===============================================================================================================================

if (-not (Get-Command Invoke-PostTextRequest -ErrorAction SilentlyContinue)) {
    $res = New-ResponseObject
    $res.ErrorMessage = "Network module not loaded"
}
else {
    $res = Invoke-KeyActivationRequest $ProductKey $ActConfigId $ConfigExt
}
if (-not $res.ErrorCode) { $res.ErrorCode = "N/A" }
if (-not $res.ErrorMessage) { $res.ErrorMessage = "N/A" }
$logStatus = Write-ApiLogs $LogPath "KeyActivation" $res

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

$f = "{0,-18}: {1}"
Write-Output ""
Write-Output ($f -f "Product Key", $ProductKey)
Write-Output ($f -f "ActConfigId", $ActConfigId)
if ($res.Success) {
    Write-Color ($f -f "Result", "Key Activation Succeeded") "BgGreen"
}
else {
    Write-Color ($f -f "Result", "Key Activation Failed") "BgRed"
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
        ProductKey     = $ProductKey
        ActConfigId    = $ActConfigId
        ConfigExt      = $ConfigExt
        Result         = if ($res.Success) { "SUCCESS" } else { "FAILED" }
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
