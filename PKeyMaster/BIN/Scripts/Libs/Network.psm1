<#
.SYNOPSIS
    HTTP GET/POST helpers and network transport for PKeyMaster.

.DESCRIPTION
    PowerShell script module providing HTTP GET and POST functions with automatic
    transport selection. Uses wget.exe from BIN\ when available, falling back
    to .NET HttpWebRequest. For large POST bodies (>5 KB) on pre-Windows 7 systems
    (build <7600), WebRequest is forced to avoid wget.exe bug.

    Failed requests are retried up to 5 times with a 2-second delay unless the
    machine is offline. An optional -ExpectedFormat ("xml" or "json") validates
    that the response body parses correctly and contains expected keywords.
    This module is intended to be imported via Import-Module, not executed directly.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Uses wget.exe from the BIN directory when available.
#>

# ===============================================================================================================================
# Initialization & Helper functions
# ===============================================================================================================================

$script:WgetPath = Join-Path $PSScriptRoot "..\..\wget.exe"

# ===============================================================================================================================

function New-Response {
    return @{
        Body       = ""
        StatusCode = 0
        Error      = ""
        Transport  = ""
    }
}

# ===============================================================================================================================

function Get-NetworkMode {
    param($Body)

    # Prefer wget when available, except for large POST payloads on Vista/older.
    $build = [Environment]::OSVersion.Version.Build
    $contentLength = 0
    if ($null -ne $Body) {
        $contentLength = [System.Text.Encoding]::UTF8.GetByteCount([string]$Body)
    }

    if ($build -lt 7600 -and $contentLength -gt 5kb) {
        return "WebRequest"
    }

    if (Test-Path $script:WgetPath) {
        return "Wget"
    }

    return "WebRequest"
}

# ===============================================================================================================================

function Test-InternetConnection {
    # COM first, then DNS fallback.
    try {
        $nlm = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}'))
        if ($nlm.IsConnectedToInternet) { return $true }
    }
    catch {}

    $hosts = @("l.root-servers.net", "resolver1.opendns.com", "download.windowsupdate.com", "google.com")
    foreach ($h in $hosts) {
        try {
            if ([System.Net.Dns]::GetHostAddresses($h)) { return $true }
        }
        catch {}
    }

    return $false
}

# ===============================================================================================================================

function Test-Xml([string]$Text) {
    # Valid XML that contains our keywords
    if (-not $Text) { return $false }
    if ($Text -match '</html>') { return $false }
    try {
        [xml]$Text | Out-Null

        if ($Text -match 'issuanceCertificateId|faultstring|ActivationRemaining') {
            return $true
        }

        return $false
    }
    catch {
        return $false
    }
}

# ===============================================================================================================================

function Test-Json([string]$Text) {
    # Valid JSON that contains our keywords
    if (-not $Text) { return $false }
    if ($Text -match '</html>') { return $false }
    try {
        $global:JsonSerializer.DeserializeObject($Text) | Out-Null

        if ($Text -match '"(cid|message|reasonCode|token|Pkpn|Product|Products|detail|name)"\s*:') {
            return $true
        }

        return $false
    }
    catch {
        return $false
    }
}

# ===============================================================================================================================
# Wget transport
# ===============================================================================================================================

function Invoke-WgetTextRequest($Method, $Url, $Body, $Headers, $ContentType, $UserAgent) {
    # Make the request via wget.exe.
    $wget = $script:WgetPath
    $tempOut = "$env:SystemRoot\Temp\$([Guid]::NewGuid())"
    $tempErr = "$env:SystemRoot\Temp\$([Guid]::NewGuid())"
    $tempPath = "$env:SystemRoot\Temp\$([Guid]::NewGuid())"
    try {
        $wgetArgs = @("--no-config", "--no-verbose", "--server-response", "--content-on-error", "--output-document=$tempOut", "--output-file=$tempErr", "--no-http-keep-alive", "--no-check-certificate", "--no-hsts", "--no-proxy", "--tries=1")
        if ($UserAgent) { $wgetArgs += @("--user-agent=$UserAgent") }
        if ($ContentType) { $wgetArgs += @("--header=Content-Type: $ContentType") }
        if ($Headers) { foreach ($k in $Headers.Keys) { $wgetArgs += @("--header=$($k): $($Headers[$k])") } }
                
        if ($Method -eq "POST") {
            if ($null -eq $Body) { $Body = "" }
            # Write POST data to a temp file to avoid CLI character limits and escaping issues
            [System.IO.File]::WriteAllText($tempPath, $Body, [System.Text.Encoding]::UTF8)
            $wgetArgs += @("--post-file=$tempPath")
        }
        $wgetArgs += $Url

        # Escape and quote arguments properly
        $escapedArgs = foreach ($arg in $wgetArgs) {
            if ($arg -match '[\s"]') { '"{0}"' -f ($arg -replace '"', '\"') } else { $arg }
        }
        $argsString = $escapedArgs -join ' '

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $wget
        $psi.Arguments = $argsString.Trim()
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        $p = [System.Diagnostics.Process]::Start($psi)
        if (-not $p.WaitForExit(30000)) {
            try { $p.Kill() } catch {}
        }

        $res = if (Test-Path $tempOut) { [System.IO.File]::ReadAllText($tempOut, [System.Text.Encoding]::UTF8) } else { "" }
        $err = if (Test-Path $tempErr) { [System.IO.File]::ReadAllText($tempErr, [System.Text.Encoding]::UTF8) } else { "" }

        $msg = ""
        if ($p.ExitCode -ne 0) {
            $lines = @($err -split "`r?`n" | Where-Object { $_ -match '\S' })
                        
            # Try to extract the HTTP status (e.g., 403 Forbidden) from headers
            $statusLine = @($lines | Where-Object { $_ -match '^\s*HTTP/\d\.\d\s+(.+)$' } | Select-Object -Last 1)
            if ($statusLine) {
                $statusText = [string]$statusLine[-1]
                if ($statusText -match '^\s*HTTP/\d\.\d\s+(.+)$') {
                    $msg = $matches[1].Trim()
                }
            }
            elseif ($lines) {
                # Default to the raw error output from wget if no HTTP status line found
                $msg = $lines[-1] -replace '^(wget|wget\.exe):\s*', ''
            }
            else {
                $msg = "wget.exe exited with code $($p.ExitCode)."
            }
        }
        $out = New-Response
        $out.Body = $res
        $out.Error = $msg
        $out.Transport = "Wget"
        return $out
    }
    finally {
        # Clean up temporary files
        foreach ($f in @($tempPath, $tempOut, $tempErr)) {
            if ($f -and (Test-Path $f)) {
                try { Remove-Item $f -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
    }
}

# ===============================================================================================================================
# .NET WebRequest transport
# ===============================================================================================================================

function Invoke-DotNetTextRequest($Method, $Url, $Body, $Headers, $ContentType, $UserAgent) {
    # Make the request via System.Net.HttpWebRequest.
    try {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}
        if ([Environment]::OSVersion.Version.Build -lt 9200) {
            try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}
        }

        $request = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Url)
        $request.Method = $Method
        $request.KeepAlive = $false
        $request.Proxy = $null

        if ($ContentType) { $request.ContentType = $ContentType }
        if ($UserAgent) { $request.UserAgent = $UserAgent }
        if ($Headers) {
            foreach ($k in $Headers.Keys) {
                $request.Headers.Set([string]$k, [string]$Headers[$k])
            }
        }

        if ($Method -eq "POST") {
            if ($null -eq $Body) { $Body = "" }
            $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
            $request.ContentLength = $bodyBytes.Length

            $requestStream = $null
            try {
                $requestStream = $request.GetRequestStream()
                $requestStream.Write($bodyBytes, 0, $bodyBytes.Length)
            }
            finally {
                if ($requestStream) { $requestStream.Close() }
            }
        }

        $response = $null
        $responseBody = ""
        $statusCode = 0
        $err = ""

        try {
            $response = $request.GetResponse()
        }
        catch [System.Net.WebException] {
            # Keep 4xx/5xx response bodies so callers can parse server-side errors.
            $webEx = $_.Exception
            $err = if ($webEx.InnerException) { $webEx.InnerException.Message } else { $webEx.Message }
            $response = $webEx.Response
        }

        if ($response) {
            $reader = $null
            try {
                $statusCode = [int]$response.StatusCode
                $stream = $response.GetResponseStream()
                if ($stream) {
                    $reader = New-Object System.IO.StreamReader($stream)
                    $responseBody = $reader.ReadToEnd()
                }
            }
            finally {
                if ($reader) { $reader.Close() }
                $response.Close()
            }
        }

        $out = New-Response
        $out.Body = $responseBody
        $out.StatusCode = $statusCode
        $out.Error = $err
        $out.Transport = "WebRequest"
        return $out
    }
    catch {
        $out = New-Response
        $out.Error = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        $out.Transport = "WebRequest"
        return $out
    }
}

# ===============================================================================================================================

function Invoke-TextRequestWithRetry($Method, $Url, $Body, $Headers, $ContentType, $UserAgent, $ExpectedFormat) {
    # Retry loop with fallback.
    try {
        $mode = Get-NetworkMode $Body

        for ($i = 0; $i -lt 6; $i++) {
            if ($mode -eq "Wget") {
                $out = Invoke-WgetTextRequest $Method $Url $Body $Headers $ContentType $UserAgent
            }
            else {
                $out = Invoke-DotNetTextRequest $Method $Url $Body $Headers $ContentType $UserAgent
            }

            $bodyValid = [bool]$out.Body
            if ($bodyValid -and $ExpectedFormat) {
                if ($ExpectedFormat -eq "xml") { $bodyValid = Test-Xml $out.Body }
                elseif ($ExpectedFormat -eq "json") { $bodyValid = Test-Json $out.Body }
            }
            if ($bodyValid) { break }
            if ($i -eq 0 -and -not (Test-InternetConnection)) { break }
            # OLSC and Visual API require TLS 1.2, which Win7 and older lack by default; don't retry if wget is missing
            if ([Environment]::OSVersion.Version.Build -lt 9200 -and $mode -eq "WebRequest" -and $Url -match "visual|m365") { break }
            # Don't delay retries on Visual API, DPoP token expires in ~10s
            if ($i -lt 5 -and $Url -notmatch "visual") { Start-Sleep -Seconds 2 }
        }
        return $out
    }
    catch {
        $out = New-Response
        $out.Error = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        $out.Transport = "Error"
        return $out
    }
}

# ===============================================================================================================================
# Public entry points
# ===============================================================================================================================

function Invoke-GetTextRequest($Url, $Headers = $null, $ContentType = "", $UserAgent = "", $ExpectedFormat = "") {
    # GET with retries
    return Invoke-TextRequestWithRetry "GET" $Url "" $Headers $ContentType $UserAgent $ExpectedFormat
}

# ===============================================================================================================================

function Invoke-PostTextRequest($Url, $Body, $Headers = $null, $ContentType = "", $UserAgent = "", $ExpectedFormat = "") {
    # POST with retries
    return Invoke-TextRequestWithRetry "POST" $Url $Body $Headers $ContentType $UserAgent $ExpectedFormat
}

# ===============================================================================================================================

function Format-RequestDetails($Method, $Url, $Body = "", $Headers = $null, $ContentType = "", $UserAgent = "", $Connection = "close") {
    $uri = New-Object System.Uri($Url)
    $lines = @("$Method $Url HTTP/1.1", "Host: $($uri.Host)")
    if ($Connection) { $lines += "Connection: $Connection" }
    if ($ContentType) { $lines += "Content-Type: $ContentType" }
    if ($UserAgent) { $lines += "User-Agent: $UserAgent" }
    if ($Headers) {
        foreach ($k in $Headers.Keys) {
            $lines += "$k`: $($Headers[$k])"
        }
    }
    if ($Method -eq "POST" -or $Body) {
        $len = if ($Body) { [System.Text.Encoding]::UTF8.GetByteCount([string]$Body) } else { 0 }
        $lines += "Content-Length: $len"
        $lines += ""
        $lines += "Body:"
        $lines += $Body
    }
    return ($lines -join "`r`n")
}

# ===============================================================================================================================

function Write-ApiLogs($LogPath, $Prefix, $Obj) {
    # Dump request/response payloads to disk.
    if (-not $LogPath) { return $null }

    try {
        if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
        if (-not (Test-Path $LogPath)) { return "Failed to create log folder" }

        $ext = if ($Obj.Token -or $Obj.RequestFull -match '^\s*[\{\[]' -or $Obj.ResponseFull -match '^\s*[\{\[]') {
            ".json"
        }
        else {
            ".xml"
        }

        $count = 0
        if ($Obj.RequestInner) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Request_BodyInner$ext") -Value $Obj.RequestInner -Encoding UTF8; $count++ }
        if ($Obj.ResponseInner) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Response_BodyInner$ext") -Value $Obj.ResponseInner -Encoding UTF8; $count++ }
        if ($Obj.RequestFull) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Request_BodyFull$ext") -Value $Obj.RequestFull -Encoding UTF8; $count++ }
        if ($Obj.Token) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Token.txt") -Value $Obj.Token -Encoding UTF8; $count++ }
        if ($Obj.ResponseFull) { Set-Content -Path (Join-Path $LogPath "$Prefix`_Response_BodyFull$ext") -Value $Obj.ResponseFull -Encoding UTF8; $count++ }
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
