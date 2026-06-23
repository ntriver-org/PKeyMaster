<#
.SYNOPSIS
    HTTP GET/POST helpers for PKeyMaster backend scripts.

.DESCRIPTION
    Provides HTTP GET and POST functions with automatic transport selection.
    Uses wget.exe from BIN\ when available, falling back to .NET HttpWebRequest.
    For large POST bodies (>5 KB) on pre-Windows 7 systems (build <7600), WebRequest
    is forced to avoid wget.exe bug.

    Failed requests are retried up to 5 times with a 2-second delay unless the
    machine is offline. An optional -ExpectedFormat ("xml" or "json") validates
    that the response body parses correctly and contains expected keywords.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Uses wget.exe from the BIN directory when available.
#>

# ===============================================================================================================================
# Initialization & Helper functions
# ===============================================================================================================================

$script:WgetPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..\..\wget.exe"

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
        Add-Type -AssemblyName System.Web.Extensions | Out-Null
        (New-Object System.Web.Script.Serialization.JavaScriptSerializer).DeserializeObject($Text) | Out-Null

        if ($Text -match '"(cid|message|reasonCode|token)"\s*:') {
            return $true
        }

        return $false
    }
    catch { return $false }
}

# ===============================================================================================================================
# Wget transport
# ===============================================================================================================================

function Invoke-WgetTextRequest($Method, $Url, $Body, $Headers, $ContentType, $UserAgent) {
    # Make the request via wget.exe.
    $wget = $script:WgetPath
    $tempPath = $null
    try {
        $wgetArgs = @("--no-config", "--no-verbose", "--server-response", "--content-on-error", "--output-document", "-", "--no-http-keep-alive", "--no-check-certificate", "--no-hsts", "--tries=1")
        if ($UserAgent) { $wgetArgs += @("--user-agent=$UserAgent") }
        if ($ContentType) { $wgetArgs += @("--header=Content-Type: $ContentType") }
        if ($Headers) { foreach ($k in $Headers.Keys) { $wgetArgs += @("--header=$($k): $($Headers[$k])") } }
                
        if ($Method -eq "POST") {
            if ($null -eq $Body) { $Body = "" }
            # Write POST data to a temp file to avoid CLI character limits and escaping issues
            $tempPath = [System.IO.Path]::GetTempFileName()
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
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true

        $p = [System.Diagnostics.Process]::Start($psi)
        $res = $p.StandardOutput.ReadToEnd()
        $err = $p.StandardError.ReadToEnd()
        $p.WaitForExit()

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
        # Clean up temporary file
        if ($tempPath -and (Test-Path $tempPath)) {
            try { Remove-Item $tempPath -Force -ErrorAction SilentlyContinue } catch {}
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
            if ([Environment]::OSVersion.Version.Build -lt 9200 -and $mode -eq "WebRequest" -and $Url -match "visual") { break }
            if ($i -lt 5) { Start-Sleep -Seconds 2 }
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

function Invoke-GetTextRequest($Url, $Headers = $null, $UserAgent = "", $ExpectedFormat = "") {
    # GET with retries
    return Invoke-TextRequestWithRetry "GET" $Url "" $Headers "" $UserAgent $ExpectedFormat
}

# ===============================================================================================================================

function Invoke-PostTextRequest($Url, $Body, $Headers = $null, $ContentType = "", $UserAgent = "", $ExpectedFormat = "") {
    # POST with retries
    return Invoke-TextRequestWithRetry "POST" $Url $Body $Headers $ContentType $UserAgent $ExpectedFormat
}

# ===============================================================================================================================
