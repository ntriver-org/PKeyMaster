<#
.SYNOPSIS
    Resolves Windows error codes (HRESULT) into human-readable descriptions.

.DESCRIPTION
    This script takes an error code or an exception and attempts to resolve it
    using the Windows FormatMessage API. It probes specific licensing and system
    DLLs (slc.dll, sppc.dll, wmiutils.dll, etc.) to find the most accurate message.

.PARAMETER ErrorCode
    The numeric error code (integer) to resolve.

.PARAMETER Exception
    An optional PowerShell Exception object to extract the HRESULT from.

.PARAMETER PassThru
    Returns a structured PSObject containing the ErrorCode and ErrorMessage.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Common.ps1 for shared helper functions.
    Uses dynamic P/Invoke to call LoadLibrary and FormatMessage.
#>
param(
    [int]$ErrorCode = 0,
    [Exception]$Exception = $null,
    [switch]$PassThru
)

# ===============================================================================================================================
# Initialization
# ===============================================================================================================================

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "." }
$commonPath = Join-Path $scriptDir "Common.ps1"
if (Test-Path $commonPath) { . $commonPath }

if ($ErrorCode -eq 0 -and -not $Exception) { return }
$f = '{0,-18}: {1}'

# ===============================================================================================================================
# HRESULT resolution
# ===============================================================================================================================

# Resolve HRESULT from exception if provided
$hres = $ErrorCode
if ($Exception) {
    $ex = if ($Exception.InnerException) { $Exception.InnerException } else { $Exception }
    $hres = [System.Runtime.InteropServices.Marshal]::GetHRForException($ex)
}

# ===============================================================================================================================
# Native P/Invoke (FormatMessage)
# ===============================================================================================================================

$msg = ''

if ($hres -ne 0) {
    # Build interop type once per session to avoid recompiling
    $typeName = 'SPPInterop'
    $interopType = $typeName -as [type]

    if (-not $interopType) {
        $TB = [AppDomain]::CurrentDomain.DefineDynamicAssembly((Get-Random), 1).DefineDynamicModule((Get-Random), $False).DefineType($typeName)
        [void]$TB.DefinePInvokeMethod('LoadLibrary', 'kernel32.dll', 22, 1, [IntPtr], @([string]), 1, 4).SetImplementationFlags(128)
        [void]$TB.DefinePInvokeMethod('FreeLibrary', 'kernel32.dll', 22, 1, [bool], @([IntPtr]), 1, 4).SetImplementationFlags(128)
        [void]$TB.DefinePInvokeMethod('FormatMessage', 'kernel32.dll', 22, 1, [int], @([int], [IntPtr], [int], [int], [System.Text.StringBuilder], [int], [IntPtr]), 1, 4).SetImplementationFlags(128)
        $interopType = $TB.CreateType()
    }

    # Walk licensing and system DLLs to find the error description
    $searchDlls = @('slc.dll', 'sppc.dll', 'wmiutils.dll', 'KernelBase.dll')
    foreach ($dll in $searchDlls) {
        $hMod = $interopType::LoadLibrary($dll)
        if ($hMod -eq [IntPtr]::Zero) { continue }

        $sb = New-Object System.Text.StringBuilder 1024
        # Flags: FORMAT_MESSAGE_FROM_HMODULE (0x800) | FORMAT_MESSAGE_IGNORE_INSERTS (0x200)
        $res = $interopType::FormatMessage(0x00000A00, $hMod, $hres, 0, $sb, $sb.Capacity, [IntPtr]::Zero)
        $interopType::FreeLibrary($hMod) | Out-Null

        if ($res -gt 0) {
            $msg = $sb.ToString().Trim()
            break 
        }
    }
}

# ===============================================================================================================================
# Message resolution
# ===============================================================================================================================

# Fallback to raw exception message if native resolution failed
if (-not $msg -and $Exception) {
    $ex = if ($Exception.InnerException) { $Exception.InnerException } else { $Exception }
    $msg = $ex.Message
}

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

Write-Color ($f -f 'Error Code', ('0x{0:X8}' -f $hres)) "BgRed"
Write-Color ($f -f 'Error Message', $msg) "BgRed"
Write-Output ""

# ===============================================================================================================================
# Object return (PassThru)
# ===============================================================================================================================

if ($PassThru) {
    return New-Object PSObject -Property @{
        ErrorCode    = $hres
        ErrorMessage = $msg
    }
}

# ===============================================================================================================================
