<#
.SYNOPSIS
    Validates pre-Windows 98 era product keys (OEM, 10-digit, 11-digit formats).

.DESCRIPTION
    Validates pre-98 key formats (Windows 95, NT 4.0, Office 95, 97, 98/2001 Mac)
    using digit-sum mod-7 checks, position constraints, and format-specific blacklists.

.PARAMETER Key
    The product key string to validate.

.NOTES
    Compatible with PowerShell 2.0 and later.
    Requires Libs\Common.ps1 for shared helper functions.

.EXAMPLE
    .\KeyCheckerPre98.ps1 -Key "123-4567890"
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Key
)

# ===============================================================================================================================
# Initialization & dependencies
# ===============================================================================================================================

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "." }

$commonPath = Join-Path $scriptDir "libs\Common.ps1"
if (Test-Path $commonPath) { . $commonPath }

# ===============================================================================================================================

# ===============================================================================================================================
# Helper functions
# ===============================================================================================================================

function Get-DigitSum([string]$str) {
    # Sum of all digits in the string. Returns -1 if any non-digit found.
    $sum = 0
    foreach ($c in $str.ToCharArray()) {
        if (-not [char]::IsDigit($c)) { return -1 }
        $sum += [int][string]$c
    }
    return $sum
}

# ===============================================================================================================================

function Test-IsNumeric([string]$str) {
    # True if the string contains only digits.
    return ($str -match '^\d+$')
}

# ===============================================================================================================================
# Key validation
# ===============================================================================================================================

$MatchedProducts = @()

$KeyUpper = $Key.ToUpper()

if ($KeyUpper.Length -eq 11 -and $KeyUpper[3] -eq '-') {
    # 10-digit CD Retail Key (format: XXX-XXXXXXX)
    $first = $KeyUpper.Substring(0, 3)
    $second = $KeyUpper.Substring(4, 7)
    
    $sum = Get-DigitSum $second
    if ($sum -ne -1 -and ($sum % 7) -eq 0) {
        $blacklisted = @('333', '444', '555', '666', '777', '888', '999')
        
        # Windows 95 Retail
        if ($blacklisted -notcontains $first) {
            $MatchedProducts += "Windows 95 Retail"
        }
        
        # Windows NT 4.0 Retail: first part must be numeric, not blacklisted, last digit of second part must not be 0, 8, or 9
        if ((Test-IsNumeric $first) -and ($blacklisted -notcontains $first)) {
            $lastDigit = [int][string]$second[6]
            if ($lastDigit -ne 0 -and $lastDigit -ne 8 -and $lastDigit -ne 9) {
                $MatchedProducts += "Windows NT 4.0 Retail"
            }
        }
        
        # Office 95 Retail, Office 98 Retail (Mac), Office 2001 Retail (Mac)
        if (Test-IsNumeric $first) {
            $MatchedProducts += "Office 95 Retail"
            $MatchedProducts += "Office 98 Retail (Mac)"
            $MatchedProducts += "Office 2001 Retail (Mac)"
        }
    }

}
elseif ($KeyUpper.Length -eq 12 -and $KeyUpper[4] -eq '-') {
    # 11-digit CD Retail Key (format: XXXX-XXXXXXX)
    $first = $KeyUpper.Substring(0, 4)
    $second = $KeyUpper.Substring(5, 7)
    
    $firstIsNumeric = Test-IsNumeric $first
    if ($firstIsNumeric) {
        # The 4th digit must be (3rd digit + 1) or (3rd digit + 2) mod 10
        $thirdDigit = [int][string]$first[2]
        $lastDigit = [int][string]$first[3]
        $valid1 = ($thirdDigit + 1) % 10
        $valid2 = ($thirdDigit + 2) % 10
        
        if ($lastDigit -eq $valid1 -or $lastDigit -eq $valid2) {
            $sum = Get-DigitSum $second
            if ($sum -ne -1 -and ($sum % 7) -eq 0) {
                # Office 97 Retail
                $MatchedProducts += "Office 97 Retail"
            }
        }
    }

}
elseif ($KeyUpper.Length -eq 23 -and $KeyUpper.Substring(5, 5) -eq '-OEM-') {
    # OEM Key (format: XXXXX-OEM-XXXXXXX-XXXXX)
    $first = $KeyUpper.Substring(0, 5)
    $third = $KeyUpper.Substring(10, 7)
    $fourth = $KeyUpper.Substring(18, 5)
    
    $isFirstNumeric = Test-IsNumeric $first
    $thirdSum = Get-DigitSum $third
    $isThirdMod7 = ($thirdSum -ne -1 -and ($thirdSum % 7) -eq 0)
    $isFourthNumeric = Test-IsNumeric $fourth
    
    if ($isFirstNumeric -and $isThirdMod7 -and $isFourthNumeric) {
        # Parse Julian date and year from the first segment (DDDYY)
        $julian = [int]$first.Substring(0, 3)
        $year = $first.Substring(3, 2)
        
        $thirdStarts0 = ($third[0] -eq '0')
        $thirdLastDigit = [int][string]$third[6]
        $thirdValidLast = ($thirdLastDigit -ne 0 -and $thirdLastDigit -ne 8 -and $thirdLastDigit -ne 9)
        
        # Windows 95 OEM
        if ($julian -ge 1 -and $julian -le 366) {
            $valid95Years = @('95', '96', '97', '98', '99', '00', '01', '02')
            if (($valid95Years -contains $year) -and $thirdStarts0 -and $thirdValidLast) {
                $MatchedProducts += "Windows 95 OEM"
            }
        }
        
        # Windows NT 4.0 OEM
        if ($julian -ge 1 -and $julian -le 366) {
            $validNTYears = @('95', '96', '97', '98', '99', '00', '01', '02', '03')
            if (($validNTYears -contains $year) -and $thirdStarts0 -and $thirdValidLast) {
                $MatchedProducts += "Windows NT 4.0 OEM"
            }
        }
        
        # Office 95 OEM
        $MatchedProducts += "Office 95 OEM"
        
        # Office 97 OEM
        $MatchedProducts += "Office 97 OEM"
    }
}

# ===============================================================================================================================
# Console output
# ===============================================================================================================================

$f = "{0,-18}: {1}"

Write-Output ""
Write-Output ($f -f "Product Key", $Key)

if ($MatchedProducts.Count -gt 0) {
    Write-Color ($f -f "Result", "Valid") "BgGreen"
    foreach ($prod in $MatchedProducts) {
        Write-Output ($f -f "Product Match", $prod)
    }
}
else {
    Write-Color ($f -f "Result", "Invalid") "BgRed"
}

# ===============================================================================================================================
