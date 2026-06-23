<#
.SYNOPSIS
    Common functions for PKeyMaster backend scripts.
#>

# ===============================================================================================================================
# ANSI / VT support detection
# ===============================================================================================================================

$script:AnsiSupported = $false
$script:ColorLineBuffer = ""
if ([System.Environment]::OSVersion.Version.Build -ge 10586) {
    $forceV2 = (Get-ItemProperty -Path 'HKCU:\Console' -Name 'ForceV2' -ErrorAction SilentlyContinue).ForceV2
    if ($null -eq $forceV2 -or $forceV2 -ne 0) {
        $script:AnsiSupported = $true
    }
}

# Color name -> @(AnsiCode, GUI-ForegroundColor, GUI-BackgroundColor)
$script:ColorMap = @{
    'BgRed'    = @("41;97", "White", "DarkRed")
    'BgGray'   = @("100;97", "White", "Gray")
    'BgGreen'  = @("42;97", "White", "Green")
    'BgBlue'   = @("44;97", "White", "Blue")
    'BgWhite'  = @("107;91", "Red", "White")
    'FgRed'    = @("40;91", "Red", "Black")
    'FgWhite'  = @("40;37", "Gray", "Black")
    'FgGreen'  = @("40;92", "Green", "Black")
    'FgYellow' = @("40;93", "Yellow", "Black")
}

# ===============================================================================================================================
# Write-Color
# Usage:  Write-Color "text" "BgRed"
#         Write-Color "label: " "BgGray" -NoNewline; Write-Color "value" "FgGreen"
# ===============================================================================================================================

function Write-Color {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Text,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateSet('BgRed', 'BgGray', 'BgGreen', 'BgBlue', 'BgWhite', 'FgRed', 'FgWhite', 'FgGreen', 'FgYellow')]
        [string]$Color,

        [Parameter(Mandatory = $false)]
        [switch]$NoNewline
    )

    $colorData = $script:ColorMap[$Color]
    $piece = ""

    if ($global:IsGuiRunspace) {
        $piece = "[c:$($colorData[1]):$($colorData[2])]$Text"
    }
    elseif ($script:AnsiSupported) {
        $piece = "$([char]27)[$($colorData[0])m$Text$([char]27)[0m"
    }
    else {
        $piece = $Text
    }

    if ($NoNewline) {
        $script:ColorLineBuffer += $piece
    }
    else {
        $fullLine = $script:ColorLineBuffer + $piece
        $script:ColorLineBuffer = ""
        Write-Output $fullLine
    }
}

# ===============================================================================================================================
