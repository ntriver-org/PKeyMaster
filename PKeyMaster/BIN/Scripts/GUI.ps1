<#
.SYNOPSIS
    WinForms graphical user interface for the PKeyMaster suite.

.DESCRIPTION
    Tabbed WinForms front-end for the PKeyMaster tools:
    key validation, IID/CID retrieval, PKeyConfig export, and key scanning.

    Long-running tools run via background PowerShell pipelines to keep the UI responsive.

.NOTES
    The launcher dot-sources this file and supplies Version.
    Requires the full PKeyMaster file layout with all BIN\Scripts\ files and
    supporting libraries in place.
#>
[CmdletBinding()]
param()

# ===============================================================================================================================
# Initialization & setup
# ===============================================================================================================================

$Script:GuiScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:ApplicationRoot = Split-Path -Parent $Script:GuiScriptRoot
$BaseUrl = 'https://ntriver.org'
$GitUrl = 'https://github.com/ntriver-org/PKeyMaster'

Add-Type -AssemblyName System.Windows.Forms | Out-Null
Add-Type -AssemblyName System.Drawing | Out-Null

function Get-HostValue {
    param(
        [string]$Name,
        [object]$DefaultValue
    )

    try {
        $variable = Get-Variable -Name $Name -ErrorAction SilentlyContinue
        if ($variable -and $null -ne $variable.Value -and ([string]$variable.Value).Trim() -ne '') {
            return $variable.Value
        }
    }
    catch { }

    return $DefaultValue
}

# ===============================================================================================================================

function Initialize-WinForms {
    try {
        if ($PSVersionTable.PSVersion.Major -gt 2) {
            $applicationType = [Type]::GetType('System.Windows.Forms.Application')
            $dpiMethod = $applicationType.GetMethod('SetHighDpiMode', [System.Reflection.BindingFlags]'Public,Static')
            if ($dpiMethod) {
                [void]$dpiMethod.Invoke($null, @([System.Windows.Forms.HighDpiMode]::SystemAware))
            }
        }
    }
    catch { }

    [System.Windows.Forms.Application]::EnableVisualStyles()
    try {
        [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)
    }
    catch { }
}

# ===============================================================================================================================
# Main GUI entry point
# ===============================================================================================================================

function Show-PKeyMasterGui {
    $applicationVersion = [string](Get-HostValue -Name 'Version' -DefaultValue '')
    $homePageUrl = [string]$BaseUrl
    $repositoryUrl = [string]$GitUrl
    $windowTitle = 'PKeyMaster'
    if ($applicationVersion) {
        $windowTitle = "$windowTitle $applicationVersion"
    }
    $browsePlaceholder = 'Click to browse...'

    function Resolve-ToolScriptPath {
        param([string]$ScriptName)

        $scriptPath = Join-Path $Script:GuiScriptRoot $ScriptName
        if (Test-Path -LiteralPath $scriptPath) {
            return $scriptPath
        }

        return $null
    }

    # ===============================================================================================================================

    function Resolve-BinaryPath {
        param([string]$FileName)

        $binaryPath = Join-Path $Script:ApplicationRoot $FileName
        if (Test-Path -LiteralPath $binaryPath) {
            return $binaryPath
        }

        return $null
    }

    # ===============================================================================================================================

    function Get-DefaultConfigRoot {
        $configRoot = Join-Path $Script:ApplicationRoot 'PKeyConfigs'
        if (Test-Path -LiteralPath $configRoot) {
            return $configRoot
        }

        return $Script:GuiScriptRoot
    }

    # ===============================================================================================================================

    function Show-ErrorMessage {
        param([object]$ErrorObject)

        $message = if ($ErrorObject -and $ErrorObject.Exception) {
            $ErrorObject.Exception.Message
        }
        else {
            [string]$ErrorObject
        }

        if (-not $message) {
            $message = 'An unexpected error occurred.'
        }

        [System.Windows.Forms.MessageBox]::Show(
            $message,
            'Error',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }

    # ===============================================================================================================================

    function Invoke-UiAction {
        param([scriptblock]$Action)

        try {
            & $Action
        }
        catch {
            Show-ErrorMessage -ErrorObject $_
        }
    }

    # ===============================================================================================================================

    function Confirm-ActivationSlotUse {
        $result = [System.Windows.Forms.MessageBox]::Show(
            "The following options would consume an activation slot:`n`n- Key Activation`n- CID`n`nContinue anyway?",
            'PKeyMaster',
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )

        return ($result -eq [System.Windows.Forms.DialogResult]::Yes)
    }

    # ===============================================================================================================================

    function Show-OwnedDialog {
        param(
            $Dialog,
            $OwnerWindow = $null
        )

        if (-not $Dialog) {
            return [System.Windows.Forms.DialogResult]::Cancel
        }

        if ($OwnerWindow -and $OwnerWindow.IsHandleCreated) {
            return $Dialog.ShowDialog($OwnerWindow)
        }

        return $Dialog.ShowDialog()
    }

    # ===============================================================================================================================

    function Test-SelectedPathText {
        param([string]$PathText)

        $trimmedPath = if ($PathText) { $PathText.Trim() } else { '' }
        return ($trimmedPath -and $trimmedPath -ne $browsePlaceholder)
    }

    # ===============================================================================================================================
    # Background task runner
    # ===============================================================================================================================

    function Start-ToolTask {
        param(
            [string]$ScriptName,
            [hashtable]$Arguments,
            $OutputBox,
            [object[]]$ControlsToDisable,
            [scriptblock]$Completed,
            [switch]$CollectObjects
        )

        $toolScriptPath = Resolve-ToolScriptPath -ScriptName $ScriptName
        if (-not $toolScriptPath) {
            Show-ErrorMessage -ErrorObject "Script not found: $ScriptName"
            return
        }

        if ($null -eq $Arguments) {
            $Arguments = @{}
        }

        $setControlsEnabled = {
            param([bool]$Enabled)

            foreach ($control in @($ControlsToDisable)) {
                if ($control) {
                    $control.Enabled = $Enabled
                }
            }
        }.GetNewClosure()

        & $setControlsEnabled $false
        if ($OutputBox) {
            $OutputBox.Clear()
        }

        $powerShellPipeline = [PowerShell]::Create()
        $textQueue = [System.Collections.Queue]::Synchronized((New-Object System.Collections.Queue))
        $objectQueue = [System.Collections.Queue]::Synchronized((New-Object System.Collections.Queue))

        $runner = {
            param($ToolScriptPath, $ToolArguments, $TextQueue, $ObjectQueue, $ShouldCollectObjects)

            if ($ShouldCollectObjects) {
                & $ToolScriptPath @ToolArguments 2>&1 | ForEach-Object {
                    $outputItem = $_
                    $baseObject = if ($outputItem -is [System.Management.Automation.PSObject] -and $outputItem.BaseObject) {
                        $outputItem.BaseObject
                    }
                    else {
                        $outputItem
                    }

                    if ($baseObject -is [string] -or $outputItem -is [System.Management.Automation.ErrorRecord]) {
                        $TextQueue.Enqueue([string]$outputItem)
                    }
                    elseif ($null -ne $outputItem) {
                        $ObjectQueue.Enqueue($outputItem)
                    }
                }
            }
            else {
                & $ToolScriptPath @ToolArguments 2>&1 | Out-String -Stream | ForEach-Object {
                    $TextQueue.Enqueue($_)
                }
            }
        }

        [void]$powerShellPipeline.AddScript('$global:IsGuiRunspace = $true')
        [void]$powerShellPipeline.AddScript($runner.ToString())
        [void]$powerShellPipeline.AddArgument($toolScriptPath)
        [void]$powerShellPipeline.AddArgument($Arguments)
        [void]$powerShellPipeline.AddArgument($textQueue)
        [void]$powerShellPipeline.AddArgument($objectQueue)
        [void]$powerShellPipeline.AddArgument([bool]$CollectObjects)

        $asyncResult = $powerShellPipeline.BeginInvoke()
        $errorIndex = 0
        $taskSucceeded = $false
        $resultObjects = New-Object 'System.Collections.Generic.List[object]'

        $appendOutput = {
            param([string[]]$Lines)

            if (-not $OutputBox -or -not $Lines -or $Lines.Count -eq 0) {
                return
            }

            try {
                foreach ($line in $Lines) {
                    # Prepend a newline for every line except the very first one
                    if ($OutputBox.TextLength -gt 0) {
                        $OutputBox.AppendText([Environment]::NewLine)
                    }

                    $currentColor = $OutputBox.ForeColor
                    $currentBackColor = $OutputBox.BackColor

                    if ($line -match '\[c:') {
                        $colorMatches = [regex]::Matches($line, '\[c:(?<f>[^:]+):(?<b>[^:]+)\]')
                        $lastIndex = 0
                        
                        foreach ($m in $colorMatches) {
                            $chunk = $line.Substring($lastIndex, $m.Index - $lastIndex)
                            if ($chunk.Length -gt 0) {
                                $start = $OutputBox.TextLength
                                $OutputBox.AppendText($chunk)
                                $OutputBox.Select($start, $OutputBox.TextLength - $start)
                                $OutputBox.SelectionColor = $currentColor
                                $OutputBox.SelectionBackColor = $currentBackColor
                            }
                            
                            # Set new colors for subsequent text
                            $f = $m.Groups['f'].Value
                            $b = $m.Groups['b'].Value
                            if ($f -ne '-') { $currentColor = [System.Drawing.Color]::FromName($f) }
                            if ($b -ne '-') { $currentBackColor = [System.Drawing.Color]::FromName($b) }
                            
                            $lastIndex = $m.Index + $m.Length
                        }
                        
                        $line = $line.Substring($lastIndex)
                    }

                    if ($line.Length -gt 0) {
                        $start = $OutputBox.TextLength
                        $OutputBox.AppendText($line)
                        $OutputBox.Select($start, $OutputBox.TextLength - $start)
                        $OutputBox.SelectionColor = $currentColor
                        $OutputBox.SelectionBackColor = $currentBackColor
                    }
                    
                    # Clear selection to avoid highlighting and ensure correct scrolling
                    $OutputBox.Select($OutputBox.TextLength, 0)
                }

                $OutputBox.SelectionStart = $OutputBox.TextLength
                $OutputBox.ScrollToCaret()
            }
            catch { }
        }.GetNewClosure()

        $pollTimer = New-Object System.Windows.Forms.Timer
        $pollTimer.Interval = 100
        $pollTimer.Add_Tick({
                $queuedText = New-Object 'System.Collections.Generic.List[string]'
                while ($textQueue.Count -gt 0 -and $queuedText.Count -lt 200) {
                    [void]$queuedText.Add([string]$textQueue.Dequeue())
                }
                & $appendOutput $queuedText.ToArray()

                while ($objectQueue.Count -gt 0) {
                    [void]$resultObjects.Add($objectQueue.Dequeue())
                }

                $queuedErrors = New-Object 'System.Collections.Generic.List[string]'
                while ($errorIndex -lt $powerShellPipeline.Streams.Error.Count -and $queuedErrors.Count -lt 200) {
                    [void]$queuedErrors.Add($powerShellPipeline.Streams.Error[$errorIndex].ToString())
                    $errorIndex++
                }
                & $appendOutput $queuedErrors.ToArray()

                $isComplete = (
                    $asyncResult.IsCompleted -and
                    $textQueue.Count -eq 0 -and
                    $objectQueue.Count -eq 0 -and
                    $errorIndex -ge $powerShellPipeline.Streams.Error.Count
                )

                if ($isComplete) {
                    $pollTimer.Stop()
                    $pollTimer.Dispose()

                    try {
                        [void]$powerShellPipeline.EndInvoke($asyncResult)
                        $taskSucceeded = $true
                    }
                    catch {
                        $message = if ($_.Exception.InnerException) {
                            $_.Exception.InnerException.Message
                        }
                        else {
                            $_.Exception.Message
                        }
                        & $appendOutput @($message)
                    }
                    finally {
                        $powerShellPipeline.Dispose()
                        
                        if ($OutputBox -and $OutputBox.TextLength -gt 0 -and -not $OutputBox.Text.EndsWith("`n")) {
                            $OutputBox.AppendText([Environment]::NewLine)
                            $OutputBox.ScrollToCaret()
                        }

                        & $setControlsEnabled $true

                        if ($Completed) {
                            if ($CollectObjects) {
                                if ($taskSucceeded) {
                                    & $Completed $resultObjects.ToArray()
                                }
                                else {
                                    & $Completed @()
                                }
                            }
                            else {
                                & $Completed
                            }
                        }
                    }
                }
            }.GetNewClosure())
        $pollTimer.Start()
    }

    # ===============================================================================================================================
    # UI factory helpers
    # ===============================================================================================================================

    function New-Size {
        param(
            [int]$Width,
            [int]$Height
        )

        return New-Object System.Drawing.Size($Width, $Height)
    }

    # ===============================================================================================================================

    function New-Point {
        param(
            [int]$X,
            [int]$Y
        )

        return New-Object System.Drawing.Point($X, $Y)
    }

    # ===============================================================================================================================

    function New-Padding {
        param(
            [int]$Left,
            [int]$Top,
            [int]$Right,
            [int]$Bottom
        )

        return New-Object System.Windows.Forms.Padding($Left, $Top, $Right, $Bottom)
    }

    # ===============================================================================================================================

    function New-UiFont {
        param(
            [string[]]$FontNames,
            [float]$Size,
            [System.Drawing.FontStyle]$Style = [System.Drawing.FontStyle]::Regular
        )

        foreach ($fontName in $FontNames) {
            try {
                $fontFamily = New-Object System.Drawing.FontFamily($fontName)
                if ($fontFamily.Name -eq $fontName) {
                    return New-Object System.Drawing.Font($fontName, $Size, $Style)
                }
            }
            catch { }
        }

        return New-Object System.Drawing.Font('Microsoft Sans Serif', $Size, $Style)
    }

    # ===============================================================================================================================

    function New-WinFormsControl {
        param(
            [string]$TypeName,
            [hashtable]$Properties
        )

        $control = New-Object "System.Windows.Forms.$TypeName"
        if ($Properties) {
            foreach ($propertyName in $Properties.Keys) {
                $control.$propertyName = $Properties[$propertyName]
            }
        }

        return $control
    }

    # ===============================================================================================================================

    function Add-ControlTooltip {
        param(
            $Control,
            [string]$Text
        )

        if (-not $Text) {
            return
        }

        $tooltip = $mainToolTip
        $targetControl = $Control
        $tooltipText = $Text

        $targetControl.Add_MouseEnter({
                $tooltip.Show($tooltipText, $targetControl, 0, $targetControl.Height, 5000)
            }.GetNewClosure())

        $targetControl.Add_MouseLeave({
                $tooltip.Hide($targetControl)
            }.GetNewClosure())
    }

    # ===============================================================================================================================
    # Form control constructors
    # ===============================================================================================================================

    function New-FormLabel {
        param(
            [string]$Text,
            [string]$TextAlign = 'MiddleRight'
        )

        return New-WinFormsControl -TypeName 'Label' -Properties @{
            Text      = $Text
            AutoSize  = $false
            Font      = $uiFont
            TextAlign = $TextAlign
        }
    }

    # ===============================================================================================================================

    function New-FormButton {
        param(
            [string]$Text,
            [string]$Tooltip = '',
            [int]$Width = 104,
            [int]$Height = 24
        )

        $button = New-WinFormsControl -TypeName 'Button' -Properties @{
            Text      = $Text
            Font      = $uiFont
            FlatStyle = 'System'
            Enabled   = $true
            Size      = New-Size -Width $Width -Height $Height
        }
        Add-ControlTooltip -Control $button -Text $Tooltip

        return $button
    }

    # ===============================================================================================================================

    function New-FormCheckBox {
        param(
            [string]$Text,
            [string]$Tooltip = '',
            [bool]$AutoSize = $true
        )

        $checkBox = New-WinFormsControl -TypeName 'CheckBox' -Properties @{
            Text         = $Text
            AutoSize     = $AutoSize
            AutoEllipsis = $true
            Font         = $uiFont
            FlatStyle    = 'System'
            TextAlign    = 'MiddleLeft'
        }
        Add-ControlTooltip -Control $checkBox -Text $Tooltip

        return $checkBox
    }

    # ===============================================================================================================================

    function New-FormTextBox {
        param(
            [bool]$ReadOnly = $false,
            [string]$Tooltip = '',
            [string]$Placeholder = '',
            [bool]$UseMonospaceFont = $false
        )

        $selectedFont = if ($UseMonospaceFont) { $inputFont } else { $uiFont }
        $textBox = New-WinFormsControl -TypeName 'TextBox' -Properties @{
            ReadOnly = $ReadOnly
            Font     = $selectedFont
        }

        if ($Placeholder) {
            $textBox.Text = $Placeholder
            $textBox.BackColor = [System.Drawing.Color]::White
            $textBox.Cursor = [System.Windows.Forms.Cursors]::Hand
        }

        Add-ControlTooltip -Control $textBox -Text $Tooltip
        return $textBox
    }

    # ===============================================================================================================================

    function New-FormComboBox {
        param(
            [string]$DisplayMember = 'Label',
            [string]$Tooltip = ''
        )

        $comboBox = New-WinFormsControl -TypeName 'ComboBox' -Properties @{
            Font           = $uiFont
            DropDownStyle  = 'DropDownList'
            DisplayMember  = $DisplayMember
            FlatStyle      = 'Standard'
            IntegralHeight = $false
        }
        Add-ControlTooltip -Control $comboBox -Text $Tooltip

        return $comboBox
    }

    # ===============================================================================================================================

    function New-FormPanel {
        param([int]$Height = 0)

        $dockStyle = if ($Height) { 'Top' } else { 'Fill' }
        $panel = New-WinFormsControl -TypeName 'Panel' -Properties @{
            BackColor = $mainWindow.BackColor
            Dock      = $dockStyle
        }

        if ($Height) {
            $panel.Height = $Height
        }
        else {
            $panel.Padding = New-Padding -Left $uiPadding -Top 0 -Right $uiPadding -Bottom $uiPadding
        }

        return $panel
    }

    # ===============================================================================================================================

    function New-OutputBox {
        return New-WinFormsControl -TypeName 'RichTextBox' -Properties @{
            Multiline   = $true
            ScrollBars  = 'Both'
            Dock        = 'Fill'
            Font        = $outputFont
            ReadOnly    = $true
            WordWrap    = $false
            BorderStyle = 'FixedSingle'
            BackColor   = [System.Drawing.Color]::FromArgb(1, 36, 86)
            ForeColor   = [System.Drawing.Color]::White
        }
    }

    # ===============================================================================================================================

    function New-UrlLinkLabel {
        param([string]$Url)

        $linkLabel = New-WinFormsControl -TypeName 'LinkLabel' -Properties @{
            Text      = $Url
            AutoSize  = $true
            TextAlign = 'MiddleCenter'
            Font      = $uiFont
            Anchor    = 'Top'
        }
        [void]$linkLabel.Links.Add(0, $Url.Length, $Url)
        $linkLabel.Add_LinkClicked({
                try {
                    [System.Diagnostics.Process]::Start([string]$_.Link.LinkData) | Out-Null
                }
                catch { }
            }.GetNewClosure())

        return $linkLabel
    }

    # ===============================================================================================================================
    # Layout measurement utilities
    # ===============================================================================================================================

    function Get-TextWidth {
        param([string]$Text)

        return [int]([System.Windows.Forms.TextRenderer]::MeasureText($Text, $uiFont).Width)
    }

    # ===============================================================================================================================

    function Get-MaxTextWidth {
        param(
            [object[]]$Controls,
            [int]$Minimum = 0,
            [int]$Extra = 0
        )

        $maxWidth = $Minimum
        foreach ($control in @($Controls)) {
            if ($control) {
                $measuredWidth = (Get-TextWidth -Text ([string]$control.Text)) + $Extra
                if ($measuredWidth -gt $maxWidth) {
                    $maxWidth = $measuredWidth
                }
            }
        }

        return $maxWidth
    }

    # ===============================================================================================================================

    function Get-ActionWidth {
        param([object[]]$Controls)

        return (Get-MaxTextWidth -Controls $Controls -Minimum $minimumActionWidth -Extra 26)
    }

    # ===============================================================================================================================

    function Set-LabeledControlBounds {
        param(
            $Label,
            $Control,
            [int]$Top,
            [int]$LabelWidth,
            [int]$ControlLeft,
            [int]$ControlWidth
        )

        $Label.SetBounds($uiPadding, $Top, $LabelWidth, $controlHeight)
        $Control.SetBounds($ControlLeft, $Top, $ControlWidth, $controlHeight)
    }

    # ===============================================================================================================================

    function Set-CheckboxRowBounds {
        param(
            [object[]]$CheckBoxes,
            [int]$Left,
            [int]$Top,
            [int]$Width,
            [int]$Gap = 2
        )

        $items = @()
        foreach ($checkBox in @($CheckBoxes)) {
            if ($checkBox) {
                $items += $checkBox
            }
        }

        if ($items.Count -eq 0) {
            return
        }

        $preferredWidths = @()
        $totalPreferredWidth = 0
        foreach ($checkBox in $items) {
            $preferredWidth = [Math]::Max(36, $checkBox.PreferredSize.Width)
            $preferredWidths += $preferredWidth
            $totalPreferredWidth += $preferredWidth
        }

        if (($totalPreferredWidth + ($Gap * ([Math]::Max(0, $items.Count - 1)))) -gt $Width) {
            $Gap = 0
            $scale = [double]$Width / [double]([Math]::Max(1, $totalPreferredWidth))
        }
        else {
            $scale = 1.0
        }

        $currentLeft = $Left
        for ($index = 0; $index -lt $items.Count; $index++) {
            if ($scale -lt 1.0) {
                $checkBoxWidth = [int][Math]::Floor($preferredWidths[$index] * $scale)
            }
            else {
                $checkBoxWidth = $preferredWidths[$index]
            }

            if ($index -eq ($items.Count - 1)) {
                $checkBoxWidth = ($Left + $Width) - $currentLeft
            }
            if ($checkBoxWidth -lt 1) {
                $checkBoxWidth = 1
            }

            $items[$index].SetBounds($currentLeft, $Top, $checkBoxWidth, $controlHeight)
            $currentLeft += ($checkBoxWidth + $Gap)
        }
    }

    # ===============================================================================================================================

    function Get-CurrentLayoutWidth {
        $layoutWidth = 0

        try {
            if ($mainTabControl -and $mainTabControl.DisplayRectangle.Width -gt 0) {
                $layoutWidth = $mainTabControl.DisplayRectangle.Width
            }
        }
        catch { }

        if ($layoutWidth -le 0) {
            try {
                if ($mainTabControl -and $mainTabControl.ClientSize.Width -gt 0) {
                    $layoutWidth = $mainTabControl.ClientSize.Width
                }
            }
            catch { }
        }

        if ($layoutWidth -le 0) {
            $layoutWidth = $mainWindow.ClientSize.Width
        }

        return [Math]::Max(1, $layoutWidth)
    }

    # ===============================================================================================================================

    function Register-OutputLinks {
        param($OutputBox)

        if (-not $OutputBox) {
            return
        }

        $OutputBox.DetectUrls = $true
        $OutputBox.Add_LinkClicked({
                try {
                    [System.Diagnostics.Process]::Start($_.LinkText) | Out-Null
                }
                catch {
                    Show-ErrorMessage -ErrorObject $_
                }
            })
    }

    # ===============================================================================================================================

    function Set-IntroText {
        param(
            $OutputBox,
            [string]$Text
        )

        $OutputBox.Clear()
        $OutputBox.SelectionColor = [System.Drawing.Color]::White
        $OutputBox.Text = $Text

        $searchIndex = 0
        while ($true) {
            $urlStartIndex = $OutputBox.Text.IndexOf('http', $searchIndex)
            if ($urlStartIndex -eq -1) { break }
            
            $urlEndIndex = $OutputBox.Text.IndexOf("`r", $urlStartIndex)
            if ($urlEndIndex -eq -1) { $urlEndIndex = $OutputBox.Text.IndexOf("`n", $urlStartIndex) }
            if ($urlEndIndex -eq -1) { $urlEndIndex = $OutputBox.Text.IndexOf(" ", $urlStartIndex) }
            if ($urlEndIndex -eq -1) { $urlEndIndex = $OutputBox.Text.Length }
            
            $OutputBox.Select($urlStartIndex, $urlEndIndex - $urlStartIndex)
            $OutputBox.SelectionBackColor = [System.Drawing.Color]::Black
            
            $searchIndex = $urlEndIndex
        }
        $OutputBox.Select($OutputBox.TextLength, 0)
    }

    # ===============================================================================================================================

    function Restore-IntroText {
        $keyCheckerText = "KeyChecker`r`n" +
        "`r`nValidates Microsoft keys (Windows, Office, VS, etc.) from Windows 95 era to present.`r`n" +
        "`r`nAvailable options:" +
        "`r`n  Key Certification - Checks SLCertifyProduct to verify key certification status." +
        "`r`n  Key Activation    - Activates key via SLActivateProduct. Consumes an activation slot." +
        "`r`n  MAK Count         - Queries the remaining MAK activation count." +
        "`r`n  IID               - Retrieves IID using PidGenX.dll." +
        "`r`n  CID               - Retrieves CID using Batch/Visual API. Consumes an activation slot." +
        "`r`n  Logs              - Saves the results to the Desktop.`r`n" +
        "`r`nEnter a key (e.g., NJCF7-PW8QT-3324D-688JX-2YV66) and click Check.`r`n" +
        "`r`nFor more information: $repositoryUrl`r`n"
        Set-IntroText -OutputBox $keyCheckerOutputBox -Text $keyCheckerText

        $iidCidText = "IID/CID Retrieval & Deposit`r`n" +
        "`r`nUpper Section: Manual CID Retrieval" +
        "`r`n  Enter a 50, 54, 59, or 63-digit IID, or select an IID file." +
        "`r`n  Example: 442875505090948411270215934376216135091582729253066826014283446`r`n" +
        "`r`nLower Section: Installed Product Activation" +
        "`r`n  1. Click 'Get IID/CID...' to scan for products." +
        "`r`n  2. Select a product from the list." +
        "`r`n  3. Click 'Deposit CID' to activate it.`r`n" +
        "`r`nLogs: Saves API payloads to the Desktop.`r`n"
        Set-IntroText -OutputBox $iidCidOutputBox -Text $iidCidText

        $readerText = "PKeyConfig Catalog Reader`r`n" +
        "`r`nExtracts metadata from .xrm-ms, .xml, and .xrm catalogs.`r`n" +
        "`r`nFeatures:" +
        "`r`n  - Batch Export: Processes files or directories." +
        "`r`n  - CSV Output: Generates product spreadsheets." +
        "`r`n  - Recursive Search: Finds catalogs in subfolders.`r`n" +
        "`r`nEnter a source path and click Export CSV to begin.`r`n"
        Set-IntroText -OutputBox $readerOutputBox -Text $readerText

        $scanKeysText = "System & File Scanner`r`n" +
        "`r`nScans files or the system for license metadata.`r`n" +
        "`r`nAvailable Scanner Actions:" +
        "`r`n  - Scan Files: Searches for 5x5 keys and DPID blobs." +
        "`r`n  - List of system files containing keys: $homePageUrl/pkeymaster/scan-keys" +
        "`r`n  - Installed Keys: Extracts keys from the SPP trusted store." +
        "`r`n  - Registry: Scans for DPID blobs of Microsoft products." +
        "`r`n  - BIOS/UEFI MSDM: Reads the OEM keys from the firmware.`r`n"
        Set-IntroText -OutputBox $scanKeysOutputBox -Text $scanKeysText
    }

    # ===============================================================================================================================

    function New-ProfileItem {
        param(
            [string]$Label,
            [string]$Mode,
            [string]$Path
        )

        return New-Object PSObject -Property @{
            Label = $Label
            Mode  = $Mode
            Path  = $Path
        }
    }

    # ===============================================================================================================================

    function Get-ProfileItems {
        param([string]$CustomProfilePath = '')

        $items = New-Object System.Collections.ArrayList
        [void]$items.Add((New-ProfileItem -Label 'Automatic detection' -Mode 'Automatic' -Path ''))

        $customLabel = if ($CustomProfilePath) {
            "Custom ... ($([System.IO.Path]::GetFileName($CustomProfilePath)))"
        }
        else {
            'Custom ...'
        }
        [void]$items.Add((New-ProfileItem -Label $customLabel -Mode 'Custom' -Path $CustomProfilePath))

        $systemDirectory = if (Test-Path "$env:SystemRoot\Sysnative\reg.exe") {
            "$env:SystemRoot\Sysnative"
        }
        else {
            "$env:SystemRoot\System32"
        }

        $sppConfig = "$systemDirectory\spp\tokens\pkeyconfig\pkeyconfig.xrm-ms"
        $licensingConfig = "$systemDirectory\licensing\pkeyconfig\pkeyconfig.xrm-ms"
        $systemConfig = if (Test-Path -LiteralPath $sppConfig) {
            $sppConfig
        }
        elseif (Test-Path -LiteralPath $licensingConfig) {
            $licensingConfig
        }
        else {
            ''
        }

        if ($systemConfig) {
            [void]$items.Add((New-ProfileItem -Label 'System' -Mode 'System' -Path $systemConfig))
        }

        [void]$items.Add((New-ProfileItem -Label 'Automatic detection (5x5 keys)' -Mode 'PidGenX' -Path ''))
        [void]$items.Add((New-ProfileItem -Label 'Pre-98 (Windows 95 - NT 4.0 - Office 95-97 - etc)' -Mode 'Pre-98' -Path ''))

        $profileMapPath = Join-Path $Script:ApplicationRoot 'PKeyConfigsMap.csv'
        if (Test-Path -LiteralPath $profileMapPath) {
            try {
                Import-Csv -LiteralPath $profileMapPath | Where-Object {
                    $_.Path -and $_.Path.Trim()
                } | ForEach-Object {
                    $relativePath = $_.Path.TrimStart('\')
                    $configPath = Join-Path $Script:ApplicationRoot ("PKeyConfigs\" + $relativePath)
                    [void]$items.Add((New-ProfileItem -Label $_.Profile.Trim() -Mode 'Catalog' -Path $configPath))
                }
            }
            catch { }
        }

        return $items.ToArray()
    }

    # ===============================================================================================================================

    function Update-ProfileList {
        param(
            [string]$TargetMode = 'Automatic',
            [string]$TargetPath = ''
        )

        $profileState['IsReloading'] = $true
        $profileComboBox.BeginUpdate()

        try {
            $profileComboBox.Items.Clear()
            $profiles = Get-ProfileItems -CustomProfilePath $profileState['CustomPath']
            foreach ($profileItem in $profiles) {
                if ($profileItem) {
                    [void]$profileComboBox.Items.Add($profileItem)
                }
            }

            $selectedIndex = 0
            for ($index = 0; $index -lt $profileComboBox.Items.Count; $index++) {
                $item = $profileComboBox.Items[$index]
                $isMatch = switch ($TargetMode) {
                    'Custom' { ($item.Mode -eq 'Custom') }
                    'Automatic' { ($item.Mode -eq 'Automatic') }
                    'System' { ($item.Mode -eq 'System') }
                    default { ($item.Mode -eq $TargetMode -and $item.Path -eq $TargetPath) }
                }

                if ($isMatch) {
                    $selectedIndex = $index
                    break
                }
            }

            if ($selectedIndex -lt 0 -or $selectedIndex -ge $profileComboBox.Items.Count) {
                $selectedIndex = 0
            }
            if ($profileComboBox.Items.Count -gt 0) {
                $profileComboBox.SelectedIndex = $selectedIndex
            }
        }
        finally {
            $profileComboBox.EndUpdate()
            $profileState['IsReloading'] = $false
        }

        Update-Layout
    }

    # ===============================================================================================================================

    function Update-DepositCidState {
        $selectedProduct = $installedProductsComboBox.SelectedItem
        $confirmationId = if ($selectedProduct) {
            [string]$selectedProduct.CID
        }
        else {
            ''
        }

        $installedProductState['ConfirmationId'] = $confirmationId
        $depositCidButton.Enabled = ($confirmationId -match '^\d+$')
    }

    # ===============================================================================================================================

    function Set-InstalledProducts {
        param($Products)

        $installedProductsComboBox.BeginUpdate()
        try {
            $installedProductsComboBox.Items.Clear()
            foreach ($product in @($Products)) {
                if ($null -ne $product) {
                    [void]$installedProductsComboBox.Items.Add($product)
                }
            }
        }
        finally {
            $installedProductsComboBox.EndUpdate()
        }

        if ($installedProductsComboBox.Items.Count -gt 0) {
            $installedProductsComboBox.SelectedIndex = 0
        }
        else {
            $installedProductState['ConfirmationId'] = ''
        }

        Update-DepositCidState
    }

    # ===============================================================================================================================
    # UI constants
    # ===============================================================================================================================

    $uiFont = New-UiFont -FontNames @('Segoe UI', 'Tahoma') -Size 9.25
    $inputFont = New-UiFont -FontNames @('Consolas', 'Lucida Console', 'Courier New') -Size 10
    $outputFont = New-UiFont -FontNames @('Consolas', 'Lucida Console', 'Courier New') -Size 10
    $titleFont = New-UiFont -FontNames @('Segoe UI', 'Tahoma') -Size 16 -Style ([System.Drawing.FontStyle]::Bold)

    $uiPadding = 10
    $labelGap = 5
    $actionGap = 8
    $controlHeight = 24
    $rowGap = 6
    $rowStep = $controlHeight + $rowGap
    $minimumInputWidth = 120
    $minimumActionWidth = 104

    $defaultKeyFilter = '*.ini,*.txt,*.xml,*.exe,*.dll'
    $defaultDpidFilter = '*.reg,*.bin'

    # ===============================================================================================================================
    # Main window & tab control
    # ===============================================================================================================================

    $mainWindow = New-Object System.Windows.Forms.Form
    $mainWindow.Text = $windowTitle
    $mainWindow.StartPosition = 'CenterScreen'
    $mainWindow.Size = New-Size -Width 688 -Height 660
    $mainWindow.MinimumSize = New-Size -Width 650 -Height 500
    $mainWindow.Font = $uiFont
    $mainWindow.KeyPreview = $true
    $mainWindow.BackColor = [System.Drawing.SystemColors]::Control

    if ([int]$PSVersionTable.PSVersion.Major -le 2) {
        $mainWindow.AutoScaleMode = 'Font'
    }
    else {
        $mainWindow.AutoScaleMode = 'Dpi'
    }

    $applicationIconPath = Resolve-BinaryPath -FileName 'icon.ico'
    if ($applicationIconPath) {
        try {
            $mainWindow.Icon = New-Object System.Drawing.Icon($applicationIconPath)
        }
        catch { }
    }

    $mainToolTip = New-Object System.Windows.Forms.ToolTip
    $mainToolTip.AutoPopDelay = 12000
    $mainToolTip.InitialDelay = 250
    $mainToolTip.ReshowDelay = 150
    $mainToolTip.ShowAlways = $true

    $mainTabControl = New-WinFormsControl -TypeName 'TabControl' -Properties @{
        Dock         = 'Fill'
        Font         = $uiFont
        Padding      = New-Point -X 12 -Y 4
        Appearance   = 'Buttons'
        HotTrack     = $true
        ShowToolTips = $true
    }

    $keyCheckerTabPage = New-WinFormsControl -TypeName 'TabPage' -Properties @{
        Text      = 'KeyChecker'
        BackColor = $mainWindow.BackColor
    }
    $iidCidTabPage = New-WinFormsControl -TypeName 'TabPage' -Properties @{
        Text      = 'IID/CID'
        BackColor = $mainWindow.BackColor
    }
    $readerTabPage = New-WinFormsControl -TypeName 'TabPage' -Properties @{
        Text      = 'PKeyConfigReader'
        BackColor = $mainWindow.BackColor
    }
    $scanKeysTabPage = New-WinFormsControl -TypeName 'TabPage' -Properties @{
        Text      = 'ScanKeys'
        BackColor = $mainWindow.BackColor
    }
    $aboutTabPage = New-WinFormsControl -TypeName 'TabPage' -Properties @{
        Text      = 'Help/About'
        BackColor = $mainWindow.BackColor
    }
    $mainTabControl.TabPages.AddRange(@($keyCheckerTabPage, $iidCidTabPage, $readerTabPage, $scanKeysTabPage, $aboutTabPage))

    $keyCheckerTopPanel = New-FormPanel -Height 135
    $keyLabel = New-FormLabel -Text 'Key'
    $keyTextBox = New-FormTextBox -Tooltip 'Enter a Microsoft product key (Windows, Office, VS, etc.) from Windows 95 era to present.' -UseMonospaceFont $true
    $keyFileLabel = New-FormLabel -Text 'Key File'
    $keyFileTextBox = New-FormTextBox -ReadOnly $true -Tooltip 'Select a file that contains one or more product keys.' -Placeholder $browsePlaceholder
    $profileLabel = New-FormLabel -Text 'Profile'
    $profileComboBox = New-FormComboBox -DisplayMember 'Label' -Tooltip 'Select a PKeyConfig profile to use for validating the key.'
    $certificationCheckBox = New-FormCheckBox -Text 'Key Certification' -Tooltip 'Checks the Microsoft SLCertifyProduct endpoint to confirm whether the key certifies as valid. This does not consume an activation slot. Works with Windows Vista / Office 2010 and later keys.' -AutoSize $false
    $activationCheckBox = New-FormCheckBox -Text 'Key Activation' -Tooltip 'Activates the key via the Microsoft SLActivateProduct endpoint. This consumes an activation slot. Works with Windows Vista / Office 2010 and later keys.' -AutoSize $false
    $makCountCheckBox = New-FormCheckBox -Text 'MAK Count' -Tooltip 'Queries the remaining MAK activation count using the Microsoft BatchActivation endpoint. Works with Windows Vista / Office 2010 and later Volume:MAK keys. The MAK count does not guarantee a key is valid for activation. Check the certification status to verify.' -AutoSize $false
    $installationIdCheckBox = New-FormCheckBox -Text 'IID' -Tooltip 'Retrieves the Installation ID using PidGenX.dll. Works with PKey2005/2009 keys.' -AutoSize $false
    $confirmationIdCheckBox = New-FormCheckBox -Text 'CID' -Tooltip 'Retrieves the Confirmation ID using the Microsoft BatchApi, fallbacks to VisualApi. This consumes an activation slot. Works with Windows Vista / Office 2010 and later keys.' -AutoSize $false
    $keyLogsCheckBox = New-FormCheckBox -Text 'Logs' -Tooltip 'Saves the result files and the request and response logs to the PKeyMaster-Logs folder on the Desktop.' -AutoSize $false
    $checkKeyButton = New-FormButton -Text 'Check' -Tooltip 'Checks the key using the selected profile and options.'
    $keyCheckerTopPanel.Controls.AddRange(@($keyLabel, $keyTextBox, $keyFileLabel, $keyFileTextBox, $profileLabel, $profileComboBox, $certificationCheckBox, $activationCheckBox, $makCountCheckBox, $installationIdCheckBox, $confirmationIdCheckBox, $keyLogsCheckBox, $checkKeyButton))

    $keyCheckerBottomPanel = New-FormPanel
    $keyCheckerOutputBox = New-OutputBox
    $keyCheckerBottomPanel.Controls.Add($keyCheckerOutputBox)
    $keyCheckerTabPage.Controls.AddRange(@($keyCheckerBottomPanel, $keyCheckerTopPanel))

    $iidCidTopPanel = New-FormPanel -Height 180
    $installationIdLabel = New-FormLabel -Text 'IID'
    $installationIdTextBox = New-FormTextBox -Tooltip 'Enter a 50, 54, 59, or 63-digit Installation ID.' -UseMonospaceFont $true
    $installationIdFileLabel = New-FormLabel -Text 'IID File'
    $installationIdFileTextBox = New-FormTextBox -ReadOnly $true -Tooltip 'Select a text file that contains one or more 50, 54, 59, or 63-digit Installation IDs.' -Placeholder $browsePlaceholder
    $manualCidLogsCheckBox = New-FormCheckBox -Text 'CID Logs' -Tooltip 'Saves the result files and the request and response logs to the PKeyMaster-Logs folder on the Desktop.' -AutoSize $false
    $installedProductLogsCheckBox = New-FormCheckBox -Text 'CID Logs' -Tooltip 'Saves the result files and the request and response logs to the PKeyMaster-Logs folder on the Desktop.' -AutoSize $false
    $getCidButton = New-FormButton -Text 'Get CID' -Tooltip 'Retrieves the Confirmation ID using the Microsoft BatchApi, fallbacks to VisualApi. This consumes an activation slot. Works with all kinds of CID supported Windows and Office products.'
    $iidCidSeparator = New-WinFormsControl -TypeName 'Label' -Properties @{ AutoSize = $false; BorderStyle = 'Fixed3D' }
    $installedProductListLabel = New-FormLabel -Text 'List'
    $installedProductsComboBox = New-FormComboBox -DisplayMember 'DisplayName' -Tooltip 'Shows installed, unactivated Windows and Office products where the installed key supports phone (CID) activation.'
    $populateInstalledProductsButton = New-FormButton -Text 'Get IID/CID of Unactivated Products' -Tooltip 'Retrieves the IID/CID of installed, unactivated Windows and Office products where the installed keys support phone (CID) activation. This consumes an activation slot.' -Width 240
    $depositCidButton = New-FormButton -Text 'Deposit CID' -Tooltip 'Deposits the current Confirmation ID into the selected installed Windows or Office product.'
    $depositCidButton.Enabled = $false
    $iidCidTopPanel.Controls.AddRange(@($installationIdLabel, $installationIdTextBox, $installationIdFileLabel, $installationIdFileTextBox, $manualCidLogsCheckBox, $getCidButton, $iidCidSeparator, $installedProductListLabel, $installedProductsComboBox, $installedProductLogsCheckBox, $populateInstalledProductsButton, $depositCidButton))

    $iidCidBottomPanel = New-FormPanel
    $iidCidOutputBox = New-OutputBox
    $iidCidBottomPanel.Controls.Add($iidCidOutputBox)
    $iidCidTabPage.Controls.AddRange(@($iidCidBottomPanel, $iidCidTopPanel))

    $readerTopPanel = New-FormPanel -Height 84
    $readerFileLabel = New-FormLabel -Text 'File'
    $readerFileTextBox = New-FormTextBox -ReadOnly $true -Tooltip 'Select a PKeyConfig file (.xrm-ms, .xml, or .xrm) to export as CSV.' -Placeholder $browsePlaceholder
    $readerFolderLabel = New-FormLabel -Text 'Folder'
    $readerFolderTextBox = New-FormTextBox -ReadOnly $true -Tooltip 'Select a folder containing PKeyConfig files to export as CSV.' -Placeholder $browsePlaceholder
    $readerRecurseCheckBox = New-FormCheckBox -Text 'Recurse' -Tooltip 'When checked, searches subfolders recursively for PKeyConfig files.' -AutoSize $false
    $exportCsvButton = New-FormButton -Text 'Export CSV' -Tooltip 'Exports the selected PKeyConfig files to CSV format under the PKeyMaster-Logs folder on the Desktop.'
    $readerTopPanel.Controls.AddRange(@($readerFileLabel, $readerFileTextBox, $readerFolderLabel, $readerFolderTextBox, $readerRecurseCheckBox, $exportCsvButton))

    $readerBottomPanel = New-FormPanel
    $readerOutputBox = New-OutputBox
    $readerBottomPanel.Controls.Add($readerOutputBox)
    $readerTabPage.Controls.AddRange(@($readerBottomPanel, $readerTopPanel))

    $scanKeysTopPanel = New-FormPanel -Height 160
    $scanFileLabel = New-FormLabel -Text 'File'
    $scanFileTextBox = New-FormTextBox -ReadOnly $true -Tooltip 'Select a file to scan for product keys or Digital Product IDs.' -Placeholder $browsePlaceholder
    $scanFolderLabel = New-FormLabel -Text 'Folder'
    $scanFolderTextBox = New-FormTextBox -ReadOnly $true -Tooltip 'Select a folder to scan for product keys or Digital Product IDs.' -Placeholder $browsePlaceholder
    $scanFilterLabel = New-FormLabel -Text 'Filter'
    $scanFilterTextBox = New-FormTextBox -Tooltip 'Comma-separated list of wildcard file patterns to include when scanning a folder. Clear to scan all files.'
    $scanFilterTextBox.Text = $defaultKeyFilter
    $scanFilterTextBox.BackColor = [System.Drawing.Color]::White
    $scanRecurseCheckBox = New-FormCheckBox -Text 'Recurse' -Tooltip 'When checked, searches subfolders recursively.' -AutoSize $false
    $scanKeyCheckBox = New-FormCheckBox -Text 'Key' -Tooltip 'Scans files for product keys.' -AutoSize $false
    $scanKeyCheckBox.Checked = $true
    $scanDpidCheckBox = New-FormCheckBox -Text 'DPID' -Tooltip 'Scans files for Digital Product ID (DPID) blobs.' -AutoSize $false
    $scanLogsCheckBox = New-FormCheckBox -Text 'Logs' -Tooltip 'Saves the scan results to log files on the Desktop.' -AutoSize $false
    $scanButton = New-FormButton -Text 'Scan' -Tooltip 'Scans the selected file or folder for product keys or Digital Product IDs.'
    $scanKeysSeparator = New-WinFormsControl -TypeName 'Label' -Properties @{ AutoSize = $false; BorderStyle = 'Fixed3D' }
    $scanInstalledKeysButton = New-FormButton -Text 'Get Installed Windows/Office Keys' -Tooltip 'Retrieves the installed Windows and Office product keys from the SPP trusted store.' -Width 190
    $scanWindowsRegistryButton = New-FormButton -Text 'Get Windows Keys From Registry' -Tooltip 'Extracts the Windows product keys from the registry Digital Product ID blobs.' -Width 190
    $scanOfficeRegistryButton = New-FormButton -Text 'Get Office Keys From Registry' -Tooltip 'Extracts the Office (MSI version) product keys from the registry Digital Product ID blobs.' -Width 190
    $scanOtherRegistryButton = New-FormButton -Text 'Get Other Product Keys From Registry' -Tooltip 'Scans the registry for product keys from other Microsoft products.' -Width 190
    $scanMsdmButton = New-FormButton -Text 'Get MSDM (BIOS/UEFI) Key' -Tooltip 'Reads the OEM product key embedded in the BIOS/UEFI MSDM table.' -Width 190
    $scanKeysTopPanel.Controls.AddRange(@($scanFileLabel, $scanFileTextBox, $scanFolderLabel, $scanFolderTextBox, $scanFilterLabel, $scanFilterTextBox, $scanRecurseCheckBox, $scanKeyCheckBox, $scanDpidCheckBox, $scanLogsCheckBox, $scanButton, $scanKeysSeparator, $scanInstalledKeysButton, $scanWindowsRegistryButton, $scanOfficeRegistryButton, $scanOtherRegistryButton, $scanMsdmButton))

    $scanKeysBottomPanel = New-FormPanel
    $scanKeysOutputBox = New-OutputBox
    $scanKeysBottomPanel.Controls.Add($scanKeysOutputBox)
    $scanKeysTabPage.Controls.AddRange(@($scanKeysBottomPanel, $scanKeysTopPanel))

    $aboutLayout = New-WinFormsControl -TypeName 'TableLayoutPanel' -Properties @{
        Dock        = 'Fill'
        ColumnCount = 3
        RowCount    = 7
    }
    [void]$aboutLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
    [void]$aboutLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$aboutLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
    [void]$aboutLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 50)))
    [void]$aboutLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$aboutLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$aboutLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$aboutLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$aboutLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$aboutLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 50)))

    $aboutIconBox = New-WinFormsControl -TypeName 'PictureBox' -Properties @{
        SizeMode = 'AutoSize'
        Anchor   = 'Bottom'
        Margin   = New-Padding -Left 0 -Top 0 -Right 0 -Bottom 10
    }
    if ($applicationIconPath) {
        try {
            $largeIcon = New-Object System.Drawing.Icon($applicationIconPath, 64, 64)
            $aboutIconBox.Image = $largeIcon.ToBitmap()
        }
        catch {
            try {
                $aboutIconBox.Image = [System.Drawing.Icon]::ExtractAssociatedIcon($applicationIconPath).ToBitmap()
            }
            catch { }
        }
    }

    $aboutTitleLabel = New-WinFormsControl -TypeName 'Label' -Properties @{
        Text      = 'PKeyMaster'
        Font      = $titleFont
        AutoSize  = $true
        TextAlign = 'MiddleCenter'
        Anchor    = 'Bottom'
        Margin    = New-Padding -Left 0 -Top 0 -Right 0 -Bottom 5
    }
    $aboutDescriptionLabel = New-WinFormsControl -TypeName 'Label' -Properties @{
        Text      = 'An open-source toolkit for Microsoft product key validation, CID retrieval, and advanced key scanning.'
        Font      = $uiFont
        AutoSize  = $true
        TextAlign = 'MiddleCenter'
        Anchor    = 'Bottom'
        Margin    = New-Padding -Left 0 -Top 0 -Right 0 -Bottom 15
    }
    $repositoryLinkLabel = New-UrlLinkLabel -Url $repositoryUrl
    $homePageLinkLabel = New-UrlLinkLabel -Url $homePageUrl

    $aboutLayout.Controls.Add($aboutIconBox, 1, 1)
    $aboutLayout.Controls.Add($aboutTitleLabel, 1, 2)
    $aboutLayout.Controls.Add($aboutDescriptionLabel, 1, 3)
    $aboutLayout.Controls.Add($repositoryLinkLabel, 1, 4)
    $aboutLayout.Controls.Add($homePageLinkLabel, 1, 5)
    $aboutTabPage.Controls.Add($aboutLayout)

    $mainWindow.Controls.Add($mainTabControl)

    # ===============================================================================================================================
    # Dynamic layout
    # ===============================================================================================================================

    function Update-Layout {
        $layoutWidth = Get-CurrentLayoutWidth

        $keyRow1Top = $uiPadding
        $keyRow2Top = $keyRow1Top + $rowStep
        $keyRow3Top = $keyRow2Top + $rowStep
        $keyRow4Top = $keyRow3Top + $rowStep
        $keyLabelWidth = Get-MaxTextWidth -Controls @($keyLabel, $keyFileLabel, $profileLabel) -Minimum 55 -Extra 6
        $checkKeyButtonWidth = Get-ActionWidth -Controls @($checkKeyButton)
        $keyInputLeft = $uiPadding + $keyLabelWidth + $labelGap
        $checkKeyButtonLeft = $layoutWidth - $uiPadding - $checkKeyButtonWidth
        $keyInputWidth = [Math]::Max($minimumInputWidth, ($checkKeyButtonLeft - $keyInputLeft - $actionGap))

        Set-LabeledControlBounds -Label $keyLabel -Control $keyTextBox -Top $keyRow1Top -LabelWidth $keyLabelWidth -ControlLeft $keyInputLeft -ControlWidth $keyInputWidth
        Set-LabeledControlBounds -Label $keyFileLabel -Control $keyFileTextBox -Top $keyRow2Top -LabelWidth $keyLabelWidth -ControlLeft $keyInputLeft -ControlWidth $keyInputWidth
        Set-LabeledControlBounds -Label $profileLabel -Control $profileComboBox -Top $keyRow3Top -LabelWidth $keyLabelWidth -ControlLeft $keyInputLeft -ControlWidth $keyInputWidth
        $checkKeyButton.SetBounds($checkKeyButtonLeft, $keyRow3Top, $checkKeyButtonWidth, $controlHeight)
        Set-CheckboxRowBounds -CheckBoxes @($certificationCheckBox, $activationCheckBox, $makCountCheckBox, $installationIdCheckBox, $confirmationIdCheckBox, $keyLogsCheckBox) -Left $keyInputLeft -Top $keyRow4Top -Width $keyInputWidth -Gap 2

        $iidRow1Top = $uiPadding
        $iidRow2Top = $iidRow1Top + $rowStep
        $iidRow3Top = $iidRow2Top + $rowStep
        $iidSeparatorTop = $iidRow3Top + $controlHeight + $actionGap
        $iidRow4Top = $iidSeparatorTop + $uiPadding
        $iidRow5Top = $iidRow4Top + $rowStep
        $iidLabelWidth = Get-MaxTextWidth -Controls @($installationIdLabel, $installationIdFileLabel, $installedProductListLabel) -Minimum 55 -Extra 6
        $iidInputLeft = $uiPadding + $iidLabelWidth + $labelGap
        $getCidButtonWidth = Get-ActionWidth -Controls @($getCidButton, $depositCidButton)
        $populateButtonWidth = Get-ActionWidth -Controls @($populateInstalledProductsButton)
        $depositButtonLeft = $layoutWidth - $uiPadding - $getCidButtonWidth
        $populateButtonLeft = $depositButtonLeft - $actionGap - $populateButtonWidth
        $iidInputWidth = [Math]::Max($minimumInputWidth, ($layoutWidth - $uiPadding - $iidInputLeft))

        Set-LabeledControlBounds -Label $installationIdLabel -Control $installationIdTextBox -Top $iidRow1Top -LabelWidth $iidLabelWidth -ControlLeft $iidInputLeft -ControlWidth $iidInputWidth
        Set-LabeledControlBounds -Label $installationIdFileLabel -Control $installationIdFileTextBox -Top $iidRow2Top -LabelWidth $iidLabelWidth -ControlLeft $iidInputLeft -ControlWidth $iidInputWidth
        $manualLogWidth = (Get-TextWidth -Text $manualCidLogsCheckBox.Text) + 18
        $manualCidLogsCheckBox.SetBounds(($depositButtonLeft - $actionGap - $manualLogWidth), $iidRow3Top, $manualLogWidth, $controlHeight)
        $getCidButton.SetBounds($depositButtonLeft, $iidRow3Top, $getCidButtonWidth, $controlHeight)
        $iidCidSeparator.SetBounds($uiPadding, $iidSeparatorTop, ([Math]::Max($minimumInputWidth, ($layoutWidth - ($uiPadding * 2)))), 2)
        Set-LabeledControlBounds -Label $installedProductListLabel -Control $installedProductsComboBox -Top $iidRow4Top -LabelWidth $iidLabelWidth -ControlLeft $iidInputLeft -ControlWidth $iidInputWidth
        $installedLogWidth = (Get-TextWidth -Text $installedProductLogsCheckBox.Text) + 18
        $installedProductLogsCheckBox.SetBounds(($populateButtonLeft - $actionGap - $installedLogWidth), $iidRow5Top, $installedLogWidth, $controlHeight)
        $populateInstalledProductsButton.SetBounds($populateButtonLeft, $iidRow5Top, $populateButtonWidth, $controlHeight)
        $depositCidButton.SetBounds($depositButtonLeft, $iidRow5Top, $getCidButtonWidth, $controlHeight)

        $readerRow1Top = $uiPadding
        $readerRow2Top = $readerRow1Top + $rowStep
        $readerLabelWidth = Get-MaxTextWidth -Controls @($readerFileLabel, $readerFolderLabel) -Minimum 55 -Extra 6
        $readerInputLeft = $uiPadding + $readerLabelWidth + $labelGap
        $readerButtonWidth = Get-ActionWidth -Controls @($exportCsvButton)
        $readerButtonLeft = $layoutWidth - $uiPadding - $readerButtonWidth
        $readerInputWidth = [Math]::Max($minimumInputWidth, ($readerButtonLeft - $readerInputLeft - $actionGap))

        Set-LabeledControlBounds -Label $readerFileLabel -Control $readerFileTextBox -Top $readerRow1Top -LabelWidth $readerLabelWidth -ControlLeft $readerInputLeft -ControlWidth $readerInputWidth
        Set-LabeledControlBounds -Label $readerFolderLabel -Control $readerFolderTextBox -Top $readerRow2Top -LabelWidth $readerLabelWidth -ControlLeft $readerInputLeft -ControlWidth $readerInputWidth
        $readerRecurseCheckBox.SetBounds($readerButtonLeft, $readerRow1Top, $readerButtonWidth, $controlHeight)
        $exportCsvButton.SetBounds($readerButtonLeft, $readerRow2Top, $readerButtonWidth, $controlHeight)

        $scanPanelWidth = $layoutWidth
        $scanPanelHeight = $scanKeysTopPanel.Height
        $scanSeparatorLeft = [int][Math]::Floor($scanPanelWidth / 2) - 1
        $scanKeysSeparator.SetBounds($scanSeparatorLeft, $uiPadding, 2, ([Math]::Max(2, ($scanPanelHeight - ($uiPadding * 2)))))

        $scanRightColumnLeft = $scanSeparatorLeft + 2 + $uiPadding
        $scanRightColumnWidth = [Math]::Max(1, ($scanPanelWidth - $uiPadding - $scanRightColumnLeft))
        $scanRow1Top = $uiPadding
        $scanRow2Top = $scanRow1Top + $rowStep
        $scanRow3Top = $scanRow2Top + $rowStep
        $scanRow4Top = $scanRow3Top + $rowStep
        $scanRow5Top = $scanRow4Top + $rowStep

        $scanInstalledKeysButton.SetBounds($scanRightColumnLeft, $scanRow1Top, $scanRightColumnWidth, $controlHeight)
        $scanWindowsRegistryButton.SetBounds($scanRightColumnLeft, $scanRow2Top, $scanRightColumnWidth, $controlHeight)
        $scanOfficeRegistryButton.SetBounds($scanRightColumnLeft, $scanRow3Top, $scanRightColumnWidth, $controlHeight)
        $scanOtherRegistryButton.SetBounds($scanRightColumnLeft, $scanRow4Top, $scanRightColumnWidth, $controlHeight)
        $scanMsdmButton.SetBounds($scanRightColumnLeft, $scanRow5Top, $scanRightColumnWidth, $controlHeight)

        $scanLabelWidth = Get-MaxTextWidth -Controls @($scanFileLabel, $scanFolderLabel, $scanFilterLabel) -Minimum 55 -Extra 6
        $scanInputLeft = $uiPadding + $scanLabelWidth + $labelGap
        $scanInputWidth = [Math]::Max($minimumInputWidth, (($scanSeparatorLeft - $actionGap) - $scanInputLeft))
        Set-LabeledControlBounds -Label $scanFileLabel -Control $scanFileTextBox -Top $scanRow1Top -LabelWidth $scanLabelWidth -ControlLeft $scanInputLeft -ControlWidth $scanInputWidth
        Set-LabeledControlBounds -Label $scanFolderLabel -Control $scanFolderTextBox -Top $scanRow2Top -LabelWidth $scanLabelWidth -ControlLeft $scanInputLeft -ControlWidth $scanInputWidth
        Set-LabeledControlBounds -Label $scanFilterLabel -Control $scanFilterTextBox -Top $scanRow3Top -LabelWidth $scanLabelWidth -ControlLeft $scanInputLeft -ControlWidth $scanInputWidth
        Set-CheckboxRowBounds -CheckBoxes @($scanKeyCheckBox, $scanDpidCheckBox, $scanRecurseCheckBox, $scanLogsCheckBox) -Left $scanInputLeft -Top $scanRow4Top -Width $scanInputWidth -Gap 2
        $scanButton.SetBounds($scanInputLeft, $scanRow5Top, $scanInputWidth, $controlHeight)

        $visibleProfiles = [Math]::Min(25, ([Math]::Max(1, $profileComboBox.Items.Count)))
        $profileComboBox.DropDownHeight = [Math]::Min(600, ([Math]::Max(140, (($visibleProfiles * ([Math]::Max(18, $profileComboBox.ItemHeight))) + 12))))
        $profileComboBox.MaxDropDownItems = $visibleProfiles
        $profileComboBox.DropDownWidth = $profileComboBox.Width
    }

    # ===============================================================================================================================
    # Output links & state
    # ===============================================================================================================================

    Register-OutputLinks -OutputBox $keyCheckerOutputBox
    Register-OutputLinks -OutputBox $iidCidOutputBox
    Register-OutputLinks -OutputBox $readerOutputBox
    Register-OutputLinks -OutputBox $scanKeysOutputBox

    $profileState = @{
        CustomPath  = ''
        LastMode    = 'Automatic'
        LastPath    = ''
        IsReloading = $false
    }
    $installedProductState = @{
        ConfirmationId = ''
    }

    # ===============================================================================================================================
    # Form event handlers
    # ===============================================================================================================================

    $mainWindow.Add_Shown({
            Update-Layout
            Update-ProfileList -TargetMode 'Automatic'
            Restore-IntroText
        })
    $mainWindow.Add_Resize({
            Update-Layout
        })
    $mainTabControl.Add_SelectedIndexChanged({
            Update-Layout
        })
    $mainWindow.Add_KeyDown({
            if ($_.KeyCode -eq 'Enter' -and -not $_.Alt -and -not $_.Control) {
                if ($mainTabControl.SelectedTab -eq $iidCidTabPage -and $getCidButton.Enabled) {
                    $getCidButton.PerformClick()
                    $_.SuppressKeyPress = $true
                }
                elseif ($mainTabControl.SelectedTab -eq $keyCheckerTabPage -and $checkKeyButton.Enabled) {
                    $checkKeyButton.PerformClick()
                    $_.SuppressKeyPress = $true
                }
            }
        })

    $activationCheckBox.Add_Click({
            if ($activationCheckBox.Checked -and -not (Confirm-ActivationSlotUse)) {
                $activationCheckBox.Checked = $false
            }
        })
    $confirmationIdCheckBox.Add_Click({
            if ($confirmationIdCheckBox.Checked -and -not (Confirm-ActivationSlotUse)) {
                $confirmationIdCheckBox.Checked = $false
            }
        })

    $keyFileTextBox.Add_MouseDown({
            Invoke-UiAction {
                $dialog = New-Object System.Windows.Forms.OpenFileDialog
                $dialog.Filter = 'Key files (*.ini;*.txt;*.xml;*.exe;*.dll)|*.ini;*.txt;*.xml;*.exe;*.dll|All files (*.*)|*.*'
                if ((Show-OwnedDialog -Dialog $dialog -OwnerWindow $mainWindow) -eq [System.Windows.Forms.DialogResult]::OK) {
                    $keyFileTextBox.Text = $dialog.FileName
                    $keyTextBox.Text = ''
                }
            }
        })
    $keyTextBox.Add_TextChanged({
            if ($keyTextBox.Text.Length -gt 0 -and (Test-SelectedPathText -PathText $keyFileTextBox.Text)) {
                $keyFileTextBox.Text = $browsePlaceholder
            }
        })
    $profileComboBox.Add_SelectionChangeCommitted({
            Invoke-UiAction {
                if ($profileState['IsReloading']) {
                    return
                }

                $selectedProfile = $profileComboBox.SelectedItem
                if (-not $selectedProfile) {
                    return
                }

                if ($selectedProfile.Mode -eq 'Custom') {
                    $dialog = New-Object System.Windows.Forms.OpenFileDialog
                    $dialog.Filter = 'Pkeyconfig files (*.xrm-ms;*.xml;*.xrm)|*.xrm-ms;*.xml;*.xrm|All files (*.*)|*.*'
                    $dialog.InitialDirectory = if ($profileState['CustomPath']) {
                        Split-Path -Parent $profileState['CustomPath']
                    }
                    else {
                        Get-DefaultConfigRoot
                    }

                    if ((Show-OwnedDialog -Dialog $dialog -OwnerWindow $mainWindow) -eq [System.Windows.Forms.DialogResult]::OK) {
                        $profileState['CustomPath'] = [System.IO.Path]::GetFullPath($dialog.FileName)
                        $profileState['LastMode'] = 'Custom'
                        $profileState['LastPath'] = $profileState['CustomPath']
                        Update-ProfileList -TargetMode 'Custom' -TargetPath $profileState['CustomPath']
                    }
                    elseif ($profileState['CustomPath']) {
                        return
                    }
                    else {
                        Update-ProfileList -TargetMode $profileState['LastMode'] -TargetPath $profileState['LastPath']
                    }
                    return
                }

                $profileState['LastMode'] = $selectedProfile.Mode
                $profileState['LastPath'] = $selectedProfile.Path
            }
        })

    $checkKeyButton.Add_Click({
            Invoke-UiAction {
                $arguments = @{}

                if (Test-SelectedPathText -PathText $keyFileTextBox.Text) {
                    $arguments['KeyFile'] = [System.IO.Path]::GetFullPath($keyFileTextBox.Text)
                }
                else {
                    $arguments['ProductKey'] = $keyTextBox.Text
                }

                if ($profileComboBox.SelectedItem) {
                    $selectedProfile = $profileComboBox.SelectedItem
                    if ($selectedProfile.Mode -eq 'Catalog' -or $selectedProfile.Mode -eq 'Custom' -or $selectedProfile.Mode -eq 'System') {
                        $arguments['KeyCheckMode'] = 'PidGenX'
                        if ($selectedProfile.Path) {
                            $arguments['PKeyConfigPath'] = $selectedProfile.Path
                            if ($selectedProfile.Mode -eq 'Catalog' -or $selectedProfile.Mode -eq 'System') {
                                $arguments['ProfileName'] = $selectedProfile.Label
                            }
                        }
                    }
                    else {
                        $arguments['KeyCheckMode'] = $selectedProfile.Mode
                    }
                }

                if ($certificationCheckBox.Checked) { $arguments['KeyCertification'] = $true }
                if ($activationCheckBox.Checked) { $arguments['KeyActivation'] = $true }
                if ($makCountCheckBox.Checked) { $arguments['MAKCount'] = $true }
                if ($confirmationIdCheckBox.Checked) {
                    $arguments['GetInstallationId'] = $true
                    $arguments['GetConfirmationId'] = $true
                }
                elseif ($installationIdCheckBox.Checked) {
                    $arguments['GetInstallationId'] = $true
                }
                if ($keyLogsCheckBox.Checked) { $arguments['ExportLogs'] = $true }

                $keyCheckerControls = @(
                    $keyTextBox,
                    $keyFileTextBox,
                    $profileComboBox,
                    $certificationCheckBox,
                    $activationCheckBox,
                    $makCountCheckBox,
                    $installationIdCheckBox,
                    $confirmationIdCheckBox,
                    $keyLogsCheckBox,
                    $checkKeyButton
                )
                Start-ToolTask -ScriptName 'KeyChecker.ps1' -Arguments $arguments -OutputBox $keyCheckerOutputBox -ControlsToDisable $keyCheckerControls -Completed $null
            }
        })

    $installationIdFileTextBox.Add_MouseDown({
            Invoke-UiAction {
                $dialog = New-Object System.Windows.Forms.OpenFileDialog
                $dialog.Filter = 'Text files (*.txt)|*.txt|All files (*.*)|*.*'
                if ((Show-OwnedDialog -Dialog $dialog -OwnerWindow $mainWindow) -eq [System.Windows.Forms.DialogResult]::OK) {
                    $installationIdFileTextBox.Text = $dialog.FileName
                    $installationIdTextBox.Text = ''
                }
            }
        })
    $installationIdTextBox.Add_TextChanged({
            if ($installationIdTextBox.Text.Length -gt 0 -and (Test-SelectedPathText -PathText $installationIdFileTextBox.Text)) {
                $installationIdFileTextBox.Text = $browsePlaceholder
            }
        })
    $installedProductsComboBox.Add_SelectedIndexChanged({
            Update-DepositCidState
        })

    $iidCidTaskControls = @(
        $installationIdTextBox,
        $installationIdFileTextBox,
        $manualCidLogsCheckBox,
        $getCidButton,
        $populateInstalledProductsButton,
        $installedProductsComboBox,
        $installedProductLogsCheckBox
    )

    $getCidButton.Add_Click({
            Invoke-UiAction {
                if (-not (Confirm-ActivationSlotUse)) {
                    return
                }

                $arguments = @{}
                if (Test-SelectedPathText -PathText $installationIdFileTextBox.Text) {
                    $arguments['IidFile'] = [System.IO.Path]::GetFullPath($installationIdFileTextBox.Text)
                }
                else {
                    $arguments['InstallationId'] = $installationIdTextBox.Text.Trim()
                }
                if ($manualCidLogsCheckBox.Checked) {
                    $arguments['ExportLogs'] = $true
                }

                Start-ToolTask -ScriptName 'GetCID.ps1' -Arguments $arguments -OutputBox $iidCidOutputBox -ControlsToDisable $iidCidTaskControls -Completed { Update-DepositCidState }
            }
        })

    $populateInstalledProductsButton.Add_Click({
            Invoke-UiAction {
                if (-not (Confirm-ActivationSlotUse)) {
                    return
                }

                $arguments = @{ PassThru = $true }
                if ($installedProductLogsCheckBox.Checked) {
                    $arguments['ExportLogs'] = $true
                }

                $completed = {
                    param($Products)
                    Set-InstalledProducts -Products $Products
                }
                Start-ToolTask -ScriptName 'GetIidCid.ps1' -Arguments $arguments -OutputBox $iidCidOutputBox -ControlsToDisable $iidCidTaskControls -Completed $completed -CollectObjects
            }
        })

    $depositCidButton.Add_Click({
            Invoke-UiAction {
                $selectedProduct = $installedProductsComboBox.SelectedItem
                $arguments = @{
                    ClassName      = if ($selectedProduct) { [string]$selectedProduct.ClassName } else { '' }
                    ActivationId   = if ($selectedProduct) { [string]$selectedProduct.Id } else { '' }
                    InstallationId = if ($selectedProduct) { [string]$selectedProduct.InstallationId } else { '' }
                    ConfirmationId = [string]$installedProductState['ConfirmationId']
                }

                Start-ToolTask -ScriptName 'DepositCID.ps1' -Arguments $arguments -OutputBox $iidCidOutputBox -ControlsToDisable $iidCidTaskControls -Completed { Update-DepositCidState }
            }
        })

    $readerFileTextBox.Add_MouseDown({
            Invoke-UiAction {
                $dialog = New-Object System.Windows.Forms.OpenFileDialog
                $dialog.Filter = 'Pkeyconfig files (*.xrm-ms;*.xml;*.xrm)|*.xrm-ms;*.xml;*.xrm|All files (*.*)|*.*'
                $dialog.InitialDirectory = Get-DefaultConfigRoot
                if ((Show-OwnedDialog -Dialog $dialog -OwnerWindow $mainWindow) -eq [System.Windows.Forms.DialogResult]::OK) {
                    $readerFileTextBox.Text = [System.IO.Path]::GetFullPath($dialog.FileName)
                    $readerFolderTextBox.Text = $browsePlaceholder
                }
            }
        })
    $readerFolderTextBox.Add_MouseDown({
            Invoke-UiAction {
                $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
                $dialog.Description = 'Select a folder containing PKeyConfig files'
                $dialog.SelectedPath = Get-DefaultConfigRoot
                if ((Show-OwnedDialog -Dialog $dialog -OwnerWindow $mainWindow) -eq [System.Windows.Forms.DialogResult]::OK) {
                    $readerFolderTextBox.Text = [System.IO.Path]::GetFullPath($dialog.SelectedPath)
                    $readerFileTextBox.Text = $browsePlaceholder
                }
            }
        })
    $exportCsvButton.Add_Click({
            Invoke-UiAction {
                $arguments = @{}
                $filePath = $readerFileTextBox.Text.Trim()
                $folderPath = $readerFolderTextBox.Text.Trim()

                if (Test-SelectedPathText -PathText $filePath) {
                    $arguments['File'] = $filePath
                }
                elseif (Test-SelectedPathText -PathText $folderPath) {
                    $arguments['Folder'] = $folderPath
                }
                if ($readerRecurseCheckBox.Checked) {
                    $arguments['Recurse'] = $true
                }

                $readerTaskControls = @($readerFileTextBox, $readerFolderTextBox, $readerRecurseCheckBox, $exportCsvButton)
                Start-ToolTask -ScriptName 'PKeyConfigReader.ps1' -Arguments $arguments -OutputBox $readerOutputBox -ControlsToDisable $readerTaskControls -Completed $null
            }
        })

    $scanKeyCheckBox.Add_Click({
            if ($scanKeyCheckBox.Checked) {
                $scanDpidCheckBox.Checked = $false
                $scanFilterTextBox.Text = $defaultKeyFilter
            }
            elseif (-not $scanDpidCheckBox.Checked) {
                $scanKeyCheckBox.Checked = $true
                $scanFilterTextBox.Text = $defaultKeyFilter
            }
        })
    $scanDpidCheckBox.Add_Click({
            if ($scanDpidCheckBox.Checked) {
                $scanKeyCheckBox.Checked = $false
                $scanFilterTextBox.Text = $defaultDpidFilter
            }
            elseif (-not $scanKeyCheckBox.Checked) {
                $scanDpidCheckBox.Checked = $true
                $scanFilterTextBox.Text = $defaultDpidFilter
            }
        })

    $scanFileTextBox.Add_MouseDown({
            Invoke-UiAction {
                $dialog = New-Object System.Windows.Forms.OpenFileDialog
                $patterns = @($scanFilterTextBox.Text -split '[,; ]+' | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
                if ($patterns) {
                    $patternText = $patterns -join ';'
                    $dialog.Filter = "Matching files ($patternText)|$patternText|All files (*.*)|*.*"
                }
                else {
                    $dialog.Filter = 'All files (*.*)|*.*'
                }
                $dialog.InitialDirectory = 'C:\Windows\System32'
                if ((Show-OwnedDialog -Dialog $dialog -OwnerWindow $mainWindow) -eq [System.Windows.Forms.DialogResult]::OK) {
                    $scanFileTextBox.Text = [System.IO.Path]::GetFullPath($dialog.FileName)
                    $scanFolderTextBox.Text = $browsePlaceholder
                }
            }
        })
    $scanFolderTextBox.Add_MouseDown({
            Invoke-UiAction {
                $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
                $dialog.Description = 'Select a folder to scan for product keys'
                $dialog.SelectedPath = 'C:\Windows\System32'
                if ((Show-OwnedDialog -Dialog $dialog -OwnerWindow $mainWindow) -eq [System.Windows.Forms.DialogResult]::OK) {
                    $scanFolderTextBox.Text = [System.IO.Path]::GetFullPath($dialog.SelectedPath)
                    $scanFileTextBox.Text = $browsePlaceholder
                }
            }
        })

    $scanTaskControls = @(
        $scanFileTextBox,
        $scanFolderTextBox,
        $scanFilterTextBox,
        $scanRecurseCheckBox,
        $scanKeyCheckBox,
        $scanDpidCheckBox,
        $scanLogsCheckBox,
        $scanButton,
        $scanWindowsRegistryButton,
        $scanOfficeRegistryButton,
        $scanInstalledKeysButton,
        $scanOtherRegistryButton,
        $scanMsdmButton
    )

    $scanButton.Add_Click({
            Invoke-UiAction {
                $patterns = @($scanFilterTextBox.Text.Trim() -split '[,; ]+' | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLower() })
                $filePath = $scanFileTextBox.Text.Trim()
                $folderPath = $scanFolderTextBox.Text.Trim()
                $arguments = @{
                    IncludeExtensions = $patterns
                    Recurse           = $scanRecurseCheckBox.Checked
                    Logs              = $scanLogsCheckBox.Checked
                    File              = if (Test-SelectedPathText -PathText $filePath) { $filePath } else { '' }
                    Folder            = if (Test-SelectedPathText -PathText $folderPath) { $folderPath } else { '' }
                }

                if (-not ($scanKeyCheckBox.Checked -or $scanDpidCheckBox.Checked)) {
                    $scanKeyCheckBox.Checked = $true
                    $scanFilterTextBox.Text = $defaultKeyFilter
                }

                $scriptName = if ($scanKeyCheckBox.Checked) { 'ScanKeysInFiles.ps1' } else { 'ScanKeysInDPID.ps1' }
                Start-ToolTask -ScriptName $scriptName -Arguments $arguments -OutputBox $scanKeysOutputBox -ControlsToDisable $scanTaskControls -Completed $null
            }
        })

    $scanInstalledKeysButton.Add_Click({
            Invoke-UiAction {
                Start-ToolTask `
                    -ScriptName 'ScanKeysInSppTrustedStore.ps1' `
                    -Arguments @{} `
                    -OutputBox $scanKeysOutputBox `
                    -ControlsToDisable $scanTaskControls `
                    -Completed $null
            }
        })
    $scanWindowsRegistryButton.Add_Click({
            Invoke-UiAction {
                Start-ToolTask `
                    -ScriptName 'ScanKeysInRegistry.ps1' `
                    -Arguments @{ Windows = $true } `
                    -OutputBox $scanKeysOutputBox `
                    -ControlsToDisable $scanTaskControls `
                    -Completed $null
            }
        })
    $scanOfficeRegistryButton.Add_Click({
            Invoke-UiAction {
                Start-ToolTask `
                    -ScriptName 'ScanKeysInRegistry.ps1' `
                    -Arguments @{ Office = $true } `
                    -OutputBox $scanKeysOutputBox `
                    -ControlsToDisable $scanTaskControls `
                    -Completed $null
            }
        })
    $scanOtherRegistryButton.Add_Click({
            Invoke-UiAction {
                Start-ToolTask `
                    -ScriptName 'ScanKeysInRegistry.ps1' `
                    -Arguments @{ Other = $true } `
                    -OutputBox $scanKeysOutputBox `
                    -ControlsToDisable $scanTaskControls `
                    -Completed $null
            }
        })
    $scanMsdmButton.Add_Click({
            Invoke-UiAction {
                Start-ToolTask `
                    -ScriptName 'GetMSDMKey.ps1' `
                    -Arguments @{} `
                    -OutputBox $scanKeysOutputBox `
                    -ControlsToDisable $scanTaskControls `
                    -Completed $null
            }
        })

    $mainWindow.ShowDialog() | Out-Null
}

# ===============================================================================================================================
# Application entry point
# ===============================================================================================================================

Initialize-WinForms
Show-PKeyMasterGui
