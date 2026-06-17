<#
=====================================================================

Driver Governance Discovery
Version 1.0

Purpose
-------
Provides lightweight driver governance, reboot impact analysis,
and driver activity monitoring for Intune-managed Windows devices.

Key Capabilities
----------------
• Discover driver updates installed within the last 100 days
• Classify Firmware, System, Extension, Storage and Display drivers
• Detect failed driver installations
• Detect newly installed drivers since previous scan
• Identify elevated-impact driver activity
• Detect device restart requirements
• Track reboot-causing driver updates (where available)
• Generate governance recommendations (OK / Monitor / Investigate)
• Produce JSON output for reporting and automation

Governance Status Model
-----------------------
Healthy
  No issues detected

Advisory
  Elevated-impact drivers present

Restart Required
  Device restart pending

Attention Required
  Failed installation or governance review required

Outputs
-------
JSON Report
C:\ProgramData\DriverGov\DriverGovernance.json

Intune Proactive Remediation
Governance summary and recent driver activity

Governance Objectives
---------------------
• Unexpected Driver Installation Detection
• Driver-Induced Restart Visibility
• Firmware / System / Extension Driver Oversight
• Driver Installation Failure Detection
• Operational Driver Risk Awareness

=====================================================================

#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# -------------------------------------------------------
# Configuration
# -------------------------------------------------------

$OutputFolder = "C:\ProgramData\DriverGov"
$JsonFile = Join-Path $OutputFolder "DriverGovernance.json"
$PreviousJsonFile = Join-Path $OutputFolder "DriverGovernance_Previous.json"

if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$CutoffDate = (Get-Date).AddDays(-180)

# -------------------------------------------------------
# PendingRebootEvidence
# -------------------------------------------------------
function Get-PendingRebootEvidence
{
    $Result = [ordered]@{
        CBS               = $false
        WindowsUpdate     = $false
        PendingRename     = $false
        RebootRequired    = $false
    }

    try
    {
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
        {
            $Result.CBS = $true
        }

        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
        {
            $Result.WindowsUpdate = $true
        }

        $Rename =
            Get-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
            -Name PendingFileRenameOperations `
            -ErrorAction SilentlyContinue

        if ($Rename)
        {
            $Result.PendingRename = $true
        }

        $Result.RebootRequired =
            $Result.CBS -or
            $Result.WindowsUpdate -or
            $Result.PendingRename
    }
    catch
    {
    }

    [PSCustomObject]$Result
}

# -------------------------------------------------------
# ReportingEventsEvidence
# -------------------------------------------------------
function Get-ReportingEventsEvidence
{
    $LogFile = "C:\Windows\SoftwareDistribution\ReportingEvents.log"

    if (!(Test-Path $LogFile))
    {
        return @()
    }

    $Results = @()

    try
    {
        Get-Content $LogFile -ErrorAction SilentlyContinue |
        ForEach-Object {

            if (
                $_ -match "Driver" -or
                $_ -match "restart" -or
                $_ -match "reboot"
            )
            {
                $Results += [PSCustomObject]@{
                    Source = "ReportingEvents"
                    Line = $_
                }
            }
        }
    }
    catch {}

    return $Results
}


# -------------------------------------------------------
# SetupApiDriverInstalls
# -------------------------------------------------------
function Get-SetupApiDriverInstalls
{
    $LogFiles = Get-ChildItem `
        -Path "$env:windir\INF" `
        -File `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '^setupapi\.dev'
        } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 3

    $Results = @()

    foreach ($LogFile in $LogFiles)
    {
        try
        {
            Get-Content $LogFile.FullName -ErrorAction SilentlyContinue |
            ForEach-Object {

                if (
                    $_ -match "Driver Package" -or
                    $_ -match "\.inf" -or
                    $_ -match "SUCCESS"
                )
                {
                    $Results += [PSCustomObject]@{
    Source = "SetupAPI"
    LogFile = $LogFile.Name
    Line = $_
}
                }
            }
        }
        catch
        {
        }
    }

    return $Results
}

# -------------------------------------------------------
# DriverInstallEvents
# -------------------------------------------------------
function Get-DriverInstallEvents
{
    $Events = @()

    try
    {
        $Events += Get-WinEvent `
            -LogName Microsoft-Windows-Kernel-PnP/Configuration `
            -MaxEvents 200 `
            -ErrorAction SilentlyContinue
    }
    catch
    {
    }

    $Events
}

# -------------------------------------------------------
# DriverRestartAttribution
# -------------------------------------------------------
function Get-DriverRestartAttribution
{
    param(
        [array]$DriverUpdates,
        [array]$ReportingEventsEvidence,
        [array]$SetupApiEvidence,
        [object]$PendingRebootState
    )

    $Results = @()

    foreach ($Driver in $DriverUpdates)
    {
        $Evidence = @()

        # SetupAPI Version Match
        $SetupApiMatch =
            $SetupApiEvidence |
            Where-Object {
                $_.Line -match [regex]::Escape($Driver.Version)
            }

        if ($SetupApiMatch)
        {
            $Evidence += "SetupApiVersionMatch"
        }

        # ReportingEvents Version Match
        $ReportingMatch =
            $ReportingEventsEvidence |
            Where-Object {
                $_.Line -match [regex]::Escape($Driver.Version)
            }

        if ($ReportingMatch)
        {
            $Evidence += "ReportingEventsMatch"
        }

        # Reboot Pending
        if ($PendingRebootState.RebootRequired)
        {
            $Evidence += "PendingRebootPresent"
        }

        # Attribution Decision

        if (
            ($Evidence -contains "SetupApiVersionMatch") -and
            ($Evidence -contains "ReportingEventsMatch")
        )
        {
            $Status = "Correlated"
        }
        elseif (
            ($Evidence -contains "SetupApiVersionMatch")
        )
        {
            $Status = "InstalledOnly"
        }
        elseif (
            ($Evidence -contains "ReportingEventsMatch")
        )
        {
            $Status = "RestartEvidenceOnly"
        }
        else
        {
            $Status = "NoEvidence"
        }

        $Results += [PSCustomObject]@{
            DriverName = $Driver.DriverName
            Version = $Driver.Version
            AttributionStatus = $Status
            Evidence = $Evidence
        }
    }

    return $Results
}
# -------------------------------------------------------
# Device Info
# -------------------------------------------------------

try {
    $ComputerSystem = Get-CimInstance Win32_ComputerSystem
    $BIOS = Get-CimInstance Win32_BIOS

    $DeviceInfo = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Manufacturer = $ComputerSystem.Manufacturer
        Model        = $ComputerSystem.Model
        SerialNumber = $BIOS.SerialNumber
        ScanTimeUTC  = (Get-Date).ToUniversalTime().ToString("o")
    }
}
catch {
    $DeviceInfo = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Manufacturer = $null
        Model        = $null
        SerialNumber = $null
        ScanTimeUTC  = (Get-Date).ToUniversalTime().ToString("o")
    }
}

# -------------------------------------------------------
# Load Previous Snapshot
# -------------------------------------------------------

$PreviousDrivers = @()

if (Test-Path $PreviousJsonFile)
{
    try
    {
        $PreviousResults =
            Get-Content $PreviousJsonFile -Raw |
            ConvertFrom-Json

        $PreviousDrivers =
            @($PreviousResults.DriverUpdates)
    }
    catch
    {
        $PreviousDrivers = @()
    }
}
# -------------------------------------------------------
# Driver Update History
# -------------------------------------------------------

$DriverUpdates = @()

try {
    $Session = New-Object -ComObject Microsoft.Update.Session
    $Searcher = $Session.CreateUpdateSearcher()
    $HistoryCount = $Searcher.GetTotalHistoryCount()

    if ($HistoryCount -gt 0) {
        $History = $Searcher.QueryHistory(0, $HistoryCount)

        foreach ($Entry in $History) {
            if ($Entry.Date -lt $CutoffDate) { continue }

            if ($Entry.Title -notmatch "Driver|Firmware|Bluetooth|Wi-?Fi|Wireless|Network|Ethernet|Display|Graphics|GPU|Audio|Storage|NVMe|RAID") {
                continue
            }

            $Version = ""
            if ($Entry.Title -match "\(([0-9\.]+)\)") {
                $Version = $Matches[1]
            }

            $DriverName = $Entry.Title
            if ($Version) {
                $DriverName = $DriverName.Replace("($Version)", "").Trim()
            }

            $Vendor = "Unknown"
            switch -Regex ($Entry.Title) {
                "Advanced Micro Devices|AMD" { $Vendor = "AMD"; break }
                "Lenovo"                     { $Vendor = "Lenovo"; break }
                "Qualcomm"                   { $Vendor = "Qualcomm"; break }
                "Intel"                      { $Vendor = "Intel"; break }
                "Realtek"                    { $Vendor = "Realtek"; break }
                "NVIDIA"                     { $Vendor = "NVIDIA"; break }
                "Synaptics"                  { $Vendor = "Synaptics"; break }
            }

            $DriverType = "Other"
            switch -Regex ($Entry.Title) {
                "Firmware"  { $DriverType = "Firmware"; break }

                "Display"   { $DriverType = "Display"; break }
                "Graphics"  { $DriverType = "Display"; break }
                "GPU"       { $DriverType = "Display"; break }

                "Extension" { $DriverType = "Extension"; break }
                "System"    { $DriverType = "System"; break }
                "Component" { $DriverType = "Component"; break }

                "Bluetooth" { $DriverType = "Bluetooth"; break }
                "Wi-?Fi"    { $DriverType = "Network"; break }
                "Wireless"  { $DriverType = "Network"; break }
                "Network"   { $DriverType = "Network"; break }
                "Ethernet"  { $DriverType = "Network"; break }

                "Storage"   { $DriverType = "Storage"; break }
                "NVMe"      { $DriverType = "Storage"; break }
                "RAID"      { $DriverType = "Storage"; break }
                "Audio"     { $DriverType = "Audio"; break }
            }

            #$VendorTrusted = $Vendor -ne "Unknown"

            $TrustedVendors = @(
    "AMD",
    "Intel",
    "Lenovo",
    "Qualcomm",
    "NVIDIA",
    "Realtek",
    "Synaptics"
)

$VendorTrusted = $Vendor -in $TrustedVendors

            $Risk = "Normal"
            switch -Regex ($Entry.Title) {
                "Firmware"  { $Risk = "High"; break }
                "Display"   { $Risk = "High"; break }
                "Graphics"  { $Risk = "High"; break }
                "GPU"       { $Risk = "High"; break }
                "Bluetooth" { $Risk = "High"; break }
                "Wi-?Fi"    { $Risk = "High"; break }
                "Wireless"  { $Risk = "High"; break }
                "Network"   { $Risk = "High"; break }
                "Ethernet"  { $Risk = "High"; break }
                "Storage"   { $Risk = "High"; break }
                "NVMe"      { $Risk = "High"; break }
                "RAID"      { $Risk = "High"; break }
            }

            $Status = switch ([int]$Entry.ResultCode) {
                0 { "NotStarted" }
                1 { "InProgress" }
                2 { "Succeeded" }
                3 { "SucceededWithErrors" }
                4 { "Failed" }
                5 { "Aborted" }
                default { "Unknown" }
            }

            # -------------------------------------------------------
# Signature Validation
# -------------------------------------------------------

$SignatureStatus = "Unknown"

try
{
    $PnPDriver =
        Get-CimInstance Win32_PnPSignedDriver |
        Where-Object {
            $_.DriverVersion -eq $Version
        } |
        Select-Object -First 1

    if ($PnPDriver)
    {
        if ($PnPDriver.IsSigned)
        {
            $SignatureStatus = "Signed"
        }
        else
        {
            $SignatureStatus = "Unsigned"
        }
    }
}
catch
{
}

            <#if ($Status -eq "Failed") {
                $Recommendation = "Investigate"
            }
            elseif ($Risk -eq "High") {
                $Recommendation = "Monitor"
            }
            else {
                $Recommendation = "OK"
            }#>

            $DaysSinceInstall = (New-TimeSpan -Start $Entry.Date -End (Get-Date)).Days
            $DeliveryMechanism = $DeliveryMechanism

# -------------------------------------------------------
# Driver Health
# -------------------------------------------------------

$DeviceHealth = "Unknown"

try
{
    $ProblemDevices =
        Get-CimInstance Win32_PnPEntity |
        Where-Object {
            $_.ConfigManagerErrorCode -ne 0
        }

    if ($ProblemDevices)
    {
        $DeviceHealth = "ProblemDetected"
    }
    else
    {
        $DeviceHealth = "Healthy"
    }
}
catch
{
}

# -------------------------------------------------------
# New Driver Detection
# -------------------------------------------------------

$CurrentDriverKey =
"$DriverName|$Version"

$IsNewDriver = $true
$ChangeType = "Added"
$PreviousVersion = $null

<#foreach ($OldDriver in $PreviousDrivers)
if ($OldDriver.DriverName -eq $DriverName)
{
    $IsNewDriver = $false

    if ($OldDriver.Version -ne $Version)
    {
        $ChangeType = "Updated"
        $PreviousVersion = $OldDriver.Version
    }
    else
    {
        $ChangeType = "Unchanged"
    }

    break
}   #>

foreach ($OldDriver in $PreviousDrivers)
{
    if ($OldDriver.DriverName -eq $DriverName)
    {
        $IsNewDriver = $false

        if ($OldDriver.Version -ne $Version)
        {
            $ChangeType = "Updated"
            $PreviousVersion = $OldDriver.Version
        }
        else
        {
            $ChangeType = "Unchanged"
        }

        break
    }
}        
            $DeviceHealth = "Unknown"
            $SignatureStatus = "Unknown"
            $DriverUpdates += [PSCustomObject]@{
                InstallDate       = $Entry.Date.ToString("yyyy-MM-dd")
                DaysSinceInstall  = $DaysSinceInstall
                DriverName        = $DriverName
                Version           = $Version
                Vendor            = $Vendor
                VendorTrusted     = $VendorTrusted
                DeliveryMechanism = $DeliveryMechanism
                DriverType        = $DriverType
                Risk              = $Risk
                Status            = $Status
                Recommendation    = $Recommendation
                IsNewDriver       = $IsNewDriver
                GovernanceCategory = $null
                SignatureStatus   = $SignatureStatus
                DeviceHealth      = $DeviceHealth
            
                #ChangeType       =   $ChangeType
                #PreviousVersion =  $PreviousVersion
            }
        }
    }
}
catch {
    Write-Verbose ("Driver history query failed: " + $_.Exception.Message)
}

# -------------------------------------------------------
# Load Previous Snapshot
# -------------------------------------------------------

$PreviousDrivers = @()

if (Test-Path $PreviousJsonFile)
{
    try
    {
        $PreviousResults =
            Get-Content $PreviousJsonFile -Raw |
            ConvertFrom-Json

        $PreviousDrivers =
            @($PreviousResults.DriverUpdates)
    }
    catch
    {
        $PreviousDrivers = @()
    }
}

# -------------------------------------------------------
# Reboot Detection
# -------------------------------------------------------

$RebootRequired = $false

try
{
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
    {
        $RebootRequired = $true
    }

    $PendingRename =
        Get-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        -Name PendingFileRenameOperations `
        -ErrorAction SilentlyContinue

    if ($PendingRename)
    {
        $RebootRequired = $true
    }
}
catch
{
}

$PendingRebootState = Get-PendingRebootEvidence

$SetupApiInstalls = Get-SetupApiDriverInstalls

$DriverInstallEvents = Get-DriverInstallEvents


$DriverRestartAttribution =
    Get-DriverRestartAttribution `
    -DriverUpdates $DriverUpdates `
    -ReportingEventsEvidence $ReportingEventsEvidence `
    -SetupApiEvidence $SetupApiEvidence `
    -PendingRebootState $PendingRebootState

# -------------------------------------------------------
# Driver Governance Classification
# -------------------------------------------------------

$ElevatedImpactDriverTypes = @(
    "Firmware",
    "Display",
    "Storage",
    "Extension",
    "System"
)

foreach ($Driver in $DriverUpdates)
{
    # -----------------------------------
    # Governance Category
    # -----------------------------------

    if ($Driver.DriverType -in $ElevatedImpactDriverTypes)
    {
        $Driver.GovernanceCategory = "Elevated"
    }
    else
    {
        $Driver.GovernanceCategory = "Standard"
    }

    # -----------------------------------
    # Recommendation Logic
    # -----------------------------------

    if ($Driver.Status -eq "Failed")
    {
        $Driver.Recommendation = "Investigate"
    }
    elseif (
        $Driver.IsNewDriver -eq $true #-and
        #$Driver.RebootRequiredByDriver -eq $true
    )
    {
        $Driver.Recommendation = "Immediate Review"
    }
    elseif ($Driver.IsNewDriver -eq $true)
    {
        $Driver.Recommendation = "Monitor"
    }
    else
    {
        $Driver.Recommendation = "OK"
    }
}

$ImmediateReviewCount =
@(
    $DriverUpdates |
    Where-Object Recommendation -eq "Immediate Review"
).Count

$NewDriverCount = @(
    $DriverUpdates |
    Where-Object IsNewDriver
).Count

# -------------------------------------------------------
# Summary
# -------------------------------------------------------

$Summary = [PSCustomObject]@{
    DriverEventsDiscovered      = @($DriverUpdates).Count
    NewDriverActivity           = $NewDriverCount
    DriversInstalledSuccessfully =
    @($DriverUpdates |
        Where-Object Status -eq "Succeeded").Count

    DriverInstallationFailures =
    @($DriverUpdates |
        Where-Object Status -eq "Failed").Count

    ElevatedImpactDrivers =
    @($DriverUpdates |
        Where-Object GovernanceCategory -eq "Elevated").Count
    ImmediateReviewRequired     = $ImmediateReviewCount
    RestartPending              = $RebootRequired

    PendingRebootDetected =
    $PendingRebootState.RebootRequired

CBSRebootPending =
    $PendingRebootState.CBS

WindowsUpdateRebootPending =
    $PendingRebootState.WindowsUpdate

PendingRenameOperations =
    $PendingRebootState.PendingRename
}
# -------------------------------------------------------
# Governance Status
# -------------------------------------------------------

if ($Summary.DriverInstallationFailures -gt 0)
{
    $GovernanceStatus = "Attention Required"
}
elseif ($Summary.ImmediateReviewRequired -gt 0)
{
    $GovernanceStatus = "Attention Required"
}
elseif ($Summary.PendingRestartState)
{
    $GovernanceStatus = "Restart Required"
}
elseif ($Summary.ElevatedImpactDrivers -gt 0)
{
    $GovernanceStatus = "Advisory"
}
else
{
    $GovernanceStatus = "Healthy"
}

$GovernanceDefinitions = [PSCustomObject]@{

    DriverEventsDiscovered =
    "Driver updates found in scope"

    NewDriverActivity =
    "Driver Not seen during previous scan"

    DriversInstalledSuccessfully =
    "Installation completed successfully"

    DriverInstallationFailures =
    "Installation failed or incomplete"

    ElevatedImpactDrivers =
    "Firmware/System/Extension/Display/Storage"

    ImmediateReviewRequired =
    "New reboot-impacting driver activity"

    RestartPending =
    "Device reboot still required"
}

# -------------------------------------------------------
# Output Object
# -------------------------------------------------------

$Results = [PSCustomObject]@{
    ScriptVersion            = "1.0"
    GovernanceStatus         = $GovernanceStatus
    DeviceInfo               = $DeviceInfo
    Summary                  = $Summary
    GovernanceDefinitions    = $GovernanceDefinitions
    DriverUpdates            = $DriverUpdates
    ChangeType               = $ChangeType
    PreviousVersion          = $PreviousVersion
    RestartAttribution       = $DriverRestartAttribution
}

# -------------------------------------------------------
# Save JSON
# -------------------------------------------------------

try
{
    # Backup current file first

    if (Test-Path $JsonFile)
    {
        Copy-Item `
            -Path $JsonFile `
            -Destination $PreviousJsonFile `
            -Force
    }

    # Write new file

    $Results |
        ConvertTo-Json -Depth 10 |
        Set-Content `
            -Path $JsonFile `
            -Encoding UTF8
}
catch
{
    Write-Verbose (
        "Failed to write JSON: " +
        $_.Exception.Message
    )
}

# -------------------------------------------------------
# Intune PR Output
# -------------------------------------------------------

Write-Output "Driver Governance Completed"
Write-Output ""
Write-Output "Governance Status : $GovernanceStatus"
Write-Output ""
Write-Output "Driver Events Discovered      : $($Summary.DriverEventsDiscovered)"
Write-Output "New Driver Activity           : $($Summary.NewDriverActivity)"
Write-Output "Successful Installations      : $($Summary.DriversInstalledSuccessfully)"
Write-Output "Driver Installation Failures  : $($Summary.DriverInstallationFailures)"
Write-Output "Elevated Impact Drivers       : $($Summary.ElevatedImpactDrivers)"
Write-Output "Immediate Review Required     : $($Summary.ImmediateReviewRequired)"
Write-Output "RestartPending                : $($Summary.RestartPending)"
Write-Output ""

# -------------------------------------------------------
# Failed Driver Updates
# -------------------------------------------------------

$FailedDrivers = @(
    $DriverUpdates | Where-Object {
        $_.Status -eq "Failed"
    }
)

if ($FailedDrivers.Count -gt 0)
{
    Write-Output ""
    Write-Output "Failed Driver Updates"

    foreach ($Driver in $FailedDrivers)
    {
        Write-Output (
            "{0} | {1} | {2}" -f `
            $Driver.InstallDate,
            $Driver.DriverName,
            $Driver.Version
        )
    }

    Write-Output ""
}

# -------------------------------------------------------
# New Driver Installations
# -------------------------------------------------------

$NewDrivers = @(
    $DriverUpdates | Where-Object {
        $_.PSObject.Properties.Name -contains "IsNewDriver" -and
        $_.IsNewDriver -eq $true
    }
)

if ($NewDrivers.Count -gt 0)
{
    Write-Output ""
    Write-Output "New Driver Installations"
    Write-Output ""

    foreach ($Driver in $NewDrivers)
    {
        Write-Output (
            "{0} | {1} | {2}" -f `
            $Driver.InstallDate,
            $Driver.DriverName,
            $Driver.Version
        )
    }

    Write-Output ""
}

Write-Output "Latest Driver Updates"
Write-Output ""

$DriverUpdates |
    Sort-Object InstallDate -Descending |
    Select-Object -First 10 |
    ForEach-Object {

        Write-Output (
            "{0} | {1} | {2} | {3} | {4} | {5} | New:{6}" -f `
            $_.InstallDate,
            $_.DriverType,
            $_.Status,
            $_.Recommendation,
            $_.Version,
            $_.DriverName,
            $_.IsNewDriver
            #$_.RebootRequiredByDriver
        )
    }

exit 0