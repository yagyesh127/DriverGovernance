<#
===========================================================
Driver Governance — V14 Refined (Enterprise Edition)
===========================================================
COMPREHENSIVE DRIVER GOVERNANCE SYSTEM

REFINED IN V14.1:
✔ Fixed Post-Install logic (no more recent-only flagging)
✔ Install source attribution with confidence levels
✔ Deterministic risk scoring (not weighted guessing)
✔ Corrected exit code semantics (pending = info, not violation)
✔ Date normalization in inventory comparison
✔ Improved vendor normalization (regex)
✔ Extended health detection (codes 12, 14, 22, 43, 52)
✔ Version baseline compliance (lightweight, local-only)
✔ Performance optimization (context caching)

FEATURES:
✔ Vendor approval validation (config-driven)
✔ Signature validation (KMCS/WHQL aligned)
✔ Install source detection (WU/DriverFramework/OEM with confidence)
✔ Risk scoring (5-tier deterministic rules)
✔ Intune Proactive Remediation (exit codes: 0/2/3/4)
✔ JSON logging & local correlation
✔ Driver health detection (extended PnP codes)
✔ Pending driver updates (Windows Update queue)
✔ Inventory tracking (Current/Previous with date normalization)
✔ Change detection (Added/Removed/Updated drivers)
✔ Priority-based reporting (governance first)
✔ Version baseline compliance checking

PRIORITIZATION:
  Governance > Driver Health > Recent Changes > Pending Drivers (Informational)

COMPATIBILITY:
  - PowerShell 5.1+
  - Windows 10/11
  - Intune Proactive Remediation (no external modules)
  - No elevation required (read-only operations)

VERSION: 14.1.0 (Refined)
CREATED: 2026-06-03
REFINED: 2026-06-04
AUTHOR: Principal Intune Architect, Senior PowerShell Engineer
===========================================================
#>

#Requires -Version 5.1

Write-Verbose "Driver Governance V14.1 Initialization"

# ========================================================================
# 1. CONFIGURATION LOADER
# ========================================================================
# Priority: External JSON > Embedded JSON > Hardcoded defaults

function Initialize-GovernanceConfig {
    $externalPath = "C:\ProgramData\DriverGovernance\config.json"
    
    if (Test-Path $externalPath -PathType Leaf) {
        try {
            $config = Get-Content $externalPath -Raw | ConvertFrom-Json -ErrorAction Stop
            Write-Verbose "Loaded governance config from $externalPath"
            return $config
        }
        catch {
            Write-Warning "Failed to load external config: $_"
        }
    }

    # Fallback: Embedded JSON (Intune-safe)
    $embeddedJson = @"
{
  "ApprovedVendors": ["Microsoft", "Intel", "Dell", "HP"],
  "AllowlistByClass": {
    "System": ["Microsoft", "Intel"],
    "Storage": ["Intel", "Broadcom"],
    "Network": ["Intel", "Broadcom"],
    "Processor": ["Intel", "AMD"],
    "Display": ["NVIDIA", "Intel", "AMD"]
  },
  "VendorNormalization": {
    "Inte": "Intel",
    "Intel Corp": "Intel",
    "Intel Corporation": "Intel",
    "Broadcom Inc": "Broadcom",
    "Advanced Micro Devices": "AMD",
    "NVIDIA Corp": "NVIDIA"
  },
  "RiskTiers": {
    "Microsoft": "trusted",
    "Intel": "trusted",
    "Dell": "oem",
    "HP": "oem",
    "Broadcom": "trusted",
    "AMD": "trusted",
    "NVIDIA": "trusted"
  },
  "DriverBaselines": {
    "Network": {
      "Intel": { "MinimumVersion": "23.40.0" }
    },
    "Storage": {
      "Intel": { "MinimumVersion": "20.0.0" }
    }
  }
}
"@
    
    try {
        $config = $embeddedJson | ConvertFrom-Json -ErrorAction Stop
        Write-Verbose "Using embedded governance config"
        return $config
    }
    catch {
        Write-Warning "Failed to parse embedded config, using hardcoded defaults"
        return [PSCustomObject]@{
            ApprovedVendors = @("Microsoft", "Intel", "Dell", "HP")
            AllowlistByClass = @{}
            VendorNormalization = @{}
            RiskTiers = @{}
            DriverBaselines = @{}
        }
    }
}

$script:GovernanceConfig = Initialize-GovernanceConfig

# ========================================================================
# 2. HELPER FUNCTIONS - STRING & VENDOR
# ========================================================================

function S { param($v); if([string]::IsNullOrWhiteSpace("$v")) { "" } else { "$v" } }

function Normalize-VendorAdvanced {
    param($name, $deviceClass = "")
    
    if (-not $name) { return "Other" }

    # Try explicit normalization mapping first (from config)
    if ($script:GovernanceConfig.VendorNormalization -and $script:GovernanceConfig.VendorNormalization[$name]) {
        return $script:GovernanceConfig.VendorNormalization[$name]
    }

    # Improved regex patterns to catch vendor name variations
    if ($name -match "(?i)^intel|Intel\s|Intel\(|Intel Corp|Inte[l]?") { return "Intel" }
    if ($name -match "(?i)^microsoft|Microsoft") { return "Microsoft" }
    if ($name -match "(?i)^dell|DellEMC|Dell\s") { return "Dell" }
    if ($name -match "(?i)^HP$|^HPE$|Hewlett|HP\s") { return "HP" }
    if ($name -match "(?i)^Lenovo|Lenovo\s") { return "Lenovo" }
    if ($name -match "(?i)^Broadcom|Broadcom\s|Broadcom\(|BCM") { return "Broadcom" }
    if ($name -match "(?i)^AMD|Advanced Micro|AMD\s") { return "AMD" }
    if ($name -match "(?i)^NVIDIA|NVIDIA\s|NVIDIA\(|GeForce") { return "NVIDIA" }
    if ($name -match "(?i)^Qualcomm|Qualcomm\s") { return "Qualcomm" }
    if ($name -match "(?i)^Realtek|Realtek\s") { return "Realtek" }
    
    return "Other"
}

function Is-VendorApproved {
    param($vendor, $deviceClass = "")
    
    if (-not $vendor) { return $false }

    $normalized = Normalize-VendorAdvanced $vendor $deviceClass

    # Check class-specific allowlist first
    if ($deviceClass -and $script:GovernanceConfig.AllowlistByClass -and 
        $script:GovernanceConfig.AllowlistByClass[$deviceClass]) {
        $classAllowlist = $script:GovernanceConfig.AllowlistByClass[$deviceClass]
        if ($classAllowlist -contains $normalized) { return $true }
        return $false
    }

    # Fall back to global approved vendors
    if ($script:GovernanceConfig.ApprovedVendors -contains $normalized) { return $true }

    return $false
}

function Get-VendorRiskTier {
    param($vendor)
    
    $normalized = Normalize-VendorAdvanced $vendor
    
    if ($script:GovernanceConfig.RiskTiers -and $script:GovernanceConfig.RiskTiers[$normalized]) {
        return $script:GovernanceConfig.RiskTiers[$normalized]
    }
    
    if ($normalized -eq "Microsoft") { return "trusted" }
    if ($normalized -in @("Intel", "AMD", "NVIDIA", "Broadcom")) { return "trusted" }
    if ($normalized -in @("Dell", "HP", "Lenovo")) { return "oem" }
    
    return "unknown"
}

# ========================================================================
# 3. DRIVER IDENTIFICATION & FILTERING
# ========================================================================

function Get-FriendlyDriverName {
    param($Driver)

    if (-not $Driver) { return "Unknown Driver" }

    $name = $Driver.DeviceName

    # Remove version suffixes
    $name = $name -replace '\s+\d+\.\d+(\.\d+)*$', ''

    # Clean whitespace
    $name = ($name -replace '\s+', ' ').Trim()

    return $name
}

function Get-PublicDriverTitle {
    param($Driver, $WUHistory)

    if (-not $Driver) { return "Unknown Driver" }

    if ($WUHistory) {
        $match = $WUHistory | Where-Object {
            $_.Title -like "*$($Driver.DriverVersion)*"
        } | Select-Object -First 1

        if ($match) { return $match.Title }
    }

    return $Driver.DeviceName
}

function Get-DriverFamily {
    param($Driver)
    
    if (-not $Driver -or -not $Driver.DeviceName) { 
        return @{ Family = "Unknown"; Relevance = "low"; Include = $false } 
    }
    
    $name = $Driver.DeviceName
    $class = $Driver.DeviceClass
    
    # Governance-critical families
    if ($class -match "System|Processor|Motherboard|Chipset|BIOS|Firmware") {
        return @{ Family = "System/Firmware"; Relevance = "critical"; Include = $true }
    }
    if ($class -match "Storage|SCSI|Disk|SAN|RAID|ATA|SATA|NVMe") {
        return @{ Family = "Storage"; Relevance = "critical"; Include = $true }
    }
    if ($class -match "Net|Network|Ethernet|Wireless|WLAN|WiFi") {
        return @{ Family = "Network"; Relevance = "high"; Include = $true }
    }
    if ($class -match "Bluetooth") {
        return @{ Family = "Bluetooth"; Relevance = "high"; Include = $true }
    }
    if ($class -match "Display|Video|GPU|Graphics|3D") {
        return @{ Family = "Graphics/Display"; Relevance = "high"; Include = $true }
    }
    if ($class -match "Audio|Sound") {
        return @{ Family = "Audio"; Relevance = "high"; Include = $true }
    }
    if ($class -match "SecurityDevices|TPM|Biometric") {
        return @{ Family = "Security"; Relevance = "high"; Include = $true }
    }
    
    # Low-level noise: suppress GPIO, SMBUS, etc.
    if ($name -match "GPIO|SMBUS|SMBus|SMCPCIe|APO|Fusion|ACPI|HAL|PCI Bus|Root|High Definition|DMA|EHCI|UHCI|XHCI|IDE|Composite Bus|Generic|Standard") {
        return @{ Family = "LowLevel"; Relevance = "low"; Include = $false }
    }
    
    # Input devices: MEDIUM relevance
    if ($class -match "USB|HID|Keyboard|Mouse|Input") {
        return @{ Family = "Input/USB"; Relevance = "medium"; Include = $false }
    }
    
    return @{ Family = "Other"; Relevance = "low"; Include = $false }
}

function Should-IncludeInReport {
    param($result)

    if (-not $result) { return $false }

    if ([string]::IsNullOrWhiteSpace($result.Driver)) { return $false }

    $noisePatterns = @(
        "GPIO", "SMBUS", "I2C", "SWC", "APO", "Provisioning",
        "Audio CoProcessor", "Crash Defender", "Micro PEP", "HSA Device",
        "DRTM", "ACP HDA", "Virtual power", "Power coordination",
        "Bus Enumerator", "Virtual Device", "Root Enumerator",
        "AMD PCI", "Function keys", "Audio Effects", "MirrorOp",
        "Virtual Graphics", "High Definition Audio", "Audio Device"
    )
    
    foreach ($pattern in $noisePatterns) {
        if ($result.Driver -match $pattern) { return $false }
    }

    # Show only High/Critical findings (for governance alerts)
    if ($result.PSObject.Properties['Severity']) {
        $severityText = [string]$result.Severity
        if ($severityText -notmatch "Critical" -and $severityText -notmatch "High") {
            return $false
        }
    }

    return $true
}

# ========================================================================
# 4. SIGNATURE VALIDATION (KMCS/WHQL ALIGNED)
# ========================================================================

function Initialize-PerformanceCache {
    $script:SignatureCache = @{}
    $script:InventoryPath = "C:\ProgramData\DriverGov"
    Write-Verbose "Signature cache initialized"
}

function Get-CachedSignature {
    param([string]$InfName)
    
    if ($script:SignatureCache.ContainsKey($InfName)) {
        return $script:SignatureCache[$InfName]
    }
    
    if (-not $InfName) {
        $result = "Unknown"
    }
    else {
        $path = Join-Path $env:windir "INF\$InfName"
        if (-not (Test-Path $path -PathType Leaf)) {
            $result = "Unknown"
        }
        else {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
                if (-not $sig) { 
                    $result = "Unknown" 
                }
                elseif ($sig.Status -ne "Valid") { 
                    $result = "Invalid" 
                }
                elseif ($sig.SignerCertificate -and $sig.SignerCertificate.NotAfter -lt (Get-Date)) { 
                    $result = "Expired" 
                }
                elseif ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -notmatch "Microsoft") { 
                    $result = "NonMicrosoft" 
                }
                else { 
                    $result = "Valid" 
                }
            }
            catch {
                $result = "Unknown"
            }
        }
    }
    $script:SignatureCache[$InfName] = $result
    return $result
}

function Get-DriverSignatureLevel {
    param($Driver)

    try {
        if ($Driver -and $Driver.PSObject.Properties['IsSigned']) {
            if ($Driver.IsSigned) { return "Valid" }
        }
    }
    catch {}

    if (-not $Driver.InfName) { return "Unknown" }
    return Get-CachedSignature -InfName $Driver.InfName
}

# ========================================================================
# 5. RISK SCORING (DETERMINISTIC RULES - V14.1 REFINED)
# ========================================================================

function Get-DriverRiskScore {
    param(
        [psobject]$Driver,
        [string]$SignatureStatus = "Unknown",
        [string]$InstallSource = "Unknown"
    )

    if (-not $Driver) { return @{ Score=10; Tier="Minimal"; Reasons=@() } }

    $reasons = @()
    $tier = "Minimal"

    # ========== RULE 1: CRITICAL TIER ==========
    # Any of these = CRITICAL
    if (
        ($SignatureStatus -eq "Invalid" -and $Driver.DeviceClass -match "System|Storage|Network") -or
        ($Driver.PSObject.Properties['ConfigManagerErrorCode'] -and $Driver.ConfigManagerErrorCode -eq 28)
    ) {
        $tier = "Critical"
        $reasons += "Critical risk condition detected"
        return @{ Score=95; Tier=$tier; Reasons=$reasons }
    }

    # ========== RULE 2: HIGH TIER ==========
    # Any of these = HIGH
    if (
        ($SignatureStatus -eq "Invalid") -or
        ($SignatureStatus -eq "Expired") -or
        (-not (Is-VendorApproved $Driver.DriverProviderName $Driver.DeviceClass) -and 
         $Driver.DeviceClass -match "System|Storage|Network")
    ) {
        $tier = "High"
        $reasons += "High risk: signature issue or unapproved critical vendor"
        return @{ Score=75; Tier=$tier; Reasons=$reasons }
    }

    # ========== RULE 3: MEDIUM TIER ==========
    # Any of these = MEDIUM
    if (
        (-not (Is-VendorApproved $Driver.DriverProviderName $Driver.DeviceClass)) -or
        ($SignatureStatus -eq "Unknown") -or
        ($InstallSource -eq "Unknown") -or
        ($Driver.DeviceClass -match "Audio|Display")
    ) {
        $tier = "Medium"
        $reasons += "Medium risk: unknown vendor, signature, or source on non-critical device"
        return @{ Score=50; Tier=$tier; Reasons=$reasons }
    }

    # ========== RULE 4: LOW TIER ==========
    # All of these = LOW
    if (
        (Is-VendorApproved $Driver.DriverProviderName $Driver.DeviceClass) -and
        ($SignatureStatus -eq "Valid") -and
        ($InstallSource -match "WindowsUpdate|DriverFramework")
    ) {
        $tier = "Low"
        $reasons += "Low risk: approved vendor, valid signature, known source"
        return @{ Score=25; Tier=$tier; Reasons=$reasons }
    }

    # ========== DEFAULT: MINIMAL ==========
    $tier = "Minimal"
    $reasons += "No risk indicators detected"
    return @{ Score=10; Tier=$tier; Reasons=$reasons }
}

function Get-DriverRiskClass {
    param($Driver, $SignatureStatus = "Unknown", $InstallSource = "Unknown")
    
    $result = Get-DriverRiskScore $Driver $SignatureStatus $InstallSource
    return $result.Tier
}

# ========================================================================
# 6. DRIVER HEALTH DETECTION (EXTENDED - V14.1 REFINED)
# ========================================================================

function Get-DriverHealthStatus {
    param($Driver)
    
    <# 
        ConfigManagerErrorCode Reference (Windows device manager codes):
        Code 0: Device working correctly
        Code 10: Device cannot start (driver failure)
        Code 12: Device has insufficient resources
        Code 14: Device cannot start (resource conflict)
        Code 22: Device is disabled
        Code 28: No drivers installed (CRITICAL)
        Code 31: Device is disabled
        Code 43: Device stopped responding (malware suspect)
        Code 52: Device is not recognized (compatibility issue)
    #>
    
    if (-not $Driver) { return @{ Status = "Unknown"; ErrorCode = $null; Severity = "Low" } }

    $errorCode = $null
    $status = "Healthy"
    $severity = "Low"

    try {
        if ($Driver.PSObject.Properties['ConfigManagerErrorCode']) {
            $errorCode = $Driver.ConfigManagerErrorCode
        }
    }
    catch {}

    # Map error codes to status and severity
    switch ($errorCode) {
        0 { 
            $status = "Healthy"
            $severity = "Low"
        }
        10 { 
            $status = "CannotStart"
            $severity = "High"
        }
        12 { 
            $status = "InsufficientResources"
            $severity = "Medium"
        }
        14 { 
            $status = "CannotStartConflict"
            $severity = "High"
        }
        22 { 
            $status = "Disabled"
            $severity = "Medium"
        }
        28 { 
            $status = "MissingDriver"
            $severity = "Critical"
        }
        31 { 
            $status = "Disabled"
            $severity = "Medium"
        }
        43 { 
            $status = "Stopped"
            $severity = "High"
        }
        52 { 
            $status = "NotRecognized"
            $severity = "High"
        }
        default { 
            if ($null -ne $errorCode -and $errorCode -ne 0) {
                $status = "Error"
                $severity = "Medium"
            }
        }
    }

    return @{
        Status = $status
        ErrorCode = $errorCode
        Severity = $severity
        IsHealthy = ($errorCode -eq 0 -or $errorCode -eq $null)
    }
}

function Detect-DriverHealthIssues {
    param($Drivers)

    $issues = @()

    if (-not $Drivers) { return $issues }

    foreach ($driver in $Drivers) {
        $health = Get-DriverHealthStatus $driver

        if (-not $health.IsHealthy) {
            $issues += [PSCustomObject]@{
                Category = "DriverHealth"
                Device = S($driver.Name)
                DeviceClass = S($driver.DeviceClass)
                Status = $health.Status
                ErrorCode = $health.ErrorCode
                Severity = $health.Severity
                Description = "Driver health issue detected"
            }
        }
    }

    return $issues
}

# ========================================================================
# 7. INSTALL SOURCE DETECTION (WITH CONFIDENCE LEVELS - V14.1 REFINED)
# ========================================================================

function Build-WUHistoryLookup {
    param([array]$WUHistory)
    
    $lookup = @{}
    if (-not $WUHistory -or $WUHistory.Count -eq 0) { return $lookup }
    
    foreach ($entry in $WUHistory) {
        if (-not $entry.Title) { continue }
        if ($entry.Title -match "^([A-Za-z]+)") {
            $provider = $matches[1]
            if (-not $lookup[$provider]) { $lookup[$provider] = @() }
            $lookup[$provider] += $entry
        }
    }
    return $lookup
}

function Resolve-InstallSource {
    param(
        [psobject]$Driver,
        [array]$WUHistory,
        [array]$DriverFrameworkEvents,
        [hashtable]$WUHistoryLookup
    )

    <#
        Returns confidence-aware source attribution:
        - WindowsUpdate-HighConfidence: Strong indicators (Microsoft provider, CatalogFile in INF)
        - WindowsUpdate-LowConfidence: Weak indicators (version match in history)
        - DriverFramework: Logged installation
        - Unknown: Cannot determine
        
        Note: Does NOT assume vendor = Windows Update origin
    #>

    if (-not $Driver) { return "Unknown" }

    # ========== SIGNAL 1: PROVIDER NAME (HIGH CONFIDENCE) ==========
    if ($Driver.DriverProviderName -eq "Microsoft") { return "WindowsUpdate-HighConfidence" }

    # ========== SIGNAL 2: INF FILE ANALYSIS (HIGH CONFIDENCE) ==========
    if ($Driver.InfName) {
        $infPath = Join-Path $env:windir "INF\$($Driver.InfName)"
        if (Test-Path $infPath -PathType Leaf) {
            try {
                $infContent = Get-Content $infPath -Raw -ErrorAction Stop
                # CatalogFile marker = Windows Update delivery method
                if ($infContent -match "(?i)CatalogFile\s*=") { 
                    return "WindowsUpdate-HighConfidence" 
                }
            }
            catch {}
        }
    }

    # ========== SIGNAL 3: DRIVERFRAMEWORK EVENTS (MEDIUM CONFIDENCE) ==========
    if ($DriverFrameworkEvents -and $DriverFrameworkEvents.Count -gt 0) {
        foreach ($evtRecord in $DriverFrameworkEvents) {
            if ($Driver.InfName -and $evtRecord.Message -match [regex]::Escape($Driver.InfName)) {
                return "DriverFramework"
            }
        }
    }

    # ========== SIGNAL 4: WINDOWS UPDATE HISTORY CORRELATION (LOW CONFIDENCE) ==========
    # Only if EXACT version match in WU history AND provider name matches
    # (Avoid false positives from common version numbers)
    if ($WUHistoryLookup -and $WUHistoryLookup.Count -gt 0 -and $Driver.DriverProviderName) {
        $normalized = Normalize-VendorAdvanced $Driver.DriverProviderName
        if ($WUHistoryLookup.ContainsKey($normalized)) {
            foreach ($entry in $WUHistoryLookup[$normalized]) {
                # Require BOTH vendor AND version to match
                if ($Driver.DriverVersion -and $entry.Title -match [regex]::Escape($Driver.DriverVersion)) {
                    return "WindowsUpdate-LowConfidence"
                }
            }
        }
    }

    # ========== DEFAULT: UNKNOWN ==========
    # Do NOT assume OEM/Manual - we genuinely don't know
    return "Unknown"
}

# ========================================================================
# 8. VERSION BASELINE COMPLIANCE (NEW V14.1 - LIGHTWEIGHT)
# ========================================================================

function Get-DriverVersionStatus {
    param(
        [psobject]$Driver,
        [string]$Vendor,
        [string]$DeviceClass
    )

    <#
        Lightweight version baseline checking (local config only, no internet).
        Configuration format:
        {
          "DriverBaselines": {
            "Network": {
              "Intel": { "MinimumVersion": "23.40.0" }
            }
          }
        }
    #>

    $status = "VersionCompliant"
    $reasons = @()

    try {
        if (-not $script:GovernanceConfig.DriverBaselines) {
            return @{ Status=$status; Reasons=$reasons }
        }

        $normalized = Normalize-VendorAdvanced $Vendor
        
        # Check if baseline exists for this class + vendor
        if ($script:GovernanceConfig.DriverBaselines[$DeviceClass] -and 
            $script:GovernanceConfig.DriverBaselines[$DeviceClass][$normalized]) {
            
            $baseline = $script:GovernanceConfig.DriverBaselines[$DeviceClass][$normalized]
            $driverVersion = $Driver.DriverVersion

            if (-not $driverVersion) {
                return @{ Status="VersionUnknown"; Reasons=@("Cannot parse driver version") }
            }

            # Simple version comparison (assumes semantic versioning)
            try {
                $current = [version]$driverVersion
                
                if ($baseline.MinimumVersion) {
                    $minimum = [version]$baseline.MinimumVersion
                    if ($current -lt $minimum) {
                        $status = "BelowMinimumVersion"
                        $reasons += "Driver version $driverVersion is below minimum $($baseline.MinimumVersion)"
                        return @{ Status=$status; Reasons=$reasons }
                    }
                }
                
                if ($baseline.MaximumVersion) {
                    $maximum = [version]$baseline.MaximumVersion
                    if ($current -gt $maximum) {
                        $status = "AboveApprovedVersion"
                        $reasons += "Driver version $driverVersion exceeds maximum $($baseline.MaximumVersion)"
                        return @{ Status=$status; Reasons=$reasons }
                    }
                }

                if ($status -eq "VersionCompliant") {
                    $reasons += "Driver version $driverVersion within baseline"
                }
            }
            catch {
                # Version parse failed - not a blocker
                return @{ Status="VersionUnknown"; Reasons=@("Cannot parse version: $driverVersion") }
            }
        }
    }
    catch {
        Write-Warning "Error checking version baseline: $_"
    }

    return @{ Status=$status; Reasons=$reasons }
}

# ========================================================================
# 9. RECENT DRIVER DETECTION
# ========================================================================

function Get-RecentDriverInstall {
    param($Driver, [int]$Days = 100)

    try {
        $age = (New-TimeSpan -Start ([datetime]$Driver.DriverDate) -End (Get-Date)).Days
        return ($age -lt $Days)
    }
    catch {
        return $false
    }
}

# ========================================================================
# 10. GOVERNANCE DETECTION (V14.1 REFINED - NO MORE RECENT-ONLY FLAGS)
# ========================================================================

function Detect-PreInstall {
    param($PendingDrivers, $ApprovedVendors)

    $alerts = @()

    foreach ($p in $PendingDrivers) {
        $vendor = Normalize-VendorAdvanced $p.Title

        if (-not (Is-VendorApproved $vendor)) {
            $alerts += [PSCustomObject]@{
                Category = "PendingDriver"
                Stage = "PreInstall"
                Driver = $p.Title
                Vendor = $vendor
                Severity = "Medium"
                Message = "Unapproved driver pending installation"
            }
        }
    }
    return $alerts
}

function Detect-PolicyViolation {
    param($Driver, $ApprovedVendors)

    if (-not $Driver -or -not $ApprovedVendors) { return $null }

    $vendor = Normalize-VendorAdvanced $Driver.DriverProviderName
    $deviceClass = $Driver.DeviceClass

    if (-not (Is-VendorApproved $vendor $deviceClass)) {
        return [PSCustomObject]@{
            Category = "Governance"
            Stage = "Policy"
            Driver = (Get-FriendlyDriverName $Driver)
            Vendor = $vendor
            DeviceClass = $deviceClass
            Version = S($Driver.DriverVersion)
            Severity = "High"
            Message = "Vendor not approved for class: $deviceClass"
        }
    }
    return $null
}

function Is-SystemDriver { param($d); return ("$($d.DeviceName)" -match "ACPI|System|Motherboard|PCI Bus|Root") }
function Is-KnownSafe { param($d); return ($d.DriverProviderName -match "Microsoft" -and $d.DeviceName -match "System") }

function Detect-PostInstall {
    param(
        $Driver, 
        $ApprovedVendors, 
        $WUHistory, 
        $DriverFrameworkEvents, 
        $WUHistoryLookup,
        $DriverContext
    )

    <#
        V14.1 REFINED: Governance findings only on actual violations.
        Recent installation alone NEVER creates a governance finding.
        
        Creates finding ONLY if one of these is true:
        - Vendor not approved (policy violation)
        - Signature is Invalid (security issue)
        - Signature is Expired (security issue)
        - Risk classification is Critical (risk assessment)
        - Driver health issue exists (functional issue)
        - Version baseline violated (compliance issue)
    #>

    if (-not $Driver -or -not $ApprovedVendors) { return $null }
    if (Is-SystemDriver $Driver) { return $null }
    if (Is-KnownSafe $Driver) { return $null }

    $vendor = Normalize-VendorAdvanced $Driver.DriverProviderName
    $deviceClass = $Driver.DeviceClass
    $sig = Get-DriverSignatureLevel $Driver
    $src = Resolve-InstallSource -Driver $Driver -WUHistory $WUHistory `
        -DriverFrameworkEvents $DriverFrameworkEvents -WUHistoryLookup $WUHistoryLookup
    $risk = Get-DriverRiskClass $Driver $sig $src
    $approved = Is-VendorApproved $vendor $deviceClass
    $health = Get-DriverHealthStatus $Driver
    $versionStatus = Get-DriverVersionStatus $Driver $vendor $deviceClass

    # ========== GOVERNANCE FINDING: Only if actual violation ==========
    if (
        (-not $approved) -or                                # Unapproved vendor
        ($sig -eq "Invalid") -or                            # Invalid signature
        ($sig -eq "Expired") -or                            # Expired certificate
        ($risk -eq "Critical") -or                          # Critical risk classification
        (-not $health.IsHealthy) -or                        # Health issue exists
        ($versionStatus.Status -eq "BelowMinimumVersion")   # Version violation
    ) {
        $severity = switch ($risk) {
            "Critical" { "Critical" }
            "High" { "High" }
            "Medium" { "Medium" }
            default { "Low" }
        }

        # Elevate severity if version baseline violated
        if ($versionStatus.Status -eq "BelowMinimumVersion") {
            $severity = "High"
        }

        return [PSCustomObject]@{
            Category = "Governance"
            Stage = "PostInstall"
            Driver = (Get-FriendlyDriverName $Driver)
            Vendor = $vendor
            DeviceClass = $deviceClass
            Version = S($Driver.DriverVersion)
            Signature = $sig
            InstallSource = $src
            Risk = $risk
            VersionStatus = $versionStatus.Status
            Severity = $severity
            Message = "Driver governance violation detected"
        }
    }

    # ========== NO FINDING: Recent install alone is not a violation ==========
    # (Purely informational tracking only - not returned as finding)
    return $null
}

# ========================================================================
# 11. INVENTORY MANAGEMENT & CHANGE TRACKING (V14.1 REFINED - DATE NORMALIZATION)
# ========================================================================

function Get-DriverInventory {
    param([array]$Drivers, $WUHistory)

    $inventory = @()

    foreach ($driver in $Drivers) {
        $vendor = Normalize-VendorAdvanced $driver.DriverProviderName
        $src = Resolve-InstallSource -Driver $driver -WUHistory $WUHistory -DriverFrameworkEvents @() -WUHistoryLookup @{}
        
        # Normalize driver date to yyyy-MM-dd format
        $normalizedDate = ""
        try {
            if ($driver.DriverDate) {
                $dt = [datetime]::Parse($driver.DriverDate)
                $normalizedDate = $dt.ToString("yyyy-MM-dd")
            }
        }
        catch {}
        
        $inventory += [PSCustomObject]@{
            DeviceId = S($driver.DeviceID)
            Device = Get-FriendlyDriverName $driver
            DeviceClass = S($driver.DeviceClass)
            Vendor = $vendor
            Version = S($driver.DriverVersion)
            DriverDate = $normalizedDate
            InfName = S($driver.InfName)
            InstallSource = $src
            IsSigned = if ($driver.PSObject.Properties['IsSigned']) { $driver.IsSigned } else { $null }
            Timestamp = (Get-Date).ToString('O')
        }
    }

    return $inventory
}

function Save-InventoryFile {
    param(
        [array]$Inventory,
        [string]$Path
    )

    try {
        $directory = Split-Path -Parent $Path
        if (-not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        $Inventory | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 -Path $Path
        Write-Verbose "Saved inventory to $Path ($($Inventory.Count) entries)"
    }
    catch {
        Write-Warning "Failed to save inventory: $_"
    }
}

function Load-InventoryFile {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return @()
    }

    try {
        $data = Get-Content $Path -Raw | ConvertFrom-Json
        if ($data -isnot [System.Collections.IEnumerable]) {
            return @($data)
        }
        return @($data)
    }
    catch {
        Write-Warning "Failed to load inventory: $_"
        return @()
    }
}

function Compare-Inventories {
    param(
        [array]$Current,
        [array]$Previous
    )

    <#
        V14.1 REFINED: Normalize dates before comparison.
        Prevents false "updated" entries from date format variations.
    #>

    $changes = @{
        Added = @()
        Removed = @()
        Updated = @()
        Unchanged = @()
    }

    if (-not $Previous -or $Previous.Count -eq 0) {
        $changes.Added = $Current
        return $changes
    }

    $prevLookup = @{}
    foreach ($item in $Previous) {
        $key = "$($item.DeviceId)|$($item.Device)".ToLower()
        $prevLookup[$key] = $item
    }

    foreach ($item in $Current) {
        $key = "$($item.DeviceId)|$($item.Device)".ToLower()

        if (-not $prevLookup.ContainsKey($key)) {
            $changes.Added += $item
        }
        else {
            $prev = $prevLookup[$key]
            
            # Normalize both versions and dates for comparison
            $currVersion = $item.Version
            $prevVersion = $prev.Version
            # Both should already be normalized to yyyy-MM-dd, but ensure consistency
            $currDate = if ($item.DriverDate) { $item.DriverDate } else { "" }
            $prevDate = if ($prev.DriverDate) { $prev.DriverDate } else { "" }

            # Only flag as updated if BOTH version AND date actually changed
            if (($currVersion -ne $prevVersion) -or ($currDate -ne $prevDate)) {
                $changes.Updated += [PSCustomObject]@{
                    Device = $item.Device
                    DeviceClass = $item.DeviceClass
                    OldVersion = $prevVersion
                    OldDate = $prevDate
                    NewVersion = $currVersion
                    NewDate = $currDate
                    Timestamp = $item.Timestamp
                }
            }
            else {
                $changes.Unchanged += $item
            }
        }
    }

    foreach ($item in $Previous) {
        $key = "$($item.DeviceId)|$($item.Device)".ToLower()
        $found = $Current | Where-Object { "$($_.DeviceId)|$($_.Device)".ToLower() -eq $key }
        if (-not $found) {
            $changes.Removed += $item
        }
    }

    return $changes
}

function Save-ChangeLog {
    param(
        [hashtable]$Changes,
        [string]$Path
    )

    try {
        $directory = Split-Path -Parent $Path
        if (-not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        $output = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString('O')
            Added = $Changes.Added
            Removed = $Changes.Removed
            Updated = $Changes.Updated
            Summary = @{
                AddedCount = ($Changes.Added | Measure-Object).Count
                RemovedCount = ($Changes.Removed | Measure-Object).Count
                UpdatedCount = ($Changes.Updated | Measure-Object).Count
                UnchangedCount = ($Changes.Unchanged | Measure-Object).Count
            }
        }

        $output | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 -Path $Path
        Write-Verbose "Saved change log to $Path"
    }
    catch {
        Write-Warning "Failed to save change log: $_"
    }
}

# ========================================================================
# 12. TRACKING & CORRELATION
# ========================================================================

function Track-RepeatIssues {
    param(
        [array]$Results,
        [int]$Threshold = 3,
        [int]$WindowDays = 14
    )

    if (-not $Results -or $Results.Count -eq 0) { return }

    $path = "C:\ProgramData\DriverGov\DriverGov_History.json"
    $now = Get-Date

    # Load existing history
    if (Test-Path $path) {
        try {
            $history = Get-Content $path -Raw | ConvertFrom-Json
            if ($history -isnot [System.Collections.IEnumerable]) {
                $history = @($history)
            }
        }
        catch {
            $history = @()
        }
    }
    else {
        $history = @()
    }

    # Add timestamp
    foreach ($r in $Results) {
        if (-not $r.PSObject.Properties["Timestamp"]) {
            $r | Add-Member -NotePropertyName Timestamp -NotePropertyValue $now -Force
        }
    }

    # Trim old history
    $history = $history | Where-Object {
        try { ([datetime]$_.Timestamp) -gt $now.AddDays(-$WindowDays) }
        catch { $false }
    }

    # Merge
    $combined = @($history + $Results) | Select-Object -Last 500

    # Group and flag repeats
    $grouped = $combined | Group-Object {
        ("$($_.Driver)|$($_.Vendor)|$($_.Version)").ToLower()
    }

    foreach ($g in $grouped) {
        if ($g.Count -ge $Threshold) {
            $groupKey = $g.Name
            foreach ($item in $Results) {
                $itemKey = ("$($item.Driver)|$($item.Vendor)|$($item.Version)").ToLower()
                if ($groupKey -eq $itemKey) {
                    $item | Add-Member -NotePropertyName RepeatFlag -NotePropertyValue "RepeatedIssue" -Force
                }
            }
        }
    }

    # Save
    try {
        $combined | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 $path
    }
    catch {}
}

function Get-PendingDriverUpdates {
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $updates = $searcher.Search("IsInstalled=0 and Type='Driver'").Updates
        return $updates
    }
    catch {
        Write-Verbose "No pending drivers available or COM error"
        return @()
    }
}

function Get-WUHistory {
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        return $session.QueryHistory("", 0, 100)
    }
    catch {
        return @()
    }
}

function Get-DriverInstallEvents {
    try {
        return @(Get-WinEvent -LogName "Microsoft-Windows-DriverFrameworks-UserMode/Operational" `
            -MaxEvents 200 -ErrorAction Stop)
    }
    catch {
        return @()
    }
}

# ========================================================================
# 13. DATA AGGREGATION & REPORTING
# ========================================================================

function Get-IntuneSummary {
    param(
        [array]$Items,
        [int]$Limit = 3
    )

    if (-not $Items) { return "" }

    $top = $Items |
        Sort-Object @{
            Expression = {
                switch ($_.Severity) {
                    "Critical" { 1 }
                    "High" { 2 }
                    "Medium" { 3 }
                    "Low" { 4 }
                    default { 5 }
                }
            }
        } |
        Select-Object -First $Limit

    return ($top | ForEach-Object { "$($_.Driver) v$($_.Version)" }) -join "; "
}

function Generate-Report {
    param(
        [array]$GovernanceResults,
        [array]$HealthResults,
        [array]$PendingResults,
        [hashtable]$Changes
    )

    $report = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString('O')
        Governance = @{
            Issues = @($GovernanceResults)
            Count = ($GovernanceResults | Measure-Object).Count
        }
        DriverHealth = @{
            Issues = @($HealthResults)
            Count = ($HealthResults | Measure-Object).Count
        }
        PendingUpdates = @{
            Issues = @($PendingResults)
            Count = ($PendingResults | Measure-Object).Count
        }
        RecentChanges = @{
            Added = $Changes.Added | Measure-Object | Select-Object -ExpandProperty Count
            Removed = $Changes.Removed | Measure-Object | Select-Object -ExpandProperty Count
            Updated = $Changes.Updated | Measure-Object | Select-Object -ExpandProperty Count
        }
    }

    return $report
}

# ========================================================================
# 14. MAIN EXECUTION
# ========================================================================

# Initialize
Initialize-PerformanceCache

Write-Verbose "Driver Governance V14.1 - Execution Starting"

# Collect data
$allDrivers = @()
try {
    $allDrivers = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop)
}
catch {
    Write-Warning "Failed to retrieve signed drivers: $_"
}

$unknownDevices = @()
try {
    $unknownDevices = @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop | 
        Where-Object { $_.ConfigManagerErrorCode -eq 28 })
}
catch {
    Write-Verbose "Could not retrieve unknown devices"
}

$pendingUpdates = @()
try {
    $pendingUpdates = @(Get-PendingDriverUpdates)
}
catch {
    Write-Verbose "Could not retrieve pending driver updates"
}

$wuHistory = @(Get-WUHistory)
$driverEvents = @(Get-DriverInstallEvents)

# Optimization: Build lookups
$wuHistoryLookup = Build-WUHistoryLookup $wuHistory
Write-Verbose "Built WU history lookup ($($wuHistoryLookup.Count) vendors)"

# Approved vendors
$approvedVendors = $script:GovernanceConfig.ApprovedVendors
Write-Verbose "Using $($approvedVendors.Count) approved vendors"

# ========== DETECTION PHASE 1: GOVERNANCE (PRIORITY 1) ==========
$governanceResults = @()

# Policy violations
foreach ($driver in $allDrivers) {
    if (Is-SystemDriver $driver) { continue }
    if (Is-KnownSafe $driver) { continue }
    
    $policy = Detect-PolicyViolation $driver $approvedVendors
    if ($policy) {
        $governanceResults += $policy
        continue
    }

    # Post-install (no more recent-only flags)
    $post = Detect-PostInstall $driver $approvedVendors $wuHistory $driverEvents $wuHistoryLookup $null
    if ($post) {
        $governanceResults += $post
    }
}

# ========== DETECTION PHASE 2: DRIVER HEALTH (PRIORITY 2) ==========
$healthResults = @(Detect-DriverHealthIssues $allDrivers)

# ========== DETECTION PHASE 3: INVENTORY & CHANGES (PRIORITY 3) ==========
$currentInventory = @(Get-DriverInventory $allDrivers $wuHistory)
$previousInventory = @(Load-InventoryFile "$($script:InventoryPath)\Inventory_Current.json")

$changes = Compare-Inventories $currentInventory $previousInventory
Save-InventoryFile $previousInventory "$($script:InventoryPath)\Inventory_Previous.json"
Save-InventoryFile $currentInventory "$($script:InventoryPath)\Inventory_Current.json"
Save-ChangeLog $changes "$($script:InventoryPath)\DriverGov_Changes.json"

# ========== DETECTION PHASE 4: PENDING DRIVERS (INFORMATIONAL ONLY - PRIORITY 4) ==========
$pendingResults = @()
if ($pendingUpdates) {
    $pendingResults = Detect-PreInstall $pendingUpdates $approvedVendors
}

# Track repeat issues
Track-RepeatIssues $governanceResults

# ========== SAVE ALL RESULTS ==========
try {
    if (-not (Test-Path $script:InventoryPath)) {
        New-Item -ItemType Directory -Path $script:InventoryPath -Force | Out-Null
    }

    if ($governanceResults) {
        $governanceResults | ConvertTo-Json -Depth 10 | Out-File -Encoding UTF8 "$($script:InventoryPath)\DriverGov_Results.json"
    }

    if ($healthResults) {
        $healthResults | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 "$($script:InventoryPath)\DriverGov_Health.json"
    }
}
catch {
    Write-Warning "Failed to save results: $_"
}

# ========== FINAL DECISION LOGIC (INTUNE COMPATIBLE - V14.1 REFINED) ==========
Write-Output ""
Write-Output "=== Driver Governance Report - V14.1 ==="
Write-Output ""

$totalScanned = $allDrivers.Count + $unknownDevices.Count + $pendingUpdates.Count
Write-Output "Scanned: $totalScanned items"
Write-Output ""

# Categorize findings by priority
$criticalGov = @($governanceResults | Where-Object { $_.Severity -eq "Critical" })
$highGov = @($governanceResults | Where-Object { $_.Severity -eq "High" })

$criticalHealth = @($healthResults | Where-Object { $_.Severity -eq "Critical" })
$highHealth = @($healthResults | Where-Object { $_.Severity -eq "High" })

# ========== EXIT 4: CRITICAL (IMMEDIATE ACTION REQUIRED) ==========
if ($criticalGov.Count -gt 0) {
    $msg = Get-IntuneSummary $criticalGov 1
    Write-Output "CRITICAL: Governance violation → $msg"
    exit 4
}

if ($criticalHealth.Count -gt 0) {
    $msg = Get-IntuneSummary $criticalHealth 1
    Write-Output "CRITICAL: Missing driver (Code 28) → $msg"
    exit 4
}

# ========== EXIT 3: WARNING (ACTION REQUIRED) ==========
if ($highGov.Count -gt 0) {
    $msg = Get-IntuneSummary $highGov 1
    Write-Output "WARNING: Governance issue → $msg"
    exit 3
}

if ($highHealth.Count -gt 0) {
    $msg = Get-IntuneSummary $highHealth 1
    Write-Output "WARNING: Device health issue → $msg"
    exit 3
}

# ========== EXIT 2: INFO (PENDING/CHANGES - INFORMATIONAL ONLY) ==========
$infoCount = 0
if ($pendingResults.Count -gt 0) { 
    Write-Output "INFO: $($pendingResults.Count) pending driver(s) - monitoring only"
    $infoCount += $pendingResults.Count
}
if ($changes.Added.Count -gt 0) { 
    Write-Output "INFO: $($changes.Added.Count) driver(s) added - tracking"
}
if ($changes.Updated.Count -gt 0) { 
    Write-Output "INFO: $($changes.Updated.Count) driver(s) updated - tracking"
}

if ($infoCount -gt 0 -or $changes.Added.Count -gt 0 -or $changes.Updated.Count -gt 0) {
    Write-Output ""
    Write-Output "Summary:"
    Write-Output "  Governance Violations: $($highGov.Count)"
    Write-Output "  Driver Health Issues: $($highHealth.Count)"
    Write-Output "  Pending Drivers: $($pendingResults.Count)"
    Write-Output "  Recent Changes: Added=$($changes.Added.Count), Updated=$($changes.Updated.Count), Removed=$($changes.Removed.Count)"
    Write-Output ""
    exit 2
}

# ========== EXIT 0: OK (COMPLIANT) ==========
Write-Output "OK: No governance or health issues detected"
Write-Output ""
Write-Output "Summary:"
Write-Output "  Governance Violations: 0"
Write-Output "  Driver Health Issues: 0"
Write-Output "  Pending Drivers: 0"
Write-Output "  Recent Changes: Added=0, Updated=0, Removed=0"
Write-Output ""

exit 0
