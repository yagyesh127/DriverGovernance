<#
===========================================================
Driver Governance — V13(Enhanced v3)
===========================================================
✔ Pre-install detection
✔ Policy validation
✔ Post-install detection
✔ False-positive control
✔ Install source accuracy
✔ KMCS signature validation
✔ Risk-aware severity
✔ Recent install detection
✔ Local correlation (repeat issues)
✔ Optional Log Analytics ingestion
✔ Intune exit codes (0 / 2 / 3 / 4)
===========================================================
#>
Write-Output "DEBUG: V13-LITE ENHANCED V3"

# ========================================================================
# GOVERNANCE CONFIG LOADER
# ========================================================================
# Supports three config sources (in priority order):
# 1. External JSON file: C:\ProgramData\DriverGovernance\config.json
# 2. Embedded JSON (Intune-safe fallback)
# 3. Hardcoded defaults (backward compatibility)
# ========================================================================

function Initialize-GovernanceConfig {
    # ========== RECOMMENDED JSON STRUCTURE ==========
    # Location: C:\ProgramData\DriverGovernance\config.json
    # {
    #   "ApprovedVendors": ["Microsoft", "Intel", "Dell", "HP"],
    #   "AllowlistByClass": {
    #     "System": ["Microsoft"],
    #     "Storage": ["Intel", "Broadcom"],
    #     "Network": ["Intel", "Broadcom"]
    #   },
    #   "VendorNormalization": {
    #     "Inte": "Intel",
    #     "Intel Corp": "Intel",
    #     "Broadcom Inc": "Broadcom",
    #     "Advanced Micro Devices": "AMD"
    #   },
    #   "RiskTiers": {
    #     "Microsoft": "trusted",
    #     "Intel": "trusted",
    #     "Dell": "oem",
    #     "HP": "oem"
    #   }
    # }

    $externalPath = "C:\ProgramData\DriverGovernance\config.json"
    
    # Try external file first (admin deployments)
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
    "Processor": ["Intel", "AMD"]
  },
  "VendorNormalization": {
    "Inte": "Intel",
    "Intel Corp": "Intel",
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
        # Fallback: Hardcoded defaults (backward compatible)
        return [PSCustomObject]@{
            ApprovedVendors = @("Microsoft", "Intel", "Dell", "HP")
            AllowlistByClass = @{}
            VendorNormalization = @{}
            RiskTiers = @{}
        }
    }
}

# Load config once at script start
$GovernanceConfig = Initialize-GovernanceConfig

# ========================================================================
# CONFIG-AWARE HELPERS
# ========================================================================

function Normalize-VendorAdvanced {
    param($name, $deviceClass = "")
    
    if (-not $name) { return "Other" }

    # Try explicit normalization mapping first
    if ($GovernanceConfig.VendorNormalization -and $GovernanceConfig.VendorNormalization[$name]) {
        return $GovernanceConfig.VendorNormalization[$name]
    }

    # Fuzzy matching (for vendors not in mapping)
    if ($name -match "Intel") { return "Intel" }
    if ($name -match "Microsoft") { return "Microsoft" }
    if ($name -match "Dell|DellEMC") { return "Dell" }
    if ($name -match "^HP$|HPE|Hewlett") { return "HP" }
    if ($name -match "Lenovo") { return "Lenovo" }
    if ($name -match "Broadcom") { return "Broadcom" }
    if ($name -match "AMD|Advanced Micro") { return "AMD" }
    if ($name -match "NVIDIA") { return "NVIDIA" }
    
    return "Other"
}

function Is-VendorApproved {
    param($vendor, $deviceClass = "")
    
    if (-not $vendor) { return $false }

    # Normalize vendor name
    $normalized = Normalize-VendorAdvanced $vendor $deviceClass

    # Check class-specific allowlist first (if defined)
    if ($deviceClass -and $GovernanceConfig.AllowlistByClass -and 
        $GovernanceConfig.AllowlistByClass[$deviceClass]) {
        $classAllowlist = $GovernanceConfig.AllowlistByClass[$deviceClass]
        if ($classAllowlist -contains $normalized) {
            return $true
        }
        # If class allowlist exists but vendor not in it, deny
        return $false
    }

    # Fall back to global approved vendors list
    if ($GovernanceConfig.ApprovedVendors -contains $normalized) {
        return $true
    }

    return $false
}

function Get-VendorRiskTier {
    param($vendor)
    
    $normalized = Normalize-VendorAdvanced $vendor
    
    if ($GovernanceConfig.RiskTiers -and $GovernanceConfig.RiskTiers[$normalized]) {
        return $GovernanceConfig.RiskTiers[$normalized]
    }
    
    # Default risk tiers if not specified
    if ($normalized -eq "Microsoft") { return "trusted" }
    if ($normalized -in @("Intel", "AMD", "NVIDIA", "Broadcom")) { return "trusted" }
    if ($normalized -in @("Dell", "HP", "Lenovo")) { return "oem" }
    
    return "unknown"
}

# --------CONFIG --------
# DEPRECATED: Direct reference to $ApprovedVendors
# USE: Initialize-GovernanceConfig and Is-VendorApproved instead
# Keeping for reference only
$ApprovedVendors = @("Microsoft","Intel","Dell","HP")

# --------HELPERS --------
function S($v){ 
    if([string]::IsNullOrWhiteSpace("$v")) { 
        return "" 
    } else { 
        return "$v" 
    } 
}

function Normalize-Vendor {
    param($name)
    if ($name -match "Intel") { return "Intel" }
    if ($name -match "Microsoft") { return "Microsoft" }
    if ($name -match "Dell") { return "Dell" }
    if ($name -match "HP") { return "HP" }
    if ($name -match "Lenovo") { return "Lenovo" }
    return "Other"
}

# ---------------- FALSE POSITIVE CONTROL ----------------
function Is-SystemDriver {
    param($d)
    $name = "$($d.DeviceName)"
    return ($name -match "ACPI|System|Motherboard|PCI Bus|Root")
}

function Is-KnownSafe {
    param($d)
    return ($d.DriverProviderName -match "Microsoft" -and $d.DeviceName -match "System")
}

# ========================================================================
# ENTERPRISE RISK CLASSIFICATION MODEL
# ========================================================================
# Aligned with:
# - Microsoft KMCS/WHQL guidance
# - CISA high-risk driver classes
# - CIS benchmarks for Windows driver governance
# - Windows Update trust model
#
# Risk Factors (in order of impact):
# 1. Device Class (firmware > storage > network > gpu > audio > input)
# 2. Signature Status (valid/expired/invalid)
# 3. Vendor Reputation (Microsoft/Intel > OEM > unknown)
# 4. Installation Source (Windows Update > firmware > manual)
# 5. Provider Consistency (provider matches vendor)
# ========================================================================

function Get-DriverRiskScore {
    param(
        [psobject]$Driver,
        [string]$SignatureStatus = "Unknown",
        [string]$InstallSource = "Unknown"
    )

    if (-not $Driver) { return @{ Score=0; Tier="Unknown"; Reasons=@() } }

    $score = 0
    $reasons = @()
    $baseClassRisk = 0

    # ========== FACTOR 1: DEVICE CLASS (CISA/Microsoft KMCS) ==========
    # System/Firmware drivers: CRITICAL baseline
    if ($Driver.DeviceClass -match "System|Processor|Motherboard|Chipset|BIOS|Firmware") {
        $baseClassRisk = 85
        $reasons += "System/firmware driver (critical infrastructure)"
    }
    # Audio drivers: HIGH (CISA flagged - malware vector)
    elseif ($Driver.DeviceClass -match "Audio|Sound|Media") {
        $baseClassRisk = 70
        $reasons += "Audio driver (CISA high-risk class)"
    }
    # Storage/RAID: HIGH (data access critical)
    elseif ($Driver.DeviceClass -match "Storage|SCSI|Disk|SAN|RAID|ATA|SATA|NVMe") {
        $baseClassRisk = 75
        $reasons += "Storage/RAID driver (data access critical)"
    }
    # Display/GPU: HIGH (display security, recent CVEs)
    elseif ($Driver.DeviceClass -match "Display|Video|GPU|Graphics|3D") {
        $baseClassRisk = 70
        $reasons += "Display/GPU driver (kernel access, recent CVEs)"
    }
    # Network: MEDIUM-HIGH (connectivity critical, wide attack surface)
    elseif ($Driver.DeviceClass -match "Net|Network|Ethernet|Wireless|WLAN|WiFi") {
        $baseClassRisk = 65
        $reasons += "Network driver (connectivity critical)"
    }
    # Bluetooth/Wireless: MEDIUM (external interface)
    elseif ($Driver.DeviceClass -match "Bluetooth|Wireless") {
        $baseClassRisk = 55
        $reasons += "Bluetooth/wireless (external interface)"
    }
    # USB/HID: MEDIUM (input vectors, external)
    elseif ($Driver.DeviceClass -match "USB|HID|Keyboard|Mouse|Input") {
        $baseClassRisk = 50
        $reasons += "Input/USB driver (external attack surface)"
    }
    # Everything else: LOW
    else {
        $baseClassRisk = 30
    }

    $score += $baseClassRisk

    # ========== FACTOR 2: SIGNATURE STATUS ==========
    # Invalid/unsigned signatures: +40 points
    if ($SignatureStatus -eq "Invalid" -or $SignatureStatus -eq "Unknown") {
        $score += 40
        $reasons += "Invalid/missing signature (+40)"
    }
    # Expired signature: +25 points
    elseif ($SignatureStatus -eq "Expired") {
        $score += 25
        $reasons += "Expired signature (+25)"
    }
    # Non-Microsoft signature: +15 points
    elseif ($SignatureStatus -eq "NonMicrosoft") {
        $score += 15
        $reasons += "Third-party signature (+15)"
    }
    # Valid Microsoft signature: -10 points (reduces risk)
    elseif ($SignatureStatus -eq "Valid") {
        $score -= 10
        $reasons += "Valid signature (-10)"
    }

    # ========== FACTOR 3: VENDOR REPUTATION ==========
    $vendor = Normalize-VendorAdvanced $Driver.DriverProviderName
    $vendorRiskModifier = 0

    if ($vendor -eq "Microsoft") {
        $vendorRiskModifier = -15
        $reasons += "Microsoft vendor (-15, trusted)"
    }
    elseif ($vendor -in @("Intel", "AMD", "NVIDIA", "Broadcom")) {
        $vendorRiskModifier = -10
        $reasons += "$vendor vendor (-10, trusted)"
    }
    elseif ($vendor -in @("Dell", "HP", "Lenovo")) {
        $vendorRiskModifier = -5
        $reasons += "$vendor OEM (-5, known)"
    }
    else {
        $vendorRiskModifier = 10
        $reasons += "$vendor vendor (+10, unverified)"
    }

    $score += $vendorRiskModifier

    # ========== FACTOR 4: INSTALLATION SOURCE ==========
    if ($InstallSource -eq "Windows Update") {
        $score -= 15
        $reasons += "Windows Update origin (-15, vetted)"
    }
    elseif ($InstallSource -eq "DriverFramework") {
        $score -= 8
        $reasons += "DriverFramework detected (-8, logged)"
    }
    elseif ($InstallSource -eq "OEM/Manual") {
        $score += 10
        $reasons += "OEM/Manual origin (+10, unvetted)"
    }

    # ========== CLAMP SCORE ==========
    $score = [Math]::Max(0, [Math]::Min(100, $score))

    # ========== MAP TO RISK TIER ==========
    $tier = switch ($score) {
        { $_ -ge 80 }  { "Critical" }
        { $_ -ge 60 }  { "High" }
        { $_ -ge 40 }  { "Medium" }
        { $_ -ge 20 }  { "Low" }
        default        { "Minimal" }
    }

    return @{
        Score = $score
        Tier = $tier
        Reasons = $reasons
        BaseClassRisk = $baseClassRisk
        VendorModifier = $vendorRiskModifier
    }
}

function Get-DriverRiskClass {
    param($d, $signatureStatus = "Unknown", $installSource = "Unknown")
    
    $result = Get-DriverRiskScore $d $signatureStatus $installSource
    
    # For backward compatibility, still return just the tier string
    # Callers can use Get-DriverRiskScore for full details
    return $result.Tier
}

# ---------------- SIGNATURE CHECK ----------------
function Get-DriverSignatureLevel {
    param($d)

    # Ensure INF name exists
    if (-not $d.InfName) {
        return "Unknown"
    }

    $path = Join-Path $env:windir "INF\$($d.InfName)"

    # Ensure path exists AND is a file
    if (-not (Test-Path $path -PathType Leaf)) {
        return "Unknown"
    }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $path

        if (-not $sig) { return "Unknown" }

        if ($sig.Status -ne "Valid") {
            return "Invalid"
        }

        if ($sig.SignerCertificate -and $sig.SignerCertificate.NotAfter -lt (Get-Date)) {
            return "Expired"
        }

        if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -notmatch "Microsoft") {
            return "NonMicrosoft"
        }

        return "Valid"
    }
    catch {
        return "Unknown"
    }
}

# ---------------- RECENT INSTALL ----------------
function Get-RecentDriverInstall {
    param($d)
    try {
        return ((New-TimeSpan -Start ([datetime]$d.DriverDate) -End (Get-Date)).Days -lt 3)
    } catch { return $false }
}

# ---------------- CONFIDENCE ----------------
function Get-ConfidenceLite {
    param($approved,$sig,$recent)

    $c = 100

    if (-not $approved) { $c -= 20 }
    if ($sig -ne "Valid") { $c -= 20 }

    # OLD (counter-intuitive)
    # if (-not $recent) { $c -= 10 }

    # NEW (change-risk aligned)
    if ($recent) { $c -= 10 }

    return $c
}

# ---------------- INVENTORY ----------------
function Get-InstalledDrivers {
    try {
        Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to retrieve installed drivers: $_"
        return @()
    }
}

# ---------------- WINDOWS UPDATE ----------------
function Get-PendingDrivers {
    try {
        $s = New-Object -ComObject Microsoft.Update.Session
        ($s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Driver'")).Updates
    } catch { @() }
}

# ---------------- INSTALL SOURCE ----------------
function Get-WUHistory {
    try {
        $s = New-Object -ComObject Microsoft.Update.Session
        return $s.QueryHistory("",0,50)
    } catch { @() }
}

function Get-DriverInstallEvents {
    try {
        Get-WinEvent -LogName "Microsoft-Windows-DriverFrameworks-UserMode/Operational" -MaxEvents 50
    } catch { @() }
}

function Resolve-InstallSource {
    param(
        [psobject]$Driver,
        [array]$WUHistory,
        [array]$DriverFrameworkEvents
    )

    if (-not $Driver) { return "Unknown" }

    # ========== SIGNAL 1: PROVIDER NAME HEURISTICS ==========
    # Microsoft drivers are almost always from Windows Update
    if ($Driver.DriverProviderName -eq "Microsoft") {
        return "Windows Update"
    }

    # Known OEM/vendor providers typically come from Windows Update
    $WUVendors = @("Intel","AMD","NVIDIA","Broadcom","Qualcomm","Marvell","LSI","Adaptec","Realtek","Atheros","Mellanox")
    if ($WUVendors -contains $Driver.DriverProviderName) {
        return "Windows Update"
    }

    # ========== SIGNAL 2: INF FILE ANALYSIS ==========
    # Parse INF to detect Windows Update markers
    if ($Driver.InfName) {
        $infPath = Join-Path $env:windir "INF\$($Driver.InfName)"
        if (Test-Path $infPath -PathType Leaf) {
            try {
                $infContent = @(Get-Content $infPath -Raw -ErrorAction Stop) -join "`n"
                # Look for WU-specific directives (WHQL, Windows Update catalog markers)
                if ($infContent -match "(?i)Windows.*Update|WHQL|CatalogFile") {
                    return "Windows Update"
                }
            }
            catch {}
        }
    }

    # ========== SIGNAL 3: DEVICE CLASS HEURISTICS ==========
    # Certain classes almost never come from OEM sources in enterprise environments
    $WUClassPatterns = @("System","Processor|CPU","Storage.*Controller","NET|Network","USB Host Controller","HID")
    $classMatch = $WUClassPatterns | Where-Object { $Driver.DeviceClass -match $_ }
    
    if ($classMatch -and $Driver.DriverProviderName -notmatch "Custom|OEM|Vendor") {
        # Reinforce Windows Update attribution for core device classes
        if ($Driver.DriverProviderName -match "Standard|Compatible") {
            return "Windows Update"
        }
    }

    # ========== SIGNAL 4: WINDOWS UPDATE HISTORY CORRELATION ==========
    # Multi-strategy matching against WU history (avoid regex injection)
    if ($WUHistory -and $WUHistory.Count -gt 0) {
        foreach ($entry in $WUHistory) {
            if (-not $entry.Title) { continue }

            # Strategy 1: Exact provider name match
            if ($entry.Title -match [regex]::Escape($Driver.DriverProviderName)) {
                return "Windows Update"
            }

            # Strategy 2: Device name + provider combined
            if ($Driver.DeviceName -and ($entry.Title -like "*$($Driver.DriverProviderName)*" -or 
                                         $entry.Title -like "*$($Driver.DeviceName)*")) {
                # Verify driver version matches to reduce false positives
                if ($Driver.DriverVersion -and $entry.Title -like "*$($Driver.DriverVersion)*") {
                    return "Windows Update"
                }
                # At least provider + device or provider + version = confidence boost
                if ($entry.Title -match [regex]::Escape($Driver.DriverProviderName)) {
                    return "Windows Update"
                }
            }

            # Strategy 3: Version number correlation (specific indicator)
            if ($Driver.DriverVersion -and $entry.Title -match [regex]::Escape($Driver.DriverVersion)) {
                return "Windows Update"
            }
        }
    }

    # ========== SIGNAL 5: DRIVERFRAMEWORK EVENT CORRELATION ==========
    # DriverFramework events indicate recent driver activity
    if ($DriverFrameworkEvents -and $DriverFrameworkEvents.Count -gt 0) {
        foreach ($event in $DriverFrameworkEvents) {
            if (-not $event.Message) { continue }

            # Match INF name (most reliable signal from DriverFramework)
            if ($Driver.InfName -and $event.Message -match [regex]::Escape($Driver.InfName)) {
                return "DriverFramework"
            }

            # Match provider + device combination
            if ($Driver.DriverProviderName -and $Driver.DeviceName -and 
                $event.Message -match [regex]::Escape($Driver.DriverProviderName) -and
                $event.Message -match [regex]::Escape($Driver.DeviceName)) {
                return "DriverFramework"
            }
        }
    }

    # ========== DEFAULT: OEM/MANUAL ==========
    # If no Windows Update or DriverFramework signals detected, assume OEM/Manual
    return "OEM/Manual"
}

# ---------------- PRE-INSTALL ----------------
function Detect-PreInstall {
    param($pending,$approvedVendors)

    $alerts = @()

    foreach ($p in $pending) {
        $vendor = Normalize-VendorAdvanced $p.Title

        # Use config-aware approval check
        if (-not (Is-VendorApproved $vendor)) {
            $alerts += [PSCustomObject]@{
                Stage="PreInstall"; Driver=$p.Title; Vendor=$vendor
                Severity="Medium"; Message="Unapproved driver pending"
            }
        }
    }
    return $alerts
}

# ---------------- POLICY ----------------
function Detect-PolicyViolation {
    param($d,$approvedVendors)

    if (-not $d -or -not $approvedVendors) { return $null }

    $vendor = Normalize-VendorAdvanced $d.DriverProviderName
    $deviceClass = $d.DeviceClass

    # Use config-aware approval check with device class context
    if (-not (Is-VendorApproved $vendor $deviceClass)) {
        return [PSCustomObject]@{
            Stage="Policy"; Driver=$d.DeviceName; Vendor=$vendor
            Severity="High"; Message="Vendor not approved for class: $deviceClass"
        }
    }
    return $null
}

# ---------------- POST-INSTALL ----------------
function Detect-PostInstall {
    param($d,$approvedVendors,$wu,$events)

    if (-not $d -or -not $approvedVendors) { return $null }
    if (Is-SystemDriver $d) { return $null }
    if (Is-KnownSafe $d) { return $null }

    $vendor = Normalize-VendorAdvanced $d.DriverProviderName
    $deviceClass = $d.DeviceClass
    $sig    = Get-DriverSignatureLevel $d
    $recent = Get-RecentDriverInstall $d
    $src    = Resolve-InstallSource -Driver $d -WUHistory $wu -DriverFrameworkEvents $events
    $risk   = Get-DriverRiskClass $d $sig $src
    $approved = Is-VendorApproved $vendor $deviceClass

    $confidence = Get-ConfidenceLite $approved $sig $recent

    if (-not $approved -or $sig -ne "Valid") {

        $severity = switch ($risk) {
            "Critical" { "Critical" }
            "High"     { "High" }
            "Medium"   { "Medium" }
            default    { "Low" }
        }

        return [PSCustomObject]@{
            Stage="PostInstall"
            Driver=$d.DeviceName
            Vendor=$vendor
            Version=$d.DriverVersion
            Risk=$risk
            Signature=$sig
            InstallSource=$src
            Confidence=$confidence
            Severity=$severity
            Message="Driver risk detected"
        }
    }
    return $null
}

# ---------------- LOCAL CORRELATION ----------------
function Track-RepeatIssues {
    param(
        [array]$Results,
        [int]$Threshold = 3,
        [int]$WindowDays = 14
    )

    if (-not $Results -or $Results.Count -eq 0) { return }

    $path = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DriverGov_History.json"
    $now  = Get-Date

    # ---------------- SAFE LOAD ----------------
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

    # ---------------- ADD TIMESTAMP ----------------
    foreach ($r in $Results) {
        if (-not $r.PSObject.Properties["Timestamp"]) {
            $r | Add-Member -NotePropertyName Timestamp -NotePropertyValue $now -Force
        }
    }

    # ---------------- TRIM OLD HISTORY ----------------
    $history = $history | Where-Object {
        try { ([datetime]$_.Timestamp) -gt $now.AddDays(-$WindowDays) }
        catch { $false }
    }

    # ---------------- MERGE + LIMIT SIZE ----------------
    $combined = @($history + $Results) | Select-Object -Last 500

    # ---------------- GROUP BY EXACT KEY ----------------
    $grouped = $combined | Group-Object {
        ("$($_.Driver)|$($_.Vendor)|$($_.Version)").ToLower()
    }

    foreach ($g in $grouped) {
        if ($g.Count -ge $Threshold) {
            $groupKey = $g.Name

            foreach ($item in $Results) {
                $itemKey = ("$($item.Driver)|$($item.Vendor)|$($item.Version)").ToLower()

                if ($groupKey -eq $itemKey) {
                    $item | Add-Member `
                        -NotePropertyName RepeatFlag `
                        -NotePropertyValue "RepeatedIssue" `
                        -Force
                }
            }
        }
    }

    # ---------------- SAVE BACK ----------------
    try {
        $combined | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 $path
    }
    catch {}
}

# ---------------- OPTIONAL LOG ANALYTICS ----------------
# ========================================================================
# OPTIONAL: LOG ANALYTICS INGESTION (PLACEHOLDER)
# NOTE:
# - This is a stub and will NOT authenticate as-is.
# - Requires HMAC-SHA256 signature, x-ms-date header, and proper authorization.
# - Intentionally disabled to avoid runtime failures.
# ========================================================================
function Send-ToLogAnalytics {
    param($data)

    $WorkspaceId=""; $SharedKey=""
    if (-not $WorkspaceId) { return }

    $json=$data|ConvertTo-Json -Depth 5

    try {
        Invoke-RestMethod -Method Post `
        -Uri "https://$WorkspaceId.ods.opinsights.azure.com/api/logs?api-version=2016-04-01" `
        -Headers @{ "Content-Type"="application/json"; "Log-Type"="DriverGov" } `
        -Body $json
    } catch {}
}
# ========================================================================
# PERFORMANCE OPTIMIZATION LAYER
# ========================================================================
# Reduces per-driver loop cost through caching and pre-processing
# ========================================================================

function Initialize-PerformanceCache {
    $script:SignatureCache = @{}
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
                if (-not $sig) { $result = "Unknown" }
                elseif ($sig.Status -ne "Valid") { $result = "Invalid" }
                elseif ($sig.SignerCertificate -and $sig.SignerCertificate.NotAfter -lt (Get-Date)) { $result = "Expired" }
                elseif ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -notmatch "Microsoft") { $result = "NonMicrosoft" }
                else { $result = "Valid" }
            }
            catch {
                $result = "Unknown"
            }
        }
    }
    $script:SignatureCache[$InfName] = $result
    return $result
}

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

function Pre-FilterEventLogs {
    param([array]$Events)
    
    if (-not $Events -or $Events.Count -eq 0) { return @() }
    return @($Events | Where-Object { $_.Message -match "Storage|System|Audio|Display|Network" })
}

function Resolve-InstallSourceOptimized {
    param(
        [psobject]$Driver,
        [array]$WUHistory,
        [array]$DriverFrameworkEventsFiltered,
        [hashtable]$WUHistoryLookup
    )

    if (-not $Driver) { return "Unknown" }

    if ($Driver.DriverProviderName -eq "Microsoft") { return "Windows Update" }
    
    $WUVendors = @("Intel","AMD","NVIDIA","Broadcom","Qualcomm","Marvell","LSI","Adaptec","Realtek","Atheros","Mellanox")
    if ($WUVendors -contains $Driver.DriverProviderName) { return "Windows Update" }

    if ($Driver.InfName) {
        $infPath = Join-Path $env:windir "INF\$($Driver.InfName)"
        if (Test-Path $infPath -PathType Leaf) {
            try {
                $infContent = Get-Content $infPath -Raw -ErrorAction Stop
                if ($infContent -match "(?i)Windows.*Update|WHQL|CatalogFile") { return "Windows Update" }
            }
            catch {}
        }
    }

    $WUClassPatterns = @("System","Processor|CPU","Storage.*Controller","NET|Network","USB Host Controller","HID")
    $classMatch = $WUClassPatterns | Where-Object { $Driver.DeviceClass -match $_ }
    if ($classMatch -and $Driver.DriverProviderName -notmatch "Custom|OEM|Vendor" -and 
        $Driver.DriverProviderName -match "Standard|Compatible") { return "Windows Update" }

    if ($WUHistoryLookup -and $WUHistoryLookup.Count -gt 0 -and $WUHistoryLookup.ContainsKey($Driver.DriverProviderName)) {
        foreach ($entry in $WUHistoryLookup[$Driver.DriverProviderName]) {
            if ($entry.Title -match [regex]::Escape($Driver.DriverVersion)) { return "Windows Update" }
        }
    }

    if ($DriverFrameworkEventsFiltered -and $DriverFrameworkEventsFiltered.Count -gt 0) {
        foreach ($event in $DriverFrameworkEventsFiltered) {
            if ($Driver.InfName -and $event.Message -match [regex]::Escape($Driver.InfName)) { return "DriverFramework" }
            if ($Driver.DriverProviderName -and $Driver.DeviceName -and 
                $event.Message -match [regex]::Escape($Driver.DriverProviderName) -and
                $event.Message -match [regex]::Escape($Driver.DeviceName)) { return "DriverFramework" }
        }
    }

    return "OEM/Manual"
}

function Detect-PostInstallOptimized {
    param($d, $approvedVendors, $wu, $events, $wuLookup, $eventsFiltered)

    if (-not $d -or -not $approvedVendors) { return $null }
    if (Is-SystemDriver $d) { return $null }
    if (Is-KnownSafe $d) { return $null }

    $vendor = Normalize-VendorAdvanced $d.DriverProviderName
    $deviceClass = $d.DeviceClass
    $sig = Get-CachedSignature -InfName $d.InfName
    $recent = Get-RecentDriverInstall $d
    $src = Resolve-InstallSourceOptimized -Driver $d -WUHistory $wu -DriverFrameworkEventsFiltered $eventsFiltered -WUHistoryLookup $wuLookup
    $risk = Get-DriverRiskClass $d $sig $src
    $approved = Is-VendorApproved $vendor $deviceClass

    $confidence = Get-ConfidenceLite $approved $sig $recent

    if (-not $approved -or $sig -ne "Valid") {
        $severity = switch ($risk) {
            "Critical" { "Critical" }
            "High" { "High" }
            "Medium" { "Medium" }
            default { "Low" }
        }

        return [PSCustomObject]@{
            Stage="PostInstall"
            Driver=$d.DeviceName
            Vendor=$vendor
            Version=$d.DriverVersion
            Risk=$risk
            Signature=$sig
            InstallSource=$src
            Confidence=$confidence
            Severity=$severity
            Message="Driver risk detected"
        }
    }
    return $null
}
# ---------------- MAIN ----------------
$results=@()

$pending=Get-PendingDrivers
$wu=Get-WUHistory
$events=Get-DriverInstallEvents

# Initialize performance optimization layer
Initialize-PerformanceCache
$wuLookup = Build-WUHistoryLookup $wu
$eventsFiltered = Pre-FilterEventLogs $events

$results+=Detect-PreInstall $pending $ApprovedVendors

$drivers=Get-InstalledDrivers

foreach($d in $drivers){
    $p=Detect-PolicyViolation $d $ApprovedVendors
    if($p){$results+=$p}

    # Use optimized detection with pre-built lookups
    $post=Detect-PostInstallOptimized $d $ApprovedVendors $wu $events $wuLookup $eventsFiltered
    if($post){$results+=$post}
}

Track-RepeatIssues $results
Send-ToLogAnalytics $results


# ---------------- OUTPUT ----------------

# Helper: build concise top-driver summary
function Get-TopDriversSummary {
    param(
        [array]$items,
        [int]$limit = 3
    )

    if (-not $items -or $items.Count -eq 0) { return "" }

    # Remove duplicates based on Driver+Vendor+Version
    $unique = $items | Sort-Object Driver, Vendor, Version | Select-Object -Unique

    # Prioritize higher severity first (Critical > High > Medium)
    $ordered = $unique | Sort-Object @{
        Expression = {
            switch ($_.Severity) {
                "Critical" { 3 }
                "High"     { 2 }
                "Medium"   { 1 }
                default    { 0 }
            }
        }
        Descending = $true
    }

    $top = $ordered | Select-Object -First $limit

    if (-not $top) { return "" }

    return ($top | ForEach-Object {
        $driver = if ($_.PSObject.Properties['Driver']) { $_.Driver } else { "Unknown" }
        $vendor = if ($_.PSObject.Properties['Vendor']) { $_.Vendor } else { "Unknown" }
        $version = if ($_.PSObject.Properties['Version']) { $_.Version } else { "Unknown" }
        $signature = if ($_.PSObject.Properties['Signature']) { $_.Signature } else { "Unknown" }
        $source = if ($_.PSObject.Properties['InstallSource']) { $_.InstallSource } else { "Unknown" }
        "$driver [$vendor] v$version ($signature, $source)"
    }) -join " | "
}

# Categorize results
$criticalPost = $results | Where-Object {
    $_ -and $_.PSObject.Properties['Stage'] -and $_.PSObject.Properties['Severity'] -and 
    $_.Stage -eq "PostInstall" -and $_.Severity -eq "Critical"
}

$anyPost = $results | Where-Object {
    $_ -and $_.PSObject.Properties['Stage'] -and $_.Stage -eq "PostInstall"
}

$policy = $results | Where-Object {
    $_ -and $_.PSObject.Properties['Stage'] -and $_.Stage -eq "Policy"
}

$pre = $results | Where-Object {
    $_ -and $_.PSObject.Properties['Stage'] -and $_.Stage -eq "PreInstall"
}

# Decision logic

if ($criticalPost -and $criticalPost.Count -gt 0) {
    $msg = Get-TopDriversSummary $criticalPost 3
    if (-not [string]::IsNullOrWhiteSpace($msg)) {
        Write-Output "CRITICAL: $msg"
    } else {
        Write-Output "CRITICAL: Driver governance violations detected"
    }
    exit 4
}

if ($anyPost -and $anyPost.Count -gt 0) {
    $msg = Get-TopDriversSummary $anyPost 3
    if (-not [string]::IsNullOrWhiteSpace($msg)) {
        Write-Output "WARNING: $msg"
    } else {
        Write-Output "WARNING: Driver issues detected"
    }
    exit 3
}

if ($policy -and $policy.Count -gt 0) {
    $msg = Get-TopDriversSummary $policy 3
    if (-not [string]::IsNullOrWhiteSpace($msg)) {
        Write-Output "WARNING: Policy issue → $msg"
    } else {
        Write-Output "WARNING: Policy violations detected"
    }
    exit 3
}

if ($pre -and $pre.Count -gt 0) {
    $msg = Get-TopDriversSummary $pre 3
    if (-not [string]::IsNullOrWhiteSpace($msg)) {
        Write-Output "INFO: Pending → $msg"
    } else {
        Write-Output "INFO: Pending driver updates"
    }
    exit 2
}

Write-Output "OK: No driver governance issues detected"
exit 0