#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Managed Device Compliance Report (Android & iOS) - Erweiterte Version
    Erstellt einen dynamischen HTML-Report mit Dashboard, Policy-Metadaten,
    Mismatch-Erkennung und verbesserter Non-Compliance Analyse.

.DESCRIPTION
    - Authentifizierung via App Registration (Client Credentials)
    - Abfrage aller Android/iOS Managed Devices
    - Ermittlung der exakten Non-Compliance-Gründe pro Gerät (Setting-Ebene)
    - Policy-Metadaten Abruf (OS-Versionen, Anforderungen)
    - Automatische Mismatch-Erkennung (z.B. ADE-Policy auf BYOD-Gerät)
    - Ausgabe als interaktiver HTML-Report mit Dashboard, Filter und Sortierung

.NOTES
    Benötigte Graph API Permissions (Application):
      - DeviceManagementManagedDevices.Read.All
      - DeviceManagementConfiguration.Read.All

    Author  : ProtinaGPT
    Version : 2.0
    Date    : 2026-04-20
#>

# ==============================================================================
# KONFIGURATION
# ==============================================================================
$TenantId     = "Value"
$ClientId     = "Value"
$ClientSecret = "Value"

$ReportPath   = "C:\Scripts\Intune_Compliance_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

# Schwellwert in Tagen: ab wann gilt "Sync zu alt"
$SyncWarningDays = 7

# ==============================================================================
# FUNKTIONEN
# ==============================================================================

function Get-GraphAccessToken {
    param([string]$TenantId, [string]$ClientId, [string]$ClientSecret)
    Write-Host "[AUTH] Hole Access Token..." -ForegroundColor Cyan
    $Body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    try {
        $Response = Invoke-RestMethod -Method POST `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -ContentType "application/x-www-form-urlencoded" `
            -Body $Body -ErrorAction Stop
        Write-Host "[AUTH] Token OK. Gültig $($Response.expires_in)s." -ForegroundColor Green
        return $Response.access_token
    } catch {
        Write-Error "[AUTH] Token-Fehler: $_"; exit 1
    }
}

function Invoke-GraphRequest {
    param([string]$Uri, [string]$AccessToken)
    $Headers    = @{ Authorization = "Bearer $AccessToken" }
    $AllResults = @()
    do {
        try {
            $Response = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers -ErrorAction Stop
            if ($Response.value) { $AllResults += $Response.value }
            else                 { $AllResults += $Response }
            $Uri = $Response.'@odata.nextLink'
        } catch {
            Write-Warning "[GRAPH] Fehler bei URI: $Uri | $_"
            $Uri = $null
        }
    } while ($Uri)
    return $AllResults
}

function Get-DeviceComplianceDetails {
    param([string]$DeviceId, [string]$AccessToken)

    $Uri         = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$DeviceId')/deviceCompliancePolicyStates"
    $PolicyStates = Invoke-GraphRequest -Uri $Uri -AccessToken $AccessToken
    $Details     = @()

    foreach ($Policy in $PolicyStates) {
        if ($Policy.state -ne "compliant") {
            $SettingUri    = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$DeviceId')/deviceCompliancePolicyStates('$($Policy.id)')/settingStates"
            $SettingStates = Invoke-GraphRequest -Uri $SettingUri -AccessToken $AccessToken

            # Alle non-compliant Settings inkl. notApplicable erfassen
            $NonCompliantSettings = $SettingStates | Where-Object { $_.state -ne "compliant" }

            if ($NonCompliantSettings.Count -gt 0) {
                foreach ($Setting in $NonCompliantSettings) {
                    $Details += [PSCustomObject]@{
                        PolicyName    = $Policy.displayName
                        PolicyId      = $Policy.id
                        PolicyState   = $Policy.state
                        SettingName   = $Setting.setting
                        SettingState  = $Setting.state
                        ErrorCode     = $Setting.errorCode
                        UserPrincipal = if ($Setting.userPrincipalName) { $Setting.userPrincipalName } else { "N/A" }
                        HasDetail     = $true
                    }
                }
            } else {
                # Fallback: Policy verletzt, aber keine Setting-Details verfügbar
                $Details += [PSCustomObject]@{
                    PolicyName    = $Policy.displayName
                    PolicyId      = $Policy.id
                    PolicyState   = $Policy.state
                    SettingName   = "(Keine Setting-Details — siehe Mismatch-Analyse)"
                    SettingState  = $Policy.state
                    ErrorCode     = "N/A"
                    UserPrincipal = "N/A"
                    HasDetail     = $false
                }
            }
        }
    }
    return $Details
}

function Get-CompliancePolicyMetadata {
    param([string]$PolicyId, [string]$AccessToken)

    $Uri    = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId"
    $Policy = $null
    try {
        $Headers = @{ Authorization = "Bearer $AccessToken" }
        $Policy  = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers -ErrorAction Stop
    } catch {
        return $null
    }

    return [PSCustomObject]@{
        DisplayName           = $Policy.displayName
        ODataType             = ($Policy.'@odata.type' -replace '#microsoft.graph.', '')
        OsMinimumVersion      = if ($Policy.osMinimumVersion)      { $Policy.osMinimumVersion }      else { "—" }
        OsMaximumVersion      = if ($Policy.osMaximumVersion)      { $Policy.osMaximumVersion }      else { "—" }
        PasswordRequired      = if ($null -ne $Policy.passwordRequired)      { $Policy.passwordRequired }      else { "—" }
        StorageEncryption     = if ($null -ne $Policy.storageRequireEncryption) { $Policy.storageRequireEncryption } else { "—" }
        ActiveFirewall        = if ($null -ne $Policy.activeFirewallRequired) { $Policy.activeFirewallRequired } else { "—" }
        DeviceThreatLevel     = if ($Policy.deviceThreatProtectionRequiredSecurityLevel) { $Policy.deviceThreatProtectionRequiredSecurityLevel } else { "—" }
        IsADEPolicy           = ($Policy.displayName -match 'ADE|AutomatedDeviceEnrollment|Automated Device')
        IsBYODPolicy          = ($Policy.displayName -match 'BYOD|Work Profile|Personal')
        IsCOBOPolicy          = ($Policy.displayName -match 'COBO|Corporate|company')
        IsWindowsPolicy       = ($Policy.'@odata.type' -match 'windows')
        IsAndroidPolicy       = ($Policy.'@odata.type' -match 'android|AndroidForWork')
        IsiOSPolicy           = ($Policy.'@odata.type' -match 'ios')
    }
}

function Get-MismatchAnalysis {
    param(
        $Device,
        $PolicyMeta
    )

    $Mismatches = @()
    $DeviceOS   = $Device.operatingSystem   # "Android" oder "iOS"
    $OwnerType  = $Device.managedDeviceOwnerType  # "personal" oder "company"
    $OsVersion  = $Device.osVersion

    if (-not $PolicyMeta) { return $Mismatches }

    # 1. Windows-Policy auf Android/iOS
    if ($PolicyMeta.IsWindowsPolicy -and $DeviceOS -in @("Android","iOS")) {
        $Mismatches += [PSCustomObject]@{
            Severity    = "critical"
            Icon        = "🔴"
            Category    = "Policy-OS-Mismatch"
            Description = "Windows Compliance Policy auf $DeviceOS Gerät zugewiesen — nicht kompatibel!"
            Action      = "Policy-Zuweisung sofort entfernen"
        }
    }

    # 2. ADE-Policy auf BYOD/Personal Gerät
    if ($PolicyMeta.IsADEPolicy -and $OwnerType -eq "personal") {
        $Mismatches += [PSCustomObject]@{
            Severity    = "critical"
            Icon        = "🔴"
            Category    = "Enrollment-Mismatch"
            Description = "ADE-Policy (für corporate-owned Geräte) auf persönlichem BYOD-Gerät zugewiesen."
            Action      = "ADE-Policy entfernen, BYOD-Policy zuweisen"
        }
    }

    # 3. BYOD-Policy auf Company-owned Gerät
    if ($PolicyMeta.IsBYODPolicy -and $OwnerType -eq "company") {
        $Mismatches += [PSCustomObject]@{
            Severity    = "warning"
            Icon        = "🟡"
            Category    = "Enrollment-Mismatch"
            Description = "BYOD-Policy auf einem company-owned Gerät zugewiesen."
            Action      = "COBO/Corporate-Policy zuweisen statt BYOD-Policy"
        }
    }

    # 4. iOS-Policy auf Android
    if ($PolicyMeta.IsiOSPolicy -and $DeviceOS -eq "Android") {
        $Mismatches += [PSCustomObject]@{
            Severity    = "critical"
            Icon        = "🔴"
            Category    = "Policy-OS-Mismatch"
            Description = "iOS Compliance Policy auf Android Gerät zugewiesen."
            Action      = "Policy-Zuweisung korrigieren"
        }
    }

    # 5. Android-Policy auf iOS
    if ($PolicyMeta.IsAndroidPolicy -and $DeviceOS -eq "iOS") {
        $Mismatches += [PSCustomObject]@{
            Severity    = "critical"
            Icon        = "🔴"
            Category    = "Policy-OS-Mismatch"
            Description = "Android Compliance Policy auf iOS Gerät zugewiesen."
            Action      = "Policy-Zuweisung korrigieren"
        }
    }

    # 6. OS-Version zu hoch (Max-Version überschritten)
    if ($PolicyMeta.OsMaximumVersion -ne "—" -and $OsVersion) {
        try {
            $DevVer = [Version]($OsVersion -replace '[^0-9.]','')
            $MaxVer = [Version]($PolicyMeta.OsMaximumVersion -replace '[^0-9.]','')
            if ($DevVer -gt $MaxVer) {
                $Mismatches += [PSCustomObject]@{
                    Severity    = "warning"
                    Icon        = "🟡"
                    Category    = "OS-Version"
                    Description = "OS Version $OsVersion überschreitet erlaubtes Maximum ($($PolicyMeta.OsMaximumVersion))."
                    Action      = "Max-OS-Version in Policy anpassen oder Gerät updaten"
                }
            }
        } catch {}
    }

    # 7. OS-Version zu niedrig (Min-Version unterschritten)
    if ($PolicyMeta.OsMinimumVersion -ne "—" -and $OsVersion) {
        try {
            $DevVer = [Version]($OsVersion -replace '[^0-9.]','')
            $MinVer = [Version]($PolicyMeta.OsMinimumVersion -replace '[^0-9.]','')
            if ($DevVer -lt $MinVer) {
                $Mismatches += [PSCustomObject]@{
                    Severity    = "warning"
                    Icon        = "🟡"
                    Category    = "OS-Version"
                    Description = "OS Version $OsVersion unterschreitet Minimum ($($PolicyMeta.OsMinimumVersion))."
                    Action      = "Gerät auf OS $($PolicyMeta.OsMinimumVersion)+ updaten"
                }
            }
        } catch {}
    }

    return $Mismatches
}

# ==============================================================================
# HAUPTPROGRAMM
# ==============================================================================

Write-Host "============================================================" -ForegroundColor Magenta
Write-Host " Intune Compliance Report v2.0 - Android & iOS" -ForegroundColor Magenta
Write-Host " $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta

$Token = Get-GraphAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

# Alle Android & iOS Managed Devices
Write-Host "`n[DEVICES] Lade Managed Devices (Android & iOS)..." -ForegroundColor Cyan
$DeviceUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=(operatingSystem eq 'Android' or operatingSystem eq 'iOS')&`$select=id,deviceName,userDisplayName,userPrincipalName,operatingSystem,osVersion,complianceState,lastSyncDateTime,enrolledDateTime,manufacturer,model,serialNumber,imei,managedDeviceOwnerType,deviceEnrollmentType,azureADDeviceId,emailAddress"
$AllDevices = Invoke-GraphRequest -Uri $DeviceUri -AccessToken $Token
Write-Host "[DEVICES] $($AllDevices.Count) Geräte gefunden." -ForegroundColor Green

# Statistiken
$TotalDevices        = $AllDevices.Count
$CompliantDevices    = ($AllDevices | Where-Object { $_.complianceState -eq "compliant" }).Count
$NonCompliantDevices = ($AllDevices | Where-Object { $_.complianceState -eq "nonCompliant" }).Count
$UnknownDevices      = ($AllDevices | Where-Object { $_.complianceState -notin @("compliant","nonCompliant") }).Count
$AndroidDevices      = ($AllDevices | Where-Object { $_.operatingSystem -eq "Android" }).Count
$iOSDevices          = ($AllDevices | Where-Object { $_.operatingSystem -eq "iOS" }).Count
$NonCompliantList    = $AllDevices | Where-Object { $_.complianceState -eq "nonCompliant" }
$AndroidNonCompliant = ($NonCompliantList | Where-Object { $_.operatingSystem -eq "Android" }).Count
$iOSNonCompliant     = ($NonCompliantList | Where-Object { $_.operatingSystem -eq "iOS" }).Count

# Policy-Metadaten Cache
Write-Host "`n[POLICIES] Lade Compliance Policy Metadaten..." -ForegroundColor Cyan
$PolicyMetaCache = @{}

# Non-Compliance Details + Mismatch Analyse
Write-Host "`n[DETAILS] Analysiere Non-Compliant Geräte ($NonCompliantDevices Stück)..." -ForegroundColor Yellow
$DeviceReportData = @()
$Counter = 0

foreach ($Device in $NonCompliantList) {
    $Counter++
    Write-Progress -Activity "Non-Compliance Details" `
        -Status "Gerät $Counter/$NonCompliantDevices : $($Device.deviceName)" `
        -PercentComplete (($Counter / [Math]::Max($NonCompliantDevices,1)) * 100)
    Write-Host "  [$Counter/$NonCompliantDevices] $($Device.deviceName) ($($Device.operatingSystem) / $($Device.managedDeviceOwnerType))" -ForegroundColor Gray

    # Sync-Alter prüfen
    $SyncAge     = $null
    $SyncWarning = $false
    if ($Device.lastSyncDateTime) {
        $SyncAge     = [math]::Round(((Get-Date) - [datetime]$Device.lastSyncDateTime).TotalDays, 1)
        $SyncWarning = $SyncAge -gt $SyncWarningDays
    }

    $ComplianceDetails = Get-DeviceComplianceDetails -DeviceId $Device.id -AccessToken $Token

    # Policy-Metadaten + Mismatch pro verletzter Policy
    $PolicyAnalyses = @()
    $AllMismatches  = @()

    foreach ($Detail in $ComplianceDetails) {
        if ($Detail.PolicyId -and -not $PolicyMetaCache.ContainsKey($Detail.PolicyId)) {
            $Meta = Get-CompliancePolicyMetadata -PolicyId $Detail.PolicyId -AccessToken $Token
            $PolicyMetaCache[$Detail.PolicyId] = $Meta
        }
        $PolicyMeta = $PolicyMetaCache[$Detail.PolicyId]

        $Mismatches = Get-MismatchAnalysis -Device $Device -PolicyMeta $PolicyMeta
        foreach ($M in $Mismatches) {
            $M | Add-Member -NotePropertyName "PolicyName" -NotePropertyValue $Detail.PolicyName -Force
        }
        $AllMismatches += $Mismatches

        if ($PolicyMeta -and -not ($PolicyAnalyses | Where-Object { $_.PolicyId -eq $Detail.PolicyId })) {
            $PolicyAnalyses += [PSCustomObject]@{
                PolicyId         = $Detail.PolicyId
                PolicyName       = $Detail.PolicyName
                Meta             = $PolicyMeta
            }
        }
    }

    # Sync-Warning als Mismatch hinzufügen
    if ($SyncWarning) {
        $AllMismatches += [PSCustomObject]@{
            Severity    = "warning"
            Icon        = "🟡"
            Category    = "Sync-Alter"
            Description = "Letzter Sync vor $SyncAge Tagen (Schwellwert: $SyncWarningDays Tage)."
            Action      = "Benutzer zum manuellen Sync auffordern (Unternehmensportal öffnen)"
            PolicyName  = "—"
        }
    }

    # Deduplizieren der Mismatches
    $AllMismatches = $AllMismatches | Sort-Object Severity, Category -Unique

    $DeviceReportData += [PSCustomObject]@{
        Device          = $Device
        Details         = $ComplianceDetails
        PolicyAnalyses  = $PolicyAnalyses
        Mismatches      = $AllMismatches
        SyncAgeDays     = $SyncAge
        SyncWarning     = $SyncWarning
        HasMismatches   = ($AllMismatches.Count -gt 0)
        HasRealViolations = ($ComplianceDetails | Where-Object { $_.HasDetail -eq $true }).Count -gt 0
    }
}
Write-Progress -Activity "Non-Compliance Details" -Completed

# Statistiken für Mismatches
$TotalMismatches       = ($DeviceReportData | Where-Object { $_.HasMismatches }).Count
$TotalRealViolations   = ($DeviceReportData | Where-Object { $_.HasRealViolations }).Count
$TotalSyncWarnings     = ($DeviceReportData | Where-Object { $_.SyncWarning }).Count
$TopViolations         = ($DeviceReportData | ForEach-Object { $_.Details }) | Where-Object { $_.HasDetail } | Group-Object SettingName | Sort-Object Count -Descending | Select-Object -First 10
$TopMismatchCategories = ($DeviceReportData | ForEach-Object { $_.Mismatches }) | Group-Object Category | Sort-Object Count -Descending | Select-Object -First 8

Write-Host "`n[REPORT] Erstelle HTML Report..." -ForegroundColor Cyan

# ==============================================================================
# HTML GENERIERUNG
# ==============================================================================

$DeviceCardsHtml = ""
foreach ($Item in $DeviceReportData) {
    $Dev        = $Item.Device
    $Details    = $Item.Details
    $Mismatches = $Item.Mismatches
    $LastSync   = if ($Dev.lastSyncDateTime) { [datetime]$Dev.lastSyncDateTime | Get-Date -Format "dd.MM.yyyy HH:mm" } else { "Unbekannt" }
    $Enrolled   = if ($Dev.enrolledDateTime)  { [datetime]$Dev.enrolledDateTime  | Get-Date -Format "dd.MM.yyyy" }      else { "Unbekannt" }
    $OsIcon     = if ($Dev.operatingSystem -eq "Android") { "🤖" } else { "" }
    $OsClass    = if ($Dev.operatingSystem -eq "Android") { "android" } else { "ios" }
    $SyncClass  = if ($Item.SyncWarning) { "sync-warning" } else { "" }
    $SyncInfo   = if ($Item.SyncAgeDays) { "$($Item.SyncAgeDays) Tage" } else { "—" }

    # Mismatch-Badges im Header
    $MismatchBadgesHtml = ""
    if ($Mismatches.Count -gt 0) {
        $CritCount = ($Mismatches | Where-Object { $_.Severity -eq "critical" }).Count
        $WarnCount = ($Mismatches | Where-Object { $_.Severity -eq "warning" }).Count
        if ($CritCount -gt 0) { $MismatchBadgesHtml += "<span class='badge badge-critical'>🔴 $CritCount Kritisch</span> " }
        if ($WarnCount -gt 0) { $MismatchBadgesHtml += "<span class='badge badge-warning'>🟡 $WarnCount Warnung</span> " }
    }

    # Mismatch-Analyse Block
    $MismatchHtml = ""
    if ($Mismatches.Count -gt 0) {
        $MismatchHtml = "<div class='mismatch-block'><h4>🔎 Mismatch-Analyse ($($Mismatches.Count) Befunde)</h4><div class='mismatch-list'>"
        foreach ($M in $Mismatches) {
            $MClass = if ($M.Severity -eq "critical") { "mismatch-critical" } else { "mismatch-warning" }
            $MismatchHtml += @"
            <div class='mismatch-item $MClass'>
                <div class='mismatch-header'>
                    <span class='mismatch-icon'>$($M.Icon)</span>
                    <span class='mismatch-category'>$($M.Category)</span>
                    <span class='mismatch-policy'>Policy: $($M.PolicyName)</span>
                </div>
                <div class='mismatch-desc'>$($M.Description)</div>
                <div class='mismatch-action'>💡 Empfehlung: $($M.Action)</div>
            </div>
"@
        }
        $MismatchHtml += "</div></div>"
    }

    # Policy-Metadaten Block
    $PolicyMetaHtml = ""
    if ($Item.PolicyAnalyses.Count -gt 0) {
        $PolicyMetaHtml = "<div class='policy-meta-block'><h4>📋 Policy-Konfiguration</h4><div class='policy-meta-grid'>"
        foreach ($PA in $Item.PolicyAnalyses) {
            $M = $PA.Meta
            if ($M) {
                $PolicyMetaHtml += @"
                <div class='policy-meta-card'>
                    <div class='policy-meta-name'>$($PA.PolicyName)</div>
                    <div class='policy-meta-type'><code>$($M.ODataType)</code></div>
                    <table class='policy-meta-table'>
                        <tr><td>Min OS</td><td>$($M.OsMinimumVersion)</td></tr>
                        <tr><td>Max OS</td><td>$($M.OsMaximumVersion)</td></tr>
                        <tr><td>Passwort</td><td>$($M.PasswordRequired)</td></tr>
                        <tr><td>Verschlüsselung</td><td>$($M.StorageEncryption)</td></tr>
                        <tr><td>Threat Level</td><td>$($M.DeviceThreatLevel)</td></tr>
                    </table>
                </div>
"@
            }
        }
        $PolicyMetaHtml += "</div></div>"
    }

    # Setting-Violations Tabelle
    $ViolationRows = ""
    if ($Details.Count -gt 0) {
        foreach ($V in $Details) {
            $StateClass  = switch ($V.SettingState) {
                "nonCompliant"  { "badge-noncompliant" }
                "error"         { "badge-error" }
                "conflict"      { "badge-conflict" }
                "notApplicable" { "badge-na" }
                default         { "badge-unknown" }
            }
            $SettingShort = $V.SettingName -replace '^.*\.', ''
            $DetailIcon   = if ($V.HasDetail) { "✅" } else { "⚠️" }
            $ViolationRows += @"
            <tr>
                <td><span class='policy-name'>$($V.PolicyName)</span></td>
                <td title='$($V.SettingName)'>$DetailIcon <code>$SettingShort</code></td>
                <td><span class='badge $StateClass'>$($V.SettingState)</span></td>
                <td>$($V.UserPrincipal)</td>
            </tr>
"@
        }
    }

    $DeviceCardsHtml += @"
    <div class='device-card $OsClass' data-os='$($Dev.operatingSystem)' data-name='$($Dev.deviceName)' data-mismatch='$($Item.HasMismatches.ToString().ToLower())'>
        <div class='device-header' onclick='toggleCard(this)'>
            <div class='device-title'>
                <span class='os-icon'>$OsIcon</span>
                <span class='device-name'>$($Dev.deviceName)</span>
                <span class='badge badge-noncompliant'>Non-Compliant</span>
                <span class='badge badge-os-$OsClass'>$($Dev.operatingSystem)</span>
                <span class='badge badge-owner-$($Dev.managedDeviceOwnerType)'>$($Dev.managedDeviceOwnerType)</span>
                $MismatchBadgesHtml
            </div>
            <button class='toggle-btn'>▼ Details</button>
        </div>
        <div class='device-meta'>
            <div class='meta-item'><span class='meta-label'>Benutzer</span><span>$($Dev.userDisplayName)</span></div>
            <div class='meta-item'><span class='meta-label'>UPN</span><span>$($Dev.userPrincipalName)</span></div>
            <div class='meta-item'><span class='meta-label'>Modell</span><span>$($Dev.manufacturer) $($Dev.model)</span></div>
            <div class='meta-item'><span class='meta-label'>OS Version</span><span>$($Dev.osVersion)</span></div>
            <div class='meta-item'><span class='meta-label'>Letzter Sync</span><span class='$SyncClass'>$LastSync $(if($Item.SyncWarning){"⚠️ ($SyncInfo)"})</span></div>
            <div class='meta-item'><span class='meta-label'>Enrolliert</span><span>$Enrolled</span></div>
            <div class='meta-item'><span class='meta-label'>Gerätetyp</span><span>$($Dev.managedDeviceOwnerType)</span></div>
            <div class='meta-item'><span class='meta-label'>IMEI</span><span>$(if($Dev.imei){$Dev.imei}else{'N/A'})</span></div>
        </div>
        <div class='device-details' style='display:none;'>
            $MismatchHtml
            $PolicyMetaHtml
            <div class='violations-section'>
                <h4>⚠️ Compliance Violations ($($Details.Count))</h4>
                <p class='violations-hint'>✅ = Setting-Detail verfügbar &nbsp;|&nbsp; ⚠️ = Kein Setting-Detail (siehe Mismatch-Analyse)</p>
                <table class='violations-table'>
                    <thead><tr><th>Compliance Policy</th><th>Setting (Grund)</th><th>Status</th><th>Benutzer</th></tr></thead>
                    <tbody>$ViolationRows</tbody>
                </table>
            </div>
        </div>
    </div>
"@
}

# Alle Geräte Tabelle
$AllDevicesRows = ""
foreach ($Dev in ($AllDevices | Sort-Object complianceState, deviceName)) {
    $StateClass = switch ($Dev.complianceState) {
        "compliant"    { "badge-compliant" }
        "nonCompliant" { "badge-noncompliant" }
        default        { "badge-unknown" }
    }
    $LastSync = if ($Dev.lastSyncDateTime) { [datetime]$Dev.lastSyncDateTime | Get-Date -Format "dd.MM.yyyy HH:mm" } else { "—" }
    $OsIcon   = if ($Dev.operatingSystem -eq "Android") { "🤖" } else { "" }
    $AllDevicesRows += @"
    <tr data-state='$($Dev.complianceState)' data-os='$($Dev.operatingSystem)' data-owner='$($Dev.managedDeviceOwnerType)'>
        <td>$OsIcon $($Dev.deviceName)</td>
        <td>$($Dev.userDisplayName)</td>
        <td>$($Dev.operatingSystem) $($Dev.osVersion)</td>
        <td>$($Dev.manufacturer) $($Dev.model)</td>
        <td>$($Dev.managedDeviceOwnerType)</td>
        <td><span class='badge $StateClass'>$($Dev.complianceState)</span></td>
        <td>$LastSync</td>
    </tr>
"@
}

$ComplianceRate          = if ($TotalDevices -gt 0) { [math]::Round(($CompliantDevices / $TotalDevices) * 100, 1) } else { 0 }
$TopViolationsJson       = ($TopViolations | ForEach-Object { $ShortName = $_.Name -replace '^.*\.',''; "{ label: '$($ShortName -replace "'","\'") ($($_.Count)x)', value: $($_.Count) }" }) -join ","
$TopMismatchJson         = ($TopMismatchCategories | ForEach-Object { "{ label: '$($_.Name -replace "'","\'") ($($_.Count)x)', value: $($_.Count) }" }) -join ","

# ==============================================================================
# HTML TEMPLATE
# ==============================================================================
$Html = @"
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intune Compliance Report v2 — $(Get-Date -Format 'dd.MM.yyyy')</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --primary:#0078d4; --primary-dark:#005a9e;
            --success:#107c10; --danger:#d13438; --warning:#ff8c00;
            --critical:#a4262c; --gray:#605e5c;
            --bg:#f3f2f1; --card-bg:#ffffff; --border:#e1dfdd;
            --android:#3ddc84; --ios:#555555;
        }
        *{box-sizing:border-box;margin:0;padding:0;}
        body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:#201f1e;}

        /* HEADER */
        .report-header{background:linear-gradient(135deg,#0078d4,#003a6e);color:white;padding:32px 40px;position:relative;overflow:hidden;}
        .report-header::before{content:'';position:absolute;top:-50%;right:-10%;width:400px;height:400px;background:rgba(255,255,255,0.05);border-radius:50%;}
        .header-content{position:relative;z-index:1;}
        .header-top{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px;}
        .header-title h1{font-size:28px;font-weight:600;margin-bottom:4px;}
        .header-title p{opacity:.85;font-size:14px;}
        .header-meta{text-align:right;font-size:13px;opacity:.85;}
        .header-meta span{display:block;}

        /* DASHBOARD */
        .dashboard{padding:28px 40px;}
        .dashboard-title{font-size:20px;font-weight:600;margin-bottom:16px;}
        .kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;margin-bottom:24px;}
        .kpi-card{background:var(--card-bg);border-radius:8px;padding:20px;border-left:4px solid var(--primary);box-shadow:0 2px 8px rgba(0,0,0,.08);transition:transform .2s,box-shadow .2s;}
        .kpi-card:hover{transform:translateY(-2px);box-shadow:0 4px 16px rgba(0,0,0,.12);}
        .kpi-card.danger{border-left-color:var(--danger);}
        .kpi-card.success{border-left-color:var(--success);}
        .kpi-card.warning{border-left-color:var(--warning);}
        .kpi-card.critical{border-left-color:var(--critical);}
        .kpi-card.android{border-left-color:var(--android);}
        .kpi-card.ios{border-left-color:#555;}
        .kpi-value{font-size:36px;font-weight:700;line-height:1;}
        .kpi-label{font-size:13px;color:var(--gray);margin-top:6px;}
        .kpi-sub{font-size:12px;color:var(--gray);margin-top:4px;}

        /* COMPLIANCE BAR */
        .compliance-bar-container{background:var(--card-bg);border-radius:8px;padding:20px;margin-bottom:24px;box-shadow:0 2px 8px rgba(0,0,0,.08);}
        .compliance-bar-label{display:flex;justify-content:space-between;margin-bottom:8px;font-size:14px;font-weight:600;}
        .compliance-bar-track{background:#fde7e9;border-radius:20px;height:24px;overflow:hidden;}
        .compliance-bar-fill{background:linear-gradient(90deg,#107c10,#54b054);height:100%;border-radius:20px;display:flex;align-items:center;padding-left:12px;color:white;font-size:12px;font-weight:600;}

        /* CHARTS */
        .charts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin-bottom:28px;}
        .chart-card{background:var(--card-bg);border-radius:8px;padding:20px;box-shadow:0 2px 8px rgba(0,0,0,.08);}
        .chart-card h3{font-size:15px;font-weight:600;margin-bottom:16px;}
        .chart-container{position:relative;height:220px;}

        /* SECTION */
        .section{padding:0 40px 32px;}
        .section-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:12px;}
        .section-title{font-size:20px;font-weight:600;}
        .section-count{background:var(--danger);color:white;border-radius:20px;padding:2px 12px;font-size:13px;font-weight:600;}
        .section-count.ok{background:var(--success);}

        /* FILTER */
        .filter-bar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;align-items:center;}
        .filter-btn{padding:6px 16px;border-radius:20px;border:2px solid var(--border);background:white;cursor:pointer;font-size:13px;font-weight:500;transition:all .2s;}
        .filter-btn.active,.filter-btn:hover{border-color:var(--primary);background:var(--primary);color:white;}
        .filter-btn.android.active{border-color:var(--android);background:var(--android);color:#1a1a1a;}
        .filter-btn.ios.active{border-color:#555;background:#555;color:white;}
        .filter-btn.mismatch.active{border-color:#d13438;background:#d13438;color:white;}
        .search-box{padding:6px 14px;border-radius:20px;border:2px solid var(--border);font-size:13px;min-width:220px;outline:none;transition:border-color .2s;}
        .search-box:focus{border-color:var(--primary);}

        /* DEVICE CARDS */
        .device-card{background:var(--card-bg);border-radius:8px;margin-bottom:12px;border-left:4px solid var(--danger);box-shadow:0 2px 6px rgba(0,0,0,.07);overflow:hidden;transition:box-shadow .2s;}
        .device-card:hover{box-shadow:0 4px 14px rgba(0,0,0,.12);}
        .device-card.android{border-left-color:var(--android);}
        .device-card.ios{border-left-color:#888;}
        .device-header{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;cursor:pointer;}
        .device-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
        .os-icon{font-size:20px;}
        .device-name{font-size:15px;font-weight:600;}
        .device-meta{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;padding:0 18px 14px;border-top:1px solid var(--border);}
        .meta-item{display:flex;flex-direction:column;gap:2px;}
        .meta-label{font-size:11px;text-transform:uppercase;color:var(--gray);font-weight:600;letter-spacing:.5px;}
        .sync-warning{color:var(--warning);font-weight:600;}
        .device-details{padding:16px 18px;background:#faf9f8;border-top:1px solid var(--border);}
        .toggle-btn{padding:5px 14px;border-radius:6px;border:1px solid var(--border);background:white;cursor:pointer;font-size:13px;white-space:nowrap;transition:all .2s;pointer-events:none;}
        .device-header:hover .toggle-btn{background:var(--primary);color:white;border-color:var(--primary);}

        /* MISMATCH BLOCK */
        .mismatch-block{margin-bottom:16px;}
        .mismatch-block h4{font-size:14px;font-weight:600;margin-bottom:10px;color:#a4262c;}
        .mismatch-list{display:flex;flex-direction:column;gap:8px;}
        .mismatch-item{border-radius:6px;padding:12px 14px;border-left:4px solid;}
        .mismatch-critical{background:#fde7e9;border-left-color:#d13438;}
        .mismatch-warning{background:#fff4ce;border-left-color:#ff8c00;}
        .mismatch-header{display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap;}
        .mismatch-icon{font-size:16px;}
        .mismatch-category{font-weight:700;font-size:13px;}
        .mismatch-policy{font-size:12px;color:var(--gray);background:rgba(0,0,0,.06);padding:1px 8px;border-radius:10px;}
        .mismatch-desc{font-size:13px;margin-bottom:4px;}
        .mismatch-action{font-size:12px;color:#107c10;font-weight:500;}

        /* POLICY META */
        .policy-meta-block{margin-bottom:16px;}
        .policy-meta-block h4{font-size:14px;font-weight:600;margin-bottom:10px;color:#0078d4;}
        .policy-meta-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px;}
        .policy-meta-card{background:white;border:1px solid var(--border);border-radius:6px;padding:12px;}
        .policy-meta-name{font-weight:600;font-size:13px;margin-bottom:4px;}
        .policy-meta-type{margin-bottom:8px;}
        .policy-meta-table{width:100%;border-collapse:collapse;font-size:12px;}
        .policy-meta-table td{padding:3px 6px;border-bottom:1px solid #f0eeec;}
        .policy-meta-table td:first-child{color:var(--gray);font-weight:500;width:50%;}

        /* VIOLATIONS */
        .violations-section{margin-top:8px;}
        .violations-section h4{font-size:14px;font-weight:600;margin-bottom:6px;color:var(--warning);}
        .violations-hint{font-size:12px;color:var(--gray);margin-bottom:8px;}
        .violations-table{width:100%;border-collapse:collapse;font-size:13px;}
        .violations-table th{background:#f3f2f1;padding:8px 12px;text-align:left;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.3px;color:var(--gray);}
        .violations-table td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:middle;}
        .violations-table tr:last-child td{border-bottom:none;}
        .violations-table tr:hover td{background:#f0f0f0;}
        .policy-name{font-weight:500;}

        /* ALL DEVICES TABLE */
        .all-devices-table{width:100%;border-collapse:collapse;font-size:13px;background:white;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08);}
        .all-devices-table th{background:#0078d4;color:white;padding:10px 14px;text-align:left;font-size:12px;font-weight:600;cursor:pointer;user-select:none;}
        .all-devices-table th:hover{background:#005a9e;}
        .all-devices-table td{padding:9px 14px;border-bottom:1px solid var(--border);}
        .all-devices-table tr:hover td{background:#f3f2f1;}
        .all-devices-table tr[data-state='nonCompliant'] td:first-child{border-left:3px solid var(--danger);}
        .all-devices-table tr[data-state='compliant'] td:first-child{border-left:3px solid var(--success);}

        /* BADGES */
        .badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.3px;}
        .badge-noncompliant{background:#fde7e9;color:#a4262c;}
        .badge-compliant{background:#dff6dd;color:#107c10;}
        .badge-error{background:#fff4ce;color:#835c00;}
        .badge-conflict{background:#f0e6ff;color:#5c2d91;}
        .badge-na{background:#f3f2f1;color:#605e5c;}
        .badge-unknown{background:#f3f2f1;color:#605e5c;}
        .badge-critical{background:#d13438;color:white;}
        .badge-warning{background:#ff8c00;color:white;}
        .badge-os-android{background:#e8f9f0;color:#1a7a40;}
        .badge-os-ios{background:#f0f0f0;color:#444;}
        .badge-owner-personal{background:#fff4ce;color:#835c00;}
        .badge-owner-company{background:#e6f2fb;color:#004e8c;}

        code{background:#f3f2f1;padding:1px 6px;border-radius:4px;font-size:12px;font-family:'Cascadia Code',Consolas,monospace;}
        .table-wrapper{overflow-x:auto;border-radius:8px;}
        .hidden{display:none !important;}

        .report-footer{text-align:center;padding:24px;color:var(--gray);font-size:12px;border-top:1px solid var(--border);margin-top:16px;}

        @media(max-width:768px){
            .dashboard,.section{padding-left:16px;padding-right:16px;}
            .charts-grid{grid-template-columns:1fr;}
            .report-header{padding:20px 16px;}
        }
    </style>
</head>
<body>

<!-- HEADER -->
<div class="report-header">
    <div class="header-content">
        <div class="header-top">
            <div class="header-title">
                <h1>📱 Intune Compliance Report v2</h1>
                <p>Android &amp; iOS — Non-Compliance Analyse mit Mismatch-Erkennung</p>
            </div>
            <div class="header-meta">
                <span><strong>Erstellt:</strong> $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')</span>
                <span><strong>Tenant:</strong> $TenantId</span>
                <span><strong>Gesamt Geräte:</strong> $TotalDevices</span>
            </div>
        </div>
    </div>
</div>

<!-- DASHBOARD -->
<div class="dashboard">
    <div class="dashboard-title">📊 Dashboard — Übersicht</div>
    <div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-value" style="color:#0078d4">$TotalDevices</div><div class="kpi-label">Gesamt Geräte</div><div class="kpi-sub">Android + iOS</div></div>
        <div class="kpi-card success"><div class="kpi-value" style="color:#107c10">$CompliantDevices</div><div class="kpi-label">Compliant</div><div class="kpi-sub">$ComplianceRate% der Geräte</div></div>
        <div class="kpi-card danger"><div class="kpi-value" style="color:#d13438">$NonCompliantDevices</div><div class="kpi-label">Non-Compliant</div><div class="kpi-sub">Handlungsbedarf</div></div>
        <div class="kpi-card critical"><div class="kpi-value" style="color:#a4262c">$TotalMismatches</div><div class="kpi-label">Mit Mismatch</div><div class="kpi-sub">Policy-Fehlzuweisungen</div></div>
        <div class="kpi-card warning"><div class="kpi-value" style="color:#ff8c00">$TotalSyncWarnings</div><div class="kpi-label">Sync veraltet</div><div class="kpi-sub">> $SyncWarningDays Tage</div></div>
        <div class="kpi-card"><div class="kpi-value" style="color:#0078d4">$TotalRealViolations</div><div class="kpi-label">Echte Verstösse</div><div class="kpi-sub">Mit Setting-Details</div></div>
        <div class="kpi-card android"><div class="kpi-value" style="color:#1a7a40">$AndroidDevices</div><div class="kpi-label">Android</div><div class="kpi-sub">$AndroidNonCompliant non-compliant</div></div>
        <div class="kpi-card ios"><div class="kpi-value" style="color:#444">$iOSDevices</div><div class="kpi-label">iOS</div><div class="kpi-sub">$iOSNonCompliant non-compliant</div></div>
    </div>

    <div class="compliance-bar-container">
        <div class="compliance-bar-label"><span>Compliance Rate</span><span style="color:#107c10;font-size:18px;font-weight:700">$ComplianceRate%</span></div>
        <div class="compliance-bar-track">
            <div class="compliance-bar-fill" style="width:${ComplianceRate}%">${ComplianceRate}% compliant</div>
        </div>
    </div>

    <div class="charts-grid">
        <div class="chart-card">
            <h3>Compliance Status</h3>
            <div class="chart-container"><canvas id="complianceChart"></canvas></div>
        </div>
        <div class="chart-card">
            <h3>Top Mismatch-Kategorien</h3>
            <div class="chart-container"><canvas id="mismatchChart"></canvas></div>
        </div>
        <div class="chart-card">
            <h3>Top Non-Compliance Settings</h3>
            <div class="chart-container"><canvas id="violationsChart"></canvas></div>
        </div>
        <div class="chart-card">
            <h3>Non-Compliant nach OS</h3>
            <div class="chart-container"><canvas id="osChart"></canvas></div>
        </div>
    </div>
</div>

<!-- NON-COMPLIANT DEVICES -->
<div class="section">
    <div class="section-header">
        <div style="display:flex;align-items:center;gap:12px;">
            <span class="section-title">⚠️ Non-Compliant Geräte</span>
            <span class="section-count">$NonCompliantDevices Geräte</span>
        </div>
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterCards('all',this)">Alle</button>
            <button class="filter-btn android" onclick="filterCards('Android',this)">🤖 Android</button>
            <button class="filter-btn ios" onclick="filterCards('iOS',this)"> iOS</button>
            <button class="filter-btn mismatch" onclick="filterCards('mismatch',this)">🔴 Nur Mismatches</button>
            <input type="text" class="search-box" placeholder="🔍 Gerät / Benutzer suchen..." oninput="searchCards(this.value)">
        </div>
    </div>
    <div id="deviceCards">$DeviceCardsHtml</div>
    <div id="noResults" class="hidden" style="text-align:center;padding:40px;color:#888;font-size:15px;">Keine Geräte gefunden.</div>
</div>

<!-- ALL DEVICES -->
<div class="section">
    <div class="section-header">
        <div style="display:flex;align-items:center;gap:12px;">
            <span class="section-title">📋 Alle Geräte — Übersicht</span>
            <span class="section-count ok">$TotalDevices Geräte</span>
        </div>
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterTable('all',this)">Alle</button>
            <button class="filter-btn" onclick="filterTable('nonCompliant',this)" style="border-color:#d13438;">Non-Compliant</button>
            <button class="filter-btn" onclick="filterTable('compliant',this)" style="border-color:#107c10;">Compliant</button>
            <button class="filter-btn android" onclick="filterTable('Android',this)">🤖 Android</button>
            <button class="filter-btn ios" onclick="filterTable('iOS',this)"> iOS</button>
            <button class="filter-btn" onclick="filterTable('personal',this)" style="border-color:#ff8c00;">BYOD</button>
            <button class="filter-btn" onclick="filterTable('company',this)" style="border-color:#0078d4;">Corporate</button>
        </div>
    </div>
    <div class="table-wrapper">
        <table class="all-devices-table" id="allDevicesTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Gerätename ↕</th>
                    <th onclick="sortTable(1)">Benutzer ↕</th>
                    <th onclick="sortTable(2)">OS / Version ↕</th>
                    <th onclick="sortTable(3)">Modell ↕</th>
                    <th onclick="sortTable(4)">Typ ↕</th>
                    <th onclick="sortTable(5)">Status ↕</th>
                    <th onclick="sortTable(6)">Letzter Sync ↕</th>
                </tr>
            </thead>
            <tbody id="allDevicesBody">$AllDevicesRows</tbody>
        </table>
    </div>
</div>

<div class="report-footer">
    <p>Intune Compliance Report v2 | Protina Pharmazeutische GmbH | $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss') | Microsoft Graph API Beta</p>
</div>

<script>
// CHARTS
new Chart(document.getElementById('complianceChart').getContext('2d'), {
    type: 'doughnut',
    data: {
        labels: ['Compliant ($CompliantDevices)', 'Non-Compliant ($NonCompliantDevices)', 'Sonstige ($UnknownDevices)'],
        datasets: [{ data: [$CompliantDevices, $NonCompliantDevices, $UnknownDevices], backgroundColor: ['#107c10','#d13438','#ff8c00'], borderWidth: 3, borderColor: '#fff' }]
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { padding: 12, font: { size: 11 } } } }, cutout: '65%' }
});

const mismatchData = [$TopMismatchJson];
new Chart(document.getElementById('mismatchChart').getContext('2d'), {
    type: 'bar',
    data: {
        labels: mismatchData.map(d => d.label),
        datasets: [{ label: 'Anzahl', data: mismatchData.map(d => d.value), backgroundColor: 'rgba(164,38,44,0.8)', borderColor: '#a4262c', borderWidth: 1, borderRadius: 4 }]
    },
    options: { responsive: true, maintainAspectRatio: false, indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { stepSize: 1 } }, y: { ticks: { font: { size: 11 } } } } }
});

const violationsData = [$TopViolationsJson];
new Chart(document.getElementById('violationsChart').getContext('2d'), {
    type: 'bar',
    data: {
        labels: violationsData.map(d => d.label),
        datasets: [{ label: 'Anzahl Geräte', data: violationsData.map(d => d.value), backgroundColor: 'rgba(209,52,56,0.75)', borderColor: '#d13438', borderWidth: 1, borderRadius: 4 }]
    },
    options: { responsive: true, maintainAspectRatio: false, indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { stepSize: 1 } }, y: { ticks: { font: { size: 11 } } } } }
});

new Chart(document.getElementById('osChart').getContext('2d'), {
    type: 'doughnut',
    data: {
        labels: ['Android ($AndroidNonCompliant)', 'iOS ($iOSNonCompliant)'],
        datasets: [{ data: [$AndroidNonCompliant, $iOSNonCompliant], backgroundColor: ['#3ddc84','#888888'], borderWidth: 3, borderColor: '#fff' }]
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { padding: 12, font: { size: 11 } } } }, cutout: '65%' }
});

// TOGGLE
function toggleCard(header) {
    const card    = header.closest('.device-card');
    const details = card.querySelector('.device-details');
    const btn     = header.querySelector('.toggle-btn');
    const open    = details.style.display !== 'none';
    details.style.display = open ? 'none' : 'block';
    btn.textContent = open ? '▼ Details' : '▲ Schliessen';
}

// FILTER CARDS
let activeFilter = 'all', activeSearch = '';
function filterCards(f, btn) {
    activeFilter = f;
    document.querySelectorAll('#deviceCards').forEach(c => c.closest('.section')?.querySelectorAll('.filter-bar .filter-btn').forEach(b => b.classList.remove('active')));
    document.querySelectorAll('.section')[0]?.querySelectorAll('.filter-bar .filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyCardFilter();
}
function searchCards(v) { activeSearch = v.toLowerCase(); applyCardFilter(); }
function applyCardFilter() {
    let visible = 0;
    document.querySelectorAll('#deviceCards .device-card').forEach(card => {
        const osMatch      = activeFilter === 'all' || card.dataset.os === activeFilter || (activeFilter === 'mismatch' && card.dataset.mismatch === 'true');
        const searchMatch  = !activeSearch || card.dataset.name.toLowerCase().includes(activeSearch) || card.textContent.toLowerCase().includes(activeSearch);
        const show = osMatch && searchMatch;
        card.classList.toggle('hidden', !show);
        if (show) visible++;
    });
    document.getElementById('noResults').classList.toggle('hidden', visible > 0);
}

// FILTER TABLE
function filterTable(f, btn) {
    btn.closest('.filter-bar').querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('#allDevicesBody tr').forEach(row => {
        const show = f === 'all' || row.dataset.state === f || row.dataset.os === f || row.dataset.owner === f;
        row.classList.toggle('hidden', !show);
    });
}

// SORT TABLE
let sortDir = {};
function sortTable(col) {
    const tbody = document.getElementById('allDevicesBody');
    const rows  = Array.from(tbody.querySelectorAll('tr'));
    sortDir[col] = !sortDir[col];
    rows.sort((a, b) => {
        const av = a.cells[col]?.textContent.trim() || '';
        const bv = b.cells[col]?.textContent.trim() || '';
        return sortDir[col] ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    rows.forEach(r => tbody.appendChild(r));
}
</script>
</body>
</html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
Write-Host "`n[DONE] Report gespeichert: $ReportPath" -ForegroundColor Green
Start-Process $ReportPath

Write-Host "`n============================================================" -ForegroundColor Magenta
Write-Host " Zusammenfassung:" -ForegroundColor Magenta
Write-Host "  Gesamt Geräte      : $TotalDevices" -ForegroundColor White
Write-Host "  Compliant          : $CompliantDevices ($ComplianceRate%)" -ForegroundColor Green
Write-Host "  Non-Compliant      : $NonCompliantDevices" -ForegroundColor Red
Write-Host "  Mit Mismatch       : $TotalMismatches" -ForegroundColor Red
Write-Host "  Echte Verstösse    : $TotalRealViolations" -ForegroundColor Yellow
Write-Host "  Sync veraltet      : $TotalSyncWarnings (> $SyncWarningDays Tage)" -ForegroundColor Yellow
Write-Host "  Android            : $AndroidDevices ($AndroidNonCompliant non-compliant)" -ForegroundColor Cyan
Write-Host "  iOS                : $iOSDevices ($iOSNonCompliant non-compliant)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Magenta
