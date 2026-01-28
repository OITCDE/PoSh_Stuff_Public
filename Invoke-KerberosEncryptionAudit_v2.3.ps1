<#
.SYNOPSIS
    Active Directory Kerberos Encryption Type Auditor and Migration Tool with Event Log Analysis
    
.DESCRIPTION
    Audits AD accounts using RC4 encryption, migrates them to AES128/AES256,
    validates Kerberos ticket encryption types across Domain Controllers, and
    analyzes Security Event Logs for actual RC4 usage patterns.
    Generates dynamic HTML reports with filtering and visualization.
    
.PARAMETER DryRun
    When enabled (default), simulates changes without applying them.
    
.PARAMETER ExportPath
    Path where the main HTML report will be saved.
    
.PARAMETER EventLogReportPath
    Path where the event log analysis report will be saved.
    
.PARAMETER IncludeComputers
    Include computer accounts in the audit and migration.
    
.PARAMETER TargetEncryption
    Target encryption type. Valid values: AES256, AES128_AES256 (default)
    
.PARAMETER ExcludeOUs
    Array of OUs to exclude from migration (e.g., service accounts)
    
.PARAMETER EventLogHours
    Number of hours to analyze in the Security Event Log (default: 24)
    
.PARAMETER MaxEvents
    Maximum number of events to retrieve from the log (default: 50000)
    
.PARAMETER AnalyzeAllDCs
    Scan event logs from all Domain Controllers (not just local)
    
.EXAMPLE
    .\Invoke-KerberosEncryptionAudit.ps1
    Runs in DryRun mode with default settings
    
.EXAMPLE
    .\Invoke-KerberosEncryptionAudit.ps1 -DryRun:$false -EventLogHours 48
    Executes migration and analyzes last 48 hours of events
    
.NOTES
    Author: Logicc AI for Ollischer IT Consulting
    Date: 17.10.2025
    Requires: Active Directory PowerShell Module, Domain Admin rights
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [bool]$DryRun = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "C:\Scripts\KerberosEncryptionAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    
    [Parameter(Mandatory=$false)]
    [string]$EventLogReportPath = "C:\Scripts\KerberosEventLogAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeComputers,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('AES256', 'AES128_AES256')]
    [string]$TargetEncryption = 'AES128_AES256',
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludeOUs = @(),
    
    [Parameter(Mandatory=$false)]
    [int]$EventLogHours = 24,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxEvents = 50000,
    
    [Parameter(Mandatory=$false)]
    [switch]$AnalyzeAllDCs
)

#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

# Script Configuration
$ErrorActionPreference = 'Stop'
$Script:Results = @()
$Script:DCValidation = @()
$Script:MigrationLog = @()
$Script:EventLogData = @()
$Script:EventLogSummary = @{}

#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'ERROR'   { Write-Host $logMessage -ForegroundColor Red }
        'WARNING' { Write-Host $logMessage -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Host $logMessage -ForegroundColor White }
    }
    
    # Add to log collection
    $Script:MigrationLog += [PSCustomObject]@{
        Timestamp = $timestamp
        Level     = $Level
        Message   = $Message
    }
}

function Get-EncryptionTypeName {
    param([int]$EncType)
    
    $encTypes = @{
        0  = 'Not Set (RC4 Default)'
        1  = 'DES-CBC-CRC'
        2  = 'DES-CBC-MD5'
        3  = 'DES-CBC-CRC, DES-CBC-MD5'
        4  = 'RC4-HMAC'
        7  = 'DES + RC4'
        8  = 'AES128-CTS-HMAC-SHA1-96'
        16 = 'AES256-CTS-HMAC-SHA1-96'
        24 = 'AES128 + AES256'
        28 = 'RC4 + AES128 + AES256'
        31 = 'All Encryption Types'
    }
    
    if ($encTypes.ContainsKey($EncType)) {
        return $encTypes[$EncType]
    } else {
        return "Custom ($EncType)"
    }
}

function Get-KerberosEncryptionTypeFromHex {
    param([string]$HexValue)
    
    $encTypes = @{
        '0x1'  = 'DES-CBC-CRC'
        '0x3'  = 'DES-CBC-MD5'
        '0x11' = 'AES128-CTS-HMAC-SHA1-96'
        '0x12' = 'AES256-CTS-HMAC-SHA1-96'
        '0x17' = 'RC4-HMAC'
        '0x18' = 'RC4-HMAC-EXP'
    }
    
    if ($encTypes.ContainsKey($HexValue)) {
        return $encTypes[$HexValue]
    } else {
        return "Unknown ($HexValue)"
    }
}

function Test-IsRC4Encryption {
    param([string]$HexValue)
    
    return ($HexValue -eq '0x17' -or $HexValue -eq '0x18')
}

function Get-TargetEncryptionValue {
    param([string]$Target)
    
    switch ($Target) {
        'AES256'         { return 16 }
        'AES128_AES256'  { return 24 }
        default          { return 24 }
    }
}

function Test-AccountInExcludedOU {
    param([string]$DistinguishedName)
    
    foreach ($ou in $ExcludeOUs) {
        if ($DistinguishedName -like "*$ou*") {
            return $true
        }
    }
    return $false
}

function Get-KerberosUpdateStatus {
    <#
    .SYNOPSIS
    Checks if the required Kerberos RC4 security update is installed
    
    .DESCRIPTION
    Verifies the presence of CVE-2026-20833 security updates:
    - Windows Server 2016: KB5073722
    - Windows Server 2019: KB5073723
    - Windows Server 2022: KB5073457
    #>
    
    # Get OS version
    $osVersion = [System.Environment]::OSVersion.Version
    $osCaption = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    
    Write-Log "Detected OS: $osCaption (Build $($osVersion.Build))" -Level INFO
    
    # Determine required KB based on OS version
    $requiredKB = $null
    $serverVersion = $null
    
    switch ($osVersion.Build) {
        14393 { 
            $requiredKB = 'KB5073722'
            $serverVersion = 'Windows Server 2016'
        }
        17763 { 
            $requiredKB = 'KB5073723'
            $serverVersion = 'Windows Server 2019'
        }
        20348 { 
            $requiredKB = 'KB5073457'
            $serverVersion = 'Windows Server 2022'
        }
        26100 { 
            $requiredKB = 'KB5073458'
            $serverVersion = 'Windows Server 2025'
        }
        default {
            Write-Log "Unknown Windows Server version (Build $($osVersion.Build))" -Level WARNING
            return @{
                IsInstalled = $false
                RequiredKB = 'Unknown'
                ServerVersion = 'Unknown'
                DetectionMethod = 'Unknown'
                InstallDate = $null
            }
        }
    }
    
    Write-Log "Expected update for $serverVersion : $requiredKB" -Level INFO
    
    # Check if KB is installed - Method 1: Get-HotFix
    Write-Log "Checking for $requiredKB using Get-HotFix..." -Level INFO
    try {
        $hotfix = Get-HotFix -Id $requiredKB -ErrorAction SilentlyContinue
        
        if ($hotfix) {
            Write-Log "✅ $requiredKB is installed (Installed: $($hotfix.InstalledOn))" -Level SUCCESS
            return @{
                IsInstalled = $true
                RequiredKB = $requiredKB
                ServerVersion = $serverVersion
                DetectionMethod = 'Get-HotFix'
                InstallDate = $hotfix.InstalledOn
                Description = $hotfix.Description
            }
        }
    } catch {
        Write-Log "Get-HotFix check failed: $_" -Level WARNING
    }
    
    # Check if KB is installed - Method 2: WMI (more reliable for recent updates)
    Write-Log "Checking for $requiredKB using WMI..." -Level INFO
    try {
        $kbNumber = $requiredKB -replace 'KB', ''
        $updates = Get-WmiObject -Class Win32_QuickFixEngineering | Where-Object { $_.HotFixID -eq $requiredKB }
        
        if ($updates) {
            Write-Log "✅ $requiredKB is installed via WMI" -Level SUCCESS
            return @{
                IsInstalled = $true
                RequiredKB = $requiredKB
                ServerVersion = $serverVersion
                DetectionMethod = 'WMI'
                InstallDate = $updates[0].InstalledOn
                Description = $updates[0].Description
            }
        }
    } catch {
        Write-Log "WMI check failed: $_" -Level WARNING
    }
    
    # Check if KB is installed - Method 3: Registry (most reliable for very recent updates)
    Write-Log "Checking for $requiredKB via Registry..." -Level INFO
    try {
        $kbNumber = $requiredKB -replace 'KB', ''
        $packagePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
        
        if (Test-Path $packagePath) {
            $packages = Get-ChildItem -Path $packagePath | Where-Object { 
                $_.Name -like "*$kbNumber*" 
            }
            
            if ($packages) {
                Write-Log "✅ $requiredKB found in registry (Package-based)" -Level SUCCESS
                return @{
                    IsInstalled = $true
                    RequiredKB = $requiredKB
                    ServerVersion = $serverVersion
                    DetectionMethod = 'Registry'
                    InstallDate = $null
                    Description = "Found via Component-Based Servicing"
                }
            }
        }
    } catch {
        Write-Log "Registry check failed: $_" -Level WARNING
    }
    
    # Check if KB is installed - Method 4: Check for Event ID capability
    Write-Log "Checking for KB5073381 Event ID capability..." -Level INFO
    try {
        # Try to query for Event 201-209 in System log (even if none exist)
        $testFilter = @{
            LogName = 'System'
            ID = 201
            StartTime = (Get-Date).AddDays(-1)
        }
        
        # If this doesn't throw an error about invalid event ID, the KB is likely installed
        $null = Get-WinEvent -FilterHashtable $testFilter -MaxEvents 1 -ErrorAction SilentlyContinue
        
        # Check if the provider exists
        $providers = Get-WinEvent -ListProvider * | Where-Object { 
            $_.Name -like '*Kdc*' -or $_.Name -like '*Kerberos*' 
        }
        
        foreach ($provider in $providers) {
            $events = $provider.Events | Where-Object { $_.Id -ge 201 -and $_.Id -le 209 }
            if ($events) {
                Write-Log "✅ Event IDs 201-209 are available (Provider capability detected)" -Level SUCCESS
                return @{
                    IsInstalled = $true
                    RequiredKB = $requiredKB
                    ServerVersion = $serverVersion
                    DetectionMethod = 'Event Capability'
                    InstallDate = $null
                    Description = "Detected via Event Provider capability"
                }
            }
        }
    } catch {
        Write-Log "Event capability check failed: $_" -Level WARNING
    }
    
    # KB not found
    Write-Log "❌ $requiredKB is NOT installed" -Level ERROR
    return @{
        IsInstalled = $false
        RequiredKB = $requiredKB
        ServerVersion = $serverVersion
        DetectionMethod = 'None'
        InstallDate = $null
    }
}

#endregion

#region Main Audit Functions

function Get-RC4Accounts {
    Write-Log "Starting RC4 account audit..." -Level INFO
    
    $filter = {Enabled -eq $true}
    $properties = @(
        'SamAccountName',
        'DistinguishedName',
        'msDS-SupportedEncryptionTypes',
        'servicePrincipalName',
        'LastLogonDate',
        'PasswordLastSet',
        'ObjectClass'
    )
    
    # Get user accounts
    Write-Log "Querying user accounts..." -Level INFO
    $users = Get-ADUser -Filter $filter -Properties $properties
    
    $accountsToProcess = @($users)
    
    # Get computer accounts if requested
    if ($IncludeComputers) {
        Write-Log "Querying computer accounts..." -Level INFO
        $computers = Get-ADComputer -Filter $filter -Properties $properties
        $accountsToProcess += $computers
    }
    
    Write-Log "Processing $($accountsToProcess.Count) accounts..." -Level INFO
    
    foreach ($account in $accountsToProcess) {
        $encType = $account.'msDS-SupportedEncryptionTypes'
        
        # If not set, defaults to RC4
        # If set to 0, 1, 2, 3, 4, 7 - uses RC4 or weaker
        $usesRC4 = ($null -eq $encType) -or ($encType -eq 0) -or 
                   ($encType -band 4) -or ($encType -lt 8)
        
        $hasAES = ($encType -band 8) -or ($encType -band 16)
        
        # Determine risk level
        $riskLevel = if ($usesRC4 -and -not $hasAES) {
            'High'
        } elseif ($usesRC4 -and $hasAES) {
            'Medium'
        } else {
            'Low'
        }
        
        # Check if in excluded OU
        $excluded = Test-AccountInExcludedOU -DistinguishedName $account.DistinguishedName
        
        $hasSPN = ($null -ne $account.servicePrincipalName) -and ($account.servicePrincipalName.Count -gt 0)
        
        $Script:Results += [PSCustomObject]@{
            SamAccountName       = $account.SamAccountName
            Type                 = $account.ObjectClass
            CurrentEncryption    = Get-EncryptionTypeName -EncType $encType
            CurrentEncryptionRaw = if ($null -eq $encType) { 0 } else { $encType }
            UsesRC4              = $usesRC4
            HasAES               = $hasAES
            HasSPN               = $hasSPN
            SPNCount             = if ($hasSPN) { $account.servicePrincipalName.Count } else { 0 }
            RiskLevel            = $riskLevel
            LastLogon            = $account.LastLogonDate
            PasswordLastSet      = $account.PasswordLastSet
            DistinguishedName    = $account.DistinguishedName
            ExcludedFromMigration = $excluded
            MigrationStatus      = 'Pending'
            MigrationError       = $null
        }
    }
    
    Write-Log "Audit complete. Found $($Script:Results.Count) accounts." -Level SUCCESS
}

function Invoke-EncryptionMigration {
    Write-Log "Starting encryption migration..." -Level INFO
    
    $targetValue = Get-TargetEncryptionValue -Target $TargetEncryption
    $accountsToMigrate = $Script:Results | Where-Object { 
        $_.UsesRC4 -and -not $_.ExcludedFromMigration 
    }
    
    Write-Log "Accounts to migrate: $($accountsToMigrate.Count)" -Level INFO
    
    if ($DryRun) {
        Write-Log "DRY RUN MODE: No changes will be applied" -Level WARNING
    }
    
    foreach ($account in $accountsToMigrate) {
        try {
            if ($DryRun) {
                Write-Log "[DRY RUN] Would migrate $($account.SamAccountName) to $TargetEncryption" -Level INFO
                $account.MigrationStatus = 'Simulated'
            } else {
                # Perform actual migration
                $identity = $account.DistinguishedName
                
                if ($account.Type -eq 'user') {
                    Set-ADUser -Identity $identity -Replace @{'msDS-SupportedEncryptionTypes' = $targetValue}
                } else {
                    Set-ADComputer -Identity $identity -Replace @{'msDS-SupportedEncryptionTypes' = $targetValue}
                }
                
                Write-Log "Migrated $($account.SamAccountName) to $TargetEncryption" -Level SUCCESS
                $account.MigrationStatus = 'Completed'
            }
        } catch {
            Write-Log "Failed to migrate $($account.SamAccountName): $_" -Level ERROR
            $account.MigrationStatus = 'Failed'
            $account.MigrationError = $_.Exception.Message
        }
    }
    
    # Mark excluded accounts
    $Script:Results | Where-Object { $_.ExcludedFromMigration } | ForEach-Object {
        $_.MigrationStatus = 'Excluded'
    }
    
    # Mark accounts already using AES
    $Script:Results | Where-Object { -not $_.UsesRC4 } | ForEach-Object {
        $_.MigrationStatus = 'Already AES'
    }
}

function Test-DomainControllerEncryption {
    Write-Log "Validating Domain Controllers..." -Level INFO
    
    try {
        $dcs = Get-ADDomainController -Filter *
        
        foreach ($dc in $dcs) {
            Write-Log "Checking DC: $($dc.HostName)" -Level INFO
            
            try {
                # Get DC computer object
                $dcObject = Get-ADComputer -Identity $dc.Name -Properties 'msDS-SupportedEncryptionTypes'
                $encType = $dcObject.'msDS-SupportedEncryptionTypes'
                
                # Check if DC supports AES
                $supportsAES128 = ($encType -band 8) -eq 8
                $supportsAES256 = ($encType -band 16) -eq 16
                $supportsRC4 = ($encType -band 4) -eq 4
                
                $Script:DCValidation += [PSCustomObject]@{
                    DCName              = $dc.HostName
                    Site                = $dc.Site
                    OperatingSystem     = $dc.OperatingSystem
                    CurrentEncryption   = Get-EncryptionTypeName -EncType $encType
                    SupportsAES128      = $supportsAES128
                    SupportsAES256      = $supportsAES256
                    SupportsRC4         = $supportsRC4
                    RecommendedAction   = if (-not $supportsAES256) { 'Enable AES256' } else { 'OK' }
                    IsGlobalCatalog     = $dc.IsGlobalCatalog
                    IPv4Address         = $dc.IPv4Address
                }
            } catch {
                Write-Log "Error checking DC $($dc.HostName): $_" -Level ERROR
                
                $Script:DCValidation += [PSCustomObject]@{
                    DCName              = $dc.HostName
                    Site                = $dc.Site
                    OperatingSystem     = 'Error'
                    CurrentEncryption   = 'Unable to retrieve'
                    SupportsAES128      = $false
                    SupportsAES256      = $false
                    SupportsRC4         = $null
                    RecommendedAction   = 'Investigation Required'
                    IsGlobalCatalog     = $dc.IsGlobalCatalog
                    IPv4Address         = $dc.IPv4Address
                }
            }
        }
        
        Write-Log "DC validation complete. Checked $($dcs.Count) controllers." -Level SUCCESS
    } catch {
        Write-Log "Error during DC validation: $_" -Level ERROR
    }
}

#endregion

#region Event Log Analysis Functions - OFFICIAL MICROSOFT EVENT IDS

function Get-KerberosEventLogData {
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
    Write-Log "  Kerberos RC4 Event Log Analysis" -Level INFO
    Write-Log "  Using Microsoft KB5073381 Event IDs (201-209)" -Level INFO
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
    
    $startTime = (Get-Date).AddHours(-$EventLogHours)
    Write-Log "Analyzing events from last $EventLogHours hours (since $startTime)" -Level INFO
    
    # Official Microsoft RC4 Event IDs (KB5073381 - January 2026)
    $microsoftRC4Events = @{
        201 = @{
            Name = 'Client Only Supports RC4'
            Description = 'Client advertising only RC4, service has default config'
            Severity = 'Warning'
            Category = 'Audit'
            Phase = 1
            TransitionsTo = 203
            Impact = 'Will fail in Enforcement mode'
        }
        202 = @{
            Name = 'Service Only Has RC4 Keys'
            Description = 'Service account lacks AES keys, has default config'
            Severity = 'Warning'
            Category = 'Audit'
            Phase = 1
            TransitionsTo = 204
            Impact = 'Will fail in Enforcement mode'
        }
        203 = @{
            Name = 'Blocked - Client RC4 Only'
            Description = 'KDC blocked RC4 request - client supports only RC4'
            Severity = 'Critical'
            Category = 'Enforcement'
            Phase = 2
            TransitionsFrom = 201
            Impact = 'Authentication FAILING NOW'
        }
        204 = @{
            Name = 'Blocked - Service RC4 Keys'
            Description = 'KDC blocked RC4 request - service has only RC4 keys'
            Severity = 'Critical'
            Category = 'Enforcement'
            Phase = 2
            TransitionsFrom = 202
            Impact = 'Authentication FAILING NOW'
        }
        205 = @{
            Name = 'Insecure DDSET Configuration'
            Description = 'DefaultDomainSupportedEncTypes includes RC4'
            Severity = 'Warning'
            Category = 'Policy'
            Phase = 1
            TransitionsTo = $null
            Impact = 'Policy recommendation - does not transition to error'
        }
        206 = @{
            Name = 'Service AES-Only, Client RC4'
            Description = 'Service configured for AES but client advertises only RC4'
            Severity = 'High'
            Category = 'Audit'
            Phase = 1
            TransitionsTo = 208
            Impact = 'Will fail in Enforcement mode'
        }
        207 = @{
            Name = 'Service AES Config, No AES Keys'
            Description = 'Service configured for AES but lacks AES keys'
            Severity = 'High'
            Category = 'Audit'
            Phase = 1
            TransitionsTo = 209
            Impact = 'Will fail in Enforcement mode'
        }
        208 = @{
            Name = 'Denied - Client No AES'
            Description = 'KDC denied - client does not advertise AES'
            Severity = 'Critical'
            Category = 'Enforcement'
            Phase = 2
            TransitionsFrom = 206
            Impact = 'Authentication FAILING NOW'
        }
        209 = @{
            Name = 'Denied - Service No AES Keys'
            Description = 'KDC denied - service lacks AES keys'
            Severity = 'Critical'
            Category = 'Enforcement'
            Phase = 2
            TransitionsFrom = 207
            Impact = 'Authentication FAILING NOW'
        }
    }
    
    # Legacy Kerberos events for backward compatibility
    $legacyKerberosEvents = @(
        4768,  # TGT requested
        4769,  # Service ticket requested
        4770,  # Service ticket renewed
        4771,  # Pre-auth failed
        4772   # TGT request failed
    )
    
    $dcsToScan = @()
    
    if ($AnalyzeAllDCs) {
        Write-Log "Scanning all Domain Controllers..." -Level INFO
        $dcsToScan = (Get-ADDomainController -Filter *).HostName
    } else {
        Write-Log "Scanning local Domain Controller..." -Level INFO
        $dcsToScan = @($env:COMPUTERNAME)
    }
    
    $totalEvents = 0
    $modernEventsFound = $false
    
    foreach ($dcName in $dcsToScan) {
        Write-Log "Processing DC: $dcName" -Level INFO
        
        # Check for Microsoft KB5073381 events (201-209) in System log
        Write-Log "  Scanning for Microsoft KB5073381 RC4 events (201-209)..." -Level INFO
        
        foreach ($eventId in $microsoftRC4Events.Keys) {
            $eventInfo = $microsoftRC4Events[$eventId]
            Write-Log "    Checking Event ID $eventId - $($eventInfo.Name)" -Level INFO
            
            # METHOD 1: Try with simplified filter (no Provider restriction)
            # This is more reliable as Provider names can vary
            $filterXml = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">
      *[System[(EventID=$eventId) and TimeCreated[timediff(@SystemTime) &lt;= $($EventLogHours * 3600000)]]]
    </Select>
  </Query>
</QueryList>
"@
            
            try {
                Write-Log "      Attempting query with simplified filter..." -Level INFO
                $events = Get-WinEvent -FilterXml $filterXml -ComputerName $dcName -MaxEvents $MaxEvents -ErrorAction Stop
                
                if ($events) {
                    # Verify these are actually KDC/Kdcsvc events
                    $kdcEvents = $events | Where-Object { 
                        $_.ProviderName -like '*Kdc*' -or 
                        $_.ProviderName -like '*Kerberos*' -or
                        $_.LogName -eq 'System'
                    }
                    
                    if ($kdcEvents) {
                        $modernEventsFound = $true
                        $totalEvents += $kdcEvents.Count
                        Write-Log "      ✅ Found $($kdcEvents.Count) events (Provider: $($kdcEvents[0].ProviderName))" -Level $(if ($eventInfo.Severity -eq 'Critical') { 'ERROR' } else { 'WARNING' })
                        
                        foreach ($event in $kdcEvents) {
                            $eventXml = [xml]$event.ToXml()
                            $eventData = @{}
                            
                            # Parse event data - handle both named and positional data
                            if ($eventXml.Event.EventData.Data) {
                                foreach ($data in $eventXml.Event.EventData.Data) {
                                    if ($data.Name) {
                                        # Named parameter
                                        $eventData[$data.Name] = $data.'#text'
                                    } else {
                                        # Positional parameter - store by index
                                        $eventData["Data$($data.GetAttribute('Name'))"] = $data.'#text'
                                    }
                                }
                            }
                            
                            # Extract detailed information with fallbacks for different data structures
                            $Script:EventLogData += [PSCustomObject]@{
                                Timestamp           = $event.TimeCreated
                                DomainController    = $dcName
                                EventID             = $eventId
                                EventType           = $eventInfo.Name
                                EventCategory       = $eventInfo.Category
                                EventSeverity       = $eventInfo.Severity
                                EventPhase          = $eventInfo.Phase
                                
                                # Account information (with fallbacks)
                                AccountName         = if ($eventData['Account Name']) { $eventData['Account Name'] } else { $eventData['TargetUserName'] }
                                AccountDomain       = if ($eventData['Supplied Realm Name']) { $eventData['Supplied Realm Name'] } else { $eventData['TargetDomainName'] }
                                AccountMsdsSET      = $eventData['msds-SupportedEncryptionTypes']
                                AvailableKeys       = $eventData['Available Keys']
                                
                                # Service information
                                ServiceName         = if ($eventData['Service Name']) { $eventData['Service Name'] } else { $eventData['ServiceName'] }
                                ServiceID           = if ($eventData['Service ID']) { $eventData['Service ID'] } else { $eventData['ServiceSid'] }
                                ServiceMsdsSET      = $eventData['msds-SupportedEncryptionTypes']
                                ServiceKeys         = $eventData['Available Keys']
                                
                                # Domain Controller configuration
                                DCMsdsSET           = $eventData['msds-SupportedEncryptionTypes']
                                DCDDSET             = if ($eventData['DefaultDomainSupportedEncTypes']) { $eventData['DefaultDomainSupportedEncTypes'] } else { $eventData['Cipher(s)'] }
                                DCKeys              = $eventData['Available Keys']
                                
                                # Client/Network information
                                ClientAddress       = if ($eventData['Client Address']) { $eventData['Client Address'] } else { $eventData['IpAddress'] }
                                ClientPort          = if ($eventData['Client Port']) { $eventData['Client Port'] } else { $eventData['IpPort'] }
                                AdvertizedEtypes    = if ($eventData['Advertized Etypes']) { $eventData['Advertized Etypes'] } else { $eventData['TicketEncryptionType'] }
                                
                                # Encryption details
                                EncryptionName      = 'RC4-HMAC (Weak)'
                                IsRC4               = $true
                                IsModernEvent       = $true
                                
                                # Impact and recommendations
                                Impact              = $eventInfo.Impact
                                ActionRequired      = Get-EventActionRequired -EventID $eventId -EventInfo $eventInfo
                                Priority            = Get-EventPriority -EventID $eventId -Severity $eventInfo.Severity
                                TransitionsTo       = $eventInfo.TransitionsTo
                                TransitionsFrom     = $eventInfo.TransitionsFrom
                                
                                # Additional metadata
                                ProviderName        = $event.ProviderName
                                FullMessage         = $event.Message
                            }
                        }
                    } else {
                        Write-Log "      ℹ️ Found events but not from KDC provider - skipping" -Level INFO
                    }
                } else {
                    Write-Log "      ℹ️ No events found" -Level INFO
                }
            } catch [System.Exception] {
                # Check if it's just "no events found" vs actual error
                if ($_.Exception.Message -like "*No events were found*") {
                    Write-Log "      ℹ️ No events found for Event ID $eventId" -Level INFO
                } else {
                    Write-Log "      ⚠️ Error querying Event ID $eventId : $($_.Exception.Message)" -Level WARNING
                    
                    # METHOD 2: Fallback - try direct Get-WinEvent with hashtable filter
                    Write-Log "      Attempting fallback method with hashtable filter..." -Level INFO
                    try {
                        $filterHash = @{
                            LogName = 'System'
                            ID = $eventId
                            StartTime = $startTime
                        }
                        
                        $fallbackEvents = Get-WinEvent -FilterHashtable $filterHash -ComputerName $dcName -MaxEvents $MaxEvents -ErrorAction Stop
                        
                        if ($fallbackEvents) {
                            # Filter to only KDC-related events
                            $kdcFallbackEvents = $fallbackEvents | Where-Object { 
                                $_.ProviderName -like '*Kdc*' -or 
                                $_.ProviderName -like '*Kerberos*'
                            }
                            
                            if ($kdcFallbackEvents) {
                                $modernEventsFound = $true
                                $totalEvents += $kdcFallbackEvents.Count
                                Write-Log "      ✅ Fallback successful! Found $($kdcFallbackEvents.Count) events" -Level SUCCESS
                                
                                # Process fallback events (same as above)
                                foreach ($event in $kdcFallbackEvents) {
                                    $eventXml = [xml]$event.ToXml()
                                    $eventData = @{}
                                    
                                    if ($eventXml.Event.EventData.Data) {
                                        foreach ($data in $eventXml.Event.EventData.Data) {
                                            if ($data.Name) {
                                                $eventData[$data.Name] = $data.'#text'
                                            }
                                        }
                                    }
                                    
                                    $Script:EventLogData += [PSCustomObject]@{
                                        Timestamp           = $event.TimeCreated
                                        DomainController    = $dcName
                                        EventID             = $eventId
                                        EventType           = $eventInfo.Name
                                        EventCategory       = $eventInfo.Category
                                        EventSeverity       = $eventInfo.Severity
                                        EventPhase          = $eventInfo.Phase
                                        AccountName         = if ($eventData['Account Name']) { $eventData['Account Name'] } else { $eventData['TargetUserName'] }
                                        AccountDomain       = if ($eventData['Supplied Realm Name']) { $eventData['Supplied Realm Name'] } else { $eventData['TargetDomainName'] }
                                        ServiceName         = if ($eventData['Service Name']) { $eventData['Service Name'] } else { $eventData['ServiceName'] }
                                        ClientAddress       = if ($eventData['Client Address']) { $eventData['Client Address'] } else { $eventData['IpAddress'] }
                                        EncryptionName      = 'RC4-HMAC (Weak)'
                                        IsRC4               = $true
                                        IsModernEvent       = $true
                                        Impact              = $eventInfo.Impact
                                        ActionRequired      = Get-EventActionRequired -EventID $eventId -EventInfo $eventInfo
                                        Priority            = Get-EventPriority -EventID $eventId -Severity $eventInfo.Severity
                                        ProviderName        = $event.ProviderName
                                        FullMessage         = $event.Message
                                    }
                                }
                            }
                        }
                    } catch {
                        if ($_.Exception.Message -notlike "*No events were found*") {
                            Write-Log "      ⚠️ Fallback also failed: $($_.Exception.Message)" -Level WARNING
                        }
                    }
                }
            }
        }
        
        # If no modern events found, check legacy events
        if (-not $modernEventsFound) {
            Write-Log "  No CVE-2026-20833 events found. Checking LEGACY Kerberos events..." -Level WARNING
            Write-Log "  (DC may need security update - see KB5073381 article)" -Level WARNING
            
            foreach ($eventId in $legacyKerberosEvents) {
                Write-Log "    Scanning Legacy Event ID $eventId..." -Level INFO
                
                $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=$eventId) and TimeCreated[timediff(@SystemTime) &lt;= $($EventLogHours * 3600000)]]]
    </Select>
  </Query>
</QueryList>
"@
                
                try {
                    $events = Get-WinEvent -FilterXml $filterXml -ComputerName $dcName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                    
                    if ($events) {
                        $totalEvents += $events.Count
                        Write-Log "      Found $($events.Count) events" -Level INFO
                        
                        foreach ($event in $events) {
                            $eventXml = [xml]$event.ToXml()
                            $eventData = @{}
                            
                            foreach ($data in $eventXml.Event.EventData.Data) {
                                $eventData[$data.Name] = $data.'#text'
                            }
                            
                            # Extract encryption type
                            $ticketEncryption = $null
                            
                            switch ($eventId) {
                                4768 { $ticketEncryption = $eventData['TicketEncryptionType'] }
                                4769 { $ticketEncryption = $eventData['TicketEncryptionType'] }
                                4770 { $ticketEncryption = $eventData['TicketEncryptionType'] }
                                4771 { $ticketEncryption = $eventData['PreAuthType'] }
                                4772 { $ticketEncryption = $eventData['TicketEncryptionType'] }
                            }
                            
                            if ($ticketEncryption) {
                                $encryptionName = Get-KerberosEncryptionTypeFromHex -HexValue $ticketEncryption
                                $isRC4 = Test-IsRC4Encryption -HexValue $ticketEncryption
                                
                                # Only store RC4 events
                                if ($isRC4) {
                                    $Script:EventLogData += [PSCustomObject]@{
                                        Timestamp           = $event.TimeCreated
                                        DomainController    = $dcName
                                        EventID             = $eventId
                                        EventType           = switch ($eventId) {
                                            4768 { 'TGT Requested (Legacy)' }
                                            4769 { 'Service Ticket Requested (Legacy)' }
                                            4770 { 'Service Ticket Renewed (Legacy)' }
                                            4771 { 'Pre-Auth Failed (Legacy)' }
                                            4772 { 'TGT Request Failed (Legacy)' }
                                        }
                                        EventCategory       = 'Legacy'
                                        EventSeverity       = 'Medium'
                                        EventPhase          = 0
                                        AccountName         = $eventData['TargetUserName']
                                        AccountDomain       = $eventData['TargetDomainName']
                                        ServiceName         = $eventData['ServiceName']
                                        ClientAddress       = $eventData['IpAddress']
                                        ClientPort          = $eventData['IpPort']
                                        TicketEncryptionType = $ticketEncryption
                                        EncryptionName      = $encryptionName
                                        IsRC4               = $isRC4
                                        IsModernEvent       = $false
                                        Impact              = 'Unknown - upgrade DC to KB5073381'
                                        ActionRequired      = 'Update DC and review modern events'
                                        Priority            = 'Medium'
                                        ProviderName        = $event.ProviderName
                                        FullMessage         = $event.Message
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    if ($_.Exception.Message -notlike "*No events were found*") {
                        Write-Log "      Error reading Legacy Event ID $eventId from $dcName : $_" -Level WARNING
                    }
                }
            }
        }
    }
    
    $rc4Events = $Script:EventLogData.Count
    
    Write-Log "═══════════════════════════════════════════════════════════" -Level SUCCESS
    Write-Log "  Event log analysis complete!" -Level SUCCESS
    Write-Log "  Total events analyzed: $totalEvents" -Level INFO
    Write-Log "  RC4 events found: $rc4Events" -Level WARNING
    Write-Log "  Using KB5073381 events: $(if ($modernEventsFound) { 'YES ✅' } else { 'NO (Legacy mode - update needed)' })" -Level INFO
    
    if ($modernEventsFound -and $Script:EventLogData.Count -gt 0) {
        $sampleProvider = ($Script:EventLogData | Where-Object { $_.ProviderName } | Select-Object -First 1).ProviderName
        if ($sampleProvider) {
            Write-Log "  Event Provider Name: $sampleProvider" -Level INFO
        }
    }
    
    Write-Log "═══════════════════════════════════════════════════════════" -Level SUCCESS
    
    # Build summary statistics
    Build-EventLogSummary -UsingModernEvents $modernEventsFound
}

function Get-EventActionRequired {
    param(
        [int]$EventID,
        [hashtable]$EventInfo
    )
    
    switch ($EventID) {
        201 { return 'AUDIT: Update clients to support AES or configure service msds-SET' }
        202 { return 'AUDIT: Reset service password to generate AES keys' }
        203 { return 'CRITICAL: Authentication failing - update client or enable RC4 explicitly' }
        204 { return 'CRITICAL: Authentication failing - reset service password for AES keys' }
        205 { return 'POLICY: Review DefaultDomainSupportedEncTypes registry setting' }
        206 { return 'HIGH: Update client to advertise AES encryption support' }
        207 { return 'HIGH: Reset service password to generate AES keys' }
        208 { return 'CRITICAL: Authentication denied - client must support AES' }
        209 { return 'CRITICAL: Authentication denied - service needs AES keys' }
        default { return 'Review and plan AES migration' }
    }
}

function Get-EventPriority {
    param(
        [int]$EventID,
        [string]$Severity
    )
    
    # Enforcement events (203, 204, 208, 209) are always Critical
    if ($EventID -in @(203, 204, 208, 209)) {
        return 'Critical'
    }
    
    # High severity audit events (206, 207)
    if ($EventID -in @(206, 207)) {
        return 'High'
    }
    
    # Warning events (201, 202, 205)
    if ($EventID -in @(201, 202, 205)) {
        return 'Medium'
    }
    
    # Default based on severity
    switch ($Severity) {
        'Critical' { return 'Critical' }
        'High' { return 'High' }
        'Warning' { return 'Medium' }
        default { return 'Low' }
    }
}

function Build-EventLogSummary {
    param([bool]$UsingModernEvents)
    
    Write-Log "Building event log summary statistics..." -Level INFO
    
    # Safe count function
    $safeCount = { param($collection) if ($collection) { @($collection).Count } else { 0 } }
    
    $Script:EventLogSummary = @{
        UsingModernEvents = $UsingModernEvents
        TotalRC4Events = $Script:EventLogData.Count
        
        # Phase categorization
        Phase1Events = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventPhase -eq 1 }))
        Phase2Events = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventPhase -eq 2 }))
        LegacyEvents = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventPhase -eq 0 }))
        
        # Event category breakdown
        AuditEvents = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventCategory -eq 'Audit' }))
        EnforcementEvents = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventCategory -eq 'Enforcement' }))
        PolicyEvents = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventCategory -eq 'Policy' }))
        
        # Severity breakdown
        CriticalEvents = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventSeverity -eq 'Critical' }))
        HighSeverityEvents = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventSeverity -eq 'High' }))
        WarningEvents = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventSeverity -eq 'Warning' }))
        
        # Individual event counts
        Event201Count = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventID -eq 201 }))
        Event202Count = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventID -eq 202 }))
        Event203Count = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventID -eq 203 }))
        Event204Count = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventID -eq 204 }))
        Event205Count = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventID -eq 205 }))
        Event206Count = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventID -eq 206 }))
        Event207Count = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventID -eq 207 }))
        Event208Count = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventID -eq 208 }))
        Event209Count = (& $safeCount ($Script:EventLogData | Where-Object { $_.EventID -eq 209 }))
        
        # Unique entities
        UniqueAccounts = (& $safeCount ($Script:EventLogData | Select-Object -ExpandProperty AccountName -Unique | Where-Object { $_ }))
        UniqueServices = (& $safeCount ($Script:EventLogData | Where-Object { $_.ServiceName } | Select-Object -ExpandProperty ServiceName -Unique))
        UniqueClients = (& $safeCount ($Script:EventLogData | Where-Object { $_.ClientAddress -and $_.ClientAddress -ne '::1' -and $_.ClientAddress -ne '-' } | Select-Object -ExpandProperty ClientAddress -Unique))
        UniqueDCs = (& $safeCount ($Script:EventLogData | Select-Object -ExpandProperty DomainController -Unique))
        
        # Top offenders with priority
        TopAccountsByRC4 = $Script:EventLogData | 
            Where-Object { $_.AccountName } |
            Group-Object AccountName | 
            Sort-Object Count -Descending | 
            Select-Object -First 10 @{N='Account';E={$_.Name}}, Count,
            @{N='HasCritical';E={ ($_.Group | Where-Object { $_.EventID -in @(203,204,208,209) }).Count -gt 0 }},
            @{N='HasHigh';E={ ($_.Group | Where-Object { $_.EventID -in @(206,207) }).Count -gt 0 }},
            @{N='HighestPriority';E={ 
                if (($_.Group | Where-Object { $_.EventID -in @(203,204,208,209) }).Count -gt 0) { 'Critical' }
                elseif (($_.Group | Where-Object { $_.EventID -in @(206,207) }).Count -gt 0) { 'High' }
                else { 'Medium' }
            }}
        
        TopServicesByRC4 = $Script:EventLogData | 
            Where-Object { $_.ServiceName -and $_.ServiceName -ne '-' } |
            Group-Object ServiceName | 
            Sort-Object Count -Descending | 
            Select-Object -First 10 @{N='Service';E={$_.Name}}, Count,
            @{N='HighestPriority';E={ 
                if (($_.Group | Where-Object { $_.EventID -in @(203,204,208,209) }).Count -gt 0) { 'Critical' }
                elseif (($_.Group | Where-Object { $_.EventID -in @(206,207) }).Count -gt 0) { 'High' }
                else { 'Medium' }
            }}
        
        TopClientsByRC4 = $Script:EventLogData | 
            Where-Object { $_.ClientAddress -and $_.ClientAddress -ne '::1' -and $_.ClientAddress -ne '-' } |
            Group-Object ClientAddress | 
            Sort-Object Count -Descending | 
            Select-Object -First 10 @{N='ClientIP';E={$_.Name}}, Count
        
        # Event type distribution
        EventTypeDistribution = $Script:EventLogData | 
            Where-Object { $_.EventType } |
            Group-Object EventType | 
            Select-Object @{N='EventType';E={$_.Name}}, Count
        
        # Event ID distribution (for modern events)
        EventIDDistribution = $Script:EventLogData |
            Where-Object { $_.EventID -ge 201 -and $_.EventID -le 209 } |
            Group-Object EventID |
            Select-Object @{N='EventID';E={$_.Name}}, 
                         @{N='EventName';E={
                             switch ([int]$_.Name) {
                                 201 { 'Client RC4 Only (Audit)' }
                                 202 { 'Service RC4 Keys (Audit)' }
                                 203 { 'Blocked - Client RC4' }
                                 204 { 'Blocked - Service RC4' }
                                 205 { 'Insecure DDSET Config' }
                                 206 { 'AES Service, RC4 Client (Audit)' }
                                 207 { 'AES Config, No Keys (Audit)' }
                                 208 { 'Denied - No Client AES' }
                                 209 { 'Denied - No Service AES' }
                                 default { "Event $($_.Name)" }
                             }
                         }},
                         Count
        
        # Timeline data with severity
        TimelineData = $Script:EventLogData | 
            Group-Object { $_.Timestamp.ToString('yyyy-MM-dd HH:00') } | 
            Sort-Object Name |
            Select-Object @{N='Hour';E={$_.Name}}, Count,
            @{N='CriticalCount';E={ ($_.Group | Where-Object { $_.EventSeverity -eq 'Critical' }).Count }},
            @{N='HighCount';E={ ($_.Group | Where-Object { $_.EventSeverity -eq 'High' }).Count }},
            @{N='WarningCount';E={ ($_.Group | Where-Object { $_.EventSeverity -eq 'Warning' }).Count }}
        
        # Readiness assessment
        ReadinessScore = Get-RC4MigrationReadiness
        CurrentPhase = Get-CurrentDeploymentPhase
    }
    
    # Ensure ALL collections are initialized (not null)
    $collectionsToCheck = @(
        'TopAccountsByRC4',
        'TopServicesByRC4',
        'TopClientsByRC4',
        'EventTypeDistribution',
        'EventIDDistribution',
        'TimelineData'
    )
    
    foreach ($collection in $collectionsToCheck) {
        if ($null -eq $Script:EventLogSummary.$collection) {
            Write-Log "  Initializing empty collection: $collection" -Level INFO
            $Script:EventLogSummary.$collection = @()
        }
    }
    
    # Ensure collections are not null
    # if (-not $Script:EventLogSummary.TopAccountsByRC4) { $Script:EventLogSummary.TopAccountsByRC4 = @() }
    # if (-not $Script:EventLogSummary.TopServicesByRC4) { $Script:EventLogSummary.TopServicesByRC4 = @() }
    # if (-not $Script:EventLogSummary.TopClientsByRC4) { $Script:EventLogSummary.TopClientsByRC4 = @() }
    # if (-not $Script:EventLogSummary.EventTypeDistribution) { $Script:EventLogSummary.EventTypeDistribution = @() }
    # if (-not $Script:EventLogSummary.EventIDDistribution) { $Script:EventLogSummary.EventIDDistribution = @() }
    # if (-not $Script:EventLogSummary.TimelineData) { $Script:EventLogSummary.TimelineData = @() }
    
    Write-Log "Summary complete:" -Level SUCCESS
    Write-Log "  Using KB5073381 Events: $(if ($UsingModernEvents) { 'YES' } else { 'NO (Legacy)' })" -Level INFO
    Write-Log "  Current Phase: $($Script:EventLogSummary.CurrentPhase)" -Level INFO
    Write-Log "  Total RC4 Events: $($Script:EventLogSummary.TotalRC4Events)" -Level INFO
    
    if ($UsingModernEvents) {
        Write-Log "  Critical Events (203,204,208,209): $($Script:EventLogSummary.CriticalEvents)" -Level $(if ($Script:EventLogSummary.CriticalEvents -gt 0) { 'ERROR' } else { 'INFO' })
        Write-Log "  High Risk Events (206,207): $($Script:EventLogSummary.HighSeverityEvents)" -Level $(if ($Script:EventLogSummary.HighSeverityEvents -gt 0) { 'WARNING' } else { 'INFO' })
        Write-Log "  Audit Events (201,202): $(($Script:EventLogSummary.Event201Count + $Script:EventLogSummary.Event202Count))" -Level INFO
    }
    
    Write-Log "  Unique Accounts: $($Script:EventLogSummary.UniqueAccounts)" -Level INFO
    Write-Log "  Migration Readiness: $($Script:EventLogSummary.ReadinessScore)%" -Level INFO
}

function Get-CurrentDeploymentPhase {
    # Try to detect current phase based on registry or event types
    $enforcementEvents = ($Script:EventLogData | Where-Object { $_.EventID -in @(203,204,208,209) }).Count
    
    if ($enforcementEvents -gt 0) {
        return 'Phase 2 - Enforcement Mode'
    }
    
    $auditEvents = ($Script:EventLogData | Where-Object { $_.EventID -in @(201,202,206,207) }).Count
    
    if ($auditEvents -gt 0) {
        return 'Phase 1 - Audit Mode'
    }
    
    return 'Unknown / Legacy'
}

function Get-RC4MigrationReadiness {
    $totalEvents = $Script:EventLogData.Count
    
    if ($totalEvents -eq 0) {
        return 100 # No RC4 usage = ready!
    }
    
    # Count critical enforcement events
    $criticalEvents = ($Script:EventLogData | Where-Object { $_.EventID -in @(203,204,208,209) }).Count
    # Count high-priority audit events
    $highEvents = ($Script:EventLogData | Where-Object { $_.EventID -in @(206,207) }).Count
    # Count standard audit events
    $auditEvents = ($Script:EventLogData | Where-Object { $_.EventID -in @(201,202) }).Count
    
    # Readiness score calculation based on KB5073381 guidance
    if ($criticalEvents -gt 0) {
        return 0 # Already experiencing authentication failures
    } elseif ($highEvents -gt 0) {
        return 25 # High risk - will fail in enforcement
    } elseif ($auditEvents -gt 0) {
        return 50 # Medium risk - needs migration planning
    } else {
        return 75 # Low usage or legacy events only
    }
}

#endregion


function Build-EventLogSummary {
    Write-Log "Building event log summary statistics..." -Level INFO
    
    # Safe count function that handles null/empty
    $safeCount = { param($collection) if ($collection) { @($collection).Count } else { 0 } }
    
    $Script:EventLogSummary = @{
        TotalRC4Events = $Script:EventLogData.Count
        UniqueAccounts = (& $safeCount ($Script:EventLogData | Select-Object -ExpandProperty AccountName -Unique | Where-Object { $_ }))
        UniqueServices = (& $safeCount ($Script:EventLogData | Where-Object { $_.ServiceName } | Select-Object -ExpandProperty ServiceName -Unique))
        UniqueClients = (& $safeCount ($Script:EventLogData | Where-Object { $_.ClientAddress -and $_.ClientAddress -ne '::1' -and $_.ClientAddress -ne '-' } | Select-Object -ExpandProperty ClientAddress -Unique))
        
        TopAccountsByRC4 = $Script:EventLogData | 
            Where-Object { $_.AccountName } |
            Group-Object AccountName | 
            Sort-Object Count -Descending | 
            Select-Object -First 10 @{N='Account';E={$_.Name}}, Count
        
        TopServicesByRC4 = $Script:EventLogData | 
            Where-Object { $_.ServiceName -and $_.ServiceName -ne '-' } |
            Group-Object ServiceName | 
            Sort-Object Count -Descending | 
            Select-Object -First 10 @{N='Service';E={$_.Name}}, Count
        
        TopClientsByRC4 = $Script:EventLogData | 
            Where-Object { $_.ClientAddress -and $_.ClientAddress -ne '::1' -and $_.ClientAddress -ne '-' } |
            Group-Object ClientAddress | 
            Sort-Object Count -Descending | 
            Select-Object -First 10 @{N='ClientIP';E={$_.Name}}, Count
        
        EventTypeDistribution = $Script:EventLogData | 
            Where-Object { $_.EventType } |
            Group-Object EventType | 
            Select-Object @{N='EventType';E={$_.Name}}, Count
        
        TimelineData = $Script:EventLogData | 
            Group-Object { $_.Timestamp.ToString('yyyy-MM-dd HH:00') } | 
            Sort-Object Name |
            Select-Object @{N='Hour';E={$_.Name}}, Count
    }
    
    # Ensure collections are not null
    if (-not $Script:EventLogSummary.TopAccountsByRC4) { 
        $Script:EventLogSummary.TopAccountsByRC4 = @() 
    }
    if (-not $Script:EventLogSummary.TopServicesByRC4) { 
        $Script:EventLogSummary.TopServicesByRC4 = @() 
    }
    if (-not $Script:EventLogSummary.TopClientsByRC4) { 
        $Script:EventLogSummary.TopClientsByRC4 = @() 
    }
    if (-not $Script:EventLogSummary.EventTypeDistribution) { 
        $Script:EventLogSummary.EventTypeDistribution = @() 
    }
    if (-not $Script:EventLogSummary.TimelineData) { 
        $Script:EventLogSummary.TimelineData = @() 
    }
    
    Write-Log "Summary complete. Found $($Script:EventLogSummary.UniqueAccounts) unique accounts using RC4" -Level SUCCESS
}
#region end

#region HTML Report Generation

function New-HTMLReport {
    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $domain = (Get-ADDomain).DNSRoot
    
    # Calculate statistics
    $totalAccounts = $Script:Results.Count
    $rc4Accounts = ($Script:Results | Where-Object { $_.UsesRC4 }).Count
    $aesAccounts = ($Script:Results | Where-Object { $_.HasAES }).Count
    $highRisk = ($Script:Results | Where-Object { $_.RiskLevel -eq 'High' }).Count
    $mediumRisk = ($Script:Results | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    $migrated = ($Script:Results | Where-Object { $_.MigrationStatus -eq 'Completed' }).Count
    $failed = ($Script:Results | Where-Object { $_.MigrationStatus -eq 'Failed' }).Count
    
    # Prepare data for charts
    $riskData = @{
        High = $highRisk
        Medium = $mediumRisk
        Low = $totalAccounts - $highRisk - $mediumRisk
    }
    
    $encryptionData = @{
        RC4Only = ($Script:Results | Where-Object { $_.UsesRC4 -and -not $_.HasAES }).Count
        Mixed = ($Script:Results | Where-Object { $_.UsesRC4 -and $_.HasAES }).Count
        AESOnly = ($Script:Results | Where-Object { -not $_.UsesRC4 -and $_.HasAES }).Count
    }
    
    $migrationData = @{
        Completed = $migrated
        Pending = ($Script:Results | Where-Object { $_.MigrationStatus -eq 'Pending' }).Count
        Failed = $failed
        Excluded = ($Script:Results | Where-Object { $_.MigrationStatus -eq 'Excluded' }).Count
        AlreadyAES = ($Script:Results | Where-Object { $_.MigrationStatus -eq 'Already AES' }).Count
    }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kerberos Encryption Audit Report - $domain</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card.danger {
            border-left-color: #e74c3c;
        }
        
        .stat-card.warning {
            border-left-color: #f39c12;
        }
        
        .stat-card.success {
            border-left-color: #27ae60;
        }
        
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
            margin: 10px 0;
        }
        
        .stat-card .label {
            color: #7f8c8d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .charts-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
            padding: 30px;
        }
        
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .chart-container h3 {
            margin-bottom: 15px;
            color: #2c3e50;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .controls {
            padding: 20px 30px;
            background: #ecf0f1;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .controls input, .controls select {
            padding: 10px 15px;
            border: 1px solid #bdc3c7;
            border-radius: 5px;
            font-size: 0.95em;
        }
        
        .controls button {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.95em;
            transition: background 0.3s;
        }
        
        .controls button:hover {
            background: #5568d3;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        .table-container {
            padding: 30px;
            overflow-x: auto;
        }
        
        .table-section {
            margin-bottom: 40px;
        }
        
        .table-section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }
        
        th {
            background: #34495e;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #ecf0f1;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge-high {
            background: #e74c3c;
            color: white;
        }
        
        .badge-medium {
            background: #f39c12;
            color: white;
        }
        
        .badge-low {
            background: #27ae60;
            color: white;
        }
        
        .badge-completed {
            background: #27ae60;
            color: white;
        }
        
        .badge-failed {
            background: #e74c3c;
            color: white;
        }
        
        .badge-pending {
            background: #3498db;
            color: white;
        }
        
        .badge-excluded {
            background: #95a5a6;
            color: white;
        }
        
        .badge-simulated {
            background: #9b59b6;
            color: white;
        }
        
        .check-yes {
            color: #27ae60;
            font-weight: bold;
        }
        
        .check-no {
            color: #e74c3c;
            font-weight: bold;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
        }
        
        .info-box {
            background: #d1ecf1;
            border-left: 4px solid #0c5460;
            padding: 15px;
            margin: 20px 30px;
            border-radius: 5px;
        }
        
        .warning-box {
            background: #fff3cd;
            border-left: 4px solid #856404;
            padding: 15px;
            margin: 20px 30px;
            border-radius: 5px;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .controls {
                display: none;
            }
            
            .stat-card:hover {
                transform: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Kerberos Encryption Audit Report</h1>
            <div class="subtitle">
                Domain: <strong>$domain</strong><br>
                Generated: <strong>$reportDate</strong><br>
                Mode: <strong>$(if ($DryRun) { 'DRY RUN (Simulation)' } else { 'LIVE MIGRATION' })</strong>
            </div>
        </div>
        
        $(if ($DryRun) {
            '<div class="warning-box"><strong>⚠️ DRY RUN MODE:</strong> This report shows simulated results. No actual changes were made to Active Directory.</div>'
        })
        
        <div class="dashboard">
            <div class="stat-card">
                <div class="label">Total Accounts</div>
                <div class="value">$totalAccounts</div>
            </div>
            <div class="stat-card danger">
                <div class="label">Using RC4</div>
                <div class="value">$rc4Accounts</div>
            </div>
            <div class="stat-card success">
                <div class="label">Using AES</div>
                <div class="value">$aesAccounts</div>
            </div>
            <div class="stat-card danger">
                <div class="label">High Risk</div>
                <div class="value">$highRisk</div>
            </div>
            <div class="stat-card warning">
                <div class="label">Medium Risk</div>
                <div class="value">$mediumRisk</div>
            </div>
            <div class="stat-card success">
                <div class="label">Migrated</div>
                <div class="value">$migrated</div>
            </div>
        </div>
        
        <div class="charts-section">
            <div class="chart-container">
                <h3>📊 Risk Distribution</h3>
                <canvas id="riskChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>🔑 Encryption Types</h3>
                <canvas id="encryptionChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>🔄 Migration Status</h3>
                <canvas id="migrationChart"></canvas>
            </div>
        </div>
        
        <div class="controls">
            <input type="text" id="searchBox" placeholder="🔍 Search accounts..." onkeyup="filterTable()">
            <select id="riskFilter" onchange="filterTable()">
                <option value="">All Risk Levels</option>
                <option value="High">High Risk</option>
                <option value="Medium">Medium Risk</option>
                <option value="Low">Low Risk</option>
            </select>
            <select id="statusFilter" onchange="filterTable()">
                <option value="">All Statuses</option>
                <option value="Completed">Completed</option>
                <option value="Pending">Pending</option>
                <option value="Failed">Failed</option>
                <option value="Excluded">Excluded</option>
                <option value="Simulated">Simulated</option>
                <option value="Already AES">Already AES</option>
            </select>
            <button onclick="exportTableToCSV()">📥 Export to CSV</button>
            <button onclick="window.print()">🖨️ Print Report</button>
        </div>
        
        <div class="table-container">
            <div class="table-section">
                <h2>👥 Account Audit Results</h2>
                <table id="accountsTable">
                    <thead>
                        <tr>
                            <th>Account Name</th>
                            <th>Type</th>
                            <th>Current Encryption</th>
                            <th>Risk Level</th>
                            <th>Uses RC4</th>
                            <th>Has AES</th>
                            <th>Has SPN</th>
                            <th>Migration Status</th>
                            <th>Last Logon</th>
                            <th>Password Last Set</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    foreach ($account in $Script:Results) {
        $rc4Icon = if ($account.UsesRC4) { '<span class="check-yes">❌</span>' } else { '<span class="check-no">✅</span>' }
        $aesIcon = if ($account.HasAES) { '<span class="check-yes">✅</span>' } else { '<span class="check-no">❌</span>' }
        $spnIcon = if ($account.HasSPN) { '<span class="check-yes">✅</span>' } else { '<span class="check-no">❌</span>' }
        
        $riskBadge = switch ($account.RiskLevel) {
            'High'   { '<span class="badge badge-high">High</span>' }
            'Medium' { '<span class="badge badge-medium">Medium</span>' }
            'Low'    { '<span class="badge badge-low">Low</span>' }
        }
        
        $statusBadge = switch ($account.MigrationStatus) {
            'Completed'   { '<span class="badge badge-completed">Completed</span>' }
            'Failed'      { '<span class="badge badge-failed">Failed</span>' }
            'Pending'     { '<span class="badge badge-pending">Pending</span>' }
            'Excluded'    { '<span class="badge badge-excluded">Excluded</span>' }
            'Simulated'   { '<span class="badge badge-simulated">Simulated</span>' }
            'Already AES' { '<span class="badge badge-completed">Already AES</span>' }
        }
        
        $lastLogon = if ($account.LastLogon) { $account.LastLogon.ToString('yyyy-MM-dd') } else { 'Never' }
        $pwdLastSet = if ($account.PasswordLastSet) { $account.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Never' }
        
        $html += @"
                        <tr data-risk="$($account.RiskLevel)" data-status="$($account.MigrationStatus)">
                            <td>$($account.SamAccountName)</td>
                            <td>$($account.Type)</td>
                            <td>$($account.CurrentEncryption)</td>
                            <td>$riskBadge</td>
                            <td>$rc4Icon</td>
                            <td>$aesIcon</td>
                            <td>$spnIcon</td>
                            <td>$statusBadge</td>
                            <td>$lastLogon</td>
                            <td>$pwdLastSet</td>
                        </tr>
"@
    }

    $html += @"
                    </tbody>
                </table>
            </div>
            
            <div class="table-section">
                <h2>🖥️ Domain Controller Validation</h2>
                <table id="dcTable">
                    <thead>
                        <tr>
                            <th>DC Name</th>
                            <th>Site</th>
                            <th>Operating System</th>
                            <th>Current Encryption</th>
                            <th>AES128</th>
                            <th>AES256</th>
                            <th>RC4</th>
                            <th>Recommended Action</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    foreach ($dc in $Script:DCValidation) {
        $aes128Icon = if ($dc.SupportsAES128) { '<span class="check-yes">✅</span>' } else { '<span class="check-no">❌</span>' }
        $aes256Icon = if ($dc.SupportsAES256) { '<span class="check-yes">✅</span>' } else { '<span class="check-no">❌</span>' }
        $rc4Icon = if ($dc.SupportsRC4) { '<span class="check-yes">⚠️</span>' } else { '<span class="check-no">❌</span>' }
        
        $html += @"
                        <tr>
                            <td>$($dc.DCName)</td>
                            <td>$($dc.Site)</td>
                            <td>$($dc.OperatingSystem)</td>
                            <td>$($dc.CurrentEncryption)</td>
                            <td>$aes128Icon</td>
                            <td>$aes256Icon</td>
                            <td>$rc4Icon</td>
                            <td>$($dc.RecommendedAction)</td>
                        </tr>
"@
    }

    $html += @"
                    </tbody>
                </table>
            </div>
            
            <div class="table-section">
                <h2>📋 Migration Log</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Level</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    foreach ($log in $Script:MigrationLog | Select-Object -Last 100) {
        $levelColor = switch ($log.Level) {
            'ERROR'   { 'color: #e74c3c; font-weight: bold;' }
            'WARNING' { 'color: #f39c12; font-weight: bold;' }
            'SUCCESS' { 'color: #27ae60; font-weight: bold;' }
            default   { 'color: #34495e;' }
        }
        
        $html += @"
                        <tr>
                            <td>$($log.Timestamp)</td>
                            <td style="$levelColor">$($log.Level)</td>
                            <td>$($log.Message)</td>
                        </tr>
"@
    }

    $html += @"
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by Ollischer IT Consulting - Kerberos Encryption Audit Tool</p>
            <p>For questions or support, contact your system administrator</p>
        </div>
    </div>
    
    <script>
        // Risk Distribution Chart
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: ['High Risk', 'Medium Risk', 'Low Risk'],
                datasets: [{
                    data: [$($riskData.High), $($riskData.Medium), $($riskData.Low)],
                    backgroundColor: ['#e74c3c', '#f39c12', '#27ae60'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
        
        // Encryption Types Chart
        const encCtx = document.getElementById('encryptionChart').getContext('2d');
        new Chart(encCtx, {
            type: 'bar',
            data: {
                labels: ['RC4 Only', 'Mixed (RC4+AES)', 'AES Only'],
                datasets: [{
                    label: 'Number of Accounts',
                    data: [$($encryptionData.RC4Only), $($encryptionData.Mixed), $($encryptionData.AESOnly)],
                    backgroundColor: ['#e74c3c', '#f39c12', '#27ae60'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
        
        // Migration Status Chart
        const migCtx = document.getElementById('migrationChart').getContext('2d');
        new Chart(migCtx, {
            type: 'pie',
            data: {
                labels: ['Completed', 'Pending', 'Failed', 'Excluded', 'Already AES'],
                datasets: [{
                    data: [$($migrationData.Completed), $($migrationData.Pending), $($migrationData.Failed), $($migrationData.Excluded), $($migrationData.AlreadyAES)],
                    backgroundColor: ['#27ae60', '#3498db', '#e74c3c', '#95a5a6', '#2ecc71'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
        
        // Table Filtering
        function filterTable() {
            const searchValue = document.getElementById('searchBox').value.toLowerCase();
            const riskFilter = document.getElementById('riskFilter').value;
            const statusFilter = document.getElementById('statusFilter').value;
            const table = document.getElementById('accountsTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const text = row.textContent.toLowerCase();
                const risk = row.getAttribute('data-risk');
                const status = row.getAttribute('data-status');
                
                let showRow = true;
                
                if (searchValue && !text.includes(searchValue)) {
                    showRow = false;
                }
                
                if (riskFilter && risk !== riskFilter) {
                    showRow = false;
                }
                
                if (statusFilter && status !== statusFilter) {
                    showRow = false;
                }
                
                row.style.display = showRow ? '' : 'none';
            }
        }
        
        // CSV Export
        function exportTableToCSV() {
            const table = document.getElementById('accountsTable');
            const rows = table.querySelectorAll('tr');
            let csv = [];
            
            for (let i = 0; i < rows.length; i++) {
                const row = rows[i];
                const cols = row.querySelectorAll('td, th');
                let csvRow = [];
                
                for (let j = 0; j < cols.length; j++) {
                    let data = cols[j].innerText.replace(/(\r\n|\n|\r)/gm, '').replace(/"/g, '""');
                    csvRow.push('"' + data + '"');
                }
                
                csv.push(csvRow.join(','));
            }
            
            const csvContent = csv.join('\n');
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            
            link.setAttribute('href', url);
            link.setAttribute('download', 'kerberos_audit_$(Get-Date -Format "yyyyMMdd_HHmmss").csv');
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
    </script>
</body>
</html>
"@

    return $html
}

function New-EventLogHTMLReport {
    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $domain = (Get-ADDomain).DNSRoot
    
    # Get summary data
    $usingModern = $Script:EventLogSummary.UsingModernEvents
    $totalRC4Events = $Script:EventLogSummary.TotalRC4Events
    $uniqueAccounts = $Script:EventLogSummary.UniqueAccounts
    $uniqueServices = $Script:EventLogSummary.UniqueServices
    $uniqueClients = $Script:EventLogSummary.UniqueClients
    $currentPhase = $Script:EventLogSummary.CurrentPhase
    
    # Event counts
    $event201 = $Script:EventLogSummary.Event201Count
    $event202 = $Script:EventLogSummary.Event202Count
    $event203 = $Script:EventLogSummary.Event203Count
    $event204 = $Script:EventLogSummary.Event204Count
    $event205 = $Script:EventLogSummary.Event205Count
    $event206 = $Script:EventLogSummary.Event206Count
    $event207 = $Script:EventLogSummary.Event207Count
    $event208 = $Script:EventLogSummary.Event208Count
    $event209 = $Script:EventLogSummary.Event209Count
    
    $criticalTotal = $Script:EventLogSummary.CriticalEvents
    $highTotal = $Script:EventLogSummary.HighSeverityEvents
    $warningTotal = $Script:EventLogSummary.WarningEvents
    
    # Readiness
    $readiness = $Script:EventLogSummary.ReadinessScore
    $readinessColor = if ($readiness -ge 75) { '#27ae60' } 
                     elseif ($readiness -ge 50) { '#f39c12' }
                     elseif ($readiness -ge 25) { '#e67e22' }
                     else { '#c0392b' }
    
    # Helper function for safe JavaScript arrays
    function Get-SafeJSArray {
        param(
            [Parameter(Mandatory=$false)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [array]$Data,
            
            [Parameter(Mandatory=$true)]
            [string]$PropertyName,
            
            [switch]$IsString
        )
        
        # Handle null or empty data
        if ($null -eq $Data -or $Data.Count -eq 0) {
            return ""
        }
        
        $values = @()
        
        foreach ($item in $Data) {
            if ($null -eq $item) { continue }
            
            $value = $item.$PropertyName
            if ($null -eq $value -or $value -eq '') { 
                continue 
            }
            
            # Escape single quotes and backslashes for JavaScript
            $escaped = $value.ToString() -replace "\\", "\\\\" -replace "'", "\'"
            
            if ($IsString) {
                $values += "'$escaped'"
            } else {
                $values += $escaped
            }
        }
        
        if ($values.Count -eq 0) {
            return ""
        }
        
        return $values -join ','
    }

    # Prepare chart data (PowerShell 7.x)
    $topAccountsLabels = Get-SafeJSArray -Data $Script:EventLogSummary.TopAccountsByRC4 -PropertyName 'Account' -IsString
    $topAccountsData = Get-SafeJSArray -Data $Script:EventLogSummary.TopAccountsByRC4 -PropertyName 'Count'
    
    $topServicesLabels = Get-SafeJSArray -Data $Script:EventLogSummary.TopServicesByRC4 -PropertyName 'Service' -IsString
    $topServicesData = Get-SafeJSArray -Data $Script:EventLogSummary.TopServicesByRC4 -PropertyName 'Count'
    
    $topClientsLabels = Get-SafeJSArray -Data $Script:EventLogSummary.TopClientsByRC4 -PropertyName 'ClientIP' -IsString
    $topClientsData = Get-SafeJSArray -Data $Script:EventLogSummary.TopClientsByRC4 -PropertyName 'Count'
    
    $eventIDLabels = Get-SafeJSArray -Data $Script:EventLogSummary.EventIDDistribution -PropertyName 'EventName' -IsString
    $eventIDData = Get-SafeJSArray -Data $Script:EventLogSummary.EventIDDistribution -PropertyName 'Count'
    
    $timelineLabels = Get-SafeJSArray -Data $Script:EventLogSummary.TimelineData -PropertyName 'Hour' -IsString
    $timelineData = Get-SafeJSArray -Data $Script:EventLogSummary.TimelineData -PropertyName 'Count'
    $timelineCritical = Get-SafeJSArray -Data $Script:EventLogSummary.TimelineData -PropertyName 'CriticalCount'
    $timelineHigh = Get-SafeJSArray -Data $Script:EventLogSummary.TimelineData -PropertyName 'HighCount'
    $timelineWarning = Get-SafeJSArray -Data $Script:EventLogSummary.TimelineData -PropertyName 'WarningCount'
    
    # Check data availability
    $hasAccountData = -not [string]::IsNullOrEmpty($topAccountsLabels)
    $hasServiceData = -not [string]::IsNullOrEmpty($topServicesLabels)
    $hasClientData = -not [string]::IsNullOrEmpty($topClientsLabels)
    $hasEventIDData = -not [string]::IsNullOrEmpty($eventIDLabels)
    $hasTimelineData = -not [string]::IsNullOrEmpty($timelineLabels)

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft KB5073381 RC4 Analysis - $domain</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1800px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            text-align: center;
            position: relative;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .kb-badge {
            display: inline-block;
            background: #27ae60;
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            font-weight: bold;
            margin: 15px 0;
            font-size: 1.1em;
        }
        
        .phase-indicator {
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(255,255,255,0.2);
            padding: 10px 20px;
            border-radius: 20px;
            font-size: 0.9em;
        }
        
        .timeline-banner {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 30px;
            border-bottom: 3px solid #667eea;
        }
        
        .timeline-banner h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .timeline {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1200px;
            margin: 0 auto;
            position: relative;
        }
        
        .timeline::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #3498db 0%, #e67e22 50%, #c0392b 100%);
            z-index: 0;
        }
        
        .timeline-item {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            text-align: center;
            position: relative;
            z-index: 1;
            min-width: 200px;
        }
        
        .timeline-item.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            transform: scale(1.1);
        }
        
        .timeline-item h3 {
            font-size: 1.1em;
            margin-bottom: 5px;
        }
        
        .timeline-item .date {
            font-size: 0.9em;
            opacity: 0.8;
        }
        
        .timeline-item .status {
            font-size: 0.85em;
            margin-top: 10px;
            font-weight: bold;
        }
        
        .alert-box {
            padding: 20px;
            margin: 20px 30px;
            border-radius: 8px;
            border-left: 6px solid;
        }
        
        .alert-critical {
            background: #ffebee;
            border-color: #c0392b;
        }
        
        .alert-high {
            background: #fff3cd;
            border-color: #e67e22;
        }
        
        .alert-warning {
            background: #e3f2fd;
            border-color: #3498db;
        }
        
        .alert-info {
            background: #e8f5e9;
            border-color: #27ae60;
        }
        
        .legacy-warning {
            background: #fff3cd;
            border: 2px solid #ffc107;
            border-left: 6px solid #ff9800;
            padding: 20px;
            margin: 20px 30px;
            border-radius: 8px;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card.critical {
            border-left-color: #c0392b;
            background: linear-gradient(135deg, #fff 0%, #ffebee 100%);
        }
        
        .stat-card.high {
            border-left-color: #e67e22;
            background: linear-gradient(135deg, #fff 0%, #fff3e0 100%);
        }
        
        .stat-card.warning {
            border-left-color: #f39c12;
        }
        
        .stat-card.success {
            border-left-color: #27ae60;
            background: linear-gradient(135deg, #fff 0%, #e8f5e9 100%);
        }
        
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
            margin: 10px 0;
        }
        
        .stat-card .label {
            color: #7f8c8d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stat-card .sublabel {
            color: #95a5a6;
            font-size: 0.75em;
            margin-top: 5px;
        }
        
        .readiness-card {
            grid-column: span 2;
            background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%);
            border-left: 6px solid $readinessColor !important;
        }
        
        .readiness-value {
            font-size: 3.5em !important;
            color: $readinessColor !important;
        }
        
        .progress-bar {
            width: 100%;
            height: 30px;
            background: #ecf0f1;
            border-radius: 15px;
            overflow: hidden;
            margin-top: 15px;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, $readinessColor 0%, $(if ($readiness -ge 50) { '#27ae60' } else { '#c0392b' }) 100%);
            width: $readiness%;
            transition: width 1s ease-in-out;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }
        
        .event-legend {
            background: #f8f9fa;
            padding: 25px;
            margin: 20px 30px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .event-legend h3 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.3em;
        }
        
        .legend-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 15px;
        }
        
        .legend-item {
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .legend-badge {
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            min-width: 100px;
            text-align: center;
            white-space: nowrap;
        }
        
        .legend-badge.event-201, .legend-badge.event-202 {
            background: #3498db;
            color: white;
        }
        
        .legend-badge.event-203, .legend-badge.event-204 {
            background: #c0392b;
            color: white;
        }
        
        .legend-badge.event-205 {
            background: #9b59b6;
            color: white;
        }
        
        .legend-badge.event-206, .legend-badge.event-207 {
            background: #e67e22;
            color: white;
        }
        
        .legend-badge.event-208, .legend-badge.event-209 {
            background: #c0392b;
            color: white;
        }
        
        .legend-info {
            flex: 1;
        }
        
        .legend-info strong {
            display: block;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        
        .legend-info small {
            color: #7f8c8d;
            line-height: 1.4;
        }
        
        .transition-arrow {
            color: #e67e22;
            font-weight: bold;
            margin: 0 5px;
        }
        
        .charts-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
            gap: 30px;
            padding: 30px;
        }
        
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .chart-container.full-width {
            grid-column: 1 / -1;
        }
        
        .chart-container h3 {
            margin-bottom: 15px;
            color: #2c3e50;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .controls {
            padding: 20px 30px;
            background: #ecf0f1;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .controls input, .controls select {
            padding: 10px 15px;
            border: 1px solid #bdc3c7;
            border-radius: 5px;
            font-size: 0.95em;
        }
        
        .controls button {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.95em;
            transition: background 0.3s;
        }
        
        .controls button:hover {
            background: #5568d3;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        .table-container {
            padding: 30px;
            overflow-x: auto;
        }
        
        .table-section {
            margin-bottom: 40px;
        }
        
        .table-section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }
        
        th {
            background: #34495e;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
            font-size: 0.9em;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #ecf0f1;
            font-size: 0.9em;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        tr.critical-row {
            background: #ffebee !important;
            border-left: 4px solid #c0392b;
        }
        
        tr.high-row {
            background: #fff3e0 !important;
            border-left: 4px solid #e67e22;
        }
        
        tr.warning-row {
            background: #e3f2fd !important;
        }
        
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge-event-201, .badge-event-202 {
            background: #3498db;
            color: white;
        }
        
        .badge-event-203, .badge-event-204 {
            background: #c0392b;
            color: white;
        }
        
        .badge-event-205 {
            background: #9b59b6;
            color: white;
        }
        
        .badge-event-206, .badge-event-207 {
            background: #e67e22;
            color: white;
        }
        
        .badge-event-208, .badge-event-209 {
            background: #c0392b;
            color: white;
        }
        
        .badge-legacy {
            background: #95a5a6;
            color: white;
        }
        
        .badge-critical {
            background: #c0392b;
            color: white;
        }
        
        .badge-high {
            background: #e67e22;
            color: white;
        }
        
        .badge-warning {
            background: #3498db;
            color: white;
        }
        
        .priority-critical {
            color: #c0392b;
            font-weight: bold;
        }
        
        .priority-high {
            color: #e67e22;
            font-weight: bold;
        }
        
        .priority-medium {
            color: #3498db;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
        }
        
        .footer a {
            color: #3498db;
            text-decoration: none;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
        
        .info-box {
            background: #e8f5e9;
            border-left: 6px solid #27ae60;
            padding: 20px;
            margin: 20px 30px;
            border-radius: 8px;
        }
        
        .info-box h3 {
            color: #2c3e50;
            margin-bottom: 15px;
        }
        
        .info-box ul {
            margin-left: 20px;
            line-height: 2;
        }
        
        .info-box ul li strong {
            color: #c0392b;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            .controls {
                display: none;
            }
        }
        
        @media (max-width: 768px) {
            .timeline {
                flex-direction: column;
                gap: 20px;
            }
            
            .timeline::before {
                display: none;
            }
            
            .legend-grid {
                grid-template-columns: 1fr;
            }
            
            .readiness-card {
                grid-column: span 1;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="phase-indicator">📊 $currentPhase</div>
            <h1>🔐 Microsoft Kerberos RC4 Analysis</h1>
            <div class="subtitle">
                Domain: <strong>$domain</strong><br>
                Generated: <strong>$reportDate</strong><br>
                Analysis Period: <strong>Last $EventLogHours hours</strong>
            </div>
            $(if ($usingModern) {
                '<div class="kb-badge">✅ CVE-2026-20833 Event IDs Active</div>'
            })
        </div>
        
        <div class="timeline-banner">
            <h2>🗓️ Microsoft RC4 Deprecation Timeline</h2>
            <div class="timeline">
                <div class="timeline-item $(if ($currentPhase -like '*Phase 1*') { 'active' })">
                    <h3>Phase 1</h3>
                    <div class="date">January 13, 2026</div>
                    <div class="status">Audit Mode</div>
                </div>
                <div class="timeline-item $(if ($currentPhase -like '*Phase 2*') { 'active' })">
                    <h3>Phase 2</h3>
                    <div class="date">April 2026</div>
                    <div class="status">Enforcement Default</div>
                </div>
                <div class="timeline-item">
                    <h3>Phase 3</h3>
                    <div class="date">July 2026</div>
                    <div class="status">Mandatory Enforcement</div>
                </div>
            </div>
        </div>
        
        $(if (-not $usingModern) {
@"
        <div class="legacy-warning">
            <strong>⚠️ LEGACY MODE ACTIVE - CVE-2026-20833 UPDATE NOT DETECTED</strong><br><br>
            This Domain Controller has not received the <strong>January 2026 security updates</strong> 
            that introduce enhanced RC4 tracking with Event IDs 201-209.<br><br>
            <strong>Required Update:</strong><br>
            • Windows Server 2016: <strong>KB5073722</strong><br>
            • Windows Server 2019: <strong>KB5073723</strong><br>
            • Windows Server 2022: <strong>KB5073457</strong><br>
            • Windows Server 2025: <strong>KB5073458</strong><br><br>
            <strong>Benefits of Updating:</strong><br>
            • Detailed RC4 usage auditing (Events 201-209)<br>
            • Phase-based deployment tracking<br>
            • Enforcement mode simulation<br>
            • Transition warnings before authentication failures<br><br>
            <a href="https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc" target="_blank" style="color: #c0392b; font-weight: bold;">
                📚 KB5073381: How to manage Kerberos KDC usage of RC4
            </a>
        </div>
"@
        })
        
        $(if ($criticalTotal -gt 0) {
@"
        <div class="alert-box alert-critical">
            <strong>🚨 CRITICAL ALERT: RC4 ENFORCEMENT ACTIVE - AUTHENTICATION FAILURES DETECTED</strong><br><br>
            Found <strong>$criticalTotal critical events</strong> (203, 204, 208, 209) indicating RC4 encryption is being <strong>actively denied</strong>.<br>
            Authentication is <strong>FAILING NOW</strong> for affected accounts/services.<br><br>
            <strong>IMMEDIATE ACTION REQUIRED:</strong><br>
            • Event 203/204: Accounts with default config being blocked<br>
            • Event 208/209: Accounts with explicit AES config being blocked<br>
            • Review detailed event table below for affected accounts<br>
            • Enable AES encryption or temporarily allow RC4 via msds-SupportedEncryptionTypes
        </div>
"@
        } elseif ($highTotal -gt 0) {
@"
        <div class="alert-box alert-high">
            <strong>⚠️ HIGH RISK: RC4 USAGE WILL BE DENIED IN ENFORCEMENT MODE</strong><br><br>
            Found <strong>$highTotal high-severity events</strong> (206, 207) indicating these requests <strong>would be denied</strong> if enforcement were active.<br>
            These accounts/services will <strong>FAIL IN APRIL 2026</strong> when Microsoft enables default enforcement.<br><br>
            <strong>URGENT: Migrate to AES before April 2026!</strong><br>
            • Event 206: Clients not advertising AES support<br>
            • Event 207: Services lacking AES keys<br>
            • Current phase allows RC4 but warnings indicate future breakage
        </div>
"@
        } elseif ($warningTotal -gt 0) {
@"
        <div class="alert-box alert-warning">
            <strong>📊 AUDIT MODE: RC4 USAGE DETECTED</strong><br><br>
            Found <strong>$warningTotal audit events</strong> (201, 202, 205) indicating current RC4 usage.<br>
            While currently functional, these should be migrated to AES encryption.<br><br>
            <strong>Recommended Actions:</strong><br>
            • Event 201: Update clients to support AES encryption<br>
            • Event 202: Reset service account passwords to generate AES keys<br>
            • Event 205: Review DefaultDomainSupportedEncTypes policy configuration<br>
            • Plan AES migration before April 2026 enforcement
        </div>
"@
        } else {
@"
        <div class="alert-box alert-info">
            <strong>✅ EXCELLENT: No KB5073381 RC4 Events Detected</strong><br><br>
            Your environment shows no RC4 usage in the analyzed timeframe using the new event IDs.<br>
            This indicates good migration readiness for the Microsoft RC4 deprecation timeline.
        </div>
"@
        })
        
        $(if ($usingModern) {
@"
        <div class="event-legend">
            <h3>📖 Kerberos RC4 Event ID Reference (CVE-2026-20833)</h3>
            <div class="legend-grid">
                <div class="legend-item">
                    <span class="legend-badge event-201">Event 201</span>
                    <div class="legend-info">
                        <strong>Client Only Supports RC4 (Audit)</strong>
                        <small>Client advertising only RC4, service has default encryption config. <span class="transition-arrow">→</span> Transitions to Event 203 in enforcement.</small>
                    </div>
                </div>
                
                <div class="legend-item">
                    <span class="legend-badge event-202">Event 202</span>
                    <div class="legend-info">
                        <strong>Service Only Has RC4 Keys (Audit)</strong>
                        <small>Service account lacks AES keys, has default config. <span class="transition-arrow">→</span> Transitions to Event 204 in enforcement.</small>
                    </div>
                </div>
                
                <div class="legend-item">
                    <span class="legend-badge event-203">Event 203</span>
                    <div class="legend-info">
                        <strong>Blocked - Client RC4 Only (Error)</strong>
                        <small><strong>CRITICAL:</strong> KDC blocked RC4 - client supports only RC4. Authentication FAILING NOW!</small>
                    </div>
                </div>
                
                <div class="legend-item">
                    <span class="legend-badge event-204">Event 204</span>
                    <div class="legend-info">
                        <strong>Blocked - Service RC4 Keys (Error)</strong>
                        <small><strong>CRITICAL:</strong> KDC blocked RC4 - service has only RC4 keys. Authentication FAILING NOW!</small>
                    </div>
                </div>
                
                <div class="legend-item">
                    <span class="legend-badge event-205">Event 205</span>
                    <div class="legend-info">
                        <strong>Insecure DDSET Configuration (Warning)</strong>
                        <small>DefaultDomainSupportedEncTypes includes RC4. Policy recommendation - does not transition to error.</small>
                    </div>
                </div>
                
                <div class="legend-item">
                    <span class="legend-badge event-206">Event 206</span>
                    <div class="legend-info">
                        <strong>Service AES-Only, Client RC4 (Audit)</strong>
                        <small>Service configured for AES-only but client advertises only RC4. <span class="transition-arrow">→</span> Transitions to Event 208 in enforcement.</small>
                    </div>
                </div>
                
                <div class="legend-item">
                    <span class="legend-badge event-207">Event 207</span>
                    <div class="legend-info">
                        <strong>Service AES Config, No AES Keys (Audit)</strong>
                        <small>Service configured for AES but lacks AES keys. <span class="transition-arrow">→</span> Transitions to Event 209 in enforcement.</small>
                    </div>
                </div>
                
                <div class="legend-item">
                    <span class="legend-badge event-208">Event 208</span>
                    <div class="legend-info">
                        <strong>Denied - Client No AES (Error)</strong>
                        <small><strong>CRITICAL:</strong> KDC denied - client does not advertise AES. Authentication FAILING NOW!</small>
                    </div>
                </div>
                
                <div class="legend-item">
                    <span class="legend-badge event-209">Event 209</span>
                    <div class="legend-info">
                        <strong>Denied - Service No AES Keys (Error)</strong>
                        <small><strong>CRITICAL:</strong> KDC denied - service lacks AES keys. Authentication FAILING NOW!</small>
                    </div>
                </div>
            </div>
        </div>
"@
        })
        
        <div class="dashboard">
            <div class="stat-card readiness-card">
                <div class="label">Migration Readiness Score</div>
                <div class="value readiness-value">$readiness%</div>
                <div class="progress-bar">
                    <div class="progress-fill">$readiness%</div>
                </div>
                <div class="sublabel">
                    $(
                        if ($readiness -ge 75) { '✅ Excellent - Minimal RC4 usage' }
                        elseif ($readiness -ge 50) { '⚠️ Fair - Active migration needed' }
                        elseif ($readiness -ge 25) { '🔶 Poor - Urgent action required' }
                        else { '🚨 Critical - Authentication failures occurring' }
                    )
                </div>
            </div>
            
            <div class="stat-card">
                <div class="label">Total RC4 Events</div>
                <div class="value">$totalRC4Events</div>
                <div class="sublabel">Last $EventLogHours hours</div>
            </div>
            
            $(if ($usingModern) {
@"
            <div class="stat-card critical">
                <div class="label">Critical Events</div>
                <div class="value">$criticalTotal</div>
                <div class="sublabel">203, 204, 208, 209 - Failing NOW</div>
            </div>
            
            <div class="stat-card high">
                <div class="label">High Risk Events</div>
                <div class="value">$highTotal</div>
                <div class="sublabel">206, 207 - Will fail in April</div>
            </div>
            
            <div class="stat-card warning">
                <div class="label">Audit Events</div>
                <div class="value">$warningTotal</div>
                <div class="sublabel">201, 202, 205 - Needs migration</div>
            </div>
"@
            })
            
            <div class="stat-card">
                <div class="label">Unique Accounts</div>
                <div class="value">$uniqueAccounts</div>
                <div class="sublabel">Requiring attention</div>
            </div>
            
            <div class="stat-card">
                <div class="label">Unique Services</div>
                <div class="value">$uniqueServices</div>
                <div class="sublabel">Service tickets</div>
            </div>
            
            <div class="stat-card">
                <div class="label">Client IPs</div>
                <div class="value">$uniqueClients</div>
                <div class="sublabel">Source systems</div>
            </div>
        </div>
        
        <div class="charts-section">
            <div class="chart-container full-width">
                <h3>📈 RC4 Usage Timeline$(if ($usingModern -and ($criticalTotal -gt 0 -or $highTotal -gt 0)) { ' with Severity Tracking' })</h3>
                <canvas id="timelineChart"></canvas>
            </div>
            
            $(if ($hasEventIDData -and $usingModern) {
@"
            <div class="chart-container">
                <h3>🎯 Event ID Distribution (KB5073381)</h3>
                <canvas id="eventIDChart"></canvas>
            </div>
"@
            })
            
            <div class="chart-container">
                <h3>👥 Top 10 Accounts Using RC4</h3>
                <canvas id="accountsChart"></canvas>
            </div>
            
            <div class="chart-container">
                <h3>🔧 Top 10 Services Using RC4</h3>
                <canvas id="servicesChart"></canvas>
            </div>
            
            <div class="chart-container">
                <h3>🌐 Top 10 Client IPs Using RC4</h3>
                <canvas id="clientsChart"></canvas>
            </div>
        </div>
        
        <div class="controls">
            <input type="text" id="searchBox" placeholder="🔍 Search events..." onkeyup="filterTable()">
            $(if ($usingModern) {
@"
            <select id="eventIDFilter" onchange="filterTable()">
                <option value="">All Event IDs</option>
                <option value="201">Event 201 - Client RC4 Only (Audit)</option>
                <option value="202">Event 202 - Service RC4 Keys (Audit)</option>
                <option value="203">Event 203 - Blocked Client RC4</option>
                <option value="204">Event 204 - Blocked Service RC4</option>
                <option value="205">Event 205 - Insecure DDSET</option>
                <option value="206">Event 206 - AES Service, RC4 Client</option>
                <option value="207">Event 207 - AES Config, No Keys</option>
                <option value="208">Event 208 - Denied Client No AES</option>
                <option value="209">Event 209 - Denied Service No AES</option>
            </select>
            <select id="severityFilter" onchange="filterTable()">
                <option value="">All Severities</option>
                <option value="Critical">Critical (203,204,208,209)</option>
                <option value="High">High (206,207)</option>
                <option value="Warning">Warning (201,202,205)</option>
            </select>
            <select id="phaseFilter" onchange="filterTable()">
                <option value="">All Phases</option>
                <option value="1">Phase 1 - Audit Mode</option>
                <option value="2">Phase 2 - Enforcement</option>
            </select>
"@
            })
            <select id="dcFilter" onchange="filterTable()">
                <option value="">All Domain Controllers</option>
"@

    # Add DC filter options
    $dcs = $Script:EventLogData | Select-Object -ExpandProperty DomainController -Unique | Sort-Object
    foreach ($dc in $dcs) {
        $html += "                <option value='$dc'>$dc</option>`n"
    }

    $html += @"
            </select>
            <button onclick="exportTableToCSV()">📥 Export to CSV</button>
            <button onclick="window.print()">🖨️ Print Report</button>
        </div>
        
        <div class="table-container">
            <div class="table-section">
                <h2>🔍 Detailed KB5073381 Event Analysis</h2>
                <table id="eventsTable">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>DC</th>
                            <th>Event</th>
                            <th>Severity</th>
                            <th>Account</th>
                            <th>Service</th>
                            <th>Client IP</th>
                            <th>Action Required</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    foreach ($event in $Script:EventLogData | Sort-Object EventSeverity,Timestamp -Descending | Select-Object -First 5000) {
        $timestamp = $event.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')
        $account = if ($event.AccountName) { 
            if ($event.AccountDomain) { "$($event.AccountDomain)\$($event.AccountName)" } 
            else { $event.AccountName }
        } else { 'N/A' }
        $service = if ($event.ServiceName) { $event.ServiceName } else { 'N/A' }
        $clientIP = if ($event.ClientAddress) { $event.ClientAddress } else { 'N/A' }
        
        $eventBadge = switch ($event.EventID) {
            201 { '<span class="badge badge-event-201">Event 201</span>' }
            202 { '<span class="badge badge-event-202">Event 202</span>' }
            203 { '<span class="badge badge-event-203">Event 203</span>' }
            204 { '<span class="badge badge-event-204">Event 204</span>' }
            205 { '<span class="badge badge-event-205">Event 205</span>' }
            206 { '<span class="badge badge-event-206">Event 206</span>' }
            207 { '<span class="badge badge-event-207">Event 207</span>' }
            208 { '<span class="badge badge-event-208">Event 208</span>' }
            209 { '<span class="badge badge-event-209">Event 209</span>' }
            default { '<span class="badge badge-legacy">Legacy</span>' }
        }
        
        $severityBadge = switch ($event.EventSeverity) {
            'Critical' { '<span class="badge badge-critical">Critical</span>' }
            'High' { '<span class="badge badge-high">High</span>' }
            'Warning' { '<span class="badge badge-warning">Warning</span>' }
            default { '<span class="badge badge-warning">Medium</span>' }
        }
        
        $rowClass = switch ($event.EventSeverity) {
            'Critical' { 'critical-row' }
            'High' { 'high-row' }
            'Warning' { 'warning-row' }
            default { '' }
        }
        
        $priorityClass = switch ($event.Priority) {
            'Critical' { 'priority-critical' }
            'High' { 'priority-high' }
            default { 'priority-medium' }
        }
        
        $html += @"
                        <tr class="$rowClass" data-severity="$($event.EventSeverity)" data-eventid="$($event.EventID)" data-phase="$($event.EventPhase)" data-dc="$($event.DomainController)">
                            <td>$timestamp</td>
                            <td>$($event.DomainController)</td>
                            <td>$eventBadge</td>
                            <td>$severityBadge</td>
                            <td>$account</td>
                            <td>$service</td>
                            <td>$clientIP</td>
                            <td class="$priorityClass" style="font-size: 0.85em;">$($event.ActionRequired)</td>
                        </tr>
"@
    }

    $html += @"
                    </tbody>
                </table>
            </div>
            
            <div class="table-section">
                <h2>📊 Top RC4 Offenders$(if ($usingModern) { ' with Priority Ranking' })</h2>
                <h3 style="margin-top: 20px; color: #667eea;">Accounts</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Rank</th>
                            <th>Account Name</th>
                            <th>Event Count</th>
                            $(if ($usingModern) { '<th>Priority</th><th>Status</th>' })
                        </tr>
                    </thead>
                    <tbody>
"@

    $rank = 1
    foreach ($account in $Script:EventLogSummary.TopAccountsByRC4) {
        $priorityBadge = if ($usingModern) {
            switch ($account.HighestPriority) {
                'Critical' { '<span class="badge badge-critical">Critical</span>' }
                'High' { '<span class="badge badge-high">High</span>' }
                default { '<span class="badge badge-warning">Medium</span>' }
            }
        } else { '' }
        
        $statusIcon = if ($account.HasCritical) { '🚨 Auth Failing' }
                     elseif ($account.HasHigh) { '⚠️ Will Fail April 2026' }
                     else { '📋 Needs Migration' }
        
        $html += @"
                        <tr>
                            <td><strong>#$rank</strong></td>
                            <td>$($account.Account)</td>
                            <td>$($account.Count) events</td>
                            $(if ($usingModern) { "<td>$priorityBadge</td><td>$statusIcon</td>" })
                        </tr>
"@
        $rank++
    }

    $html += @"
                    </tbody>
                </table>
                
                $(if ($Script:EventLogSummary.TopServicesByRC4.Count -gt 0) {
@"
                <h3 style="margin-top: 30px; color: #667eea;">Services</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Rank</th>
                            <th>Service Name</th>
                            <th>Event Count</th>
                            $(if ($usingModern) { '<th>Priority</th>' })
                        </tr>
                    </thead>
                    <tbody>
"@
                    $rank = 1
                    foreach ($service in $Script:EventLogSummary.TopServicesByRC4) {
                        $priorityBadge = if ($usingModern) {
                            switch ($service.HighestPriority) {
                                'Critical' { '<span class="badge badge-critical">Critical</span>' }
                                'High' { '<span class="badge badge-high">High</span>' }
                                default { '<span class="badge badge-warning">Medium</span>' }
                            }
                        } else { '' }
                        
                        $html += @"
                        <tr>
                            <td><strong>#$rank</strong></td>
                            <td>$($service.Service)</td>
                            <td>$($service.Count) events</td>
                            $(if ($usingModern) { "<td>$priorityBadge</td>" })
                        </tr>
"@
                        $rank++
                    }
                    $html += @"
                    </tbody>
                </table>
"@
                })
                
                $html += @"
            </div>
        </div>
        
        <div class="info-box">
            <h3>💡 Remediation Steps & Best Practices</h3>
            <ul>
                $(if ($event203 -gt 0 -or $event204 -gt 0) {
                    '<li><strong>CRITICAL - Event 203/204:</strong> Authentication failing NOW! Immediately configure msds-SupportedEncryptionTypes to include AES or temporarily allow RC4 if needed. Reset service passwords to generate AES keys.</li>'
                })
                $(if ($event208 -gt 0 -or $event209 -gt 0) {
                    '<li><strong>CRITICAL - Event 208/209:</strong> Explicit AES configuration blocking RC4 fallback! Update clients to support AES or reset service passwords for AES key generation.</li>'
                })
                $(if ($event206 -gt 0 -or $event207 -gt 0) {
                    '<li><strong>HIGH PRIORITY - Event 206/207:</strong> Will fail in April 2026 when enforcement becomes default! Update clients to advertise AES support and reset service passwords.</li>'
                })
                $(if ($event201 -gt 0) {
                    '<li><strong>Event 201:</strong> Update client systems to support and advertise AES encryption. Configure service accounts with explicit msds-SupportedEncryptionTypes if needed.</li>'
                })
                $(if ($event202 -gt 0) {
                    '<li><strong>Event 202:</strong> Reset service account passwords to generate AES keys. Use: <code>Set-ADAccountPassword</code> or password reset through AD Users and Computers.</li>'
                })
                $(if ($event205 -gt 0) {
                    '<li><strong>Event 205:</strong> Review and update DefaultDomainSupportedEncTypes registry value to remove RC4 support (set to 0x18 for AES-only).</li>'
                })
                $(if (-not $usingModern) {
                    '<li><strong>Update Domain Controllers:</strong> Apply Windows updates released on or after January 13, 2026 (KB5073381) to enable enhanced RC4 tracking.</li>'
                })
                <li><strong>Configure AES Encryption:</strong> Set msds-SupportedEncryptionTypes attribute to 0x18 (AES128 + AES256) or 0x10 (AES256 only) on service accounts.</li>
                <li><strong>Group Policy:</strong> Navigate to <code>Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options → Network security: Configure encryption types allowed for Kerberos</code></li>
                <li><strong>Test Thoroughly:</strong> Use registry value RC4DefaultDisablementPhase=2 to test enforcement mode before April 2026 default change.</li>
                <li><strong>Monitor Continuously:</strong> Review System event log Event IDs 201-209 daily during migration period.</li>
                <li><strong>Documentation:</strong> Track all changes for compliance and audit purposes. Document any exceptions requiring RC4.</li>
            </ul>
        </div>
        
        <div class="footer">
            <p><strong>Generated by Ollischer IT Consulting</strong> - Kerberos RC4 Analysis Tool</p>
            <p>CVE-2026-20833 Compliance | Event IDs 201-209</p>
            <p style="margin-top: 10px;">
                <a href="https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc" target="_blank">📚 KB5073381 Article</a> | 
                <a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20833" target="_blank">🔒 CVE-2026-20833</a> | 
                <a href="https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos" target="_blank">🛠️ RC4 Remediation Guide</a>
            </p>
        </div>
    </div>
    
    <script>
        // Timeline Chart with severity tracking
        const timelineCtx = document.getElementById('timelineChart').getContext('2d');
        $(if ($hasTimelineData) {
            if ($usingModern -and ($criticalTotal -gt 0 -or $highTotal -gt 0)) {
@"
        new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: [$timelineLabels],
                datasets: [
                    {
                        label: 'Critical (203,204,208,209)',
                        data: [$timelineCritical],
                        borderColor: '#c0392b',
                        backgroundColor: 'rgba(192, 57, 43, 0.2)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 5,
                        pointHoverRadius: 7
                    },
                    {
                        label: 'High (206,207)',
                        data: [$timelineHigh],
                        borderColor: '#e67e22',
                        backgroundColor: 'rgba(230, 126, 34, 0.2)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    },
                    {
                        label: 'Warning (201,202,205)',
                        data: [$timelineWarning],
                        borderColor: '#3498db',
                        backgroundColor: 'rgba(52, 152, 219, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 3,
                        pointHoverRadius: 5
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Event Count'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Time (Hourly)'
                        }
                    }
                }
            }
        });
"@
            } else {
@"
        new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: [$timelineLabels],
                datasets: [{
                    label: 'RC4 Events per Hour',
                    data: [$timelineData],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Event Count'
                        }
                    }
                }
            }
        });
"@
            }
        } else {
@"
        timelineCtx.font = '16px Segoe UI';
        timelineCtx.fillStyle = '#7f8c8d';
        timelineCtx.textAlign = 'center';
        timelineCtx.fillText('No timeline data available', timelineCtx.canvas.width / 2, timelineCtx.canvas.height / 2);
"@
        })
        
        $(if ($hasEventIDData -and $usingModern) {
@"
        // Event ID Distribution Chart
        const eventIDCtx = document.getElementById('eventIDChart').getContext('2d');
        new Chart(eventIDCtx, {
            type: 'doughnut',
            data: {
                labels: [$eventIDLabels],
                datasets: [{
                    data: [$eventIDData],
                    backgroundColor: [
                        '#3498db', '#3498db', '#c0392b', '#c0392b',
                        '#9b59b6', '#e67e22', '#e67e22', '#c0392b', '#c0392b'
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            boxWidth: 12,
                            font: {
                                size: 10
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                let label = context.label || '';
                                if (label) {
                                    label += ': ';
                                }
                                label += context.parsed + ' events';
                                return label;
                            }
                        }
                    }
                }
            }
        });
"@
        })
        
        // Top Accounts Chart
        const accountsCtx = document.getElementById('accountsChart').getContext('2d');
        $(if ($hasAccountData) {
@"
        new Chart(accountsCtx, {
            type: 'bar',
            data: {
                labels: [$topAccountsLabels],
                datasets: [{
                    label: 'RC4 Events',
                    data: [$topAccountsData],
                    backgroundColor: '#c0392b',
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Event Count'
                        }
                    }
                }
            }
        });
"@
        } else {
@"
        accountsCtx.font = '16px Segoe UI';
        accountsCtx.fillStyle = '#7f8c8d';
        accountsCtx.textAlign = 'center';
        accountsCtx.fillText('No account data available', accountsCtx.canvas.width / 2, accountsCtx.canvas.height / 2);
"@
        })
        
        // Top Services Chart
        const servicesCtx = document.getElementById('servicesChart').getContext('2d');
        $(if ($hasServiceData) {
@"
        new Chart(servicesCtx, {
            type: 'bar',
            data: {
                labels: [$topServicesLabels],
                datasets: [{
                    label: 'RC4 Events',
                    data: [$topServicesData],
                    backgroundColor: '#e67e22',
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Event Count'
                        }
                    }
                }
            }
        });
"@
        } else {
@"
        servicesCtx.font = '16px Segoe UI';
        servicesCtx.fillStyle = '#7f8c8d';
        servicesCtx.textAlign = 'center';
        servicesCtx.fillText('No service data available', servicesCtx.canvas.width / 2, servicesCtx.canvas.height / 2);
"@
        })
        
        // Top Clients Chart
        const clientsCtx = document.getElementById('clientsChart').getContext('2d');
        $(if ($hasClientData) {
@"
        new Chart(clientsCtx, {
            type: 'bar',
            data: {
                labels: [$topClientsLabels],
                datasets: [{
                    label: 'RC4 Events',
                    data: [$topClientsData],
                    backgroundColor: '#3498db',
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Event Count'
                        }
                    }
                }
            }
        });
"@
        } else {
@"
        clientsCtx.font = '16px Segoe UI';
        clientsCtx.fillStyle = '#7f8c8d';
        clientsCtx.textAlign = 'center';
        clientsCtx.fillText('No client data available', clientsCtx.canvas.width / 2, clientsCtx.canvas.height / 2);
"@
        })
        
        // Table Filtering
        function filterTable() {
            const searchValue = document.getElementById('searchBox').value.toLowerCase();
            const dcFilter = document.getElementById('dcFilter').value;
            const eventIDFilter = document.getElementById('eventIDFilter') ? document.getElementById('eventIDFilter').value : '';
            const severityFilter = document.getElementById('severityFilter') ? document.getElementById('severityFilter').value : '';
            const phaseFilter = document.getElementById('phaseFilter') ? document.getElementById('phaseFilter').value : '';
            const table = document.getElementById('eventsTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const text = row.textContent.toLowerCase();
                const severity = row.getAttribute('data-severity');
                const eventid = row.getAttribute('data-eventid');
                const phase = row.getAttribute('data-phase');
                const dc = row.getAttribute('data-dc');
                
                let showRow = true;
                
                if (searchValue && !text.includes(searchValue)) {
                    showRow = false;
                }
                
                if (severityFilter && severity !== severityFilter) {
                    showRow = false;
                }
                
                if (eventIDFilter && eventid !== eventIDFilter) {
                    showRow = false;
                }
                
                if (phaseFilter && phase !== phaseFilter) {
                    showRow = false;
                }
                
                if (dcFilter && dc !== dcFilter) {
                    showRow = false;
                }
                
                row.style.display = showRow ? '' : 'none';
            }
        }
        
        // CSV Export
        function exportTableToCSV() {
            const table = document.getElementById('eventsTable');
            const rows = table.querySelectorAll('tr');
            let csv = [];
            
            for (let i = 0; i < rows.length; i++) {
                const row = rows[i];
                if (row.style.display !== 'none') {
                    const cols = row.querySelectorAll('td, th');
                    let csvRow = [];
                    
                    for (let j = 0; j < cols.length; j++) {
                        let data = cols[j].innerText.replace(/(\r\n|\n|\r)/gm, '').replace(/"/g, '""');
                        csvRow.push('"' + data + '"');
                    }
                    
                    csv.push(csvRow.join(','));
                }
            }
            
            const csvContent = csv.join('\n');
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            
            link.setAttribute('href', url);
            link.setAttribute('download', 'kb5073381_rc4_analysis_$(Get-Date -Format "yyyyMMdd_HHmmss").csv');
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
    </script>
</body>
</html>
"@

    return $html
}

#endregion

#region Main Execution

try {
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
    Write-Log "  Kerberos Encryption Audit & Event Log Analysis Tool" -Level INFO
    Write-Log "  Ollischer IT Consulting" -Level INFO
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
    Write-Log "" -Level INFO
    
        # Validate prerequisites
    Write-Log "Validating prerequisites..." -Level INFO
    
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "Active Directory PowerShell module is not installed"
    }
    
    Import-Module ActiveDirectory
    
    # Check for required Kerberos security update (CVE-2026-20833)
    Write-Log "" -Level INFO
    Write-Log "Checking for CVE-2026-20833 security updates..." -Level INFO
    $updateStatus = Get-KerberosUpdateStatus
    
    if ($updateStatus.IsInstalled) {
        Write-Log "✅ Security update installed: $($updateStatus.RequiredKB)" -Level SUCCESS
        Write-Log "   Server Version: $($updateStatus.ServerVersion)" -Level INFO
        Write-Log "   Detection Method: $($updateStatus.DetectionMethod)" -Level INFO
        if ($updateStatus.InstallDate) {
            Write-Log "   Install Date: $($updateStatus.InstallDate)" -Level INFO
        }
    } else {
        Write-Log "⚠️ WARNING: Required security update NOT detected!" -Level WARNING
        Write-Log "   Server Version: $($updateStatus.ServerVersion)" -Level WARNING
        Write-Log "   Required Update: $($updateStatus.RequiredKB)" -Level WARNING
        Write-Log "   Event IDs 201-209 may not be available" -Level WARNING
        Write-Log "" -Level WARNING
        Write-Log "   To install the update:" -Level WARNING
        Write-Log "   1. Open Windows Update or WSUS" -Level WARNING
        Write-Log "   2. Search for $($updateStatus.RequiredKB)" -Level WARNING
        Write-Log "   3. Install and reboot" -Level WARNING
        Write-Log "" -Level WARNING
        Write-Log "   Reference: https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc" -Level WARNING
    }
    
    Write-Log "" -Level INFO
    
    # Create export directory if it doesn't exist
    $exportDir = Split-Path -Path $ExportPath -Parent
    if (-not (Test-Path $exportDir)) {
        New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
        Write-Log "Created export directory: $exportDir" -Level INFO
    }
    
    # Execute audit
    Get-RC4Accounts
    
    # Validate Domain Controllers
    Test-DomainControllerEncryption
    
    # Perform migration
    Invoke-EncryptionMigration
    
    # Analyze Event Logs
    Get-KerberosEventLogData
    
    # Generate main report
    Write-Log "Generating main HTML report..." -Level INFO
    $reportHTML = New-HTMLReport
    $reportHTML | Out-File -FilePath $ExportPath -Encoding UTF8
    Write-Log "Main report saved: $ExportPath" -Level SUCCESS
    
    # Generate event log report
    Write-Log "Generating event log HTML report..." -Level INFO
    $eventLogHTML = New-EventLogHTMLReport
    $eventLogHTML | Out-File -FilePath $EventLogReportPath -Encoding UTF8
    Write-Log "Event log report saved: $EventLogReportPath" -Level SUCCESS
    
    Write-Log "═══════════════════════════════════════════════════════════" -Level SUCCESS
    Write-Log "  Reports generated successfully!" -Level SUCCESS
    Write-Log "  Main Report: $ExportPath" -Level SUCCESS
    Write-Log "  Event Log Report: $EventLogReportPath" -Level SUCCESS
    Write-Log "═══════════════════════════════════════════════════════════" -Level SUCCESS
    
    # Display summary
    Write-Log "" -Level INFO
    Write-Log "AUDIT SUMMARY:" -Level INFO
    Write-Log "  Total Accounts Audited: $($Script:Results.Count)" -Level INFO
    Write-Log "  Accounts Using RC4: $(($Script:Results | Where-Object { $_.UsesRC4 }).Count)" -Level INFO
    Write-Log "  High Risk Accounts: $(($Script:Results | Where-Object { $_.RiskLevel -eq 'High' }).Count)" -Level INFO
    
    Write-Log "" -Level INFO
    Write-Log "EVENT LOG SUMMARY:" -Level INFO
    Write-Log "  Total RC4 Events Found: $($Script:EventLogSummary.TotalRC4Events)" -Level WARNING
    Write-Log "  Unique Accounts Using RC4: $($Script:EventLogSummary.UniqueAccounts)" -Level WARNING
    Write-Log "  Unique Services Using RC4: $($Script:EventLogSummary.UniqueServices)" -Level WARNING
    
    if ($DryRun) {
        Write-Log "" -Level INFO
        Write-Log "  Mode: DRY RUN (No changes made)" -Level WARNING
        Write-Log "  To execute migration, run with -DryRun:`$false" -Level WARNING
    } else {
        Write-Log "" -Level INFO
        Write-Log "  Accounts Migrated: $(($Script:Results | Where-Object { $_.MigrationStatus -eq 'Completed' }).Count)" -Level SUCCESS
        Write-Log "  Migration Failures: $(($Script:Results | Where-Object { $_.MigrationStatus -eq 'Failed' }).Count)" -Level WARNING
    }
    
    # Display configuration
    Write-Log "Configuration:" -Level INFO
    Write-Log "  - DryRun Mode: $DryRun" -Level INFO
    Write-Log "  - Target Encryption: $TargetEncryption" -Level INFO
    Write-Log "  - Include Computers: $IncludeComputers" -Level INFO
    Write-Log "  - Export Path: $ExportPath" -Level INFO
    Write-Log "  - Event Log Report Path: $EventLogReportPath" -Level INFO
    Write-Log "  - Event Log Hours: $EventLogHours" -Level INFO
    Write-Log "  - Analyze All DCs: $AnalyzeAllDCs" -Level INFO
    Write-Log "  - Excluded OUs: $($ExcludeOUs -join ', ')" -Level INFO
    Write-Log "  - Security Update Status: $(if ($updateStatus.IsInstalled) { "Installed ($($updateStatus.RequiredKB))" } else { "NOT Installed - $($updateStatus.RequiredKB) required" })" -Level INFO
    Write-Log "" -Level INFO

    # Open reports in default browser
    Write-Log "" -Level INFO
    Write-Log "Opening reports in browser..." -Level INFO
    Start-Process $ExportPath
    Start-Sleep -Seconds 2
    Start-Process $EventLogReportPath
    
} catch {
    Write-Log "CRITICAL ERROR: $_" -Level ERROR
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
    throw
}

#endregion
