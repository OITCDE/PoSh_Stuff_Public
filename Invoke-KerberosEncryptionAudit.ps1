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

#region Event Log Analysis Functions

function Get-KerberosEventLogData {
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
    Write-Log "  Starting Kerberos Event Log Analysis" -Level INFO
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
    
    $startTime = (Get-Date).AddHours(-$EventLogHours)
    Write-Log "Analyzing events from last $EventLogHours hours (since $startTime)" -Level INFO
    
    # Kerberos event IDs to monitor
    $kerberosEvents = @(
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
    $rc4Events = 0
    
    foreach ($dcName in $dcsToScan) {
        Write-Log "Processing DC: $dcName" -Level INFO
        
        try {
            foreach ($eventId in $kerberosEvents) {
                Write-Log "  Scanning Event ID $eventId on $dcName..." -Level INFO
                
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
                        Write-Log "    Found $($events.Count) events" -Level INFO
                        
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
                                
                                if ($isRC4) {
                                    $rc4Events++
                                }
                                
                                # Only store RC4 events to save memory
                                if ($isRC4) {
                                    $Script:EventLogData += [PSCustomObject]@{
                                        Timestamp           = $event.TimeCreated
                                        DomainController    = $dcName
                                        EventID             = $eventId
                                        EventType           = switch ($eventId) {
                                            4768 { 'TGT Requested' }
                                            4769 { 'Service Ticket Requested' }
                                            4770 { 'Service Ticket Renewed' }
                                            4771 { 'Pre-Auth Failed' }
                                            4772 { 'TGT Request Failed' }
                                        }
                                        AccountName         = $eventData['TargetUserName']
                                        AccountDomain       = $eventData['TargetDomainName']
                                        ServiceName         = $eventData['ServiceName']
                                        ServiceSID          = $eventData['ServiceSid']
                                        ClientAddress       = $eventData['IpAddress']
                                        EncryptionType      = $ticketEncryption
                                        EncryptionName      = $encryptionName
                                        IsRC4               = $isRC4
                                        Status              = $eventData['Status']
                                        FailureCode         = $eventData['FailureCode']
                                    }
                                }
                            }
                        }
                    } else {
                        Write-Log "    No events found" -Level INFO
                    }
                } catch {
                    Write-Log "    Error reading Event ID $eventId from $dcName : $_" -Level WARNING
                }
            }
        } catch {
            Write-Log "Error processing DC $dcName : $_" -Level ERROR
        }
    }
    
    Write-Log "Event log analysis complete!" -Level SUCCESS
    Write-Log "  Total events analyzed: $totalEvents" -Level INFO
    Write-Log "  RC4 events found: $rc4Events" -Level WARNING
    
    # Build summary statistics
    Build-EventLogSummary
}

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
    
    # Get summary data with safe defaults
    $totalRC4Events = $Script:EventLogSummary.TotalRC4Events
    $uniqueAccounts = $Script:EventLogSummary.UniqueAccounts
    $uniqueServices = $Script:EventLogSummary.UniqueServices
    $uniqueClients = $Script:EventLogSummary.UniqueClients
    
    # Helper function to safely build JavaScript arrays
    function Get-SafeJSArray {
        param(
            [Parameter(Mandatory=$true)]
            [AllowEmptyCollection()]
            [array]$Data,
            
            [Parameter(Mandatory=$true)]
            [string]$PropertyName,
            
            [switch]$IsString
        )
        
        if (-not $Data -or $Data.Count -eq 0) {
            return ""
        }
        
        $values = $Data | ForEach-Object { 
            $value = $_.$PropertyName
            if ($null -eq $value -or $value -eq '') { 
                return 
            }
            # Escape single quotes and backslashes for JavaScript
            $escaped = $value -replace "\\", "\\\\" -replace "'", "\'"
            if ($IsString) {
                "'$escaped'"
            } else {
                $escaped
            }
        }
        
        return ($values | Where-Object { $_ }) -join ','
    }
    
    # Prepare chart data with safe defaults
    $topAccountsLabels = Get-SafeJSArray -Data $Script:EventLogSummary.TopAccountsByRC4 -PropertyName 'Account' -IsString
    $topAccountsData = Get-SafeJSArray -Data $Script:EventLogSummary.TopAccountsByRC4 -PropertyName 'Count'
    
    $topServicesLabels = Get-SafeJSArray -Data $Script:EventLogSummary.TopServicesByRC4 -PropertyName 'Service' -IsString
    $topServicesData = Get-SafeJSArray -Data $Script:EventLogSummary.TopServicesByRC4 -PropertyName 'Count'
    
    $topClientsLabels = Get-SafeJSArray -Data $Script:EventLogSummary.TopClientsByRC4 -PropertyName 'ClientIP' -IsString
    $topClientsData = Get-SafeJSArray -Data $Script:EventLogSummary.TopClientsByRC4 -PropertyName 'Count'
    
    $eventTypeLabels = Get-SafeJSArray -Data $Script:EventLogSummary.EventTypeDistribution -PropertyName 'EventType' -IsString
    $eventTypeData = Get-SafeJSArray -Data $Script:EventLogSummary.EventTypeDistribution -PropertyName 'Count'
    
    $timelineLabels = Get-SafeJSArray -Data $Script:EventLogSummary.TimelineData -PropertyName 'Hour' -IsString
    $timelineData = Get-SafeJSArray -Data $Script:EventLogSummary.TimelineData -PropertyName 'Count'
    
    # Check if we have data for charts
    $hasAccountData = -not [string]::IsNullOrEmpty($topAccountsLabels)
    $hasServiceData = -not [string]::IsNullOrEmpty($topServicesLabels)
    $hasClientData = -not [string]::IsNullOrEmpty($topClientsLabels)
    $hasEventTypeData = -not [string]::IsNullOrEmpty($eventTypeLabels)
    $hasTimelineData = -not [string]::IsNullOrEmpty($timelineLabels)

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kerberos RC4 Event Log Analysis - $domain</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3.0.0/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #8e44ad 0%, #c0392b 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #8e44ad 0%, #c0392b 100%);
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
        
        .alert-box {
            background: #fff3cd;
            border: 2px solid #ffc107;
            border-left: 6px solid #ff9800;
            padding: 20px;
            margin: 20px 30px;
            border-radius: 5px;
            font-size: 1.1em;
        }
        
        .alert-box strong {
            color: #c0392b;
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
            border-left: 4px solid #8e44ad;
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card.danger {
            border-left-color: #c0392b;
        }
        
        .stat-card.warning {
            border-left-color: #e67e22;
        }
        
        .stat-card.info {
            border-left-color: #3498db;
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
            border-bottom: 2px solid #8e44ad;
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
            background: #8e44ad;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.95em;
            transition: background 0.3s;
        }
        
        .controls button:hover {
            background: #9b59b6;
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
            border-bottom: 3px solid #8e44ad;
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
        
        .badge-rc4 {
            background: #c0392b;
            color: white;
        }
        
        .badge-tgt {
            background: #3498db;
            color: white;
        }
        
        .badge-service {
            background: #e67e22;
            color: white;
        }
        
        .badge-renewed {
            background: #16a085;
            color: white;
        }
        
        .badge-failed {
            background: #e74c3c;
            color: white;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
        }
        
        .summary-box {
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
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
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 Kerberos RC4 Event Log Analysis</h1>
            <div class="subtitle">
                Domain: <strong>$domain</strong><br>
                Generated: <strong>$reportDate</strong><br>
                Analysis Period: <strong>Last $EventLogHours hours</strong>
            </div>
        </div>
        
        <div class="alert-box">
            <strong>⚠️ SECURITY ALERT:</strong> This report shows accounts actively using RC4 encryption in Kerberos authentication. 
            RC4 is cryptographically weak and should be migrated to AES immediately.
        </div>
        
        <div class="dashboard">
            <div class="stat-card danger">
                <div class="label">Total RC4 Events</div>
                <div class="value">$totalRC4Events</div>
            </div>
            <div class="stat-card warning">
                <div class="label">Unique Accounts</div>
                <div class="value">$uniqueAccounts</div>
            </div>
            <div class="stat-card info">
                <div class="label">Unique Services</div>
                <div class="value">$uniqueServices</div>
            </div>
            <div class="stat-card info">
                <div class="label">Client IPs</div>
                <div class="value">$uniqueClients</div>
            </div>
        </div>
        
        <div class="charts-section">
            <div class="chart-container full-width">
                <h3>📈 RC4 Usage Timeline (Hourly)</h3>
                <canvas id="timelineChart"></canvas>
            </div>
            
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
            
            <div class="chart-container">
                <h3>📊 Event Type Distribution</h3>
                <canvas id="eventTypeChart"></canvas>
            </div>
        </div>
        
        <div class="controls">
            <input type="text" id="searchBox" placeholder="🔍 Search events..." onkeyup="filterTable()">
            <select id="eventTypeFilter" onchange="filterTable()">
                <option value="">All Event Types</option>
                <option value="TGT Requested">TGT Requested</option>
                <option value="Service Ticket Requested">Service Ticket Requested</option>
                <option value="Service Ticket Renewed">Service Ticket Renewed</option>
                <option value="Pre-Auth Failed">Pre-Auth Failed</option>
                <option value="TGT Request Failed">TGT Request Failed</option>
            </select>
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
                <h2>🔍 Detailed RC4 Events</h2>
                <table id="eventsTable">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Domain Controller</th>
                            <th>Event Type</th>
                            <th>Account</th>
                            <th>Service</th>
                            <th>Client IP</th>
                            <th>Encryption</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    foreach ($event in $Script:EventLogData | Sort-Object Timestamp -Descending | Select-Object -First 5000) {
        $timestamp = $event.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')
        $account = if ($event.AccountName) { "$($event.AccountDomain)\$($event.AccountName)" } else { 'N/A' }
        $service = if ($event.ServiceName) { $event.ServiceName } else { 'N/A' }
        $clientIP = if ($event.ClientAddress) { $event.ClientAddress } else { 'N/A' }
        
        $eventBadge = switch ($event.EventType) {
            'TGT Requested'              { '<span class="badge badge-tgt">TGT Requested</span>' }
            'Service Ticket Requested'   { '<span class="badge badge-service">Service Ticket</span>' }
            'Service Ticket Renewed'     { '<span class="badge badge-renewed">Renewed</span>' }
            'Pre-Auth Failed'            { '<span class="badge badge-failed">Pre-Auth Failed</span>' }
            'TGT Request Failed'         { '<span class="badge badge-failed">Failed</span>' }
        }
        
        $html += @"
                        <tr data-eventtype="$($event.EventType)" data-dc="$($event.DomainController)">
                            <td>$timestamp</td>
                            <td>$($event.DomainController)</td>
                            <td>$eventBadge</td>
                            <td>$account</td>
                            <td>$service</td>
                            <td>$clientIP</td>
                            <td><span class="badge badge-rc4">$($event.EncryptionName)</span></td>
                        </tr>
"@
    }

    $html += @"
                    </tbody>
                </table>
            </div>
            
            <div class="table-section">
                <h2>📋 Top Offenders Summary</h2>
                <h3 style="margin-top: 20px; color: #8e44ad;">Accounts with Most RC4 Usage</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Rank</th>
                            <th>Account Name</th>
                            <th>RC4 Event Count</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    $rank = 1
    foreach ($account in $Script:EventLogSummary.TopAccountsByRC4) {
        $html += @"
                        <tr>
                            <td><strong>#$rank</strong></td>
                            <td>$($account.Account)</td>
                            <td><span class="badge badge-rc4">$($account.Count) events</span></td>
                        </tr>
"@
        $rank++
    }

    $html += @"
                    </tbody>
                </table>
                
                <h3 style="margin-top: 30px; color: #8e44ad;">Services with Most RC4 Usage</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Rank</th>
                            <th>Service Name</th>
                            <th>RC4 Event Count</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    $rank = 1
    foreach ($service in $Script:EventLogSummary.TopServicesByRC4) {
        $html += @"
                        <tr>
                            <td><strong>#$rank</strong></td>
                            <td>$($service.Service)</td>
                            <td><span class="badge badge-rc4">$($service.Count) events</span></td>
                        </tr>
"@
        $rank++
    }

    $html += @"
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="summary-box">
            <h3 style="color: #2c3e50; margin-bottom: 10px;">💡 Recommendations</h3>
            <ul style="margin-left: 20px; line-height: 1.8;">
                <li>Immediately investigate the top accounts shown in this report</li>
                <li>Update client applications and services to support AES encryption</li>
                <li>Configure Group Policy to enforce AES encryption types</li>
                <li>Monitor event logs regularly for RC4 usage patterns</li>
                <li>Plan migration timeline for all RC4-dependent accounts and services</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>Generated by Ollischer IT Consulting - Kerberos Event Log Analysis Tool</p>
            <p>For questions or support, contact your system administrator</p>
        </div>
    </div>
    
    <script>
                // Timeline Chart
        const timelineCtx = document.getElementById('timelineChart').getContext('2d');
        $(if ($hasTimelineData) {
@"
        new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: [$timelineLabels],
                datasets: [{
                    label: 'RC4 Events per Hour',
                    data: [$timelineData],
                    borderColor: '#c0392b',
                    backgroundColor: 'rgba(192, 57, 43, 0.1)',
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
                        beginAtZero: true
                    }
                }
            }
        });
"@
        } else {
@"
        timelineCtx.font = '16px Segoe UI';
        timelineCtx.fillStyle = '#7f8c8d';
        timelineCtx.textAlign = 'center';
        timelineCtx.fillText('No timeline data available', timelineCtx.canvas.width / 2, timelineCtx.canvas.height / 2);
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
                        beginAtZero: true
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
                        beginAtZero: true
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
        servicesCtx.fillText('No service ticket data found', servicesCtx.canvas.width / 2, servicesCtx.canvas.height / 2);
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
                        beginAtZero: true
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
        clientsCtx.fillText('No client IP data available', clientsCtx.canvas.width / 2, clientsCtx.canvas.height / 2);
"@
        })
        
        // Event Type Distribution Chart
        const eventTypeCtx = document.getElementById('eventTypeChart').getContext('2d');
        $(if ($hasEventTypeData) {
@"
        new Chart(eventTypeCtx, {
            type: 'doughnut',
            data: {
                labels: [$eventTypeLabels],
                datasets: [{
                    data: [$eventTypeData],
                    backgroundColor: ['#3498db', '#e67e22', '#16a085', '#e74c3c', '#95a5a6'],
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
"@
        } else {
@"
        eventTypeCtx.font = '16px Segoe UI';
        eventTypeCtx.fillStyle = '#7f8c8d';
        eventTypeCtx.textAlign = 'center';
        eventTypeCtx.fillText('No event type data available', eventTypeCtx.canvas.width / 2, eventTypeCtx.canvas.height / 2);
"@
        })
        
        // Table Filtering
        function filterTable() {
            const searchValue = document.getElementById('searchBox').value.toLowerCase();
            const eventTypeFilter = document.getElementById('eventTypeFilter').value;
            const dcFilter = document.getElementById('dcFilter').value;
            const table = document.getElementById('eventsTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const text = row.textContent.toLowerCase();
                const eventType = row.getAttribute('data-eventtype');
                const dc = row.getAttribute('data-dc');
                
                let showRow = true;
                
                if (searchValue && !text.includes(searchValue)) {
                    showRow = false;
                }
                
                if (eventTypeFilter && eventType !== eventTypeFilter) {
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
            link.setAttribute('download', 'kerberos_rc4_events_$(Get-Date -Format "yyyyMMdd_HHmmss").csv');
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
