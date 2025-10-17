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
