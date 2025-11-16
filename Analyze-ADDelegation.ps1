<#
.SYNOPSIS
    Active Directory Delegation Analysis Script
.DESCRIPTION
    Analyzes AD environment for delegation settings on computer and user objects.
    Generates an interactive HTML report with dashboard and charts.
    READ-ONLY - No changes are made to Active Directory.
.NOTES
    Author: Ollischer IT Consulting
    Created: 2025-10-17
    Requires: Active Directory PowerShell Module, Domain Controller execution
.EXAMPLES
    # Custom output path
    .\Analyze-ADDelegation.ps1 -OutputPath "C:\Reports\AD_Delegation.html"

    # Specific domain
    .\Analyze-ADDelegation.ps1 -Domain "contoso.com"

#>

#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$PSScriptRoot\AD_Delegation_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    
    [Parameter(Mandatory=$false)]
    [string]$Domain = $env:USERDNSDOMAIN
)

# Start transcript for logging
$TranscriptPath = "$PSScriptRoot\AD_Delegation_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $TranscriptPath

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "AD Delegation Analysis Script (READ-ONLY)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Domain: $Domain" -ForegroundColor Yellow
Write-Host "Output: $OutputPath" -ForegroundColor Yellow
Write-Host ""

# UserAccountControl flags for delegation
$UAC_TRUSTED_FOR_DELEGATION = 0x80000           # Unconstrained delegation
$UAC_NOT_DELEGATED = 0x100000                   # Account is sensitive and cannot be delegated
$UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 # Protocol transition (constrained delegation with protocol transition)
$UAC_PARTIAL_SECRETS_ACCOUNT = 0x4000000        # RODC

# Collection objects
$DelegationResults = @{
    UnconstrainedDelegation = @()
    ConstrainedDelegation = @()
    ResourceBasedDelegation = @()
    ProtocolTransition = @()
    SensitiveAccounts = @()
    LegacyDelegation = @()
    Statistics = @{
        TotalComputers = 0
        TotalUsers = 0
        UnconstrainedComputers = 0
        UnconstrainedUsers = 0
        ConstrainedComputers = 0
        ConstrainedUsers = 0
        ProtocolTransitionComputers = 0
        ProtocolTransitionUsers = 0
        ResourceBasedComputers = 0
        SensitiveAccounts = 0
        LegacyDelegation = 0
    }
}

#region Functions

function Test-UserAccountControl {
    param(
        [Parameter(Mandatory=$true)]
        [int]$UAC,
        [Parameter(Mandatory=$true)]
        [int]$Flag
    )
    return ($UAC -band $Flag) -ne 0
}

function Get-DelegationType {
    param(
        [Parameter(Mandatory=$true)]
        $Object
    )
    
    $types = @()
    
    if (Test-UserAccountControl -UAC $Object.userAccountControl -Flag $UAC_TRUSTED_FOR_DELEGATION) {
        $types += "Unconstrained"
    }
    
    if ($Object.'msDS-AllowedToDelegateTo' -and $Object.'msDS-AllowedToDelegateTo'.Count -gt 0) {
        $types += "Constrained"
    }
    
    if (Test-UserAccountControl -UAC $Object.userAccountControl -Flag $UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) {
        $types += "Protocol Transition"
    }
    
    if ($Object.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
        $types += "Resource-Based Constrained"
    }
    
    if (Test-UserAccountControl -UAC $Object.userAccountControl -Flag $UAC_NOT_DELEGATED) {
        $types += "Not Delegated (Sensitive)"
    }
    
    return ($types -join ", ")
}

function Get-SPNList {
    param(
        [Parameter(Mandatory=$false)]
        $SPNArray
    )
    
    if ($SPNArray) {
        return ($SPNArray -join "; ")
    }
    return "N/A"
}

#endregion

#region Data Collection

Write-Host "[+] Querying Active Directory..." -ForegroundColor Green

# Properties to retrieve
$Properties = @(
    'Name', 'DistinguishedName', 'ObjectClass', 'userAccountControl', 
    'servicePrincipalName', 'msDS-AllowedToDelegateTo', 
    'msDS-AllowedToActOnBehalfOfOtherIdentity', 'whenCreated', 
    'whenChanged', 'Enabled', 'Description', 'OperatingSystem'
)

# Query all computers
Write-Host "  [*] Analyzing computer objects..." -ForegroundColor Cyan
$AllComputers = Get-ADComputer -Filter * -Properties $Properties -Server $Domain
$DelegationResults.Statistics.TotalComputers = $AllComputers.Count

# Query all users
Write-Host "  [*] Analyzing user objects..." -ForegroundColor Cyan
$AllUsers = Get-ADUser -Filter * -Properties $Properties -Server $Domain
$DelegationResults.Statistics.TotalUsers = $AllUsers.Count

# Combine all objects
$AllObjects = $AllComputers + $AllUsers

Write-Host "  [*] Total objects to analyze: $($AllObjects.Count)" -ForegroundColor Yellow
Write-Host ""

# Analyze each object
$Counter = 0
foreach ($Object in $AllObjects) {
    $Counter++
    if ($Counter % 100 -eq 0) {
        Write-Progress -Activity "Analyzing AD Objects" -Status "Processing $Counter of $($AllObjects.Count)" -PercentComplete (($Counter / $AllObjects.Count) * 100)
    }
    
    $IsComputer = $Object.ObjectClass -eq 'computer'
    $DelegationType = Get-DelegationType -Object $Object
    
    # Skip if no delegation configured
    if ([string]::IsNullOrEmpty($DelegationType)) {
        continue
    }
    
    # Build delegation object
    $DelegationInfo = [PSCustomObject]@{
        Name = $Object.Name
        DistinguishedName = $Object.DistinguishedName
        ObjectType = if ($IsComputer) { "Computer" } else { "User" }
        DelegationType = $DelegationType
        Enabled = $Object.Enabled
        UnconstrainedDelegation = Test-UserAccountControl -UAC $Object.userAccountControl -Flag $UAC_TRUSTED_FOR_DELEGATION
        ConstrainedDelegation = ($Object.'msDS-AllowedToDelegateTo' -and $Object.'msDS-AllowedToDelegateTo'.Count -gt 0)
        ProtocolTransition = Test-UserAccountControl -UAC $Object.userAccountControl -Flag $UAC_TRUSTED_TO_AUTH_FOR_DELEGATION
        ResourceBasedDelegation = [bool]$Object.'msDS-AllowedToActOnBehalfOfOtherIdentity'
        AllowedToDelegateTo = Get-SPNList -SPNArray $Object.'msDS-AllowedToDelegateTo'
        ServicePrincipalNames = Get-SPNList -SPNArray $Object.servicePrincipalName
        Sensitive = Test-UserAccountControl -UAC $Object.userAccountControl -Flag $UAC_NOT_DELEGATED
        WhenCreated = $Object.whenCreated
        WhenChanged = $Object.whenChanged
        Description = $Object.Description
        OperatingSystem = if ($IsComputer) { $Object.OperatingSystem } else { "N/A" }
    }
    
    # Categorize findings
    if ($DelegationInfo.UnconstrainedDelegation) {
        $DelegationResults.UnconstrainedDelegation += $DelegationInfo
        if ($IsComputer) { $DelegationResults.Statistics.UnconstrainedComputers++ }
        else { $DelegationResults.Statistics.UnconstrainedUsers++ }
    }
    
    if ($DelegationInfo.ConstrainedDelegation) {
        $DelegationResults.ConstrainedDelegation += $DelegationInfo
        if ($IsComputer) { $DelegationResults.Statistics.ConstrainedComputers++ }
        else { $DelegationResults.Statistics.ConstrainedUsers++ }
    }
    
    if ($DelegationInfo.ProtocolTransition) {
        $DelegationResults.ProtocolTransition += $DelegationInfo
        if ($IsComputer) { $DelegationResults.Statistics.ProtocolTransitionComputers++ }
        else { $DelegationResults.Statistics.ProtocolTransitionUsers++ }
    }
    
    if ($DelegationInfo.ResourceBasedDelegation) {
        $DelegationResults.ResourceBasedDelegation += $DelegationInfo
        if ($IsComputer) { $DelegationResults.Statistics.ResourceBasedComputers++ }
    }
    
    if ($DelegationInfo.Sensitive) {
        $DelegationResults.SensitiveAccounts += $DelegationInfo
        $DelegationResults.Statistics.SensitiveAccounts++
    }
    
    # Check for legacy/unusual configurations
    if ($DelegationInfo.UnconstrainedDelegation -and $DelegationInfo.ConstrainedDelegation) {
        $DelegationResults.LegacyDelegation += $DelegationInfo
        $DelegationResults.Statistics.LegacyDelegation++
    }
}

Write-Progress -Activity "Analyzing AD Objects" -Completed

Write-Host "[+] Analysis Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Statistics:" -ForegroundColor Yellow
Write-Host "  Total Computers: $($DelegationResults.Statistics.TotalComputers)" -ForegroundColor White
Write-Host "  Total Users: $($DelegationResults.Statistics.TotalUsers)" -ForegroundColor White
Write-Host "  Unconstrained Delegation (Computers): $($DelegationResults.Statistics.UnconstrainedComputers)" -ForegroundColor $(if($DelegationResults.Statistics.UnconstrainedComputers -gt 0){'Red'}else{'Green'})
Write-Host "  Unconstrained Delegation (Users): $($DelegationResults.Statistics.UnconstrainedUsers)" -ForegroundColor $(if($DelegationResults.Statistics.UnconstrainedUsers -gt 0){'Red'}else{'Green'})
Write-Host "  Constrained Delegation (Computers): $($DelegationResults.Statistics.ConstrainedComputers)" -ForegroundColor White
Write-Host "  Constrained Delegation (Users): $($DelegationResults.Statistics.ConstrainedUsers)" -ForegroundColor White
Write-Host "  Protocol Transition (Computers): $($DelegationResults.Statistics.ProtocolTransitionComputers)" -ForegroundColor White
Write-Host "  Protocol Transition (Users): $($DelegationResults.Statistics.ProtocolTransitionUsers)" -ForegroundColor White
Write-Host "  Resource-Based Delegation: $($DelegationResults.Statistics.ResourceBasedComputers)" -ForegroundColor White
Write-Host "  Sensitive Accounts (Cannot be delegated): $($DelegationResults.Statistics.SensitiveAccounts)" -ForegroundColor White
Write-Host "  Legacy/Mixed Delegation: $($DelegationResults.Statistics.LegacyDelegation)" -ForegroundColor $(if($DelegationResults.Statistics.LegacyDelegation -gt 0){'Red'}else{'Green'})
Write-Host ""

#endregion

#region HTML Report Generation

Write-Host "[+] Generating HTML Report..." -ForegroundColor Green

# Convert data to JSON for JavaScript - FIX: Ensure arrays are always arrays
# Using Depth parameter and handling empty/single-item arrays
function ConvertTo-JsonSafe {
    param($Data)
    
    if ($null -eq $Data -or $Data.Count -eq 0) {
        return "[]"
    }
    
    # Force array output even for single items
    if ($Data -is [array]) {
        return ($Data | ConvertTo-Json -Depth 10 -Compress)
    } else {
        # Single item - wrap in array
        return (@($Data) | ConvertTo-Json -Depth 10 -Compress)
    }
}

$UnconstrainedJSON = ConvertTo-JsonSafe -Data $DelegationResults.UnconstrainedDelegation
$ConstrainedJSON = ConvertTo-JsonSafe -Data $DelegationResults.ConstrainedDelegation
$ProtocolTransitionJSON = ConvertTo-JsonSafe -Data $DelegationResults.ProtocolTransition
$ResourceBasedJSON = ConvertTo-JsonSafe -Data $DelegationResults.ResourceBasedDelegation
$SensitiveJSON = ConvertTo-JsonSafe -Data $DelegationResults.SensitiveAccounts
$LegacyJSON = ConvertTo-JsonSafe -Data $DelegationResults.LegacyDelegation
$StatsJSON = $DelegationResults.Statistics | ConvertTo-Json -Depth 5 -Compress

# Debug output to verify JSON is being created
Write-Host "  [*] JSON Data Summary:" -ForegroundColor Cyan
Write-Host "      Unconstrained: $($DelegationResults.UnconstrainedDelegation.Count) items" -ForegroundColor White
Write-Host "      Constrained: $($DelegationResults.ConstrainedDelegation.Count) items" -ForegroundColor White
Write-Host "      Protocol Transition: $($DelegationResults.ProtocolTransition.Count) items" -ForegroundColor White
Write-Host "      Resource-Based: $($DelegationResults.ResourceBasedDelegation.Count) items" -ForegroundColor White
Write-Host "      Sensitive: $($DelegationResults.SensitiveAccounts.Count) items" -ForegroundColor White
Write-Host "      Legacy: $($DelegationResults.LegacyDelegation.Count) items" -ForegroundColor White
Write-Host ""

# HTML Template (JavaScript section needs updating)
$HTMLReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Delegation Analysis Report - $Domain</title>
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
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }
        
        .stat-card h3 {
            font-size: 0.9em;
            color: #666;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .stat-card.danger .number {
            color: #e74c3c;
        }
        
        .stat-card.warning .number {
            color: #f39c12;
        }
        
        .stat-card.success .number {
            color: #27ae60;
        }
        
        .stat-card.info .number {
            color: #3498db;
        }
        
        .charts-section {
            padding: 30px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
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
            font-size: 1.3em;
        }
        
        .tabs {
            background: #ecf0f1;
            padding: 0;
            display: flex;
            flex-wrap: wrap;
            border-bottom: 3px solid #2c3e50;
        }
        
        .tab-button {
            background: transparent;
            border: none;
            padding: 15px 25px;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            color: #555;
            transition: all 0.3s;
            border-bottom: 3px solid transparent;
            margin-bottom: -3px;
        }
        
        .tab-button:hover {
            background: rgba(0,0,0,0.05);
        }
        
        .tab-button.active {
            background: white;
            color: #2c3e50;
            border-bottom-color: #3498db;
        }
        
        .tab-content {
            display: none;
            padding: 30px;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .filter-section {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .filter-section input,
        .filter-section select {
            padding: 10px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 1em;
            flex: 1;
            min-width: 200px;
        }
        
        .filter-section button {
            padding: 10px 20px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1em;
            transition: background 0.3s;
        }
        
        .filter-section button:hover {
            background: #2980b9;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        
        thead {
            background: #2c3e50;
            color: white;
        }
        
        th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #ecf0f1;
        }
        
        tbody tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .badge.computer {
            background: #3498db;
            color: white;
        }
        
        .badge.user {
            background: #9b59b6;
            color: white;
        }
        
        .badge.enabled {
            background: #27ae60;
            color: white;
        }
        
        .badge.disabled {
            background: #e74c3c;
            color: white;
        }
        
        .badge.yes {
            background: #f39c12;
            color: white;
        }
        
        .badge.no {
            background: #95a5a6;
            color: white;
        }
        
        .info-box {
            background: #e8f4f8;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        
        .warning-box {
            background: #fef5e7;
            border-left: 4px solid #f39c12;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        
        .danger-box {
            background: #fadbd8;
            border-left: 4px solid #e74c3c;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }
        
        .no-data {
            text-align: center;
            padding: 40px;
            color: #95a5a6;
            font-size: 1.2em;
        }
        
        .debug-info {
            background: #f0f0f0;
            padding: 10px;
            margin: 10px;
            font-family: monospace;
            font-size: 0.85em;
            border-left: 3px solid #999;
            display: none;
        }
        
        @media print {
            body {
                background: white;
            }
            .container {
                box-shadow: none;
            }
            .tab-button {
                display: none;
            }
            .tab-content {
                display: block !important;
                page-break-before: always;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Active Directory Delegation Analysis</h1>
            <p>Domain: <strong>$Domain</strong> | Generated: <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong></p>
            <p>Ollischer IT Consulting | READ-ONLY Analysis</p>
        </div>
        
        <div class="dashboard">
            <div class="stat-card info">
                <h3>Total Computers</h3>
                <div class="number" id="totalComputers">0</div>
            </div>
            <div class="stat-card info">
                <h3>Total Users</h3>
                <div class="number" id="totalUsers">0</div>
            </div>
            <div class="stat-card danger">
                <h3>Unconstrained (Computers)</h3>
                <div class="number" id="unconstrainedComputers">0</div>
            </div>
            <div class="stat-card danger">
                <h3>Unconstrained (Users)</h3>
                <div class="number" id="unconstrainedUsers">0</div>
            </div>
            <div class="stat-card warning">
                <h3>Constrained (Computers)</h3>
                <div class="number" id="constrainedComputers">0</div>
            </div>
            <div class="stat-card warning">
                <h3>Constrained (Users)</h3>
                <div class="number" id="constrainedUsers">0</div>
            </div>
            <div class="stat-card info">
                <h3>Protocol Transition</h3>
                <div class="number" id="protocolTransition">0</div>
            </div>
            <div class="stat-card success">
                <h3>Sensitive Accounts</h3>
                <div class="number" id="sensitiveAccounts">0</div>
            </div>
        </div>
        
        <div class="charts-section">
            <div class="chart-container">
                <h3>Delegation Types Overview</h3>
                <canvas id="delegationTypesChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Object Types with Delegation</h3>
                <canvas id="objectTypesChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Risk Distribution</h3>
                <canvas id="riskChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Protocol Transition Usage</h3>
                <canvas id="protocolTransitionChart"></canvas>
            </div>
        </div>
        
        <div class="tabs">
            <button class="tab-button active" onclick="openTab(event, 'unconstrainedTab')">Unconstrained Delegation</button>
            <button class="tab-button" onclick="openTab(event, 'constrainedTab')">Constrained Delegation</button>
            <button class="tab-button" onclick="openTab(event, 'protocolTransitionTab')">Protocol Transition</button>
            <button class="tab-button" onclick="openTab(event, 'resourceBasedTab')">Resource-Based</button>
            <button class="tab-button" onclick="openTab(event, 'sensitiveTab')">Sensitive Accounts</button>
            <button class="tab-button" onclick="openTab(event, 'legacyTab')">Legacy/Mixed</button>
        </div>
        
        <div id="unconstrainedTab" class="tab-content active">
            <div class="danger-box">
                <strong>⚠️ Security Risk:</strong> Unconstrained delegation is a significant security risk. Any service with unconstrained delegation can impersonate users to ANY service in the domain. This is a common attack vector (e.g., Kerberos delegation attacks).
            </div>
            <div class="filter-section">
                <input type="text" id="filterUnconstrained" placeholder="Search..." onkeyup="filterTable('unconstrainedTable', 'filterUnconstrained')">
                <select id="filterUnconstrainedType" onchange="filterTable('unconstrainedTable', 'filterUnconstrained')">
                    <option value="">All Types</option>
                    <option value="Computer">Computers</option>
                    <option value="User">Users</option>
                </select>
            </div>
            <div id="unconstrainedContent"></div>
        </div>
        
        <div id="constrainedTab" class="tab-content">
            <div class="info-box">
                <strong>ℹ️ Information:</strong> Constrained delegation allows services to impersonate users only to specific services. This is more secure than unconstrained delegation but still requires careful management.
            </div>
            <div class="filter-section">
                <input type="text" id="filterConstrained" placeholder="Search..." onkeyup="filterTable('constrainedTable', 'filterConstrained')">
                <select id="filterConstrainedType" onchange="filterTable('constrainedTable', 'filterConstrained')">
                    <option value="">All Types</option>
                    <option value="Computer">Computers</option>
                    <option value="User">Users</option>
                </select>
            </div>
            <div id="constrainedContent"></div>
        </div>
        
        <div id="protocolTransitionTab" class="tab-content">
            <div class="warning-box">
                <strong>⚠️ Warning:</strong> Protocol transition (S4U2Self) allows a service to obtain a service ticket to itself on behalf of a user without the user providing credentials. Combined with constrained delegation, this can be powerful but also risky.
            </div>
            <div class="filter-section">
                <input type="text" id="filterProtocol" placeholder="Search..." onkeyup="filterTable('protocolTable', 'filterProtocol')">
            </div>
            <div id="protocolTransitionContent"></div>
        </div>
        
        <div id="resourceBasedTab" class="tab-content">
            <div class="info-box">
                <strong>ℹ️ Information:</strong> Resource-Based Constrained Delegation (RBCD) is configured on the target resource rather than the service account. This provides more granular control.
            </div>
            <div class="filter-section">
                <input type="text" id="filterResource" placeholder="Search..." onkeyup="filterTable('resourceTable', 'filterResource')">
            </div>
            <div id="resourceBasedContent"></div>
        </div>
        
        <div id="sensitiveTab" class="tab-content">
            <div class="info-box">
                <strong>✅ Good Practice:</strong> These accounts are marked as "sensitive and cannot be delegated" - this is a security best practice for privileged accounts.
            </div>
            <div class="filter-section">
                <input type="text" id="filterSensitive" placeholder="Search..." onkeyup="filterTable('sensitiveTable', 'filterSensitive')">
            </div>
            <div id="sensitiveContent"></div>
        </div>
        
        <div id="legacyTab" class="tab-content">
            <div class="danger-box">
                <strong>⚠️ Critical:</strong> These accounts have mixed/conflicting delegation settings (e.g., both unconstrained and constrained). This is unusual and should be reviewed immediately.
            </div>
            <div class="filter-section">
                <input type="text" id="filterLegacy" placeholder="Search..." onkeyup="filterTable('legacyTable', 'filterLegacy')">
            </div>
            <div id="legacyContent"></div>
        </div>
        
        <div class="footer">
            <p>&copy; 2025 Ollischer IT Consulting | Active Directory Security Analysis</p>
            <p>This report is READ-ONLY and makes no changes to Active Directory</p>
        </div>
    </div>
    
    <script>
        // Data from PowerShell - FIXED: Ensure proper parsing
        let unconstrainedData = [];
        let constrainedData = [];
        let protocolTransitionData = [];
        let resourceBasedData = [];
        let sensitiveData = [];
        let legacyData = [];
        let stats = {};
        
        try {
            unconstrainedData = $UnconstrainedJSON;
            if (!Array.isArray(unconstrainedData)) unconstrainedData = [];
        } catch(e) {
            console.error('Error parsing unconstrained data:', e);
            unconstrainedData = [];
        }
        
        try {
            constrainedData = $ConstrainedJSON;
            if (!Array.isArray(constrainedData)) constrainedData = [];
        } catch(e) {
            console.error('Error parsing constrained data:', e);
            constrainedData = [];
        }
        
        try {
            protocolTransitionData = $ProtocolTransitionJSON;
            if (!Array.isArray(protocolTransitionData)) protocolTransitionData = [];
        } catch(e) {
            console.error('Error parsing protocol transition data:', e);
            protocolTransitionData = [];
        }
        
        try {
            resourceBasedData = $ResourceBasedJSON;
            if (!Array.isArray(resourceBasedData)) resourceBasedData = [];
        } catch(e) {
            console.error('Error parsing resource-based data:', e);
            resourceBasedData = [];
        }
        
        try {
            sensitiveData = $SensitiveJSON;
            if (!Array.isArray(sensitiveData)) sensitiveData = [];
        } catch(e) {
            console.error('Error parsing sensitive data:', e);
            sensitiveData = [];
        }
        
        try {
            legacyData = $LegacyJSON;
            if (!Array.isArray(legacyData)) legacyData = [];
        } catch(e) {
            console.error('Error parsing legacy data:', e);
            legacyData = [];
        }
        
        try {
            stats = $StatsJSON;
            if (!stats) stats = {};
        } catch(e) {
            console.error('Error parsing stats:', e);
            stats = {};
        }
        
        // Debug logging
        console.log('Data loaded:', {
            unconstrained: unconstrainedData.length,
            constrained: constrainedData.length,
            protocolTransition: protocolTransitionData.length,
            resourceBased: resourceBasedData.length,
            sensitive: sensitiveData.length,
            legacy: legacyData.length,
            stats: stats
        });
        
        // Update dashboard stats
        document.getElementById('totalComputers').textContent = stats.TotalComputers || 0;
        document.getElementById('totalUsers').textContent = stats.TotalUsers || 0;
        document.getElementById('unconstrainedComputers').textContent = stats.UnconstrainedComputers || 0;
        document.getElementById('unconstrainedUsers').textContent = stats.UnconstrainedUsers || 0;
        document.getElementById('constrainedComputers').textContent = stats.ConstrainedComputers || 0;
        document.getElementById('constrainedUsers').textContent = stats.ConstrainedUsers || 0;
        document.getElementById('protocolTransition').textContent = (stats.ProtocolTransitionComputers || 0) + (stats.ProtocolTransitionUsers || 0);
        document.getElementById('sensitiveAccounts').textContent = stats.SensitiveAccounts || 0;
        
        // Chart.js configurations
        const chartColors = {
            red: 'rgb(231, 76, 60)',
            orange: 'rgb(243, 156, 18)',
            blue: 'rgb(52, 152, 219)',
            green: 'rgb(39, 174, 96)',
            purple: 'rgb(155, 89, 182)',
            gray: 'rgb(149, 165, 166)'
        };
        
        // Delegation Types Chart
        new Chart(document.getElementById('delegationTypesChart'), {
            type: 'doughnut',
            data: {
                labels: ['Unconstrained', 'Constrained', 'Resource-Based', 'Protocol Transition'],
                datasets: [{
                    data: [
                        unconstrainedData.length,
                        constrainedData.length,
                        resourceBasedData.length,
                        protocolTransitionData.length
                    ],
                    backgroundColor: [chartColors.red, chartColors.orange, chartColors.blue, chartColors.purple]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
        
        // Object Types Chart
        new Chart(document.getElementById('objectTypesChart'), {
            type: 'bar',
            data: {
                labels: ['Computers', 'Users'],
                datasets: [
                    {
                        label: 'Unconstrained',
                        data: [stats.UnconstrainedComputers || 0, stats.UnconstrainedUsers || 0],
                        backgroundColor: chartColors.red
                    },
                    {
                        label: 'Constrained',
                        data: [stats.ConstrainedComputers || 0, stats.ConstrainedUsers || 0],
                        backgroundColor: chartColors.orange
                    },
                    {
                        label: 'Protocol Transition',
                        data: [stats.ProtocolTransitionComputers || 0, stats.ProtocolTransitionUsers || 0],
                        backgroundColor: chartColors.purple
                    }
                ]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
        
        // Risk Distribution Chart
        const totalDelegation = unconstrainedData.length + constrainedData.length + resourceBasedData.length;
        const highRisk = unconstrainedData.length;
        const mediumRisk = constrainedData.length + protocolTransitionData.length;
        const lowRisk = resourceBasedData.length;
        
        new Chart(document.getElementById('riskChart'), {
            type: 'pie',
            data: {
                labels: ['High Risk (Unconstrained)', 'Medium Risk (Constrained)', 'Low Risk (Resource-Based)'],
                datasets: [{
                    data: [highRisk, mediumRisk, lowRisk],
                    backgroundColor: [chartColors.red, chartColors.orange, chartColors.green]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
        
        // Protocol Transition Chart
        const withProtocolTransition = protocolTransitionData.length;
        const withoutProtocolTransition = Math.max(0, constrainedData.length - protocolTransitionData.length);
        
        new Chart(document.getElementById('protocolTransitionChart'), {
            type: 'bar',
            data: {
                labels: ['With Protocol Transition', 'Without Protocol Transition'],
                datasets: [{
                    label: 'Accounts',
                    data: [withProtocolTransition, withoutProtocolTransition],
                    backgroundColor: [chartColors.purple, chartColors.gray]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
        
        // Function to create table
        function createTable(data, tableId) {
            if (!data || data.length === 0) {
                return '<div class="no-data">📊 No data found</div>';
            }
            
            let html = '<table id="' + tableId + '"><thead><tr>';
            html += '<th>Name</th><th>Type</th><th>Enabled</th><th>Delegation Type</th>';
            html += '<th>Protocol Transition</th><th>Allowed To Delegate To</th><th>Created</th></tr></thead><tbody>';
            
            data.forEach(item => {
                html += '<tr>';
                html += '<td title="' + (item.DistinguishedName || '') + '">' + (item.Name || '') + '</td>';
                html += '<td><span class="badge ' + (item.ObjectType || '').toLowerCase() + '">' + (item.ObjectType || '') + '</span></td>';
                html += '<td><span class="badge ' + (item.Enabled ? 'enabled' : 'disabled') + '">' + (item.Enabled ? 'Yes' : 'No') + '</span></td>';
                html += '<td>' + (item.DelegationType || '') + '</td>';
                html += '<td><span class="badge ' + (item.ProtocolTransition ? 'yes' : 'no') + '">' + (item.ProtocolTransition ? 'Yes' : 'No') + '</span></td>';
                html += '<td style="max-width:300px; word-wrap:break-word;">' + (item.AllowedToDelegateTo || 'N/A') + '</td>';
                html += '<td>' + (item.WhenCreated ? new Date(item.WhenCreated).toLocaleDateString() : 'N/A') + '</td>';
                html += '</tr>';
            });
            
            html += '</tbody></table>';
            return html;
        }
        
        // Populate tables
        document.getElementById('unconstrainedContent').innerHTML = createTable(unconstrainedData, 'unconstrainedTable');
        document.getElementById('constrainedContent').innerHTML = createTable(constrainedData, 'constrainedTable');
        document.getElementById('protocolTransitionContent').innerHTML = createTable(protocolTransitionData, 'protocolTable');
        document.getElementById('resourceBasedContent').innerHTML = createTable(resourceBasedData, 'resourceTable');
        document.getElementById('sensitiveContent').innerHTML = createTable(sensitiveData, 'sensitiveTable');
        document.getElementById('legacyContent').innerHTML = createTable(legacyData, 'legacyTable');
        
        // Tab switching
        function openTab(evt, tabName) {
            const tabContents = document.getElementsByClassName('tab-content');
            for (let i = 0; i < tabContents.length; i++) {
                tabContents[i].classList.remove('active');
            }
            
            const tabButtons = document.getElementsByClassName('tab-button');
            for (let i = 0; i < tabButtons.length; i++) {
                tabButtons[i].classList.remove('active');
            }
            
            document.getElementById(tabName).classList.add('active');
            evt.currentTarget.classList.add('active');
        }
        
        // Table filtering
        function filterTable(tableId, filterId) {
            const table = document.getElementById(tableId);
            if (!table) return;
            
            const filter = document.getElementById(filterId).value.toUpperCase();
            const typeFilter = document.getElementById(filterId + 'Type');
            const typeValue = typeFilter ? typeFilter.value.toUpperCase() : '';
            
            const tr = table.getElementsByTagName('tr');
            
            for (let i = 1; i < tr.length; i++) {
                let showRow = true;
                const tds = tr[i].getElementsByTagName('td');
                
                // Text filter
                if (filter) {
                    let found = false;
                    for (let j = 0; j < tds.length; j++) {
                        if (tds[j].textContent.toUpperCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) showRow = false;
                }
                
                // Type filter
                if (typeValue && tds[1]) {
                    if (tds[1].textContent.toUpperCase().indexOf(typeValue) === -1) {
                        showRow = false;
                    }
                }
                
                tr[i].style.display = showRow ? '' : 'none';
            }
        }
    </script>
</body>
</html>
"@

# Write HTML to file
$HTMLReport | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "[+] Report generated successfully!" -ForegroundColor Green
Write-Host "    Location: $OutputPath" -ForegroundColor Cyan
Write-Host ""

# Open report in default browser
Write-Host "[+] Opening report in browser..." -ForegroundColor Green
Start-Process $OutputPath

#endregion

# Stop transcript
Stop-Transcript

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Analysis Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Review the HTML report for delegation findings" -ForegroundColor White
Write-Host "  2. Prioritize remediation of unconstrained delegation" -ForegroundColor White
Write-Host "  3. Verify constrained delegation configurations" -ForegroundColor White
Write-Host "  4. Check protocol transition settings for necessity" -ForegroundColor White
Write-Host "  5. Review legacy/mixed delegation configurations" -ForegroundColor White
Write-Host ""
Write-Host "Transcript saved to: $TranscriptPath" -ForegroundColor Cyan
Write-Host ""
