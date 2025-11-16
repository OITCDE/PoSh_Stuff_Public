<#
.SYNOPSIS
    Dynamic Active Directory HTML Report for Stale Object Detection with Compliance Checks
.DESCRIPTION
    Generates an interactive HTML report with dashboard, visualizations, filtering,
    and comprehensive compliance checks
.AUTHOR
    Alexander Ollischer - Ollischer IT Consulting
.DATE
    06.11.2025
#>

# Configuration
$StaleUserDays = 90
$StaleComputerDays = 90
$StaleGPODays = 180
$PasswordExpiryWarningDays = 14
$ReportPath = "$PSScriptRoot\AD-StaleObjects-Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$Domain = (Get-ADDomain).DNSRoot

# Ensure output directory exists
$ReportDir = Split-Path -Path $ReportPath -Parent
if (-not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}

Write-Host "Gathering Active Directory data..." -ForegroundColor Cyan

# Calculate cutoff dates
$StaleUserDate = (Get-Date).AddDays(-$StaleUserDays)
$StaleComputerDate = (Get-Date).AddDays(-$StaleComputerDays)
$StaleGPODate = (Get-Date).AddDays(-$StaleGPODays)
$PasswordExpiryDate = (Get-Date).AddDays($PasswordExpiryWarningDays)

# Gather User Data
Write-Host "  - Collecting user accounts..." -ForegroundColor Gray
$Users = Get-ADUser -Filter * -Properties DisplayName, Enabled, LastLogonTimestamp, whenCreated, PasswordLastSet, PasswordNeverExpires, PasswordExpired, AccountExpirationDate, LockedOut, Department, Title, Manager, DistinguishedName, adminCount, CannotChangePassword, DoesNotRequirePreAuth | 
    Select-Object @{N='Name';E={$_.DisplayName}},
                  @{N='SamAccountName';E={$_.SamAccountName}},
                  @{N='Enabled';E={$_.Enabled}},
                  @{N='LastLogon';E={if($_.LastLogonTimestamp){[DateTime]::FromFileTime($_.LastLogonTimestamp)}else{$null}}},
                  @{N='Created';E={$_.whenCreated}},
                  @{N='PasswordLastSet';E={$_.PasswordLastSet}},
                  @{N='PasswordNeverExpires';E={$_.PasswordNeverExpires}},
                  @{N='PasswordExpired';E={$_.PasswordExpired}},
                  @{N='AccountExpirationDate';E={$_.AccountExpirationDate}},
                  @{N='LockedOut';E={$_.LockedOut}},
                  @{N='Department';E={$_.Department}},
                  @{N='Title';E={$_.Title}},
                  @{N='AdminCount';E={$_.adminCount}},
                  @{N='CannotChangePassword';E={$_.CannotChangePassword}},
                  @{N='DoesNotRequirePreAuth';E={$_.DoesNotRequirePreAuth}},
                  @{N='DaysSinceLastLogon';E={if($_.LastLogonTimestamp){((Get-Date) - [DateTime]::FromFileTime($_.LastLogonTimestamp)).Days}else{9999}}},
                  @{N='IsStale';E={if($_.LastLogonTimestamp){([DateTime]::FromFileTime($_.LastLogonTimestamp) -lt $StaleUserDate) -and $_.Enabled}else{$_.Enabled}}},
                  @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}

# Gather Computer Data
Write-Host "  - Collecting computer accounts..." -ForegroundColor Gray
$Computers = Get-ADComputer -Filter * -Properties Name, Enabled, LastLogonTimestamp, whenCreated, OperatingSystem, DistinguishedName |
    Select-Object @{N='Name';E={$_.Name}},
                  @{N='Enabled';E={$_.Enabled}},
                  @{N='LastLogon';E={if($_.LastLogonTimestamp){[DateTime]::FromFileTime($_.LastLogonTimestamp)}else{$null}}},
                  @{N='Created';E={$_.whenCreated}},
                  @{N='OperatingSystem';E={$_.OperatingSystem}},
                  @{N='DaysSinceLastLogon';E={if($_.LastLogonTimestamp){((Get-Date) - [DateTime]::FromFileTime($_.LastLogonTimestamp)).Days}else{9999}}},
                  @{N='IsStale';E={if($_.LastLogonTimestamp){([DateTime]::FromFileTime($_.LastLogonTimestamp) -lt $StaleComputerDate) -and $_.Enabled}else{$_.Enabled}}},
                  @{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}

# Gather GPO Data
Write-Host "  - Collecting Group Policy Objects..." -ForegroundColor Gray
$GPOs = Get-GPO -All | Select-Object DisplayName, 
                               @{N='Created';E={$_.CreationTime}},
                               @{N='Modified';E={$_.ModificationTime}},
                               @{N='DaysSinceModified';E={((Get-Date) - $_.ModificationTime).Days}},
                               @{N='IsStale';E={$_.ModificationTime -lt $StaleGPODate}},
                               @{N='Status';E={$_.GpoStatus}},
                               Id

# Gather Groups
Write-Host "  - Collecting groups..." -ForegroundColor Gray
$Groups = Get-ADGroup -Filter * -Properties whenCreated, Members, ManagedBy |
    Select-Object Name, 
                  @{N='MemberCount';E={($_.Members).Count}},
                  @{N='Created';E={$_.whenCreated}},
                  @{N='ManagedBy';E={$_.ManagedBy}}

# Get Domain Password Policy
Write-Host "  - Collecting password policy..." -ForegroundColor Gray
$DefaultPasswordPolicy = Get-ADDefaultDomainPasswordPolicy

# Gather Compliance Data
Write-Host "  - Performing compliance checks..." -ForegroundColor Gray

# Password Compliance
$PasswordNeverExpires = $Users | Where-Object { $_.PasswordNeverExpires -and $_.Enabled }
$PasswordExpired = $Users | Where-Object { $_.PasswordExpired -and $_.Enabled }
$PasswordNotSet = $Users | Where-Object { $null -eq $_.PasswordLastSet -and $_.Enabled }
$PasswordExpiringSoon = $Users | Where-Object { 
    $_.Enabled -and 
    -not $_.PasswordNeverExpires -and 
    $_.PasswordLastSet -and 
    ($_.PasswordLastSet.AddDays($DefaultPasswordPolicy.MaxPasswordAge.Days) -le $PasswordExpiryDate)
}

# Account Security Compliance
$LockedOutAccounts = $Users | Where-Object { $_.LockedOut }
$AccountsCannotChangePassword = $Users | Where-Object { $_.CannotChangePassword -and $_.Enabled }
$AccountsNoPreAuth = $Users | Where-Object { $_.DoesNotRequirePreAuth -and $_.Enabled }
$PrivilegedAccounts = $Users | Where-Object { $_.AdminCount -eq 1 -and $_.Enabled }
$ExpiredAccounts = $Users | Where-Object { $_.AccountExpirationDate -and $_.AccountExpirationDate -lt (Get-Date) -and $_.Enabled }
$ExpiringAccounts = $Users | Where-Object { 
    $_.AccountExpirationDate -and 
    $_.AccountExpirationDate -gt (Get-Date) -and 
    $_.AccountExpirationDate -le $PasswordExpiryDate -and 
    $_.Enabled
}

# Service Accounts (typically password never expires and might be privileged)
$ServiceAccounts = $Users | Where-Object { 
    $_.Enabled -and 
    $_.PasswordNeverExpires -and 
    ($_.Name -like "*service*" -or $_.Name -like "*svc*" -or $_.SamAccountName -like "svc*")
}

# Dormant Privileged Accounts
$DormantPrivilegedAccounts = $Users | Where-Object {
    $_.AdminCount -eq 1 -and 
    $_.Enabled -and 
    $_.DaysSinceLastLogon -gt 30
}

# Calculate Statistics
Write-Host "  - Calculating statistics..." -ForegroundColor Gray
$Stats = @{
    TotalUsers = $Users.Count
    EnabledUsers = ($Users | Where-Object {$_.Enabled}).Count
    DisabledUsers = ($Users | Where-Object {-not $_.Enabled}).Count
    StaleUsers = ($Users | Where-Object {$_.IsStale}).Count
    NeverLoggedOnUsers = ($Users | Where-Object {$null -eq $_.LastLogon -and $_.Enabled}).Count
    
    TotalComputers = $Computers.Count
    EnabledComputers = ($Computers | Where-Object {$_.Enabled}).Count
    DisabledComputers = ($Computers | Where-Object {-not $_.Enabled}).Count
    StaleComputers = ($Computers | Where-Object {$_.IsStale}).Count
    NeverLoggedOnComputers = ($Computers | Where-Object {$null -eq $_.LastLogon -and $_.Enabled}).Count
    
    TotalGPOs = $GPOs.Count
    StaleGPOs = ($GPOs | Where-Object {$_.IsStale}).Count
    
    TotalGroups = $Groups.Count
    EmptyGroups = ($Groups | Where-Object {$_.MemberCount -eq 0}).Count
    
    # Compliance Stats
    PasswordNeverExpires = $PasswordNeverExpires.Count
    PasswordExpired = $PasswordExpired.Count
    PasswordNotSet = $PasswordNotSet.Count
    PasswordExpiringSoon = $PasswordExpiringSoon.Count
    LockedOutAccounts = $LockedOutAccounts.Count
    CannotChangePassword = $AccountsCannotChangePassword.Count
    NoPreAuthRequired = $AccountsNoPreAuth.Count
    PrivilegedAccounts = $PrivilegedAccounts.Count
    ExpiredAccounts = $ExpiredAccounts.Count
    ExpiringAccounts = $ExpiringAccounts.Count
    ServiceAccounts = $ServiceAccounts.Count
    DormantPrivilegedAccounts = $DormantPrivilegedAccounts.Count
}

# Calculate Compliance Score
$TotalChecks = 12
$FailedChecks = 0
if ($Stats.PasswordNeverExpires -gt 0) { $FailedChecks++ }
if ($Stats.PasswordExpired -gt 0) { $FailedChecks++ }
if ($Stats.PasswordNotSet -gt 0) { $FailedChecks++ }
if ($Stats.PasswordExpiringSoon -gt 10) { $FailedChecks++ }
if ($Stats.LockedOutAccounts -gt 0) { $FailedChecks++ }
if ($Stats.CannotChangePassword -gt 0) { $FailedChecks++ }
if ($Stats.NoPreAuthRequired -gt 0) { $FailedChecks++ }
if ($Stats.ExpiredAccounts -gt 0) { $FailedChecks++ }
if ($Stats.DormantPrivilegedAccounts -gt 0) { $FailedChecks++ }
if ($Stats.StaleUsers -gt ($Stats.TotalUsers * 0.1)) { $FailedChecks++ }
if ($Stats.NeverLoggedOnUsers -gt 5) { $FailedChecks++ }
if ($Stats.ServiceAccounts -gt 0) { $FailedChecks++ }

$ComplianceScore = [math]::Round((($TotalChecks - $FailedChecks) / $TotalChecks) * 100, 1)

# Generate HTML Report
Write-Host "Generating HTML report..." -ForegroundColor Cyan

$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active Directory - Stale Objects & Compliance Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .meta-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-top: 15px;
            font-size: 0.95em;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
            transition: transform 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }
        
        .stat-card.warning {
            border-left-color: #f39c12;
        }
        
        .stat-card.danger {
            border-left-color: #e74c3c;
        }
        
        .stat-card.success {
            border-left-color: #2ecc71;
        }
        
        .stat-card.info {
            border-left-color: #3498db;
        }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin: 10px 0;
        }
        
        .stat-card.warning .stat-value {
            color: #f39c12;
        }
        
        .stat-card.danger .stat-value {
            color: #e74c3c;
        }
        
        .stat-card.success .stat-value {
            color: #2ecc71;
        }
        
        .stat-card.info .stat-value {
            color: #3498db;
        }
        
        .stat-label {
            font-size: 0.95em;
            color: #7f8c8d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .stat-sublabel {
            font-size: 0.85em;
            color: #95a5a6;
            margin-top: 5px;
        }
        
        .section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            font-size: 1.8em;
        }
        
        .filters {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .filter-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .filters label {
            font-weight: 600;
            color: #555;
        }
        
        .filters input, .filters select {
            padding: 10px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 0.95em;
            transition: border-color 0.3s;
        }
        
        .filters input:focus, .filters select:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.95em;
            transition: background 0.3s;
        }
        
        .btn:hover {
            background: #5568d3;
        }
        
        .btn-danger {
            background: #e74c3c;
        }
        
        .btn-danger:hover {
            background: #c0392b;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        thead {
            background: #f8f9fa;
            position: sticky;
            top: 0;
        }
        
        th {
            padding: 15px 10px;
            text-align: left;
            font-weight: 600;
            color: #2c3e50;
            border-bottom: 2px solid #667eea;
            cursor: pointer;
            user-select: none;
        }
        
        th:hover {
            background: #e9ecef;
        }
        
        th.sortable::after {
            content: ' ⇅';
            opacity: 0.5;
        }
        
        th.sort-asc::after {
            content: ' ↑';
            opacity: 1;
        }
        
        th.sort-desc::after {
            content: ' ↓';
            opacity: 1;
        }
        
        td {
            padding: 12px 10px;
            border-bottom: 1px solid #ecf0f1;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .badge-success {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-danger {
            background: #f8d7da;
            color: #721c24;
        }
        
        .badge-warning {
            background: #fff3cd;
            color: #856404;
        }
        
        .badge-info {
            background: #d1ecf1;
            color: #0c5460;
        }
        
        .chart-container {
            margin: 20px 0;
            height: 300px;
            position: relative;
        }
        
        canvas {
            max-height: 300px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .summary-item {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }
        
        .summary-item h3 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .summary-item ul {
            list-style: none;
            padding-left: 0;
        }
        
        .summary-item li {
            padding: 5px 0;
            color: #555;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #e0e0e0;
        }
        
        .tab {
            padding: 12px 24px;
            cursor: pointer;
            background: transparent;
            border: none;
            font-size: 1em;
            color: #666;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }
        
        .tab:hover {
            color: #667eea;
        }
        
        .tab.active {
            color: #667eea;
            border-bottom-color: #667eea;
            font-weight: 600;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
            animation: fadeIn 0.3s;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .table-wrapper {
            overflow-x: auto;
            max-height: 600px;
            overflow-y: auto;
        }
        
        .export-btn {
            float: right;
            margin-bottom: 10px;
        }
        
        .compliance-score {
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
            color: white;
            margin-bottom: 30px;
        }
        
        .compliance-score h3 {
            font-size: 1.5em;
            margin-bottom: 15px;
        }
        
        .score-circle {
            width: 200px;
            height: 200px;
            margin: 0 auto;
            border-radius: 50%;
            background: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3em;
            font-weight: bold;
            color: #667eea;
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
        }
        
        .compliance-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .compliance-item {
            background: white;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
        }
        
        .compliance-item.pass {
            border-left-color: #2ecc71;
        }
        
        .compliance-item.warning {
            border-left-color: #f39c12;
        }
        
        .compliance-item h4 {
            color: #2c3e50;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .compliance-item .count {
            font-size: 2em;
            font-weight: bold;
            color: #e74c3c;
        }
        
        .compliance-item.pass .count {
            color: #2ecc71;
        }
        
        .compliance-item.warning .count {
            color: #f39c12;
        }
        
        .policy-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .policy-info h3 {
            color: #2c3e50;
            margin-bottom: 15px;
        }
        
        .policy-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .policy-item {
            display: flex;
            justify-content: space-between;
            padding: 10px;
            background: white;
            border-radius: 5px;
        }
        
        .policy-label {
            font-weight: 600;
            color: #555;
        }
        
        .policy-value {
            color: #667eea;
            font-weight: bold;
        }
        
        @media print {
            .filters, .btn, .tabs { display: none; }
            .section { page-break-inside: avoid; }
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Active Directory Stale Objects & Compliance Report</h1>
            <p>Comprehensive analysis of AD objects for cleanup, optimization, and compliance</p>
            <div class="meta-info">
                <div>📅 Generated: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')</div>
                <div>🌐 Domain: $Domain</div>
                <div>👤 Generated by: $env:USERNAME</div>
                <div>💼 Company: Ollischer IT Consulting</div>
            </div>
        </header>
        
        <!-- Compliance Score -->
        <div class="compliance-score">
            <h3>🎯 Overall Compliance Score</h3>
            <div class="score-circle">$ComplianceScore%</div>
            <p style="margin-top: 15px; font-size: 1.1em;">Based on $TotalChecks security and compliance checks</p>
        </div>
        
        <!-- Executive Summary -->
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h3>Key Findings</h3>
                    <ul>
                        <li>🎯 <strong>$($Stats.StaleUsers)</strong> stale user accounts detected (>$StaleUserDays days)</li>
                        <li>💻 <strong>$($Stats.StaleComputers)</strong> stale computer accounts detected (>$StaleComputerDays days)</li>
                        <li>📋 <strong>$($Stats.StaleGPOs)</strong> stale GPOs detected (>$StaleGPODays days)</li>
                        <li>⚠️ <strong>$($Stats.NeverLoggedOnUsers)</strong> enabled users never logged on</li>
                    </ul>
                </div>
                <div class="summary-item">
                    <h3>Compliance Issues</h3>
                    <ul>
                        <li>🔑 <strong>$($Stats.PasswordNeverExpires)</strong> accounts with non-expiring passwords</li>
                        <li>🚫 <strong>$($Stats.PasswordExpired)</strong> accounts with expired passwords</li>
                        <li>🔒 <strong>$($Stats.LockedOutAccounts)</strong> locked out accounts</li>
                        <li>👑 <strong>$($Stats.DormantPrivilegedAccounts)</strong> dormant privileged accounts</li>
                    </ul>
                </div>
                <div class="summary-item">
                    <h3>Recommendations</h3>
                    <ul>
                        <li>✓ Review and disable stale user accounts</li>
                        <li>✓ Clean up inactive computer objects</li>
                        <li>✓ Enforce password expiration policies</li>
                        <li>✓ Monitor privileged account usage</li>
                        <li>✓ Schedule regular compliance audits</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <!-- Dashboard -->
        <div class="section">
            <h2>📈 Dashboard Overview</h2>
            <div class="dashboard">
                <div class="stat-card">
                    <div class="stat-label">Total Users</div>
                    <div class="stat-value">$($Stats.TotalUsers)</div>
                    <div class="stat-sublabel">$($Stats.EnabledUsers) Enabled • $($Stats.DisabledUsers) Disabled</div>
                </div>
                
                <div class="stat-card danger">
                    <div class="stat-label">Stale Users</div>
                    <div class="stat-value">$($Stats.StaleUsers)</div>
                    <div class="stat-sublabel">Inactive for >$StaleUserDays days</div>
                </div>
                
                <div class="stat-card warning">
                    <div class="stat-label">Never Logged On Users</div>
                    <div class="stat-value">$($Stats.NeverLoggedOnUsers)</div>
                    <div class="stat-sublabel">Enabled accounts without logon</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-label">Total Computers</div>
                    <div class="stat-value">$($Stats.TotalComputers)</div>
                    <div class="stat-sublabel">$($Stats.EnabledComputers) Enabled • $($Stats.DisabledComputers) Disabled</div>
                </div>
                
                <div class="stat-card danger">
                    <div class="stat-label">Stale Computers</div>
                    <div class="stat-value">$($Stats.StaleComputers)</div>
                    <div class="stat-sublabel">Inactive for >$StaleComputerDays days</div>
                </div>
                
                <div class="stat-card warning">
                    <div class="stat-label">Password Issues</div>
                    <div class="stat-value">$($Stats.PasswordNeverExpires)</div>
                    <div class="stat-sublabel">Non-expiring passwords</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-label">Group Policies</div>
                    <div class="stat-value">$($Stats.TotalGPOs)</div>
                    <div class="stat-sublabel">$($Stats.StaleGPOs) not modified in $StaleGPODays days</div>
                </div>
                
                <div class="stat-card success">
                    <div class="stat-label">AD Groups</div>
                    <div class="stat-value">$($Stats.TotalGroups)</div>
                    <div class="stat-sublabel">$($Stats.EmptyGroups) empty groups</div>
                </div>
            </div>
            
            <div class="chart-container">
                <canvas id="overviewChart"></canvas>
            </div>
        </div>
        
        <!-- Tabs for different object types -->
        <div class="section">
            <div class="tabs">
                <button class="tab active" onclick="switchTab(event, 'users')">👤 User Accounts</button>
                <button class="tab" onclick="switchTab(event, 'computers')">💻 Computer Accounts</button>
                <button class="tab" onclick="switchTab(event, 'gpos')">📋 Group Policies</button>
                <button class="tab" onclick="switchTab(event, 'groups')">👥 Groups</button>
                <button class="tab" onclick="switchTab(event, 'compliance')">🔒 Compliance</button>
            </div>
            
            <!-- Users Tab -->
            <div id="users-tab" class="tab-content active">
                <h2>👤 User Accounts Analysis</h2>
                <button class="btn export-btn" onclick="exportTableToCSV('users-table', 'AD-Users.csv')">Export to CSV</button>
                <div class="filters">
                    <div class="filter-group">
                        <label>Search:</label>
                        <input type="text" id="userSearch" placeholder="Search users..." oninput="filterTable('users')">
                    </div>
                    <div class="filter-group">
                        <label>Status:</label>
                        <select id="userStatus" onchange="filterTable('users')">
                            <option value="all">All Users</option>
                            <option value="enabled">Enabled Only</option>
                            <option value="disabled">Disabled Only</option>
                            <option value="stale">Stale Only</option>
                            <option value="neverloggedon">Never Logged On</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Days Inactive:</label>
                        <input type="number" id="userDays" placeholder="e.g., 90" oninput="filterTable('users')" style="width: 100px;">
                    </div>
                    <button class="btn" onclick="resetFilters('users')">Reset Filters</button>
                </div>
                
                <div class="table-wrapper">
                    <table id="users-table">
                        <thead>
                            <tr>
                                <th class="sortable" onclick="sortTable('users-table', 0)">Name</th>
                                <th class="sortable" onclick="sortTable('users-table', 1)">Username</th>
                                <th class="sortable" onclick="sortTable('users-table', 2)">Status</th>
                                <th class="sortable" onclick="sortTable('users-table', 3)">Last Logon</th>
                                <th class="sortable" onclick="sortTable('users-table', 4)">Days Inactive</th>
                                <th class="sortable" onclick="sortTable('users-table', 5)">Department</th>
                                <th class="sortable" onclick="sortTable('users-table', 6)">Title</th>
                                <th class="sortable" onclick="sortTable('users-table', 7)">Created</th>
                                <th class="sortable" onclick="sortTable('users-table', 8)">Password Last Set</th>
                                <th>Stale</th>
                            </tr>
                        </thead>
                        <tbody>
"@

# Add user rows
foreach ($User in $Users) {
    $statusBadge = if ($User.Enabled) { "<span class='badge badge-success'>Enabled</span>" } else { "<span class='badge badge-danger'>Disabled</span>" }
    $staleBadge = if ($User.IsStale) { "<span class='badge badge-danger'>Yes</span>" } else { "<span class='badge badge-success'>No</span>" }
    $lastLogon = if ($User.LastLogon) { $User.LastLogon.ToString('dd.MM.yyyy HH:mm') } else { "Never" }
    $created = if ($User.Created) { $User.Created.ToString('dd.MM.yyyy') } else { "N/A" }
    $pwdSet = if ($User.PasswordLastSet) { $User.PasswordLastSet.ToString('dd.MM.yyyy') } else { "Never" }
    
    # Convert to lowercase strings for JavaScript
    $enabledStr = if ($User.Enabled) { "true" } else { "false" }
    $staleStr = if ($User.IsStale) { "true" } else { "false" }
    $neverLoggedOn = if ($User.DaysSinceLastLogon -eq 9999) { "true" } else { "false" }
    
    $HTML += @"
                            <tr data-enabled="$enabledStr" data-stale="$staleStr" data-days="$($User.DaysSinceLastLogon)" data-neverloggedon="$neverLoggedOn">
                                <td>$($User.Name)</td>
                                <td>$($User.SamAccountName)</td>
                                <td>$statusBadge</td>
                                <td>$lastLogon</td>
                                <td>$($User.DaysSinceLastLogon)</td>
                                <td>$($User.Department)</td>
                                <td>$($User.Title)</td>
                                <td>$created</td>
                                <td>$pwdSet</td>
                                <td>$staleBadge</td>
                            </tr>
"@
}

$HTML += @"
                        </tbody>
                    </table>
                </div>
                <div class="chart-container">
                    <canvas id="usersChart"></canvas>
                </div>
            </div>
            
            <!-- Computers Tab -->
            <div id="computers-tab" class="tab-content">
                <h2>💻 Computer Accounts Analysis</h2>
                <button class="btn export-btn" onclick="exportTableToCSV('computers-table', 'AD-Computers.csv')">Export to CSV</button>
                <div class="filters">
                    <div class="filter-group">
                        <label>Search:</label>
                        <input type="text" id="computerSearch" placeholder="Search computers..." oninput="filterTable('computers')">
                    </div>
                    <div class="filter-group">
                        <label>Status:</label>
                        <select id="computerStatus" onchange="filterTable('computers')">
                            <option value="all">All Computers</option>
                            <option value="enabled">Enabled Only</option>
                            <option value="disabled">Disabled Only</option>
                            <option value="stale">Stale Only</option>
                            <option value="neverloggedon">Never Logged On</option>
                            <option value="passwordstale">Stale Password</option>
                            <option value="legacyos">Legacy OS</option>
                            <option value="delegation">Trusted for Delegation</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Operating System:</label>
                        <select id="computerOperatingSystem" onchange="filterTable('computers')">
                            <option value="all">All Operating Systems</option>
"@

# Generate OS options dynamically from the data
foreach ($OS in $OSDistribution) {
    $HTML += "                            <option value='$($OS.OS)'>$($OS.OS) ($($OS.Count))</option>`n"
}

$HTML += @"
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Days Inactive:</label>
                        <input type="number" id="computerDays" placeholder="e.g., 90" oninput="filterTable('computers')" style="width: 100px;">
                    </div>
                    <button class="btn" onclick="resetFilters('computers')">Reset Filters</button>
                </div>

                <div class="table-wrapper">
                    <table id="computers-table">
                        <thead>
                            <tr>
                                <th class="sortable" onclick="sortTable('computers-table', 0)">Computer Name</th>
                                <th class="sortable" onclick="sortTable('computers-table', 1)">Status</th>
                                <th class="sortable" onclick="sortTable('computers-table', 2)">Last Logon</th>
                                <th class="sortable" onclick="sortTable('computers-table', 3)">Days Inactive</th>
                                <th class="sortable" onclick="sortTable('computers-table', 4)">Operating System</th>
                                <th class="sortable" onclick="sortTable('computers-table', 5)">Created</th>
                                <th>Stale</th>
                            </tr>
                        </thead>
                        <tbody>
"@

# Add computer rows
foreach ($Computer in $Computers) {
    $statusBadge = if ($Computer.Enabled) { "<span class='badge badge-success'>Enabled</span>" } else { "<span class='badge badge-danger'>Disabled</span>" }
    $staleBadge = if ($Computer.IsStale) { "<span class='badge badge-danger'>Yes</span>" } else { "<span class='badge badge-success'>No</span>" }
    $lastLogon = if ($Computer.LastLogon) { $Computer.LastLogon.ToString('dd.MM.yyyy HH:mm') } else { "Never" }
    $created = if ($Computer.Created) { $Computer.Created.ToString('dd.MM.yyyy') } else { "N/A" }
    
    # Convert to lowercase strings for JavaScript
    $enabledStr = if ($Computer.Enabled) { "true" } else { "false" }
    $staleStr = if ($Computer.IsStale) { "true" } else { "false" }
    $neverLoggedOn = if ($Computer.DaysSinceLastLogon -eq 9999) { "true" } else { "false" }
    
    $HTML += @"
                            <tr data-enabled="$enabledStr" data-stale="$staleStr" data-days="$($Computer.DaysSinceLastLogon)" data-neverloggedon="$neverLoggedOn">
                                <td>$($Computer.Name)</td>
                                <td>$statusBadge</td>
                                <td>$lastLogon</td>
                                <td>$($Computer.DaysSinceLastLogon)</td>
                                <td>$($Computer.OperatingSystem)</td>
                                <td>$created</td>
                                <td>$staleBadge</td>
                            </tr>
"@
}

$HTML += @"
                        </tbody>
                    </table>
                </div>
                <div class="chart-container">
                    <canvas id="computersChart"></canvas>
                </div>
            </div>
            
            <!-- GPOs Tab -->
            <div id="gpos-tab" class="tab-content">
                <h2>📋 Group Policy Objects Analysis</h2>
                <button class="btn export-btn" onclick="exportTableToCSV('gpos-table', 'AD-GPOs.csv')">Export to CSV</button>
                <div class="filters">
                    <div class="filter-group">
                        <label>Search:</label>
                        <input type="text" id="gpoSearch" placeholder="Search GPOs..." oninput="filterTable('gpos')">
                    </div>
                    <div class="filter-group">
                        <label>Filter:</label>
                        <select id="gpoStatus" onchange="filterTable('gpos')">
                            <option value="all">All GPOs</option>
                            <option value="stale">Stale Only (>$StaleGPODays days)</option>
                        </select>
                    </div>
                    <button class="btn" onclick="resetFilters('gpos')">Reset Filters</button>
                </div>
                
                <div class="table-wrapper">
                    <table id="gpos-table">
                        <thead>
                            <tr>
                                <th class="sortable" onclick="sortTable('gpos-table', 0)">GPO Name</th>
                                <th class="sortable" onclick="sortTable('gpos-table', 1)">Created</th>
                                <th class="sortable" onclick="sortTable('gpos-table', 2)">Last Modified</th>
                                <th class="sortable" onclick="sortTable('gpos-table', 3)">Days Since Modified</th>
                                <th class="sortable" onclick="sortTable('gpos-table', 4)">Status</th>
                                <th>Stale</th>
                            </tr>
                        </thead>
                        <tbody>
"@

# Add GPO rows
foreach ($GPO in $GPOs) {
    $staleBadge = if ($GPO.IsStale) { "<span class='badge badge-warning'>Yes</span>" } else { "<span class='badge badge-success'>No</span>" }
    $created = $GPO.Created.ToString('dd.MM.yyyy')
    $modified = $GPO.Modified.ToString('dd.MM.yyyy HH:mm')
    
    # Convert to lowercase strings for JavaScript
    $staleStr = if ($GPO.IsStale) { "true" } else { "false" }
    
    $HTML += @"
                            <tr data-stale="$staleStr" data-days="$($GPO.DaysSinceModified)">
                                <td>$($GPO.DisplayName)</td>
                                <td>$created</td>
                                <td>$modified</td>
                                <td>$($GPO.DaysSinceModified)</td>
                                <td>$($GPO.Status)</td>
                                <td>$staleBadge</td>
                            </tr>
"@
}

$HTML += @"
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Groups Tab -->
            <div id="groups-tab" class="tab-content">
                <h2>👥 Groups Analysis</h2>
                <button class="btn export-btn" onclick="exportTableToCSV('groups-table', 'AD-Groups.csv')">Export to CSV</button>
                <div class="filters">
                    <div class="filter-group">
                        <label>Search:</label>
                        <input type="text" id="groupSearch" placeholder="Search groups..." oninput="filterTable('groups')">
                    </div>
                    <div class="filter-group">
                        <label>Filter:</label>
                        <select id="groupStatus" onchange="filterTable('groups')">
                            <option value="all">All Groups</option>
                            <option value="empty">Empty Groups Only</option>
                        </select>
                    </div>
                    <button class="btn" onclick="resetFilters('groups')">Reset Filters</button>
                </div>
                
                <div class="table-wrapper">
                    <table id="groups-table">
                        <thead>
                            <tr>
                                <th class="sortable" onclick="sortTable('groups-table', 0)">Group Name</th>
                                <th class="sortable" onclick="sortTable('groups-table', 1)">Member Count</th>
                                <th class="sortable" onclick="sortTable('groups-table', 2)">Created</th>
                                <th class="sortable" onclick="sortTable('groups-table', 3)">Managed By</th>
                            </tr>
                        </thead>
                        <tbody>
"@

# Add group rows
foreach ($Group in $Groups) {
    $created = if ($Group.Created) { $Group.Created.ToString('dd.MM.yyyy') } else { "N/A" }
    $managedBy = if ($Group.ManagedBy) { $Group.ManagedBy -replace '^CN=([^,]+),.*','$1' } else { "N/A" }
    
    $HTML += @"
                            <tr data-members="$($Group.MemberCount)">
                                <td>$($Group.Name)</td>
                                <td>$($Group.MemberCount)</td>
                                <td>$created</td>
                                <td>$managedBy</td>
                            </tr>
"@
}

$HTML += @"
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Compliance Tab -->
            <div id="compliance-tab" class="tab-content">
                <h2>🔒 Security & Compliance Checks</h2>
                
                <!-- Domain Password Policy -->
                <div class="policy-info">
                    <h3>📋 Domain Password Policy</h3>
                    <div class="policy-grid">
                        <div class="policy-item">
                            <span class="policy-label">Min Password Length:</span>
                            <span class="policy-value">$($DefaultPasswordPolicy.MinPasswordLength) characters</span>
                        </div>
                        <div class="policy-item">
                            <span class="policy-label">Password History:</span>
                            <span class="policy-value">$($DefaultPasswordPolicy.PasswordHistoryCount) passwords</span>
                        </div>
                        <div class="policy-item">
                            <span class="policy-label">Max Password Age:</span>
                            <span class="policy-value">$($DefaultPasswordPolicy.MaxPasswordAge.Days) days</span>
                        </div>
                        <div class="policy-item">
                            <span class="policy-label">Min Password Age:</span>
                            <span class="policy-value">$($DefaultPasswordPolicy.MinPasswordAge.Days) days</span>
                        </div>
                        <div class="policy-item">
                            <span class="policy-label">Lockout Threshold:</span>
                            <span class="policy-value">$($DefaultPasswordPolicy.LockoutThreshold) attempts</span>
                        </div>
                        <div class="policy-item">
                            <span class="policy-label">Lockout Duration:</span>
                            <span class="policy-value">$($DefaultPasswordPolicy.LockoutDuration.Minutes) minutes</span>
                        </div>
                        <div class="policy-item">
                            <span class="policy-label">Complexity Required:</span>
                            <span class="policy-value">$($DefaultPasswordPolicy.ComplexityEnabled)</span>
                        </div>
                        <div class="policy-item">
                            <span class="policy-label">Reversible Encryption:</span>
                            <span class="policy-value">$($DefaultPasswordPolicy.ReversibleEncryptionEnabled)</span>
                        </div>
                    </div>
                </div>
                
                <!-- Compliance Checks -->
                <h3 style="margin-top: 30px; margin-bottom: 20px;">🎯 Compliance Check Results</h3>
                <div class="compliance-grid">
                    <div class="compliance-item $(if ($Stats.PasswordNeverExpires -eq 0) { 'pass' } else { 'danger' })">
                        <h4>🔑 Password Never Expires</h4>
                        <div class="count">$($Stats.PasswordNeverExpires)</div>
                        <p>Enabled accounts with non-expiring passwords pose a security risk</p>
                    </div>
                    
                    <div class="compliance-item $(if ($Stats.PasswordExpired -eq 0) { 'pass' } else { 'danger' })">
                        <h4>🚫 Expired Passwords</h4>
                        <div class="count">$($Stats.PasswordExpired)</div>
                        <p>Active accounts with expired passwords should be reviewed</p>
                    </div>
                    
                    <div class="compliance-item $(if ($Stats.PasswordNotSet -eq 0) { 'pass' } else { 'danger' })">
                        <h4>❌ Password Not Set</h4>
                        <div class="count">$($Stats.PasswordNotSet)</div>
                        <p>Enabled accounts without passwords set</p>
                    </div>
                    
                    <div class="compliance-item $(if ($Stats.PasswordExpiringSoon -le 10) { 'pass' } else { 'warning' })">
                        <h4>⏰ Password Expiring Soon</h4>
                        <div class="count">$($Stats.PasswordExpiringSoon)</div>
                        <p>Passwords expiring within $PasswordExpiryWarningDays days</p>
                    </div>
                    
                    <div class="compliance-item $(if ($Stats.LockedOutAccounts -eq 0) { 'pass' } else { 'warning' })">
                        <h4>🔒 Locked Out Accounts</h4>
                        <div class="count">$($Stats.LockedOutAccounts)</div>
                        <p>Currently locked out user accounts</p>
                    </div>
                    
                    <div class="compliance-item $(if ($Stats.CannotChangePassword -eq 0) { 'pass' } else { 'warning' })">
                        <h4>🚷 Cannot Change Password</h4>
                        <div class="count">$($Stats.CannotChangePassword)</div>
                        <p>Users restricted from changing their own passwords</p>
                    </div>
                    
                    <div class="compliance-item $(if ($Stats.NoPreAuthRequired -eq 0) { 'pass' } else { 'danger' })">
                        <h4>⚠️ No Pre-Auth Required</h4>
                        <div class="count">$($Stats.NoPreAuthRequired)</div>
                        <p>Kerberos pre-authentication disabled (AS-REP Roasting risk)</p>
                    </div>
                    
                    <div class="compliance-item $(if ($Stats.PrivilegedAccounts -le 5) { 'pass' } else { 'warning' })">
                        <h4>👑 Privileged Accounts</h4>
                        <div class="count">$($Stats.PrivilegedAccounts)</div>
                        <p>Accounts with AdminCount attribute set</p>
                    </div>
                    
                    <div class="compliance-item $(if ($Stats.DormantPrivilegedAccounts -eq 0) { 'pass' } else { 'danger' })">
                        <h4>💤 Dormant Privileged Accounts</h4>
                        <div class="count">$($Stats.DormantPrivilegedAccounts)</div>
                        <p>Privileged accounts inactive for >30 days</p>
                    </div>
                    
                    <div class="compliance-item $(if ($Stats.ExpiredAccounts -eq 0) { 'pass' } else { 'warning' })">
                        <h4>📅 Expired Accounts</h4>
                        <div class="count">$($Stats.ExpiredAccounts)</div>
                        <p>Accounts past their expiration date</p>
                    </div>
                    
                    <div class="compliance-item $(if ($Stats.ExpiringAccounts -le 5) { 'pass' } else { 'warning' })">
                        <h4>⌛ Accounts Expiring Soon</h4>
                        <div class="count">$($Stats.ExpiringAccounts)</div>
                        <p>Accounts expiring within $PasswordExpiryWarningDays days</p>
                    </div>
                    
                    <div class="compliance-item $(if ($Stats.ServiceAccounts -eq 0) { 'pass' } else { 'warning' })">
                        <h4>🔧 Service Accounts</h4>
                        <div class="count">$($Stats.ServiceAccounts)</div>
                        <p>Detected service accounts (should be monitored)</p>
                    </div>
                </div>
                
                <!-- Detailed Compliance Tables -->
                <h3 style="margin-top: 40px; margin-bottom: 20px;">📊 Detailed Compliance Issues</h3>
                
                <!-- Password Never Expires -->
                $(if ($PasswordNeverExpires.Count -gt 0) {
                    "<h4 style='margin-top: 20px; color: #e74c3c;'>🔑 Accounts with Non-Expiring Passwords ($($PasswordNeverExpires.Count))</h4>"
                    "<button class='btn export-btn' onclick='exportTableToCSV(""pwd-never-expires-table"", ""PasswordNeverExpires.csv"")'>Export to CSV</button>"
                    "<div class='table-wrapper'><table id='pwd-never-expires-table'><thead><tr><th>Name</th><th>Username</th><th>Last Logon</th><th>Department</th><th>Title</th></tr></thead><tbody>"
                    foreach ($User in ($PasswordNeverExpires | Select-Object -First 50)) {
                        $lastLogon = if ($User.LastLogon) { $User.LastLogon.ToString('dd.MM.yyyy HH:mm') } else { "Never" }
                        "<tr><td>$($User.Name)</td><td>$($User.SamAccountName)</td><td>$lastLogon</td><td>$($User.Department)</td><td>$($User.Title)</td></tr>"
                    }
                    "</tbody></table></div>"
                    if ($PasswordNeverExpires.Count -gt 50) { "<p style='margin-top: 10px; color: #7f8c8d;'>Showing first 50 of $($PasswordNeverExpires.Count) accounts. Export to CSV for full list.</p>" }
                })
                
                <!-- Privileged Accounts -->
                $(if ($PrivilegedAccounts.Count -gt 0) {
                    "<h4 style='margin-top: 30px; color: #f39c12;'>👑 Privileged Accounts ($($PrivilegedAccounts.Count))</h4>"
                    "<button class='btn export-btn' onclick='exportTableToCSV(""privileged-accounts-table"", ""PrivilegedAccounts.csv"")'>Export to CSV</button>"
                    "<div class='table-wrapper'><table id='privileged-accounts-table'><thead><tr><th>Name</th><th>Username</th><th>Last Logon</th><th>Password Never Expires</th><th>Days Inactive</th></tr></thead><tbody>"
                    foreach ($User in $PrivilegedAccounts) {
                        $lastLogon = if ($User.LastLogon) { $User.LastLogon.ToString('dd.MM.yyyy HH:mm') } else { "Never" }
                        $pwdNeverExpires = if ($User.PasswordNeverExpires) { "<span class='badge badge-danger'>Yes</span>" } else { "<span class='badge badge-success'>No</span>" }
                        "<tr><td>$($User.Name)</td><td>$($User.SamAccountName)</td><td>$lastLogon</td><td>$pwdNeverExpires</td><td>$($User.DaysSinceLastLogon)</td></tr>"
                    }
                    "</tbody></table></div>"
                })
                
                <!-- Dormant Privileged Accounts -->
                $(if ($DormantPrivilegedAccounts.Count -gt 0) {
                    "<h4 style='margin-top: 30px; color: #e74c3c;'>💤 Dormant Privileged Accounts ($($DormantPrivilegedAccounts.Count))</h4>"
                    "<button class='btn export-btn' onclick='exportTableToCSV(""dormant-privileged-table"", ""DormantPrivilegedAccounts.csv"")'>Export to CSV</button>"
                    "<div class='table-wrapper'><table id='dormant-privileged-table'><thead><tr><th>Name</th><th>Username</th><th>Last Logon</th><th>Days Inactive</th><th>Password Last Set</th></tr></thead><tbody>"
                    foreach ($User in $DormantPrivilegedAccounts) {
                        $lastLogon = if ($User.LastLogon) { $User.LastLogon.ToString('dd.MM.yyyy HH:mm') } else { "Never" }
                        $pwdSet = if ($User.PasswordLastSet) { $User.PasswordLastSet.ToString('dd.MM.yyyy') } else { "Never" }
                        "<tr><td>$($User.Name)</td><td>$($User.SamAccountName)</td><td>$lastLogon</td><td>$($User.DaysSinceLastLogon)</td><td>$pwdSet</td></tr>"
                    }
                    "</tbody></table></div>"
                })
                
                <!-- Accounts with No Pre-Auth -->
                $(if ($AccountsNoPreAuth.Count -gt 0) {
                    "<h4 style='margin-top: 30px; color: #e74c3c;'>⚠️ Accounts Without Pre-Authentication ($($AccountsNoPreAuth.Count))</h4>"
                    "<p style='color: #e74c3c; margin-bottom: 10px;'><strong>Critical Security Risk:</strong> These accounts are vulnerable to AS-REP Roasting attacks!</p>"
                    "<button class='btn export-btn' onclick='exportTableToCSV(""no-preauth-table"", ""NoPreAuthAccounts.csv"")'>Export to CSV</button>"
                    "<div class='table-wrapper'><table id='no-preauth-table'><thead><tr><th>Name</th><th>Username</th><th>Last Logon</th><th>Department</th></tr></thead><tbody>"
                    foreach ($User in $AccountsNoPreAuth) {
                        $lastLogon = if ($User.LastLogon) { $User.LastLogon.ToString('dd.MM.yyyy HH:mm') } else { "Never" }
                        "<tr><td>$($User.Name)</td><td>$($User.SamAccountName)</td><td>$lastLogon</td><td>$($User.Department)</td></tr>"
                    }
                    "</tbody></table></div>"
                })
                
                <!-- Locked Out Accounts -->
                $(if ($LockedOutAccounts.Count -gt 0) {
                    "<h4 style='margin-top: 30px; color: #f39c12;'>🔒 Locked Out Accounts ($($LockedOutAccounts.Count))</h4>"
                    "<button class='btn export-btn' onclick='exportTableToCSV(""locked-accounts-table"", ""LockedOutAccounts.csv"")'>Export to CSV</button>"
                    "<div class='table-wrapper'><table id='locked-accounts-table'><thead><tr><th>Name</th><th>Username</th><th>Department</th><th>Last Logon</th></tr></thead><tbody>"
                    foreach ($User in $LockedOutAccounts) {
                        $lastLogon = if ($User.LastLogon) { $User.LastLogon.ToString('dd.MM.yyyy HH:mm') } else { "Never" }
                        "<tr><td>$($User.Name)</td><td>$($User.SamAccountName)</td><td>$($User.Department)</td><td>$lastLogon</td></tr>"
                    }
                    "</tbody></table></div>"
                })
                
                <!-- Service Accounts -->
                $(if ($ServiceAccounts.Count -gt 0) {
                    "<h4 style='margin-top: 30px; color: #f39c12;'>🔧 Detected Service Accounts ($($ServiceAccounts.Count))</h4>"
                    "<p style='color: #7f8c8d; margin-bottom: 10px;'>Service accounts detected by naming convention. Review for proper security configuration.</p>"
                    "<button class='btn export-btn' onclick='exportTableToCSV(""service-accounts-table"", ""ServiceAccounts.csv"")'>Export to CSV</button>"
                    "<div class='table-wrapper'><table id='service-accounts-table'><thead><tr><th>Name</th><th>Username</th><th>Last Logon</th><th>Password Last Set</th><th>Privileged</th></tr></thead><tbody>"
                    foreach ($User in $ServiceAccounts) {
                        $lastLogon = if ($User.LastLogon) { $User.LastLogon.ToString('dd.MM.yyyy HH:mm') } else { "Never" }
                        $pwdSet = if ($User.PasswordLastSet) { $User.PasswordLastSet.ToString('dd.MM.yyyy') } else { "Never" }
                        $privileged = if ($User.AdminCount -eq 1) { "<span class='badge badge-warning'>Yes</span>" } else { "<span class='badge badge-success'>No</span>" }
                        "<tr><td>$($User.Name)</td><td>$($User.SamAccountName)</td><td>$lastLogon</td><td>$pwdSet</td><td>$privileged</td></tr>"
                    }
                    "</tbody></table></div>"
                })
                
            </div>
        </div>
    </div>
    
    <script>
        // Tab switching
        function switchTab(event, tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            document.querySelectorAll('.tab').forEach(btn => {
                btn.classList.remove('active');
            });
            
            document.getElementById(tabName + '-tab').classList.add('active');
            event.currentTarget.classList.add('active');
        }
        
        // Table filtering - Enhanced for computers with Operating System filter
        function filterTable(type) {
            console.log('Filtering table: ' + type);
            
            const typeMap = {
                'users': 'user',
                'computers': 'computer',
                'gpos': 'gpo',
                'groups': 'group'
            };
            const singular = typeMap[type] || type;
            
            const table = document.getElementById(type + '-table');
            if (!table) {
                console.error('Table not found: ' + type + '-table');
                return;
            }
            
            const tbody = table.querySelector('tbody');
            const rows = tbody.querySelectorAll('tr');
            
            const searchInput = document.getElementById(singular + 'Search');
            const statusSelect = document.getElementById(singular + 'Status');
            const daysInput = document.getElementById(singular + 'Days');
            const osSelect = document.getElementById(singular + 'OperatingSystem');
            
            const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
            const statusFilter = statusSelect ? statusSelect.value : 'all';
            const daysFilter = daysInput ? parseInt(daysInput.value) : 0;
            const osFilter = osSelect ? osSelect.value : 'all';
            
            console.log('Search: "' + searchTerm + '", Status: ' + statusFilter + ', Days: ' + daysFilter + ', OS: ' + osFilter);
            
            let visibleCount = 0;
            
            rows.forEach(row => {
                let show = true;
                
                // Search filter
                if (searchTerm && searchTerm.length > 0) {
                    const text = row.textContent.toLowerCase();
                    if (text.indexOf(searchTerm) === -1) {
                        show = false;
                    }
                }
                
                // Status filter
                if (show && statusFilter && statusFilter !== 'all') {
                    const enabled = row.getAttribute('data-enabled');
                    const stale = row.getAttribute('data-stale');
                    const neverLoggedOn = row.getAttribute('data-neverloggedon');
                    const members = row.getAttribute('data-members');
                    const passwordStale = row.getAttribute('data-passwordstale');
                    const legacyOS = row.getAttribute('data-legacyos');
                    const delegation = row.getAttribute('data-delegation');
                    
                    if (statusFilter === 'enabled') {
                        if (enabled !== 'true') show = false;
                    } else if (statusFilter === 'disabled') {
                        if (enabled !== 'false') show = false;
                    } else if (statusFilter === 'stale') {
                        if (stale !== 'true') show = false;
                    } else if (statusFilter === 'neverloggedon') {
                        if (neverLoggedOn !== 'true') show = false;
                    } else if (statusFilter === 'empty') {
                        if (members !== '0') show = false;
                    } else if (statusFilter === 'passwordstale') {
                        if (passwordStale !== 'true') show = false;
                    } else if (statusFilter === 'legacyos') {
                        if (legacyOS !== 'true') show = false;
                    } else if (statusFilter === 'delegation') {
                        if (delegation !== 'true') show = false;
                    }
                }
                
                // Operating System filter (more granular than OSCategory)
                if (show && osFilter && osFilter !== 'all') {
                    // Get the OS version from column 2 (0-indexed as 2)
                    const osCell = row.cells[2];
                    if (osCell) {
                        const osText = osCell.textContent.trim();
                        if (!osText.includes(osFilter)) {
                            show = false;
                        }
                    }
                }
                
                // Days filter
                if (show && daysFilter > 0) {
                    const days = parseInt(row.getAttribute('data-days'));
                    if (isNaN(days) || days < daysFilter) {
                        show = false;
                    }
                }
                
                // Show/hide row
                if (show) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            
            console.log('Visible rows: ' + visibleCount + ' of ' + rows.length);
        }
        
        // Reset filters
        function resetFilters(type) {
            const typeMap = {
                'users': 'user',
                'computers': 'computer',
                'gpos': 'gpo',
                'groups': 'group'
            };
            const singular = typeMap[type] || type;
            
            const searchInput = document.getElementById(singular + 'Search');
            const statusSelect = document.getElementById(singular + 'Status');
            const daysInput = document.getElementById(singular + 'Days');
            const osSelect = document.getElementById(singular + 'OperatingSystem');
            
            if (searchInput) searchInput.value = '';
            if (statusSelect) statusSelect.value = 'all';
            if (daysInput) daysInput.value = '';
            if (osSelect) osSelect.value = 'all';
            
            const table = document.getElementById(type + '-table');
            if (table) {
                const rows = table.querySelectorAll('tbody tr');
                rows.forEach(row => {
                    row.style.display = '';
                });
            }
            
            console.log('Filters reset for: ' + type);
        }
        
        // Table sorting
        function sortTable(tableId, columnIndex) {
            const table = document.getElementById(tableId);
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const th = table.querySelectorAll('th')[columnIndex];
            
            const isAsc = th.classList.contains('sort-asc');
            
            table.querySelectorAll('th').forEach(header => {
                header.classList.remove('sort-asc', 'sort-desc');
            });
            
            th.classList.add(isAsc ? 'sort-desc' : 'sort-asc');
            
            rows.sort((a, b) => {
                const aVal = a.cells[columnIndex].textContent.trim();
                const bVal = b.cells[columnIndex].textContent.trim();
                
                const aNum = parseFloat(aVal.replace(/[^0-9.-]/g, ''));
                const bNum = parseFloat(bVal.replace(/[^0-9.-]/g, ''));
                
                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return isAsc ? bNum - aNum : aNum - bNum;
                }
                
                return isAsc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
            });
            
            rows.forEach(row => tbody.appendChild(row));
        }
        
        // Export to CSV
        function exportTableToCSV(tableId, filename) {
            const table = document.getElementById(tableId);
            const rows = table.querySelectorAll('tr');
            const csv = [];
            
            rows.forEach(row => {
                const cols = row.querySelectorAll('td, th');
                const rowData = Array.from(cols).map(col => {
                    let text = col.textContent.trim();
                    text = text.replace(/\s+/g, ' ');
                    text = text.replace(/"/g, '""');
                    return '"' + text + '"';
                });
                csv.push(rowData.join(','));
            });
            
            const blob = new Blob([csv.join('\n')], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
            window.URL.revokeObjectURL(url);
        }
        
        // Initialize Charts
        window.addEventListener('load', function() {
            // Overview Chart
            const overviewCtx = document.getElementById('overviewChart').getContext('2d');
            new Chart(overviewCtx, {
                type: 'bar',
                data: {
                    labels: ['Users', 'Computers', 'GPOs'],
                    datasets: [{
                        label: 'Total',
                        data: [$($Stats.TotalUsers), $($Stats.TotalComputers), $($Stats.TotalGPOs)],
                        backgroundColor: 'rgba(102, 126, 234, 0.6)',
                        borderColor: 'rgba(102, 126, 234, 1)',
                        borderWidth: 2
                    }, {
                        label: 'Stale',
                        data: [$($Stats.StaleUsers), $($Stats.StaleComputers), $($Stats.StaleGPOs)],
                        backgroundColor: 'rgba(231, 76, 60, 0.6)',
                        borderColor: 'rgba(231, 76, 60, 1)',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: 'AD Objects Overview - Total vs Stale',
                            font: { size: 16, weight: 'bold' }
                        },
                        legend: {
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
            
            // Users Chart
            const usersCtx = document.getElementById('usersChart').getContext('2d');
            new Chart(usersCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Active Users', 'Stale Users', 'Disabled Users', 'Never Logged On'],
                    datasets: [{
                        data: [
                            $($Stats.EnabledUsers - $Stats.StaleUsers - $Stats.NeverLoggedOnUsers),
                            $($Stats.StaleUsers),
                            $($Stats.DisabledUsers),
                            $($Stats.NeverLoggedOnUsers)
                        ],
                        backgroundColor: [
                            'rgba(46, 204, 113, 0.8)',
                            'rgba(231, 76, 60, 0.8)',
                            'rgba(149, 165, 166, 0.8)',
                            'rgba(243, 156, 18, 0.8)'
                        ],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: 'User Accounts Distribution',
                            font: { size: 16, weight: 'bold' }
                        },
                        legend: {
                            position: 'right'
                        }
                    }
                }
            });
            
            // Computers Chart
            const computersCtx = document.getElementById('computersChart').getContext('2d');
            new Chart(computersCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Active Computers', 'Stale Computers', 'Disabled Computers', 'Never Logged On'],
                    datasets: [{
                        data: [
                            $($Stats.EnabledComputers - $Stats.StaleComputers - $Stats.NeverLoggedOnComputers),
                            $($Stats.StaleComputers),
                            $($Stats.DisabledComputers),
                            $($Stats.NeverLoggedOnComputers)
                        ],
                        backgroundColor: [
                            'rgba(46, 204, 113, 0.8)',
                            'rgba(231, 76, 60, 0.8)',
                            'rgba(149, 165, 166, 0.8)',
                            'rgba(243, 156, 18, 0.8)'
                        ],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Computer Accounts Distribution',
                            font: { size: 16, weight: 'bold' }
                        },
                        legend: {
                            position: 'right'
                        }
                    }
                }
            });
        });
    </script>
</body>
</html>
"@

# Save HTML report
$HTML | Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host "`n✅ Report generated successfully!" -ForegroundColor Green
Write-Host "📁 Location: $ReportPath" -ForegroundColor Cyan
Write-Host "`n📊 Summary:" -ForegroundColor Yellow
Write-Host "   • Total Users: $($Stats.TotalUsers) (Stale: $($Stats.StaleUsers))" -ForegroundColor White
Write-Host "   • Total Computers: $($Stats.TotalComputers) (Stale: $($Stats.StaleComputers))" -ForegroundColor White
Write-Host "   • Total GPOs: $($Stats.TotalGPOs) (Stale: $($Stats.StaleGPOs))" -ForegroundColor White
Write-Host "   • Total Groups: $($Stats.TotalGroups) (Empty: $($Stats.EmptyGroups))" -ForegroundColor White
Write-Host "`n🔒 Compliance Score: $ComplianceScore%" -ForegroundColor $(if ($ComplianceScore -ge 80) { 'Green' } elseif ($ComplianceScore -ge 60) { 'Yellow' } else { 'Red' })
Write-Host "   • Password Issues: $($Stats.PasswordNeverExpires) never expire, $($Stats.PasswordExpired) expired" -ForegroundColor White
Write-Host "   • Privileged Accounts: $($Stats.PrivilegedAccounts) total, $($Stats.DormantPrivilegedAccounts) dormant" -ForegroundColor White
Write-Host "   • Security Risks: $($Stats.NoPreAuthRequired) no pre-auth, $($Stats.LockedOutAccounts) locked" -ForegroundColor White

# Open report in default browser
Start-Process $ReportPath

Write-Host "`n🚀 Opening report in your default browser..." -ForegroundColor Cyan
