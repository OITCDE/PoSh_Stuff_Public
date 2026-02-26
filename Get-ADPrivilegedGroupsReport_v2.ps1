<#
.SYNOPSIS
    Active Directory Tier-0 and Tier-1 Privileged Group Membership Report (Language-Agnostic)
.DESCRIPTION
    Generates a comprehensive HTML report of all Tier-0 and Tier-1 groups and their members
    using Well-Known SIDs for language-independent group identification.
    Works with German, English, French, and all other localized AD installations.
.NOTES
    Author: Logicc AI for Alexander Ollischer
    Date: 2026-02-26
    Requires: Active Directory PowerShell Module
#>

#Requires -Modules ActiveDirectory

# Configuration
$OutputPath = ".\AD_PrivilegedGroups_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$MaxDepth = 10  # Maximum recursion depth for nested groups

# Get Domain and Forest information
try {
    $domain = Get-ADDomain
    $forest = Get-ADForest
    $domainSID = $domain.DomainSID.Value
    $rootDomainSID = (Get-ADDomain -Identity $forest.RootDomain).DomainSID.Value
} catch {
    Write-Error "Failed to retrieve domain information. Ensure you're running this on a domain-joined computer with AD PowerShell module."
    exit 1
}

# Tier-0 Groups using Well-Known SIDs
# These SIDs are universal across all languages and AD versions
$Tier0GroupSIDs = @(
    # Forest-level groups (using root domain SID)
    @{
        SID = "$rootDomainSID-519"  # Enterprise Admins
        Description = "Enterprise Admins (Forest-wide)"
        Level = "Forest"
    },
    @{
        SID = "$rootDomainSID-518"  # Schema Admins
        Description = "Schema Admins (Forest-wide)"
        Level = "Forest"
    },
    @{
        SID = "$rootDomainSID-527"  # Enterprise Key Admins
        Description = "Enterprise Key Admins (Forest-wide)"
        Level = "Forest"
    },
    
    # Domain-level privileged groups (using domain SID)
    @{
        SID = "$domainSID-512"      # Domain Admins
        Description = "Domain Admins"
        Level = "Domain"
    },
    @{
        SID = "$domainSID-520"      # Group Policy Creator Owners
        Description = "Group Policy Creator Owners"
        Level = "Domain"
    },
    @{
        SID = "$domainSID-516"      # Domain Controllers
        Description = "Domain Controllers"
        Level = "Domain"
    },
    @{
        SID = "$domainSID-521"      # Read-only Domain Controllers
        Description = "Read-only Domain Controllers"
        Level = "Domain"
    },
    @{
        SID = "$domainSID-522"      # Cloneable Domain Controllers
        Description = "Cloneable Domain Controllers"
        Level = "Domain"
    },
    @{
        SID = "$domainSID-525"      # Protected Users
        Description = "Protected Users"
        Level = "Domain"
    },
    @{
        SID = "$domainSID-526"      # Key Admins
        Description = "Key Admins"
        Level = "Domain"
    },
    @{
        SID = "$domainSID-498"      # Enterprise Read-only Domain Controllers
        Description = "Enterprise Read-only Domain Controllers"
        Level = "Domain"
    },
    
    # Built-in groups (universal SIDs)
    @{
        SID = "S-1-5-32-544"        # Administrators
        Description = "Administrators (Built-in)"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-548"        # Account Operators
        Description = "Account Operators"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-549"        # Server Operators
        Description = "Server Operators"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-550"        # Print Operators
        Description = "Print Operators"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-551"        # Backup Operators
        Description = "Backup Operators"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-552"        # Replicator
        Description = "Replicator"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-569"        # Cryptographic Operators
        Description = "Cryptographic Operators"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-556"        # Network Configuration Operators
        Description = "Network Configuration Operators"
        Level = "Built-in"
    }
)

# Tier-1 Groups using Well-Known SIDs
$Tier1GroupSIDs = @(
    # Built-in groups (universal SIDs)
    @{
        SID = "S-1-5-32-555"        # Remote Desktop Users
        Description = "Remote Desktop Users"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-580"        # Remote Management Users
        Description = "Remote Management Users"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-578"        # Hyper-V Administrators
        Description = "Hyper-V Administrators"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-582"        # Storage Replica Administrators
        Description = "Storage Replica Administrators"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-573"        # Event Log Readers
        Description = "Event Log Readers"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-559"        # Performance Monitor Users
        Description = "Performance Monitor Users"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-558"        # Performance Log Users
        Description = "Performance Log Users"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-562"        # Distributed COM Users
        Description = "Distributed COM Users"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-568"        # IIS_IUSRS
        Description = "IIS Users"
        Level = "Built-in"
    },
    @{
        SID = "S-1-5-32-579"        # Access Control Assistance Operators
        Description = "Access Control Assistance Operators"
        Level = "Built-in"
    }
)

# Additional groups to check (common custom groups - add your own as needed)
# These need to be looked up by name since they don't have well-known SIDs
$AdditionalGroupNames = @(
    'DnsAdmins',
    'DNSAdmins',
    'Cert Publishers'
)

# Function to get all group members recursively
function Get-ADGroupMemberRecursive {
    param(
        [string]$GroupIdentity,
        [string]$GroupName,
        [int]$CurrentDepth = 0,
        [hashtable]$ProcessedGroups = @{}
    )
    
    if ($CurrentDepth -gt $MaxDepth) {
        return @()
    }
    
    try {
        $group = Get-ADGroup -Identity $GroupIdentity -ErrorAction SilentlyContinue
        
        if (-not $group) {
            Write-Verbose "Group with identity '$GroupIdentity' not found"
            return @()
        }
        
        # Prevent circular reference processing
        if ($ProcessedGroups.ContainsKey($group.DistinguishedName)) {
            return @()
        }
        
        $ProcessedGroups[$group.DistinguishedName] = $true
        $members = @()
        
        $groupMembers = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
        
        foreach ($member in $groupMembers) {
            $memberInfo = [PSCustomObject]@{
                Name = $member.Name
                SamAccountName = $member.SamAccountName
                ObjectClass = $member.objectClass
                DistinguishedName = $member.DistinguishedName
                SID = $member.SID.Value
                Depth = $CurrentDepth
                ParentGroup = $GroupName
                Enabled = $null
                LastLogon = $null
                Created = $null
                PasswordLastSet = $null
                PasswordNeverExpires = $null
                IsNested = $CurrentDepth -gt 0
            }
            
            # Get additional user details
            if ($member.objectClass -eq 'user') {
                try {
                    $userDetails = Get-ADUser -Identity $member.SamAccountName -Properties Enabled, LastLogonDate, Created, PasswordLastSet, PasswordNeverExpires -ErrorAction SilentlyContinue
                    $memberInfo.Enabled = $userDetails.Enabled
                    $memberInfo.LastLogon = $userDetails.LastLogonDate
                    $memberInfo.Created = $userDetails.Created
                    $memberInfo.PasswordLastSet = $userDetails.PasswordLastSet
                    $memberInfo.PasswordNeverExpires = $userDetails.PasswordNeverExpires
                } catch {
                    Write-Verbose "Could not retrieve details for user: $($member.SamAccountName)"
                }
            }
            
            $members += $memberInfo
            
            # Recursively get nested group members
            if ($member.objectClass -eq 'group') {
                $nestedMembers = Get-ADGroupMemberRecursive -GroupIdentity $member.SID.Value -GroupName $member.Name -CurrentDepth ($CurrentDepth + 1) -ProcessedGroups $ProcessedGroups
                $members += $nestedMembers
            }
        }
        
        return $members
    }
    catch {
        Write-Warning "Error processing group '$GroupName': $_"
        return @()
    }
}

# Function to check if group has AdminSDHolder protection
function Test-AdminSDHolder {
    param([string]$GroupIdentity)
    
    try {
        $group = Get-ADGroup -Identity $GroupIdentity -Properties adminCount -ErrorAction SilentlyContinue
        return ($group.adminCount -eq 1)
    }
    catch {
        return $false
    }
}

# Function to get group details by SID
function Get-GroupDetailsBySID {
    param(
        [string]$SID,
        [string]$Description,
        [string]$Level,
        [string]$Tier
    )
    
    try {
        $group = Get-ADGroup -Identity $SID -Properties Description, adminCount, whenCreated, whenChanged, GroupScope, GroupCategory, SID -ErrorAction SilentlyContinue
        
        if (-not $group) {
            Write-Verbose "Group with SID $SID not found (may not exist in this domain/forest)"
            return $null
        }
        
        $members = Get-ADGroupMemberRecursive -GroupIdentity $SID -GroupName $group.Name
        $userMembers = $members | Where-Object { $_.ObjectClass -eq 'user' }
        $groupMembers = $members | Where-Object { $_.ObjectClass -eq 'group' } | Select-Object -Unique Name
        
        return [PSCustomObject]@{
            GroupName = $group.Name
            Description = if ($group.Description) { $group.Description } else { $Description }
            SID = $SID
            Tier = $Tier
            Level = $Level
            AdminSDHolder = ($group.adminCount -eq 1)
            MemberCount = ($members | Select-Object -Unique DistinguishedName).Count
            DirectUserCount = ($userMembers | Where-Object { $_.Depth -eq 0 }).Count
            NestedUserCount = ($userMembers | Where-Object { $_.Depth -gt 0 }).Count
            NestedGroupCount = $groupMembers.Count
            Members = $members
            GroupScope = $group.GroupScope
            GroupCategory = $group.GroupCategory
            Created = $group.whenCreated
            Modified = $group.whenChanged
            DistinguishedName = $group.DistinguishedName
        }
    }
    catch {
        Write-Warning "Error getting details for group SID '$SID': $_"
        return $null
    }
}

# Function to get group details by name (for additional groups)
function Get-GroupDetailsByName {
    param(
        [string]$GroupName,
        [string]$Tier
    )
    
    try {
        $group = Get-ADGroup -Filter "Name -eq '$GroupName'" -Properties Description, adminCount, whenCreated, whenChanged, GroupScope, GroupCategory, SID -ErrorAction SilentlyContinue
        
        if (-not $group) {
            Write-Verbose "Group '$GroupName' not found"
            return $null
        }
        
        $members = Get-ADGroupMemberRecursive -GroupIdentity $group.SID.Value -GroupName $group.Name
        $userMembers = $members | Where-Object { $_.ObjectClass -eq 'user' }
        $groupMembers = $members | Where-Object { $_.ObjectClass -eq 'group' } | Select-Object -Unique Name
        
        return [PSCustomObject]@{
            GroupName = $group.Name
            Description = $group.Description
            SID = $group.SID.Value
            Tier = $Tier
            Level = "Custom"
            AdminSDHolder = ($group.adminCount -eq 1)
            MemberCount = ($members | Select-Object -Unique DistinguishedName).Count
            DirectUserCount = ($userMembers | Where-Object { $_.Depth -eq 0 }).Count
            NestedUserCount = ($userMembers | Where-Object { $_.Depth -gt 0 }).Count
            NestedGroupCount = $groupMembers.Count
            Members = $members
            GroupScope = $group.GroupScope
            GroupCategory = $group.GroupCategory
            Created = $group.whenCreated
            Modified = $group.whenChanged
            DistinguishedName = $group.DistinguishedName
        }
    }
    catch {
        Write-Warning "Error getting details for group '$GroupName': $_"
        return $null
    }
}

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   AD Privileged Groups Report - Language-Agnostic (SID-based) ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Yellow
Write-Host "Forest: $($forest.Name)" -ForegroundColor Yellow
Write-Host "Domain SID: $domainSID" -ForegroundColor Gray
Write-Host "Root Domain SID: $rootDomainSID" -ForegroundColor Gray
Write-Host ""
Write-Host "Gathering Active Directory Privileged Group Information..." -ForegroundColor Cyan
Write-Host "This may take several minutes depending on your AD size..." -ForegroundColor Yellow
Write-Host ""

# Collect all group data
$allGroupData = @()

Write-Host "Processing Tier-0 Groups (using Well-Known SIDs)..." -ForegroundColor Green
foreach ($groupInfo in $Tier0GroupSIDs) {
    Write-Host "  - SID: $($groupInfo.SID) [$($groupInfo.Level)]" -ForegroundColor Gray
    $groupData = Get-GroupDetailsBySID -SID $groupInfo.SID -Description $groupInfo.Description -Level $groupInfo.Level -Tier "Tier-0"
    if ($groupData) {
        Write-Host "    ✓ Found: $($groupData.GroupName)" -ForegroundColor Green
        $allGroupData += $groupData
    } else {
        Write-Host "    ⚠ Not found in this domain/forest" -ForegroundColor DarkGray
    }
}

Write-Host "`nProcessing Tier-1 Groups (using Well-Known SIDs)..." -ForegroundColor Green
foreach ($groupInfo in $Tier1GroupSIDs) {
    Write-Host "  - SID: $($groupInfo.SID) [$($groupInfo.Level)]" -ForegroundColor Gray
    $groupData = Get-GroupDetailsBySID -SID $groupInfo.SID -Description $groupInfo.Description -Level $groupInfo.Level -Tier "Tier-1"
    if ($groupData) {
        Write-Host "    ✓ Found: $($groupData.GroupName)" -ForegroundColor Green
        $allGroupData += $groupData
    } else {
        Write-Host "    ⚠ Not found in this domain/forest" -ForegroundColor DarkGray
    }
}

# Process additional groups by name
if ($AdditionalGroupNames.Count -gt 0) {
    Write-Host "`nProcessing Additional Groups (by name)..." -ForegroundColor Green
    foreach ($groupName in $AdditionalGroupNames) {
        Write-Host "  - $groupName" -ForegroundColor Gray
        $groupData = Get-GroupDetailsByName -GroupName $groupName -Tier "Tier-0"
        if ($groupData) {
            Write-Host "    ✓ Found: $($groupData.GroupName)" -ForegroundColor Green
            $allGroupData += $groupData
        } else {
            Write-Host "    ⚠ Not found" -ForegroundColor DarkGray
        }
    }
}

# Calculate statistics
$totalTier0Groups = ($allGroupData | Where-Object { $_.Tier -eq 'Tier-0' }).Count
$totalTier1Groups = ($allGroupData | Where-Object { $_.Tier -eq 'Tier-1' }).Count
$totalTier0Users = ($allGroupData | Where-Object { $_.Tier -eq 'Tier-0' } | ForEach-Object { $_.Members | Where-Object { $_.ObjectClass -eq 'user' } } | Select-Object -Unique SamAccountName).Count
$totalTier1Users = ($allGroupData | Where-Object { $_.Tier -eq 'Tier-1' } | ForEach-Object { $_.Members | Where-Object { $_.ObjectClass -eq 'user' } } | Select-Object -Unique SamAccountName).Count

# Generate HTML Report
$html = @"
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Privileged Groups Security Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
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
            max-width: 1600px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
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
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .header .subtitle {
            background: rgba(255,255,255,0.2);
            padding: 10px 20px;
            border-radius: 20px;
            display: inline-block;
            margin-top: 10px;
            font-size: 0.9em;
        }
        
        .metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 3px solid #e9ecef;
        }
        
        .metadata-item {
            background: white;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .metadata-item strong {
            display: block;
            color: #667eea;
            font-size: 0.9em;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .metadata-item span {
            font-size: 1.1em;
            color: #333;
            word-break: break-all;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: white;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }
        
        .stat-card.tier0 {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        
        .stat-card.tier1 {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }
        
        .stat-card h3 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .stat-card p {
            font-size: 1em;
            opacity: 0.9;
        }
        
        .controls {
            padding: 20px 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .search-box {
            flex: 1;
            min-width: 250px;
            position: relative;
        }
        
        .search-box input {
            width: 100%;
            padding: 12px 40px 12px 15px;
            border: 2px solid #dee2e6;
            border-radius: 25px;
            font-size: 1em;
            transition: all 0.3s ease;
        }
        
        .search-box input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .filter-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            padding: 10px 20px;
            border: 2px solid #667eea;
            background: white;
            color: #667eea;
            border-radius: 25px;
            cursor: pointer;
            font-size: 0.95em;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .filter-btn:hover {
            background: #667eea;
            color: white;
        }
        
        .filter-btn.active {
            background: #667eea;
            color: white;
        }
        
        .content {
            padding: 30px;
        }
        
        .group-section {
            margin-bottom: 30px;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
        }
        
        .group-section:hover {
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }
        
        .group-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.3s ease;
        }
        
        .group-header.tier0 {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        
        .group-header.tier1 {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }
        
        .group-header:hover {
            opacity: 0.9;
        }
        
        .group-header h2 {
            font-size: 1.5em;
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .badge {
            background: rgba(255,255,255,0.3);
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.6em;
            font-weight: 600;
        }
        
        .sid-badge {
            background: rgba(0,0,0,0.2);
            padding: 5px 10px;
            border-radius: 12px;
            font-size: 0.5em;
            font-family: 'Courier New', monospace;
        }
        
        .group-info {
            background: #f8f9fa;
            padding: 15px 20px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            border-bottom: 1px solid #dee2e6;
        }
        
        .info-item {
            display: flex;
            flex-direction: column;
        }
        
        .info-item strong {
            color: #667eea;
            font-size: 0.85em;
            margin-bottom: 3px;
            text-transform: uppercase;
        }
        
        .info-item span {
            color: #333;
            font-size: 1em;
        }
        
        .members-table {
            background: white;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.5s ease;
        }
        
        .members-table.expanded {
            max-height: 5000px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead {
            background: #f8f9fa;
            position: sticky;
            top: 0;
        }
        
        th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #495057;
            border-bottom: 2px solid #dee2e6;
            font-size: 0.9em;
            text-transform: uppercase;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #f1f3f5;
            font-size: 0.95em;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .user-row {
            background: white;
        }
        
        .group-row {
            background: #fff3cd;
        }
        
        .nested-indicator {
            color: #667eea;
            font-weight: 600;
        }
        
        .status-enabled {
            color: #28a745;
            font-weight: 600;
        }
        
        .status-disabled {
            color: #dc3545;
            font-weight: 600;
        }
        
        .warning-icon {
            color: #ffc107;
            margin-left: 5px;
            cursor: help;
        }
        
        .critical-icon {
            color: #dc3545;
            margin-left: 5px;
            cursor: help;
        }
        
        .toggle-icon {
            transition: transform 0.3s ease;
            font-size: 1.2em;
        }
        
        .toggle-icon.expanded {
            transform: rotate(180deg);
        }
        
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 1px solid #dee2e6;
        }
        
        .alert {
            padding: 15px 20px;
            margin: 20px 0;
            border-radius: 8px;
            border-left: 4px solid;
        }
        
        .alert-info {
            background: #d1ecf1;
            border-color: #17a2b8;
            color: #0c5460;
        }
        
        .alert-warning {
            background: #fff3cd;
            border-color: #ffc107;
            color: #856404;
        }
        
        .alert-danger {
            background: #f8d7da;
            border-color: #dc3545;
            color: #721c24;
        }
        
        .no-results {
            text-align: center;
            padding: 40px;
            color: #6c757d;
            font-size: 1.2em;
        }
        
        @media print {
            body {
                background: white;
            }
            .controls, .filter-buttons {
                display: none;
            }
            .group-section {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Active Directory Privileged Groups Security Report</h1>
            <p>Tier-0 & Tier-1 Group Membership Analysis</p>
            <div class="subtitle">🌍 Language-Agnostic (SID-based Detection)</div>
        </div>
        
        <div class="metadata">
            <div class="metadata-item">
                <strong>Domain</strong>
                <span>$($domain.DNSRoot)</span>
            </div>
            <div class="metadata-item">
                <strong>Forest</strong>
                <span>$($forest.Name)</span>
            </div>
            <div class="metadata-item">
                <strong>Domain SID</strong>
                <span style="font-family: 'Courier New', monospace; font-size: 0.9em;">$domainSID</span>
            </div>
            <div class="metadata-item">
                <strong>Root Domain SID</strong>
                <span style="font-family: 'Courier New', monospace; font-size: 0.9em;">$rootDomainSID</span>
            </div>
            <div class="metadata-item">
                <strong>Report Generated</strong>
                <span>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span>
            </div>
            <div class="metadata-item">
                <strong>Generated By</strong>
                <span>$($env:USERNAME)@$($env:USERDNSDOMAIN)</span>
            </div>
        </div>
        
        <div class="alert alert-info" style="margin: 20px 30px;">
            <strong>ℹ️ Language-Independent Detection:</strong> This report uses Well-Known Security Identifiers (SIDs) to identify privileged groups, 
            making it work seamlessly across all languages (German: Domänen-Admins, English: Domain Admins, etc.). 
            Group names are automatically detected in your environment's language.
        </div>
        
        <div class="stats">
            <div class="stat-card tier0">
                <h3>$totalTier0Groups</h3>
                <p>Tier-0 Groups</p>
            </div>
            <div class="stat-card tier0">
                <h3>$totalTier0Users</h3>
                <p>Unique Tier-0 Users</p>
            </div>
            <div class="stat-card tier1">
                <h3>$totalTier1Groups</h3>
                <p>Tier-1 Groups</p>
            </div>
            <div class="stat-card tier1">
                <h3>$totalTier1Users</h3>
                <p>Unique Tier-1 Users</p>
            </div>
        </div>
        
        <div class="controls">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="🔍 Search groups or members...">
            </div>
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="filterGroups('all')">All Groups</button>
                <button class="filter-btn" onclick="filterGroups('tier0')">Tier-0 Only</button>
                <button class="filter-btn" onclick="filterGroups('tier1')">Tier-1 Only</button>
                <button class="filter-btn" onclick="filterGroups('adminsd')">AdminSDHolder</button>
                <button class="filter-btn" onclick="filterGroups('builtin')">Built-in</button>
                <button class="filter-btn" onclick="filterGroups('domain')">Domain</button>
                <button class="filter-btn" onclick="filterGroups('forest')">Forest</button>
                <button class="filter-btn" onclick="toggleAll()">Expand All</button>
            </div>
        </div>
        
        <div class="content">
"@

# Generate group sections
foreach ($groupData in $allGroupData | Sort-Object Tier, Level, GroupName) {
    $tierClass = if ($groupData.Tier -eq 'Tier-0') { 'tier0' } else { 'tier1' }
    $adminSDHolderBadge = if ($groupData.AdminSDHolder) { '<span class="badge">AdminSDHolder</span>' } else { '' }
    $levelBadge = '<span class="badge">' + $groupData.Level + '</span>'
    
    $html += @"
            <div class="group-section" data-tier="$($groupData.Tier.ToLower())" data-adminsd="$($groupData.AdminSDHolder)" data-level="$($groupData.Level.ToLower())">
                <div class="group-header $tierClass" onclick="toggleMembers(this)">
                    <h2>
                        $($groupData.GroupName)
                        <span class="badge">$($groupData.Tier)</span>
                        $levelBadge
                        $adminSDHolderBadge
                        <span class="sid-badge">$($groupData.SID)</span>
                    </h2>
                    <span class="toggle-icon">▼</span>
                </div>
                <div class="group-info">
                    <div class="info-item">
                        <strong>Description</strong>
                        <span>$($groupData.Description -replace '<', '&lt;' -replace '>', '&gt;')</span>
                    </div>
                    <div class="info-item">
                        <strong>SID</strong>
                        <span style="font-family: 'Courier New', monospace; font-size: 0.85em;">$($groupData.SID)</span>
                    </div>
                    <div class="info-item">
                        <strong>Total Members</strong>
                        <span>$($groupData.MemberCount)</span>
                    </div>
                    <div class="info-item">
                        <strong>Direct Users</strong>
                        <span>$($groupData.DirectUserCount)</span>
                    </div>
                    <div class="info-item">
                        <strong>Nested Users</strong>
                        <span>$($groupData.NestedUserCount)</span>
                    </div>
                    <div class="info-item">
                        <strong>Nested Groups</strong>
                        <span>$($groupData.NestedGroupCount)</span>
                    </div>
                    <div class="info-item">
                        <strong>Group Scope</strong>
                        <span>$($groupData.GroupScope)</span>
                    </div>
                    <div class="info-item">
                        <strong>Group Category</strong>
                        <span>$($groupData.GroupCategory)</span>
                    </div>
                </div>
                <div class="members-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Type</th>
                                <th>Account Name</th>
                                <th>SID</th>
                                <th>Status</th>
                                <th>Nesting Level</th>
                                <th>Parent Group</th>
                                <th>Last Logon</th>
                                <th>Password Last Set</th>
                            </tr>
                        </thead>
                        <tbody>
"@
    
    if ($groupData.Members.Count -eq 0) {
        $html += @"
                            <tr>
                                <td colspan="9" style="text-align: center; padding: 20px; color: #6c757d;">
                                    ✓ No members found in this group (empty or not applicable)
                                </td>
                            </tr>
"@
    } else {
        foreach ($member in $groupData.Members | Sort-Object Depth, ObjectClass, Name) {
            $rowClass = if ($member.ObjectClass -eq 'group') { 'group-row' } else { 'user-row' }
            $statusClass = ''
            $statusText = ''
            $warningIcon = ''
            
            if ($member.ObjectClass -eq 'user') {
                if ($member.Enabled -eq $true) {
                    $statusClass = 'status-enabled'
                    $statusText = '✓ Enabled'
                } elseif ($member.Enabled -eq $false) {
                    $statusClass = 'status-disabled'
                    $statusText = '✗ Disabled'
                }
                
                # Check for security concerns
                if ($member.LastLogon -and $member.LastLogon -lt (Get-Date).AddDays(-90)) {
                    $warningIcon = '<span class="warning-icon" title="No logon in 90+ days">⚠️</span>'
                }
                if ($member.PasswordLastSet -and $member.PasswordLastSet -lt (Get-Date).AddDays(-365)) {
                    $warningIcon += '<span class="critical-icon" title="Password not changed in 365+ days">🔴</span>'
                }
                if ($member.PasswordNeverExpires) {
                    $warningIcon += '<span class="critical-icon" title="Password never expires">⏳</span>'
                }
            }
            
            $nestingLevel = if ($member.Depth -gt 0) { "<span class='nested-indicator'>Level $($member.Depth)</span>" } else { "Direct" }
            $lastLogon = if ($member.LastLogon) { $member.LastLogon.ToString('yyyy-MM-dd') } else { '-' }
            $passwordSet = if ($member.PasswordLastSet) { $member.PasswordLastSet.ToString('yyyy-MM-dd') } else { '-' }
            $sidDisplay = if ($member.SID) { $member.SID.Substring(0, [Math]::Min(30, $member.SID.Length)) + '...' } else { '-' }
            
            $html += @"
                            <tr class="$rowClass">
                                <td>$($member.Name -replace '<', '&lt;' -replace '>', '&gt;')$warningIcon</td>
                                <td>$($member.ObjectClass)</td>
                                <td>$($member.SamAccountName)</td>
                                <td style="font-family: 'Courier New', monospace; font-size: 0.85em;" title="$($member.SID)">$sidDisplay</td>
                                <td class="$statusClass">$statusText</td>
                                <td>$nestingLevel</td>
                                <td>$($member.ParentGroup)</td>
                                <td>$lastLogon</td>
                                <td>$passwordSet</td>
                            </tr>
"@
        }
    }
    
    $html += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
}

$html += @"
        </div>
        
        <div class="footer">
            <p><strong>🔒 Security Recommendations:</strong></p>
            <p>• Regularly review privileged group memberships • Remove unused accounts • Implement Just-In-Time (JIT) admin access • Use Protected Users group for Tier-0 accounts • Monitor for unauthorized changes • Implement Privileged Access Workstations (PAWs) • Enable AdminSDHolder protection for custom privileged groups</p>
            <p style="margin-top: 15px;"><strong>📋 About Well-Known SIDs:</strong> This report uses Security Identifiers (SIDs) instead of group names, ensuring accurate detection across all Active Directory languages (German, English, French, etc.)</p>
            <p style="margin-top: 10px;">Report generated by Ollischer IT Consulting - Active Directory Security Audit Tool v2.0</p>
        </div>
    </div>
    
    <script>
        function toggleMembers(header) {
            const section = header.parentElement;
            const membersTable = section.querySelector('.members-table');
            const icon = header.querySelector('.toggle-icon');
            
            membersTable.classList.toggle('expanded');
            icon.classList.toggle('expanded');
        }
        
        function toggleAll() {
            const allSections = document.querySelectorAll('.group-section');
            const allExpanded = Array.from(allSections).every(section => 
                section.querySelector('.members-table').classList.contains('expanded')
            );
            
            allSections.forEach(section => {
                const membersTable = section.querySelector('.members-table');
                const icon = section.querySelector('.toggle-icon');
                
                if (allExpanded) {
                    membersTable.classList.remove('expanded');
                    icon.classList.remove('expanded');
                } else {
                    membersTable.classList.add('expanded');
                    icon.classList.add('expanded');
                }
            });
        }
        
        function filterGroups(filter) {
            const sections = document.querySelectorAll('.group-section');
            const buttons = document.querySelectorAll('.filter-btn');
            
            // Update active button
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            sections.forEach(section => {
                switch(filter) {
                    case 'all':
                        section.style.display = 'block';
                        break;
                    case 'tier0':
                        section.style.display = section.dataset.tier === 'tier-0' ? 'block' : 'none';
                        break;
                    case 'tier1':
                        section.style.display = section.dataset.tier === 'tier-1' ? 'block' : 'none';
                        break;
                    case 'adminsd':
                        section.style.display = section.dataset.adminsd === 'True' ? 'block' : 'none';
                        break;
                    case 'builtin':
                        section.style.display = section.dataset.level === 'built-in' ? 'block' : 'none';
                        break;
                    case 'domain':
                        section.style.display = section.dataset.level === 'domain' ? 'block' : 'none';
                        break;
                    case 'forest':
                        section.style.display = section.dataset.level === 'forest' ? 'block' : 'none';
                        break;
                }
            });
        }
        
        // Search functionality
        document.getElementById('searchInput').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            const sections = document.querySelectorAll('.group-section');
            
            sections.forEach(section => {
                const groupName = section.querySelector('.group-header h2').textContent.toLowerCase();
                const members = Array.from(section.querySelectorAll('tbody tr')).map(row => 
                    row.textContent.toLowerCase()
                );
                
                const matchesGroup = groupName.includes(searchTerm);
                const matchesMembers = members.some(member => member.includes(searchTerm));
                
                if (searchTerm === '' || matchesGroup || matchesMembers) {
                    section.style.display = 'block';
                    if (matchesMembers && searchTerm !== '') {
                        // Auto-expand if member matches
                        section.querySelector('.members-table').classList.add('expanded');
                        section.querySelector('.toggle-icon').classList.add('expanded');
                    }
                } else {
                    section.style.display = 'none';
                }
            });
        });
        
        // Auto-expand groups with security warnings
        document.addEventListener('DOMContentLoaded', function() {
            const warningGroups = document.querySelectorAll('.warning-icon, .critical-icon');
            warningGroups.forEach(icon => {
                const section = icon.closest('.group-section');
                if (section) {
                    section.querySelector('.members-table').classList.add('expanded');
                    section.querySelector('.toggle-icon').classList.add('expanded');
                }
            });
        });
    </script>
</body>
</html>
"@

# Save the HTML report
try {
    $reportDir = Split-Path -Path $OutputPath -Parent
    if (-not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    
    Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║              ✓ Report generated successfully!                 ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "📁 Location: $OutputPath" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Opening report in default browser..." -ForegroundColor Yellow
    
    Start-Process $OutputPath
    
    # Display summary
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                        SUMMARY                                 ║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Tier-0 Groups Found: $($totalTier0Groups.ToString().PadRight(43)) ║" -ForegroundColor Yellow
    Write-Host "║ Tier-0 Unique Users: $($totalTier0Users.ToString().PadRight(43)) ║" -ForegroundColor Yellow
    Write-Host "║ Tier-1 Groups Found: $($totalTier1Groups.ToString().PadRight(43)) ║" -ForegroundColor Yellow
    Write-Host "║ Tier-1 Unique Users: $($totalTier1Users.ToString().PadRight(43)) ║" -ForegroundColor Yellow
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ 🌍 Language-Agnostic: SID-based detection                     ║" -ForegroundColor Green
    Write-Host "║ ✓ Works with German, English, and all AD languages           ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
} catch {
    Write-Error "Failed to create report: $_"
    exit 1
}
