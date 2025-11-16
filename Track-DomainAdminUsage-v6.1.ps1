<#
.SYNOPSIS
    Domain Admin Account Usage Tracker with Advanced Security Analysis
.DESCRIPTION
    Analyzes Security event logs across all Domain Controllers to identify usage of specified domain admin accounts.
    Tracks NTLM and Kerberos authentication, SPNs, logon types, group memberships, failed logons, encryption types,
    privileged operations, and calculates risk scores.
    Uses SID-based group detection for multi-language AD environments.
    Generates an interactive HTML report with actionable recommendations.
.PARAMETER AccountName
    The domain admin account to track (without domain prefix)
.PARAMETER DaysBack
    Number of days to search back in event logs (default: 30)
.PARAMETER OutputPath
    Path where the HTML report will be saved
.EXAMPLE
    .\Track-DomainAdminUsage.ps1 -AccountName "OldAdmin" -DaysBack 60 -OutputPath "C:\Reports\AdminUsage.html"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$AccountName,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\DomainAdminUsageReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
)

#region Helper Functions

function Get-AccountSPNs {
    param(
        [Parameter(Mandatory=$true)]
        [string]$AccountName
    )
    
    try {
        Write-Host "`nQuerying Service Principal Names (SPNs) for $AccountName..." -ForegroundColor Yellow
        
        $adUser = Get-ADUser -Identity $AccountName -Properties ServicePrincipalName, DistinguishedName, Enabled, PasswordLastSet, LastLogonDate, PasswordNeverExpires, AccountExpirationDate, whenCreated, MemberOf, adminCount, SID -ErrorAction Stop
        
        $spnInfo = [PSCustomObject]@{
            AccountName = $adUser.SamAccountName
            DistinguishedName = $adUser.DistinguishedName
            Enabled = $adUser.Enabled
            PasswordLastSet = $adUser.PasswordLastSet
            LastLogonDate = $adUser.LastLogonDate
            PasswordNeverExpires = $adUser.PasswordNeverExpires
            AccountExpirationDate = $adUser.AccountExpirationDate
            WhenCreated = $adUser.whenCreated
            MemberOf = $adUser.MemberOf
            AdminCount = $adUser.adminCount
            SID = $adUser.SID
            SPNs = $adUser.ServicePrincipalName
            SPNCount = if ($adUser.ServicePrincipalName) { $adUser.ServicePrincipalName.Count } else { 0 }
        }
        
        if ($spnInfo.SPNCount -gt 0) {
            Write-Host "  ✓ Found $($spnInfo.SPNCount) SPN(s):" -ForegroundColor Green
            foreach ($spn in $spnInfo.SPNs) {
                Write-Host "    - $spn" -ForegroundColor Cyan
            }
        } else {
            Write-Host "  ℹ No SPNs configured on this account" -ForegroundColor Gray
        }
        
        if ($spnInfo.AdminCount -eq 1) {
            Write-Host "  ⚠ adminCount = 1 (Protected account - is or was member of privileged group)" -ForegroundColor Yellow
        }
        
        return $spnInfo
        
    } catch {
        Write-Warning "Could not query SPNs for $AccountName : $_"
        return [PSCustomObject]@{
            AccountName = $AccountName
            DistinguishedName = "N/A"
            Enabled = $null
            PasswordLastSet = $null
            LastLogonDate = $null
            PasswordNeverExpires = $null
            AccountExpirationDate = $null
            WhenCreated = $null
            MemberOf = @()
            AdminCount = $null
            SID = $null
            SPNs = @()
            SPNCount = 0
        }
    }
}

function Get-PrivilegedGroupMembership {
    param(
        [Parameter(Mandatory=$true)]
        [array]$MemberOf,
        [Parameter(Mandatory=$true)]
        [string]$DomainSID
    )
    
    $privilegedGroupSIDs = @{
        "$DomainSID-512" = @{ Name = 'Domain Admins'; Risk = 'CRITICAL' }
        "$DomainSID-519" = @{ Name = 'Enterprise Admins'; Risk = 'CRITICAL' }
        "$DomainSID-518" = @{ Name = 'Schema Admins'; Risk = 'CRITICAL' }
        "$DomainSID-520" = @{ Name = 'Group Policy Creator Owners'; Risk = 'HIGH' }
        'S-1-5-32-544' = @{ Name = 'Administrators'; Risk = 'CRITICAL' }
        'S-1-5-32-548' = @{ Name = 'Account Operators'; Risk = 'HIGH' }
        'S-1-5-32-551' = @{ Name = 'Backup Operators'; Risk = 'HIGH' }
        'S-1-5-32-549' = @{ Name = 'Server Operators'; Risk = 'HIGH' }
        'S-1-5-32-550' = @{ Name = 'Print Operators'; Risk = 'MEDIUM' }
        'S-1-5-32-569' = @{ Name = 'Cryptographic Operators'; Risk = 'MEDIUM' }
        'S-1-5-32-573' = @{ Name = 'Event Log Readers'; Risk = 'LOW' }
        'S-1-5-32-578' = @{ Name = 'Hyper-V Administrators'; Risk = 'HIGH' }
        'S-1-5-32-555' = @{ Name = 'Remote Desktop Users'; Risk = 'MEDIUM' }
        'S-1-5-32-562' = @{ Name = 'Distributed COM Users'; Risk = 'LOW' }
    }
    
    $memberships = @()
    
    foreach ($dn in $MemberOf) {
        try {
            $group = Get-ADGroup -Identity $dn -Properties SID, Name -ErrorAction Stop
            $groupSID = $group.SID.Value
            
            if ($privilegedGroupSIDs.ContainsKey($groupSID)) {
                $memberships += [PSCustomObject]@{
                    GroupName = $group.Name
                    EnglishName = $privilegedGroupSIDs[$groupSID].Name
                    RiskLevel = $privilegedGroupSIDs[$groupSID].Risk
                    DistinguishedName = $dn
                    SID = $groupSID
                }
            }
            elseif ($group.Name -match 'DnsAdmins|DNS-Admins') {
                $memberships += [PSCustomObject]@{
                    GroupName = $group.Name
                    EnglishName = 'DnsAdmins'
                    RiskLevel = 'HIGH'
                    DistinguishedName = $dn
                    SID = $groupSID
                }
            }
        } catch {
            Write-Verbose "Could not resolve group: $dn"
        }
    }
    
    return $memberships
}

function Get-LogonTypeDescription {
    param([string]$LogonType)
    
    switch ($LogonType) {
        "2"  { return "Interactive (Local logon)" }
        "3"  { return "Network (SMB, IPC$, etc.)" }
        "4"  { return "Batch (Scheduled Task)" }
        "5"  { return "Service (Service Control Manager)" }
        "7"  { return "Unlock (Workstation unlock)" }
        "8"  { return "NetworkCleartext (IIS Basic Auth)" }
        "9"  { return "NewCredentials (RunAs /netonly)" }
        "10" { return "RemoteInteractive (RDP, Terminal Services)" }
        "11" { return "CachedInteractive (Cached credentials)" }
        default { return "Unknown ($LogonType)" }
    }
}

function Get-FailureReason {
    param([string]$Status, [string]$SubStatus)
    
    $failureCodes = @{
        '0xC0000064' = 'User name does not exist'
        '0xC000006A' = 'Correct user name but wrong password'
        '0xC000006D' = 'Bad user name or password'
        '0xC000006E' = 'Account restriction (time/workstation)'
        '0xC000006F' = 'User logon outside authorized hours'
        '0xC0000070' = 'User logon from unauthorized workstation'
        '0xC0000071' = 'Password expired'
        '0xC0000072' = 'Account disabled'
        '0xC0000193' = 'Account expired'
        '0xC0000224' = 'User must change password at next logon'
        '0xC0000234' = 'Account locked out'
        '0xC00002EE' = 'An error occurred during logon'
        '0x6' = 'Bad user name (Kerberos)'
        '0x12' = 'Account disabled/expired (Kerberos)'
        '0x17' = 'Password expired (Kerberos)'
        '0x18' = 'Bad password (Kerberos)'
    }
    
    if ($failureCodes.ContainsKey($Status)) {
        return $failureCodes[$Status]
    } elseif ($failureCodes.ContainsKey($SubStatus)) {
        return $failureCodes[$SubStatus]
    } else {
        return "Unknown ($Status / $SubStatus)"
    }
}

function Get-EncryptionTypeName {
    param([string]$EncryptionType)
    
    switch ($EncryptionType) {
        '0x1'  { return 'DES-CBC-CRC' }
        '0x3'  { return 'DES-CBC-MD5' }
        '0x11' { return 'AES128-CTS-HMAC-SHA1-96' }
        '0x12' { return 'AES256-CTS-HMAC-SHA1-96' }
        '0x17' { return 'RC4-HMAC' }
        '0x18' { return 'RC4-HMAC-EXP' }
        default { return "Unknown ($EncryptionType)" }
    }
}

function Get-EncryptionTypeRisk {
    param([string]$EncryptionType)
    
    switch ($EncryptionType) {
        '0x1'  { return 'CRITICAL' }
        '0x3'  { return 'CRITICAL' }
        '0x17' { return 'HIGH' }
        '0x18' { return 'HIGH' }
        '0x11' { return 'LOW' }
        '0x12' { return 'LOW' }
        default { return 'UNKNOWN' }
    }
}

function Get-PrivilegeDescription {
    param([string]$Privilege)
    
    $privilegeMap = @{
        'SeAssignPrimaryTokenPrivilege' = 'Replace a process-level token'
        'SeAuditPrivilege' = 'Generate security audits'
        'SeBackupPrivilege' = 'Back up files and directories'
        'SeChangeNotifyPrivilege' = 'Bypass traverse checking'
        'SeCreateGlobalPrivilege' = 'Create global objects'
        'SeCreatePagefilePrivilege' = 'Create a pagefile'
        'SeCreatePermanentPrivilege' = 'Create permanent shared objects'
        'SeCreateSymbolicLinkPrivilege' = 'Create symbolic links'
        'SeCreateTokenPrivilege' = 'Create a token object'
        'SeDebugPrivilege' = 'Debug programs (CRITICAL - Full memory access)'
        'SeEnableDelegationPrivilege' = 'Enable computer and user accounts to be trusted for delegation'
        'SeImpersonatePrivilege' = 'Impersonate a client after authentication'
        'SeIncreaseBasePriorityPrivilege' = 'Increase scheduling priority'
        'SeIncreaseQuotaPrivilege' = 'Adjust memory quotas for a process'
        'SeIncreaseWorkingSetPrivilege' = 'Increase a process working set'
        'SeLoadDriverPrivilege' = 'Load and unload device drivers (CRITICAL)'
        'SeLockMemoryPrivilege' = 'Lock pages in memory'
        'SeMachineAccountPrivilege' = 'Add workstations to domain'
        'SeManageVolumePrivilege' = 'Manage the files on a volume'
        'SeProfileSingleProcessPrivilege' = 'Profile single process'
        'SeRelabelPrivilege' = 'Modify an object label'
        'SeRemoteShutdownPrivilege' = 'Force shutdown from a remote system'
        'SeRestorePrivilege' = 'Restore files and directories'
        'SeSecurityPrivilege' = 'Manage auditing and security log'
        'SeShutdownPrivilege' = 'Shut down the system'
        'SeSyncAgentPrivilege' = 'Synchronize directory service data'
        'SeSystemEnvironmentPrivilege' = 'Modify firmware environment values'
        'SeSystemProfilePrivilege' = 'Profile system performance'
        'SeSystemtimePrivilege' = 'Change the system time'
        'SeTakeOwnershipPrivilege' = 'Take ownership of files or other objects'
        'SeTcbPrivilege' = 'Act as part of the operating system (CRITICAL)'
        'SeTimeZonePrivilege' = 'Change the time zone'
        'SeTrustedCredManAccessPrivilege' = 'Access Credential Manager as trusted caller'
        'SeUndockPrivilege' = 'Remove computer from docking station'
        'SeUnsolicitedInputPrivilege' = 'Read unsolicited input from a terminal device'
    }
    
    if ($privilegeMap.ContainsKey($Privilege)) {
        return $privilegeMap[$Privilege]
    } else {
        return $Privilege
    }
}

function Get-PrivilegeRiskLevel {
    param([string]$Privilege)
    
    $criticalPrivileges = @(
        'SeDebugPrivilege',
        'SeTcbPrivilege',
        'SeLoadDriverPrivilege',
        'SeRestorePrivilege',
        'SeTakeOwnershipPrivilege'
    )
    
    $highPrivileges = @(
        'SeBackupPrivilege',
        'SeSecurityPrivilege',
        'SeSystemEnvironmentPrivilege',
        'SeEnableDelegationPrivilege',
        'SeImpersonatePrivilege'
    )
    
    if ($criticalPrivileges -contains $Privilege) {
        return 'CRITICAL'
    } elseif ($highPrivileges -contains $Privilege) {
        return 'HIGH'
    } else {
        return 'MEDIUM'
    }
}

function Calculate-RiskScore {
    param(
        [object]$AccountInfo,
        [object]$Stats,
        [array]$PrivilegedGroups,
        [array]$EncryptionIssues
    )
    
    $riskFactors = @()
    $totalScore = 0
    
    if ($AccountInfo.PasswordLastSet) {
        $passwordAge = (Get-Date) - $AccountInfo.PasswordLastSet
        if ($passwordAge.TotalDays -gt 365) {
            $riskFactors += [PSCustomObject]@{
                Factor = "Password age > 365 days ($([math]::Round($passwordAge.TotalDays)) days)"
                Severity = 'CRITICAL'
                Score = 25
                Recommendation = 'Rotate password immediately or migrate to gMSA'
            }
            $totalScore += 25
        } elseif ($passwordAge.TotalDays -gt 180) {
            $riskFactors += [PSCustomObject]@{
                Factor = "Password age > 180 days ($([math]::Round($passwordAge.TotalDays)) days)"
                Severity = 'HIGH'
                Score = 15
                Recommendation = 'Schedule password rotation'
            }
            $totalScore += 15
        } elseif ($passwordAge.TotalDays -gt 90) {
            $riskFactors += [PSCustomObject]@{
                Factor = "Password age > 90 days ($([math]::Round($passwordAge.TotalDays)) days)"
                Severity = 'MEDIUM'
                Score = 10
                Recommendation = 'Consider password rotation policy'
            }
            $totalScore += 10
        }
    }
    
    if ($AccountInfo.PasswordNeverExpires) {
        $riskFactors += [PSCustomObject]@{
            Factor = 'Password never expires is set'
            Severity = 'CRITICAL'
            Score = 20
            Recommendation = 'Remove "Password Never Expires" flag or convert to gMSA'
        }
        $totalScore += 20
    }
    
    $criticalGroups = $PrivilegedGroups | Where-Object { $_.RiskLevel -eq 'CRITICAL' }
    if ($criticalGroups.Count -gt 0) {
        $groupNames = ($criticalGroups | Select-Object -ExpandProperty GroupName) -join ', '
        $riskFactors += [PSCustomObject]@{
            Factor = "Member of critical groups: $groupNames"
            Severity = 'CRITICAL'
            Score = 25
            Recommendation = 'Remove from privileged groups if not actively needed'
        }
        $totalScore += 25
    }
    
    if ($Stats.InteractiveLogons -gt 0 -or $Stats.RemoteInteractiveLogons -gt 0) {
        $riskFactors += [PSCustomObject]@{
            Factor = "Interactive/RDP logons detected ($($Stats.InteractiveLogons + $Stats.RemoteInteractiveLogons) events)"
            Severity = 'HIGH'
            Score = 20
            Recommendation = 'Legacy admin accounts should not have interactive usage'
        }
        $totalScore += 20
    }
    
    $criticalEncryption = $EncryptionIssues | Where-Object { $_.Risk -eq 'CRITICAL' }
    if ($criticalEncryption.Count -gt 0) {
        $riskFactors += [PSCustomObject]@{
            Factor = "DES encryption detected ($($criticalEncryption.Count) instances)"
            Severity = 'CRITICAL'
            Score = 25
            Recommendation = 'Upgrade to AES encryption immediately - DES is severely compromised'
        }
        $totalScore += 25
    }
    
    $highEncryption = $EncryptionIssues | Where-Object { $_.Risk -eq 'HIGH' }
    if ($highEncryption.Count -gt 0) {
        $riskFactors += [PSCustomObject]@{
            Factor = "RC4 encryption detected ($($highEncryption.Count) instances)"
            Severity = 'HIGH'
            Score = 15
            Recommendation = 'Upgrade to AES encryption - RC4 is deprecated and weak'
        }
        $totalScore += 15
    }
    
    if ($Stats.FailedEvents -gt 50) {
        $riskFactors += [PSCustomObject]@{
            Factor = "High number of failed logons ($($Stats.FailedEvents) failures)"
            Severity = 'HIGH'
            Score = 15
            Recommendation = 'Investigate for potential brute force attacks or misconfigured services'
        }
        $totalScore += 15
    }
    
    if ($AccountInfo.WhenCreated) {
        $accountAge = (Get-Date) - $AccountInfo.WhenCreated
        if ($accountAge.TotalDays -gt 1825) {
            $riskFactors += [PSCustomObject]@{
                Factor = "Account is very old ($([math]::Round($accountAge.TotalDays / 365, 1)) years)"
                Severity = 'MEDIUM'
                Score = 10
                Recommendation = 'Review if account is still needed or should be migrated'
            }
            $totalScore += 10
        }
    }
    
    if ($Stats.TotalEvents -eq 0) {
        $riskFactors += [PSCustomObject]@{
            Factor = "No authentication events in past $DaysBack days"
            Severity = 'LOW'
            Score = 5
            Recommendation = 'Consider disabling account if no longer needed'
        }
        $totalScore += 5
    }
    
    if ($AccountInfo.AdminCount -eq 1 -and $PrivilegedGroups.Count -eq 0) {
        $riskFactors += [PSCustomObject]@{
            Factor = 'adminCount=1 but no current privileged group membership (orphaned protected account)'
            Severity = 'MEDIUM'
            Score = 10
            Recommendation = 'Review if AdminSDHolder protection is still needed; consider running SDProp cleanup'
        }
        $totalScore += 10
    }
    
    $overallRisk = if ($totalScore -ge 75) { 'CRITICAL' }
                   elseif ($totalScore -ge 50) { 'HIGH' }
                   elseif ($totalScore -ge 25) { 'MEDIUM' }
                   else { 'LOW' }
    
    return [PSCustomObject]@{
        TotalScore = $totalScore
        OverallRisk = $overallRisk
        RiskFactors = $riskFactors
    }
}

#endregion

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "This script requires Administrator privileges to read Security event logs."
    
    $response = Read-Host "Would you like to restart as Administrator? (Y/N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        $scriptPath = $MyInvocation.MyCommand.Path
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -AccountName `"$AccountName`" -DaysBack $DaysBack -OutputPath `"$OutputPath`""
        
        Start-Process PowerShell -Verb RunAs -ArgumentList $arguments
        exit
    } else {
        Write-Error "Script cannot continue without Administrator privileges. Exiting."
        exit 1
    }
}

Write-Host "✓ Running with Administrator privileges" -ForegroundColor Green

# Relevant Event IDs for tracking
$EventIDs = @{
    4768 = "Kerberos TGT Request"
    4769 = "Kerberos Service Ticket Request"
    4770 = "Kerberos Service Ticket Renewed"
    4771 = "Kerberos Pre-authentication Failed"
    4776 = "Domain Controller Authentication (NTLM)"
    4624 = "Successful Logon"
    4625 = "Failed Logon"
    4672 = "Special Privileges Assigned to New Logon"
}

Write-Host "`nDomain Admin Usage Tracker" -ForegroundColor Cyan
Write-Host "=" * 50

# Query Account Information and SPNs
$AccountInfo = Get-AccountSPNs -AccountName $AccountName

# Get Domain SID
$DomainSID = $AccountInfo.SID.AccountDomainSid.Value

# Get Privileged Group Memberships
Write-Host "`nAnalyzing privileged group memberships..." -ForegroundColor Yellow
$PrivilegedGroups = Get-PrivilegedGroupMembership -MemberOf $AccountInfo.MemberOf -DomainSID $DomainSID

if ($PrivilegedGroups.Count -gt 0) {
    Write-Host "  ⚠ Found $($PrivilegedGroups.Count) privileged group membership(s):" -ForegroundColor Yellow
    foreach ($group in $PrivilegedGroups) {
        $color = switch ($group.RiskLevel) {
            'CRITICAL' { 'Red' }
            'HIGH' { 'Yellow' }
            'MEDIUM' { 'Cyan' }
            default { 'Gray' }
        }
        Write-Host "    - $($group.GroupName) [$($group.EnglishName)] [$($group.RiskLevel)]" -ForegroundColor $color
    }
} else {
    Write-Host "  ✓ No privileged group memberships detected" -ForegroundColor Green
}

if ($AccountInfo.AdminCount -eq 1) {
    Write-Host "  ℹ Note: adminCount=1 indicates this account is or was a protected admin account" -ForegroundColor Cyan
}

# Get all Domain Controllers
try {
    Write-Host "`nDiscovering Domain Controllers..." -ForegroundColor Yellow
    $DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    Write-Host "Found $($DomainControllers.Count) Domain Controller(s): $($DomainControllers -join ', ')" -ForegroundColor Green
} catch {
    Write-Error "Failed to retrieve Domain Controllers: $_"
    exit 1
}

# Calculate time range
$StartTime = (Get-Date).AddDays(-$DaysBack)
$EndTime = Get-Date

Write-Host "`nSearching for account: $AccountName" -ForegroundColor Yellow
Write-Host "Time range: $($StartTime.ToString('yyyy-MM-dd HH:mm')) to $($EndTime.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Yellow

# Collection arrays
$AllEvents = @()
$DCStatus = @()

# Query each Domain Controller
foreach ($DC in $DomainControllers) {
    Write-Host "`nQuerying $DC..." -ForegroundColor Cyan
    $dcStartTime = Get-Date
    
    try {
        # Check if this is the local machine
        $isLocalhost = ($DC -eq $env:COMPUTERNAME) -or 
                       ($DC -eq "$env:COMPUTERNAME.$env:USERDNSDOMAIN") -or
                       ($DC -eq "localhost") -or
                       ($DC -eq "127.0.0.1") -or
                       ($DC -eq $env:COMPUTERNAME.ToLower()) -or
                       ($DC.Split('.')[0] -eq $env:COMPUTERNAME)
        
        if (-not $isLocalhost) {
            if (-not (Test-Connection -ComputerName $DC -Count 1 -Quiet)) {
                Write-Warning "Cannot reach $DC - skipping"
                $DCStatus += [PSCustomObject]@{
                    DomainController = $DC
                    Status = "Unreachable"
                    EventsFound = 0
                    QueryTime = "N/A"
                }
                continue
            }
        }
        
        # Define the scriptblock
        $ScriptBlock = {
            param(
                $AccountName,
                $DomainName,
                $StartTimeUTC,
                $EndTimeUTC,
                $EventIDs
            )
            
            # Build filter XML
            $FilterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[
        (EventID=4768 or EventID=4769 or EventID=4770 or EventID=4771 or EventID=4776 or EventID=4624 or EventID=4625 or EventID=4672)
        and TimeCreated[@SystemTime&gt;='$StartTimeUTC' and @SystemTime&lt;='$EndTimeUTC']
      ]]
      and
      *[EventData[Data and (Data='$AccountName' or Data='$DomainName\$AccountName')]]
    </Select>
  </Query>
</QueryList>
"@
            
            $RawEvents = Get-WinEvent -FilterXml $FilterXml -ErrorAction Stop
            
            # Parse events and return custom objects
            $ParsedEvents = foreach ($Event in $RawEvents) {
                $EventXml = [xml]$Event.ToXml()
                $EventData = @{}
                
                foreach ($Data in $EventXml.Event.EventData.Data) {
                    if ($Data.Name) {
                        $EventData[$Data.Name] = $Data.'#text'
                    }
                }
                
                [PSCustomObject]@{
                    TimeCreated = $Event.TimeCreated
                    EventID = $Event.Id
                    RecordID = $Event.RecordId
                    AccountName = if ($EventData.ContainsKey('TargetUserName')) { $EventData.TargetUserName } 
                                  elseif ($EventData.ContainsKey('TargetUser')) { $EventData.TargetUser }
                                  else { $AccountName }
                    SourceWorkstation = if ($EventData.ContainsKey('WorkstationName')) { $EventData.WorkstationName }
                                       elseif ($EventData.ContainsKey('IpAddress')) { $EventData.IpAddress }
                                       else { "N/A" }
                    IpAddress = if ($EventData.ContainsKey('IpAddress')) { $EventData.IpAddress } else { "N/A" }
                    LogonType = if ($EventData.ContainsKey('LogonType')) { $EventData.LogonType } else { "N/A" }
                    ServiceName = if ($EventData.ContainsKey('ServiceName')) { $EventData.ServiceName } else { "N/A" }
                    Status = if ($EventData.ContainsKey('Status')) { $EventData.Status } 
                             elseif ($EventData.ContainsKey('FailureCode')) { $EventData.FailureCode }
                             else { "Success" }
                    SubStatus = if ($EventData.ContainsKey('SubStatus')) { $EventData.SubStatus } else { "N/A" }
                    TicketOptions = if ($EventData.ContainsKey('TicketOptions')) { $EventData.TicketOptions } else { "N/A" }
                    TicketEncryptionType = if ($EventData.ContainsKey('TicketEncryptionType')) { $EventData.TicketEncryptionType } else { "N/A" }
                    ProcessName = if ($EventData.ContainsKey('ProcessName')) { $EventData.ProcessName } else { "N/A" }
                    AuthenticationPackage = if ($EventData.ContainsKey('AuthenticationPackageName')) { $EventData.AuthenticationPackageName } else { "N/A" }
                    TargetDomainName = if ($EventData.ContainsKey('TargetDomainName')) { $EventData.TargetDomainName } else { "N/A" }
                    LogonProcessName = if ($EventData.ContainsKey('LogonProcessName')) { $EventData.LogonProcessName } else { "N/A" }
                    PrivilegeList = if ($EventData.ContainsKey('PrivilegeList')) { 
                        $EventData.PrivilegeList 
                    } else { "N/A" }
                    LogonID = if ($EventData.ContainsKey('TargetLogonId')) { 
                        $EventData.TargetLogonId 
                    } else { "N/A" }
                }
            }
            
            return $ParsedEvents
        }
        
        # Execute scriptblock locally or remotely
        if ($isLocalhost) {
            Write-Verbose "Querying local event log directly..."
            $Events = & $ScriptBlock -AccountName $AccountName -DomainName $env:USERDOMAIN -StartTimeUTC $StartTime.ToUniversalTime().ToString('o') -EndTimeUTC $EndTime.ToUniversalTime().ToString('o') -EventIDs $EventIDs
        } else {
            Write-Verbose "Querying via WinRM/PowerShell Remoting..."
            $Events = Invoke-Command -ComputerName $DC -ScriptBlock $ScriptBlock -ArgumentList $AccountName, $env:USERDOMAIN, $StartTime.ToUniversalTime().ToString('o'), $EndTime.ToUniversalTime().ToString('o'), $EventIDs -ErrorAction Stop
        }
        
        Write-Host "  Found $($Events.Count) events" -ForegroundColor Green
        
        # Add DC information and event type to each event
        foreach ($Event in $Events) {
            $EventObj = [PSCustomObject]@{
                TimeCreated = $Event.TimeCreated
                DomainController = $DC
                EventID = $Event.EventID
                RecordID = $Event.RecordID
                EventType = $EventIDs[$Event.EventID]
                AccountName = $Event.AccountName
                SourceWorkstation = $Event.SourceWorkstation
                IpAddress = $Event.IpAddress
                LogonType = $Event.LogonType
                ServiceName = $Event.ServiceName
                Status = $Event.Status
                SubStatus = $Event.SubStatus
                TicketOptions = $Event.TicketOptions
                TicketEncryptionType = $Event.TicketEncryptionType
                ProcessName = $Event.ProcessName
                AuthenticationPackage = $Event.AuthenticationPackage
                TargetDomainName = $Event.TargetDomainName
                LogonProcessName = $Event.LogonProcessName
                PrivilegeList = $Event.PrivilegeList
                LogonID = $Event.LogonID
            }
            
            $AllEvents += $EventObj
        }
        
        $queryDuration = ((Get-Date) - $dcStartTime).TotalSeconds
        $DCStatus += [PSCustomObject]@{
            DomainController = $DC
            Status = "Success $(if($isLocalhost){'(Local)'}else{''})"
            EventsFound = $Events.Count
            QueryTime = "$([math]::Round($queryDuration, 2))s"
        }
        
    } catch {
        Write-Warning "Error querying $DC : $_"
        $DCStatus += [PSCustomObject]@{
            DomainController = $DC
            Status = "Error: $($_.Exception.Message)"
            EventsFound = 0
            QueryTime = "N/A"
        }
    }
}

Write-Host "`n" + "=" * 50
Write-Host "Total events collected: $($AllEvents.Count)" -ForegroundColor Green

# Analyze Failed Logons
Write-Host "`nAnalyzing failed logon attempts..." -ForegroundColor Yellow
$FailedLogons = $AllEvents | Where-Object { $_.EventID -in @(4625, 4771) }
$FailedLogonAnalysis = $FailedLogons | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventID = $_.EventID
        SourceWorkstation = $_.SourceWorkstation
        IpAddress = $_.IpAddress
        FailureReason = Get-FailureReason -Status $_.Status -SubStatus $_.SubStatus
        Status = $_.Status
        SubStatus = $_.SubStatus
    }
}

$FailedLogonByReason = $FailedLogonAnalysis | Group-Object -Property FailureReason | 
    Select-Object Name, Count | 
    Sort-Object Count -Descending

if ($FailedLogons.Count -gt 0) {
    Write-Host "  ⚠ Found $($FailedLogons.Count) failed logon attempt(s)" -ForegroundColor Yellow
    foreach ($reason in ($FailedLogonByReason | Select-Object -First 5)) {
        Write-Host "    - $($reason.Name): $($reason.Count)" -ForegroundColor Cyan
    }
} else {
    Write-Host "  ✓ No failed logon attempts detected" -ForegroundColor Green
}

# Analyze Encryption Types
Write-Host "`nAnalyzing Kerberos encryption types..." -ForegroundColor Yellow
$EncryptionEvents = $AllEvents | Where-Object { $_.TicketEncryptionType -ne 'N/A' -and $_.TicketEncryptionType -ne '' }
$EncryptionAnalysis = $EncryptionEvents | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EncryptionType = $_.TicketEncryptionType
        EncryptionName = Get-EncryptionTypeName -EncryptionType $_.TicketEncryptionType
        Risk = Get-EncryptionTypeRisk -EncryptionType $_.TicketEncryptionType
        SourceWorkstation = $_.SourceWorkstation
        ServiceName = $_.ServiceName
    }
}

$EncryptionDistribution = $EncryptionAnalysis | Group-Object -Property EncryptionName | 
    Select-Object @{N='EncryptionType';E={$_.Name}}, Count, @{N='Risk';E={(Get-EncryptionTypeRisk -EncryptionType $_.Group[0].EncryptionType)}} |
    Sort-Object Count -Descending

$WeakEncryption = $EncryptionAnalysis | Where-Object { $_.Risk -in @('CRITICAL', 'HIGH') }

if ($WeakEncryption.Count -gt 0) {
    Write-Host "  ⚠ Found $($WeakEncryption.Count) instance(s) of weak encryption!" -ForegroundColor Red
    $weakByType = $WeakEncryption | Group-Object EncryptionName
    foreach ($type in $weakByType) {
        Write-Host "    - $($type.Name): $($type.Count) occurrences" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ✓ No weak encryption detected (all AES)" -ForegroundColor Green
}

# Analyze Special Privileges (Event 4672)
Write-Host "`nAnalyzing special privilege assignments (Event 4672)..." -ForegroundColor Yellow
$PrivilegedEvents = $AllEvents | Where-Object { $_.EventID -eq 4672 }

$PrivilegedEventDetails = $PrivilegedEvents | ForEach-Object {
    $privList = if ($_.PrivilegeList -ne 'N/A') {
        ($_.PrivilegeList -split "`n" | Where-Object { $_ -match '\S' }).Trim()
    } else {
        @()
    }
    
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        DomainController = $_.DomainController
        SourceWorkstation = $_.SourceWorkstation
        LogonType = $_.LogonType
        PrivilegeList = $privList
        PrivilegeCount = $privList.Count
    }
}

$PrivilegeFrequency = $PrivilegedEventDetails | 
    ForEach-Object { $_.PrivilegeList } | 
    Group-Object | 
    Select-Object Name, Count | 
    Sort-Object Count -Descending

$PrivilegesByWorkstation = $PrivilegedEventDetails | 
    Group-Object -Property SourceWorkstation | 
    Select-Object Name, Count, @{
        N='UniquePrivileges';
        E={($_.Group | ForEach-Object { $_.PrivilegeList } | Select-Object -Unique).Count}
    } |
    Sort-Object Count -Descending

if ($PrivilegedEvents.Count -gt 0) {
    Write-Host "  ⚠ Found $($PrivilegedEvents.Count) privileged logon(s)" -ForegroundColor Yellow
    Write-Host "  Most frequently assigned privileges:" -ForegroundColor Cyan
    foreach ($priv in ($PrivilegeFrequency | Select-Object -First 5)) {
        Write-Host "    - $($priv.Name): $($priv.Count) times" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ✓ No special privilege assignments detected" -ForegroundColor Green
}

# Generate Statistics
$Stats = @{
    TotalEvents = $AllEvents.Count
    DateRange = "$($StartTime.ToString('yyyy-MM-dd')) to $($EndTime.ToString('yyyy-MM-dd'))"
    AccountTracked = $AccountName
    AccountEnabled = $AccountInfo.Enabled
    PasswordLastSet = if ($AccountInfo.PasswordLastSet) { $AccountInfo.PasswordLastSet.ToString('yyyy-MM-dd HH:mm') } else { "N/A" }
    PasswordAge = if ($AccountInfo.PasswordLastSet) { [math]::Round(((Get-Date) - $AccountInfo.PasswordLastSet).TotalDays) } else { 0 }
    LastLogonDate = if ($AccountInfo.LastLogonDate) { $AccountInfo.LastLogonDate.ToString('yyyy-MM-dd HH:mm') } else { "N/A" }
    PasswordNeverExpires = $AccountInfo.PasswordNeverExpires
    SPNCount = $AccountInfo.SPNCount
    PrivilegedGroupCount = $PrivilegedGroups.Count
    DomainControllersQueried = $DomainControllers.Count
    UniqueSourceIPs = ($AllEvents | Where-Object { $_.IpAddress -ne 'N/A' -and $_.IpAddress -ne '::1' -and $_.IpAddress -ne '127.0.0.1' } | Select-Object -ExpandProperty IpAddress -Unique).Count
    UniqueWorkstations = ($AllEvents | Where-Object { $_.SourceWorkstation -ne 'N/A' -and $_.SourceWorkstation -ne '-' } | Select-Object -ExpandProperty SourceWorkstation -Unique).Count
    KerberosEvents = ($AllEvents | Where-Object { $_.EventID -in @(4768, 4769, 4770, 4771) }).Count
    NTLMEvents = ($AllEvents | Where-Object { $_.EventID -eq 4776 }).Count
    LogonEvents = ($AllEvents | Where-Object { $_.EventID -eq 4624 }).Count
    FailedEvents = $FailedLogons.Count
    InteractiveLogons = ($AllEvents | Where-Object { $_.LogonType -eq '2' }).Count
    NetworkLogons = ($AllEvents | Where-Object { $_.LogonType -eq '3' }).Count
    RemoteInteractiveLogons = ($AllEvents | Where-Object { $_.LogonType -eq '10' }).Count
    ServiceLogons = ($AllEvents | Where-Object { $_.LogonType -eq '5' }).Count
    BatchLogons = ($AllEvents | Where-Object { $_.LogonType -eq '4' }).Count
    PrivilegedLogons = $PrivilegedEvents.Count
    WeakEncryptionCount = $WeakEncryption.Count
}

# Calculate Risk Score
Write-Host "`nCalculating risk score..." -ForegroundColor Yellow
$RiskAssessment = Calculate-RiskScore -AccountInfo $AccountInfo -Stats $Stats -PrivilegedGroups $PrivilegedGroups -EncryptionIssues $WeakEncryption

Write-Host "  Risk Score: $($RiskAssessment.TotalScore)/100 - $($RiskAssessment.OverallRisk)" -ForegroundColor $(
    switch ($RiskAssessment.OverallRisk) {
        'CRITICAL' { 'Red' }
        'HIGH' { 'Yellow' }
        'MEDIUM' { 'Cyan' }
        default { 'Green' }
    }
)

# Logon Type Distribution
$LogonTypeDistribution = $AllEvents | Where-Object { $_.LogonType -ne 'N/A' } | 
    Group-Object -Property LogonType | 
    Select-Object @{N='LogonType';E={$_.Name}}, @{N='Description';E={Get-LogonTypeDescription -LogonType $_.Name}}, Count | 
    Sort-Object Count -Descending

# Event Type Distribution
$EventTypeDistribution = $AllEvents | Group-Object -Property EventType | Select-Object Name, Count | Sort-Object Count -Descending

# Service Name Distribution
$ServiceNameDistribution = $AllEvents | 
    Where-Object { $_.ServiceName -ne 'N/A' -and $_.ServiceName -ne '' } | 
    Group-Object -Property ServiceName | 
    Select-Object Name, Count | 
    Sort-Object Count -Descending |
    Select-Object -First 15

# Timeline Data
if ($AllEvents.Count -gt 0) {
    $grouped = $AllEvents | Group-Object -Property { $_.TimeCreated.Date.ToString('yyyy-MM-dd') }
    $TimelineData = $grouped | ForEach-Object {
        [PSCustomObject]@{
            DateString = $_.Name
            DateDisplay = ([DateTime]::Parse($_.Name)).ToString('MM/dd')
            Count = $_.Count
        }
    } | Sort-Object DateString
    
    Write-Host "`nTimeline: $($TimelineData.Count) days with activity" -ForegroundColor Cyan
} else {
    $TimelineData = @()
}

# Top Source Workstations
$TopWorkstations = $AllEvents | Where-Object { $_.SourceWorkstation -ne 'N/A' -and $_.SourceWorkstation -ne '-' } |
    Group-Object -Property SourceWorkstation | 
    Select-Object Name, Count | 
    Sort-Object Count -Descending | 
    Select-Object -First 10

# Events by Hour of Day
$HourlyDistribution = $AllEvents | Group-Object -Property { $_.TimeCreated.Hour } |
    Select-Object @{N='Hour';E={$_.Name}}, Count |
    Sort-Object Hour

# Weak Encryption by Workstation and Service
$WeakEncByWorkstation = $WeakEncryption | 
    Group-Object -Property SourceWorkstation | 
    Select-Object Name, Count, @{N='EncryptionTypes';E={($_.Group | Select-Object -ExpandProperty EncryptionName -Unique) -join ', '}} |
    Sort-Object Count -Descending

$WeakEncByService = $WeakEncryption | 
    Where-Object { $_.ServiceName -ne 'N/A' -and $_.ServiceName -ne '' } |
    Group-Object -Property ServiceName | 
    Select-Object Name, Count, @{N='EncryptionTypes';E={($_.Group | Select-Object -ExpandProperty EncryptionName -Unique) -join ', '}} |
    Sort-Object Count -Descending

$RC4Systems = $WeakEncryption | Where-Object { $_.EncryptionName -like '*RC4*' } | 
    Group-Object -Property SourceWorkstation |
    Select-Object Name, Count |
    Sort-Object Count -Descending

$DESystems = $WeakEncryption | Where-Object { $_.EncryptionName -like '*DES*' } | 
    Group-Object -Property SourceWorkstation |
    Select-Object Name, Count |
    Sort-Object Count -Descending

Write-Host "`n✓ Data collection complete. Generating HTML report..." -ForegroundColor Green

# Prepare privileged events for table
$PrivilegedEventsForTable = $PrivilegedEventDetails | Sort-Object TimeCreated -Descending | Select-Object -First 100

# Start HTML Report generation
$HtmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Admin Usage Report - $AccountName</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
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
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .risk-banner {
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            font-size: 1.2em;
            font-weight: bold;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .risk-critical {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
            color: white;
        }
        
        .risk-high {
            background: linear-gradient(135deg, #ffc107 0%, #ff9800 100%);
            color: #333;
        }
        
        .risk-medium {
            background: linear-gradient(135deg, #17a2b8 0%, #138496 100%);
            color: white;
        }
        
        .risk-low {
            background: linear-gradient(135deg, #28a745 0%, #218838 100%);
            color: white;
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
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .stat-card h3 {
            color: #667eea;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }
        
        .section {
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 25px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .section h3 {
            color: #667eea;
            margin-top: 20px;
            margin-bottom: 10px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        tr:hover {
            background: #f8f9ff;
        }
        
        .filter-container {
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .filter-container input,
        .filter-container select {
            padding: 10px 15px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        .filter-container input:focus,
        .filter-container select:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .filter-container label {
            font-weight: 600;
            color: #555;
        }
        
        .badge {
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            display: inline-block;
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
        
        .badge-critical {
            background: #dc3545;
            color: white;
        }
        
        .badge-high {
            background: #ffc107;
            color: #333;
        }
        
        .badge-medium {
            background: #17a2b8;
            color: white;
        }
        
        .badge-low {
            background: #28a745;
            color: white;
        }
        
        .chart-container {
            margin: 20px 0;
            height: 300px;
            min-height: 300px;
            position: relative;
        }
        
        .chart-container canvas {
            max-height: 300px;
        }
        
        .grid-2 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 25px;
            margin-bottom: 25px;
        }
        
        .status-success {
            color: #28a745;
            font-weight: 600;
        }
        
        .status-error {
            color: #dc3545;
            font-weight: 600;
        }
        
        .status-warning {
            color: #ffc107;
            font-weight: 600;
        }
        
        .export-btn {
            background: #667eea;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: background 0.3s;
        }
        
        .export-btn:hover {
            background: #764ba2;
        }
        
        .no-data {
            text-align: center;
            padding: 40px;
            color: #999;
            font-style: italic;
        }
        
        .recommendation-box {
            margin-top: 20px;
            padding: 15px;
            border-left: 4px solid #667eea;
            background: #f8f9ff;
            border-radius: 5px;
        }
        
        .recommendation-box h4 {
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .recommendation-box ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        
        .recommendation-box li {
            margin: 5px 0;
        }
        
        .recommendation-box ol {
            margin: 10px 0;
            padding-left: 20px;
        }
        
        .recommendation-box code {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        @media print {
            .filter-container, .export-btn {
                display: none;
            }
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Domain Admin Usage Report</h1>
            <div class="subtitle">
                Account: <strong>$AccountName</strong> | 
                Period: <strong>$($Stats.DateRange)</strong> | 
                Generated: <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong>
            </div>
        </header>
        
        <!-- Risk Assessment Banner -->
        <div class="risk-banner risk-$($RiskAssessment.OverallRisk.ToLower())">
            🛡️ RISK ASSESSMENT: $($RiskAssessment.OverallRisk) RISK - Score: $($RiskAssessment.TotalScore)/100
        </div>
        
        <!-- Risk Factors Section -->
        <div class="section">
            <h2>⚠️ Risk Analysis & Recommendations</h2>
"@

if ($RiskAssessment.RiskFactors.Count -gt 0) {
    $HtmlReport += @"
            <table>
                <thead>
                    <tr>
                        <th>Risk Factor</th>
                        <th>Severity</th>
                        <th>Score</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
"@
    foreach ($factor in $RiskAssessment.RiskFactors) {
        $HtmlReport += @"
                    <tr>
                        <td>$($factor.Factor)</td>
                        <td><span class="badge badge-$($factor.Severity.ToLower())">$($factor.Severity)</span></td>
                        <td><strong>+$($factor.Score)</strong></td>
                        <td>$($factor.Recommendation)</td>
                    </tr>
"@
    }
    $HtmlReport += @"
                </tbody>
            </table>
"@
} else {
    $HtmlReport += @"
            <p style="text-align: center; padding: 40px; color: #28a745; font-size: 1.2em;">
                ✓ No significant risk factors detected for this account
            </p>
"@
}

$HtmlReport += @"
        </div>
        
        <!-- Executive Dashboard -->
        <div class="dashboard">
            <div class="stat-card">
                <h3>Total Events</h3>
                <div class="stat-value">$($Stats.TotalEvents)</div>
            </div>
            <div class="stat-card">
                <h3>Risk Score</h3>
                <div class="stat-value" style="color: $(
                    switch ($RiskAssessment.OverallRisk) {
                        'CRITICAL' { '#dc3545' }
                        'HIGH' { '#ffc107' }
                        'MEDIUM' { '#17a2b8' }
                        default { '#28a745' }
                    }
                )">$($RiskAssessment.TotalScore)</div>
                <small>$($RiskAssessment.OverallRisk) Risk</small>
            </div>
            <div class="stat-card">
                <h3>Password Age</h3>
                <div class="stat-value" style="color: $(if ($Stats.PasswordAge -gt 365) { '#dc3545' } elseif ($Stats.PasswordAge -gt 180) { '#ffc107' } else { '#28a745' })">$($Stats.PasswordAge)</div>
                <small>days old</small>
            </div>
            <div class="stat-card">
                <h3>Privileged Groups</h3>
                <div class="stat-value" style="color: $(if ($Stats.PrivilegedGroupCount -gt 0) { '#ffc107' } else { '#28a745' })">$($Stats.PrivilegedGroupCount)</div>
                <small>memberships</small>
            </div>
            <div class="stat-card">
                <h3>Kerberos Events</h3>
                <div class="stat-value">$($Stats.KerberosEvents)</div>
            </div>
            <div class="stat-card">
                <h3>NTLM Events</h3>
                <div class="stat-value">$($Stats.NTLMEvents)</div>
            </div>
            <div class="stat-card">
                <h3>Failed Attempts</h3>
                <div class="stat-value" style="color: $(if ($Stats.FailedEvents -gt 50) { '#dc3545' } elseif ($Stats.FailedEvents -gt 10) { '#ffc107' } else { '#28a745' })">$($Stats.FailedEvents)</div>
            </div>
            <div class="stat-card">
                <h3>Weak Encryption</h3>
                <div class="stat-value" style="color: $(if ($Stats.WeakEncryptionCount -gt 0) { '#dc3545' } else { '#28a745' })">$($Stats.WeakEncryptionCount)</div>
                <small>DES/RC4 instances</small>
            </div>
            <div class="stat-card">
                <h3>SPNs Configured</h3>
                <div class="stat-value">$($Stats.SPNCount)</div>
                $(if ($Stats.SPNCount -gt 0) {
                    '<small style="color: #ffc107;">⚠ Service Account</small>'
                } else {
                    '<small style="color: #6c757d;">Regular Account</small>'
                })
            </div>
            <div class="stat-card">
                <h3>Interactive Logons</h3>
                <div class="stat-value" style="color: $(if ($Stats.InteractiveLogons -gt 0) { '#dc3545' } else { '#28a745' })">$($Stats.InteractiveLogons)</div>
                <small>Type 2 - Local</small>
            </div>
            <div class="stat-card">
                <h3>RDP Logons</h3>
                <div class="stat-value" style="color: $(if ($Stats.RemoteInteractiveLogons -gt 0) { '#dc3545' } else { '#28a745' })">$($Stats.RemoteInteractiveLogons)</div>
                <small>Type 10 - Remote Desktop</small>
            </div>
            <div class="stat-card">
                <h3>Privileged Logons</h3>
                <div class="stat-value">$($Stats.PrivilegedLogons)</div>
                <small>Event 4672</small>
            </div>
            <div class="stat-card">
                <h3>Unique Privileges</h3>
                <div class="stat-value">$(if ($PrivilegeFrequency) { $PrivilegeFrequency.Count } else { 0 })</div>
                <small>Different privileges</small>
            </div>
        </div>
        
        <!-- Account Information Section -->
        <div class="section">
            <h2>👤 Account Information</h2>
            <div class="grid-2">
                <div>
                    <table>
                        <tr>
                            <th style="width: 200px;">Property</th>
                            <th>Value</th>
                        </tr>
                        <tr>
                            <td><strong>Account Name</strong></td>
                            <td>$($AccountInfo.AccountName)</td>
                        </tr>
                        <tr>
                            <td><strong>Distinguished Name</strong></td>
                            <td style="font-size: 0.9em;">$($AccountInfo.DistinguishedName)</td>
                        </tr>
                        <tr>
                            <td><strong>Account Status</strong></td>
                            <td>
                                $(if ($AccountInfo.Enabled) { 
                                    '<span class="badge badge-success">✓ Enabled</span>' 
                                } else { 
                                    '<span class="badge badge-danger">✗ Disabled</span>' 
                                })
                            </td>
                        </tr>
                        <tr>
                            <td><strong>Created</strong></td>
                            <td>$(if ($AccountInfo.WhenCreated) { $AccountInfo.WhenCreated.ToString('yyyy-MM-dd HH:mm') } else { 'N/A' })</td>
                        </tr>
                        <tr>
                            <td><strong>Password Last Set</strong></td>
                            <td>
                                $($Stats.PasswordLastSet)
                                $(if ($Stats.PasswordAge -gt 365) {
                                    '<span class="badge badge-danger">⚠ Very Old</span>'
                                } elseif ($Stats.PasswordAge -gt 180) {
                                    '<span class="badge badge-warning">⚠ Old</span>'
                                })
                            </td>
                        </tr>
                        <tr>
                            <td><strong>Password Age</strong></td>
                            <td><strong>$($Stats.PasswordAge) days</strong></td>
                        </tr>
                        <tr>
                            <td><strong>Password Never Expires</strong></td>
                            <td>
                                $(if ($AccountInfo.PasswordNeverExpires) {
                                    '<span class="badge badge-danger">YES - High Risk</span>'
                                } else {
                                    '<span class="badge badge-success">No</span>'
                                })
                            </td>
                        </tr>
                        <tr>
                            <td><strong>Admin Count</strong></td>
                            <td>
                                $(if ($AccountInfo.AdminCount -eq 1) {
                                    '<span class="badge badge-warning">1 - Protected Account</span>'
                                } else {
                                    '0 - Regular Account'
                                })
                            </td>
                        </tr>
                        <tr>
                            <td><strong>Last Logon (AD)</strong></td>
                            <td>$($Stats.LastLogonDate)</td>
                        </tr>
                        <tr>
                            <td><strong>Service Principal Names</strong></td>
                            <td>
                                <strong>$($Stats.SPNCount) SPN(s)</strong>
                                $(if ($Stats.SPNCount -gt 0) {
                                    '<span class="badge badge-warning">⚠ Service Account Indicator</span>'
                                })
                            </td>
                        </tr>
                    </table>
                </div>
                <div>
                    <h3 style="margin-top: 0;">Privileged Group Memberships</h3>
                    $(if ($PrivilegedGroups.Count -gt 0) {
                        "<table><thead><tr><th>Group Name (Localized)</th><th>English Name</th><th>Risk Level</th><th>SID</th></tr></thead><tbody>"
                        foreach ($group in $PrivilegedGroups) {
                            "<tr>
                                <td><strong>$($group.GroupName)</strong></td>
                                <td style='font-family: monospace; font-size: 0.9em;'>$($group.EnglishName)</td>
                                <td><span class='badge badge-$($group.RiskLevel.ToLower())'>$($group.RiskLevel)</span></td>
                                <td style='font-family: monospace; font-size: 0.85em;'>$($group.SID)</td>
                            </tr>"
                        }
                        "</tbody></table>"
                        if ($AccountInfo.AdminCount -eq 1) {
                            "<p style='margin-top: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 5px;'>
                                <strong>ℹ️ Note:</strong> adminCount = 1 indicates this account has AdminSDHolder protection, 
                                meaning it is or was a member of a privileged group. Even if removed from privileged groups, 
                                the account retains certain security settings.
                            </p>"
                        }
                    } else {
                        "<p style='color: #999; font-style: italic;'>No privileged group memberships detected.</p>"
                        if ($AccountInfo.AdminCount -eq 1) {
                            "<p style='margin-top: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 5px;'>
                                <strong>⚠️ Warning:</strong> adminCount = 1 but no current privileged group memberships detected. 
                                This account <strong>was previously a member of a privileged group</strong> and still has AdminSDHolder protection.
                                Consider reviewing account permissions and inheritance.
                            </p>"
                        }
                    })
                    
                    <h3 style="margin-top: 20px;">Configured SPNs</h3>
                    $(if ($AccountInfo.SPNCount -gt 0) {
                        "<ul style='margin: 10px 0; padding-left: 20px;'>"
                        foreach ($spn in $AccountInfo.SPNs) {
                            "<li style='margin: 5px 0; font-family: monospace; font-size: 0.9em;'>$spn</li>"
                        }
                        "</ul>"
                    } else {
                        "<p style='color: #999; font-style: italic;'>No SPNs configured on this account.</p>"
                    })
                </div>
            </div>
        </div>
"@

# Include Failed Logon Analysis section if there are failed logons
if ($FailedLogons.Count -gt 0) {
    $HtmlReport += @"
        <div class="section">
            <h2>🚫 Failed Logon Analysis</h2>
            <p style="margin-bottom: 20px;">
                <strong>$($FailedLogons.Count) failed logon attempt(s)</strong> detected. 
                High numbers may indicate brute force attacks, misconfigured services, or orphaned credentials.
            </p>
            
            <div class="grid-2">
                <div class="chart-container">
                    <canvas id="failedLogonChart"></canvas>
                </div>
                <div>
                    <h3>Failed Logons by Reason</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Failure Reason</th>
                                <th>Count</th>
                            </tr>
                        </thead>
                        <tbody>
"@
    foreach ($reason in $FailedLogonByReason) {
        $HtmlReport += @"
                            <tr>
                                <td>$($reason.Name)</td>
                                <td><strong>$($reason.Count)</strong></td>
                            </tr>
"@
    }
    $HtmlReport += @"
                        </tbody>
                    </table>
                    
                    <div class="recommendation-box">
                        <h4>⚠️ Interpretation</h4>
                        <ul>
                            <li><strong>"Wrong password":</strong> May indicate attack or user error</li>
                            <li><strong>"Account disabled/locked":</strong> Expected if account was disabled</li>
                            <li><strong>"Time restriction":</strong> Service trying to authenticate outside allowed hours</li>
                            <li><strong>Spikes in failures:</strong> Investigate for potential attacks</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
"@
}

# Include Encryption Analysis section if there are encryption events
if ($EncryptionAnalysis.Count -gt 0) {
    $HtmlReport += @"
        <div class="section">
            <h2>🔐 Kerberos Encryption Analysis</h2>
            <p style="margin-bottom: 20px;">
                Encryption type analysis reveals security posture. <strong>DES and RC4 are weak and deprecated</strong> - 
                all Kerberos authentication should use AES encryption.
            </p>
            
            <div class="grid-2">
                <div class="chart-container">
                    <canvas id="encryptionChart"></canvas>
                </div>
                <div>
                    <h3>Encryption Types Used</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Encryption Type</th>
                                <th>Risk</th>
                                <th>Count</th>
                            </tr>
                        </thead>
                        <tbody>
"@
    foreach ($enc in $EncryptionDistribution) {
        $HtmlReport += @"
                            <tr>
                                <td style="font-family: monospace;">$($enc.EncryptionType)</td>
                                <td><span class="badge badge-$($enc.Risk.ToLower())">$($enc.Risk)</span></td>
                                <td><strong>$($enc.Count)</strong></td>
                            </tr>
"@
    }
    
    $riskBoxColor = if ($WeakEncryption.Count -gt 0) { '#dc3545' } else { '#28a745' }
    $riskBoxText = if ($WeakEncryption.Count -gt 0) { '⚠️ Security Risk' } else { '✓ Good Security' }
    $riskBoxContent = if ($WeakEncryption.Count -gt 0) {
        "<ul>
            <li><strong>Action Required:</strong> $($WeakEncryption.Count) weak encryption instance(s) detected</li>
            <li>Configure clients/services to use AES encryption</li>
            <li>Set msDS-SupportedEncryptionTypes to 0x18 (AES only)</li>
            <li>DES and RC4 are vulnerable to offline attacks</li>
        </ul>"
    } else {
        "<p style='color: #28a745;'>✓ All authentication using strong encryption (AES)</p>"
    }
    
    $HtmlReport += @"
                        </tbody>
                    </table>
                    
                    <div class="recommendation-box" style="border-left-color: $riskBoxColor;">
                        <h4>$riskBoxText</h4>
                        $riskBoxContent
                    </div>
                </div>
            </div>
"@

    # Weak Encryption Breakdown by System
    if ($WeakEncryption.Count -gt 0) {
        $HtmlReport += @"
            
            <h3 style="margin-top: 30px; color: #dc3545;">⚠️ Systems Using Weak Encryption - REMEDIATION REQUIRED</h3>
            <p style="margin-bottom: 20px;">
                The following systems are using deprecated encryption algorithms and should be reconfigured to use AES.
                This typically indicates legacy applications, outdated operating systems, or misconfigured services.
            </p>
            
            <div class="grid-2">
                <div>
                    <h3>🖥️ Source Workstations/Servers Using Weak Crypto</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Source System</th>
                                <th>Weak Encryption Type(s)</th>
                                <th>Instances</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($system in $WeakEncByWorkstation) {
            $actionBadge = if ($system.Count -gt 10) { 'badge-danger' } elseif ($system.Count -gt 5) { 'badge-warning' } else { 'badge-info' }
            $actionText = if ($system.Count -gt 10) { 'URGENT' } elseif ($system.Count -gt 5) { 'High Priority' } else { 'Normal' }
            
            $HtmlReport += @"
                            <tr>
                                <td><strong>$($system.Name)</strong></td>
                                <td style="font-family: monospace; font-size: 0.9em;">$($system.EncryptionTypes)</td>
                                <td><span class="badge $actionBadge">$($system.Count)</span></td>
                                <td style="font-size: 0.85em;">$actionText</td>
                            </tr>
"@
        }
        
        $HtmlReport += @"
                        </tbody>
                    </table>
                </div>
"@
        
        if ($WeakEncByService.Count -gt 0) {
            $HtmlReport += @"
                
                <div>
                    <h3>🎫 Services Accessed with Weak Crypto</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Service Name (SPN)</th>
                                <th>Encryption Type(s)</th>
                                <th>Instances</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            
            foreach ($service in $WeakEncByService) {
                $HtmlReport += @"
                            <tr>
                                <td style="font-family: monospace; font-size: 0.9em;">$($service.Name)</td>
                                <td style="font-family: monospace; font-size: 0.9em;">$($service.EncryptionTypes)</td>
                                <td><strong>$($service.Count)</strong></td>
                            </tr>
"@
            }
            
            $HtmlReport += @"
                        </tbody>
                    </table>
                </div>
"@
        } else {
            $HtmlReport += @"
                
                <div>
                    <h3>🎫 Services Accessed with Weak Crypto</h3>
                    <p style="text-align: center; padding: 40px; color: #999; font-style: italic;">
                        No service name data available for weak encryption events
                    </p>
                </div>
"@
        }
        
        $HtmlReport += @"
            </div>
            
            <!-- Breakdown by Encryption Type -->
            <div class="grid-2" style="margin-top: 25px;">
"@
        
        if ($RC4Systems.Count -gt 0) {
            $HtmlReport += @"
                <div>
                    <div class="recommendation-box" style="border-left-color: #ffc107; background: #fff3cd;">
                        <h4 style="color: #856404;">⚠️ RC4-HMAC Usage ($($RC4Systems.Count) system(s))</h4>
                        <p style="font-size: 0.9em; color: #856404; margin: 10px 0;">
                            RC4 is deprecated since 2013 and vulnerable to attacks. Microsoft disabled it by default in Windows Server 2008 R2+.
                        </p>
                        <table style="margin-top: 10px;">
                            <thead>
                                <tr style="background: #856404;">
                                    <th>System</th>
                                    <th>RC4 Events</th>
                                </tr>
                            </thead>
                            <tbody>
"@
            
            foreach ($system in ($RC4Systems | Select-Object -First 10)) {
                $HtmlReport += @"
                                <tr>
                                    <td>$($system.Name)</td>
                                    <td><strong>$($system.Count)</strong></td>
                                </tr>
"@
            }
            
            $HtmlReport += @"
                            </tbody>
                        </table>
                        <p style="margin-top: 10px; font-size: 0.9em; color: #856404;">
                            <strong>Fix:</strong> Update client OS, configure registry to disable RC4, or upgrade applications.
                        </p>
                    </div>
                </div>
"@
        }
        
        if ($DESystems.Count -gt 0) {
            $HtmlReport += @"
                <div>
                    <div class="recommendation-box" style="border-left-color: #dc3545; background: #f8d7da;">
                        <h4 style="color: #721c24;">🚨 DES Usage ($($DESystems.Count) system(s))</h4>
                        <p style="font-size: 0.9em; color: #721c24; margin: 10px 0;">
                            DES is extremely weak (56-bit key) and should NEVER be used. This is a critical security vulnerability.
                        </p>
                        <table style="margin-top: 10px;">
                            <thead>
                                <tr style="background: #721c24;">
                                    <th>System</th>
                                    <th>DES Events</th>
                                </tr>
                            </thead>
                            <tbody>
"@
            
            foreach ($system in ($DESystems | Select-Object -First 10)) {
                $HtmlReport += @"
                                <tr>
                                    <td>$($system.Name)</td>
                                    <td><strong>$($system.Count)</strong></td>
                                </tr>
"@
            }
            
            $HtmlReport += @"
                            </tbody>
                        </table>
                        <p style="margin-top: 10px; font-size: 0.9em; color: #721c24;">
                            <strong>Fix:</strong> Likely legacy systems - upgrade OS immediately or isolate from network.
                        </p>
                    </div>
                </div>
"@
        }
        
        $HtmlReport += @"
            </div>
            
            <!-- Remediation Guide -->
            <div class="recommendation-box" style="margin-top: 25px; border-left-color: #667eea;">
                <h4 style="color: #667eea;">🔧 Remediation Steps</h4>
                <ol style="margin: 10px 0 10px 20px;">
                    <li><strong>Identify the systems:</strong> Use the tables above to identify which systems are using weak encryption</li>
                    <li><strong>Check OS version:</strong> RC4/DES usage often indicates Windows Server 2003/2008 or older Windows clients</li>
                    <li><strong>Update msDS-SupportedEncryptionTypes:</strong>
                        <ul style="margin: 5px 0 5px 20px;">
                            <li>For the service account: <code>Set-ADUser `$AccountName -Replace @{'msDS-SupportedEncryptionTypes'=24}</code></li>
                            <li>Value 24 = 0x18 = AES128 + AES256 only</li>
                        </ul>
                    </li>
                    <li><strong>Configure clients:</strong> Ensure client systems support AES (Windows Vista+ / Server 2008+)</li>
                    <li><strong>Registry fix for legacy apps:</strong> 
                        <ul style="margin: 5px 0 5px 20px;">
                            <li>Path: <code>HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters</code></li>
                            <li>Value: <code>DefaultEncryptionType = 0x12</code> (AES256)</li>
                        </ul>
                    </li>
                    <li><strong>Test before full deployment:</strong> Monitor authentication after changes to ensure no breakage</li>
                    <li><strong>Plan legacy system upgrades:</strong> Systems that can't support AES should be upgraded or decommissioned</li>
                </ol>
                <p style="margin-top: 10px; padding: 10px; background: #fff3cd; border-radius: 5px; color: #856404;">
                    <strong>⚠️ Warning:</strong> Changing encryption settings can break authentication for legacy applications. 
                    Test thoroughly in a non-production environment first, and have a rollback plan.
                </p>
            </div>
"@
    }
    
    $HtmlReport += @"
        </div>
"@
}

# Include Logon Type Analysis section
$HtmlReport += @"
        <div class="section">
            <h2>🔐 Logon Type Analysis</h2>
            <p style="margin-bottom: 20px;">
                Understanding logon types helps identify how the account is being used:
                <strong>Interactive (Type 2)</strong> and <strong>RemoteInteractive (Type 10)</strong> indicate human usage,
                while <strong>Network (Type 3)</strong> and <strong>Service (Type 5)</strong> typically indicate automated/service usage.
            </p>
            
            <div class="grid-2">
                <div class="chart-container">
                    <canvas id="logonTypeChart"></canvas>
                </div>
                <div>
                    <table>
                        <thead>
                            <tr>
                                <th>Logon Type</th>
                                <th>Description</th>
                                <th>Count</th>
                                <th>%</th>
                            </tr>
                        </thead>
                        <tbody>
"@

foreach ($logonType in $LogonTypeDistribution) {
    $percentage = if ($Stats.TotalEvents -gt 0) { [math]::Round(($logonType.Count / $Stats.TotalEvents) * 100, 1) } else { 0 }
    $badge = switch ($logonType.LogonType) {
        "2"  { "badge-danger" }
        "10" { "badge-danger" }
        "3"  { "badge-warning" }
        "5"  { "badge-info" }
        "4"  { "badge-info" }
        default { "badge-info" }
    }
    
    $HtmlReport += @"
                            <tr>
                                <td><span class="badge $badge">Type $($logonType.LogonType)</span></td>
                                <td>$($logonType.Description)</td>
                                <td><strong>$($logonType.Count)</strong></td>
                                <td>$percentage%</td>
                            </tr>
"@
}

$HtmlReport += @"
                        </tbody>
                    </table>
                    
                    <div class="recommendation-box" style="border-left-color: $(if ($Stats.InteractiveLogons -gt 0 -or $Stats.RemoteInteractiveLogons -gt 0) { '#dc3545' } else { '#28a745' });">
                        <h4>⚠️ Interpretation Guide</h4>
                        <ul>
                            <li><strong>High Interactive/RDP logons:</strong> Account is actively used by humans</li>
                            <li><strong>High Network/Service logons:</strong> Likely service account usage (check SPNs)</li>
                            <li><strong>Legacy admin account:</strong> Should have minimal to zero interactive logons</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
"@

# Include Service Name Distribution if applicable
if ($ServiceNameDistribution.Count -gt 0) {
    $HtmlReport += @"
        <div class="section">
            <h2>🎫 Kerberos Service Ticket Requests</h2>
            <p style="margin-bottom: 20px;">
                Shows which services this account is requesting tickets for. For service accounts with SPNs, 
                this indicates which services are authenticating <strong>TO</strong> this account.
            </p>
            <div class="grid-2">
                <div class="chart-container">
                    <canvas id="serviceNameChart"></canvas>
                </div>
                <div>
                    <table>
                        <thead>
                            <tr>
                                <th>Service Name</th>
                                <th>Requests</th>
                            </tr>
                        </thead>
                        <tbody>
"@
    foreach ($service in $ServiceNameDistribution) {
        $HtmlReport += @"
                            <tr>
                                <td style="font-family: monospace; font-size: 0.9em;">$($service.Name)</td>
                                <td><strong>$($service.Count)</strong></td>
                            </tr>
"@
    }
    $HtmlReport += @"
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
"@
}

# Include Privileged Operations (Event 4672) section
if ($PrivilegedEvents.Count -gt 0) {
    $HtmlReport += @"
        <div class="section">
            <h2>🔑 Privileged Operations Analysis (Event 4672)</h2>
            <p style="margin-bottom: 20px;">
                <strong>$($PrivilegedEvents.Count) logon(s)</strong> where special privileges were assigned to the account.
                Event 4672 is logged when an account is assigned sensitive privileges that allow privileged operations.
            </p>
            
    <!-- Privilege Tables - Stacked Layout -->
                <div style="display: block;">
                    <div style="margin-bottom: 30px;">
                        <h3>Most Frequently Assigned Privileges</h3>
                        <div style="overflow-x: auto;">
                        <table>
                        <thead>
                            <tr>
                                <th>Privilege</th>
                                <th>Description</th>
                                <th>Risk</th>
                                <th>Count</th>
                            </tr>
                        </thead>
                        <tbody>
"@
    
    foreach ($priv in ($PrivilegeFrequency | Select-Object -First 10)) {
        $description = Get-PrivilegeDescription -Privilege $priv.Name
        $risk = Get-PrivilegeRiskLevel -Privilege $priv.Name
        $badgeClass = switch ($risk) {
            'CRITICAL' { 'badge-danger' }
            'HIGH' { 'badge-warning' }
            default { 'badge-info' }
        }
        $HtmlReport += @"
                            <tr>
                                <td style="font-family: monospace; font-size: 0.85em;">$($priv.Name)</td>
                                <td style="font-size: 0.9em;">$description</td>
                                <td><span class="badge $badgeClass">$risk</span></td>
                                <td><strong>$($priv.Count)</strong></td>
                            </tr>
"@
    }
    
    $HtmlReport += @"
                        </tbody>
                    </table>
                    </table>
                    </div>
                </div>
                <div style="margin-bottom: 30px;">
                    <h3>Systems Where Privileges Were Assigned</h3>
                    <div style="overflow-x: auto;">
                    <table>                        
                         <thead>
                            <tr>
                                <th>Domain Controller</th>
                                <th>Privileged Logons</th>
                                <th>Unique Privileges</th>
                            </tr>
                        </thead>
                        <tbody>
"@
    
    $PrivilegesByDC = $PrivilegedEventDetails | 
        Group-Object -Property DomainController | 
        Select-Object Name, Count, @{N='UniquePrivileges';E={($_.Group | ForEach-Object { $_.PrivilegeList } | Select-Object -Unique).Count}} |
        Sort-Object Count -Descending
    
    foreach ($dc in ($PrivilegesByDC | Select-Object -First 10)) {
        $HtmlReport += @"
                            <tr>
                                <td><strong>$($dc.Name)</strong></td>
                                <td>$($dc.Count)</td>
                                <td>$($dc.UniquePrivileges)</td>
                            </tr>
"@
    }
    
    $HtmlReport += @"
                        </tbody>
                    </table>
                </div>
            </div>
            </div>
            
            <!-- Information Box Below Tables -->
            <div class="recommendation-box" style="margin-top: 20px;">
                <h4>ℹ️ Understanding Event 4672</h4>
                <ul style="font-size: 0.95em;">
                    <li><strong>When:</strong> Logged immediately after successful logon (Event 4624)</li>
                    <li><strong>What:</strong> Shows special privileges assigned to the security token</li>
                    <li><strong>Where:</strong> Event occurs on the Domain Controller where authentication happened</li>
                    <li><strong>Critical Privileges:</strong> SeDebugPrivilege, SeTcbPrivilege, SeLoadDriverPrivilege</li>
                    <li><strong>Normal Admin:</strong> Domain Admins typically get 10-15 privileges automatically</li>
                </ul>
            </div>
            
            <!-- Detailed Privilege Events Table with Filters -->
            <h3 style="margin-top: 30px;">Detailed Privilege Assignment Events</h3>
            <div class="filter-container">
                <div>
                    <label for="privSearchInput">Search:</label>
                    <input type="text" id="privSearchInput" placeholder="Search in table..." style="width: 250px;">
                </div>
                <div>
                    <label for="privDCFilter">Domain Controller:</label>
                    <select id="privDCFilter">
                        <option value="">All DCs</option>
"@
    
    foreach ($dc in ($PrivilegedEventDetails | Select-Object -ExpandProperty DomainController -Unique | Sort-Object)) {
        $HtmlReport += "                        <option value=`"$dc`">$dc</option>`n"
    }
    
    $HtmlReport += @"
                    </select>
                </div>
                <div>
                    <label for="privPrivilegeFilter">Privilege:</label>
                    <select id="privPrivilegeFilter">
                        <option value="">All Privileges</option>
"@
    
    # Only show privileges that are actually in the displayed events (not all privileges)
    $PrivilegesInTable = @()
    foreach ($event in $PrivilegedEventsForTable) {
        foreach ($priv in $event.PrivilegeList) {
            if ($priv -and $priv.Trim()) {
                $PrivilegesInTable += $priv.Trim()
            }
        }
    }
    $UniqPrivilegesInTable = $PrivilegesInTable | Select-Object -Unique | Sort-Object
    
    foreach ($priv in $UniqPrivilegesInTable) {
        $HtmlReport += "                        <option value=`"$($priv)`">$($priv)</option>`n"
    }
    
    $HtmlReport += @"
                    </select>
                </div>
               <button class="export-btn" onclick="exportPrivilegeTableToCSV()">📥 Export to CSV</button>
            </div>
            
            <div style="overflow-x: auto; margin-top: 15px;">
                <table id="privilegeEventsTable">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Domain Controller</th>
                            <th>Privileges Assigned</th>
                            <th>Privilege Count</th>
                        </tr>
                    </thead>
                    <tbody>
"@
    
    foreach ($event in $PrivilegedEventsForTable) {
        $privilegesBadges = ($event.PrivilegeList | ForEach-Object {
            $risk = Get-PrivilegeRiskLevel -Privilege $_
            $badgeClass = switch ($risk) {
                'CRITICAL' { 'badge-danger' }
                'HIGH' { 'badge-warning' }
                default { 'badge-info' }
            }
            $privDesc = Get-PrivilegeDescription -Privilege $_
            "<span class='badge $badgeClass' style='margin: 2px; font-size: 0.75em; cursor: help;' title='$privDesc'>$_</span>"
        }) -join ' '
        
        # Create a pipe-delimited list of privileges for reliable filtering
        # Trim all privileges and join with pipes
        $trimmedPrivileges = @()
        foreach ($priv in $event.PrivilegeList) {
            if ($priv -and $priv.Trim()) {
                $trimmedPrivileges += $priv.Trim()
            }
        }
        $privilegesForFilter = '|' + ($trimmedPrivileges -join '|') + '|'
        
        $HtmlReport += @"
                        <tr data-dc="$($event.DomainController)" data-privileges="$privilegesForFilter">
                            <td style="white-space: nowrap; font-size: 0.9em;">$($event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                            <td><strong>$($event.DomainController)</strong></td>
                            <td style="font-size: 0.9em;">$privilegesBadges</td>
                            <td style="text-align: center;"><strong>$($event.PrivilegeCount)</strong></td>
                        </tr>
"@
    }
    
    $HtmlReport += @"
                    </tbody>
                </table>
            </div>
            
            <!-- Privilege Risk Assessment -->
            <div class="recommendation-box" style="margin-top: 25px; border-left-color: $(
                if ($PrivilegeFrequency | Where-Object { (Get-PrivilegeRiskLevel -Privilege $_.Name) -eq 'CRITICAL' }) {
                    '#dc3545'
                } else {
                    '#667eea'
                }
            );">
                <h4>🛡️ Privilege Risk Assessment</h4>
"@
    
    $criticalPrivs = $PrivilegeFrequency | Where-Object { (Get-PrivilegeRiskLevel -Privilege $_.Name) -eq 'CRITICAL' }
    if ($criticalPrivs) {
        $HtmlReport += @"
                <p style='color: #dc3545; font-weight: bold;'>⚠️ CRITICAL: This account is being assigned highly sensitive privileges:</p>
                <ul style='color: #dc3545; margin-bottom: 15px;'>
"@
        
        foreach ($priv in $criticalPrivs) {
            $privDesc = Get-PrivilegeDescription -Privilege $priv.Name
            $HtmlReport += @"
                    <li><strong>$($priv.Name):</strong> $privDesc - Used $($priv.Count) times</li>
"@
        }
        
        $HtmlReport += @"
                </ul>
                <p style='color: #721c24; margin-top: 10px;'>
                    <strong>Action Required:</strong> Accounts with these privileges have near-complete system control. 
                    Verify this is intentional and consider using separate accounts for privileged operations.
                </p>
"@
    } else {
        $HtmlReport += @"
                <p style='color: #28a745; font-weight: bold;'>✓ Good News</p>
                <p style='color: #28a745;'>No critical privileges detected. This account is using standard administrative privileges only.</p>
"@
    }
    
    $HtmlReport += @"
            </div>
        </div>
"@
}

# Include remaining chart sections
$HtmlReport += @"
        <!-- Charts Section -->
        <div class="grid-2">
            <div class="section">
                <h2>📊 Event Type Distribution</h2>
                <div class="chart-container">
                    <canvas id="eventTypeChart"></canvas>
                </div>
            </div>
            <div class="section">
                <h2>📈 Events Timeline</h2>
                <div class="chart-container">
                    <canvas id="timelineChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="grid-2">
            <div class="section">
                <h2>🖥️ Top Source Workstations</h2>
                <div class="chart-container">
                    <canvas id="workstationChart"></canvas>
                </div>
            </div>
            <div class="section">
                <h2>🕐 Events by Hour of Day</h2>
                <div class="chart-container">
                    <canvas id="hourlyChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Domain Controller Status -->
        <div class="section">
            <h2>🖧 Domain Controller Query Status</h2>
            <table>
                <thead>
                    <tr>
                        <th>Domain Controller</th>
                        <th>Status</th>
                        <th>Events Found</th>
                        <th>Query Time</th>
                    </tr>
                </thead>
                <tbody>
"@

foreach ($dc in $DCStatus) {
    $statusClass = switch -Wildcard ($dc.Status) {
        "Success*" { "status-success" }
        "Error*" { "status-error" }
        "Unreachable" { "status-warning" }
        default { "" }
    }
    
    $HtmlReport += @"
                    <tr>
                        <td>$($dc.DomainController)</td>
                        <td class="$statusClass">$($dc.Status)</td>
                        <td>$($dc.EventsFound)</td>
                        <td>$($dc.QueryTime)</td>
                    </tr>
"@
}

$HtmlReport += @"
                </tbody>
            </table>
        </div>
        
        <!-- Detailed Events Table -->
        <div class="section">
            <h2>📋 Detailed Event Log</h2>
            <div class="filter-container">
                <div>
                    <label for="searchInput">Search:</label>
                    <input type="text" id="searchInput" placeholder="Filter events..." style="width: 300px;">
                </div>
                <div>
                    <label for="eventTypeFilter">Event Type:</label>
                    <select id="eventTypeFilter">
                        <option value="">All Events</option>
"@

foreach ($eventType in ($EventTypeDistribution | Select-Object -ExpandProperty Name | Sort-Object)) {
    $HtmlReport += "                        <option value=`"$eventType`">$eventType</option>`n"
}

$HtmlReport += @"
                    </select>
                </div>
                <div>
                    <label for="dcFilter">Domain Controller:</label>
                    <select id="dcFilter">
                        <option value="">All DCs</option>
"@

foreach ($dc in ($AllEvents | Select-Object -ExpandProperty DomainController -Unique | Sort-Object)) {
    $HtmlReport += "                        <option value=`"$dc`">$dc</option>`n"
}

$HtmlReport += @"
                    </select>
                </div>
                <div>
                    <label for="logonTypeFilter">Logon Type:</label>
                    <select id="logonTypeFilter">
                        <option value="">All Types</option>
                        <option value="2">Type 2 - Interactive</option>
                        <option value="3">Type 3 - Network</option>
                        <option value="4">Type 4 - Batch</option>
                        <option value="5">Type 5 - Service</option>
                        <option value="10">Type 10 - RDP</option>
                    </select>
                </div>
                <button class="export-btn" onclick="exportTableToCSV()">📥 Export to CSV</button>
            </div>
            
            <div style="overflow-x: auto;">
                <table id="eventsTable">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Event Type</th>
                            <th>Event ID</th>
                            <th>Domain Controller</th>
                            <th>Source Workstation</th>
                            <th>Source IP</th>
                            <th>Logon Type</th>
                            <th>Auth Package</th>
                            <th>Encryption</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
"@

foreach ($event in ($AllEvents | Sort-Object TimeCreated -Descending)) {
    $eventBadge = switch ($event.EventID) {
        4624 { "badge-success" }
        4625 { "badge-danger" }
        4771 { "badge-danger" }
        4768 { "badge-info" }
        4769 { "badge-info" }
        4776 { "badge-warning" }
        default { "badge-info" }
    }
    
    $encryptionDisplay = if ($event.TicketEncryptionType -ne 'N/A') {
        $encName = Get-EncryptionTypeName -EncryptionType $event.TicketEncryptionType
        $encRisk = Get-EncryptionTypeRisk -EncryptionType $event.TicketEncryptionType
        $encBadge = switch ($encRisk) {
            'CRITICAL' { 'badge-danger' }
            'HIGH' { 'badge-warning' }
            default { 'badge-success' }
        }
        "<span class='badge $encBadge'>$encName</span>"
    } else {
        'N/A'
    }
    
    $HtmlReport += @"
                        <tr data-logontype="$($event.LogonType)">
                            <td>$($event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                            <td><span class="badge $eventBadge">$($event.EventType)</span></td>
                            <td>$($event.EventID)</td>
                            <td>$($event.DomainController)</td>
                            <td>$($event.SourceWorkstation)</td>
                            <td>$($event.IpAddress)</td>
                            <td>$($event.LogonType)</td>
                            <td>$($event.AuthenticationPackage)</td>
                            <td>$encryptionDisplay</td>
                            <td>$($event.Status)</td>
                        </tr>
"@
}

if ($AllEvents.Count -eq 0) {
    $HtmlReport += @"
                        <tr>
                            <td colspan="10" class="no-data">No events found for the specified account and time range.</td>
                        </tr>
"@
}

$HtmlReport += @"
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <script>
        // Failed Logon Chart (if data exists)
        const failedLogonCanvas = document.getElementById('failedLogonChart');
        if (failedLogonCanvas) {
            const failedLogonCtx = failedLogonCanvas.getContext('2d');
            new Chart(failedLogonCtx, {
                type: 'doughnut',
                data: {
                    labels: [$( ($FailedLogonByReason | ForEach-Object { "'$($_.Name)'" }) -join ',' )],
                    datasets: [{
                        data: [$( ($FailedLogonByReason | ForEach-Object { $_.Count }) -join ',' )],
                        backgroundColor: [
                            '#dc3545', '#ffc107', '#17a2b8', '#6f42c1',
                            '#fd7e14', '#20c997', '#6c757d', '#e83e8c'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right'
                        }
                    }
                }
            });
        }
        
        // Encryption Chart (if data exists)
        const encryptionCanvas = document.getElementById('encryptionChart');
        if (encryptionCanvas) {
            const encryptionCtx = encryptionCanvas.getContext('2d');
            new Chart(encryptionCtx, {
                type: 'bar',
                data: {
                    labels: [$( ($EncryptionDistribution | ForEach-Object { "'$($_.EncryptionType)'" }) -join ',' )],
                    datasets: [{
                        label: 'Usage Count',
                        data: [$( ($EncryptionDistribution | ForEach-Object { $_.Count }) -join ',' )],
                        backgroundColor: [$( ($EncryptionDistribution | ForEach-Object { 
                            switch ($_.Risk) {
                                'CRITICAL' { "'#dc3545'" }
                                'HIGH' { "'#ffc107'" }
                                default { "'#28a745'" }
                            }
                        }) -join ',' )]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    }
                }
            });
        }
    
        // Logon Type Distribution Chart
        const logonTypeCtx = document.getElementById('logonTypeChart').getContext('2d');
        new Chart(logonTypeCtx, {
            type: 'doughnut',
            data: {
                labels: [$( ($LogonTypeDistribution | ForEach-Object { "'$($_.Description)'" }) -join ',' )],
                datasets: [{
                    data: [$( ($LogonTypeDistribution | ForEach-Object { $_.Count }) -join ',' )],
                    backgroundColor: [
                        '#dc3545', '#ffc107', '#28a745', '#17a2b8',
                        '#6f42c1', '#fd7e14', '#20c997', '#6c757d'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = ((value / total) * 100).toFixed(1);
                                return label + ': ' + value + ' (' + percentage + '%)';
                            }
                        }
                    }
                }
            }
        });
        
        // Service Name Chart (if data exists)
        const serviceNameCanvas = document.getElementById('serviceNameChart');
        if (serviceNameCanvas) {
            const serviceNameCtx = serviceNameCanvas.getContext('2d');
            new Chart(serviceNameCtx, {
                type: 'bar',
                data: {
                    labels: [$( ($ServiceNameDistribution | ForEach-Object { "'$($_.Name)'" }) -join ',' )],
                    datasets: [{
                        label: 'Service Ticket Requests',
                        data: [$( ($ServiceNameDistribution | ForEach-Object { $_.Count }) -join ',' )],
                        backgroundColor: '#17a2b8'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    scales: {
                        x: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    }
                }
            });
        }
    
        // Event Type Distribution Chart
        const eventTypeCtx = document.getElementById('eventTypeChart').getContext('2d');
        new Chart(eventTypeCtx, {
            type: 'doughnut',
            data: {
                labels: [$( ($EventTypeDistribution | ForEach-Object { "'$($_.Name)'" }) -join ',' )],
                datasets: [{
                    data: [$( ($EventTypeDistribution | ForEach-Object { $_.Count }) -join ',' )],
                    backgroundColor: [
                        '#667eea', '#764ba2', '#f093fb', '#4facfe',
                        '#43e97b', '#fa709a', '#fee140', '#30cfd0'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
        
        // Timeline Chart with error handling
        try {
            const timelineCtx = document.getElementById('timelineChart').getContext('2d');
            const timelineLabels = [$( ($TimelineData | ForEach-Object { "'$($_.DateDisplay)'" }) -join ',' )];
            const timelineData = [$( ($TimelineData | ForEach-Object { $_.Count }) -join ',' )];
            
            if (timelineLabels.length === 0) {
                document.getElementById('timelineChart').parentElement.innerHTML = '<p style="text-align:center; padding:50px; color:#999;">No timeline data available</p>';
            } else {
                new Chart(timelineCtx, {
                    type: 'bar',
                    data: {
                        labels: timelineLabels,
                        datasets: [{
                            label: 'Events per Day',
                            data: timelineData,
                            backgroundColor: 'rgba(102, 126, 234, 0.8)',
                            borderColor: '#667eea',
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    precision: 0
                                }
                            }
                        }
                    }
                });
            }
        } catch (error) {
            console.error('Error creating timeline chart:', error);
        }
        
        // Top Workstations Chart
        const workstationCtx = document.getElementById('workstationChart').getContext('2d');
        new Chart(workstationCtx, {
            type: 'bar',
            data: {
                labels: [$( ($TopWorkstations | ForEach-Object { "'$($_.Name)'" }) -join ',' )],
                datasets: [{
                    label: 'Events',
                    data: [$( ($TopWorkstations | ForEach-Object { $_.Count }) -join ',' )],
                    backgroundColor: '#667eea'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
        
        // Hourly Distribution Chart
        const hourlyCtx = document.getElementById('hourlyChart').getContext('2d');
        new Chart(hourlyCtx, {
            type: 'bar',
            data: {
                labels: [$( ($HourlyDistribution | ForEach-Object { "'$($_.Hour):00'" }) -join ',' )],
                datasets: [{
                    label: 'Events by Hour',
                    data: [$( ($HourlyDistribution | ForEach-Object { $_.Count }) -join ',' )],
                    backgroundColor: '#764ba2'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
        
        // Table filtering functionality
        const searchInput = document.getElementById('searchInput');
        const eventTypeFilter = document.getElementById('eventTypeFilter');
        const dcFilter = document.getElementById('dcFilter');
        const logonTypeFilter = document.getElementById('logonTypeFilter');
        const table = document.getElementById('eventsTable');
        const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
        
        function filterTable() {
            const searchTerm = searchInput.value.toLowerCase();
            const selectedEventType = eventTypeFilter.value.toLowerCase();
            const selectedDC = dcFilter.value.toLowerCase();
            const selectedLogonType = logonTypeFilter.value;
            
            for (let row of rows) {
                if (row.cells.length === 1) continue;
                
                const rowText = row.textContent.toLowerCase();
                const eventType = row.cells[1].textContent.toLowerCase();
                const dc = row.cells[3].textContent.toLowerCase();
                const logonType = row.getAttribute('data-logontype');
                
                const matchesSearch = searchTerm === '' || rowText.includes(searchTerm);
                const matchesEventType = selectedEventType === '' || eventType.includes(selectedEventType);
                const matchesDC = selectedDC === '' || dc.includes(selectedDC);
                const matchesLogonType = selectedLogonType === '' || logonType === selectedLogonType;
                
                row.style.display = (matchesSearch && matchesEventType && matchesDC && matchesLogonType) ? '' : 'none';
            }
        }
        
        searchInput.addEventListener('keyup', filterTable);
        eventTypeFilter.addEventListener('change', filterTable);
        dcFilter.addEventListener('change', filterTable);
        logonTypeFilter.addEventListener('change', filterTable);
        
        // Export to CSV
        function exportTableToCSV() {
            const rows = [];
            const table = document.getElementById('eventsTable');
            
            const headers = [];
            for (let th of table.getElementsByTagName('th')) {
                headers.push(th.textContent);
            }
            rows.push(headers.join(','));
            
            for (let row of table.getElementsByTagName('tbody')[0].getElementsByTagName('tr')) {
                if (row.style.display !== 'none' && row.cells.length > 1) {
                    const rowData = [];
                    for (let cell of row.cells) {
                        let text = cell.textContent.trim().replace(/"/g, '""');
                        if (text.includes(',')) {
                            text = '"' + text + '"';
                        }
                        rowData.push(text);
                    }
                    rows.push(rowData.join(','));
                }
            }
            
            const csvContent = rows.join('\n');
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', 'DomainAdminUsage_$($AccountName)_$(Get-Date -Format "yyyyMMdd").csv');
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
        
        // Privilege Events Table Filtering
        const privSearchInput = document.getElementById('privSearchInput');
        const privDCFilter = document.getElementById('privDCFilter');
        const privPrivilegeFilter = document.getElementById('privPrivilegeFilter');
        const privTable = document.getElementById('privilegeEventsTable');
        const privRows = privTable ? privTable.getElementsByTagName('tbody')[0].getElementsByTagName('tr') : [];
        
        function filterPrivilegeTable() {
            if (!privTable) return;
            
            const searchTerm = privSearchInput ? privSearchInput.value.toLowerCase() : '';
            const selectedDC = privDCFilter ? privDCFilter.value : '';
            const selectedPrivilege = privPrivilegeFilter ? privPrivilegeFilter.value : '';
            
            let visibleCount = 0;
            
            for (let row of privRows) {
                if (row.cells.length === 0) continue;
                
                const rowText = row.textContent.toLowerCase();
                const rowDC = row.getAttribute('data-dc') ? row.getAttribute('data-dc') : '';
                const rowPrivileges = row.getAttribute('data-privileges') ? row.getAttribute('data-privileges') : '';
                
                const matchesSearch = searchTerm === '' || rowText.includes(searchTerm);
                const matchesDC = selectedDC === '' || rowDC === selectedDC;
                
                let matchesPrivilege = true;
                if (selectedPrivilege !== '') {
                    // Search with both the original case and lowercase for robustness
                    const searchPattern1 = '|' + selectedPrivilege + '|';
                    const searchPattern2 = '|' + selectedPrivilege.toLowerCase() + '|';
                    matchesPrivilege = rowPrivileges.includes(searchPattern1) || rowPrivileges.toLowerCase().includes(searchPattern2);
                }
                
                const shouldShow = matchesSearch && matchesDC && matchesPrivilege;
                row.style.display = shouldShow ? '' : 'none';
                
                if (shouldShow) visibleCount++;
            }
            
            console.log('Filtered rows: ' + visibleCount + ' visible');
        }
        
        if (privSearchInput) privSearchInput.addEventListener('keyup', filterPrivilegeTable);
        if (privDCFilter) privDCFilter.addEventListener('change', filterPrivilegeTable);
        if (privPrivilegeFilter) privPrivilegeFilter.addEventListener('change', filterPrivilegeTable);
        
        // Export Privilege Table to CSV
        function exportPrivilegeTableToCSV() {
            const rows = [];
            const table = document.getElementById('privilegeEventsTable');
            if (!table) return;
            
            const headers = [];
            for (let th of table.getElementsByTagName('th')) {
                headers.push(th.textContent);
            }
            rows.push(headers.join(','));
            
            let exportedCount = 0;
            for (let row of table.getElementsByTagName('tbody')[0].getElementsByTagName('tr')) {
                if (row.style.display !== 'none' && row.cells.length > 0) {
                    const rowData = [];
                    for (let cell of row.cells) {
                        let text = cell.textContent.trim().replace(/"/g, '""');
                        if (text.includes(',') || text.includes('\n')) {
                            text = '"' + text + '"';
                        }
                        rowData.push(text);
                    }
                    rows.push(rowData.join(','));
                    exportedCount++;
                }
            }
            
            const csvContent = rows.join('\n');
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', 'PrivilegeAssignmentEvents_$($AccountName)_$(Get-Date -Format "yyyyMMdd").csv');
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
    </script>
</body>
</html>
"@

# Save HTML Report
try {
    $HtmlReport | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host "`n✓ Report generated successfully!" -ForegroundColor Green
    Write-Host "Location: $OutputPath" -ForegroundColor Cyan
    
    # Console Summary
    Write-Host "`n" + "=" * 70 -ForegroundColor Cyan
    Write-Host "EXECUTIVE SUMMARY" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    
    Write-Host "`n🎯 RISK ASSESSMENT" -ForegroundColor Yellow
    Write-Host "Risk Level: $($RiskAssessment.OverallRisk) - Score: $($RiskAssessment.TotalScore)/100"
    
    if ($RiskAssessment.RiskFactors.Count -gt 0) {
        Write-Host "`nTop Risk Factors:" -ForegroundColor Yellow
        foreach ($factor in ($RiskAssessment.RiskFactors | Sort-Object Score -Descending | Select-Object -First 5)) {
            $color = switch ($factor.Severity) {
                'CRITICAL' { 'Red' }
                'HIGH' { 'Yellow' }
                'MEDIUM' { 'Cyan' }
                default { 'Gray' }
            }
            Write-Host "  [$($factor.Severity)] " -ForegroundColor $color -NoNewline
            Write-Host "$($factor.Factor) (+$($factor.Score) points)"
        }
    }
    
    Write-Host "`n👤 ACCOUNT INFORMATION" -ForegroundColor Yellow
    Write-Host "Account: $AccountName"
    Write-Host "Status: $(if ($AccountInfo.Enabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($AccountInfo.Enabled) { 'Yellow' } else { 'Green' })
    Write-Host "Password Age: $($Stats.PasswordAge) days" -ForegroundColor $(if ($Stats.PasswordAge -gt 365) { 'Red' } elseif ($Stats.PasswordAge -gt 180) { 'Yellow' } else { 'Green' })
    Write-Host "Password Never Expires: $(if ($AccountInfo.PasswordNeverExpires) { 'YES (High Risk)' } else { 'No' })" -ForegroundColor $(if ($AccountInfo.PasswordNeverExpires) { 'Red' } else { 'Green' })
    Write-Host "Admin Count: $(if ($AccountInfo.AdminCount -eq 1) { '1 (Protected Account)' } else { '0' })" -ForegroundColor $(if ($AccountInfo.AdminCount -eq 1) { 'Yellow' } else { 'Gray' })
    Write-Host "Privileged Groups: $($Stats.PrivilegedGroupCount)" -ForegroundColor $(if ($Stats.PrivilegedGroupCount -gt 0) { 'Yellow' } else { 'Green' })
    
    if ($PrivilegedGroups.Count -gt 0) {
        foreach ($group in $PrivilegedGroups) {
            Write-Host "  - $($group.GroupName) [$($group.EnglishName)]" -ForegroundColor Cyan
        }
    }
    
    Write-Host "SPNs Configured: $($Stats.SPNCount)" -ForegroundColor $(if ($Stats.SPNCount -gt 0) { 'Yellow' } else { 'Gray' })
    
    if ($Stats.SPNCount -gt 0) {
        foreach ($spn in $AccountInfo.SPNs) {
            Write-Host "  - $spn" -ForegroundColor Cyan
        }
    }
    
    Write-Host "`n📊 AUTHENTICATION EVENTS" -ForegroundColor Yellow
    Write-Host "Total Events: $($Stats.TotalEvents)"
    Write-Host "  - Kerberos: $($Stats.KerberosEvents)"
    Write-Host "  - NTLM: $($Stats.NTLMEvents)"
    Write-Host "  - Successful: $($Stats.LogonEvents)"
    Write-Host "  - Failed: $($Stats.FailedEvents)" -ForegroundColor $(if ($Stats.FailedEvents -gt 50) { 'Red' } elseif ($Stats.FailedEvents -gt 10) { 'Yellow' } else { 'Green' })
    
    Write-Host "`n🔐 LOGON TYPE ANALYSIS" -ForegroundColor Yellow
    Write-Host "  - Interactive (Type 2): $($Stats.InteractiveLogons)" -ForegroundColor $(if ($Stats.InteractiveLogons -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  - Remote Desktop (Type 10): $($Stats.RemoteInteractiveLogons)" -ForegroundColor $(if ($Stats.RemoteInteractiveLogons -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  - Network (Type 3): $($Stats.NetworkLogons)"
    Write-Host "  - Service (Type 5): $($Stats.ServiceLogons)"
    Write-Host "  - Batch (Type 4): $($Stats.BatchLogons)"
    
    Write-Host "`n🔑 PRIVILEGED OPERATIONS (Event 4672)" -ForegroundColor Yellow
    Write-Host "Total Privileged Logons: $($Stats.PrivilegedLogons)"
    if ($PrivilegeFrequency.Count -gt 0) {
        Write-Host "Unique Privileges Assigned: $($PrivilegeFrequency.Count)"
        Write-Host "Top 5 Privileges:" -ForegroundColor Cyan
        foreach ($priv in ($PrivilegeFrequency | Select-Object -First 5)) {
            $risk = Get-PrivilegeRiskLevel -Privilege $priv.Name
            $desc = Get-PrivilegeDescription -Privilege $priv.Name
            $color = switch ($risk) {
                'CRITICAL' { 'Red' }
                'HIGH' { 'Yellow' }
                default { 'Cyan' }
            }
            Write-Host "  - $($priv.Name) ($risk): $($priv.Count) times" -ForegroundColor $color
            Write-Host "    $desc" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n🔒 ENCRYPTION ANALYSIS" -ForegroundColor Yellow
    Write-Host "Weak Encryption Instances: $($Stats.WeakEncryptionCount)" -ForegroundColor $(if ($Stats.WeakEncryptionCount -gt 0) { 'Red' } else { 'Green' })
    if ($WeakEncryption.Count -gt 0) {
        foreach ($enc in ($EncryptionDistribution)) {
            Write-Host "  - $($enc.EncryptionType): $($enc.Count) (Risk: $($enc.Risk))" -ForegroundColor Yellow
        }
        
        Write-Host "`nSystems using weak encryption:" -ForegroundColor Red
        foreach ($system in ($WeakEncByWorkstation | Select-Object -First 10)) {
            Write-Host "  - $($system.Name): $($system.Count) instances" -ForegroundColor Yellow
        }
        
        if ($WeakEncByWorkstation.Count -gt 10) {
            Write-Host "  ... and $(($WeakEncryption | Group-Object -Property SourceWorkstation).Count - 10) more systems" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n📍 USAGE SCOPE" -ForegroundColor Yellow
    Write-Host "Unique Workstations: $($Stats.UniqueWorkstations)"
    Write-Host "Unique Source IPs: $($Stats.UniqueSourceIPs)"
    
    Write-Host "`n" + "=" * 70 -ForegroundColor Cyan
    
    # Warnings and recommendations
    if ($Stats.InteractiveLogons -gt 0 -or $Stats.RemoteInteractiveLogons -gt 0) {
        Write-Host "`n⚠️  CRITICAL: Interactive or RDP logons detected!" -ForegroundColor Red
        Write-Host "   Legacy admin accounts should NOT have interactive usage." -ForegroundColor Red
        Write-Host "   Action: Investigate and migrate interactive usage to personal admin accounts" -ForegroundColor Yellow
    }
    
    if ($Stats.WeakEncryptionCount -gt 0) {
        Write-Host "`n⚠️  SECURITY RISK: Weak encryption detected!" -ForegroundColor Red
        Write-Host "   DES and RC4 are vulnerable to offline attacks" -ForegroundColor Red
        Write-Host "   Action: Configure clients/services to use AES encryption" -ForegroundColor Yellow
    }
    
    if ($AccountInfo.PasswordNeverExpires) {
        Write-Host "`n⚠️  HIGH RISK: Password never expires is set!" -ForegroundColor Red
        Write-Host "   Action: Remove flag or migrate to gMSA (Group Managed Service Account)" -ForegroundColor Yellow
    }
    
    if ($Stats.SPNCount -gt 0 -and $Stats.ServiceLogons -gt 0) {
        Write-Host "`nℹ️  INFO: This appears to be a service account" -ForegroundColor Cyan
        Write-Host "   Consider migrating to a Group Managed Service Account (gMSA)" -ForegroundColor Cyan
    }
    
    if ($Stats.FailedEvents -gt 50) {
        Write-Host "`n⚠️  WARNING: High number of failed logons ($($Stats.FailedEvents))" -ForegroundColor Yellow
        Write-Host "   This may indicate attack attempts or misconfigured services" -ForegroundColor Yellow
        Write-Host "   Review failed logon analysis in the report" -ForegroundColor Yellow
    }
    
    if ($AccountInfo.AdminCount -eq 1 -and $PrivilegedGroups.Count -eq 0) {
        Write-Host "`nℹ️  INFO: adminCount=1 but no current privileged group memberships" -ForegroundColor Cyan
        Write-Host "   This account was previously privileged and may need permission review" -ForegroundColor Cyan
    }
    
    Write-Host "`n" + "=" * 70 -ForegroundColor Cyan
    
    # Optionally open the report
    $openReport = Read-Host "`nWould you like to open the report now? (Y/N)"
    if ($openReport -eq 'Y' -or $openReport -eq 'y') {
        Start-Process $OutputPath
    }
    
} catch {
    Write-Error "Failed to save report: $_"
}
