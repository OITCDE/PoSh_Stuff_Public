#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
    Active Directory Health & Stale Object Report Generator
.DESCRIPTION
    Generates a self-contained, interactive HTML report of all AD objects.
    Identifies stale users/computers, unlinked GPOs, empty groups, EOL systems,
    Exchange Shared/Room/Equipment Mailboxes, and provides an executive dashboard,
    charts, multi-select filters, and remediation guidance.
    Includes full Fine-Grained Password Policy (FGPP) support.
.PARAMETER OutputPath
    Full path for the HTML output file. Defaults to Desktop.
.PARAMETER StaleUserDays
    Days since last logon to flag a user as stale. Default: 90
.PARAMETER StaleComputerDays
    Days since last logon to flag a computer as stale. Default: 90
.PARAMETER PasswordAgeDays
    Days to consider a password "old". Default: 90
.PARAMETER Domain
    Target domain DNS root. Defaults to current domain.
.EXAMPLE
    .\AD-HealthReport.ps1 -StaleUserDays 60 -StaleComputerDays 60
.EXAMPLE
    .\AD-HealthReport.ps1 -OutputPath "C:\Reports\ADReport.html" -Domain "corp.contoso.com"
#>

[CmdletBinding()]
param(
    [string]$OutputPath      = ".\AD_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [int]$StaleUserDays      = 90,
    [int]$StaleComputerDays  = 90,
    [int]$PasswordAgeDays    = 90,
    [string]$Domain          = ""
)

$ErrorActionPreference = "Stop"

# ============================================================
# REGION 1 – PREREQUISITES
# ============================================================
Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host "  Active Directory Health Report Generator" -ForegroundColor Cyan
Write-Host "=====================================================`n" -ForegroundColor Cyan

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy     -ErrorAction Stop
    Write-Host "[OK] Modules loaded." -ForegroundColor Green
} catch {
    Write-Error "Required modules not found. Install RSAT tools first.`n$_"
    exit 1
}

$Now               = Get-Date
$StaleUserDate     = $Now.AddDays(-$StaleUserDays)
$StaleComputerDate = $Now.AddDays(-$StaleComputerDays)

if ([string]::IsNullOrEmpty($Domain)) { $Domain = (Get-ADDomain).DNSRoot }

try {
    $DomainInfo = Get-ADDomain -Server $Domain
    $ForestInfo = Get-ADForest -Server $Domain
} catch {
    Write-Error "Cannot connect to domain '$Domain': $_"
    exit 1
}
Write-Host "[OK] Connected to: $Domain`n" -ForegroundColor Green

# ============================================================
# REGION 2 – HELPER FUNCTIONS
# ============================================================
function Format-DateStr {
    param($d)
    if ($null -eq $d -or $d -eq [DateTime]::MinValue) { return "Never" }
    return $d.ToString("yyyy-MM-dd HH:mm")
}
function Get-DaysSince {
    param($d)
    if ($null -eq $d -or $d -eq [DateTime]::MinValue) { return 99999 }
    return [int]($Now - $d).TotalDays
}
function Safe {
    param($v, $default = "")
    if ($null -eq $v) { return $default }
    return $v.ToString()
}
function Format-TimeSpanDays {
    param($ts)
    if ($null -eq $ts) { return "N/A" }
    try {
        $days = [Math]::Abs($ts.Days)
        if ($days -ge 36500) { return "Never" }
        return "$days days"
    } catch { return "N/A" }
}

# msExchRecipientTypeDetails bitmask → label
function Get-MailboxType {
    param([long]$typeDetails)
    switch ($typeDetails) {
        1            { return "UserMailbox" }
        2            { return "LinkedMailbox" }
        4            { return "SharedMailbox" }
        8            { return "LegacyMailbox" }
        16           { return "RoomMailbox" }
        32           { return "EquipmentMailbox" }
        128          { return "MailUser" }
        2147483648   { return "RemoteUserMailbox" }
        8589934592   { return "RemoteSharedMailbox" }
        17179869184  { return "RemoteRoomMailbox" }
        34359738368  { return "RemoteEquipmentMailbox" }
        default      { return "Other ($typeDetails)" }
    }
}

# Guaranteed valid JSON array – fixes PS 5.1 ConvertTo-Json returning "" for @()
function ConvertTo-SafeJson ($obj) {
    $arr = @($obj)
    if ($arr.Count -eq 0) { return "[]" }
    $json = ($arr | ConvertTo-Json -Depth 4 -Compress) `
        -replace '\\u0000', '' `
        -replace '</script>', '<\/script>'
    if ([string]::IsNullOrWhiteSpace($json) -or $json -eq 'null') { return "[]" }
    if ($json -notmatch '^\[') { $json = "[$json]" }
    return $json
}

# ============================================================
# REGION 3 – DATA COLLECTION
# ============================================================

# ---- USERS ----
Write-Host "[...] Collecting users..." -ForegroundColor Yellow
$ADUsers = Get-ADUser -Filter * -Server $Domain -Properties `
    DisplayName, SamAccountName, EmailAddress, Department, Title, Manager,
    LastLogonDate, PasswordLastSet, PasswordNeverExpires, PasswordExpired,
    PasswordNotRequired, Enabled, AdminCount, ServicePrincipalNames,
    MemberOf, Description, whenCreated, LockedOut, SmartcardLogonRequired,
    msExchRecipientTypeDetails `
    -ErrorAction SilentlyContinue

$SharedMailboxTypes = @(4, 8589934592)
$RoomMailboxTypes   = @(16, 17179869184)
$EquipMailboxTypes  = @(32, 34359738368)
$AllSpecialMbxTypes = $SharedMailboxTypes + $RoomMailboxTypes + $EquipMailboxTypes

$AllUsers = foreach ($u in $ADUsers) {
    $dsl   = Get-DaysSince $u.LastLogonDate
    $dspw  = Get-DaysSince $u.PasswordLastSet
    $stale = ($u.Enabled -eq $true) -and ($dsl -ge $StaleUserDays)
    $admin = ($u.AdminCount -eq 1) -or (($u.MemberOf | Out-String) -match "Domain Admins|Enterprise Admins|Schema Admins|Builtin\\Administrators")
    $svc   = ($u.ServicePrincipalNames.Count -gt 0) -or ($u.SamAccountName -match "^svc[_-]|^service[_-]|[_-]svc$|[_-]service$")

    $exchType    = $u.msExchRecipientTypeDetails
    $mbxLabel    = if ($null -ne $exchType -and $exchType -ne 0) { Get-MailboxType $exchType } else { "" }
    $isSharedMbx = ($exchType -in $SharedMailboxTypes)
    $isRoomMbx   = ($exchType -in $RoomMailboxTypes)
    $isEquipMbx  = ($exchType -in $EquipMailboxTypes)
    $isAnyMbx    = ($exchType -in $AllSpecialMbxTypes)

    $accountType = if ($isSharedMbx)    { "SharedMailbox" }
                   elseif ($isRoomMbx)  { "RoomMailbox" }
                   elseif ($isEquipMbx) { "EquipmentMailbox" }
                   elseif ($svc)        { "ServiceAccount" }
                   elseif ($admin)      { "AdminAccount" }
                   else                 { "UserAccount" }

    $status = if ($isAnyMbx -and (-not $u.Enabled)) { "Mailbox" }
              elseif (-not $u.Enabled)               { "Disabled" }
              elseif ($stale)                        { "Stale" }
              elseif ($dsl -le ($StaleUserDays*0.5)) { "Active" }
              else                                   { "Warning" }

    [PSCustomObject]@{
        Name             = if ($u.DisplayName) { $u.DisplayName } else { $u.SamAccountName }
        SamAccountName   = $u.SamAccountName
        Email            = Safe $u.EmailAddress
        Department       = Safe $u.Department
        Title            = Safe $u.Title
        Enabled          = $u.Enabled
        LastLogon        = Format-DateStr $u.LastLogonDate
        DaysSinceLogon   = if ($dsl -ge 99999) { -1 } else { $dsl }
        PasswordLastSet  = Format-DateStr $u.PasswordLastSet
        DaysSincePwSet   = if ($dspw -ge 99999) { -1 } else { $dspw }
        PwNeverExpires   = [bool]$u.PasswordNeverExpires
        PwExpired        = [bool]$u.PasswordExpired
        PwNotRequired    = [bool]$u.PasswordNotRequired
        LockedOut        = [bool]$u.LockedOut
        IsAdmin          = $admin
        IsServiceAccount = $svc
        AdminCount       = ($u.AdminCount -eq 1)
        IsStale          = $stale
        Created          = Format-DateStr $u.whenCreated
        Description      = Safe $u.Description
        AccountType      = $accountType
        MailboxType      = $mbxLabel
        IsSharedMailbox  = $isSharedMbx
        IsRoomMailbox    = $isRoomMbx
        IsEquipMailbox   = $isEquipMbx
        IsAnyMailbox     = $isAnyMbx
        Status           = $status
    }
}
Write-Host "    -> $($AllUsers.Count) users found." -ForegroundColor Green

# ---- COMPUTERS ----
Write-Host "[...] Collecting computers..." -ForegroundColor Yellow
$ADComputers = Get-ADComputer -Filter * -Server $Domain -Properties `
    DNSHostName, OperatingSystem, OperatingSystemVersion, IPv4Address,
    LastLogonDate, Enabled, whenCreated, Description, ManagedBy `
    -ErrorAction SilentlyContinue

$AllComputers = foreach ($c in $ADComputers) {
    $dsl   = Get-DaysSince $c.LastLogonDate
    $stale = ($c.Enabled -eq $true) -and ($dsl -ge $StaleComputerDays)
    $eol   = ($c.OperatingSystem -match "Windows XP|Windows Vista|Windows 7|2003|2008 R2|2000")
    $osCat = switch -Wildcard ($c.OperatingSystem) {
        "*Server 2022*" { "Server 2022" }  "*Server 2019*" { "Server 2019" }
        "*Server 2016*" { "Server 2016" }  "*Server 2012*" { "Server 2012/R2" }
        "*Server 2008*" { "Server 2008 (EOL)" } "*Server 2003*" { "Server 2003 (EOL)" }
        "*Windows 11*"  { "Windows 11" }   "*Windows 10*"  { "Windows 10" }
        "*Windows 7*"   { "Windows 7 (EOL)" } "*Windows XP*" { "Windows XP (EOL)" }
        default         { if ($c.OperatingSystem) { "Other" } else { "Unknown" } }
    }
    [PSCustomObject]@{
        Name            = $c.Name
        DNSHostName     = Safe $c.DNSHostName
        OperatingSystem = if ($c.OperatingSystem) { $c.OperatingSystem } else { "Unknown" }
        OSVersion       = Safe $c.OperatingSystemVersion
        OSCategory      = $osCat
        IPv4Address     = Safe $c.IPv4Address
        Enabled         = $c.Enabled
        LastLogon       = Format-DateStr $c.LastLogonDate
        DaysSinceLogon  = if ($dsl -ge 99999) { -1 } else { $dsl }
        IsStale         = $stale
        IsEOL           = $eol
        Created         = Format-DateStr $c.whenCreated
        Description     = Safe $c.Description
        Status          = if (-not $c.Enabled) { "Disabled" }
                          elseif ($stale)      { "Stale" }
                          elseif ($dsl -le ($StaleComputerDays*0.5)) { "Active" }
                          else                 { "Warning" }
    }
}
Write-Host "    -> $($AllComputers.Count) computers found." -ForegroundColor Green

# ---- GROUPS ----
Write-Host "[...] Collecting groups..." -ForegroundColor Yellow
$ADGroups = Get-ADGroup -Filter * -Server $Domain -Properties `
    Members, ManagedBy, Description, GroupScope, GroupCategory,
    whenCreated, AdminCount -ErrorAction SilentlyContinue

$AllGroups = foreach ($g in $ADGroups) {
    $cnt  = $g.Members.Count
    $priv = ($g.AdminCount -eq 1) -or ($g.Name -match "^Domain Admins$|^Enterprise Admins$|^Schema Admins$|^Administrators$|^Backup Operators$|^Account Operators$|^Print Operators$|^Server Operators$")
    [PSCustomObject]@{
        Name         = $g.Name
        Scope        = $g.GroupScope.ToString()
        Category     = $g.GroupCategory.ToString()
        MemberCount  = $cnt
        IsEmpty      = ($cnt -eq 0)
        IsPrivileged = $priv
        AdminCount   = ($g.AdminCount -eq 1)
        ManagedBy    = Safe $g.ManagedBy
        Description  = Safe $g.Description
        Created      = Format-DateStr $g.whenCreated
        Status       = if ($cnt -eq 0) { "Empty" } elseif ($priv) { "Privileged" } else { "Active" }
    }
}
Write-Host "    -> $($AllGroups.Count) groups found." -ForegroundColor Green

# ---- GPOs ----
Write-Host "[...] Collecting GPOs..." -ForegroundColor Yellow
$AllGPOs = @()
try {
    $RawGPOs = Get-GPO -All -Domain $Domain -ErrorAction SilentlyContinue
    $LinkedGuids = @{}
    Get-ADOrganizationalUnit -Filter * -Properties LinkedGroupPolicyObjects -Server $Domain | ForEach-Object {
        foreach ($lnk in $_.LinkedGroupPolicyObjects) {
            $guid = ([regex]::Match($lnk, '\{([^}]+)\}')).Groups[1].Value.ToUpper()
            if ($guid) { $LinkedGuids[$guid] = $true }
        }
    }
    try {
        (Get-ADDomain -Server $Domain).LinkedGroupPolicyObjects | ForEach-Object {
            $guid = ([regex]::Match($_, '\{([^}]+)\}')).Groups[1].Value.ToUpper()
            if ($guid) { $LinkedGuids[$guid] = $true }
        }
    } catch {}
    $AllGPOs = foreach ($gpo in $RawGPOs) {
        $guid    = $gpo.Id.ToString().ToUpper()
        $linked  = $LinkedGuids.ContainsKey($guid)
        $daysMod = [int]($Now - $gpo.ModificationTime).TotalDays
        [PSCustomObject]@{
            Name            = $gpo.DisplayName
            Guid            = $gpo.Id.ToString()
            GPOStatus       = $gpo.GpoStatus.ToString()
            IsLinked        = $linked
            Created         = $gpo.CreationTime.ToString("yyyy-MM-dd HH:mm")
            Modified        = $gpo.ModificationTime.ToString("yyyy-MM-dd HH:mm")
            DaysSinceMod    = $daysMod
            ComputerEnabled = ($gpo.GpoStatus -ne "ComputerSettingsDisabled" -and $gpo.GpoStatus -ne "AllSettingsDisabled")
            UserEnabled     = ($gpo.GpoStatus -ne "UserSettingsDisabled"     -and $gpo.GpoStatus -ne "AllSettingsDisabled")
            Description     = Safe $gpo.Description
            RiskLevel       = if (-not $linked) { "Unlinked" }
                              elseif ($gpo.GpoStatus -eq "AllSettingsDisabled") { "Disabled" }
                              else { "Active" }
        }
    }
} catch { Write-Warning "GPO collection failed: $_" }
Write-Host "    -> $($AllGPOs.Count) GPOs found." -ForegroundColor Green

# ---- OUs ----
Write-Host "[...] Collecting OUs..." -ForegroundColor Yellow
$AllOUs = Get-ADOrganizationalUnit -Filter * -Server $Domain -Properties Description, ManagedBy, whenCreated, LinkedGroupPolicyObjects |
    ForEach-Object {
        [PSCustomObject]@{
            Name              = $_.Name
            DistinguishedName = $_.DistinguishedName
            Description       = Safe $_.Description
            ManagedBy         = Safe $_.ManagedBy
            LinkedGPOs        = $_.LinkedGroupPolicyObjects.Count
            Created           = Format-DateStr $_.whenCreated
            Depth             = ($_.DistinguishedName.Split(',') | Where-Object { $_ -match '^OU=' }).Count
        }
    }
Write-Host "    -> $($AllOUs.Count) OUs found." -ForegroundColor Green

# ---- DOMAIN CONTROLLERS ----
Write-Host "[...] Collecting DCs..." -ForegroundColor Yellow
$AllDCs = Get-ADDomainController -Filter * -Server $Domain | ForEach-Object {
    [PSCustomObject]@{
        Name      = $_.Name
        Hostname  = $_.HostName
        IPAddress = Safe $_.IPv4Address
        Site      = Safe $_.Site
        IsGC      = $_.IsGlobalCatalog
        IsRODC    = $_.IsReadOnly
        OSVersion = Safe $_.OperatingSystem
        IsEnabled = $_.Enabled
    }
}
Write-Host "    -> $($AllDCs.Count) DCs found." -ForegroundColor Green

# ---- PASSWORD POLICIES ----
Write-Host "[...] Collecting password policies..." -ForegroundColor Yellow
$DefaultPwPolicy = Get-ADDefaultDomainPasswordPolicy -Identity $Domain

Write-Host "[...] Collecting Fine-Grained Password Policies (FGPP)..." -ForegroundColor Yellow
$AllFGPPs = @()
try {
    $RawFGPPs = Get-ADFineGrainedPasswordPolicy -Filter * -Server $Domain `
        -Properties Name, Precedence, MinPasswordLength, MaxPasswordAge,
                    MinPasswordAge, PasswordHistoryCount, LockoutThreshold,
                    LockoutDuration, LockoutObservationWindow,
                    ComplexityEnabled, ReversibleEncryptionEnabled,
                    AppliesTo, Description, whenCreated, whenChanged `
        -ErrorAction SilentlyContinue

    if ($RawFGPPs) {
        $AllFGPPs = foreach ($fgpp in $RawFGPPs) {
            $appliesToNames = @()
            foreach ($dn in $fgpp.AppliesTo) {
                try {
                    $obj = Get-ADObject -Identity $dn -Server $Domain -Properties SamAccountName, Name -ErrorAction SilentlyContinue
                    $appliesToNames += if ($obj -and $obj.SamAccountName) { $obj.SamAccountName }
                                       elseif ($obj) { $obj.Name }
                                       else { ($dn -split ',')[0] -replace '^CN=','' }
                } catch { $appliesToNames += ($dn -split ',')[0] -replace '^CN=','' }
            }
            $weakMinLen = ($fgpp.MinPasswordLength -lt 8)
            $noExpiry   = (Format-TimeSpanDays $fgpp.MaxPasswordAge) -eq "Never"
            $noLockout  = ($fgpp.LockoutThreshold -eq 0)
            $revEncrypt = [bool]$fgpp.ReversibleEncryptionEnabled
            $noComplex  = (-not [bool]$fgpp.ComplexityEnabled)
            $weakScore  = @($weakMinLen,$noExpiry,$noLockout,$revEncrypt,$noComplex) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
            $riskLevel  = if ($weakScore -ge 3) { "Critical" } elseif ($weakScore -ge 2) { "High" } elseif ($weakScore -ge 1) { "Medium" } else { "Good" }

            [PSCustomObject]@{
                Name                     = $fgpp.Name
                Precedence               = [int]$fgpp.Precedence
                AppliesTo                = ($appliesToNames -join ", ")
                AppliesToCount           = $fgpp.AppliesTo.Count
                MinPasswordLength        = [int]$fgpp.MinPasswordLength
                MaxPasswordAge           = Format-TimeSpanDays $fgpp.MaxPasswordAge
                MinPasswordAge           = Format-TimeSpanDays $fgpp.MinPasswordAge
                PasswordHistoryCount     = [int]$fgpp.PasswordHistoryCount
                LockoutThreshold         = [int]$fgpp.LockoutThreshold
                LockoutDuration          = Format-TimeSpanDays $fgpp.LockoutDuration
                LockoutObservationWindow = Format-TimeSpanDays $fgpp.LockoutObservationWindow
                ComplexityEnabled        = [bool]$fgpp.ComplexityEnabled
                ReversibleEncryption     = [bool]$fgpp.ReversibleEncryptionEnabled
                Description              = Safe $fgpp.Description
                Created                  = Format-DateStr $fgpp.whenCreated
                LastChanged              = Format-DateStr $fgpp.whenChanged
                RiskLevel                = $riskLevel
                WeakMinLength            = $weakMinLen
                NoExpiry                 = $noExpiry
                NoLockout                = $noLockout
                RevEncryptEnabled        = $revEncrypt
                ComplexityDisabled       = $noComplex
            }
        }
    }
    Write-Host "    -> $($AllFGPPs.Count) FGPP(s) found." -ForegroundColor Green
} catch {
    Write-Warning "FGPP collection failed (requires Domain Admin or delegated rights): $_"
    $AllFGPPs = @()
}

# ============================================================
# REGION 4 – STATISTICS & SECURITY FINDINGS
# ============================================================
Write-Host "[...] Calculating statistics & findings..." -ForegroundColor Yellow

$TrueDisabled = $AllUsers | Where-Object { (-not $_.Enabled) -and (-not $_.IsAnyMailbox) }

$Stats = [ordered]@{
    TotalUsers           = $AllUsers.Count
    EnabledUsers         = ($AllUsers | Where-Object Enabled).Count
    DisabledUsers        = ($AllUsers | Where-Object { -not $_.Enabled }).Count
    TrueDisabledUsers    = $TrueDisabled.Count
    SharedMailboxes      = ($AllUsers | Where-Object IsSharedMailbox).Count
    RoomMailboxes        = ($AllUsers | Where-Object IsRoomMailbox).Count
    EquipMailboxes       = ($AllUsers | Where-Object IsEquipMailbox).Count
    StaleUsers           = ($AllUsers | Where-Object IsStale).Count
    AdminUsers           = ($AllUsers | Where-Object IsAdmin).Count
    ServiceAccounts      = ($AllUsers | Where-Object IsServiceAccount).Count
    PwNeverExpires       = ($AllUsers | Where-Object PwNeverExpires).Count
    LockedOutUsers       = ($AllUsers | Where-Object LockedOut).Count
    TotalComputers       = $AllComputers.Count
    EnabledComputers     = ($AllComputers | Where-Object Enabled).Count
    DisabledComputers    = ($AllComputers | Where-Object { -not $_.Enabled }).Count
    StaleComputers       = ($AllComputers | Where-Object IsStale).Count
    EOLComputers         = ($AllComputers | Where-Object IsEOL).Count
    ServerCount          = ($AllComputers | Where-Object { $_.OSCategory -like "*Server*" }).Count
    TotalGroups          = $AllGroups.Count
    EmptyGroups          = ($AllGroups | Where-Object IsEmpty).Count
    PrivilegedGroups     = ($AllGroups | Where-Object IsPrivileged).Count
    TotalGPOs            = $AllGPOs.Count
    UnlinkedGPOs         = ($AllGPOs | Where-Object { -not $_.IsLinked }).Count
    DisabledGPOs         = ($AllGPOs | Where-Object { $_.GPOStatus -eq "AllSettingsDisabled" }).Count
    TotalOUs             = $AllOUs.Count
    TotalDCs             = $AllDCs.Count
    GlobalCatalogs       = ($AllDCs | Where-Object IsGC).Count
    RODCs                = ($AllDCs | Where-Object IsRODC).Count
    TotalFGPPs           = $AllFGPPs.Count
    WeakFGPPs            = ($AllFGPPs | Where-Object { $_.RiskLevel -in @("Critical","High","Medium") }).Count
}

# Health Score
$HealthDeductions = 0.0
if ($Stats.TotalUsers     -gt 0) { $HealthDeductions += [Math]::Min(20, ($Stats.StaleUsers    / $Stats.TotalUsers   ) * 100) }
if ($Stats.TotalComputers -gt 0) { $HealthDeductions += [Math]::Min(20, ($Stats.StaleComputers/ $Stats.TotalComputers) * 100) }
if ($Stats.TotalComputers -gt 0) { $HealthDeductions += [Math]::Min(20, ($Stats.EOLComputers  / $Stats.TotalComputers) * 100) }
if ($Stats.TotalGPOs      -gt 0) { $HealthDeductions += [Math]::Min(10, ($Stats.UnlinkedGPOs  / $Stats.TotalGPOs    ) * 50 ) }
if ($Stats.TotalGroups    -gt 0) { $HealthDeductions += [Math]::Min(10, ($Stats.EmptyGroups   / $Stats.TotalGroups  ) * 50 ) }
if ($Stats.TotalUsers     -gt 0) { $HealthDeductions += [Math]::Min(10, ($Stats.PwNeverExpires/ $Stats.TotalUsers   ) * 50 ) }
if ($Stats.TotalFGPPs     -gt 0) { $HealthDeductions += [Math]::Min(10, ($Stats.WeakFGPPs     / $Stats.TotalFGPPs  ) * 50 ) }
$HealthScore  = [Math]::Max(0, [int](100 - $HealthDeductions))
$HealthColor  = if ($HealthScore -ge 80) { "#22c55e" } elseif ($HealthScore -ge 60) { "#f59e0b" } else { "#ef4444" }
$HealthLabel  = if ($HealthScore -ge 80) { "Healthy" } elseif ($HealthScore -ge 60) { "Needs Attention" } else { "Critical" }

$OSDist = $AllComputers | Group-Object OSCategory |
    ForEach-Object { [PSCustomObject]@{ OS = $_.Name; Count = $_.Count } } |
    Sort-Object Count -Descending

# Security Findings
$SecurityFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

$fgppCritical = @($AllFGPPs | Where-Object { $_.RiskLevel -eq "Critical" })
$fgppHigh     = @($AllFGPPs | Where-Object { $_.RiskLevel -eq "High" })
$fgppRevEnc   = @($AllFGPPs | Where-Object { $_.RevEncryptEnabled -eq $true })
$fgppNoLock   = @($AllFGPPs | Where-Object { $_.NoLockout -eq $true })
$fgppNoExpiry = @($AllFGPPs | Where-Object { $_.NoExpiry -eq $true })
$fgppWeakLen  = @($AllFGPPs | Where-Object { $_.WeakMinLength -eq $true })
$fgppNoCmplx  = @($AllFGPPs | Where-Object { $_.ComplexityDisabled -eq $true })

$findingDefs = @(
    @{ Cond=($Stats.EOLComputers   -gt 0);  Risk="Critical"; Cat="Computers";       Title="End-of-Life Operating Systems Detected";          Detail="$($Stats.EOLComputers) computer(s) run unsupported OS versions (XP, Vista, 7, Server 2003/2008).";                                    Fix="Upgrade or decommission EOL systems immediately to eliminate unpatched vulnerabilities." }
    @{ Cond=($fgppCritical.Count   -gt 0);  Risk="Critical"; Cat="FGPP";            Title="Critically Weak Fine-Grained Password Policies";  Detail="$($fgppCritical.Count) FGPP(s) have 3+ weak settings: $(($fgppCritical.Name -join ', ')).";                                           Fix="Review and harden these FGPPs immediately. Apply minimum 12-char passwords, lockout after 5 attempts, and enforce expiry." }
    @{ Cond=($Stats.StaleUsers     -gt 0);  Risk="High";     Cat="User Accounts";   Title="Stale Enabled User Accounts";                     Detail="$($Stats.StaleUsers) enabled user(s) have not logged on for over $StaleUserDays days.";                                                Fix="Disable and schedule deletion of stale accounts to reduce lateral movement risk." }
    @{ Cond=($Stats.StaleComputers -gt 0);  Risk="High";     Cat="Computers";       Title="Stale Enabled Computer Accounts";                 Detail="$($Stats.StaleComputers) enabled computer(s) inactive for over $StaleComputerDays days.";                                             Fix="Disable stale computer accounts and investigate if the machines are still in use." }
    @{ Cond=($fgppHigh.Count       -gt 0);  Risk="High";     Cat="FGPP";            Title="High-Risk Fine-Grained Password Policies";        Detail="$($fgppHigh.Count) FGPP(s) have 2 weak settings: $(($fgppHigh.Name -join ', ')).";                                                   Fix="Harden affected FGPPs: enable complexity, set max password age, and configure account lockout." }
    @{ Cond=($fgppRevEnc.Count     -gt 0);  Risk="High";     Cat="FGPP";            Title="FGPPs with Reversible Encryption Enabled";        Detail="$($fgppRevEnc.Count) FGPP(s) store passwords with reversible encryption: $(($fgppRevEnc.Name -join ', ')).";                         Fix="Disable reversible encryption in all FGPPs unless required for specific legacy applications (e.g. CHAP)." }
    @{ Cond=($fgppNoLock.Count     -gt 0);  Risk="Medium";   Cat="FGPP";            Title="FGPPs Without Account Lockout";                   Detail="$($fgppNoLock.Count) FGPP(s) have LockoutThreshold = 0: $(($fgppNoLock.Name -join ', ')).";                                          Fix="Set lockout threshold to 5-10 attempts and configure lockout duration/observation window." }
    @{ Cond=($fgppNoExpiry.Count   -gt 0);  Risk="Medium";   Cat="FGPP";            Title="FGPPs Without Password Expiry";                   Detail="$($fgppNoExpiry.Count) FGPP(s) have MaxPasswordAge = Never: $(($fgppNoExpiry.Name -join ', ')).";                                     Fix="Set an appropriate MaxPasswordAge (90-365 days) unless managing Managed Service Accounts." }
    @{ Cond=($Stats.PwNeverExpires -gt 0);  Risk="Medium";   Cat="Password Policy"; Title="Accounts with Non-Expiring Passwords";            Detail="$($Stats.PwNeverExpires) account(s) have PasswordNeverExpires = True.";                                                               Fix="Enforce password rotation unless accounts use LAPS or Managed Service Account passwords." }
    @{ Cond=($Stats.UnlinkedGPOs   -gt 0);  Risk="Medium";   Cat="Group Policy";    Title="Unlinked Group Policy Objects";                   Detail="$($Stats.UnlinkedGPOs) GPO(s) are not linked to any OU and have zero effect.";                                                        Fix="Review and delete unlinked GPOs to reduce administrative overhead and confusion." }
    @{ Cond=($Stats.LockedOutUsers -gt 0);  Risk="Medium";   Cat="User Accounts";   Title="Currently Locked Out Accounts";                   Detail="$($Stats.LockedOutUsers) account(s) are currently locked out.";                                                                       Fix="Investigate the lockout source (bad password spray?). Resolve or disable the accounts." }
    @{ Cond=($fgppWeakLen.Count    -gt 0);  Risk="Medium";   Cat="FGPP";            Title="FGPPs With Short Minimum Password Length";        Detail="$($fgppWeakLen.Count) FGPP(s) allow passwords shorter than 8 characters: $(($fgppWeakLen.Name -join ', ')).";                        Fix="Increase MinPasswordLength to at least 12 characters (NIST recommends 15+ for privileged accounts)." }
    @{ Cond=($fgppNoCmplx.Count    -gt 0);  Risk="Medium";   Cat="FGPP";            Title="FGPPs With Complexity Disabled";                  Detail="$($fgppNoCmplx.Count) FGPP(s) do not require password complexity: $(($fgppNoCmplx.Name -join ', ')).";                              Fix="Enable complexity requirements or compensate with a longer passphrase minimum length (15+ chars)." }
    @{ Cond=($Stats.EmptyGroups    -gt 0);  Risk="Low";      Cat="Groups";          Title="Empty Security Groups";                           Detail="$($Stats.EmptyGroups) group(s) have no members and add unnecessary complexity.";                                                      Fix="Remove empty groups unless they are placeholders for future use." }
    @{ Cond=($Stats.DisabledGPOs   -gt 0);  Risk="Low";      Cat="Group Policy";    Title="Fully Disabled GPOs";                             Detail="$($Stats.DisabledGPOs) GPO(s) have all settings disabled.";                                                                          Fix="Delete disabled GPOs that serve no purpose to keep the environment clean." }
    @{ Cond=($Stats.TrueDisabledUsers -gt ($Stats.TotalUsers * 0.3)); Risk="Low"; Cat="User Accounts"; Title="High Ratio of Truly Disabled Accounts"; Detail="Over 30% of user accounts are disabled and not Exchange mailboxes ($($Stats.TrueDisabledUsers) real disabled of $($Stats.TotalUsers) total). Note: $($Stats.DisabledUsers - $Stats.TrueDisabledUsers) disabled account(s) are shared/room/equipment mailboxes (expected)."; Fix="Review truly disabled accounts and delete those no longer needed per your retention policy." }
)

foreach ($fd in $findingDefs) {
    if ($fd.Cond) {
        $SecurityFindings.Add([PSCustomObject]@{
            Risk        = $fd.Risk
            Category    = $fd.Cat
            Finding     = $fd.Title
            Detail      = $fd.Detail
            Remediation = $fd.Fix
        })
    }
}

# ============================================================
# REGION 5 – SERIALIZE TO JSON
# ============================================================
Write-Host "[...] Serializing data to JSON..." -ForegroundColor Yellow

$UsersJson     = ConvertTo-SafeJson $AllUsers
$ComputersJson = ConvertTo-SafeJson $AllComputers
$GroupsJson    = ConvertTo-SafeJson $AllGroups
$GPOsJson      = ConvertTo-SafeJson $AllGPOs
$OUsJson       = ConvertTo-SafeJson $AllOUs
$DCsJson       = ConvertTo-SafeJson $AllDCs
$FGPPsJson     = ConvertTo-SafeJson $AllFGPPs
$FindingsJson  = ConvertTo-SafeJson $SecurityFindings.ToArray()
$OsDistJson    = ConvertTo-SafeJson $OSDist

$ReportDate             = $Now.ToString("dddd, MMMM dd, yyyy HH:mm")
$DomainFunctionalLevel  = $DomainInfo.DomainMode.ToString()
$ForestFunctionalLevel  = $ForestInfo.ForestMode.ToString()
$PDCEmulator            = $DomainInfo.PDCEmulator
$RIDMaster              = $DomainInfo.RIDMaster
$InfraMaster            = $DomainInfo.InfrastructureMaster
$NetBIOS                = $DomainInfo.NetBIOSName
$ForestName             = $ForestInfo.Name
$PwMinLength  = $DefaultPwPolicy.MinPasswordLength
$PwMaxAge     = $DefaultPwPolicy.MaxPasswordAge.Days
$PwMinAge     = $DefaultPwPolicy.MinPasswordAge.Days
$PwHistory    = $DefaultPwPolicy.PasswordHistoryCount
$LockoutThr   = $DefaultPwPolicy.LockoutThreshold
$LockoutDur   = $DefaultPwPolicy.LockoutDuration.Minutes
$PwComplex    = $DefaultPwPolicy.ComplexityEnabled.ToString()
$PwRevEnc     = $DefaultPwPolicy.ReversibleEncryptionEnabled.ToString()
$FindingsCount = $SecurityFindings.Count

# ============================================================
# REGION 6 – HTML REPORT
# ============================================================
Write-Host "[...] Building HTML report..." -ForegroundColor Yellow

$HTML = @"
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD Health Report - $Domain</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
<link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.2/css/buttons.dataTables.min.css">
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.print.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#f1f5f9;--surface:#fff;--surface2:#f8fafc;--border:#e2e8f0;--text:#1e293b;--text2:#64748b;--primary:#3b82f6;--success:#22c55e;--warning:#f59e0b;--danger:#ef4444;--info:#06b6d4;--purple:#8b5cf6;--orange:#f97316;--shadow:0 1px 3px rgba(0,0,0,.1),0 1px 2px rgba(0,0,0,.06);--shadow-md:0 4px 6px rgba(0,0,0,.07),0 2px 4px rgba(0,0,0,.06);--radius:12px;}
[data-theme="dark"]{--bg:#0f172a;--surface:#1e293b;--surface2:#0f172a;--border:#334155;--text:#f1f5f9;--text2:#94a3b8;--shadow:0 1px 3px rgba(0,0,0,.4);--shadow-md:0 4px 6px rgba(0,0,0,.4);}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;}
.hdr{background:linear-gradient(135deg,#0f2952 0%,#1d4ed8 55%,#0ea5e9 100%);color:#fff;padding:22px 32px;display:flex;justify-content:space-between;align-items:center;box-shadow:0 4px 20px rgba(29,78,216,.35);}
.hdr h1{font-size:1.6rem;font-weight:800;letter-spacing:-.5px;}
.hdr p{opacity:.85;margin-top:4px;font-size:.85rem;}
.hdr-right{text-align:right;font-size:.82rem;opacity:.9;}
.theme-btn{background:rgba(255,255,255,.2);border:none;color:#fff;padding:7px 14px;border-radius:8px;cursor:pointer;font-size:.82rem;transition:.2s;}
.theme-btn:hover{background:rgba(255,255,255,.3);}
.nav{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;display:flex;gap:0;overflow-x:auto;position:sticky;top:0;z-index:100;box-shadow:var(--shadow);}
.nav-btn{padding:14px 16px;border:none;background:none;color:var(--text2);cursor:pointer;font-size:.82rem;font-weight:600;white-space:nowrap;border-bottom:3px solid transparent;transition:.2s;}
.nav-btn:hover{color:var(--primary);background:rgba(59,130,246,.05);}
.nav-btn.active{color:var(--primary);border-bottom-color:var(--primary);}
.nav-badge{display:inline-flex;align-items:center;justify-content:center;background:var(--danger);color:#fff;border-radius:10px;font-size:.68rem;font-weight:700;padding:1px 6px;margin-left:4px;}
.main{padding:24px 28px;max-width:1700px;margin:0 auto;}
.section{display:none;animation:fadeIn .25s ease;}
.section.active{display:block;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.cards-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(185px,1fr));gap:14px;margin-bottom:20px;}
.card{background:var(--surface);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow);border:1px solid var(--border);transition:box-shadow .2s;}
.card:hover{box-shadow:var(--shadow-md);}
.card-hdr{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;}
.card-icon{width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:1.15rem;}
.card-val{font-size:1.9rem;font-weight:800;line-height:1;}
.card-lbl{font-size:.75rem;color:var(--text2);margin-top:3px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;}
.stat-row{display:flex;justify-content:space-between;font-size:.77rem;margin-top:4px;}
.stat-row .lbl{color:var(--text2);}
.stat-row .val{font-weight:700;}
.health-wrap{grid-column:span 2;}
@media(max-width:768px){.health-wrap{grid-column:span 1;}}
.health-val{font-size:3.2rem;font-weight:900;color:#fff;}
.progress-bar{height:7px;background:rgba(255,255,255,.25);border-radius:4px;overflow:hidden;margin-top:10px;}
.progress-fill{height:100%;border-radius:4px;background:#fff;transition:width .7s ease;}
.charts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:18px;margin-bottom:20px;}
.chart-card{background:var(--surface);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow);border:1px solid var(--border);}
.chart-title{font-size:.9rem;font-weight:700;margin-bottom:14px;color:var(--text);}
.chart-wrap{position:relative;height:210px;}
/* ── Table cards: overflow-x scoped inside card ── */
.tbl-card{background:var(--surface);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow);border:1px solid var(--border);margin-bottom:18px;overflow:hidden;}
.tbl-card .dataTables_wrapper{overflow-x:auto;width:100%;}
.tbl-hdr{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:14px;flex-wrap:wrap;gap:10px;}
.tbl-title{font-size:1rem;font-weight:700;}
/* ── Multi-filter group ── */
.filter-group{display:flex;gap:6px;flex-wrap:wrap;align-items:center;}
.filter-btn{padding:5px 12px;border-radius:20px;border:1px solid var(--border);background:var(--surface2);color:var(--text2);cursor:pointer;font-size:.77rem;font-weight:600;transition:.2s;user-select:none;}
.filter-btn:hover{background:rgba(59,130,246,.12);color:var(--primary);border-color:var(--primary);}
.filter-btn.active{background:var(--primary);color:#fff;border-color:var(--primary);}
.filter-btn.f-all.active{background:var(--text2);border-color:var(--text2);}
.filter-sep{width:1px;height:20px;background:var(--border);margin:0 4px;}
.active-filter-hint{font-size:.72rem;color:var(--primary);font-weight:600;margin-left:4px;opacity:.9;}
table.dataTable{border-collapse:collapse;font-size:.82rem;}
table.dataTable thead th{background:var(--surface2);color:var(--text2);font-weight:700;font-size:.72rem;text-transform:uppercase;letter-spacing:.4px;padding:9px 11px;border-bottom:2px solid var(--border);white-space:nowrap;}
table.dataTable tbody td{padding:9px 11px;border-bottom:1px solid var(--border);vertical-align:middle;}
table.dataTable tbody tr:hover td{background:rgba(59,130,246,.04);}
.dataTables_wrapper .dataTables_filter input,.dataTables_wrapper .dataTables_length select{border:1px solid var(--border);border-radius:7px;padding:5px 9px;background:var(--surface2);color:var(--text);font-size:.82rem;}
.dataTables_wrapper .dataTables_info,.dataTables_wrapper .dataTables_paginate{color:var(--text2);font-size:.78rem;margin-top:8px;}
.dataTables_wrapper .dataTables_paginate .paginate_button{border-radius:5px!important;color:var(--text)!important;}
.dataTables_wrapper .dataTables_paginate .paginate_button.current{background:var(--primary)!important;color:#fff!important;border-color:var(--primary)!important;}
.dt-buttons .dt-button{background:var(--surface2)!important;border:1px solid var(--border)!important;color:var(--text2)!important;border-radius:6px!important;padding:4px 11px!important;font-size:.77rem!important;font-weight:600!important;margin-right:3px!important;}
.dt-buttons .dt-button:hover{background:var(--primary)!important;color:#fff!important;border-color:var(--primary)!important;}
[data-theme="dark"] table.dataTable thead th{background:#1e293b;color:#94a3b8;border-color:#334155;}
[data-theme="dark"] table.dataTable tbody td{border-color:#334155;}
[data-theme="dark"] .dataTables_wrapper .dataTables_filter input,[data-theme="dark"] .dataTables_wrapper .dataTables_length select{background:#1e293b;border-color:#334155;color:#f1f5f9;}
[data-theme="dark"] .dataTables_wrapper .dataTables_info,[data-theme="dark"] .dataTables_wrapper .dataTables_paginate{color:#94a3b8;}
[data-theme="dark"] .dataTables_wrapper .dataTables_paginate .paginate_button{color:#94a3b8!important;}
.badge{display:inline-flex;align-items:center;padding:2px 9px;border-radius:20px;font-size:.72rem;font-weight:700;white-space:nowrap;}
.b-active{background:#dcfce7;color:#166534;}.b-stale{background:#fee2e2;color:#991b1b;}
.b-warning{background:#fef3c7;color:#92400e;}.b-disabled{background:#f1f5f9;color:#475569;}
.b-mailbox{background:#ede9fe;color:#5b21b6;}
.b-empty{background:#fef3c7;color:#92400e;}.b-privileged{background:#ede9fe;color:#5b21b6;}
.b-unlinked{background:#ffedd5;color:#9a3412;}.b-linked{background:#dcfce7;color:#166534;}
.b-yes{background:#dcfce7;color:#166534;}.b-no{background:#f1f5f9;color:#475569;}
.b-eol{background:#fee2e2;color:#991b1b;}.b-critical{background:#fee2e2;color:#991b1b;}
.b-high{background:#ffedd5;color:#9a3412;}.b-medium{background:#fef3c7;color:#92400e;}
.b-low{background:#dbeafe;color:#1e40af;}.b-locked{background:#fee2e2;color:#991b1b;}
.b-good{background:#dcfce7;color:#166534;}
[data-theme="dark"] .b-active{background:#14532d;color:#86efac;}[data-theme="dark"] .b-stale{background:#7f1d1d;color:#fca5a5;}
[data-theme="dark"] .b-warning{background:#78350f;color:#fde68a;}[data-theme="dark"] .b-disabled{background:#1e293b;color:#94a3b8;}
[data-theme="dark"] .b-mailbox{background:#2e1065;color:#c4b5fd;}
[data-theme="dark"] .b-privileged{background:#2e1065;color:#c4b5fd;}[data-theme="dark"] .b-unlinked{background:#431407;color:#fdba74;}
[data-theme="dark"] .b-linked{background:#14532d;color:#86efac;}[data-theme="dark"] .b-yes{background:#14532d;color:#86efac;}
[data-theme="dark"] .b-no{background:#1e293b;color:#94a3b8;}[data-theme="dark"] .b-eol{background:#7f1d1d;color:#fca5a5;}
[data-theme="dark"] .b-critical{background:#7f1d1d;color:#fca5a5;}[data-theme="dark"] .b-high{background:#431407;color:#fdba74;}
[data-theme="dark"] .b-medium{background:#451a03;color:#fde68a;}[data-theme="dark"] .b-low{background:#1e3a5f;color:#93c5fd;}
[data-theme="dark"] .b-good{background:#14532d;color:#86efac;}
.rc-critical{background:#fee2e2!important;color:#991b1b;font-weight:700;}
.rc-high{background:#ffedd5!important;color:#9a3412;font-weight:700;}
.rc-medium{background:#fef3c7!important;color:#92400e;font-weight:700;}
.rc-good{background:#dcfce7!important;color:#166534;font-weight:700;}
[data-theme="dark"] .rc-critical{background:#7f1d1d!important;color:#fca5a5;}[data-theme="dark"] .rc-high{background:#431407!important;color:#fdba74;}
[data-theme="dark"] .rc-medium{background:#2d2a0a!important;color:#fde68a;}[data-theme="dark"] .rc-good{background:#14532d!important;color:#86efac;}
.fgpp-compare{overflow-x:auto;margin-top:16px;}
.fgpp-compare table{border-collapse:collapse;min-width:700px;}
.fgpp-compare th{background:var(--surface2);padding:9px 14px;font-size:.72rem;text-transform:uppercase;letter-spacing:.4px;color:var(--text2);border:1px solid var(--border);font-weight:700;}
.fgpp-compare td{padding:9px 14px;border:1px solid var(--border);font-size:.82rem;}
.fgpp-compare tr:hover td{background:rgba(59,130,246,.04);}
.fgpp-label-col{font-weight:700;color:var(--text2);background:var(--surface2)!important;font-size:.78rem;}
.finding{border-radius:10px;padding:14px 16px;margin-bottom:10px;border-left:4px solid;}
.f-critical{background:#fff5f5;border-color:var(--danger);}.f-high{background:#fff8f1;border-color:var(--orange);}
.f-medium{background:#fffbeb;border-color:var(--warning);}.f-low{background:#eff6ff;border-color:var(--info);}
[data-theme="dark"] .f-critical{background:#2d1515;}[data-theme="dark"] .f-high{background:#2d1f0a;}
[data-theme="dark"] .f-medium{background:#2d2a0a;}[data-theme="dark"] .f-low{background:#0f1f35;}
.f-title{font-weight:800;font-size:.92rem;margin-bottom:4px;}
.f-detail{font-size:.82rem;color:var(--text2);margin-bottom:6px;}
.f-fix{font-size:.8rem;background:rgba(0,0,0,.05);padding:5px 10px;border-radius:6px;}
[data-theme="dark"] .f-fix{background:rgba(255,255,255,.05);}
.info-grid,.policy-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;}
.info-item{display:flex;flex-direction:column;gap:2px;}
.i-lbl{font-size:.7rem;color:var(--text2);font-weight:700;text-transform:uppercase;letter-spacing:.4px;}
.i-val{font-size:.88rem;font-weight:600;}
.pol-item{background:var(--surface2);padding:11px 14px;border-radius:8px;border:1px solid var(--border);}
.pol-lbl{font-size:.7rem;color:var(--text2);font-weight:700;text-transform:uppercase;letter-spacing:.4px;margin-bottom:3px;}
.pol-val{font-size:1.05rem;font-weight:800;}
.sec-hdr{font-size:1.3rem;font-weight:800;margin-bottom:18px;display:flex;align-items:center;gap:9px;}
.sec-icon{width:34px;height:34px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:1rem;background:rgba(59,130,246,.1);}
.empty-msg{text-align:center;padding:32px;color:var(--text2);font-size:.88rem;}
.mbx-note{background:rgba(139,92,246,.07);border:1px solid rgba(139,92,246,.25);border-radius:8px;padding:10px 14px;font-size:.8rem;color:var(--text2);margin-bottom:14px;display:flex;align-items:flex-start;gap:8px;}
.mbx-note strong{color:var(--text);}
</style>
</head>
<body>

<div class="hdr">
  <div>
    <h1>&#x1F6E1;&#xFE0F; Active Directory Health Report</h1>
    <p>Domain: <strong>$Domain</strong> &nbsp;|&nbsp; Generated: $ReportDate &nbsp;|&nbsp; Stale threshold - Users: $StaleUserDays d / Computers: $StaleComputerDays d</p>
  </div>
  <div class="hdr-right">
    <button class="theme-btn" onclick="toggleTheme()">&#9728; Toggle Dark Mode</button>
    <div style="margin-top:7px;opacity:.8;">$NetBIOS &nbsp;|&nbsp; $DomainFunctionalLevel</div>
  </div>
</div>

<nav class="nav">
  <button class="nav-btn active" onclick="showSection('dashboard',this)">&#x1F4CA; Dashboard</button>
  <button class="nav-btn" onclick="showSection('users',this)">&#x1F464; Users <span id="navUsers"></span></button>
  <button class="nav-btn" onclick="showSection('computers',this)">&#x1F4BB; Computers <span id="navComputers"></span></button>
  <button class="nav-btn" onclick="showSection('groups',this)">&#x1F465; Groups <span id="navGroups"></span></button>
  <button class="nav-btn" onclick="showSection('gpos',this)">&#x1F4DC; GPOs <span id="navGPOs"></span></button>
  <button class="nav-btn" onclick="showSection('ous',this)">&#x1F3E2; OUs ($($Stats.TotalOUs))</button>
  <button class="nav-btn" onclick="showSection('dcs',this)">&#x1F5A5;&#xFE0F; DCs ($($Stats.TotalDCs))</button>
  <button class="nav-btn" onclick="showSection('pwpolicies',this)">&#x1F512; Password Policies <span id="navFGPP"></span></button>
  <button class="nav-btn" onclick="showSection('findings',this)">&#x26A0;&#xFE0F; Findings <span id="navFindings"></span></button>
</nav>

<div class="main">

<!-- ════════════ DASHBOARD ════════════ -->
<div id="dashboard" class="section active">
  <div class="sec-hdr"><div class="sec-icon">&#x1F4CA;</div>Executive Dashboard</div>
  <div class="cards-grid">
    <div class="card health-wrap" style="background:linear-gradient(135deg,#0f2952,$HealthColor);border:none;color:#fff;">
      <div style="opacity:.75;font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;">AD Health Score</div>
      <div class="health-val">$HealthScore<span style="font-size:1.4rem;opacity:.7;">/100</span></div>
      <div style="font-size:.85rem;opacity:.85;margin-top:4px;font-weight:600;">$HealthLabel</div>
      <div class="progress-bar"><div class="progress-fill" style="width:$($HealthScore)%;"></div></div>
      <div style="font-size:.75rem;opacity:.7;margin-top:7px;">Based on stale objects, EOL systems, FGPP hygiene &amp; password policy</div>
    </div>
    <div class="card">
      <div class="card-hdr"><div><div class="card-val">$($Stats.TotalUsers)</div><div class="card-lbl">Users</div></div><div class="card-icon" style="background:#dbeafe;color:#1d4ed8;">&#x1F464;</div></div>
      <div class="stat-row"><span class="lbl">Enabled</span><span class="val" style="color:var(--success)">$($Stats.EnabledUsers)</span></div>
      <div class="stat-row"><span class="lbl">Disabled (real)</span><span class="val" style="color:var(--text2)">$($Stats.TrueDisabledUsers)</span></div>
      <div class="stat-row"><span class="lbl">&#x1F4E7; Shared Mailboxes</span><span class="val" style="color:var(--purple)">$($Stats.SharedMailboxes)</span></div>
      <div class="stat-row"><span class="lbl">&#x26A0; Stale</span><span class="val" style="color:var(--danger)">$($Stats.StaleUsers)</span></div>
      <div class="stat-row"><span class="lbl">Admins</span><span class="val" style="color:var(--purple)">$($Stats.AdminUsers)</span></div>
    </div>
    <div class="card">
      <div class="card-hdr"><div><div class="card-val">$($Stats.TotalComputers)</div><div class="card-lbl">Computers</div></div><div class="card-icon" style="background:#dcfce7;color:#166534;">&#x1F4BB;</div></div>
      <div class="stat-row"><span class="lbl">Enabled</span><span class="val" style="color:var(--success)">$($Stats.EnabledComputers)</span></div>
      <div class="stat-row"><span class="lbl">Servers</span><span class="val" style="color:var(--info)">$($Stats.ServerCount)</span></div>
      <div class="stat-row"><span class="lbl">&#x26A0; Stale</span><span class="val" style="color:var(--danger)">$($Stats.StaleComputers)</span></div>
      <div class="stat-row"><span class="lbl">&#x1F534; EOL</span><span class="val" style="color:var(--danger)">$($Stats.EOLComputers)</span></div>
    </div>
    <div class="card">
      <div class="card-hdr"><div><div class="card-val">$($Stats.TotalGroups)</div><div class="card-lbl">Groups</div></div><div class="card-icon" style="background:#ede9fe;color:#5b21b6;">&#x1F465;</div></div>
      <div class="stat-row"><span class="lbl">Privileged</span><span class="val" style="color:var(--purple)">$($Stats.PrivilegedGroups)</span></div>
      <div class="stat-row"><span class="lbl">&#x26A0; Empty</span><span class="val" style="color:var(--warning)">$($Stats.EmptyGroups)</span></div>
    </div>
    <div class="card">
      <div class="card-hdr"><div><div class="card-val">$($Stats.TotalGPOs)</div><div class="card-lbl">GPOs</div></div><div class="card-icon" style="background:#fef3c7;color:#92400e;">&#x1F4DC;</div></div>
      <div class="stat-row"><span class="lbl">&#x26A0; Unlinked</span><span class="val" style="color:var(--warning)">$($Stats.UnlinkedGPOs)</span></div>
      <div class="stat-row"><span class="lbl">Disabled</span><span class="val" style="color:var(--text2)">$($Stats.DisabledGPOs)</span></div>
    </div>
    <div class="card">
      <div class="card-hdr"><div><div class="card-val">$($Stats.TotalFGPPs)</div><div class="card-lbl">Fine-Grained Policies</div></div><div class="card-icon" style="background:#fce7f3;color:#9d174d;">&#x1F512;</div></div>
      <div class="stat-row"><span class="lbl">&#x26A0; Weak / At-Risk</span><span class="val" style="color:var(--danger)">$($Stats.WeakFGPPs)</span></div>
      <div class="stat-row"><span class="lbl">&#x2705; Good Posture</span><span class="val" style="color:var(--success)">$($Stats.TotalFGPPs - $Stats.WeakFGPPs)</span></div>
    </div>
    <div class="card">
      <div class="card-hdr"><div><div class="card-val">$($Stats.TotalDCs)</div><div class="card-lbl">Domain Controllers</div></div><div class="card-icon" style="background:#fff1f2;color:#be123c;">&#x1F5A5;</div></div>
      <div class="stat-row"><span class="lbl">Global Catalogs</span><span class="val" style="color:var(--info)">$($Stats.GlobalCatalogs)</span></div>
      <div class="stat-row"><span class="lbl">RODCs</span><span class="val" style="color:var(--text2)">$($Stats.RODCs)</span></div>
    </div>
    <div class="card">
      <div class="card-hdr"><div><div class="card-val" style="color:var(--danger)">$FindingsCount</div><div class="card-lbl">Security Findings</div></div><div class="card-icon" style="background:#fee2e2;color:#991b1b;">&#x26A0;</div></div>
      <div class="stat-row"><span class="lbl">Pw Never Expires</span><span class="val" style="color:var(--warning)">$($Stats.PwNeverExpires)</span></div>
      <div class="stat-row"><span class="lbl">Locked Out</span><span class="val" style="color:var(--danger)">$($Stats.LockedOutUsers)</span></div>
    </div>
  </div>
  <div class="charts-grid">
    <div class="chart-card"><div class="chart-title">&#x1F464; User Account Status</div><div class="chart-wrap"><canvas id="cUserStatus"></canvas></div></div>
    <div class="chart-card"><div class="chart-title">&#x1F4BB; Computer OS Distribution</div><div class="chart-wrap"><canvas id="cOSDist"></canvas></div></div>
    <div class="chart-card"><div class="chart-title">&#x1F9F9; Stale &amp; At-Risk Objects</div><div class="chart-wrap"><canvas id="cStale"></canvas></div></div>
    <div class="chart-card"><div class="chart-title">&#x1F4DC; GPO Status Overview</div><div class="chart-wrap"><canvas id="cGPO"></canvas></div></div>
  </div>
  <div class="card" style="margin-bottom:16px;">
    <div class="chart-title" style="margin-bottom:14px;">&#x1F310; Domain &amp; Forest Information</div>
    <div class="info-grid">
      <div class="info-item"><div class="i-lbl">DNS Domain</div><div class="i-val">$Domain</div></div>
      <div class="info-item"><div class="i-lbl">NetBIOS Name</div><div class="i-val">$NetBIOS</div></div>
      <div class="info-item"><div class="i-lbl">Forest</div><div class="i-val">$ForestName</div></div>
      <div class="info-item"><div class="i-lbl">Domain Functional Level</div><div class="i-val">$DomainFunctionalLevel</div></div>
      <div class="info-item"><div class="i-lbl">Forest Functional Level</div><div class="i-val">$ForestFunctionalLevel</div></div>
      <div class="info-item"><div class="i-lbl">PDC Emulator</div><div class="i-val">$PDCEmulator</div></div>
      <div class="info-item"><div class="i-lbl">RID Master</div><div class="i-val">$RIDMaster</div></div>
      <div class="info-item"><div class="i-lbl">Infrastructure Master</div><div class="i-val">$InfraMaster</div></div>
    </div>
  </div>
  <div class="card">
    <div class="chart-title" style="margin-bottom:14px;">&#x1F512; Default Domain Password Policy</div>
    <div class="policy-grid">
      <div class="pol-item"><div class="pol-lbl">Min Password Length</div><div class="pol-val">$PwMinLength chars</div></div>
      <div class="pol-item"><div class="pol-lbl">Max Password Age</div><div class="pol-val">$PwMaxAge days</div></div>
      <div class="pol-item"><div class="pol-lbl">Min Password Age</div><div class="pol-val">$PwMinAge days</div></div>
      <div class="pol-item"><div class="pol-lbl">Password History</div><div class="pol-val">$PwHistory remembered</div></div>
      <div class="pol-item"><div class="pol-lbl">Lockout Threshold</div><div class="pol-val">$LockoutThr attempts</div></div>
      <div class="pol-item"><div class="pol-lbl">Lockout Duration</div><div class="pol-val">$LockoutDur minutes</div></div>
      <div class="pol-item"><div class="pol-lbl">Complexity Required</div><div class="pol-val">$PwComplex</div></div>
      <div class="pol-item"><div class="pol-lbl">Reversible Encryption</div><div class="pol-val">$PwRevEnc</div></div>
    </div>
  </div>
</div>

<!-- ════════════ USERS ════════════ -->
<div id="users" class="section">
  <div class="sec-hdr"><div class="sec-icon">&#x1F464;</div>User Accounts</div>
  <div class="mbx-note">
    <span>&#x2139;&#xFE0F;</span>
    <div><strong>Multi-filter tip:</strong> Click multiple filter buttons to combine them (OR logic for status, AND logic for attributes). Status filters: <em>Disabled (real)</em> shows only manually disabled accounts; <em>&#x1F4E7; Mailboxes</em> shows shared/room/equipment mailboxes. Exchange mailboxes are intentionally disabled — they are <strong>not</strong> a security concern.</div>
  </div>
  <div class="tbl-card">
    <div class="tbl-hdr">
      <div class="tbl-title">All Users <span id="userFilterHint" class="active-filter-hint"></span></div>
      <div class="filter-group" id="userFilters">
        <!-- Status filters (OR) -->
        <button class="filter-btn f-all active" id="userAll" onclick="mfClearStatus('userTable','userFilters','userAll','userFilterHint')">All</button>
        <button class="filter-btn" data-mf-status="Active"    onclick="mfToggleStatus('userTable','userFilters','userAll','userFilterHint',this)">&#x1F7E2; Active</button>
        <button class="filter-btn" data-mf-status="Warning"   onclick="mfToggleStatus('userTable','userFilters','userAll','userFilterHint',this)">&#x1F7E1; Warning</button>
        <button class="filter-btn" data-mf-status="Stale"     onclick="mfToggleStatus('userTable','userFilters','userAll','userFilterHint',this)">&#x1F534; Stale</button>
        <button class="filter-btn" data-mf-status="Disabled"  onclick="mfToggleStatus('userTable','userFilters','userAll','userFilterHint',this)">&#x26AA; Disabled (real)</button>
        <button class="filter-btn" data-mf-status="Mailbox"   onclick="mfToggleStatus('userTable','userFilters','userAll','userFilterHint',this)">&#x1F4E7; Mailboxes</button>
        <div class="filter-sep"></div>
        <!-- Attribute filters (AND) -->
        <button class="filter-btn" data-mf-attr="data-admin"  data-mf-val="true" onclick="mfToggleAttr('userTable','userFilters','userAll','userFilterHint',this)">&#x1F451; Admins</button>
        <button class="filter-btn" data-mf-attr="data-svc"    data-mf-val="true" onclick="mfToggleAttr('userTable','userFilters','userAll','userFilterHint',this)">&#x2699;&#xFE0F; Svc Accts</button>
        <button class="filter-btn" data-mf-attr="data-locked" data-mf-val="true" onclick="mfToggleAttr('userTable','userFilters','userAll','userFilterHint',this)">&#x1F512; Locked Out</button>
        <button class="filter-btn" data-mf-attr="data-pwne"   data-mf-val="true" onclick="mfToggleAttr('userTable','userFilters','userAll','userFilterHint',this)">&#x231B; Pw Never Expires</button>
      </div>
    </div>
    <table id="userTable" class="dataTable display" style="width:100%">
      <thead><tr>
        <th>Display Name</th><th>Username</th><th>Department</th><th>Title</th>
        <th>Status</th><th>Account Type</th><th>Mailbox Type</th>
        <th>Last Logon</th><th>Days Since Logon</th><th>Pw Age (days)</th>
        <th>Pw Never Expires</th><th>Locked Out</th><th>Admin</th><th>Svc Acct</th><th>Created</th>
      </tr></thead>
      <tbody id="userTbody"></tbody>
    </table>
  </div>
</div>

<!-- ════════════ COMPUTERS ════════════ -->
<div id="computers" class="section">
  <div class="sec-hdr"><div class="sec-icon">&#x1F4BB;</div>Computer Accounts</div>
  <div class="tbl-card">
    <div class="tbl-hdr">
      <div class="tbl-title">All Computers <span id="compFilterHint" class="active-filter-hint"></span></div>
      <div class="filter-group" id="compFilters">
        <button class="filter-btn f-all active" id="compAll" onclick="mfClearStatus('compTable','compFilters','compAll','compFilterHint')">All</button>
        <button class="filter-btn" data-mf-status="Active"   onclick="mfToggleStatus('compTable','compFilters','compAll','compFilterHint',this)">&#x1F7E2; Active</button>
        <button class="filter-btn" data-mf-status="Warning"  onclick="mfToggleStatus('compTable','compFilters','compAll','compFilterHint',this)">&#x1F7E1; Warning</button>
        <button class="filter-btn" data-mf-status="Stale"    onclick="mfToggleStatus('compTable','compFilters','compAll','compFilterHint',this)">&#x1F534; Stale</button>
        <button class="filter-btn" data-mf-status="Disabled" onclick="mfToggleStatus('compTable','compFilters','compAll','compFilterHint',this)">&#x26AA; Disabled</button>
        <div class="filter-sep"></div>
        <button class="filter-btn" data-mf-attr="data-eol"   data-mf-val="true" onclick="mfToggleAttr('compTable','compFilters','compAll','compFilterHint',this)">&#x26A0;&#xFE0F; EOL Systems</button>
        <button class="filter-btn" data-mf-oscat="Server"    onclick="mfToggleOSCat('compTable','compFilters','compAll','compFilterHint',this)">&#x1F5A5; Servers</button>
      </div>
    </div>
    <table id="compTable" class="dataTable display" style="width:100%">
      <thead><tr><th>Computer Name</th><th>DNS Hostname</th><th>Operating System</th><th>OS Version</th><th>IP Address</th><th>Status</th><th>Last Logon</th><th>Days Inactive</th><th>EOL</th><th>Created</th><th>Description</th></tr></thead>
      <tbody id="compTbody"></tbody>
    </table>
  </div>
</div>

<!-- ════════════ GROUPS ════════════ -->
<div id="groups" class="section">
  <div class="sec-hdr"><div class="sec-icon">&#x1F465;</div>Groups</div>
  <div class="tbl-card">
    <div class="tbl-hdr">
      <div class="tbl-title">All Groups <span id="grpFilterHint" class="active-filter-hint"></span></div>
      <div class="filter-group" id="grpFilters">
        <button class="filter-btn f-all active" id="grpAll" onclick="mfClearStatus('grpTable','grpFilters','grpAll','grpFilterHint')">All</button>
        <button class="filter-btn" data-mf-status="Active"     onclick="mfToggleStatus('grpTable','grpFilters','grpAll','grpFilterHint',this)">&#x1F7E2; Active</button>
        <button class="filter-btn" data-mf-status="Empty"      onclick="mfToggleStatus('grpTable','grpFilters','grpAll','grpFilterHint',this)">&#x1F7E1; Empty</button>
        <button class="filter-btn" data-mf-status="Privileged" onclick="mfToggleStatus('grpTable','grpFilters','grpAll','grpFilterHint',this)">&#x1F451; Privileged</button>
      </div>
    </div>
    <table id="grpTable" class="dataTable display" style="width:100%">
      <thead><tr><th>Group Name</th><th>Scope</th><th>Category</th><th>Members</th><th>Status</th><th>Privileged</th><th>AdminCount</th><th>Managed By</th><th>Description</th><th>Created</th></tr></thead>
      <tbody id="grpTbody"></tbody>
    </table>
  </div>
</div>

<!-- ════════════ GPOs ════════════ -->
<div id="gpos" class="section">
  <div class="sec-hdr"><div class="sec-icon">&#x1F4DC;</div>Group Policy Objects</div>
  <div class="tbl-card">
    <div class="tbl-hdr">
      <div class="tbl-title">All GPOs <span id="gpoFilterHint" class="active-filter-hint"></span></div>
      <div class="filter-group" id="gpoFilters">
        <button class="filter-btn f-all active" id="gpoAll" onclick="mfClearStatus('gpoTable','gpoFilters','gpoAll','gpoFilterHint')">All</button>
        <button class="filter-btn" data-mf-status="Active"   onclick="mfToggleStatus('gpoTable','gpoFilters','gpoAll','gpoFilterHint',this)">&#x1F7E2; Active</button>
        <button class="filter-btn" data-mf-status="Unlinked" onclick="mfToggleStatus('gpoTable','gpoFilters','gpoAll','gpoFilterHint',this)">&#x1F534; Unlinked</button>
        <button class="filter-btn" data-mf-status="Disabled" onclick="mfToggleStatus('gpoTable','gpoFilters','gpoAll','gpoFilterHint',this)">&#x26AA; Disabled</button>
      </div>
    </div>
    <table id="gpoTable" class="dataTable display" style="width:100%">
      <thead><tr><th>GPO Name</th><th>Status</th><th>Linked</th><th>Computer Settings</th><th>User Settings</th><th>Created</th><th>Last Modified</th><th>Days Since Modified</th><th>Description</th></tr></thead>
      <tbody id="gpoTbody"></tbody>
    </table>
  </div>
</div>

<!-- ════════════ OUs ════════════ -->
<div id="ous" class="section">
  <div class="sec-hdr"><div class="sec-icon">&#x1F3E2;</div>Organizational Units</div>
  <div class="tbl-card">
    <div class="tbl-hdr"><div class="tbl-title">All OUs ($($Stats.TotalOUs))</div></div>
    <table id="ouTable" class="dataTable display" style="width:100%">
      <thead><tr><th>Name</th><th>Distinguished Name</th><th>Depth</th><th>Linked GPOs</th><th>Managed By</th><th>Description</th><th>Created</th></tr></thead>
      <tbody id="ouTbody"></tbody>
    </table>
  </div>
</div>

<!-- ════════════ DCs ════════════ -->
<div id="dcs" class="section">
  <div class="sec-hdr"><div class="sec-icon">&#x1F5A5;</div>Domain Controllers</div>
  <div class="tbl-card">
    <div class="tbl-hdr"><div class="tbl-title">All Domain Controllers ($($Stats.TotalDCs))</div></div>
    <table id="dcTable" class="dataTable display" style="width:100%">
      <thead><tr><th>Name</th><th>Hostname</th><th>IP Address</th><th>Site</th><th>Global Catalog</th><th>RODC</th><th>Operating System</th><th>Enabled</th></tr></thead>
      <tbody id="dcTbody"></tbody>
    </table>
  </div>
</div>

<!-- ════════════ PASSWORD POLICIES ════════════ -->
<div id="pwpolicies" class="section">
  <div class="sec-hdr"><div class="sec-icon">&#x1F512;</div>Password Policies</div>
  <div class="card" style="margin-bottom:18px;">
    <div class="chart-title" style="margin-bottom:14px;">&#x1F30D; Default Domain Password Policy <span style="font-size:.75rem;font-weight:400;color:var(--text2);margin-left:8px;">(applies to all accounts without an FGPP)</span></div>
    <div class="policy-grid">
      <div class="pol-item"><div class="pol-lbl">Min Password Length</div><div class="pol-val">$PwMinLength chars</div></div>
      <div class="pol-item"><div class="pol-lbl">Max Password Age</div><div class="pol-val">$PwMaxAge days</div></div>
      <div class="pol-item"><div class="pol-lbl">Min Password Age</div><div class="pol-val">$PwMinAge days</div></div>
      <div class="pol-item"><div class="pol-lbl">Password History</div><div class="pol-val">$PwHistory remembered</div></div>
      <div class="pol-item"><div class="pol-lbl">Lockout Threshold</div><div class="pol-val">$LockoutThr attempts</div></div>
      <div class="pol-item"><div class="pol-lbl">Lockout Duration</div><div class="pol-val">$LockoutDur minutes</div></div>
      <div class="pol-item"><div class="pol-lbl">Complexity Required</div><div class="pol-val">$PwComplex</div></div>
      <div class="pol-item"><div class="pol-lbl">Reversible Encryption</div><div class="pol-val">$PwRevEnc</div></div>
    </div>
  </div>
  <div class="card" style="margin-bottom:18px;">
    <div class="chart-title" style="margin-bottom:6px;">&#x1F4CA; Fine-Grained Password Policy Comparison</div>
    <div style="font-size:.8rem;color:var(--text2);margin-bottom:14px;">All FGPPs shown side-by-side. Lower precedence number = higher priority. Coloured cells highlight security risks.</div>
    <div id="fgppCompareBody"></div>
  </div>
  <div class="tbl-card">
    <div class="tbl-hdr">
      <div class="tbl-title">Fine-Grained Password Policies &ndash; Detail Table <span id="fgppFilterHint" class="active-filter-hint"></span></div>
      <div class="filter-group" id="fgppFilters">
        <button class="filter-btn f-all active" id="fgppAll" onclick="mfClearStatus('fgppTable','fgppFilters','fgppAll','fgppFilterHint')">All</button>
        <button class="filter-btn" data-mf-status="Good"     onclick="mfToggleStatus('fgppTable','fgppFilters','fgppAll','fgppFilterHint',this)">&#x2705; Good</button>
        <button class="filter-btn" data-mf-status="Medium"   onclick="mfToggleStatus('fgppTable','fgppFilters','fgppAll','fgppFilterHint',this)">&#x1F7E1; Medium Risk</button>
        <button class="filter-btn" data-mf-status="High"     onclick="mfToggleStatus('fgppTable','fgppFilters','fgppAll','fgppFilterHint',this)">&#x1F7E0; High Risk</button>
        <button class="filter-btn" data-mf-status="Critical" onclick="mfToggleStatus('fgppTable','fgppFilters','fgppAll','fgppFilterHint',this)">&#x1F534; Critical</button>
      </div>
    </div>
    <!-- FIX: tbody is intentionally EMPTY before DataTables init.
         DataTables' language.emptyTable handles the "no data" message,
         avoiding the "Incorrect column count" warning from colspan rows. -->
    <table id="fgppTable" class="dataTable display" style="width:100%">
      <thead><tr>
        <th>Policy Name</th><th>Precedence</th><th>Applies To</th>
        <th>Min Pw Length</th><th>Max Pw Age</th><th>Min Pw Age</th><th>History</th>
        <th>Lockout Threshold</th><th>Lockout Duration</th><th>Obs. Window</th>
        <th>Complexity</th><th>Rev. Encryption</th><th>Risk Level</th>
        <th>Last Changed</th><th>Description</th>
      </tr></thead>
      <tbody id="fgppTbody"></tbody>
    </table>
  </div>
</div>

<!-- ════════════ FINDINGS ════════════ -->
<div id="findings" class="section">
  <div class="sec-hdr"><div class="sec-icon">&#x26A0;</div>Security Findings &amp; Remediation</div>
  <div id="findingsBody"></div>
</div>

</div><!-- /main -->

<script>
// ── DATA ──────────────────────────────────────────────────────────
var DATA = {
  users:     $UsersJson,
  computers: $ComputersJson,
  groups:    $GroupsJson,
  gpos:      $GPOsJson,
  ous:       $OUsJson,
  dcs:       $DCsJson,
  fgpps:     $FGPPsJson,
  findings:  $FindingsJson,
  osDist:    $OsDistJson
};

// ── MULTI-FILTER ENGINE ───────────────────────────────────────────
// Each table has its own state: { statuses: [], attrs: {}, oscat: '' }
var MF = {};
function mfState(tid) {
  if (!MF[tid]) MF[tid] = { statuses: [], attrs: {}, oscat: '' };
  return MF[tid];
}

// Toggle a STATUS filter button (OR logic: any matching status shown)
function mfToggleStatus(tid, fgId, allId, hintId, btn) {
  var st = mfState(tid);
  var val = btn.getAttribute('data-mf-status');
  var idx = st.statuses.indexOf(val);
  if (idx >= 0) { st.statuses.splice(idx,1); btn.classList.remove('active'); }
  else           { st.statuses.push(val);    btn.classList.add('active'); }
  document.getElementById(allId).classList.remove('active');
  if (st.statuses.length === 0 && Object.keys(st.attrs).length === 0 && !st.oscat) {
    document.getElementById(allId).classList.add('active');
  }
  mfApply(tid, hintId);
}

// Toggle an ATTRIBUTE filter button (AND logic: all attr filters must match)
function mfToggleAttr(tid, fgId, allId, hintId, btn) {
  var st = mfState(tid);
  var attr = btn.getAttribute('data-mf-attr');
  var val  = btn.getAttribute('data-mf-val');
  if (st.attrs[attr]) { delete st.attrs[attr]; btn.classList.remove('active'); }
  else                { st.attrs[attr] = val;  btn.classList.add('active'); }
  document.getElementById(allId).classList.remove('active');
  if (st.statuses.length === 0 && Object.keys(st.attrs).length === 0 && !st.oscat) {
    document.getElementById(allId).classList.add('active');
  }
  mfApply(tid, hintId);
}

// Toggle OS-category filter (for Computers tab)
function mfToggleOSCat(tid, fgId, allId, hintId, btn) {
  var st = mfState(tid);
  var cat = btn.getAttribute('data-mf-oscat');
  if (st.oscat === cat) { st.oscat = ''; btn.classList.remove('active'); }
  else                  { st.oscat = cat; btn.classList.add('active'); }
  document.getElementById(allId).classList.remove('active');
  if (st.statuses.length === 0 && Object.keys(st.attrs).length === 0 && !st.oscat) {
    document.getElementById(allId).classList.add('active');
  }
  mfApply(tid, hintId);
}

// Clear ALL filters for a table (All button)
function mfClearStatus(tid, fgId, allId, hintId) {
  MF[tid] = { statuses: [], attrs: {}, oscat: '' };
  var grp = document.getElementById(fgId);
  grp.querySelectorAll('.filter-btn').forEach(function(b){ b.classList.remove('active'); });
  document.getElementById(allId).classList.add('active');
  mfApply(tid, hintId);
}

// Apply current filter state to all tbody rows
function mfApply(tid, hintId) {
  try {
    var st = mfState(tid);
    var dt = jQuery('#'+tid).DataTable();
    var hasStatus = st.statuses.length > 0;
    var attrKeys  = Object.keys(st.attrs);
    var hasAttr   = attrKeys.length > 0;
    var hasOSCat  = !!st.oscat;
    var total = 0, visible = 0;

    jQuery('#'+tid+' tbody tr').each(function(){
      var row = jQuery(this);
      total++;
      // Status: OR logic
      var statusOk = !hasStatus || st.statuses.indexOf(row.attr('data-status')) >= 0;
      // Attrs: AND logic
      var attrOk = true;
      for (var i = 0; i < attrKeys.length; i++) {
        if (row.attr(attrKeys[i]) !== st.attrs[attrKeys[i]]) { attrOk = false; break; }
      }
      // OS category: contains check
      var osOk = !hasOSCat || ((row.attr('data-oscat')||'').toLowerCase().indexOf(st.oscat.toLowerCase()) >= 0);
      var show = statusOk && attrOk && osOk;
      row.toggle(show);
      if (show) visible++;
    });

    dt.draw(false);

    // Update hint text
    if (hintId) {
      var el = document.getElementById(hintId);
      if (el) {
        var activeCount = st.statuses.length + attrKeys.length + (hasOSCat ? 1 : 0);
        el.textContent = activeCount > 0 ? '— ' + visible + ' of ' + total + ' rows' : '';
      }
    }
  } catch(e) { console.error('mfApply:', e); }
}

// ── THEME ─────────────────────────────────────────────────────────
function toggleTheme() {
  var html = document.documentElement;
  html.setAttribute('data-theme', html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
}

// ── NAVIGATION ───────────────────────────────────────────────────
function showSection(id, btn) {
  document.querySelectorAll('.section').forEach(function(s){ s.classList.remove('active'); });
  document.querySelectorAll('.nav-btn').forEach(function(b){ b.classList.remove('active'); });
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
}

// ── BADGE HELPERS ─────────────────────────────────────────────────
function sb(status) {
  var m = {Active:'active',Stale:'stale',Warning:'warning',Disabled:'disabled',Mailbox:'mailbox',
           Empty:'empty',Privileged:'privileged',Unlinked:'unlinked',
           Good:'good',Medium:'medium',High:'high',Critical:'critical'};
  return '<span class="badge b-'+(m[status]||'no')+'">'+status+'</span>';
}
function bb(v, tLbl, fLbl) {
  tLbl = tLbl||'Yes'; fLbl = (fLbl===undefined?'No':fLbl);
  return v ? '<span class="badge b-yes">'+tLbl+'</span>'
           : (fLbl ? '<span class="badge b-no">'+fLbl+'</span>' : '');
}
function rb(risk) { return '<span class="badge b-'+risk.toLowerCase()+'">'+risk+'</span>'; }
function linkedBadge(v) {
  return v ? '<span class="badge b-linked">Linked</span>' : '<span class="badge b-unlinked">Unlinked</span>';
}
function dayCell(d) {
  if (d < 0) return '<span style="color:var(--text2)">Never</span>';
  if (d > $StaleUserDays) return '<span style="color:var(--danger);font-weight:700;">'+d+'</span>';
  if (d > $StaleUserDays*0.66) return '<span style="color:var(--warning);font-weight:700;">'+d+'</span>';
  return d;
}

// ── TABLE BUILDERS ────────────────────────────────────────────────
function buildUsers() {
  try {
    document.getElementById('userTbody').innerHTML = DATA.users.map(function(u){
      var acBadge = u.AccountType==='SharedMailbox'||u.AccountType==='RoomMailbox'||u.AccountType==='EquipmentMailbox'
                    ? 'mailbox' : u.AccountType==='AdminAccount' ? 'privileged'
                    : u.AccountType==='ServiceAccount' ? 'warning' : 'no';
      return '<tr data-status="'+u.Status+'" data-admin="'+(u.IsAdmin?'true':'false')+
        '" data-svc="'+(u.IsServiceAccount?'true':'false')+
        '" data-locked="'+(u.LockedOut?'true':'false')+
        '" data-pwne="'+(u.PwNeverExpires?'true':'false')+'">'+
        '<td>'+(u.Name||'')+'</td>'+
        '<td><code>'+u.SamAccountName+'</code></td>'+
        '<td>'+(u.Department||'')+'</td>'+
        '<td>'+(u.Title||'')+'</td>'+
        '<td>'+sb(u.Status)+'</td>'+
        '<td><span class="badge b-'+acBadge+'">'+u.AccountType+'</span></td>'+
        '<td>'+(u.MailboxType?'<span class="badge b-mailbox">'+u.MailboxType+'</span>':'')+'</td>'+
        '<td>'+u.LastLogon+'</td>'+
        '<td>'+dayCell(u.DaysSinceLogon)+'</td>'+
        '<td>'+dayCell(u.DaysSincePwSet)+'</td>'+
        '<td>'+bb(u.PwNeverExpires)+'</td>'+
        '<td>'+(u.LockedOut?'<span class="badge b-locked">Locked</span>':'<span class="badge b-no">No</span>')+'</td>'+
        '<td>'+bb(u.IsAdmin,'&#x1F451; Admin','')+'</td>'+
        '<td>'+bb(u.IsServiceAccount,'&#x2699; Svc','')+'</td>'+
        '<td>'+u.Created+'</td></tr>';
    }).join('');
  } catch(e) { console.error('buildUsers:', e); }
}

function buildComputers() {
  try {
    document.getElementById('compTbody').innerHTML = DATA.computers.map(function(c){
      return '<tr data-status="'+c.Status+'" data-eol="'+(c.IsEOL?'true':'false')+'" data-oscat="'+c.OSCategory+'">'+
        '<td><strong>'+c.Name+'</strong></td>'+
        '<td>'+(c.DNSHostName||'')+'</td>'+
        '<td>'+(c.OperatingSystem||'Unknown')+'</td>'+
        '<td style="color:var(--text2);font-size:.78rem;">'+(c.OSVersion||'')+'</td>'+
        '<td>'+(c.IPv4Address||'')+'</td>'+
        '<td>'+sb(c.Status)+'</td>'+
        '<td>'+c.LastLogon+'</td>'+
        '<td>'+dayCell(c.DaysSinceLogon)+'</td>'+
        '<td>'+(c.IsEOL?'<span class="badge b-eol">EOL</span>':'<span class="badge b-no">No</span>')+'</td>'+
        '<td>'+c.Created+'</td>'+
        '<td style="color:var(--text2)">'+(c.Description||'')+'</td></tr>';
    }).join('');
  } catch(e) { console.error('buildComputers:', e); }
}

function buildGroups() {
  try {
    document.getElementById('grpTbody').innerHTML = DATA.groups.map(function(g){
      return '<tr data-status="'+g.Status+'">'+
        '<td><strong>'+g.Name+'</strong></td>'+
        '<td>'+g.Scope+'</td><td>'+g.Category+'</td>'+
        '<td><strong>'+g.MemberCount+'</strong></td>'+
        '<td>'+sb(g.Status)+'</td>'+
        '<td>'+bb(g.IsPrivileged,'&#x1F451; Yes','No')+'</td>'+
        '<td>'+bb(g.AdminCount,'Yes','No')+'</td>'+
        '<td style="font-size:.78rem;color:var(--text2)">'+(g.ManagedBy||'')+'</td>'+
        '<td style="color:var(--text2)">'+(g.Description||'')+'</td>'+
        '<td>'+g.Created+'</td></tr>';
    }).join('');
  } catch(e) { console.error('buildGroups:', e); }
}

function buildGPOs() {
  try {
    document.getElementById('gpoTbody').innerHTML = DATA.gpos.map(function(g){
      return '<tr data-status="'+g.RiskLevel+'">'+
        '<td><strong>'+g.Name+'</strong></td>'+
        '<td>'+sb(g.RiskLevel)+'</td>'+
        '<td>'+linkedBadge(g.IsLinked)+'</td>'+
        '<td>'+bb(g.ComputerEnabled,'Enabled','Disabled')+'</td>'+
        '<td>'+bb(g.UserEnabled,'Enabled','Disabled')+'</td>'+
        '<td>'+g.Created+'</td><td>'+g.Modified+'</td>'+
        '<td>'+g.DaysSinceMod+'</td>'+
        '<td style="color:var(--text2)">'+(g.Description||'')+'</td></tr>';
    }).join('');
  } catch(e) { console.error('buildGPOs:', e); }
}

function buildOUs() {
  try {
    document.getElementById('ouTbody').innerHTML = DATA.ous.map(function(o){
      return '<tr>'+
        '<td><strong>'+o.Name+'</strong></td>'+
        '<td style="font-size:.75rem;color:var(--text2)">'+o.DistinguishedName+'</td>'+
        '<td>'+o.Depth+'</td><td>'+o.LinkedGPOs+'</td>'+
        '<td style="font-size:.78rem;color:var(--text2)">'+(o.ManagedBy||'')+'</td>'+
        '<td style="color:var(--text2)">'+(o.Description||'')+'</td>'+
        '<td>'+o.Created+'</td></tr>';
    }).join('');
  } catch(e) { console.error('buildOUs:', e); }
}

function buildDCs() {
  try {
    document.getElementById('dcTbody').innerHTML = DATA.dcs.map(function(d){
      return '<tr>'+
        '<td><strong>'+d.Name+'</strong></td>'+
        '<td>'+(d.Hostname||'')+'</td>'+
        '<td>'+(d.IPAddress||'')+'</td>'+
        '<td>'+(d.Site||'')+'</td>'+
        '<td>'+bb(d.IsGC,'&#x1F30D; Yes','No')+'</td>'+
        '<td>'+bb(d.IsRODC,'RODC','No')+'</td>'+
        '<td>'+(d.OSVersion||'')+'</td>'+
        '<td>'+bb(d.IsEnabled,'Yes','No')+'</td></tr>';
    }).join('');
  } catch(e) { console.error('buildDCs:', e); }
}

// FIX: Leave tbody EMPTY when no data — DataTables' language.emptyTable
// handles the message. Writing a colspan row BEFORE init causes
// "Incorrect column count" because DataTables counts 1 col vs 15 in thead.
function buildFGPPs() {
  try {
    if (!DATA.fgpps || DATA.fgpps.length === 0) {
      document.getElementById('fgppTbody').innerHTML = '';
      return;
    }
    document.getElementById('fgppTbody').innerHTML = DATA.fgpps.map(function(p){
      return '<tr data-status="'+p.RiskLevel+'">'+
        '<td><strong>'+p.Name+'</strong></td>'+
        '<td><strong>'+p.Precedence+'</strong></td>'+
        '<td style="font-size:.78rem;max-width:200px;">'+(p.AppliesTo||'<em style="color:var(--text2)">None</em>')+'</td>'+
        '<td class="'+(p.WeakMinLength?'rc-critical':'')+'">'+p.MinPasswordLength+'</td>'+
        '<td class="'+(p.NoExpiry?'rc-medium':'')+'">'+p.MaxPasswordAge+'</td>'+
        '<td>'+p.MinPasswordAge+'</td>'+
        '<td>'+p.PasswordHistoryCount+'</td>'+
        '<td class="'+(p.NoLockout?'rc-high':'')+'">'+
          (p.LockoutThreshold===0?'<strong style="color:var(--danger)">Disabled</strong>':p.LockoutThreshold)+'</td>'+
        '<td>'+p.LockoutDuration+'</td>'+
        '<td>'+p.LockoutObservationWindow+'</td>'+
        '<td class="'+(p.ComplexityDisabled?'rc-medium':'')+'">'+
          (p.ComplexityEnabled?'<span class="badge b-yes">Yes</span>':'<span class="badge b-no">No</span>')+'</td>'+
        '<td class="'+(p.RevEncryptEnabled?'rc-high':'')+'">'+
          (p.ReversibleEncryption?'<span class="badge b-stale">Enabled</span>':'<span class="badge b-yes">Disabled</span>')+'</td>'+
        '<td>'+rb(p.RiskLevel)+'</td>'+
        '<td style="font-size:.78rem;color:var(--text2)">'+p.LastChanged+'</td>'+
        '<td style="color:var(--text2);max-width:200px;">'+(p.Description||'')+'</td></tr>';
    }).join('');
  } catch(e) { console.error('buildFGPPs:', e); }
}

function buildFGPPComparison() {
  try {
    var el = document.getElementById('fgppCompareBody');
    if (!DATA.fgpps || DATA.fgpps.length === 0) {
      el.innerHTML = '<div class="empty-msg">&#x2139;&#xFE0F; No Fine-Grained Password Policies found in this domain.<br><span style="font-size:.78rem;">All accounts use the Default Domain Password Policy.</span></div>';
      return;
    }
    var sorted = DATA.fgpps.slice().sort(function(a,b){ return a.Precedence - b.Precedence; });
    var rowDefs = [
      { lbl:'Precedence',            key:'Precedence',               wFn:null,                                                               fFn:null },
      { lbl:'Applies To',            key:'AppliesTo',                wFn:null,                                                               fFn:null },
      { lbl:'Min Password Length',   key:'MinPasswordLength',        wFn:function(v){return v<8?'rc-critical':v<12?'rc-medium':'rc-good';},  fFn:function(v){return v+' chars';} },
      { lbl:'Max Password Age',      key:'MaxPasswordAge',           wFn:function(v){return v==='Never'?'rc-medium':'rc-good';},             fFn:null },
      { lbl:'Min Password Age',      key:'MinPasswordAge',           wFn:null, fFn:null },
      { lbl:'Password History',      key:'PasswordHistoryCount',     wFn:function(v){return v<5?'rc-medium':'rc-good';},                    fFn:function(v){return v+' remembered';} },
      { lbl:'Lockout Threshold',     key:'LockoutThreshold',         wFn:function(v){return v===0?'rc-high':v>20?'rc-medium':'rc-good';},   fFn:function(v){return v===0?'Disabled':v+' attempts';} },
      { lbl:'Lockout Duration',      key:'LockoutDuration',          wFn:null, fFn:null },
      { lbl:'Observation Window',    key:'LockoutObservationWindow', wFn:null, fFn:null },
      { lbl:'Complexity Required',   key:'ComplexityEnabled',        wFn:function(v){return !v?'rc-medium':'rc-good';},                     fFn:function(v){return v?'<span class="badge b-yes">Yes</span>':'<span class="badge b-no">No</span>';} },
      { lbl:'Reversible Encryption', key:'ReversibleEncryption',     wFn:function(v){return v?'rc-high':'rc-good';},                        fFn:function(v){return v?'<span class="badge b-stale">Enabled</span>':'<span class="badge b-yes">Disabled</span>';} },
      { lbl:'Risk Level',            key:'RiskLevel',                wFn:null, fFn:function(v){return rb(v);} },
      { lbl:'Last Changed',          key:'LastChanged',              wFn:null, fFn:null },
      { lbl:'Description',           key:'Description',              wFn:null, fFn:null }
    ];
    var html = '<div class="fgpp-compare"><table><thead><tr><th style="min-width:160px;">Setting</th>';
    sorted.forEach(function(p){ html += '<th>'+p.Name+'</th>'; });
    html += '</tr></thead><tbody>';
    rowDefs.forEach(function(row){
      html += '<tr><td class="fgpp-label-col">'+row.lbl+'</td>';
      sorted.forEach(function(p){
        var v = p[row.key];
        var d = row.fFn ? row.fFn(v) : (v===null||v===undefined||v===''?'<span style="color:var(--text2)">-</span>':v);
        var c = row.wFn ? row.wFn(v) : '';
        html += '<td class="'+c+'">'+d+'</td>';
      });
      html += '</tr>';
    });
    html += '</tbody></table></div>';
    el.innerHTML = html;
  } catch(e) { console.error('buildFGPPComparison:', e); }
}

function buildFindings() {
  try {
    var el = document.getElementById('findingsBody');
    if (!DATA.findings || DATA.findings.length === 0) {
      el.innerHTML = '<div class="card" style="text-align:center;padding:48px;"><div style="font-size:3rem">&#x2705;</div><div style="font-size:1.2rem;font-weight:800;margin-top:10px;color:var(--success)">No Security Findings!</div><div style="color:var(--text2);margin-top:6px;">Your Active Directory is in great shape.</div></div>';
      return;
    }
    var order = ['Critical','High','Medium','Low'];
    var sorted = DATA.findings.slice().sort(function(a,b){ return order.indexOf(a.Risk)-order.indexOf(b.Risk); });
    el.innerHTML = sorted.map(function(f){
      return '<div class="finding f-'+f.Risk.toLowerCase()+'">'+
        '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">'+rb(f.Risk)+
        '<span style="font-size:.78rem;color:var(--text2);font-weight:700;">'+f.Category+'</span></div>'+
        '<div class="f-title">'+f.Finding+'</div>'+
        '<div class="f-detail">'+f.Detail+'</div>'+
        '<div class="f-fix">&#x1F527; <strong>Remediation:</strong> '+f.Remediation+'</div></div>';
    }).join('');
  } catch(e) { console.error('buildFindings:', e); }
}

// ── NAV BADGES ────────────────────────────────────────────────────
function setNavBadges() {
  try {
    function set(id, n) {
      var el = document.getElementById(id);
      if (el) el.innerHTML = '<span class="nav-badge">'+n+'</span>';
    }
    set('navUsers',     DATA.users.length);
    set('navComputers', DATA.computers.length);
    set('navGroups',    DATA.groups.length);
    set('navGPOs',      DATA.gpos.length);
    set('navFGPP',      DATA.fgpps ? DATA.fgpps.length : 0);
    set('navFindings',  DATA.findings ? DATA.findings.length : 0);
  } catch(e) { console.error('setNavBadges:', e); }
}

// ── CHARTS ────────────────────────────────────────────────────────
function initCharts() {
  try {
    if (typeof Chart === 'undefined') { return; }
    var pal = ['#22c55e','#f59e0b','#ef4444','#94a3b8','#3b82f6','#8b5cf6','#06b6d4','#f97316','#ec4899','#6366f1'];
    var opts = { responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'right', labels:{ font:{size:11}, padding:10 } } } };
    var uActive = DATA.users.filter(function(u){ return u.Status==='Active'; }).length;
    var uWarn   = DATA.users.filter(function(u){ return u.Status==='Warning'; }).length;
    var uStale  = DATA.users.filter(function(u){ return u.Status==='Stale'; }).length;
    var uDisab  = DATA.users.filter(function(u){ return u.Status==='Disabled'; }).length;
    var uMbx    = DATA.users.filter(function(u){ return u.Status==='Mailbox'; }).length;
    new Chart(document.getElementById('cUserStatus'),{type:'doughnut',data:{labels:['Active','Warning','Stale','Disabled','Mailbox'],datasets:[{data:[uActive,uWarn,uStale,uDisab,uMbx],backgroundColor:['#22c55e','#f59e0b','#ef4444','#94a3b8','#8b5cf6'],borderWidth:2,borderColor:'transparent'}]},options:Object.assign({},opts,{cutout:'65%'})});
    new Chart(document.getElementById('cOSDist'),{type:'doughnut',data:{labels:DATA.osDist.map(function(o){return o.OS;}),datasets:[{data:DATA.osDist.map(function(o){return o.Count;}),backgroundColor:pal,borderWidth:2,borderColor:'transparent'}]},options:Object.assign({},opts,{cutout:'65%'})});
    var staleC = DATA.computers.filter(function(c){ return c.IsStale; }).length;
    new Chart(document.getElementById('cStale'),{type:'bar',data:{labels:['Stale Users','Stale Computers','Empty Groups','Unlinked GPOs','EOL Systems','Locked Out'],datasets:[{label:'Count',data:[uStale,staleC,DATA.groups.filter(function(g){return g.IsEmpty;}).length,DATA.gpos.filter(function(g){return !g.IsLinked;}).length,DATA.computers.filter(function(c){return c.IsEOL;}).length,DATA.users.filter(function(u){return u.LockedOut;}).length],backgroundColor:['#ef4444','#f97316','#f59e0b','#8b5cf6','#dc2626','#06b6d4'],borderRadius:6}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,ticks:{stepSize:1}}}}});
    var gLinked=DATA.gpos.filter(function(g){return g.IsLinked&&g.RiskLevel!=='Disabled';}).length;
    var gUnlinked=DATA.gpos.filter(function(g){return !g.IsLinked;}).length;
    var gDisab=DATA.gpos.filter(function(g){return g.RiskLevel==='Disabled';}).length;
    new Chart(document.getElementById('cGPO'),{type:'pie',data:{labels:['Linked & Active','Unlinked','All Settings Disabled'],datasets:[{data:[gLinked,gUnlinked,gDisab],backgroundColor:['#22c55e','#f97316','#94a3b8'],borderWidth:2,borderColor:'transparent'}]},options:opts});
  } catch(e) { console.error('initCharts:', e); }
}

// ── DATATABLES ────────────────────────────────────────────────────
function initDataTables() {
  try {
    if (typeof jQuery === 'undefined' || !jQuery.fn.DataTable) { return; }
    var dtBase = {
      pageLength: 25,
      scrollX: true,
      dom: '<"top"Bflp>rt<"bottom"ip>',
      buttons: [{extend:'csvHtml5',text:'&#x1F4BE; CSV'},{extend:'excelHtml5',text:'&#x1F4CA; Excel'},{extend:'print',text:'&#x1F5A8; Print'}],
      language: { search:'&#x1F50D;', lengthMenu:'Show _MENU_ rows' }
    };
    jQuery('#userTable').DataTable(jQuery.extend(true,{},dtBase,{order:[[8,'desc']]}));
    jQuery('#compTable').DataTable(jQuery.extend(true,{},dtBase,{order:[[7,'desc']]}));
    jQuery('#grpTable').DataTable( jQuery.extend(true,{},dtBase,{order:[[3,'desc']]}));
    jQuery('#gpoTable').DataTable( jQuery.extend(true,{},dtBase,{order:[[7,'desc']]}));
    jQuery('#ouTable').DataTable(  jQuery.extend(true,{},dtBase,{order:[[2,'asc']]}));
    jQuery('#dcTable').DataTable(  jQuery.extend(true,{},dtBase,{}));
    // FIX: language.emptyTable provides the "no data" message for fgppTable.
    // This avoids the "Incorrect column count" error that occurs when a
    // colspan row is pre-written into tbody before DataTables initialises.
    jQuery('#fgppTable').DataTable(jQuery.extend(true,{},dtBase,{
      order: [[1,'asc']],
      language: {
        search: '&#x1F50D;',
        lengthMenu: 'Show _MENU_ rows',
        emptyTable: 'No Fine-Grained Password Policies configured in this domain. All accounts use the Default Domain Password Policy.'
      }
    }));
  } catch(e) { console.error('initDataTables:', e); }
}

// ── BOOT ──────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
  buildUsers();
  buildComputers();
  buildGroups();
  buildGPOs();
  buildOUs();
  buildDCs();
  buildFGPPs();
  buildFGPPComparison();
  buildFindings();
  setNavBadges();
  initCharts();
  initDataTables();
});
</script>
</body>
</html>
"@

# ============================================================
# REGION 7 – WRITE & OPEN
# ============================================================
try {
    $HTML | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

    Write-Host "`n====================================================" -ForegroundColor Green
    Write-Host "  Report successfully generated!" -ForegroundColor Green
    Write-Host "====================================================" -ForegroundColor Green
    Write-Host "  File   : $OutputPath" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Users          : $($Stats.TotalUsers) total | $($Stats.StaleUsers) stale | $($Stats.AdminUsers) admins" -ForegroundColor White
    Write-Host "  Disabled (real): $($Stats.TrueDisabledUsers) | Shared Mailboxes: $($Stats.SharedMailboxes) | Room: $($Stats.RoomMailboxes) | Equip: $($Stats.EquipMailboxes)" -ForegroundColor White
    Write-Host "  Computers      : $($Stats.TotalComputers) total | $($Stats.StaleComputers) stale | $($Stats.EOLComputers) EOL" -ForegroundColor White
    Write-Host "  Groups         : $($Stats.TotalGroups) total | $($Stats.EmptyGroups) empty | $($Stats.PrivilegedGroups) privileged" -ForegroundColor White
    Write-Host "  GPOs           : $($Stats.TotalGPOs) total | $($Stats.UnlinkedGPOs) unlinked | $($Stats.DisabledGPOs) disabled" -ForegroundColor White
    Write-Host "  DCs            : $($Stats.TotalDCs) | OUs: $($Stats.TotalOUs)" -ForegroundColor White
    Write-Host "  FGPPs          : $($Stats.TotalFGPPs) total | $($Stats.WeakFGPPs) at-risk" -ForegroundColor White
    Write-Host ""
    $scoreColor = if ($HealthScore -ge 80) { "Green" } elseif ($HealthScore -ge 60) { "Yellow" } else { "Red" }
    Write-Host "  Health Score : $HealthScore/100 - $HealthLabel" -ForegroundColor $scoreColor
    Write-Host "  Findings     : $FindingsCount" -ForegroundColor $(if ($FindingsCount -eq 0) { "Green" } elseif ($FindingsCount -le 3) { "Yellow" } else { "Red" })
    Write-Host ""
    Start-Process $OutputPath
    Write-Host "  Opening report in browser..." -ForegroundColor Cyan
} catch {
    Write-Error "Failed to write report to '$OutputPath': $_"
}
