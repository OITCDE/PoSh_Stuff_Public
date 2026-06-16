#Requires -Version 5.1
<#
.SYNOPSIS
    Microsoft 365 Tenant MFA Status – Interactive HTML Report Generator

.DESCRIPTION
    Generates a rich, interactive HTML report analysing the tenant-wide MFA posture.
    Covers: Microsoft Authenticator, FIDO2 security keys, Passkeys, Phone (SMS/Voice),
    Software OATH tokens, Temporary Access Pass, Windows Hello for Business, Email OTP.

    Based on the proven Get-MgBetaUser / Get-MgBetaUserAuthenticationMethod approach.

.PARAMETER OutputPath
    Folder where the HTML report is saved. Defaults to user Desktop.

.PARAMETER CsvExport
    Also export raw data as CSV alongside the HTML report.

.PARAMETER MaxUsers
    Limit users processed (0 = all). Useful for testing.

.PARAMETER IncludeGuests
    Include guest / B2B accounts.

.PARAMETER TenantId
    Optional Entra tenant ID or primary domain (e.g. contoso.onmicrosoft.com).

.NOTES
    Required Microsoft Graph permissions (Delegated):
      - User.Read.All
      - UserAuthenticationMethod.Read.All

    Optionally (for richer data):
      - AuditLog.Read.All        – last sign-in times
      - Reports.Read.All         – MFA registration detail report
      - Organization.Read.All    – tenant display name

    Install / update module:
      Install-Module Microsoft.Graph.Beta -Scope CurrentUser -Force
#>
[CmdletBinding()]
param(
    [string] $OutputPath  = ".\",
    [switch] $CsvExport,
    [int]    $MaxUsers    = 0,
    [switch] $IncludeGuests,

    [Parameter(HelpMessage='Optional: Tenant ID or primary domain')]
    [string] $TenantId   = ''
)

$ErrorActionPreference = 'Continue'

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts    = Get-Date -Format 'HH:mm:ss'
    $color = switch ($Level) { 'WARN'{'Yellow'} 'ERROR'{'Red'} 'OK'{'Green'} default{'Cyan'} }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
}

# Safely read a named property from any object (never throws)
function gprop { param($o,$n,$d='')
    if ($null -eq $o) { return $d }
    try {
        $p = $o.PSObject.Properties[$n]
        if ($null -ne $p -and $null -ne $p.Value) { return $p.Value }
    } catch {}
    return $d
}

# ─────────────────────────────────────────────────────────────────────────────
# Module check
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "Checking Microsoft.Graph.Beta module ..."
if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Beta.Users')) {
    Write-Log "Microsoft.Graph.Beta not found — installing ..." 'WARN'
    Install-Module Microsoft.Graph.Beta -Scope CurrentUser -Force -AllowClobber
}

# ─────────────────────────────────────────────────────────────────────────────
# Connect
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "Connecting to Microsoft Graph ..."
$scopes = @(
    'User.Read.All',
    'UserAuthenticationMethod.Read.All',
    'Organization.Read.All',
    'AuditLog.Read.All',
    'Reports.Read.All'
)
try {
    $cp = @{ Scopes = $scopes; NoWelcome = $true }
    if ($TenantId -ne '') { $cp['TenantId'] = $TenantId }
    Connect-MgGraph @cp -ErrorAction Stop
    Write-Log "Connected successfully." 'OK'
} catch {
    Write-Log "Connection failed: $($_.Exception.Message)" 'ERROR'
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Tenant info
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "Fetching tenant information ..."
$tenantName = 'Unknown Tenant'
$tenantId_val = 'N/A'

try {
    $org = Get-MgBetaOrganization -ErrorAction Stop | Select-Object -First 1
    if ($null -ne $org) {
        $n = gprop $org 'DisplayName'
        $i = gprop $org 'Id'
        if (-not [string]::IsNullOrWhiteSpace($n)) { $tenantName   = $n }
        if (-not [string]::IsNullOrWhiteSpace($i)) { $tenantId_val = $i }
    }
} catch {
    Write-Log "Could not read org info ($($_.Exception.Message)) — trying MgContext ..." 'WARN'
}

if ($tenantId_val -eq 'N/A') {
    try { $tenantId_val = (Get-MgContext).TenantId } catch {}
}
Write-Log "Tenant: $tenantName  ($tenantId_val)" 'OK'

# ─────────────────────────────────────────────────────────────────────────────
# Fetch users  (proven Beta cmdlet approach)
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "Fetching users ..."
$allUsers = Get-MgBetaUser -All -Property 'id,displayName,userPrincipalName,department,jobTitle,accountEnabled,userType,assignedLicenses,createdDateTime,mail' -ErrorAction Stop

if (-not $IncludeGuests) {
    $allUsers = $allUsers | Where-Object { $_.UserType -ne 'Guest' }
}
if ($MaxUsers -gt 0) {
    $allUsers = $allUsers | Select-Object -First $MaxUsers
}
$totalUsers = @($allUsers).Count
Write-Log "Users to process: $totalUsers" 'OK'

# ─────────────────────────────────────────────────────────────────────────────
# Optional: bulk registration details (Reports.Read.All)
# ─────────────────────────────────────────────────────────────────────────────
$regLookup = @{}
try {
    $regRaw = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999' -Method GET -ErrorAction Stop
    $regItems = if ($regRaw['value']) { $regRaw['value'] } else { @() }
    foreach ($r in $regItems) {
        $rid = if ($r -is [hashtable]) { $r['id'] } else { $r.id }
        if ($rid) { $regLookup[$rid] = $r }
    }
    # handle pagination
    $nextLink = if ($regRaw['@odata.nextLink']) { $regRaw['@odata.nextLink'] } else { $null }
    while ($nextLink) {
        $pageRaw   = Invoke-MgGraphRequest -Uri $nextLink -Method GET -ErrorAction Stop
        $pageItems = if ($pageRaw['value']) { $pageRaw['value'] } else { @() }
        foreach ($r in $pageItems) {
            $rid = if ($r -is [hashtable]) { $r['id'] } else { $r.id }
            if ($rid) { $regLookup[$rid] = $r }
        }
        $nextLink = if ($pageRaw['@odata.nextLink']) { $pageRaw['@odata.nextLink'] } else { $null }
    }
    Write-Log "Registration details loaded for $($regLookup.Count) users." 'OK'
} catch {
    Write-Log "Registration details unavailable (needs Reports.Read.All) — using method-derived flags." 'WARN'
}

# ─────────────────────────────────────────────────────────────────────────────
# Per-user auth methods  (proven pattern from working script)
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "Fetching authentication methods per user ..."
$results   = [System.Collections.Generic.List[hashtable]]::new()
$counter   = 0

foreach ($user in $allUsers) {
    $counter++
    $pct = [math]::Round(($counter / $totalUsers) * 100)
    Write-Progress -Activity "Fetching MFA data" `
                   -Status   "$counter of $totalUsers — $($user.UserPrincipalName) — $pct% complete" `
                   -PercentComplete $pct

    # Per-user tracking
    $hasEmail      = $false
    $hasFido2      = $false
    $hasAuthApp    = $false
    $hasPhone      = $false
    $hasSoftOath   = $false
    $hasTap        = $false
    $hasWhfb       = $false
    $hasPasskey    = $false

    $authAppDevices = @()   # [{name, tag, os}]
    $fido2Keys      = @()   # [{name, aaguid, created}]
    $passkeys       = @()   # [{name, created}]
    $phoneNumbers   = @()   # [{type, number}]

    # ── Proven method: Get-MgBetaUserAuthenticationMethod ─────────────────
    try {
        $MFAData = Get-MgBetaUserAuthenticationMethod -UserId $user.UserPrincipalName -ErrorAction Stop

        foreach ($method in $MFAData) {
            $odataType = $method.AdditionalProperties["@odata.type"]

            switch ($odataType) {

                "#microsoft.graph.emailAuthenticationMethod" {
                    $hasEmail = $true
                }

                "#microsoft.graph.fido2AuthenticationMethod" {
                    $hasFido2 = $true
                    $fido2Keys += @{
                        name    = if ($method.AdditionalProperties["displayName"]) { $method.AdditionalProperties["displayName"] } else { "FIDO2 Key" }
                        aaguid  = if ($method.AdditionalProperties["aaGuid"]) { $method.AdditionalProperties["aaGuid"] } else { "N/A" }
                        created = if ($method.AdditionalProperties["createdDateTime"]) {
                                    try { ([datetime]$method.AdditionalProperties["createdDateTime"]).ToString('yyyy-MM-dd') } catch { "N/A" }
                                  } else { "N/A" }
                    }
                }

                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                    $hasAuthApp = $true
                    $authAppDevices += @{
                        name = if ($method.AdditionalProperties["displayName"]) { $method.AdditionalProperties["displayName"] } else { "Authenticator" }
                        tag  = if ($method.AdditionalProperties["deviceTag"])   { $method.AdditionalProperties["deviceTag"]   } else { "" }
                        os   = if ($method.AdditionalProperties["clientAppName"]) { $method.AdditionalProperties["clientAppName"] } else { "" }
                    }
                }

                "#microsoft.graph.phoneAuthenticationMethod" {
                    $hasPhone = $true
                    $phoneNumbers += @{
                        type   = if ($method.AdditionalProperties["phoneType"])   { $method.AdditionalProperties["phoneType"]   } else { "phone" }
                        number = if ($method.AdditionalProperties["phoneNumber"]) { $method.AdditionalProperties["phoneNumber"] } else { "N/A" }
                    }
                }

                "#microsoft.graph.softwareOathAuthenticationMethod" {
                    $hasSoftOath = $true
                }

                "#microsoft.graph.temporaryAccessPassAuthenticationMethod" {
                    $hasTap = $true
                }

                "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
                    $hasWhfb = $true
                }

                "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod" {
                    $hasPasskey = $true
                    $passkeys += @{
                        name    = if ($method.AdditionalProperties["displayName"])     { $method.AdditionalProperties["displayName"]     } else { "Passkey" }
                        created = if ($method.AdditionalProperties["createdDateTime"]) {
                                    try { ([datetime]$method.AdditionalProperties["createdDateTime"]).ToString('yyyy-MM-dd') } catch { "N/A" }
                                  } else { "N/A" }
                    }
                }
            }
        }
    } catch {
        Write-Log "Could not read auth methods for $($user.UserPrincipalName): $($_.Exception.Message)" 'WARN'
    }

    # ── MFA status flags ───────────────────────────────────────────────────
    $mfaEnabled = $hasEmail -or $hasFido2 -or $hasAuthApp -or $hasPhone -or
                  $hasSoftOath -or $hasTap -or $hasWhfb -or $hasPasskey

    # If we have registration details from the bulk API, prefer those flags
    $uid = $user.Id
    $regEntry = if ($regLookup.ContainsKey($uid)) { $regLookup[$uid] } else { $null }

    $isMfaRegistered  = if ($null -ne $regEntry) {
                            $v = if ($regEntry -is [hashtable]) { $regEntry['isMfaRegistered'] } else { $regEntry.isMfaRegistered }
                            [bool]$v
                        } else { $mfaEnabled }

    $isMfaCapable     = if ($null -ne $regEntry) {
                            $v = if ($regEntry -is [hashtable]) { $regEntry['isMfaCapable'] } else { $regEntry.isMfaCapable }
                            [bool]$v
                        } else { $mfaEnabled }

    $isPasswordless   = $hasFido2 -or $hasWhfb -or $hasPasskey
    if ($null -ne $regEntry) {
        $v = if ($regEntry -is [hashtable]) { $regEntry['isPasswordlessCapable'] } else { $regEntry.isPasswordlessCapable }
        $isPasswordless = [bool]$v
    }

    $isSsprRegistered = if ($null -ne $regEntry) {
                            $v = if ($regEntry -is [hashtable]) { $regEntry['isSsprRegistered'] } else { $regEntry.isSsprRegistered }
                            [bool]$v
                        } else { $false }

    $defaultMethod    = if ($null -ne $regEntry) {
                            $v = if ($regEntry -is [hashtable]) { $regEntry['defaultMfaMethod'] } else { $regEntry.defaultMfaMethod }
                            if ($v) { "$v" } else { 'none' }
                        } else { if ($mfaEnabled) { 'unknown' } else { 'none' } }

    # ── Build methods-registered list ──────────────────────────────────────
    $methodsList = @()
    if ($hasAuthApp)  { $methodsList += 'microsoftAuthenticatorApp' }
    if ($hasPhone)    { $methodsList += 'mobilePhone' }
    if ($hasFido2)    { $methodsList += 'fido2' }
    if ($hasPasskey)  { $methodsList += 'passkey' }
    if ($hasWhfb)     { $methodsList += 'windowsHelloForBusiness' }
    if ($hasSoftOath) { $methodsList += 'softwareOneTimePasscode' }
    if ($hasTap)      { $methodsList += 'temporaryAccessPass' }
    if ($hasEmail)    { $methodsList += 'email' }

    # ── License ────────────────────────────────────────────────────────────
    $licCount = if ($user.AssignedLicenses) { @($user.AssignedLicenses).Count } else { 0 }
    $licLabel = if ($licCount -gt 0) { "Licensed ($licCount SKU)" } else { 'Unlicensed' }

    # ── Created date ───────────────────────────────────────────────────────
    $createdStr = 'N/A'
    if ($user.CreatedDateTime) {
        try { $createdStr = ([datetime]$user.CreatedDateTime).ToString('yyyy-MM-dd') } catch {}
    }

    # ── Risk level ─────────────────────────────────────────────────────────
    $riskLevel = if     (-not $isMfaRegistered -and $user.AccountEnabled) { 'HIGH'   }
                 elseif ($isMfaRegistered -and -not $isPasswordless)      { 'MEDIUM' }
                 elseif ($isPasswordless)                                  { 'LOW'    }
                 else                                                       { 'NONE'  }

    # ── Assemble detail strings for HTML ───────────────────────────────────
    $authDevStr  = ($authAppDevices | ForEach-Object { "$($_.name) [$($_.tag)] ($($_.os))" -replace '"','' }) -join ' || '
    $fido2Str    = ($fido2Keys      | ForEach-Object { "$($_.name) [$($_.aaguid)] $($_.created)" -replace '"','' }) -join ' || '
    $passkeyStr  = ($passkeys       | ForEach-Object { "$($_.name) ($($_.created))"  -replace '"','' }) -join ' || '
    $phoneStr    = ($phoneNumbers   | ForEach-Object { "$($_.type): $($_.number)"    -replace '"','' }) -join ' || '

    $results.Add(@{
        Id                = $uid
        DisplayName       = if ($user.DisplayName)          { $user.DisplayName }          else { '' }
        UPN               = if ($user.UserPrincipalName)    { $user.UserPrincipalName }    else { '' }
        Department        = if ($user.Department)           { $user.Department }           else { 'N/A' }
        JobTitle          = if ($user.JobTitle)             { $user.JobTitle }             else { 'N/A' }
        AccountEnabled    = [bool]$user.AccountEnabled
        UserType          = if ($user.UserType)             { $user.UserType }             else { 'Member' }
        License           = $licLabel
        LicenseCount      = $licCount
        IsMfaRegistered   = $isMfaRegistered
        IsMfaCapable      = $isMfaCapable
        IsPasswordless    = $isPasswordless
        IsSsprRegistered  = $isSsprRegistered
        DefaultMfaMethod  = $defaultMethod
        MethodsRegistered = $methodsList
        MethodsCount      = $methodsList.Count
        AuthDevices       = $authDevStr
        AuthDeviceCount   = $authAppDevices.Count
        Fido2Keys         = $fido2Str
        Fido2Count        = $fido2Keys.Count
        Passkeys          = $passkeyStr
        PasskeyCount      = $passkeys.Count
        PhoneMethods      = $phoneStr
        PhoneCount        = $phoneNumbers.Count
        WhfbCount         = [int]$hasWhfb
        TapCount          = [int]$hasTap
        SoftwareOath      = [int]$hasSoftOath
        EmailAuth         = [int]$hasEmail
        RiskLevel         = $riskLevel
        CreatedDateTime   = $createdStr
    })
}

Write-Progress -Activity "Fetching MFA data" -Completed
Write-Log "Auth method collection complete for $($results.Count) users." 'OK'
$reportData = $results

# ─────────────────────────────────────────────────────────────────────────────
# Aggregate statistics
# ─────────────────────────────────────────────────────────────────────────────
$total           = $reportData.Count
$mfaRegistered   = ($reportData | Where-Object { $_.IsMfaRegistered                             }).Count
$mfaNotReg       = ($reportData | Where-Object { -not $_.IsMfaRegistered -and $_.AccountEnabled }).Count
$mfaCapable      = ($reportData | Where-Object { $_.IsMfaCapable                                }).Count
$passwordless    = ($reportData | Where-Object { $_.IsPasswordless                              }).Count
$highRisk        = ($reportData | Where-Object { $_.RiskLevel -eq 'HIGH'                        }).Count
$mediumRisk      = ($reportData | Where-Object { $_.RiskLevel -eq 'MEDIUM'                      }).Count
$lowRisk         = ($reportData | Where-Object { $_.RiskLevel -eq 'LOW'                         }).Count
$disabledAccts   = ($reportData | Where-Object { -not $_.AccountEnabled                         }).Count
$authDeviceUsers = ($reportData | Where-Object { $_.AuthDeviceCount -gt 0                       }).Count
$fido2Users      = ($reportData | Where-Object { $_.Fido2Count -gt 0                            }).Count
$passkeyUsers    = ($reportData | Where-Object { $_.PasskeyCount -gt 0                          }).Count
$phoneUsers      = ($reportData | Where-Object { $_.PhoneCount -gt 0                            }).Count
$whfbUsers       = ($reportData | Where-Object { $_.WhfbCount -gt 0                             }).Count
$ssprUsers       = ($reportData | Where-Object { $_.IsSsprRegistered                            }).Count
$tapUsers        = ($reportData | Where-Object { $_.TapCount -gt 0                              }).Count
$softOathUsers   = ($reportData | Where-Object { $_.SoftwareOath -gt 0                          }).Count
$emailAuthUsers  = ($reportData | Where-Object { $_.EmailAuth -gt 0                             }).Count

$mfaPct          = if ($total -gt 0) { [math]::Round($mfaRegistered / $total * 100, 1) } else { 0 }
$passwordlessPct = if ($total -gt 0) { [math]::Round($passwordless  / $total * 100, 1) } else { 0 }
$highRiskPct     = if ($total -gt 0) { [math]::Round($highRisk      / $total * 100, 1) } else { 0 }

# Department breakdown (top 12)
$deptGroups = $reportData | Group-Object Department | Sort-Object Count -Descending | Select-Object -First 12
$deptLabels = ($deptGroups | ForEach-Object { "'$($_.Name -replace "'","\'")'" }) -join ','
$deptTotal  = ($deptGroups | ForEach-Object { $_.Count }) -join ','
$deptMfaReg = ($deptGroups | ForEach-Object { ($_.Group | Where-Object { $_.IsMfaRegistered }).Count }) -join ','

# Methods distribution
$methodCounts = [ordered]@{
    'Microsoft Authenticator' = $authDeviceUsers
    'FIDO2 Key'               = $fido2Users
    'Passkey'                 = $passkeyUsers
    'Phone (SMS/Voice)'       = $phoneUsers
    'Windows Hello'           = $whfbUsers
    'Software OATH'           = $softOathUsers
    'Email OTP'               = $emailAuthUsers
    'Temp Access Pass'        = $tapUsers
}
$methodLabelsJs = ($methodCounts.Keys | ForEach-Object { "'$_'" }) -join ','
$methodValuesJs = ($methodCounts.Values) -join ','

# ─────────────────────────────────────────────────────────────────────────────
# Serialize user rows to JSON
# ─────────────────────────────────────────────────────────────────────────────
$jsonRows = [System.Collections.Generic.List[string]]::new()
foreach ($u in $reportData) {
    $methodBadges = ($u.MethodsRegistered | ForEach-Object { "$_" }) -join '|'
    $row = [ordered]@{
        id           = $u.Id
        name         = $u.DisplayName
        upn          = $u.UPN
        dept         = $u.Department
        jobTitle     = $u.JobTitle
        enabled      = $u.AccountEnabled
        userType     = $u.UserType
        license      = $u.License
        mfaReg       = $u.IsMfaRegistered
        mfaCap       = $u.IsMfaCapable
        passwordless = $u.IsPasswordless
        sspr         = $u.IsSsprRegistered
        defaultMethod= $u.DefaultMfaMethod
        methods      = $methodBadges
        methodCount  = $u.MethodsCount
        authDevices  = $u.AuthDevices
        authDevCount = $u.AuthDeviceCount
        fido2        = $u.Fido2Keys
        fido2Count   = $u.Fido2Count
        passkey      = $u.Passkeys
        passkeyCount = $u.PasskeyCount
        phone        = $u.PhoneMethods
        phoneCount   = $u.PhoneCount
        whfb         = $u.WhfbCount
        tap          = $u.TapCount
        softOath     = $u.SoftwareOath
        emailAuth    = $u.EmailAuth
        risk         = $u.RiskLevel
        created      = $u.CreatedDateTime
    }
    $jsonRows.Add(($row | ConvertTo-Json -Compress))
}
$allDataJson = "[$($jsonRows -join ',')]"

# ─────────────────────────────────────────────────────────────────────────────
# Optional CSV export
# ─────────────────────────────────────────────────────────────────────────────
if ($CsvExport) {
    $LogDate = Get-Date -Format 'yyyyMMddHHmm'
    $csvFile = Join-Path $OutputPath "M365_MFA_$LogDate.csv"
    $reportData | ForEach-Object {
        [PSCustomObject]@{
            DisplayName               = $_.DisplayName
            UserPrincipalName         = $_.UPN
            Department                = $_.Department
            JobTitle                  = $_.JobTitle
            AccountEnabled            = $_.AccountEnabled
            UserType                  = $_.UserType
            MFAEnabled                = $_.IsMfaRegistered
            IsPasswordless            = $_.IsPasswordless
            DefaultMethod             = $_.DefaultMfaMethod
            RiskLevel                 = $_.RiskLevel
            MicrosoftAuthenticatorApp = ($_.AuthDeviceCount -gt 0)
            AuthenticatorDevices      = $_.AuthDevices
            FIDO2                     = ($_.Fido2Count -gt 0)
            FIDO2Keys                 = $_.Fido2Keys
            Passkey                   = ($_.PasskeyCount -gt 0)
            Phone                     = ($_.PhoneCount -gt 0)
            PhoneNumbers              = $_.PhoneMethods
            WindowsHelloForBusiness   = ($_.WhfbCount -gt 0)
            SoftwareOath              = ($_.SoftwareOath -gt 0)
            TemporaryAccessPass       = ($_.TapCount -gt 0)
            Email                     = ($_.EmailAuth -gt 0)
            License                   = $_.License
            AccountCreated            = $_.CreatedDateTime
        }
    } | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Log "CSV exported: $csvFile" 'OK'
}

# ─────────────────────────────────────────────────────────────────────────────
# HTML report
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "Generating HTML report ..."
$reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>M365 MFA Status Report – $tenantName</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
a{color:#60a5fa}
/* ── header ── */
.hdr{background:linear-gradient(135deg,#1e293b,#0f172a);padding:16px 28px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #334155}
.hdr-left{display:flex;align-items:center;gap:14px}
.hdr-icon{width:42px;height:42px;background:linear-gradient(135deg,#3b82f6,#6366f1);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px}
.hdr h1{font-size:1.4rem;font-weight:700;color:#f1f5f9}
.hdr p{font-size:.8rem;color:#94a3b8;margin-top:2px}
.hdr-right{text-align:right;font-size:.78rem;color:#94a3b8}
.hdr-right strong{color:#60a5fa;font-size:.9rem}
/* ── main ── */
.main{padding:24px 28px;max-width:1800px;margin:0 auto}
/* ── section header ── */
.sec-hdr{font-size:.7rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#64748b;margin:28px 0 12px;display:flex;align-items:center;gap:8px}
.sec-hdr::before{content:'';flex:1;height:1px;background:#1e293b}
/* ── KPI grid ── */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px}
.kpi{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px;position:relative;overflow:hidden;transition:transform .15s}
.kpi:hover{transform:translateY(-2px)}
.kpi::after{content:'';position:absolute;bottom:0;left:0;right:0;height:3px;border-radius:0 0 10px 10px}
.kpi.blue::after{background:#3b82f6}.kpi.green::after{background:#22c55e}
.kpi.red::after{background:#ef4444}.kpi.amber::after{background:#f59e0b}
.kpi.purple::after{background:#a855f7}.kpi.teal::after{background:#14b8a6}
.kpi.pink::after{background:#ec4899}.kpi.indigo::after{background:#6366f1}
.kpi.sky::after{background:#0ea5e9}.kpi.lime::after{background:#84cc16}
.kpi label{font-size:.7rem;color:#94a3b8;font-weight:500;display:block;margin-bottom:6px}
.kpi .val{font-size:2rem;font-weight:800;line-height:1}
.kpi.blue .val{color:#60a5fa}.kpi.green .val{color:#4ade80}
.kpi.red .val{color:#f87171}.kpi.amber .val{color:#fbbf24}
.kpi.purple .val{color:#c084fc}.kpi.teal .val{color:#2dd4bf}
.kpi.pink .val{color:#f472b6}.kpi.indigo .val{color:#818cf8}
.kpi.sky .val{color:#38bdf8}.kpi.lime .val{color:#a3e635}
.kpi .sub{font-size:.72rem;color:#64748b;margin-top:4px}
/* ── chart grid ── */
.chart-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
.chart-grid-wide{display:grid;grid-template-columns:1fr;gap:16px;margin-top:16px}
.chart-box{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px}
.chart-box h3{font-size:.78rem;font-weight:600;color:#94a3b8;margin-bottom:16px;display:flex;align-items:center;gap:6px}
canvas{display:block;width:100%!important}
/* ── bar chart (CSS) ── */
.bar-list{display:flex;flex-direction:column;gap:10px}
.bar-row{display:grid;grid-template-columns:160px 1fr 40px;align-items:center;gap:10px;font-size:.78rem}
.bar-row label{color:#94a3b8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{background:#0f172a;border-radius:4px;height:10px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .4s ease}
.bar-row span{color:#e2e8f0;font-weight:600;text-align:right}
/* ── filters ── */
.filters{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px 20px;display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end}
.fgroup{display:flex;flex-direction:column;gap:4px}
.fgroup label{font-size:.7rem;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:.08em}
.fgroup input,.fgroup select{background:#0f172a;border:1px solid #334155;color:#e2e8f0;padding:7px 10px;border-radius:6px;font-size:.82rem;outline:none}
.fgroup input:focus,.fgroup select:focus{border-color:#3b82f6}
.fgroup input{width:260px}
.fgroup select{min-width:160px}
.btn{background:#3b82f6;color:#fff;border:none;padding:8px 16px;border-radius:6px;font-size:.82rem;cursor:pointer;font-weight:600;transition:background .15s}
.btn:hover{background:#2563eb}
.btn.sec{background:#1e293b;border:1px solid #334155;color:#94a3b8}
.btn.sec:hover{background:#334155}
/* ── table ── */
.tbl-wrap{overflow-x:auto;margin-top:16px}
table{width:100%;border-collapse:collapse;font-size:.8rem}
thead tr{background:#0f172a}
th{padding:10px 12px;text-align:left;color:#64748b;font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;cursor:pointer;user-select:none;white-space:nowrap;border-bottom:1px solid #334155}
th:hover{color:#94a3b8}
th .sort-arrow{margin-left:4px;opacity:.4}
th.asc .sort-arrow::after{content:'▲'}
th.desc .sort-arrow::after{content:'▼'}
th:not(.asc):not(.desc) .sort-arrow::after{content:'⇅'}
tbody tr{border-bottom:1px solid #1e293b;transition:background .1s;cursor:pointer}
tbody tr:hover{background:#1e293b}
tbody tr.expanded{background:#172036}
td{padding:9px 12px;vertical-align:middle}
.detail-row td{padding:0;background:#0f172a}
.detail-inner{padding:12px 24px;border-top:1px solid #334155;display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px}
.detail-item{font-size:.75rem;color:#94a3b8}
.detail-item strong{color:#e2e8f0;display:block;margin-bottom:2px}
/* ── badges ── */
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:.68rem;font-weight:600;margin:1px 2px 1px 0;white-space:nowrap}
.b-auth{background:#1e3a5f;color:#60a5fa}
.b-fido{background:#1c3d2e;color:#4ade80}
.b-pass{background:#2e1c3d;color:#c084fc}
.b-phone{background:#3d2e1c;color:#fbbf24}
.b-whfb{background:#1c3d3d;color:#2dd4bf}
.b-oath{background:#3d3d1c;color:#a3e635}
.b-tap{background:#3d1c1c;color:#f87171}
.b-email{background:#1c2e3d;color:#38bdf8}
.b-other{background:#2a2a2a;color:#94a3b8}
/* ── risk chips ── */
.risk{display:inline-block;padding:2px 10px;border-radius:20px;font-size:.7rem;font-weight:700}
.risk-HIGH{background:#450a0a;color:#f87171;border:1px solid #7f1d1d}
.risk-MEDIUM{background:#431407;color:#fb923c;border:1px solid #7c2d12}
.risk-LOW{background:#052e16;color:#4ade80;border:1px solid #14532d}
.risk-NONE{background:#1e293b;color:#64748b;border:1px solid #334155}
/* ── status dots ── */
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:middle}
.dot-ok{background:#22c55e}.dot-no{background:#ef4444}.dot-dis{background:#64748b}
/* ── pagination ── */
.pager{display:flex;align-items:center;justify-content:space-between;padding:12px 4px;font-size:.78rem;color:#64748b}
.pager-btns{display:flex;gap:6px}
.pager-btns button{background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:4px 10px;border-radius:5px;cursor:pointer;font-size:.78rem}
.pager-btns button:hover{background:#334155}
.pager-btns button:disabled{opacity:.3;cursor:default}
/* ── CSV export ── */
.export-row{display:flex;justify-content:flex-end;margin-bottom:10px}
/* ── responsive ── */
@media(max-width:900px){
  .chart-grid{grid-template-columns:1fr}
  .hdr{flex-direction:column;align-items:flex-start;gap:8px}
}
</style>
</head>
<body>

<header class="hdr">
  <div class="hdr-left">
    <div class="hdr-icon">&#128737;</div>
    <div>
      <h1>MFA Status Report</h1>
      <p>Microsoft 365 Authentication Methods Analysis</p>
    </div>
  </div>
  <div class="hdr-right">
    <strong>&#127970; $tenantName</strong><br>
    Tenant ID: $tenantId_val<br>
    Generated: $reportDate
  </div>
</header>

<main class="main">

<!-- ═══════════════════════ KPI DASHBOARD ═══════════════════════ -->
<div class="sec-hdr">&#9711; Overview Dashboard</div>
<div class="kpi-grid">
  <div class="kpi blue"><label>Total Users</label><div class="val">$total</div><div class="sub">Member accounts</div></div>
  <div class="kpi green"><label>MFA Registered</label><div class="val">$mfaRegistered</div><div class="sub">$mfaPct% of total users</div></div>
  <div class="kpi red"><label>&#9651; No MFA (Active)</label><div class="val">$mfaNotReg</div><div class="sub">Enabled accounts at risk</div></div>
  <div class="kpi purple"><label>Passwordless Capable</label><div class="val">$passwordless</div><div class="sub">$passwordlessPct% of total</div></div>
  <div class="kpi teal"><label>Authenticator App</label><div class="val">$authDeviceUsers</div><div class="sub">Registered devices</div></div>
  <div class="kpi green"><label>FIDO2 Keys</label><div class="val">$fido2Users</div><div class="sub">Users with security keys</div></div>
  <div class="kpi indigo"><label>Passkeys</label><div class="val">$passkeyUsers</div><div class="sub">Passwordless Authenticator</div></div>
  <div class="kpi amber"><label>Phone Methods</label><div class="val">$phoneUsers</div><div class="sub">SMS / Voice call</div></div>
  <div class="kpi sky"><label>Windows Hello</label><div class="val">$whfbUsers</div><div class="sub">WHFB enrolled</div></div>
  <div class="kpi lime"><label>Software OATH</label><div class="val">$softOathUsers</div><div class="sub">TOTP / hardware tokens</div></div>
  <div class="kpi pink"><label>Email OTP</label><div class="val">$emailAuthUsers</div><div class="sub">Email authentication</div></div>
  <div class="kpi amber"><label>Temp Access Pass</label><div class="val">$tapUsers</div><div class="sub">Active TAP users</div></div>
  <div class="kpi blue"><label>MFA Capable</label><div class="val">$mfaCapable</div><div class="sub">Can perform MFA</div></div>
  <div class="kpi teal"><label>SSPR Registered</label><div class="val">$ssprUsers</div><div class="sub">Self-service password reset</div></div>
  <div class="kpi red"><label>Disabled Accounts</label><div class="val">$disabledAccts</div><div class="sub">Sign-in blocked</div></div>
  <div class="kpi amber"><label>High Risk</label><div class="val">$highRisk</div><div class="sub">$highRiskPct% — no MFA &amp; active</div></div>
</div>

<!-- ═══════════════════════ CHARTS ═══════════════════════════════ -->
<div class="sec-hdr">&#9685; Visual Analytics</div>
<div class="chart-grid">
  <div class="chart-box">
    <h3>&#9711; MFA Registration Status</h3>
    <canvas id="cvDonut" height="220"></canvas>
    <div id="donutLegend" style="margin-top:12px"></div>
  </div>
  <div class="chart-box">
    <h3>&#9651; Risk Distribution</h3>
    <div id="riskBars" class="bar-list"></div>
  </div>
  <div class="chart-box">
    <h3>&#128273; Authentication Methods in Use</h3>
    <div id="methodBars" class="bar-list"></div>
  </div>
</div>
<div class="chart-grid-wide">
  <div class="chart-box">
    <h3>&#127968; MFA Compliance by Department (Top 12)</h3>
    <div id="deptBars" class="bar-list"></div>
  </div>
</div>

<!-- ═══════════════════════ USER TABLE ══════════════════════════ -->
<div class="sec-hdr">&#128101; User Details</div>

<div class="filters">
  <div class="fgroup">
    <label>Search</label>
    <input type="text" id="searchBox" placeholder="Name, UPN, department …" oninput="applyFilters()"/>
  </div>
  <div class="fgroup">
    <label>MFA Status</label>
    <select id="fMfa" onchange="applyFilters()">
      <option value="">All</option>
      <option value="true">Registered</option>
      <option value="false">Not Registered</option>
    </select>
  </div>
  <div class="fgroup">
    <label>Risk Level</label>
    <select id="fRisk" onchange="applyFilters()">
      <option value="">All</option>
      <option value="HIGH">High</option>
      <option value="MEDIUM">Medium</option>
      <option value="LOW">Low</option>
      <option value="NONE">None</option>
    </select>
  </div>
  <div class="fgroup">
    <label>Account Status</label>
    <select id="fEnabled" onchange="applyFilters()">
      <option value="">All</option>
      <option value="true">Enabled</option>
      <option value="false">Disabled</option>
    </select>
  </div>
  <div class="fgroup">
    <label>Passwordless</label>
    <select id="fPwdless" onchange="applyFilters()">
      <option value="">All</option>
      <option value="true">Yes</option>
      <option value="false">No</option>
    </select>
  </div>
  <div class="fgroup">
    <label>Department</label>
    <select id="fDept" onchange="applyFilters()"></select>
  </div>
  <div style="display:flex;gap:8px;align-items:flex-end">
    <button class="btn sec" onclick="clearFilters()">&#10005; Clear</button>
    <button class="btn" onclick="exportCsv()">&#8615; Export CSV</button>
  </div>
</div>

<div class="export-row">
  <span id="resultCount" style="font-size:.78rem;color:#64748b"></span>
</div>

<div class="tbl-wrap">
<table id="userTable">
  <thead>
    <tr>
      <th data-col="name">Display Name<span class="sort-arrow"></span></th>
      <th data-col="upn">UPN<span class="sort-arrow"></span></th>
      <th data-col="dept">Department<span class="sort-arrow"></span></th>
      <th data-col="enabled">Status<span class="sort-arrow"></span></th>
      <th data-col="mfaReg">MFA<span class="sort-arrow"></span></th>
      <th data-col="risk">Risk<span class="sort-arrow"></span></th>
      <th data-col="defaultMethod">Default Method<span class="sort-arrow"></span></th>
      <th>Methods</th>
      <th data-col="methodCount">#<span class="sort-arrow"></span></th>
      <th data-col="license">License<span class="sort-arrow"></span></th>
      <th data-col="created">Created<span class="sort-arrow"></span></th>
    </tr>
  </thead>
  <tbody id="tableBody"></tbody>
</table>
</div>

<div class="pager">
  <span id="pageInfo"></span>
  <div class="pager-btns">
    <button id="btnFirst" onclick="goPage(0)">&#171; First</button>
    <button id="btnPrev"  onclick="goPage(curPage-1)">&#8249; Prev</button>
    <button id="btnNext"  onclick="goPage(curPage+1)">Next &#8250;</button>
    <button id="btnLast"  onclick="goPage(lastPage())">Last &#187;</button>
  </div>
</div>

</main>

<script>
// ── Data injected by PowerShell ──────────────────────────────────────────────
var allData    = $allDataJson;
var deptLabels = [$deptLabels];
var deptTotal  = [$deptTotal];
var deptMfaReg = [$deptMfaReg];

// ── Donut chart (pure Canvas, no template literals) ──────────────────────────
(function(){
  var cv = document.getElementById('cvDonut');
  if(!cv) return;
  var w  = cv.parentElement.clientWidth - 40;
  var sz = Math.min(w || 220, 220);
  cv.width = sz; cv.height = sz;
  var ctx = cv.getContext('2d');
  var cx = sz/2, cy = sz/2, r = sz*0.38, ir = sz*0.22;

  var segments = [
    { label:'MFA Registered',   val:$mfaRegistered,                       color:'#22c55e' },
    { label:'No MFA (Active)',  val:$mfaNotReg,                           color:'#ef4444' },
    { label:'Disabled / Other', val:$total-$mfaRegistered-$mfaNotReg,    color:'#334155' }
  ];
  var total = 0;
  for(var i=0;i<segments.length;i++) total += segments[i].val;
  total = total || 1;

  var startAngle = -Math.PI/2;
  for(var i=0;i<segments.length;i++){
    var s = segments[i];
    var sweep = (s.val/total)*Math.PI*2;
    ctx.beginPath();
    ctx.moveTo(cx,cy);
    ctx.arc(cx,cy,r,startAngle,startAngle+sweep);
    ctx.closePath();
    ctx.fillStyle = s.color;
    ctx.fill();
    startAngle += sweep;
  }
  ctx.beginPath();
  ctx.arc(cx,cy,ir,0,Math.PI*2);
  ctx.fillStyle = '#1e293b';
  ctx.fill();
  ctx.fillStyle = '#f1f5f9';
  ctx.font = 'bold ' + Math.round(sz*0.12) + 'px Segoe UI,sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('$mfaPct%', cx, cy - sz*0.04);
  ctx.font = Math.round(sz*0.07) + 'px Segoe UI,sans-serif';
  ctx.fillStyle = '#94a3b8';
  ctx.fillText('MFA', cx, cy + sz*0.06);

  var leg = document.getElementById('donutLegend');
  leg.style.cssText = 'display:flex;flex-wrap:wrap;gap:10px;justify-content:center;margin-top:12px';
  for(var i=0;i<segments.length;i++){
    var s   = segments[i];
    var pct = Math.round(s.val/total*100);
    leg.innerHTML += '<span style="font-size:.73rem;color:#94a3b8;display:flex;align-items:center;gap:5px">'
      + '<span style="width:10px;height:10px;background:' + s.color + ';border-radius:2px;display:inline-block"></span> '
      + s.label
      + ' <strong style="color:#e2e8f0">' + s.val + '</strong>'
      + ' <span style="color:#475569">(' + pct + '%)</span>'
      + '</span>';
  }
})();

// ── CSS bar-chart helper (no template literals) ──────────────────────────────
function buildBars(id, items, maxVal) {
  var el  = document.getElementById(id);
  if(!el) return;
  var max = maxVal || 1;
  for(var i=0;i<items.length;i++) if(items[i].val > max) max = items[i].val;
  var html = '';
  for(var i=0;i<items.length;i++){
    var pct = Math.round(items[i].val / max * 100);
    html += '<div class="bar-row">'
      + '<label title="' + items[i].label + '">' + items[i].label + '</label>'
      + '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:' + items[i].color + '"></div></div>'
      + '<span>' + items[i].val + '</span>'
      + '</div>';
  }
  el.innerHTML = html;
}

buildBars('riskBars', [
  { label:'HIGH',   val:$highRisk,                                  color:'#ef4444' },
  { label:'MEDIUM', val:$mediumRisk,                                color:'#f97316' },
  { label:'LOW',    val:$lowRisk,                                   color:'#22c55e' },
  { label:'NONE',   val:$total-$highRisk-$mediumRisk-$lowRisk,     color:'#334155' }
]);

buildBars('methodBars', [
  { label:'MS Authenticator', val:$authDeviceUsers, color:'#3b82f6' },
  { label:'FIDO2 Key',        val:$fido2Users,      color:'#22c55e' },
  { label:'Passkey',          val:$passkeyUsers,    color:'#a855f7' },
  { label:'Phone',            val:$phoneUsers,      color:'#f59e0b' },
  { label:'Windows Hello',    val:$whfbUsers,       color:'#14b8a6' },
  { label:'Software OATH',    val:$softOathUsers,   color:'#84cc16' },
  { label:'Email OTP',        val:$emailAuthUsers,  color:'#0ea5e9' },
  { label:'Temp Access Pass', val:$tapUsers,        color:'#f43f5e' }
]);

// ── Department compliance bars ───────────────────────────────────────────────
(function(){
  var el = document.getElementById('deptBars');
  if(!el) return;
  var max = 1;
  for(var i=0;i<deptTotal.length;i++) if(deptTotal[i]>max) max=deptTotal[i];
  var html = '';
  for(var i=0;i<deptLabels.length;i++){
    var tot    = deptTotal[i] || 0;
    var mfa    = deptMfaReg[i] || 0;
    var pctTot = Math.round(tot/max*100);
    var pctMfa = tot>0 ? Math.round(mfa/tot*100) : 0;
    html += '<div class="bar-row" style="grid-template-columns:160px 1fr 80px">'
      + '<label title="' + deptLabels[i] + '">' + deptLabels[i] + '</label>'
      + '<div class="bar-track" style="position:relative">'
      + '<div class="bar-fill" style="width:' + pctTot + '%;background:#334155;position:absolute;top:0;left:0;height:100%"></div>'
      + '<div class="bar-fill" style="width:' + Math.round(mfa/max*100) + '%;background:#3b82f6;position:relative"></div>'
      + '</div>'
      + '<span style="font-size:.72rem">' + mfa + '/' + tot + ' (' + pctMfa + '%)</span>'
      + '</div>';
  }
  el.innerHTML = html;
})();

// ── Table logic (no template literals) ──────────────────────────────────────
var PAGE_SIZE = 50;
var filtered  = allData.slice();
var curPage   = 0;
var sortCol   = 'name';
var sortDir   = 1;

// Populate dept dropdown
(function(){
  var seen = {};
  var depts = [];
  for(var i=0;i<allData.length;i++){
    var d = allData[i].dept || 'N/A';
    if(!seen[d]){ seen[d]=1; depts.push(d); }
  }
  depts.sort();
  var sel = document.getElementById('fDept');
  var html = '<option value="">All Departments</option>';
  for(var i=0;i<depts.length;i++)
    html += '<option value="' + depts[i] + '">' + depts[i] + '</option>';
  sel.innerHTML = html;
})();

var methodBadgeClass = {
  microsoftAuthenticatorApp:'b-auth', mobilePhone:'b-phone',
  fido2:'b-fido', passkey:'b-pass', windowsHelloForBusiness:'b-whfb',
  softwareOneTimePasscode:'b-oath', temporaryAccessPass:'b-tap', email:'b-email'
};
var methodLabel = {
  microsoftAuthenticatorApp:'Authenticator', mobilePhone:'Phone',
  fido2:'FIDO2', passkey:'Passkey', windowsHelloForBusiness:'WHfB',
  softwareOneTimePasscode:'OATH', temporaryAccessPass:'TAP', email:'Email'
};

function methodBadges(str){
  if(!str) return '<span style="color:#475569;font-size:.7rem">None</span>';
  var parts = str.split('|').filter(Boolean);
  var out = '';
  for(var i=0;i<parts.length;i++){
    var cls = methodBadgeClass[parts[i]] || 'b-other';
    var lbl = methodLabel[parts[i]] || parts[i];
    out += '<span class="badge ' + cls + '">' + lbl + '</span>';
  }
  return out;
}

function renderRow(d, idx){
  var statusDot = d.enabled
    ? '<span class="dot dot-ok"></span>Enabled'
    : '<span class="dot dot-dis"></span>Disabled';
  var mfaHtml = d.mfaReg
    ? '<span class="dot dot-ok"></span>Yes'
    : '<span class="dot dot-no"></span>No';
  return '<tr onclick="toggleDetail(' + idx + ',this)" data-idx="' + idx + '">'
    + '<td><strong>' + (d.name||'') + '</strong></td>'
    + '<td style="color:#94a3b8;font-size:.75rem">' + (d.upn||'') + '</td>'
    + '<td>' + (d.dept||'N/A') + '</td>'
    + '<td style="white-space:nowrap">' + statusDot + '</td>'
    + '<td style="white-space:nowrap">' + mfaHtml + '</td>'
    + '<td><span class="risk risk-' + d.risk + '">' + d.risk + '</span></td>'
    + '<td style="font-size:.75rem;color:#94a3b8">' + (d.defaultMethod||'none') + '</td>'
    + '<td>' + methodBadges(d.methods) + '</td>'
    + '<td style="text-align:center;color:#64748b">' + (d.methodCount||0) + '</td>'
    + '<td style="font-size:.75rem;color:#94a3b8">' + (d.license||'') + '</td>'
    + '<td style="font-size:.75rem;color:#64748b">' + (d.created||'N/A') + '</td>'
    + '</tr>'
    + '<tr class="detail-row" id="detail-' + idx + '" style="display:none"><td colspan="11">'
    + '<div class="detail-inner">'
    + '<div class="detail-item"><strong>Job Title</strong>' + (d.jobTitle||'N/A') + '</div>'
    + '<div class="detail-item"><strong>User Type</strong>' + (d.userType||'Member') + '</div>'
    + '<div class="detail-item"><strong>Passwordless</strong>' + (d.passwordless?'Yes':'No') + '</div>'
    + '<div class="detail-item"><strong>SSPR Registered</strong>' + (d.sspr?'Yes':'No') + '</div>'
    + '<div class="detail-item"><strong>MFA Capable</strong>' + (d.mfaCap?'Yes':'No') + '</div>'
    + '<div class="detail-item"><strong>Authenticator Devices</strong>' + (d.authDevices||'\u2014') + '</div>'
    + '<div class="detail-item"><strong>FIDO2 Keys</strong>' + (d.fido2||'\u2014') + '</div>'
    + '<div class="detail-item"><strong>Passkeys</strong>' + (d.passkey||'\u2014') + '</div>'
    + '<div class="detail-item"><strong>Phone Numbers</strong>' + (d.phone||'\u2014') + '</div>'
    + '<div class="detail-item"><strong>Windows Hello</strong>' + (d.whfb ? d.whfb+' device(s)' : '\u2014') + '</div>'
    + '<div class="detail-item"><strong>Software OATH</strong>' + (d.softOath?'Yes':'No') + '</div>'
    + '<div class="detail-item"><strong>Temp Access Pass</strong>' + (d.tap?'Yes':'No') + '</div>'
    + '<div class="detail-item"><strong>Email OTP</strong>' + (d.emailAuth?'Yes':'No') + '</div>'
    + '<div class="detail-item"><strong>User ID</strong><span style="font-size:.7rem;color:#64748b">' + (d.id||'\u2014') + '</span></div>'
    + '</div></td></tr>';
}

function lastPage(){ return Math.max(0, Math.ceil(filtered.length/PAGE_SIZE)-1); }

function renderTable(){
  var start = curPage * PAGE_SIZE;
  var page  = filtered.slice(start, start + PAGE_SIZE);
  var body  = document.getElementById('tableBody');
  var html  = '';
  for(var i=0;i<page.length;i++) html += renderRow(page[i], start+i);
  body.innerHTML = html;
  var end = Math.min(start+PAGE_SIZE, filtered.length);
  document.getElementById('pageInfo').textContent =
    'Showing ' + (start+1) + '\u2013' + end + ' of ' + filtered.length + ' users';
  document.getElementById('resultCount').textContent =
    filtered.length < allData.length
      ? filtered.length + ' of ' + allData.length + ' users match current filters'
      : allData.length + ' total users';
  document.getElementById('btnFirst').disabled = curPage === 0;
  document.getElementById('btnPrev').disabled  = curPage === 0;
  document.getElementById('btnNext').disabled  = curPage >= lastPage();
  document.getElementById('btnLast').disabled  = curPage >= lastPage();
}

function toggleDetail(idx, row){
  var dr = document.getElementById('detail-' + idx);
  if(!dr) return;
  var visible = dr.style.display !== 'none';
  dr.style.display = visible ? 'none' : 'table-row';
  row.classList.toggle('expanded', !visible);
}

function applyFilters(){
  var q     = document.getElementById('searchBox').value.toLowerCase();
  var fMfa  = document.getElementById('fMfa').value;
  var fRisk = document.getElementById('fRisk').value;
  var fEn   = document.getElementById('fEnabled').value;
  var fPwdl = document.getElementById('fPwdless').value;
  var fDept = document.getElementById('fDept').value;

  filtered = allData.filter(function(d){
    if(q && (d.name||'').toLowerCase().indexOf(q) < 0
         && (d.upn||'').toLowerCase().indexOf(q) < 0
         && (d.dept||'').toLowerCase().indexOf(q) < 0
         && (d.jobTitle||'').toLowerCase().indexOf(q) < 0) return false;
    if(fMfa  && String(d.mfaReg)       !== fMfa)  return false;
    if(fRisk && d.risk                 !== fRisk) return false;
    if(fEn   && String(d.enabled)      !== fEn)   return false;
    if(fPwdl && String(d.passwordless) !== fPwdl) return false;
    if(fDept && (d.dept||'N/A')        !== fDept) return false;
    return true;
  });

  filtered.sort(function(a,b){
    var av = (a[sortCol] != null ? a[sortCol] : '');
    var bv = (b[sortCol] != null ? b[sortCol] : '');
    if(typeof av === 'boolean') return ((av?1:0) - (bv?1:0)) * sortDir;
    return String(av).localeCompare(String(bv)) * sortDir;
  });

  curPage = 0;
  renderTable();
}

document.querySelectorAll('th[data-col]').forEach(function(th){
  th.addEventListener('click', function(){
    var col = th.getAttribute('data-col');
    if(sortCol === col){ sortDir *= -1; }
    else { sortCol = col; sortDir = 1; }
    document.querySelectorAll('th').forEach(function(t){ t.classList.remove('asc','desc'); });
    th.classList.add(sortDir === 1 ? 'asc' : 'desc');
    applyFilters();
  });
});

function clearFilters(){
  document.getElementById('searchBox').value = '';
  document.getElementById('fMfa').value      = '';
  document.getElementById('fRisk').value     = '';
  document.getElementById('fEnabled').value  = '';
  document.getElementById('fPwdless').value  = '';
  document.getElementById('fDept').value     = '';
  applyFilters();
}

function goPage(p){
  curPage = Math.max(0, Math.min(p, lastPage()));
  renderTable();
}

function exportCsv(){
  var cols = ['name','upn','dept','jobTitle','enabled','mfaReg','mfaCap','passwordless','sspr',
              'risk','defaultMethod','methods','authDevices','fido2','passkey','phone',
              'whfb','softOath','tap','emailAuth','license','created'];
  var header = cols.join(',');
  var rows = filtered.map(function(d){
    return cols.map(function(c){
      var v = d[c] != null ? d[c] : '';
      var s = String(v).replace(/"/g, '""');
      return (s.indexOf(',') >= 0 || s.indexOf('"') >= 0 || s.indexOf('\n') >= 0)
        ? '"' + s + '"' : s;
    }).join(',');
  });
  var csv = [header].concat(rows).join('\r\n');
  var a = document.createElement('a');
  a.href     = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
  a.download = 'M365_MFA_Export.csv';
  a.click();
}

// Initial render
applyFilters();
</script>
</body>
</html>
"@

# ─────────────────────────────────────────────────────────────────────────────
# REGION 8 – Save & open
# ─────────────────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$reportFile = Join-Path $OutputPath "M365_MFA_Report_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$html | Out-File -FilePath $reportFile -Encoding UTF8 -Force

Write-Log "Report saved: $reportFile" 'OK'

try {
    Start-Process $reportFile
    Write-Log "Opened report in default browser." 'OK'
} catch {
    Write-Log "Could not auto-open. Please open manually: $reportFile" 'WARN'
}

Write-Progress -Activity "MFA Report" -Completed
Write-Log "=== M365 MFA Status Report Complete ===" 'OK'
Write-Log "File : $reportFile" 'OK'
Write-Log "Users: $total total / $mfaRegistered MFA registered ($mfaPct%) / $highRisk high risk" 'OK'

Disconnect-MgGraph -ErrorAction SilentlyContinue
