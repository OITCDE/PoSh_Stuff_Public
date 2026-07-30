<#
.SYNOPSIS
    Microsoft 365 Tenant MFA Status - Interactive HTML Report Generator

.DESCRIPTION
    Collects MFA registration details for all users in an M365 tenant using
    Microsoft.Graph.Beta cmdlets and optionally Exchange Online for Shared Mailbox
    identification. Produces a self-contained interactive HTML dashboard.

.PARAMETER OutputPath
    Folder where the HTML (and optional CSV) report is saved.
    Default: user Desktop.

.PARAMETER CsvExport
    If specified, also exports a CSV alongside the HTML report.

.PARAMETER MaxUsers
    Limit user processing (0 = all users). Useful for testing.

.PARAMETER IncludeGuests
    Include Guest accounts in the report.

.PARAMETER TenantId
    Optional: Tenant ID or primary domain to connect to.

.PARAMETER SkipExchangeOnline
    Skip Exchange Online connection for Shared Mailbox detection.
    Use this if ExchangeOnlineManagement module is not installed or you
    do not have Exchange admin rights.

.NOTES
    Required Graph permissions (Application or Delegated):
      - User.Read.All               - user list + properties
      - UserAuthenticationMethod.Read.All - authentication methods
      - AuditLog.Read.All           - last sign-in times
      - Reports.Read.All            - MFA registration detail report
      - Organization.Read.All       - tenant display name
    Required Exchange permission (optional, for Shared Mailbox detection):
      - Exchange Online: View-Only Recipients (or higher)
#>

[CmdletBinding()]
param(
    [string] $OutputPath  = "$env:USERPROFILE\Desktop",
    [switch] $CsvExport,
    [int]    $MaxUsers    = 0,
    [switch] $IncludeGuests,
    [switch] $SkipExchangeOnline,

    [Parameter(HelpMessage='Optional: Tenant ID or primary domain')]
    [string] $TenantId   = ''
)

$ErrorActionPreference = 'Continue'

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts    = Get-Date -Format 'HH:mm:ss'
    $color = switch ($Level) {
        'WARN'   { 'Yellow' }
        'ERROR'  { 'Red'    }
        'OK'     { 'Green'  }
        default  { 'Cyan'   }
    }
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

# -----------------------------------------------------------------------
# Module check - Graph Beta
# -----------------------------------------------------------------------
Write-Log "Checking Microsoft.Graph.Beta module ..."
if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Beta.Users')) {
    Write-Log "Microsoft.Graph.Beta not found - installing ..." 'WARN'
    Install-Module Microsoft.Graph.Beta -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph.Beta.Users              -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Beta.Identity.SignIns   -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Beta.Reports            -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Beta.Organizations      -ErrorAction SilentlyContinue

# -----------------------------------------------------------------------
# Module check - Exchange Online (optional)
# -----------------------------------------------------------------------
$ExoAvailable = $false
if (-not $SkipExchangeOnline) {
    if (Get-Module -ListAvailable -Name 'ExchangeOnlineManagement') {
        $ExoAvailable = $true
        Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue
        Write-Log "ExchangeOnlineManagement module found." 'OK'
    } else {
        Write-Log "ExchangeOnlineManagement module not found. Shared Mailbox detection will be skipped." 'WARN'
        Write-Log "Install it with:  Install-Module ExchangeOnlineManagement -Scope CurrentUser" 'WARN'
    }
}

# -----------------------------------------------------------------------
# Connect to Graph
# -----------------------------------------------------------------------
$connectParams = @{
    Scopes = @(
        'User.Read.All',
        'UserAuthenticationMethod.Read.All',
        'AuditLog.Read.All',
        'Reports.Read.All',
        'Organization.Read.All'
    )
}
if ($TenantId) { $connectParams['TenantId'] = $TenantId }

Write-Log "Connecting to Microsoft Graph ..."
Connect-MgGraph @connectParams -NoWelcome
Write-Log "Graph connected." 'OK'

# -----------------------------------------------------------------------
# Connect to Exchange Online (optional)
# -----------------------------------------------------------------------
$SharedMailboxIds = @{}
if ($ExoAvailable -and -not $SkipExchangeOnline) {
    try {
        Write-Log "Connecting to Exchange Online for Shared Mailbox detection ..."
        $exoParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($TenantId) { $exoParams['DelegatedOrganization'] = $TenantId }
        Connect-ExchangeOnline @exoParams
        Write-Log "Exchange Online connected. Fetching Shared Mailboxes ..." 'OK'

        $sharedMbx = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited `
                     -Properties ExternalDirectoryObjectId -ErrorAction SilentlyContinue
        foreach ($mb in $sharedMbx) {
            if ($mb.ExternalDirectoryObjectId) {
                $SharedMailboxIds[$mb.ExternalDirectoryObjectId.ToLower()] = $true
            }
        }
        Write-Log ("Found {0} Shared Mailboxes in Exchange Online." -f $SharedMailboxIds.Count) 'OK'
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Exchange Online connection failed: $_" 'WARN'
        Write-Log "Shared Mailbox detection disabled for this run." 'WARN'
    }
}

# -----------------------------------------------------------------------
# Tenant info
# -----------------------------------------------------------------------
$tenantName = 'Unknown Tenant'
$tenantId   = 'N/A'
try {
    $org = Get-MgBetaOrganization -ErrorAction Stop | Select-Object -First 1
    if ($org) {
        $dn = gprop $org 'DisplayName'
        if ($dn) { $tenantName = $dn }
        $ti = gprop $org 'Id'
        if ($ti) { $tenantId = $ti }
    }
} catch {
    try {
        $ctx = Get-MgContext
        if ($ctx) {
            $tenantId = if ($ctx.TenantId) { $ctx.TenantId } else { 'N/A' }
        }
    } catch {}
}

Write-Log "Tenant: $tenantName ($tenantId)"

# -----------------------------------------------------------------------
# Fetch users
# -----------------------------------------------------------------------
Write-Log "Fetching users ..."
$userFilter = "userType eq 'Member'"
if ($IncludeGuests) { $userFilter = $null }

$userProps = @(
    'Id','DisplayName','UserPrincipalName','Department','JobTitle',
    'AccountEnabled','UserType','AssignedLicenses','CreatedDateTime',
    'SignInActivity'
)

$getUserParams = @{
    All      = $true
    Property = $userProps
    ErrorAction = 'SilentlyContinue'
}
if ($userFilter) { $getUserParams['Filter'] = $userFilter }

$allUsers = Get-MgBetaUser @getUserParams
if ($MaxUsers -gt 0) { $allUsers = $allUsers | Select-Object -First $MaxUsers }
Write-Log ("Retrieved {0} users." -f $allUsers.Count) 'OK'

# -----------------------------------------------------------------------
# Process each user
# -----------------------------------------------------------------------
$report   = [System.Collections.Generic.List[hashtable]]::new()
$total    = $allUsers.Count
$index    = 0

# KPI accumulators
$cntMfaReg       = 0
$cntPwdless      = 0
$cntAuth         = 0
$cntFido2        = 0
$cntPasskey      = 0
$cntPhone        = 0
$cntWhfb         = 0
$cntOath         = 0
$cntTap          = 0
$cntEmail        = 0
$cntMfaCap       = 0
$cntSspr         = 0
$cntDisabled     = 0
$cntHighRisk     = 0
$cntSharedMbx    = 0

foreach ($user in $allUsers) {
    $index++
    $uid  = gprop $user 'Id'
    $upn  = gprop $user 'UserPrincipalName'
    $name = gprop $user 'DisplayName'
    if (-not $name) { $name = $upn }

    Write-Progress -Activity "Processing users" -Status "$index/$total  $name" `
                   -PercentComplete (($index / [Math]::Max($total,1)) * 100)

    # ---- Shared Mailbox detection ----
    $isShared = $false
    if ($SharedMailboxIds.Count -gt 0 -and $uid) {
        $isShared = $SharedMailboxIds.ContainsKey($uid.ToLower())
    }
    if ($isShared) { $cntSharedMbx++ }

    # ---- Basic properties ----
    $enabled    = [bool](gprop $user 'AccountEnabled' $false)
    $userType   = gprop $user 'UserType' 'Member'
    $dept       = gprop $user 'Department' 'N/A'
    $jobTitle   = gprop $user 'JobTitle' 'N/A'
    $created    = ''
    $createdRaw = gprop $user 'CreatedDateTime'
    if ($createdRaw) {
        try { $created = ([datetime]$createdRaw).ToString('yyyy-MM-dd') } catch {}
    }

    # Licenses
    $licRaw   = gprop $user 'AssignedLicenses'
    $licCount = 0
    if ($licRaw) {
        try {
            if ($licRaw -is [System.Collections.ICollection]) { $licCount = $licRaw.Count }
            elseif ($licRaw.Count) { $licCount = $licRaw.Count }
        } catch {}
    }
    $license = if ($licCount -eq 0) { 'Unlicensed' } else { "Licensed ($licCount SKU)" }

    # ---- Authentication methods ----
    $methods        = [System.Collections.Generic.List[string]]::new()
    $authDevList    = [System.Collections.Generic.List[string]]::new()
    $fido2List      = [System.Collections.Generic.List[string]]::new()
    $passkeyList    = [System.Collections.Generic.List[string]]::new()
    $phoneList      = [System.Collections.Generic.List[string]]::new()
    $whfbCount      = 0
    $tapActive      = 0
    $softOathActive = 0
    $emailAuthCount = 0
    $defaultMethod  = 'none'

    try {
        $authMethods = Get-MgBetaUserAuthenticationMethod -UserId $uid -ErrorAction SilentlyContinue
        foreach ($am in $authMethods) {
            $odataType = ''
            try {
                if ($am.AdditionalProperties -and $am.AdditionalProperties['@odata.type']) {
                    $odataType = $am.AdditionalProperties['@odata.type']
                }
            } catch {}
            if (-not $odataType) {
                try { $odataType = gprop $am '@odata.type' } catch {}
            }

            switch -Wildcard ($odataType) {
                '*microsoftAuthenticatorAuthenticationMethod*' {
                    if ($methods -notcontains 'microsoftAuthenticatorApp') {
                        $methods.Add('microsoftAuthenticatorApp')
                    }
                    $devName    = ''
                    $devOS      = ''
                    $devAppType = ''
                    try { $devName    = $am.AdditionalProperties['displayName']     } catch {}
                    try { $devOS      = $am.AdditionalProperties['operatingSystem'] } catch {}
                    try { $devAppType = $am.AdditionalProperties['clientAppName']   } catch {}
                    $authDevList.Add("$devName [$devOS] ($devAppType)")
                }
                '*phoneAuthenticationMethod*' {
                    if ($methods -notcontains 'mobilePhone') { $methods.Add('mobilePhone') }
                    $ph   = ''
                    $phTy = ''
                    try { $ph   = $am.AdditionalProperties['phoneNumber'] } catch {}
                    try { $phTy = $am.AdditionalProperties['phoneType']   } catch {}
                    $phoneList.Add("$phTy`: $ph")
                }
                '*fido2AuthenticationMethod*' {
                    $aaguid = ''
                    $model  = ''
                    $fid    = gprop $am 'Id'
                    try { $aaguid = $am.AdditionalProperties['aaGuid']      } catch {}
                    try { $model  = $am.AdditionalProperties['model']       } catch {}
                    try {
                        $disp = $am.AdditionalProperties['displayName']
                        if ($disp) { $model = $disp }
                    } catch {}
                    # Distinguish passkey vs hardware FIDO2 key
                    $isPasskey = $false
                    try {
                        $passkeyIndicators = @(
                            '90a3ccdf-635c-4729-a248-9b709135078f',  # MS Authenticator (iOS)
                            'de1e552d-db1d-4423-a619-566b625cdc84'   # MS Authenticator (Android)
                        )
                        if ($aaguid -and $passkeyIndicators -contains $aaguid.ToLower()) {
                            $isPasskey = $true
                        }
                        if (-not $isPasskey) {
                            $credsType = $am.AdditionalProperties['keyType']
                            if ($credsType -eq 'passkey') { $isPasskey = $true }
                        }
                    } catch {}

                    if ($isPasskey) {
                        if ($methods -notcontains 'passkey') { $methods.Add('passkey') }
                        $passkeyList.Add("$model ($aaguid)")
                    } else {
                        if ($methods -notcontains 'fido2') { $methods.Add('fido2') }
                        $fido2List.Add("$model [$aaguid] $fid")
                    }
                }
                '*windowsHelloForBusinessAuthenticationMethod*' {
                    if ($methods -notcontains 'windowsHelloForBusiness') {
                        $methods.Add('windowsHelloForBusiness')
                    }
                    $whfbCount++
                }
                '*softwareOathAuthenticationMethod*' {
                    if ($methods -notcontains 'softwareOneTimePasscode') {
                        $methods.Add('softwareOneTimePasscode')
                    }
                    $softOathActive++
                }
                '*temporaryAccessPassAuthenticationMethod*' {
                    $tapState = ''
                    try { $tapState = $am.AdditionalProperties['isUsable'] } catch {}
                    if ($methods -notcontains 'temporaryAccessPass') {
                        $methods.Add('temporaryAccessPass')
                    }
                    if ($tapState -ne $false) { $tapActive++ }
                }
                '*emailAuthenticationMethod*' {
                    if ($methods -notcontains 'email') { $methods.Add('email') }
                    $emailAuthCount++
                }
                '*passwordAuthenticationMethod*' {
                    # Password is not an MFA method; skip
                }
            }
        }
    } catch {
        Write-Log "Auth methods failed for $upn`: $_" 'WARN'
    }

    # ---- Derived flags ----
    $hasMfa        = $methods.Count -gt 0
    $isPasswordless = ($methods -contains 'fido2' -or $methods -contains 'passkey' -or
                       $methods -contains 'windowsHelloForBusiness' -or
                       ($methods -contains 'microsoftAuthenticatorApp' -and $authDevList.Count -gt 0))
    $isMfaCapable  = $hasMfa

    # ---- Risk level ----
    # Shared Mailboxes and disabled accounts with no sign-in capability = NONE
    $risk = if ($isShared) {
        'NONE'
    } elseif (-not $enabled) {
        'NONE'
    } elseif (-not $hasMfa) {
        'HIGH'
    } elseif (-not $isPasswordless) {
        'MEDIUM'
    } else {
        'LOW'
    }

    # ---- Counters ----
    if ($hasMfa)         { $cntMfaReg++ }
    if ($isPasswordless) { $cntPwdless++ }
    if ($isMfaCapable)   { $cntMfaCap++ }
    if ($authDevList.Count -gt 0) { $cntAuth++ }
    if ($fido2List.Count  -gt 0)  { $cntFido2++ }
    if ($passkeyList.Count -gt 0) { $cntPasskey++ }
    if ($phoneList.Count  -gt 0)  { $cntPhone++ }
    if ($whfbCount  -gt 0)        { $cntWhfb++ }
    if ($softOathActive -gt 0)    { $cntOath++ }
    if ($tapActive  -gt 0)        { $cntTap++ }
    if ($emailAuthCount -gt 0)    { $cntEmail++ }
    if (-not $enabled)            { $cntDisabled++ }
    if ($risk -eq 'HIGH')         { $cntHighRisk++ }

    $report.Add(@{
        id            = $uid
        name          = $name
        upn           = $upn
        dept          = if ($dept)     { $dept     } else { 'N/A' }
        jobTitle      = if ($jobTitle) { $jobTitle } else { 'N/A' }
        enabled       = $enabled
        userType      = $userType
        license       = $license
        isSharedMailbox = $isShared
        mfaReg        = $hasMfa
        mfaCap        = $isMfaCapable
        passwordless  = $isPasswordless
        sspr          = $false
        defaultMethod = $defaultMethod
        methods       = ($methods -join '|')
        methodCount   = $methods.Count
        authDevices   = ($authDevList  -join ' || ')
        authDevCount  = $authDevList.Count
        fido2         = ($fido2List    -join ' || ')
        fido2Count    = $fido2List.Count
        passkey       = ($passkeyList  -join ' || ')
        passkeyCount  = $passkeyList.Count
        phone         = ($phoneList    -join ' || ')
        phoneCount    = $phoneList.Count
        whfb          = $whfbCount
        tap           = $tapActive
        softOath      = $softOathActive
        emailAuth     = $emailAuthCount
        risk          = $risk
        created       = $created
    })
}
Write-Progress -Activity "Processing users" -Completed

Write-Log ("Processed {0} users. MFA Registered: {1} | High Risk: {2} | Shared Mailboxes: {3}" `
    -f $total, $cntMfaReg, $cntHighRisk, $cntSharedMbx) 'OK'

# -----------------------------------------------------------------------
# Optional CSV export
# -----------------------------------------------------------------------
if ($CsvExport) {
    $csvPath = Join-Path $OutputPath ("M365_MFA_Export_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmm'))
    $report | ForEach-Object {
        [PSCustomObject]$_
    } | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV exported: $csvPath" 'OK'
}

# -----------------------------------------------------------------------
# Build JSON for HTML
# -----------------------------------------------------------------------
$jsonRows = ($report | ForEach-Object {
    $row = $_
    $parts = @(
        ('"id":"'             + ($row.id -replace '"','\"') + '"'),
        ('"name":"'           + ($row.name -replace '"','\"') + '"'),
        ('"upn":"'            + ($row.upn -replace '"','\"') + '"'),
        ('"dept":"'           + ($row.dept -replace '"','\"') + '"'),
        ('"jobTitle":"'       + ($row.jobTitle -replace '"','\"') + '"'),
        ('"enabled":'         + ($row.enabled).ToString().ToLower()),
        ('"userType":"'       + $row.userType + '"'),
        ('"license":"'        + ($row.license -replace '"','\"') + '"'),
        ('"isSharedMailbox":' + ($row.isSharedMailbox).ToString().ToLower()),
        ('"mfaReg":'          + ($row.mfaReg).ToString().ToLower()),
        ('"mfaCap":'          + ($row.mfaCap).ToString().ToLower()),
        ('"passwordless":'    + ($row.passwordless).ToString().ToLower()),
        ('"sspr":'            + ($row.sspr).ToString().ToLower()),
        ('"defaultMethod":"'  + $row.defaultMethod + '"'),
        ('"methods":"'        + ($row.methods -replace '"','\"') + '"'),
        ('"methodCount":'     + $row.methodCount),
        ('"authDevices":"'    + ($row.authDevices -replace '"','\"') + '"'),
        ('"authDevCount":'    + $row.authDevCount),
        ('"fido2":"'          + ($row.fido2 -replace '"','\"') + '"'),
        ('"fido2Count":'      + $row.fido2Count),
        ('"passkey":"'        + ($row.passkey -replace '"','\"') + '"'),
        ('"passkeyCount":'    + $row.passkeyCount),
        ('"phone":"'          + ($row.phone -replace '"','\"') + '"'),
        ('"phoneCount":'      + $row.phoneCount),
        ('"whfb":'            + $row.whfb),
        ('"tap":'             + $row.tap),
        ('"softOath":'        + $row.softOath),
        ('"emailAuth":'       + $row.emailAuth),
        ('"risk":"'           + $row.risk + '"'),
        ('"created":"'        + $row.created + '"')
    )
    '{' + ($parts -join ',') + '}'
}) -join ','

$jsonData = "[" + $jsonRows + "]"

# -----------------------------------------------------------------------
# HTML report
# -----------------------------------------------------------------------
$generatedAt   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$highRiskPct   = if ($total -gt 0) { [Math]::Round(($cntHighRisk / $total) * 100, 1) } else { 0 }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>M365 MFA Status Report - $tenantName</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
a{color:#60a5fa}
.hdr{background:linear-gradient(135deg,#1e293b,#0f172a);padding:16px 28px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #334155}
.hdr-left{display:flex;align-items:center;gap:14px}
.hdr-icon{width:42px;height:42px;background:linear-gradient(135deg,#3b82f6,#6366f1);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px}
.hdr h1{font-size:1.4rem;font-weight:700;color:#f1f5f9}
.hdr p{font-size:.8rem;color:#94a3b8;margin-top:2px}
.hdr-right{text-align:right;font-size:.78rem;color:#94a3b8}
.hdr-right strong{color:#60a5fa;font-size:.9rem}
.main{padding:24px 28px;max-width:1800px;margin:0 auto}
.sec-hdr{font-size:.7rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#64748b;margin:28px 0 12px;display:flex;align-items:center;gap:8px}
.sec-hdr::before{content:'';flex:1;height:1px;background:#1e293b}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px}
.kpi{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px;position:relative;overflow:hidden;transition:transform .15s}
.kpi:hover{transform:translateY(-2px)}
.kpi::after{content:'';position:absolute;bottom:0;left:0;right:0;height:3px;border-radius:0 0 10px 10px}
.kpi.blue::after{background:#3b82f6}.kpi.green::after{background:#22c55e}
.kpi.red::after{background:#ef4444}.kpi.amber::after{background:#f59e0b}
.kpi.purple::after{background:#a855f7}.kpi.teal::after{background:#14b8a6}
.kpi.pink::after{background:#ec4899}.kpi.indigo::after{background:#6366f1}
.kpi.sky::after{background:#0ea5e9}.kpi.lime::after{background:#84cc16}
.kpi.slate::after{background:#64748b}
.kpi label{font-size:.7rem;color:#94a3b8;font-weight:500;display:block;margin-bottom:6px}
.kpi .val{font-size:2rem;font-weight:800;line-height:1}
.kpi.blue .val{color:#60a5fa}.kpi.green .val{color:#4ade80}
.kpi.red .val{color:#f87171}.kpi.amber .val{color:#fbbf24}
.kpi.purple .val{color:#c084fc}.kpi.teal .val{color:#2dd4bf}
.kpi.pink .val{color:#f472b6}.kpi.indigo .val{color:#818cf8}
.kpi.sky .val{color:#38bdf8}.kpi.lime .val{color:#a3e635}
.kpi.slate .val{color:#94a3b8}
.kpi .sub{font-size:.72rem;color:#64748b;margin-top:4px}
.chart-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
.chart-grid-wide{display:grid;grid-template-columns:1fr;gap:16px;margin-top:16px}
.chart-box{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px}
.chart-box h3{font-size:.78rem;font-weight:600;color:#94a3b8;margin-bottom:16px;display:flex;align-items:center;gap:6px}
canvas{display:block;width:100%!important}
.bar-list{display:flex;flex-direction:column;gap:10px}
.bar-row{display:grid;grid-template-columns:160px 1fr 40px;align-items:center;gap:10px;font-size:.78rem}
.bar-row label{color:#94a3b8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{background:#0f172a;border-radius:4px;height:10px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .4s ease}
.bar-row span{color:#e2e8f0;font-weight:600;text-align:right}
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
.tbl-wrap{overflow-x:auto;margin-top:16px}
table{width:100%;border-collapse:collapse;font-size:.8rem}
thead tr{background:#0f172a}
th{padding:10px 12px;text-align:left;color:#64748b;font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;cursor:pointer;user-select:none;white-space:nowrap;border-bottom:1px solid #334155}
th:hover{color:#94a3b8}
th .sort-arrow{margin-left:4px;opacity:.4}
th.asc .sort-arrow::after{content:'triangle-up'}
th.desc .sort-arrow::after{content:'triangle-down'}
th:not(.asc):not(.desc) .sort-arrow::after{content:'updown'}
tbody tr{border-bottom:1px solid #1e293b;transition:background .1s;cursor:pointer}
tbody tr:hover{background:#1e293b}
tbody tr.expanded{background:#172036}
tbody tr.shared-row{border-left:3px solid #64748b}
td{padding:9px 12px;vertical-align:middle}
.detail-row td{padding:0;background:#0f172a}
.detail-inner{padding:12px 24px;border-top:1px solid #334155;display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px}
.detail-item{font-size:.75rem;color:#94a3b8}
.detail-item strong{color:#e2e8f0;display:block;margin-bottom:2px}
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
.b-shared{background:#1e293b;color:#94a3b8;border:1px solid #475569}
.risk{display:inline-block;padding:2px 10px;border-radius:20px;font-size:.7rem;font-weight:700}
.risk-HIGH{background:#450a0a;color:#f87171;border:1px solid #7f1d1d}
.risk-MEDIUM{background:#431407;color:#fb923c;border:1px solid #7c2d12}
.risk-LOW{background:#052e16;color:#4ade80;border:1px solid #14532d}
.risk-NONE{background:#1e293b;color:#64748b;border:1px solid #334155}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:middle}
.dot-ok{background:#22c55e}.dot-no{background:#ef4444}.dot-dis{background:#64748b}
.dot-shared{background:#94a3b8}
.pager{display:flex;align-items:center;justify-content:space-between;padding:12px 4px;font-size:.78rem;color:#64748b}
.pager-btns{display:flex;gap:6px}
.pager-btns button{background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:4px 10px;border-radius:5px;cursor:pointer;font-size:.78rem}
.pager-btns button:hover{background:#334155}
.pager-btns button:disabled{opacity:.3;cursor:default}
.export-row{display:flex;justify-content:flex-end;margin-bottom:10px}
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
    Tenant ID: $tenantId<br>
    Generated: $generatedAt
  </div>
</header>

<main class="main">

<div class="sec-hdr">&#9711; Overview Dashboard</div>
<div class="kpi-grid">
  <div class="kpi blue"><label>Total Users</label><div class="val">$total</div><div class="sub">Member accounts</div></div>
  <div class="kpi green"><label>MFA Registered</label><div class="val">$cntMfaReg</div><div class="sub">$(if($total -gt 0){[Math]::Round(($cntMfaReg/$total)*100,1)}else{0})% of total users</div></div>
  <div class="kpi red"><label>&#9651; No MFA (Active)</label><div class="val">$cntHighRisk</div><div class="sub">Enabled accounts at risk</div></div>
  <div class="kpi purple"><label>Passwordless Capable</label><div class="val">$cntPwdless</div><div class="sub">$(if($total -gt 0){[Math]::Round(($cntPwdless/$total)*100,1)}else{0})% of total</div></div>
  <div class="kpi teal"><label>Authenticator App</label><div class="val">$cntAuth</div><div class="sub">Registered devices</div></div>
  <div class="kpi green"><label>FIDO2 Keys</label><div class="val">$cntFido2</div><div class="sub">Users with security keys</div></div>
  <div class="kpi indigo"><label>Passkeys</label><div class="val">$cntPasskey</div><div class="sub">Passwordless Authenticator</div></div>
  <div class="kpi amber"><label>Phone Methods</label><div class="val">$cntPhone</div><div class="sub">SMS / Voice call</div></div>
  <div class="kpi sky"><label>Windows Hello</label><div class="val">$cntWhfb</div><div class="sub">WHFB enrolled</div></div>
  <div class="kpi lime"><label>Software OATH</label><div class="val">$cntOath</div><div class="sub">TOTP / hardware tokens</div></div>
  <div class="kpi pink"><label>Email OTP</label><div class="val">$cntEmail</div><div class="sub">Email authentication</div></div>
  <div class="kpi amber"><label>Temp Access Pass</label><div class="val">$cntTap</div><div class="sub">Active TAP users</div></div>
  <div class="kpi blue"><label>MFA Capable</label><div class="val">$cntMfaCap</div><div class="sub">Can perform MFA</div></div>
  <div class="kpi teal"><label>SSPR Registered</label><div class="val">$cntSspr</div><div class="sub">Self-service password reset</div></div>
  <div class="kpi red"><label>Disabled Accounts</label><div class="val">$cntDisabled</div><div class="sub">Sign-in blocked</div></div>
  <div class="kpi slate"><label>Shared Mailboxes</label><div class="val">$cntSharedMbx</div><div class="sub">Exchange shared mailboxes</div></div>
  <div class="kpi amber"><label>High Risk</label><div class="val">$cntHighRisk</div><div class="sub">$highRiskPct% - no MFA &amp; active</div></div>
</div>

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

<div class="sec-hdr">&#128101; User Details</div>

<div class="filters">
  <div class="fgroup">
    <label>Search</label>
    <input type="text" id="searchBox" placeholder="Name, UPN, department ..." oninput="applyFilters()"/>
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
    <label>Account Type</label>
    <select id="fShared" onchange="applyFilters()">
      <option value="">All Accounts</option>
      <option value="false">Regular Users Only</option>
      <option value="true">Shared Mailboxes Only</option>
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
      <th data-col="isSharedMailbox">Type<span class="sort-arrow"></span></th>
      <th data-col="mfaReg">MFA<span class="sort-arrow"></span></th>
      <th data-col="risk">Risk<span class="sort-arrow"></span></th>
      <th data-col="defaultMethod">Default Method<span class="sort-arrow"></span></th>
      <th data-col="methods">Auth Methods<span class="sort-arrow"></span></th>
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
const allData = $jsonData;

// ---- Donut chart (pure canvas, no library) ----
(function(){
  var mfaYes = allData.filter(function(d){ return d.mfaReg; }).length;
  var mfaNo  = allData.filter(function(d){ return !d.mfaReg && d.enabled && !d.isSharedMailbox; }).length;
  var dis    = allData.filter(function(d){ return !d.enabled || d.isSharedMailbox; }).length;
  var slices = [
    {label:'MFA Registered', val:mfaYes, color:'#22c55e'},
    {label:'No MFA (Active)', val:mfaNo,  color:'#ef4444'},
    {label:'Disabled / Shared', val:dis,   color:'#475569'}
  ];
  var total  = mfaYes + mfaNo + dis;
  var cv     = document.getElementById('cvDonut');
  cv.width   = cv.parentElement.clientWidth;
  cv.height  = 220;
  var ctx    = cv.getContext('2d');
  var cx     = cv.width / 2;
  var cy     = 110;
  var r      = 80;
  var ri     = 50;
  var start  = -Math.PI / 2;
  slices.forEach(function(s){
    if (!s.val) return;
    var sweep = (s.val / total) * 2 * Math.PI;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, start, start + sweep);
    ctx.closePath();
    ctx.fillStyle = s.color;
    ctx.fill();
    start += sweep;
  });
  ctx.beginPath();
  ctx.arc(cx, cy, ri, 0, 2 * Math.PI);
  ctx.fillStyle = '#1e293b';
  ctx.fill();
  ctx.fillStyle = '#f1f5f9';
  ctx.font = 'bold 22px Segoe UI,sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText(mfaYes, cx, cy - 4);
  ctx.fillStyle = '#94a3b8';
  ctx.font = '11px Segoe UI,sans-serif';
  ctx.fillText('MFA Ready', cx, cy + 14);
  var leg = document.getElementById('donutLegend');
  leg.innerHTML = slices.map(function(s){
    return '<div style="display:flex;align-items:center;gap:6px;font-size:.75rem;margin-bottom:4px">'
      + '<span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:' + s.color + '"></span>'
      + '<span style="color:#94a3b8">' + s.label + '</span>'
      + '<span style="margin-left:auto;color:#e2e8f0;font-weight:600">' + s.val + '</span>'
      + '</div>';
  }).join('');
})();

// ---- Bar builder ----
function buildBars(containerId, items, maxVal, colorFn) {
  var el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = items.map(function(item) {
    var pct = maxVal > 0 ? Math.round((item.val / maxVal) * 100) : 0;
    var color = typeof colorFn === 'string' ? colorFn : colorFn(item);
    return '<div class="bar-row">'
      + '<label title="' + item.label + '">' + item.label + '</label>'
      + '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:' + color + '"></div></div>'
      + '<span>' + item.val + '</span>'
      + '</div>';
  }).join('');
}

// Risk bars
(function(){
  var riskCounts = {HIGH:0, MEDIUM:0, LOW:0, NONE:0};
  allData.forEach(function(d){ riskCounts[d.risk] = (riskCounts[d.risk]||0)+1; });
  var items = [
    {label:'High',   val:riskCounts.HIGH,   color:'#ef4444'},
    {label:'Medium', val:riskCounts.MEDIUM, color:'#f59e0b'},
    {label:'Low',    val:riskCounts.LOW,    color:'#22c55e'},
    {label:'None',   val:riskCounts.NONE,   color:'#475569'}
  ];
  buildBars('riskBars', items, Math.max.apply(null, items.map(function(i){return i.val;})),
    function(item){ return item.color; });
})();

// Method bars
(function(){
  var mc = {
    microsoftAuthenticatorApp:'Authenticator App',
    fido2:'FIDO2 Key',
    passkey:'Passkey',
    mobilePhone:'Phone (SMS/Voice)',
    windowsHelloForBusiness:'Windows Hello',
    softwareOneTimePasscode:'Software OATH',
    temporaryAccessPass:'Temp Access Pass',
    email:'Email OTP'
  };
  var counts = {};
  allData.forEach(function(d){
    if (!d.methods) return;
    d.methods.split('|').filter(Boolean).forEach(function(m){
      counts[m] = (counts[m]||0) + 1;
    });
  });
  var items = Object.keys(mc).map(function(k){
    return {label: mc[k], val: counts[k]||0};
  }).sort(function(a,b){ return b.val - a.val; });
  var colors = ['#3b82f6','#22c55e','#a855f7','#f59e0b','#14b8a6','#84cc16','#ef4444','#0ea5e9'];
  buildBars('methodBars', items, items[0] ? items[0].val : 1,
    function(item){ return colors[items.indexOf(item) % colors.length]; });
})();

// Dept bars
(function(){
  var deptMap = {};
  allData.forEach(function(d){
    var dep = d.dept || 'N/A';
    if (!deptMap[dep]) deptMap[dep] = {total:0, mfa:0};
    deptMap[dep].total++;
    if (d.mfaReg) deptMap[dep].mfa++;
  });
  var items = Object.keys(deptMap).map(function(k){
    var e = deptMap[k];
    return {label:k, val:e.mfa, total:e.total, pct: e.total>0 ? Math.round((e.mfa/e.total)*100) : 0};
  }).sort(function(a,b){ return b.pct - a.pct; }).slice(0,12);
  var el = document.getElementById('deptBars');
  if (!el) return;
  el.innerHTML = items.map(function(item){
    var color = item.pct >= 80 ? '#22c55e' : item.pct >= 50 ? '#f59e0b' : '#ef4444';
    return '<div class="bar-row">'
      + '<label title="' + item.label + '">' + item.label + '</label>'
      + '<div class="bar-track"><div class="bar-fill" style="width:' + item.pct + '%;background:' + color + '"></div></div>'
      + '<span>' + item.pct + '%</span>'
      + '</div>';
  }).join('');
})();

// ---- Table ----
const PAGE_SIZE = 50;
let filtered = allData.slice();
let curPage  = 0;
let sortCol  = 'name';
let sortDir  = 1;

// Populate dept dropdown
(function(){
  var depts = [];
  allData.forEach(function(d){ if (depts.indexOf(d.dept||'N/A') < 0) depts.push(d.dept||'N/A'); });
  depts.sort();
  var sel = document.getElementById('fDept');
  sel.innerHTML = '<option value="">All Departments</option>'
    + depts.map(function(d){ return '<option value="' + d + '">' + d + '</option>'; }).join('');
})();

var methodBadgeClass = {
  microsoftAuthenticatorApp:'b-auth',
  mobilePhone:'b-phone',
  fido2:'b-fido',
  passkey:'b-pass',
  windowsHelloForBusiness:'b-whfb',
  softwareOneTimePasscode:'b-oath',
  temporaryAccessPass:'b-tap',
  email:'b-email'
};
var methodLabel = {
  microsoftAuthenticatorApp:'Authenticator',
  mobilePhone:'Phone',
  fido2:'FIDO2',
  passkey:'Passkey',
  windowsHelloForBusiness:'WHfB',
  softwareOneTimePasscode:'OATH',
  temporaryAccessPass:'TAP',
  email:'Email'
};

function methodBadges(str) {
  if (!str) return '<span style="color:#475569;font-size:.7rem">None</span>';
  return str.split('|').filter(Boolean).map(function(m){
    var cls = methodBadgeClass[m] || 'b-other';
    var lbl = methodLabel[m] || m;
    return '<span class="badge ' + cls + '">' + lbl + '</span>';
  }).join('');
}

function renderRow(d, idx) {
  var enabled    = d.enabled;
  var isShared   = d.isSharedMailbox;
  var statusDot  = isShared
    ? '<span class="dot dot-shared"></span>Shared MB'
    : (enabled
        ? '<span class="dot dot-ok"></span>Enabled'
        : '<span class="dot dot-dis"></span>Disabled');
  var typeHtml   = isShared
    ? '<span class="badge b-shared">Shared Mailbox</span>'
    : '<span style="color:#64748b;font-size:.72rem">' + (d.userType || 'Member') + '</span>';
  var mfaHtml    = d.mfaReg
    ? '<span class="dot dot-ok"></span>Yes'
    : '<span class="dot dot-no"></span>No';
  var rowClass   = isShared ? ' class="shared-row"' : '';
  return '<tr' + rowClass + ' onclick="toggleDetail(' + idx + ',this)" data-idx="' + idx + '">'
    + '<td><strong>' + (d.name || '') + '</strong></td>'
    + '<td style="color:#94a3b8;font-size:.75rem">' + (d.upn || '') + '</td>'
    + '<td>' + (d.dept || 'N/A') + '</td>'
    + '<td style="white-space:nowrap">' + statusDot + '</td>'
    + '<td>' + typeHtml + '</td>'
    + '<td style="white-space:nowrap">' + mfaHtml + '</td>'
    + '<td><span class="risk risk-' + d.risk + '">' + d.risk + '</span></td>'
    + '<td style="font-size:.75rem;color:#94a3b8">' + (d.defaultMethod || 'none') + '</td>'
    + '<td>' + methodBadges(d.methods) + '</td>'
    + '<td style="text-align:center;color:#64748b">' + (d.methodCount || 0) + '</td>'
    + '<td style="font-size:.75rem;color:#94a3b8">' + (d.license || '') + '</td>'
    + '<td style="font-size:.75rem;color:#64748b">' + (d.created || 'N/A') + '</td>'
    + '</tr>'
    + '<tr class="detail-row" id="detail-' + idx + '" style="display:none">'
    + '<td colspan="12">'
    + '<div class="detail-inner">'
    + '<div class="detail-item"><strong>Job Title</strong>' + (d.jobTitle || 'N/A') + '</div>'
    + '<div class="detail-item"><strong>User Type</strong>' + (d.userType || 'Member') + '</div>'
    + '<div class="detail-item"><strong>Shared Mailbox</strong>' + (isShared ? 'Yes' : 'No') + '</div>'
    + '<div class="detail-item"><strong>Passwordless</strong>' + (d.passwordless ? 'Yes' : 'No') + '</div>'
    + '<div class="detail-item"><strong>SSPR Registered</strong>' + (d.sspr ? 'Yes' : 'No') + '</div>'
    + '<div class="detail-item"><strong>MFA Capable</strong>' + (d.mfaCap ? 'Yes' : 'No') + '</div>'
    + '<div class="detail-item"><strong>Authenticator Devices</strong>' + (d.authDevices || 'None') + '</div>'
    + '<div class="detail-item"><strong>FIDO2 Keys</strong>' + (d.fido2 || 'None') + '</div>'
    + '<div class="detail-item"><strong>Passkeys</strong>' + (d.passkey || 'None') + '</div>'
    + '<div class="detail-item"><strong>Phone Numbers</strong>' + (d.phone || 'None') + '</div>'
    + '<div class="detail-item"><strong>Windows Hello</strong>' + (d.whfb ? d.whfb + ' device(s)' : 'None') + '</div>'
    + '<div class="detail-item"><strong>Software OATH</strong>' + (d.softOath ? 'Yes' : 'No') + '</div>'
    + '<div class="detail-item"><strong>Temp Access Pass</strong>' + (d.tap ? 'Yes' : 'No') + '</div>'
    + '<div class="detail-item"><strong>Email OTP</strong>' + (d.emailAuth ? 'Yes' : 'No') + '</div>'
    + '<div class="detail-item"><strong>User ID</strong><span style="font-size:.7rem;color:#64748b">' + (d.id || 'N/A') + '</span></div>'
    + '</div></td></tr>';
}

function lastPage() { return Math.max(0, Math.ceil(filtered.length / PAGE_SIZE) - 1); }

function renderTable() {
  var start = curPage * PAGE_SIZE;
  var page  = filtered.slice(start, start + PAGE_SIZE);
  var body  = document.getElementById('tableBody');
  body.innerHTML = page.map(function(d, i){ return renderRow(d, start + i); }).join('');
  var end   = Math.min(start + PAGE_SIZE, filtered.length);
  document.getElementById('pageInfo').textContent =
    'Showing ' + (start + 1) + ' - ' + end + ' of ' + filtered.length + ' users';
  document.getElementById('resultCount').textContent =
    filtered.length < allData.length
      ? filtered.length + ' of ' + allData.length + ' users match current filters'
      : allData.length + ' total users';
  document.getElementById('btnFirst').disabled = curPage === 0;
  document.getElementById('btnPrev').disabled  = curPage === 0;
  document.getElementById('btnNext').disabled  = curPage >= lastPage();
  document.getElementById('btnLast').disabled  = curPage >= lastPage();
}

function toggleDetail(idx, row) {
  var dr = document.getElementById('detail-' + idx);
  if (!dr) return;
  var visible = dr.style.display !== 'none';
  dr.style.display = visible ? 'none' : 'table-row';
  row.classList.toggle('expanded', !visible);
}

function applyFilters() {
  var q       = document.getElementById('searchBox').value.toLowerCase();
  var fMfa    = document.getElementById('fMfa').value;
  var fRisk   = document.getElementById('fRisk').value;
  var fEn     = document.getElementById('fEnabled').value;
  var fPwdl   = document.getElementById('fPwdless').value;
  var fShared = document.getElementById('fShared').value;
  var fDept   = document.getElementById('fDept').value;

  filtered = allData.filter(function(d) {
    if (q && !(
          (d.name     || '').toLowerCase().indexOf(q) >= 0 ||
          (d.upn      || '').toLowerCase().indexOf(q) >= 0 ||
          (d.dept     || '').toLowerCase().indexOf(q) >= 0 ||
          (d.jobTitle || '').toLowerCase().indexOf(q) >= 0
        )) return false;
    if (fMfa    && String(d.mfaReg)         !== fMfa)    return false;
    if (fRisk   && d.risk                   !== fRisk)   return false;
    if (fEn     && String(d.enabled)        !== fEn)     return false;
    if (fPwdl   && String(d.passwordless)   !== fPwdl)   return false;
    if (fShared && String(d.isSharedMailbox)!== fShared) return false;
    if (fDept   && (d.dept || 'N/A')        !== fDept)   return false;
    return true;
  });

  filtered.sort(function(a, b) {
    var av = a[sortCol] != null ? a[sortCol] : '';
    var bv = b[sortCol] != null ? b[sortCol] : '';
    if (typeof av === 'boolean') return ((av ? 1 : 0) - (bv ? 1 : 0)) * sortDir;
    return String(av).localeCompare(String(bv)) * sortDir;
  });

  curPage = 0;
  renderTable();
}

document.querySelectorAll('th[data-col]').forEach(function(th) {
  th.addEventListener('click', function() {
    var col = th.getAttribute('data-col');
    if (sortCol === col) { sortDir *= -1; }
    else { sortCol = col; sortDir = 1; }
    document.querySelectorAll('th').forEach(function(t) { t.classList.remove('asc','desc'); });
    th.classList.add(sortDir === 1 ? 'asc' : 'desc');
    applyFilters();
  });
});

function clearFilters() {
  document.getElementById('searchBox').value = '';
  document.getElementById('fMfa').value      = '';
  document.getElementById('fRisk').value     = '';
  document.getElementById('fEnabled').value  = '';
  document.getElementById('fPwdless').value  = '';
  document.getElementById('fShared').value   = '';
  document.getElementById('fDept').value     = '';
  applyFilters();
}

function goPage(p) {
  curPage = Math.max(0, Math.min(p, lastPage()));
  renderTable();
}

function exportCsv() {
  var cols = ['name','upn','dept','jobTitle','enabled','isSharedMailbox','mfaReg','mfaCap',
              'passwordless','sspr','risk','defaultMethod','methods','authDevices','fido2',
              'passkey','phone','whfb','softOath','tap','emailAuth','license','created'];
  var header = cols.join(',');
  var rows = filtered.map(function(d) {
    return cols.map(function(c) {
      var v = d[c] != null ? d[c] : '';
      var s = String(v).replace(/"/g, '""');
      return (s.indexOf(',') >= 0 || s.indexOf('"') >= 0 || s.indexOf('\n') >= 0)
        ? '"' + s + '"' : s;
    }).join(',');
  });
  var csv = [header].concat(rows).join('\r\n');
  var a   = document.createElement('a');
  a.href  = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
  a.download = 'M365_MFA_Export.csv';
  a.click();
}

applyFilters();
</script>
</body>
</html>
"@

# -----------------------------------------------------------------------
# Save report
# -----------------------------------------------------------------------
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$reportFile = Join-Path $OutputPath ("M365_MFA_Report_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmm'))

# Write UTF-8 with BOM so PowerShell 5.1 reads it correctly if re-opened
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($reportFile, $html, $utf8Bom)

Write-Log "Report saved: $reportFile" 'OK'
Write-Log "Opening in default browser ..." 'OK'
Start-Process $reportFile
