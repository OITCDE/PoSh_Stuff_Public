#Requires -Version 5.1
<#
.SYNOPSIS
    AD Service Account Usage Analyzer — Interactive HTML Report Generator

.DESCRIPTION
    Queries Domain Controller Security Event Logs (live or archived .evtx files)
    for authentication-related events, normalizes and correlates them, and produces
    a fully self-contained interactive HTML report with dashboard, charts, a
    filterable/sortable event table, and per-account analysis cards.

.PARAMETER DomainControllers
    One or more DC hostnames. Auto-detected via Get-ADDomainController if omitted.
    Ignored when -EvtxFolder or -EvtxFiles are specified.

.PARAMETER DaysBack
    Days of history to analyze. Default: 7. Overridden by -StartTime / -EndTime.

.PARAMETER StartTime
    Explicit analysis start time.

.PARAMETER EndTime
    Explicit analysis end time. Default: now.

.PARAMETER OutputPath
    HTML output path. Defaults to current directory with a timestamp.

.PARAMETER AccountFilter
    Restrict the report to these account names. Supports wildcards (e.g. "svc_*").
    Exact names use fast XPath queries; wildcards fall back to broad fetch + filter.

.PARAMETER IncludeComputerAccounts
    Include machine accounts (names ending with $).

.PARAMETER MaxEventsPerQuery
    Safety cap for broad (wildcard/no-filter) queries. Default: 50000.

.PARAMETER EvtxFolder
    Path to a folder containing .evtx archive files to analyze.

.PARAMETER EvtxFiles
    One or more explicit .evtx file paths to analyze.

.PARAMETER EvtxRecurse
    Recurse into subfolders when using -EvtxFolder.

.PARAMETER NoTimeFilter
    Skip StartTime/EndTime filtering. Recommended when processing full archive files.

.EXAMPLE
    .\Get-ADServiceAccountReport.ps1 -DomainControllers DC01 -DaysBack 7 -AccountFilter "Dienste"

.EXAMPLE
    .\Get-ADServiceAccountReport.ps1 -EvtxFiles "D:\Archive\Security.evtx" -NoTimeFilter -AccountFilter "Dienste"

.EXAMPLE
    .\Get-ADServiceAccountReport.ps1 -EvtxFolder "D:\Archive" -EvtxRecurse -NoTimeFilter -AccountFilter "svc_*"

.NOTES
    Author  : Ollischer IT Consulting
    Version : 1.4
#>

[CmdletBinding()]
param(
    [string[]]$DomainControllers,
    [int]$DaysBack = 7,
    [datetime]$StartTime,
    [datetime]$EndTime          = (Get-Date),
    [string]$OutputPath         = ".\AD_SvcAcct_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [string[]]$AccountFilter    = @(),
    [switch]$IncludeComputerAccounts,
    [int]$MaxEventsPerQuery     = 50000,
    [string]$EvtxFolder,
    [string[]]$EvtxFiles        = @(),
    [switch]$EvtxRecurse,
    [switch]$NoTimeFilter
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ─────────────────────────────────────────────────────────────────────────────
# INITIALISATION
# ─────────────────────────────────────────────────────────────────────────────

if (-not $PSBoundParameters.ContainsKey('StartTime')) { $StartTime = $EndTime.AddDays(-$DaysBack) }

$GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$Timespan    = "$($StartTime.ToString('yyyy-MM-dd HH:mm')) - $($EndTime.ToString('yyyy-MM-dd HH:mm'))"
$DomainName  = try { (Get-ADDomain -ErrorAction SilentlyContinue).DNSRoot } catch { $env:USERDNSDOMAIN }

Write-Host ''
Write-Host '  +--------------------------------------------------+' -ForegroundColor Cyan
Write-Host '  |   AD Service Account Usage Analyzer  v1.4        |' -ForegroundColor Cyan
Write-Host '  |   Ollischer IT Consulting                         |' -ForegroundColor Cyan
Write-Host '  +--------------------------------------------------+' -ForegroundColor Cyan
Write-Host "  Domain  : $DomainName"
Write-Host "  Output  : $OutputPath"

# ─────────────────────────────────────────────────────────────────────────────
# BUILD UNIFIED SOURCE LIST (DCs and/or .evtx files)
# ─────────────────────────────────────────────────────────────────────────────

$Sources = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($EvtxFolder -or $EvtxFiles.Count -gt 0) {

    if ($EvtxFolder) {
        if (-not (Test-Path $EvtxFolder)) {
            Write-Warning "EvtxFolder not found: $EvtxFolder"
        } else {
            $gciParams = @{ Path = $EvtxFolder; Filter = '*.evtx' }
            if ($EvtxRecurse) { $gciParams['Recurse'] = $true }
            foreach ($f in (Get-ChildItem @gciParams | Sort-Object Name)) {
                $Sources.Add([PSCustomObject]@{ Type = 'FILE'; Label = $f.Name; Path = $f.FullName })
            }
        }
    }

    foreach ($fp in $EvtxFiles) {
        if (Test-Path $fp) {
            $Sources.Add([PSCustomObject]@{ Type = 'FILE'; Label = (Split-Path $fp -Leaf); Path = $fp })
        } else {
            Write-Warning "File not found, skipping: $fp"
        }
    }

    if ($Sources.Count -eq 0) { Write-Warning 'No valid .evtx files found. Exiting.'; exit 1 }

    Write-Host "  Mode    : EVTX Archive ($($Sources.Count) file(s))" -ForegroundColor Cyan
    $Sources | ForEach-Object { Write-Host "            $($_.Path)" -ForegroundColor DarkGray }

} else {

    if (-not $DomainControllers -or $DomainControllers.Count -eq 0) {
        try {
            $DomainControllers = (Get-ADDomainController -Filter * -ErrorAction Stop).HostName
            Write-Host "  DCs     : $($DomainControllers -join ', ')  [auto-detected]" -ForegroundColor Green
        } catch {
            $ls = ($env:LOGONSERVER -replace '\\', '').Trim()
            $DomainControllers = @(if ($ls) { $ls } else { 'localhost' })
            Write-Host "  DCs     : $($DomainControllers -join ', ')  [fallback]" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  DCs     : $($DomainControllers -join ', ')"
    }

    foreach ($dc in $DomainControllers) {
        $Sources.Add([PSCustomObject]@{ Type = 'DC'; Label = $dc; Path = $null })
    }
}

if ($NoTimeFilter) {
    Write-Host "  Filter  : No time filter — full archive(s)" -ForegroundColor Yellow
} else {
    Write-Host "  Window  : $Timespan"
}

# ─────────────────────────────────────────────────────────────────────────────
# LOOKUP TABLES
# ─────────────────────────────────────────────────────────────────────────────

$script:LTMap = @{
    '2'='Interactive'; '3'='Network'; '4'='Batch (Scheduled Task)';
    '5'='Service'; '7'='Unlock'; '8'='Network Cleartext';
    '9'='NewCredentials (RunAs)'; '10'='RemoteInteractive (RDP)';
    '11'='CachedInteractive'; '12'='CachedRemoteInteractive'; '13'='CachedUnlock'
}

$script:StatusMap = @{
    '0x6'='Account Not Found';       '0x7'='New Computer Account';
    '0xC'='Workstation Restriction'; '0x12'='Account Disabled/Expired/Locked';
    '0x17'='Password Expired';       '0x18'='Bad Password';
    '0x20'='Ticket Expired';         '0x25'='Clock Skew Too Great';
    '0x32'='Logon Type Not Permitted';
    '0xC0000064'='Account Not Found'; '0xC000006A'='Wrong Password';
    '0xC000006D'='Bad Credentials';   '0xC000006E'='Account Restriction';
    '0xC0000070'='Workstation Restriction'; '0xC0000071'='Password Expired';
    '0xC0000072'='Account Disabled';  '0xC0000193'='Account Expired';
    '0xC0000234'='Account Locked Out';'0xC00002EE'='General Logon Failure'
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

function Get-EvtProps([System.Diagnostics.Eventing.Reader.EventLogRecord]$ev) {
    $h = @{}
    try {
        $x = [xml]$ev.ToXml()
        foreach ($d in $x.Event.EventData.Data) { if ($d.Name) { $h[$d.Name] = $d.'#text' } }
    } catch {}
    return $h
}

function Get-LTName([string]$t) {
    if ($script:LTMap.ContainsKey($t)) { return $script:LTMap[$t] }
    if ($t) { return "Type $t" } else { return '' }
}

function Get-StatusMsg([string]$c) {
    if (-not $c -or $c -eq '0x0') { return 'Success' }
    if ($script:StatusMap.ContainsKey($c)) { return $script:StatusMap[$c] }
    return $c
}

function Get-Purpose([int]$id, [hashtable]$p) {
    switch ($id) {
        4768 {
            if ($p['Status'] -and $p['Status'] -ne '0x0') { return 'Kerberos TGT Request [FAILED]' }
            return 'Kerberos TGT Request'
        }
        4769 {
            $svc = $p['ServiceName']
            $f   = ($p['Status'] -and $p['Status'] -ne '0x0')
            $sfx = if ($f) { ' [FAILED]' } else { '' }
            if ($svc -eq 'krbtgt')                                         { return "TGT Renewal$sfx" }
            if ($svc -match '^(host|cifs|ldap|http|mssql|rpc|wsman|gc)/') { return "Service Access: $svc$sfx" }
            return "Service Ticket: $svc$sfx"
        }
        4771 { return 'Kerberos Pre-Auth Failure [FAILED]' }
        4776 {
            if ($p['Status'] -and $p['Status'] -ne '0x0') { return 'NTLM Authentication [FAILED]' }
            return 'NTLM Authentication'
        }
        4624 { return "Logon - $(Get-LTName $p['LogonType'])" }
        4625 { return "Failed Logon - $(Get-LTName $p['LogonType']) [FAILED]" }
        4648 { return 'Explicit Credential Logon (RunAs / PassThrough)' }
        4672 { return 'Special Privileges Assigned at Logon' }
        4740 { return 'Account Lockout [FAILED]' }
        default { return "Event $id" }
    }
}

function Get-AuthMeth([int]$id, [hashtable]$p) {
    if ($id -in @(4768,4769,4771)) { return 'Kerberos' }
    if ($id -eq 4776)              { return 'NTLM' }
    $pkg = $p['AuthenticationPackageName']
    if (-not $pkg)              { return 'N/A' }
    if ($pkg -match 'Kerberos') { return 'Kerberos' }
    if ($pkg -match 'NTLM|MSV') { return 'NTLM' }
    return $pkg
}

function Test-Include([string]$n) {
    if ([string]::IsNullOrWhiteSpace($n))                                              { return $false }
    if ($n -in @('-','ANONYMOUS LOGON','LOCAL SERVICE','NETWORK SERVICE','SYSTEM'))    { return $false }
    if ($n -match '^(DWM|UMFD)-\d+$')                                                 { return $false }
    if (-not $IncludeComputerAccounts -and $n -match '^[A-Za-z0-9\-]+\$$')            { return $false }
    if ($AccountFilter.Count -gt 0) {
        $match = $false
        foreach ($f in $AccountFilter) { if ($n -like $f) { $match = $true; break } }
        if (-not $match) { return $false }
    }
    return $true
}

function Build-XPath {
    param([int]$EventId, [string]$AccountName, [datetime]$Start, [datetime]$End, [switch]$NoTime)
    $field    = if ($EventId -eq 4672) { 'SubjectUserName' } else { 'TargetUserName' }
    $startUtc = $Start.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")
    $endUtc   = $End.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")
    $timePart = if (-not $NoTime) { " and TimeCreated[@SystemTime>='$startUtc' and @SystemTime<='$endUtc']" } else { '' }
    return "*[System[EventID=$EventId$timePart] and EventData[Data[@Name='$field']='$AccountName']]"
}

function Js([string]$s) {
    if (-not $s) { return '""' }
    $s = $s -replace '\\',   '\\'
    $s = $s -replace '"',    '\"'
    $s = $s -replace "`r`n", '\n'
    $s = $s -replace "`n",   '\n'
    $s = $s -replace "`t",   '\t'
    return "`"$s`""
}

# ─────────────────────────────────────────────────────────────────────────────
# EVENT DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

$EventDefs = [ordered]@{
    '4768' = 'Kerberos TGT Request'
    '4769' = 'Kerberos Service Ticket'
    '4771' = 'Kerberos Pre-Auth Failure'
    '4776' = 'NTLM Credential Validation'
    '4624' = 'Successful Logon'
    '4625' = 'Failed Logon'
    '4648' = 'Explicit Credential Logon'
    '4672' = 'Special Privileges Assigned'
    '4740' = 'Account Lockout'
}

# ─────────────────────────────────────────────────────────────────────────────
# EVENT COLLECTION
# ─────────────────────────────────────────────────────────────────────────────

$AllEvents     = [System.Collections.Generic.List[PSCustomObject]]::new()
$CollectErrors = [System.Collections.Generic.List[string]]::new()

# Determine query strategy
$exactAccounts = @($AccountFilter | Where-Object { $_ -notmatch '[\*\?]' })
$wildAccounts  = @($AccountFilter | Where-Object { $_ -match  '[\*\?]' })
$useXPath      = $exactAccounts.Count -gt 0

Write-Host ''

foreach ($source in $Sources) {

    Write-Host "  [$($source.Type)] $($source.Label)" -ForegroundColor Cyan

    foreach ($eid in $EventDefs.Keys) {
        Write-Host ("       EID {0} - {1,-35}" -f $eid, $EventDefs[$eid]) -NoNewline -ForegroundColor DarkGray

        $n        = 0
        $rawCount = 0

        # XPath: one query per exact account name (fast, no cap)
        # Broad: single query + PowerShell filter (needed for wildcards / no filter)
        $queryTargets = if ($useXPath) { $exactAccounts } else { @($null) }

        foreach ($targetAccount in $queryTargets) {
            try {
                if ($useXPath -and $targetAccount) {
                    $xpath = Build-XPath -EventId ([int]$eid) `
                                         -AccountName $targetAccount `
                                         -Start $StartTime `
                                         -End   $EndTime `
                                         -NoTime:$NoTimeFilter

                    if ($source.Type -eq 'FILE') {
                        $raw = Get-WinEvent -Path $source.Path `
                                            -FilterXPath $xpath `
                                            -ErrorAction Stop
                    } else {
                        $raw = Get-WinEvent -ComputerName $source.Label `
                                            -LogName 'Security' `
                                            -FilterXPath $xpath `
                                            -ErrorAction Stop
                    }
                } else {
                    $fh = @{ Id = [int]$eid }
                    if (-not $NoTimeFilter) { $fh['StartTime'] = $StartTime; $fh['EndTime'] = $EndTime }
                    if ($source.Type -eq 'FILE') {
                        $fh['Path']    = $source.Path
                        $raw = Get-WinEvent -FilterHashtable $fh `
                                            -MaxEvents $MaxEventsPerQuery -ErrorAction Stop
                    } else {
                        $fh['LogName'] = 'Security'
                        $raw = Get-WinEvent -ComputerName $source.Label `
                                            -FilterHashtable $fh `
                                            -MaxEvents $MaxEventsPerQuery -ErrorAction Stop
                    }
                }

                $rawCount += @($raw).Count

                foreach ($r in $raw) {
                    $p    = Get-EvtProps $r
                    $acct = if ($eid -eq '4672') { $p['SubjectUserName'] } else { $p['TargetUserName'] }

                    if ($useXPath -and $targetAccount) {
                        if ([string]::IsNullOrWhiteSpace($acct)) { continue }
                        if ($wildAccounts.Count -gt 0) {
                            $wm = $false
                            foreach ($wf in $wildAccounts) { if ($acct -like $wf) { $wm = $true; break } }
                            if (-not $wm) { continue }
                        }
                    } else {
                        if (-not (Test-Include $acct)) { continue }
                    }

                    $srcIP = switch ($eid) {
                        { $_ -in @('4768','4769','4771','4624','4625','4648') } { $p['IpAddress'] }
                        '4776'  { $p['Workstation'] }
                        '4740'  { $p['CallerComputerName'] }
                        default { '-' }
                    }
                    if (-not $srcIP -or $srcIP -in @('','::1','127.0.0.1')) { $srcIP = 'localhost' }
                    $srcIP = $srcIP -replace '^::ffff:', ''

                    $sc = $p['Status']
                    $ok = switch ($eid) {
                        { $_ -in @('4624','4648','4672') } { $true  }
                        { $_ -in @('4625','4771','4740') } { $false }
                        default { -not $sc -or $sc -eq '0x0' }
                    }

                    $evtDomain  = if ($p['TargetDomainName'])     { $p['TargetDomainName']  }
                                  elseif ($p['SubjectDomainName']) { $p['SubjectDomainName'] }
                                  else { '' }
                    $evtService = if ($p['ServiceName'])     { $p['ServiceName'] }     else { '' }
                    $evtLT      = if ($p['LogonType'])       { $p['LogonType'] }       else { '' }
                    $evtStatus  = if ($ok)                   { 'Success' }             else { 'Failure' }
                    $evtSC      = if ($sc)                   { $sc }                   else { '0x0' }
                    $evtWS      = if ($p['WorkstationName']) { $p['WorkstationName'] }
                                  elseif ($p['Workstation']) { $p['Workstation'] }
                                  else { '' }
                    $evtPriv    = if ($p['PrivilegeList'])   { ($p['PrivilegeList'] -replace "`n", ', ') }
                                  else { '' }

                    $AllEvents.Add([PSCustomObject]@{
                        Time        = $r.TimeCreated
                        TimeStr     = $r.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                        DateStr     = $r.TimeCreated.ToString('yyyy-MM-dd')
                        HourInt     = [int]$r.TimeCreated.Hour
                        EID         = [int]$eid
                        EType       = $EventDefs[$eid]
                        Account     = $acct
                        Domain      = $evtDomain
                        SourceIP    = $srcIP
                        Service     = $evtService
                        LogonType   = $evtLT
                        LTName      = Get-LTName $evtLT
                        AuthMethod  = Get-AuthMeth ([int]$eid) $p
                        IsSuccess   = $ok
                        Status      = $evtStatus
                        StatusCode  = $evtSC
                        StatusMsg   = Get-StatusMsg $sc
                        Purpose     = Get-Purpose ([int]$eid) $p
                        DC          = $source.Label
                        Workstation = $evtWS
                        Privileges  = $evtPriv
                    })
                    $n++
                }

            } catch {
                if ($_.Exception.Message -notmatch 'No events were found') {
                    Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
                    $CollectErrors.Add("Source=$($source.Label) EID=$eid Account=$targetAccount | $($_.Exception.Message)")
                }
            }
        }

        $modeTag = if ($useXPath) { '[XPath]' } else { '[Broad]' }
        Write-Host ("  {0} kept  ({1} raw)  {2}" -f $n, $rawCount, $modeTag) `
                   -ForegroundColor $(if ($n -gt 0) { 'Green' } else { 'DarkGray' })
    }
}

Write-Host ''
Write-Host "  Total events collected : $($AllEvents.Count)" `
           -ForegroundColor $(if ($AllEvents.Count -gt 0) { 'Green' } else { 'Red' })

if ($AllEvents.Count -eq 0) {
    Write-Warning 'No events collected. Verify source accessibility, permissions, and audit policy.'
    exit 1
}

$AllEvents = [System.Collections.Generic.List[PSCustomObject]]($AllEvents | Sort-Object Time)

# ─────────────────────────────────────────────────────────────────────────────
# AGGREGATIONS
# ─────────────────────────────────────────────────────────────────────────────

$UniqueAccounts  = @($AllEvents | Select-Object -ExpandProperty Account -Unique | Sort-Object)
$TotalEvents     = $AllEvents.Count
$TotalFailures   = @($AllEvents | Where-Object { -not $_.IsSuccess }).Count
$TotalLockouts   = @($AllEvents | Where-Object { $_.EID -eq 4740 }).Count
$NTLMCount       = @($AllEvents | Where-Object { $_.AuthMethod -eq 'NTLM' }).Count
$UniqueSourceIPs = @($AllEvents | Where-Object { $_.SourceIP -notmatch '^(localhost|-)$' } |
                    Select-Object -ExpandProperty SourceIP -Unique).Count

$ByAccount  = @($AllEvents | Group-Object Account  | Sort-Object Count -Descending)
$ByDay      = @($AllEvents | Group-Object DateStr  | Sort-Object Name)
$ByType     = @($AllEvents | Group-Object EType    | Sort-Object Count -Descending)
$BySrcIP    = @($AllEvents | Where-Object { $_.SourceIP -notmatch '^(localhost|-)$' } |
               Group-Object SourceIP | Sort-Object Count -Descending | Select-Object -First 15)
$ByAuth     = @($AllEvents | Group-Object AuthMethod | Sort-Object Count -Descending)
$ByLT       = @($AllEvents | Where-Object { $_.LTName } | Group-Object LTName | Sort-Object Count -Descending)
$Top15Accts = $ByAccount | Select-Object -First 15
$HourCounts = 0..23 | ForEach-Object { $h = $_; @($AllEvents | Where-Object { $_.HourInt -eq $h }).Count }

$AcctDetails = foreach ($ag in $ByAccount) {
    $ae = @($ag.Group)
    [PSCustomObject]@{
        Name       = $ag.Name
        Total      = $ag.Count
        Failures   = @($ae | Where-Object { -not $_.IsSuccess }).Count
        Lockouts   = @($ae | Where-Object { $_.EID -eq 4740 }).Count
        NTLMCount  = @($ae | Where-Object { $_.AuthMethod -eq 'NTLM' }).Count
        FirstSeen  = ($ae | Measure-Object Time -Minimum).Minimum.ToString('yyyy-MM-dd HH:mm:ss')
        LastSeen   = ($ae | Measure-Object Time -Maximum).Maximum.ToString('yyyy-MM-dd HH:mm:ss')
        UniqueIPs  = @($ae | Where-Object { $_.SourceIP -notmatch '^(localhost|-)$' } |
                     Select-Object -ExpandProperty SourceIP -Unique).Count
        TopSources = @($ae | Where-Object { $_.SourceIP -notmatch '^(localhost|-)$' } |
                     Group-Object SourceIP | Sort-Object Count -Descending | Select-Object -First 8)
        TopPurpose = @($ae | Group-Object Purpose  | Sort-Object Count -Descending | Select-Object -First 8)
        ByType     = @($ae | Group-Object EType    | Sort-Object Count -Descending)
        ByLT       = @($ae | Where-Object { $_.LTName } | Group-Object LTName |
                     Sort-Object Count -Descending | Select-Object -First 6)
        Services   = @($ae | Where-Object { $_.Service -and $_.Service -notin @('krbtgt','') } |
                     Select-Object -ExpandProperty Service -Unique | Sort-Object | Select-Object -First 20)
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# SERIALISE DATA FOR HTML EMBEDDING
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# SERIALISE DATA FOR HTML EMBEDDING
# ─────────────────────────────────────────────────────────────────────────────

Write-Host '  Serialising data...' -ForegroundColor DarkGray

# ── Events table ─────────────────────────────────────────────────────────────
$eventsForJson = @($AllEvents | ForEach-Object {
    [PSCustomObject]@{
        t   = $_.TimeStr
        eid = $_.EID
        et  = $_.EType
        a   = $_.Account
        d   = $_.Domain
        ip  = $_.SourceIP
        svc = $_.Service
        lt  = $_.LTName
        am  = $_.AuthMethod
        ok  = $_.IsSuccess
        st  = $_.Status
        sm  = $_.StatusMsg
        pu  = $_.Purpose
        dc  = $_.DC
        ws  = $_.Workstation
    }
})
$D_EVENTS = if ($eventsForJson.Count -eq 0) { '[]' }
            elseif ($eventsForJson.Count -eq 1) { '[' + ($eventsForJson | ConvertTo-Json -Compress -Depth 2) + ']' }
            else { $eventsForJson | ConvertTo-Json -Compress -Depth 2 }

# ── Account details ───────────────────────────────────────────────────────────
$acctsForJson = @($AcctDetails | ForEach-Object {
    $a = $_
    [PSCustomObject]@{
        name     = $a.Name
        total    = $a.Total
        failures = $a.Failures
        lockouts = $a.Lockouts
        ntlm     = $a.NTLMCount
        first    = $a.FirstSeen
        last     = $a.LastSeen
        uips     = $a.UniqueIPs
        sources  = @($a.TopSources | ForEach-Object { [PSCustomObject]@{ v = $_.Name; c = $_.Count } })
        purposes = @($a.TopPurpose | ForEach-Object { [PSCustomObject]@{ v = $_.Name; c = $_.Count } })
        types    = @($a.ByType     | ForEach-Object { [PSCustomObject]@{ v = $_.Name; c = $_.Count } })
        lts      = @($a.ByLT       | ForEach-Object { [PSCustomObject]@{ v = $_.Name; c = $_.Count } })
        services = @($a.Services)
    }
})
$D_ACCTS = if ($acctsForJson.Count -eq 0) { '[]' }
           elseif ($acctsForJson.Count -eq 1) { '[' + ($acctsForJson | ConvertTo-Json -Compress -Depth 4) + ']' }
           else { $acctsForJson | ConvertTo-Json -Compress -Depth 4 }

# ── Errors ────────────────────────────────────────────────────────────────────
$D_ERRORS = if ($CollectErrors.Count -eq 0) { '[]' }
            elseif ($CollectErrors.Count -eq 1) { '[' + ($CollectErrors[0] | ConvertTo-Json -Compress) + ']' }
            else { $CollectErrors | ConvertTo-Json -Compress }

# ── Chart arrays ──────────────────────────────────────────────────────────────
$D_DAY_L  = if ($ByDay.Count  -gt 0) { '"' + (($ByDay  | Select-Object -ExpandProperty Name) -join '","') + '"' } else { '' }
$D_DAY_S  = ($ByDay  | ForEach-Object { @($_.Group | Where-Object {  $_.IsSuccess }).Count }) -join ','
$D_DAY_F  = ($ByDay  | ForEach-Object { @($_.Group | Where-Object { -not $_.IsSuccess }).Count }) -join ','

$D_TYPE_L = if ($ByType.Count  -gt 0) { '"' + (($ByType  | Select-Object -ExpandProperty Name | ForEach-Object { $_ -replace '"','' }) -join '","') + '"' } else { '' }
$D_TYPE_C = ($ByType  | Select-Object -ExpandProperty Count) -join ','

$D_ACCT_L = if ($Top15Accts.Count -gt 0) { '"' + (($Top15Accts | Select-Object -ExpandProperty Name | ForEach-Object { $_ -replace '"','' }) -join '","') + '"' } else { '' }
$D_ACCT_T = ($Top15Accts | Select-Object -ExpandProperty Count) -join ','
$D_ACCT_F = ($Top15Accts | ForEach-Object { @($_.Group | Where-Object { -not $_.IsSuccess }).Count }) -join ','
$D_ACCT_S = ($Top15Accts | ForEach-Object {
    $tot = $_.Count
    $f   = @($_.Group | Where-Object { -not $_.IsSuccess }).Count
    $tot - $f
}) -join ','

$D_SRC_L  = if ($BySrcIP.Count  -gt 0) { '"' + (($BySrcIP  | Select-Object -ExpandProperty Name | ForEach-Object { $_ -replace '"','' }) -join '","') + '"' } else { '' }
$D_SRC_C  = ($BySrcIP  | Select-Object -ExpandProperty Count) -join ','

$D_AUTH_L = if ($ByAuth.Count   -gt 0) { '"' + (($ByAuth   | Select-Object -ExpandProperty Name | ForEach-Object { $_ -replace '"','' }) -join '","') + '"' } else { '' }
$D_AUTH_C = ($ByAuth   | Select-Object -ExpandProperty Count) -join ','

$D_LT_L   = if ($ByLT.Count    -gt 0) { '"' + (($ByLT     | Select-Object -ExpandProperty Name | ForEach-Object { $_ -replace '"','' }) -join '","') + '"' } else { '' }
$D_LT_C   = ($ByLT     | Select-Object -ExpandProperty Count) -join ','

$D_HOUR_C = $HourCounts -join ','

# ─────────────────────────────────────────────────────────────────────────────
# HTML TEMPLATE
# ─────────────────────────────────────────────────────────────────────────────

$htmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD Service Account Usage Report</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--txt:#e6edf3;--muted:#8b949e;
      --blue:#58a6ff;--green:#3fb950;--red:#f85149;--orange:#d29922;--purple:#bc8cff;--cyan:#39d5ff}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0}
.topbar{background:var(--card);border-bottom:1px solid var(--border);padding:.6rem 1.2rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem}
.topbar-brand{color:var(--blue);font-weight:700;font-size:1.05rem;display:flex;align-items:center;gap:.5rem}
.topbar-meta{font-size:.75rem;color:var(--muted);display:flex;gap:1rem;flex-wrap:wrap}
.tabs{display:flex;border-bottom:1px solid var(--border);padding:0 1rem;background:var(--card)}
.tab-btn{background:none;border:none;color:var(--muted);padding:.6rem 1.1rem;cursor:pointer;border-bottom:2px solid transparent;font-size:.85rem;transition:color .15s}
.tab-btn:hover{color:var(--txt)}
.tab-btn.active{color:var(--blue);border-bottom-color:var(--blue)}
.content{padding:1rem 1.2rem}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:.75rem;margin-bottom:1.2rem}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem 1.1rem;display:flex;justify-content:space-between;align-items:flex-start;transition:border-color .2s}
.kpi:hover{border-color:var(--blue)}
.kpi-val{font-size:1.9rem;font-weight:700;line-height:1}
.kpi-lbl{font-size:.7rem;color:var(--muted);margin-top:.25rem;text-transform:uppercase;letter-spacing:.04em}
.kpi-ico{font-size:1.4rem;opacity:.65}
.cc{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem 1.1rem;margin-bottom:.8rem}
.cc h6{font-size:.7rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-bottom:.7rem}
.chart-row{display:grid;gap:.8rem;margin-bottom:.8rem}
.chart-row.r2{grid-template-columns:2fr 1fr}
.chart-row.r3{grid-template-columns:1fr 1fr 1fr}
.chart-row.r2b{grid-template-columns:1fr 1fr}
@media(max-width:900px){.chart-row.r2,.chart-row.r3,.chart-row.r2b{grid-template-columns:1fr}}
.fbar{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin-bottom:.8rem}
.fbar input,.fbar select{background:#21262d;border:1px solid var(--border);color:var(--txt);border-radius:6px;padding:.3rem .65rem;font-size:.8rem}
.fbar input:focus,.fbar select:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 2px rgba(88,166,255,.18)}
.fbar select option{background:#21262d}
.btn-clr{background:none;border:1px solid var(--border);color:var(--muted);border-radius:6px;padding:.3rem .7rem;cursor:pointer;font-size:.77rem}
.btn-clr:hover{border-color:var(--red);color:var(--red)}
.pg-info{font-size:.77rem;color:var(--muted)}
.tbl-wrap{background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:.78rem}
thead th{background:#1c2128;color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;padding:.5rem .65rem;cursor:pointer;user-select:none;white-space:nowrap;border-bottom:1px solid var(--border)}
thead th:hover{color:var(--txt)}
tbody td{padding:.4rem .65rem;border-bottom:1px solid #1c2128;vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:#1c2128}
th.sa::after{content:' ▲';font-size:.6rem}
th.sd::after{content:' ▼';font-size:.6rem}
.bd{display:inline-block;padding:.1rem .4rem;border-radius:3px;font-size:.72rem;white-space:nowrap}
.bd-ok{background:rgba(63,185,80,.12);color:var(--green);border:1px solid rgba(63,185,80,.25)}
.bd-fail{background:rgba(248,81,73,.12);color:var(--red);border:1px solid rgba(248,81,73,.25)}
.bd-eid{background:rgba(88,166,255,.1);color:var(--blue);border:1px solid rgba(88,166,255,.2);font-family:monospace}
.bd-kerb{background:rgba(57,213,255,.1);color:var(--cyan);border:1px solid rgba(57,213,255,.2)}
.bd-ntlm{background:rgba(210,153,34,.12);color:var(--orange);border:1px solid rgba(210,153,34,.25)}
.bd-na{background:rgba(139,148,158,.08);color:var(--muted);border:1px solid rgba(139,148,158,.15)}
.pgbar{display:flex;align-items:center;gap:.4rem;margin-top:.5rem;flex-wrap:wrap}
.pgbtn{background:#21262d;border:1px solid var(--border);color:var(--muted);border-radius:4px;padding:.22rem .55rem;cursor:pointer;font-size:.78rem}
.pgbtn:hover,.pgbtn.act{background:var(--blue);color:#fff;border-color:var(--blue)}
.pgbtn:disabled{opacity:.4;cursor:not-allowed}
.ac{background:var(--card);border:1px solid var(--border);border-radius:8px;margin-bottom:.6rem;overflow:hidden}
.ac-hd{padding:.75rem 1rem;cursor:pointer;display:flex;align-items:center;gap:.7rem;transition:background .12s}
.ac-hd:hover{background:#1c2128}
.ac-name{font-weight:600;font-size:.88rem;color:var(--blue);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ac-tags{display:flex;gap:.35rem;flex-wrap:wrap}
.ac-tag{font-size:.68rem;padding:.12rem .45rem;border-radius:3px}
.ac-bd{padding:.85rem 1rem;border-top:1px solid var(--border);display:none}
.ac-bd.open{display:block}
.ac-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:1rem}
.sec-lbl{font-size:.67rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin:.6rem 0 .3rem}
.dtbl{width:100%;font-size:.77rem}
.dtbl td:first-child{color:var(--muted);padding:.18rem .4rem .18rem 0;width:45%}
.dtbl td:last-child{padding:.18rem 0}
.mbar{display:flex;align-items:center;gap:.4rem;margin:.12rem 0}
.mbar-lbl{font-size:.7rem;color:var(--muted);min-width:120px;max-width:190px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mbar-trk{flex:1;height:4px;background:#21262d;border-radius:2px;overflow:hidden}
.mbar-fil{height:100%;border-radius:2px;transition:width .3s}
.mbar-fil.b{background:var(--blue)}.mbar-fil.g{background:var(--green)}.mbar-fil.o{background:var(--orange)}.mbar-fil.r{background:var(--red)}
.mbar-cnt{font-size:.7rem;color:var(--muted);min-width:26px;text-align:right}
.alert-box{background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.22);border-radius:5px;padding:.4rem .75rem;margin-bottom:.4rem;font-size:.77rem;color:var(--red)}
.warn-box{background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.22);border-radius:5px;padding:.4rem .75rem;margin-bottom:.4rem;font-size:.77rem;color:var(--orange)}
.svc-chip{display:inline-block;background:rgba(88,166,255,.1);color:var(--blue);border:1px solid rgba(88,166,255,.2);border-radius:3px;font-size:.68rem;padding:.1rem .4rem;margin:.1rem .1rem}
.acct-btn{background:none;border:1px solid var(--border);color:var(--muted);border-radius:5px;padding:.25rem .65rem;cursor:pointer;font-size:.75rem;margin-top:.5rem}
.acct-btn:hover{border-color:var(--blue);color:var(--blue)}
.err-banner{background:rgba(248,81,73,.09);border:1px solid rgba(248,81,73,.28);border-radius:6px;padding:.5rem .9rem;margin-bottom:.8rem;font-size:.78rem;color:var(--red);display:none}
#acctQ{background:#21262d;border:1px solid var(--border);color:var(--txt);border-radius:6px;padding:.3rem .65rem;font-size:.82rem;width:260px}
#acctQ:focus{outline:none;border-color:var(--blue)}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:#30363d;border-radius:3px}
</style>
</head>
<body>
<div class="topbar">
  <div class="topbar-brand"><i class="bi bi-shield-lock-fill"></i> AD Service Account Analyzer</div>
  <div class="topbar-meta">
    <span><i class="bi bi-hdd-network me-1"></i>%%DOMAIN%%</span>
    <span><i class="bi bi-calendar3 me-1"></i>%%TIMESPAN%%</span>
    <span><i class="bi bi-server me-1"></i>%%DCLIST%%</span>
    <span><i class="bi bi-clock me-1"></i>Generated %%GENERATED%%</span>
  </div>
</div>
<div class="tabs">
  <button class="tab-btn active" onclick="showTab('dashboard',this)"><i class="bi bi-speedometer2 me-1"></i>Dashboard</button>
  <button class="tab-btn"        onclick="showTab('events',this)"><i class="bi bi-table me-1"></i>Event Log</button>
  <button class="tab-btn"        onclick="showTab('accounts',this)"><i class="bi bi-person-lines-fill me-1"></i>Account Analysis</button>
</div>
<div class="content">
<div id="errBanner" class="err-banner"></div>
<div id="tab-dashboard">
  <div class="kpi-grid">
    <div class="kpi"><div><div class="kpi-val" style="color:var(--blue)">%%KPI_TOTAL%%</div><div class="kpi-lbl">Total Events</div></div><i class="bi bi-activity kpi-ico" style="color:var(--blue)"></i></div>
    <div class="kpi"><div><div class="kpi-val" style="color:var(--purple)">%%KPI_ACCTS%%</div><div class="kpi-lbl">Unique Accounts</div></div><i class="bi bi-people kpi-ico" style="color:var(--purple)"></i></div>
    <div class="kpi"><div><div class="kpi-val" style="color:var(--red)">%%KPI_FAILS%%</div><div class="kpi-lbl">Auth Failures</div></div><i class="bi bi-x-circle kpi-ico" style="color:var(--red)"></i></div>
    <div class="kpi"><div><div class="kpi-val" style="color:var(--orange)">%%KPI_LOCKS%%</div><div class="kpi-lbl">Lockouts</div></div><i class="bi bi-lock kpi-ico" style="color:var(--orange)"></i></div>
    <div class="kpi"><div><div class="kpi-val" style="color:var(--orange)">%%KPI_NTLM%%</div><div class="kpi-lbl">NTLM Auths</div></div><i class="bi bi-exclamation-triangle kpi-ico" style="color:var(--orange)"></i></div>
    <div class="kpi"><div><div class="kpi-val" style="color:var(--cyan)">%%KPI_IPS%%</div><div class="kpi-lbl">Source IPs</div></div><i class="bi bi-globe kpi-ico" style="color:var(--cyan)"></i></div>
  </div>
  <div class="chart-row r2">
    <div class="cc"><h6><i class="bi bi-graph-up me-1"></i>Authentication Events Over Time</h6><canvas id="cTimeline" height="85"></canvas></div>
    <div class="cc"><h6><i class="bi bi-pie-chart me-1"></i>Events by Type</h6><canvas id="cByType" height="160"></canvas></div>
  </div>
  <div class="chart-row r2b">
    <div class="cc"><h6><i class="bi bi-bar-chart-horizontal me-1"></i>Top Accounts by Activity</h6><canvas id="cTopAccts" height="170"></canvas></div>
    <div class="cc"><h6><i class="bi bi-geo-alt me-1"></i>Top Source IPs / Hosts</h6><canvas id="cSrcIPs" height="170"></canvas></div>
  </div>
  <div class="chart-row r3">
    <div class="cc"><h6><i class="bi bi-shield-check me-1"></i>Authentication Method</h6><canvas id="cAuth" height="155"></canvas></div>
    <div class="cc"><h6><i class="bi bi-door-open me-1"></i>Logon Types (EID 4624)</h6><canvas id="cLT" height="155"></canvas></div>
    <div class="cc"><h6><i class="bi bi-clock-history me-1"></i>Activity by Hour of Day</h6><canvas id="cHour" height="155"></canvas></div>
  </div>
</div>
<div id="tab-events" style="display:none">
  <div class="fbar">
    <input id="fQ" type="text" placeholder="Search account, IP, purpose, service..." style="width:270px" oninput="applyF()">
    <select id="fA" onchange="applyF()"><option value="">All Accounts</option></select>
    <select id="fT" onchange="applyF()"><option value="">All Event Types</option></select>
    <select id="fS" onchange="applyF()"><option value="">All Statuses</option><option>Success</option><option>Failure</option></select>
    <select id="fM" onchange="applyF()"><option value="">All Auth Methods</option><option>Kerberos</option><option>NTLM</option></select>
    <select id="fL" onchange="applyF()"><option value="">All Logon Types</option></select>
    <button class="btn-clr" onclick="clearF()">Clear Filters</button>
    <span class="pg-info ms-auto" id="fSummary"></span>
  </div>
  <div class="tbl-wrap">
    <table id="evtTbl">
      <thead><tr>
        <th onclick="srt(0)">Time</th><th onclick="srt(1)">EID</th><th onclick="srt(2)">Account</th>
        <th onclick="srt(3)">Domain</th><th onclick="srt(4)">Source IP / Host</th>
        <th onclick="srt(5)">Purpose</th><th onclick="srt(6)">Auth</th><th onclick="srt(7)">Logon Type</th>
        <th onclick="srt(8)">Status</th><th onclick="srt(9)">Status Detail</th>
        <th onclick="srt(10)">Service</th><th onclick="srt(11)">Workstation</th><th onclick="srt(12)">Source</th>
      </tr></thead>
      <tbody id="evtBody"></tbody>
    </table>
  </div>
  <div class="pgbar">
    <button class="pgbtn" id="bPrev" onclick="pg(-1)">Prev</button>
    <span class="pg-info" id="pgInfo"></span>
    <button class="pgbtn" id="bNext" onclick="pg(1)">Next</button>
    <select class="pgbtn" id="pgSz" onchange="setPgSz(+this.value)" style="padding:.22rem .5rem">
      <option value="50">50/page</option><option value="100">100/page</option>
      <option value="250">250/page</option><option value="500">500/page</option>
    </select>
  </div>
</div>
<div id="tab-accounts" style="display:none">
  <div style="display:flex;align-items:center;gap:1rem;margin-bottom:.8rem">
    <input id="acctQ" type="text" placeholder="Filter accounts..." oninput="filterAccts()">
    <span class="pg-info" id="acctCnt"></span>
  </div>
  <div id="acctContainer"></div>
</div>
</div>
<script>
const EVENTS = %%EVENTS%%;
const ACCTS  = %%ACCTS%%;
const ERRS   = %%ERRORS%%;
document.addEventListener('DOMContentLoaded', () => {
  if (ERRS.length) {
    const b = document.getElementById('errBanner');
    b.style.display = 'block';
    b.innerHTML = '<i class="bi bi-exclamation-triangle-fill me-2"></i><strong>Collection warnings:</strong> ' + ERRS.join(' | ');
  }
      try { initCharts(); } catch(e) {
      console.warn('Chart.js unavailable:', e);
      document.querySelectorAll('canvas').forEach(c => {
        c.closest('.cc').innerHTML = '<div style="color:var(--muted);font-size:.78rem;padding:2rem;text-align:center">Charts unavailable (CDN blocked)</div>';
      });
    }
    initFilters();
    renderTable();
    renderAccounts();
});
function showTab(name, btn) {
  document.querySelectorAll('[id^="tab-"]').forEach(t => t.style.display = 'none');
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).style.display = '';
  btn.classList.add('active');
}
const PAL=['#58a6ff','#3fb950','#f85149','#d29922','#bc8cff','#39d5ff','#ffa657','#ff7b72','#79c0ff','#56d364'];
const GRID='rgba(48,54,61,.7)',TC='#8b949e';
Chart.defaults.color=TC;
function initCharts() {
  new Chart(document.getElementById('cTimeline'),{type:'bar',data:{labels:[%%D_DAY_L%%],datasets:[{label:'Success',data:[%%D_DAY_S%%],backgroundColor:'rgba(63,185,80,.7)',borderRadius:2,stack:'s'},{label:'Failure',data:[%%D_DAY_F%%],backgroundColor:'rgba(248,81,73,.7)',borderRadius:2,stack:'s'}]},options:{responsive:true,scales:{x:{stacked:true,grid:{color:GRID},ticks:{color:TC,maxTicksLimit:14}},y:{stacked:true,grid:{color:GRID},ticks:{color:TC}}},plugins:{legend:{labels:{color:TC,font:{size:11}}}}}});
  new Chart(document.getElementById('cByType'),{type:'doughnut',data:{labels:[%%D_TYPE_L%%],datasets:[{data:[%%D_TYPE_C%%],backgroundColor:PAL,borderColor:'#0d1117',borderWidth:2}]},options:{responsive:true,plugins:{legend:{position:'bottom',labels:{color:TC,font:{size:10},boxWidth:10,padding:5}}}}});
  new Chart(document.getElementById('cTopAccts'),{type:'bar',data:{labels:[%%D_ACCT_L%%],datasets:[{label:'Success',data:[%%D_ACCT_S%%],backgroundColor:'rgba(63,185,80,.7)',borderRadius:2,stack:'s'},{label:'Failure',data:[%%D_ACCT_F%%],backgroundColor:'rgba(248,81,73,.7)',borderRadius:2,stack:'s'}]},options:{indexAxis:'y',responsive:true,scales:{x:{stacked:true,grid:{color:GRID},ticks:{color:TC}},y:{stacked:true,grid:{display:false},ticks:{color:TC,font:{size:10}}}},plugins:{legend:{labels:{color:TC,font:{size:11}}}}}});
  new Chart(document.getElementById('cSrcIPs'),{type:'bar',data:{labels:[%%D_SRC_L%%],datasets:[{label:'Events',data:[%%D_SRC_C%%],backgroundColor:'rgba(88,166,255,.7)',borderRadius:2}]},options:{indexAxis:'y',responsive:true,scales:{x:{grid:{color:GRID},ticks:{color:TC}},y:{grid:{display:false},ticks:{color:TC,font:{size:10}}}},plugins:{legend:{display:false}}}});
  new Chart(document.getElementById('cAuth'),{type:'doughnut',data:{labels:[%%D_AUTH_L%%],datasets:[{data:[%%D_AUTH_C%%],backgroundColor:['rgba(57,213,255,.8)','rgba(210,153,34,.8)','rgba(188,140,255,.8)','rgba(139,148,158,.5)'],borderColor:'#0d1117',borderWidth:2}]},options:{responsive:true,plugins:{legend:{position:'bottom',labels:{color:TC,font:{size:10},boxWidth:10,padding:5}}}}});
  new Chart(document.getElementById('cLT'),{type:'bar',data:{labels:[%%D_LT_L%%],datasets:[{label:'Count',data:[%%D_LT_C%%],backgroundColor:PAL.map(c=>c+'bb'),borderRadius:2}]},options:{responsive:true,scales:{x:{grid:{color:GRID},ticks:{color:TC,font:{size:9},maxRotation:30}},y:{grid:{color:GRID},ticks:{color:TC}}},plugins:{legend:{display:false}}}});
  new Chart(document.getElementById('cHour'),{type:'bar',data:{labels:Array.from({length:24},(_,i)=>i.toString().padStart(2,'0')+':00'),datasets:[{label:'Events',data:[%%D_HOUR_C%%],backgroundColor:'rgba(88,166,255,.55)',borderRadius:2}]},options:{responsive:true,scales:{x:{grid:{color:GRID},ticks:{color:TC,font:{size:9}}},y:{grid:{color:GRID},ticks:{color:TC}}},plugins:{legend:{display:false}}}});
}
let fEvts=[...EVENTS],curPage=1,pgSz=50,colDirs={};
function initFilters(){
  const fa=document.getElementById('fA'),ft=document.getElementById('fT'),fl=document.getElementById('fL');
  [...new Set(EVENTS.map(e=>e.a))].sort().forEach(v=>fa.add(new Option(v,v)));
  [...new Set(EVENTS.map(e=>e.et))].sort().forEach(v=>ft.add(new Option(v,v)));
  [...new Set(EVENTS.filter(e=>e.lt).map(e=>e.lt))].sort().forEach(v=>fl.add(new Option(v,v)));
}
function applyF(){
  const q=document.getElementById('fQ').value.toLowerCase(),fa=document.getElementById('fA').value,
        ft=document.getElementById('fT').value,fs=document.getElementById('fS').value,
        fm=document.getElementById('fM').value,fl=document.getElementById('fL').value;
  fEvts=EVENTS.filter(e=>{
    if(fa&&e.a!==fa)return false;if(ft&&e.et!==ft)return false;
    if(fs&&e.st!==fs)return false;if(fm&&e.am!==fm)return false;if(fl&&e.lt!==fl)return false;
    if(q&&![(e.a||''),(e.ip||''),(e.pu||''),(e.svc||''),(e.ws||''),(e.sm||''),(e.dc||'')].some(v=>v.toLowerCase().includes(q)))return false;
    return true;
  });
  curPage=1;renderTable();
}
function clearF(){['fQ','fA','fT','fS','fM','fL'].forEach(id=>{document.getElementById(id).value='';});applyF();}
function xe(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function authBadge(am){
  if(am==='Kerberos')return`<span class="bd bd-kerb">${xe(am)}</span>`;
  if(am==='NTLM')return`<span class="bd bd-ntlm">${xe(am)}</span>`;
  return`<span class="bd bd-na">${xe(am||'N/A')}</span>`;
}
function renderTable(){
  const s=(curPage-1)*pgSz,e=s+pgSz,pg=fEvts.slice(s,e),tot=fEvts.length;
  document.getElementById('fSummary').textContent=`Showing ${(s+1).toLocaleString()}-${Math.min(e,tot).toLocaleString()} of ${tot.toLocaleString()} events`;
  document.getElementById('pgInfo').textContent=`Page ${curPage} of ${Math.max(1,Math.ceil(tot/pgSz))}`;
  document.getElementById('bPrev').disabled=curPage<=1;
  document.getElementById('bNext').disabled=e>=tot;
  document.getElementById('evtBody').innerHTML=pg.map(e=>`<tr>
    <td style="white-space:nowrap;font-family:monospace;font-size:.73rem">${xe(e.t)}</td>
    <td><span class="bd bd-eid">${e.eid}</span></td>
    <td><strong style="color:var(--blue)">${xe(e.a)}</strong></td>
    <td style="color:var(--muted);font-size:.75rem">${xe(e.d)}</td>
    <td style="font-family:monospace;font-size:.73rem">${xe(e.ip)}</td>
    <td>${xe(e.pu)}</td><td>${authBadge(e.am)}</td>
    <td style="font-size:.74rem">${xe(e.lt)}</td>
    <td>${e.ok?'<span class="bd bd-ok">Success</span>':'<span class="bd bd-fail">Failure</span>'}</td>
    <td style="font-size:.73rem;color:var(--muted)">${xe(e.sm)}</td>
    <td style="font-size:.73rem;color:var(--muted)">${xe(e.svc)}</td>
    <td style="font-size:.73rem;color:var(--muted)">${xe(e.ws)}</td>
    <td style="font-size:.73rem;color:var(--muted)">${xe(e.dc)}</td>
  </tr>`).join('');
}
function pg(d){const max=Math.ceil(fEvts.length/pgSz);curPage=Math.max(1,Math.min(max,curPage+d));renderTable();}
function setPgSz(n){pgSz=n;curPage=1;renderTable();}
const COLS=['t','eid','a','d','ip','pu','am','lt','st','sm','svc','ws','dc'];
function srt(i){
  const k=COLS[i],d=(colDirs[i]===1)?-1:1;
  Object.keys(colDirs).forEach(k=>delete colDirs[k]);colDirs[i]=d;
  fEvts.sort((a,b)=>d*String(a[k]||'').localeCompare(String(b[k]||'')));
  document.querySelectorAll('#evtTbl thead th').forEach((th,j)=>{th.className=j===i?(d===1?'sa':'sd'):'';});
  curPage=1;renderTable();
}
function mBar(label,count,total,cls='b'){
  const pct=total>0?Math.min(100,Math.round(count/total*100)):0;
  return`<div class="mbar"><span class="mbar-lbl" title="${xe(label)}">${xe(label)}</span><div class="mbar-trk"><div class="mbar-fil ${cls}" style="width:${pct}%"></div></div><span class="mbar-cnt">${count}</span></div>`;
}
function renderAccounts(){
  const c=document.getElementById('acctContainer');
  document.getElementById('acctCnt').textContent=`${ACCTS.length} accounts`;
  c.innerHTML=ACCTS.map((a,i)=>{
    const fpct=a.total>0?Math.round(a.failures/a.total*100):0;
    const risk=a.lockouts>0?'var(--red)':(a.failures>10&&fpct>20)?'var(--orange)':'var(--blue)';
    let alerts='';
    if(a.lockouts>0)alerts+=`<div class="alert-box"><i class="bi bi-lock-fill me-1"></i><strong>Account Locked Out</strong> - ${a.lockouts} lockout event(s).</div>`;
    if(a.failures>10&&fpct>20)alerts+=`<div class="alert-box"><i class="bi bi-exclamation-triangle-fill me-1"></i><strong>High Failure Rate</strong> - ${a.failures} failures (${fpct}%).</div>`;
    if(a.ntlm>0)alerts+=`<div class="warn-box"><i class="bi bi-shield-exclamation me-1"></i><strong>NTLM Usage</strong> - ${a.ntlm} NTLM authentication(s).</div>`;
    return`<div class="ac" id="ac${i}">
      <div class="ac-hd" onclick="togAc(${i})">
        <i class="bi bi-person-circle" style="color:${risk};font-size:1.05rem"></i>
        <span class="ac-name">${xe(a.name)}</span>
        <div class="ac-tags">
          <span class="ac-tag" style="background:rgba(88,166,255,.12);color:var(--blue)">${a.total.toLocaleString()} events</span>
          ${a.failures>0?`<span class="ac-tag" style="background:rgba(248,81,73,.12);color:var(--red)">${a.failures} failures</span>`:''}
          ${a.lockouts>0?`<span class="ac-tag" style="background:rgba(210,153,34,.15);color:var(--orange)">${a.lockouts} lockout(s)</span>`:''}
          ${a.ntlm>0?`<span class="ac-tag" style="background:rgba(210,153,34,.1);color:var(--orange)">NTLM:${a.ntlm}</span>`:''}
          <span class="ac-tag" style="background:rgba(139,148,158,.1);color:var(--muted)">${a.uips} IP(s)</span>
        </div>
        <i class="bi bi-chevron-down" id="chev${i}" style="color:var(--muted);flex-shrink:0"></i>
      </div>
      <div class="ac-bd" id="acbd${i}">
        ${alerts}
        <div class="ac-grid">
          <div>
            <div class="sec-lbl">Summary</div>
            <table class="dtbl">
              <tr><td>First Seen</td><td style="font-family:monospace;font-size:.73rem">${xe(a.first)}</td></tr>
              <tr><td>Last Seen</td><td style="font-family:monospace;font-size:.73rem">${xe(a.last)}</td></tr>
              <tr><td>Total Events</td><td>${a.total.toLocaleString()}</td></tr>
              <tr><td>Failures</td><td style="color:${a.failures>0?'var(--red)':'var(--green)'}">${a.failures} (${fpct}%)</td></tr>
              <tr><td>Lockouts</td><td style="color:${a.lockouts>0?'var(--orange)':'inherit'}">${a.lockouts}</td></tr>
              <tr><td>NTLM Auths</td><td style="color:${a.ntlm>0?'var(--orange)':'inherit'}">${a.ntlm}</td></tr>
              <tr><td>Unique Source IPs</td><td>${a.uips}</td></tr>
            </table>
            <div class="sec-lbl">Kerberos Services</div>
            <div>${a.services.length?a.services.map(s=>`<span class="svc-chip">${xe(s)}</span>`).join(''):'<span style="font-size:.74rem;color:var(--muted)">None</span>'}</div>
          </div>
          <div>
            <div class="sec-lbl">Top Source IPs</div>${a.sources.length?a.sources.map(x=>mBar(x.v,x.c,a.total,'b')).join(''):'<span style="font-size:.74rem;color:var(--muted)">None</span>'}
            <div class="sec-lbl">Logon Types</div>${a.lts.length?a.lts.map(x=>mBar(x.v,x.c,a.total,'b')).join(''):'<span style="font-size:.74rem;color:var(--muted)">N/A</span>'}
          </div>
          <div><div class="sec-lbl">Usage Purposes</div>${a.purposes.map(x=>mBar(x.v,x.c,a.total,'g')).join('')}</div>
          <div><div class="sec-lbl">Event Types</div>${a.types.map(x=>mBar(x.v,x.c,a.total,'o')).join('')}</div>
        </div>
        <button class="acct-btn" onclick="jumpToEvts('${xe(a.name).replace(/'/g,"\\'")}')">Show in Event Log</button>
      </div>
    </div>`;
  }).join('');
}
function togAc(i){
  const bd=document.getElementById('acbd'+i),ch=document.getElementById('chev'+i);
  const o=bd.classList.toggle('open');
  ch.className=`bi ${o?'bi-chevron-up':'bi-chevron-down'}`;ch.style.color='var(--muted)';
}
function filterAccts(){
  const q=document.getElementById('acctQ').value.toLowerCase();let n=0;
  ACCTS.forEach((_,i)=>{const el=document.getElementById('ac'+i);const m=ACCTS[i].name.toLowerCase().includes(q);el.style.display=m?'':'none';if(m)n++;});
  document.getElementById('acctCnt').textContent=`${n} of ${ACCTS.length} accounts`;
}
function jumpToEvts(name){
  document.getElementById('fA').value=name;applyF();
  document.querySelectorAll('.tab-btn')[1].click();
}
</script>
</body>
</html>
'@

# ─────────────────────────────────────────────────────────────────────────────
# TOKEN REPLACEMENT
# ─────────────────────────────────────────────────────────────────────────────

Write-Host '  Building HTML...' -ForegroundColor DarkGray

$html = $htmlTemplate
$html = $html.Replace('%%DOMAIN%%',    $DomainName)
$html = $html.Replace('%%TIMESPAN%%',  $Timespan)
$html = $html.Replace('%%DCLIST%%',    ($Sources | Select-Object -ExpandProperty Label) -join ', ')
$html = $html.Replace('%%GENERATED%%', $GeneratedAt)
$html = $html.Replace('%%KPI_TOTAL%%', $TotalEvents.ToString('N0'))
$html = $html.Replace('%%KPI_ACCTS%%', $UniqueAccounts.Count.ToString())
$html = $html.Replace('%%KPI_FAILS%%', $TotalFailures.ToString('N0'))
$html = $html.Replace('%%KPI_LOCKS%%', $TotalLockouts.ToString())
$html = $html.Replace('%%KPI_NTLM%%',  $NTLMCount.ToString('N0'))
$html = $html.Replace('%%KPI_IPS%%',   $UniqueSourceIPs.ToString())
$html = $html.Replace('%%D_DAY_L%%',   $D_DAY_L)
$html = $html.Replace('%%D_DAY_S%%',   $D_DAY_S)
$html = $html.Replace('%%D_DAY_F%%',   $D_DAY_F)
$html = $html.Replace('%%D_TYPE_L%%',  $D_TYPE_L)
$html = $html.Replace('%%D_TYPE_C%%',  $D_TYPE_C)
$html = $html.Replace('%%D_ACCT_L%%',  $D_ACCT_L)
$html = $html.Replace('%%D_ACCT_T%%',  $D_ACCT_T)
$html = $html.Replace('%%D_ACCT_S%%',  $D_ACCT_S)
$html = $html.Replace('%%D_ACCT_F%%',  $D_ACCT_F)
$html = $html.Replace('%%D_SRC_L%%',   $D_SRC_L)
$html = $html.Replace('%%D_SRC_C%%',   $D_SRC_C)
$html = $html.Replace('%%D_AUTH_L%%',  $D_AUTH_L)
$html = $html.Replace('%%D_AUTH_C%%',  $D_AUTH_C)
$html = $html.Replace('%%D_LT_L%%',    $D_LT_L)
$html = $html.Replace('%%D_LT_C%%',    $D_LT_C)
$html = $html.Replace('%%D_HOUR_C%%',  $D_HOUR_C)
$html = $html.Replace('%%EVENTS%%',    $D_EVENTS)
$html = $html.Replace('%%ACCTS%%',     $D_ACCTS)
$html = $html.Replace('%%ERRORS%%',    $D_ERRORS)

# ─────────────────────────────────────────────────────────────────────────────
# WRITE OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

$html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
$sz = [math]::Round((Get-Item $OutputPath).Length / 1KB, 1)

Write-Host ''
Write-Host "  Report  : $OutputPath  ($sz KB)" -ForegroundColor Green
Write-Host "  Accounts: $($UniqueAccounts.Count)"
Write-Host "  Events  : $TotalEvents"
Write-Host "  Failures: $TotalFailures"
Write-Host "  Lockouts: $TotalLockouts"
Write-Host "  NTLM    : $NTLMCount"
if ($CollectErrors.Count -gt 0) {
    Write-Host "  Warnings: $($CollectErrors.Count) collection error(s)" -ForegroundColor Yellow
}
Write-Host ''

$isLegacyPS = $PSVersionTable.PSVersion.Major -le 5
if ($isLegacyPS -or $IsWindows) {
    $ans = Read-Host '  Open report in browser? [Y/n]'
    if ($ans -notmatch '^[Nn]') { Start-Process $OutputPath }
}

