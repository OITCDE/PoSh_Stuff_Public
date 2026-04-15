#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    NTLM Usage Analysis & Interactive HTML Report Generator for Active Directory.

.DESCRIPTION
    Collects NTLM-related events from Domain Controllers, reads live NTLM/GPO
    configuration from DC registries, and generates a comprehensive, interactive
    HTML dashboard to identify and eliminate NTLM/NTLMv1 usage.

    Based on: Microsoft AD Hardening Series – Part 8 – Disabling NTLM
    https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/
    active-directory-hardening-series---part-8-disabling-ntlm/4485782

.PARAMETER DomainControllers
    Specific DC hostnames to query. Defaults to all DCs in the domain.

.PARAMETER HoursBack
    How many hours of event log history to collect. Default: 24

.PARAMETER MaxEventsPerLog
    Maximum events collected per log source per DC. Default: 5000

.PARAMETER OutputPath
    Full path for the HTML report file. Default: .\NTLM-Report-<timestamp>.html

.PARAMETER IncludeBlockingEvents
    Also collect blocking events (4001-4006) from the NTLM Operational log.

.PARAMETER Credential
    PSCredential for remote DC connections (optional).

.EXAMPLE
    .\Get-NTLMReport.ps1 -HoursBack 48 -IncludeBlockingEvents
    .\Get-NTLMReport.ps1 -DomainControllers DC01,DC02 -OutputPath C:\Reports\NTLM.html
#>

[CmdletBinding()]
param(
    [string[]]$DomainControllers,
    [int]$HoursBack          = 24,
    [int]$MaxEventsPerLog    = 5000,
    [string]$OutputPath,
    [switch]$IncludeBlockingEvents,
    [System.Management.Automation.PSCredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Web

#region ── Helpers ────────────────────────────────────────────────────────────

function Write-Status {
    param([string]$Message, [string]$Type = 'INFO')
    $color = switch ($Type) {
        'SUCCESS' { 'Green'  }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red'    }
        default   { 'Cyan'   }
    }
    Write-Host "[$Type] $(Get-Date -Format 'HH:mm:ss') – $Message" -ForegroundColor $color
}

function Escape-Html ([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return '' }
    [System.Web.HttpUtility]::HtmlEncode($s)
}

function Get-Prop {
    param([object]$Obj, [string]$Name, [string]$Default = '')
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { if ($null -ne $p.Value) { [string]$p.Value } else { $Default } } else { $Default }
}

function Get-RegValueSafe {
    param([string]$ComputerName, [string]$Path, [string]$Name)
    try {
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
        $key = $reg.OpenSubKey($Path)
        if ($key) { $key.GetValue($Name) } else { $null }
    } catch { $null }
}

#endregion

#region ── Timestamps & Output ────────────────────────────────────────────────

$reportTime      = Get-Date
$tsStr           = $reportTime.ToString('yyyyMMdd-HHmmss')
$startTime       = $reportTime.AddHours(-$HoursBack)

if (-not $OutputPath) {
    $OutputPath = Join-Path $PWD "NTLM-Report-$tsStr.html"
}

#endregion

#region ── 1. Discover Domain Controllers ────────────────────────────────────

Write-Status "Discovering Domain Controllers..."
try {
    $domain = Get-ADDomain
    $domainDNS = $domain.DNSRoot
    if (-not $DomainControllers) {
        $DomainControllers = (Get-ADDomainController -Filter *).HostName | Sort-Object
        Write-Status "Found $($DomainControllers.Count) DC(s) in $domainDNS." 'SUCCESS'
    }
} catch {
    Write-Status "AD module error: $_" 'WARN'
    $domainDNS = $env:USERDNSDOMAIN
    if (-not $DomainControllers) {
        $DomainControllers = @($env:LOGONSERVER -replace '\\\\')
    }
}

$icmBase = @{ ErrorAction = 'SilentlyContinue' }
if ($Credential) { $icmBase['Credential'] = $Credential }

#endregion

#region ── 2. Collect DC Registry Configuration ───────────────────────────────

Write-Status "Querying NTLM registry configuration from Domain Controllers..."

# Registry paths
$regLsa    = 'SYSTEM\CurrentControlSet\Control\Lsa'
$regMSV1   = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$regNL     = 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'

$dcConfigData = foreach ($dc in $DomainControllers) {
    Write-Status "  → $dc (registry)" 'INFO'
    try {
        $result = Invoke-Command -ComputerName $dc @icmBase -ScriptBlock {
            param($lsa, $msv1, $nl)

            function grv ($path, $name) {
                try { (Get-ItemProperty "HKLM:\$path" -Name $name -EA Stop).$name }
                catch { $null }
            }

            $os = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue

            [pscustomobject]@{
                ComputerName                 = $env:COMPUTERNAME
                OSCaption                    = if ($os) { $os.Caption } else { 'Unknown' }
                OSBuild                      = if ($os) { $os.BuildNumber } else { '?' }
                LmCompatibilityLevel         = grv $lsa  'LmCompatibilityLevel'
                AuditReceivingNTLMTraffic    = grv $msv1 'AuditReceivingNTLMTraffic'
                RestrictSendingNTLMTraffic   = grv $msv1 'RestrictSendingNTLMTraffic'
                RestrictReceivingNTLMTraffic = grv $msv1 'RestrictReceivingNTLMTraffic'
                AuditNTLMInDomain            = grv $nl   'AuditNTLMInDomain'
                RestrictNTLMInDomain         = grv $nl   'RestrictNTLMInDomain'
                NTLMServerExceptionList      = grv $nl   'NTLMServerExceptionList'
                ClientAllowedNTLMServers     = grv $msv1 'ClientAllowedNTLMServers'
            }
        } -ArgumentList $regLsa, $regMSV1, $regNL

        if ($result) { $result } else { throw "No result returned" }

    } catch {
        Write-Status "  Registry query failed for $dc : $_" 'ERROR'
        [pscustomobject]@{
            ComputerName                 = $dc
            OSCaption                    = 'Query Error'
            OSBuild                      = '?'
            LmCompatibilityLevel         = -1
            AuditReceivingNTLMTraffic    = -1
            RestrictSendingNTLMTraffic   = -1
            RestrictReceivingNTLMTraffic = -1
            AuditNTLMInDomain            = -1
            RestrictNTLMInDomain         = -1
            NTLMServerExceptionList      = $null
            ClientAllowedNTLMServers     = $null
        }
    }
}

#endregion

#region ── 3. Collect Security Log Events (4776 & 4624) ──────────────────────

Write-Status "Collecting Security log events (4776 & 4624) from DCs..."

$securityEvents = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($dc in $DomainControllers) {
    Write-Status "  → $dc (Security log)" 'INFO'
    try {
        $evts = Invoke-Command -ComputerName $dc @icmBase -ScriptBlock {
            param($startTime, $maxEvents)
            $out = [System.Collections.Generic.List[pscustomobject]]::new()

            # ── 4776 Credential Validation ─────────────────────────────────
            $e4776 = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'; Id = 4776; StartTime = $startTime
            } -MaxEvents $maxEvents -EA SilentlyContinue

            foreach ($e in $e4776) {
                try {
                    $xml  = [xml]$e.ToXml()
                    $d    = $xml.Event.EventData.Data
                    $out.Add([pscustomobject]@{
                        DC          = $env:COMPUTERNAME
                        EventId     = 4776
                        EventType   = 'Credential Validation'
                        TimeCreated = $e.TimeCreated
                        Account     = ($d | Where-Object Name -eq 'TargetUserName').'#text'
                        Workstation = ($d | Where-Object Name -eq 'Workstation').'#text'
                        Server      = ''
                        NTLMVersion = ''
                        LogonType   = ''
                        Process     = ''
                        ErrorCode   = ($d | Where-Object Name -eq 'Status').'#text'
                        IsBlocked   = $false
                        SPN         = ''
                        Reason      = ''
                    })
                } catch {}
            }

            # ── 4624 Logon Events (NTLM only) ─────────────────────────────
            $e4624 = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'; Id = 4624; StartTime = $startTime
            } -MaxEvents $maxEvents -EA SilentlyContinue

            foreach ($e in $e4624) {
                try {
                    $xml     = [xml]$e.ToXml()
                    $d       = $xml.Event.EventData.Data
                    $authPkg = ($d | Where-Object Name -eq 'AuthenticationPackageName').'#text'
                    if ($authPkg -notmatch 'NTLM') { continue }

                    $lmPkg = ($d | Where-Object Name -eq 'LmPackageName').'#text'
                    $ntlmv = switch -Regex ($lmPkg) {
                        'NTLM V2|NTLMv2' { 'NTLMv2' }
                        'NTLM V1|NTLMv1' { 'NTLMv1' }
                        '^LM$'           { 'LM (NTLMv1)' }
                        default          { if ($lmPkg) { $lmPkg } else { 'NTLM' } }
                    }

                    $out.Add([pscustomobject]@{
                        DC          = $env:COMPUTERNAME
                        EventId     = 4624
                        EventType   = 'NTLM Logon'
                        TimeCreated = $e.TimeCreated
                        Account     = ($d | Where-Object Name -eq 'TargetUserName').'#text'
                        Workstation = ($d | Where-Object Name -eq 'WorkstationName').'#text'
                        Server      = ($d | Where-Object Name -eq 'IpAddress').'#text'
                        NTLMVersion = $ntlmv
                        LogonType   = ($d | Where-Object Name -eq 'LogonType').'#text'
                        Process     = ($d | Where-Object Name -eq 'ProcessName').'#text'
                        ErrorCode   = ''
                        IsBlocked   = $false
                        SPN         = ''
                        Reason      = ''
                    })
                } catch {}
            }

            $out
        } -ArgumentList $startTime, $MaxEventsPerLog

        if ($evts) { foreach ($e in $evts) { $securityEvents.Add($e) } }
    } catch {
        Write-Status "  Security log failed on $dc : $_" 'ERROR'
    }
}

#endregion

#region ── 4. Collect NTLM Operational Log Events ────────────────────────────

Write-Status "Collecting NTLM Operational log events from DCs..."

$ntlmOpEvents = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($dc in $DomainControllers) {
    Write-Status "  → $dc (NTLM Operational log)" 'INFO'
    try {
        $evts = Invoke-Command -ComputerName $dc @icmBase -ScriptBlock {
            param($startTime, $maxEvents, $inclBlocking)

            $auditIds    = @(8001,8002,8003,8004,8005,8006)
            $blockIds    = @(4001,4002,4003,4004,4005,4006)
            $enhancedIds = @(4020,4022,4030,4032)

            $ids = $auditIds + $enhancedIds
            if ($inclBlocking) { $ids += $blockIds }

            $out = [System.Collections.Generic.List[pscustomobject]]::new()

            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-NTLM/Operational'
                Id        = $ids
                StartTime = $startTime
            } -MaxEvents $maxEvents -EA SilentlyContinue

            foreach ($e in $events) {
                try {
                    $xml = [xml]$e.ToXml()
                    $d   = $xml.Event.EventData.Data

                    function gf ($n) { ($d | Where-Object Name -eq $n).'#text' }

                    $typeMap = @{
                        8001 = 'Outgoing NTLM – Audit'
                        8002 = 'Incoming NTLM Local – Audit'
                        8003 = 'Incoming NTLM Domain – Audit'
                        8004 = 'DC Credential Validation (Member) – Audit'
                        8005 = 'DC Credential Validation (Direct) – Audit'
                        8006 = 'DC Credential Validation (Trust) – Audit'
                        4001 = 'Outgoing NTLM – BLOCKED'
                        4002 = 'Incoming NTLM Local – BLOCKED'
                        4003 = 'Incoming NTLM Domain – BLOCKED'
                        4004 = 'DC Credential Validation (Member) – BLOCKED'
                        4005 = 'DC Credential Validation (Direct) – BLOCKED'
                        4006 = 'DC Credential Validation (Trust) – BLOCKED'
                        4020 = 'Outgoing NTLM Enhanced (WS2025/24H2)'
                        4022 = 'Incoming NTLM Enhanced (WS2025/24H2)'
                        4030 = 'DC NTLM Enhanced (WS2025/24H2)'
                        4032 = 'DC Credential Validation Enhanced (WS2025/24H2)'
                    }

                    $account = gf 'UserName';     if (-not $account) { $account = gf 'TargetUserName' }
                    $ws      = gf 'WorkstationName'; if (-not $ws) { $ws = gf 'ClientComputerName' }
                    $server  = gf 'ServerName';   if (-not $server) { $server = gf 'TargetServerName' }
                    $proc    = gf 'CallerProcessName'; if (-not $proc) { $proc = gf 'ProcessName' }
                    $ver     = gf 'NTLMVersion';  if (-not $ver) { $ver = gf 'MessageType' }
                    # Normalize version string to NTLMv1 / NTLMv2
                    $verNorm = switch -Regex ($ver) {
                        '^1$|NTLMv1|V1' { 'NTLMv1' }
                        '^2$|NTLMv2|V2' { 'NTLMv2' }
                        default         { $ver }
                    }

                    $out.Add([pscustomobject]@{
                        DC          = $env:COMPUTERNAME
                        EventId     = $e.Id
                        EventType   = if ($typeMap[$e.Id]) { $typeMap[$e.Id] } else { "Event $($e.Id)" }
                        TimeCreated = $e.TimeCreated
                        Account     = $account
                        Workstation = $ws
                        Server      = $server
                        NTLMVersion = $verNorm
                        Process     = $proc
                        PID         = gf 'CallerProcessId'
                        Reason      = gf 'Reason'
                        SPN         = gf 'ServiceName'
                        ErrorCode   = ''
                        LogonType   = ''
                        IsBlocked   = $e.Id -in @(4001,4002,4003,4004,4005,4006)
                    })
                } catch {}
            }

            $out
        } -ArgumentList $startTime, $MaxEventsPerLog, $IncludeBlockingEvents.IsPresent

        if ($evts) { foreach ($e in $evts) { $ntlmOpEvents.Add($e) } }
    } catch {
        Write-Status "  NTLM Operational log failed on $dc : $_" 'ERROR'
    }
}

#endregion

#region ── 5. Aggregate & Analyze ────────────────────────────────────────────

Write-Status "Aggregating and analyzing data..."

$allEvents = [System.Collections.Generic.List[pscustomobject]]::new()
foreach ($e in $securityEvents) { $allEvents.Add($e) }
foreach ($e in $ntlmOpEvents)   { $allEvents.Add($e) }

$totalCount      = $allEvents.Count
$ntlmv1All       = @($allEvents | Where-Object { $_.NTLMVersion -match 'NTLMv1|LM' })
$ntlmv2All       = @($allEvents | Where-Object { $_.NTLMVersion -match 'NTLMv2' })
$blockedAll      = @($allEvents | Where-Object { $_.IsBlocked -eq $true })

$uniqueAccounts  = @($allEvents | Where-Object { $_.Account } | Select-Object -ExpandProperty Account -Unique).Count
$uniqueWS        = @($allEvents | Where-Object { $_.Workstation -and $_.Workstation -notmatch '^\s*$|-' } | Select-Object -ExpandProperty Workstation -Unique).Count

$topAccounts     = $allEvents | Where-Object { $_.Account }   | Group-Object Account    | Sort-Object Count -Descending | Select-Object -First 10
$topWorkstations = $allEvents | Where-Object { $_.Workstation -and $_.Workstation -notmatch '^\s*$|-' } | Group-Object Workstation | Sort-Object Count -Descending | Select-Object -First 10
$topServers      = $allEvents | Where-Object { $_.Server -and $_.Server -notmatch '^\s*$|-' }          | Group-Object Server      | Sort-Object Count -Descending | Select-Object -First 10
$topProcesses    = $ntlmOpEvents | Where-Object { $_.Process } | Group-Object Process   | Sort-Object Count -Descending | Select-Object -First 10

$eventsPerDC     = $allEvents | Group-Object DC | Sort-Object Count -Descending
$eventsByID      = $allEvents | Group-Object EventId | Sort-Object { [int]$_.Name }
$hourlyTrend     = $allEvents | Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:00') } | Sort-Object Name

# Chart.js data arrays
function fmtJsArray ($items) { if ($items) { $items -join ',' } else { '' } }

$jsHourLabels    = fmtJsArray ($hourlyTrend | ForEach-Object { "'$($_.Name)'" })
$jsHourCounts    = fmtJsArray ($hourlyTrend | ForEach-Object { $_.Count })
$jsEidLabels     = fmtJsArray ($eventsByID  | ForEach-Object { "'Evt $($_.Name)'" })
$jsEidCounts     = fmtJsArray ($eventsByID  | ForEach-Object { $_.Count })
$jsDcLabels      = fmtJsArray ($eventsPerDC | ForEach-Object { "'$($_.Name)'" })
$jsDcCounts      = fmtJsArray ($eventsPerDC | ForEach-Object { $_.Count })
$jsAcctLabels    = fmtJsArray ($topAccounts | ForEach-Object { "'$(($_.Name -replace "'","\'"))'" })
$jsAcctCounts    = fmtJsArray ($topAccounts | ForEach-Object { $_.Count })
$jsProcLabels    = fmtJsArray ($topProcesses| ForEach-Object { "'$(($_.Name -replace "'","\'"))'" })
$jsProcCounts    = fmtJsArray ($topProcesses| ForEach-Object { $_.Count })

#endregion

#region ── 6. Helper: Registry Value Labels & CSS Classes ────────────────────

function Get-LmLabel ($v) {
    switch ($v) {
        0  { '⛔ 0 – LM &amp; NTLMv1 allowed (insecure)' }
        1  { '⚠️ 1 – LM &amp; NTLM; use NTLMv2 if negotiated' }
        2  { '⚠️ 2 – Send NTLM response only' }
        3  { '⚠️ 3 – NTLMv2 only (DC still accepts NTLMv1)' }
        4  { '✅ 4 – NTLMv2; DC refuses LM responses' }
        5  { '✅ 5 – NTLMv2 only; DC refuses LM &amp; NTLMv1' }
        -1 { '❌ Query Error' }
        default { if ($null -eq $v) { '⚠️ Not Set (default = 0)' } else { "❓ $v" } }
    }
}
function Get-LmClass ($v) {
    if ($v -in @(4,5)) { 'cell-good' }
    elseif ($v -eq -1) { 'cell-error' }
    else { 'cell-warn' }
}

function Get-AuditRxLabel ($v) {
    switch ($v) {
        0  { '❌ 0 – Disabled' }
        1  { '✅ 1 – Audit domain accounts' }
        2  { '✅ 2 – Audit all accounts' }
        -1 { '❌ Query Error' }
        default { if ($null -eq $v) { '⚠️ Not Set (default = disabled)' } else { "❓ $v" } }
    }
}
function Get-AuditRxClass ($v) {
    if ($v -in @(1,2)) { 'cell-good' }
    elseif ($v -eq -1) { 'cell-error' }
    else { 'cell-warn' }
}

function Get-RestrictSendLabel ($v) {
    switch ($v) {
        0  { '⚠️ 0 – Allow all (no restriction)' }
        1  { '✅ 1 – Audit all outgoing NTLM' }
        2  { '🔒 2 – Deny all outgoing NTLM' }
        -1 { '❌ Query Error' }
        default { if ($null -eq $v) { '⚠️ Not Set (default = allow)' } else { "❓ $v" } }
    }
}
function Get-RestrictSendClass ($v) {
    if ($v -in @(1,2)) { 'cell-good' }
    elseif ($v -eq -1) { 'cell-error' }
    else { 'cell-warn' }
}

function Get-RestrictRxLabel ($v) {
    switch ($v) {
        0  { '⚠️ 0 – Allow all incoming NTLM' }
        1  { '🔒 1 – Deny domain accounts' }
        2  { '🔒 2 – Deny all accounts' }
        -1 { '❌ Query Error' }
        default { if ($null -eq $v) { '⚠️ Not Set (default = allow all)' } else { "❓ $v" } }
    }
}
function Get-RestrictRxClass ($v) {
    if ($v -in @(1,2)) { 'cell-good' }
    elseif ($v -eq -1) { 'cell-error' }
    else { 'cell-warn' }
}

function Get-AuditDomLabel ($v) {
    switch ($v) {
        0  { '❌ 0 – Disabled' }
        1  { '✅ 1 – Enable for domain accounts' }
        3  { '✅ 3 – Enable for domain accounts to domain servers' }
        7  { '✅ 7 – Enable all (recommended)' }
        -1 { '❌ Query Error' }
        default { if ($null -eq $v) { '⚠️ Not Set (default = disabled)' } else { "❓ $v" } }
    }
}
function Get-AuditDomClass ($v) {
    if ($v -in @(1,3,7)) { 'cell-good' }
    elseif ($v -eq -1) { 'cell-error' }
    else { 'cell-warn' }
}

function Get-RestrictDomLabel ($v) {
    switch ($v) {
        0  { '⚠️ 0 – Disabled (no restriction)' }
        1  { '🔒 1 – Deny domain accounts to domain servers' }
        3  { '🔒 3 – Deny for domain accounts' }
        5  { '🔒 5 – Deny for domain servers' }
        7  { '🔒 7 – Deny all NTLM in domain' }
        -1 { '❌ Query Error' }
        default { if ($null -eq $v) { '⚠️ Not Set (default = disabled)' } else { "❓ $v" } }
    }
}
function Get-RestrictDomClass ($v) {
    if ($v -in @(1,3,5,7)) { 'cell-good' }
    elseif ($v -eq -1) { 'cell-error' }
    else { 'cell-warn' }
}

#endregion

#region ── 7. Build HTML Fragments ───────────────────────────────────────────

# ── DC Config table rows ─────────────────────────────────────────────────────
$dcConfigRows = -join ($dcConfigData | ForEach-Object {
    $lmL  = Get-LmLabel  $_.LmCompatibilityLevel;         $lmC  = Get-LmClass  $_.LmCompatibilityLevel
    $arL  = Get-AuditRxLabel $_.AuditReceivingNTLMTraffic; $arC  = Get-AuditRxClass $_.AuditReceivingNTLMTraffic
    $rsL  = Get-RestrictSendLabel $_.RestrictSendingNTLMTraffic; $rsC = Get-RestrictSendClass $_.RestrictSendingNTLMTraffic
    $rrL  = Get-RestrictRxLabel $_.RestrictReceivingNTLMTraffic; $rrC = Get-RestrictRxClass $_.RestrictReceivingNTLMTraffic
    $adL  = Get-AuditDomLabel $_.AuditNTLMInDomain;        $adC  = Get-AuditDomClass $_.AuditNTLMInDomain
    $rdL  = Get-RestrictDomLabel $_.RestrictNTLMInDomain;  $rdC  = Get-RestrictDomClass $_.RestrictNTLMInDomain
    $excS = if ($_.NTLMServerExceptionList)   { Escape-Html $_.NTLMServerExceptionList }   else { '<em class="muted">None</em>' }
    $excC = if ($_.ClientAllowedNTLMServers)  { Escape-Html $_.ClientAllowedNTLMServers }  else { '<em class="muted">None</em>' }
    @"
<tr>
  <td class="sticky-col"><strong>$(Escape-Html $_.ComputerName)</strong><br><small class="muted">$(Escape-Html $_.OSCaption) (Build $(Escape-Html ([string]$_.OSBuild)))</small></td>
  <td class="$lmC">$lmL</td>
  <td class="$arC">$arL</td>
  <td class="$rsC">$rsL</td>
  <td class="$rrC">$rrL</td>
  <td class="$adC">$adL</td>
  <td class="$rdC">$rdL</td>
  <td>$excS</td>
  <td>$excC</td>
</tr>
"@
})

# ── DC filter <option> list ───────────────────────────────────────────────────
$dcFilterOpts = -join ($DomainControllers | Sort-Object | ForEach-Object { "<option value='$(Escape-Html $_)'>$(Escape-Html $_)</option>" })

# ── Security Events rows ──────────────────────────────────────────────────────
$secEventRows = -join ($securityEvents | Sort-Object TimeCreated -Descending | ForEach-Object {
    $ntlmVer  = Get-Prop $_ 'NTLMVersion'
    $errCode  = Get-Prop $_ 'ErrorCode'
    $dc       = Get-Prop $_ 'DC'
    $evtId    = Get-Prop $_ 'EventId'
    $evtType  = Get-Prop $_ 'EventType'
    $account  = Get-Prop $_ 'Account'
    $ws       = Get-Prop $_ 'Workstation'
    $server   = Get-Prop $_ 'Server'
    $logonTyp = Get-Prop $_ 'LogonType'
    $timeCr   = $_.TimeCreated

    $rowClass = switch -Regex ($ntlmVer) {
        'NTLMv1|LM' { 'row-v1' }
        'NTLMv2'    { 'row-v2' }
        default     { if ($errCode -and $errCode -ne '0x0') { 'row-err' } else { '' } }
    }
    $verBadge = if ($ntlmVer) {
        $bc = if ($ntlmVer -match 'NTLMv1|LM') { 'vbadge-v1' } elseif ($ntlmVer -match 'NTLMv2') { 'vbadge-v2' } else { 'vbadge-unk' }
        "<span class='vbadge $bc'>$(Escape-Html $ntlmVer)</span>"
    } else { '' }

    @"
<tr class="sec-row $rowClass"
    data-dc="$(Escape-Html $dc)" data-eid="$evtId"
    data-acct="$(Escape-Html $account)" data-ver="$(Escape-Html $ntlmVer)"
    data-ws="$(Escape-Html $ws)">
  <td class="mono">$($timeCr.ToString('yyyy-MM-dd HH:mm:ss'))</td>
  <td><span class="eid-badge">$evtId</span></td>
  <td>$(Escape-Html $evtType)</td>
  <td>$(Escape-Html $dc)</td>
  <td>$(Escape-Html $account)</td>
  <td>$(Escape-Html $ws)</td>
  <td>$(Escape-Html $server)</td>
  <td>$verBadge</td>
  <td>$(Escape-Html $logonTyp)</td>
  <td class="mono">$(Escape-Html $errCode)</td>
</tr>
"@
})

# ── NTLM Operational Events rows ─────────────────────────────────────────────
$opEventRows = -join ($ntlmOpEvents | Sort-Object TimeCreated -Descending | ForEach-Object {
    $ntlmVer  = Get-Prop $_ 'NTLMVersion'
    $isBlk    = [bool](Get-Prop $_ 'IsBlocked' 'false')
    $dc       = Get-Prop $_ 'DC'
    $evtId    = Get-Prop $_ 'EventId'
    $evtType  = Get-Prop $_ 'EventType'
    $account  = Get-Prop $_ 'Account'
    $ws       = Get-Prop $_ 'Workstation'
    $server   = Get-Prop $_ 'Server'
    $process  = Get-Prop $_ 'Process'
    $reason   = Get-Prop $_ 'Reason'
    $spn      = Get-Prop $_ 'SPN'
    $timeCr   = $_.TimeCreated

    $rowClass = if ($isBlk) { 'row-blocked' }
                elseif ($ntlmVer -match 'NTLMv1|LM') { 'row-v1' }
                elseif ($ntlmVer -match 'NTLMv2') { 'row-v2' }
                else { '' }
    $verBadge = if ($ntlmVer) {
        $bc = if ($ntlmVer -match 'NTLMv1|LM') { 'vbadge-v1' } elseif ($ntlmVer -match 'NTLMv2') { 'vbadge-v2' } else { 'vbadge-unk' }
        "<span class='vbadge $bc'>$(Escape-Html $ntlmVer)</span>"
    } else { '' }
    $eidClass = if ($isBlk) { 'eid-badge eid-blocked' } else { 'eid-badge eid-audit' }
    $blkAttr  = if ($isBlk) { 'true' } else { 'false' }

    @"
<tr class="op-row $rowClass"
    data-dc="$(Escape-Html $dc)" data-eid="$evtId"
    data-acct="$(Escape-Html $account)" data-ver="$(Escape-Html $ntlmVer)"
    data-ws="$(Escape-Html $ws)" data-srv="$(Escape-Html $server)"
    data-proc="$(Escape-Html $process)" data-blocked="$blkAttr">
  <td class="mono">$($timeCr.ToString('yyyy-MM-dd HH:mm:ss'))</td>
  <td><span class="$eidClass">$evtId</span></td>
  <td>$(Escape-Html $evtType)</td>
  <td>$(Escape-Html $dc)</td>
  <td>$(Escape-Html $account)</td>
  <td>$(Escape-Html $ws)</td>
  <td>$(Escape-Html $server)</td>
  <td>$verBadge</td>
  <td class="mono small">$(Escape-Html $process)</td>
  <td>$(Escape-Html $reason)</td>
  <td class="mono small">$(Escape-Html $spn)</td>
</tr>
"@
})

# ── Top-Talker bar rows (reusable helper) ─────────────────────────────────────
function Build-TopRows ($items, $color) {
    if (-not $items) { return '<tr><td colspan="2"><em class="muted">No data</em></td></tr>' }
    $max = ($items | Measure-Object Count -Maximum).Maximum
    -join ($items | ForEach-Object {
        $pct = if ($max -gt 0) { [int](($_.Count / $max) * 120) } else { 0 }
        "<tr><td>$(Escape-Html $_.Name)</td><td><div class='bar-cell'><div class='bar-fill' style='width:${pct}px;background:$color'></div><span>$($_.Count)</span></div></td></tr>"
    })
}

$rowsAccounts  = Build-TopRows $topAccounts    '#3b82f6'
$rowsWS        = Build-TopRows $topWorkstations '#f59e0b'
$rowsServers   = Build-TopRows $topServers      '#10b981'
$rowsProcesses = Build-TopRows $topProcesses    '#8b5cf6'
$rowsDC        = Build-TopRows $eventsPerDC     '#ef4444'

# ── Alerts HTML ───────────────────────────────────────────────────────────────
$alertsHtml = ''
if ($ntlmv1All.Count -gt 0) {
    $alertsHtml += "<div class='alert alert-critical'>🚨 <strong>NTLMv1 Detected!</strong> $($ntlmv1All.Count) NTLMv1/LM event(s) found. NTLMv1 is critically vulnerable — address immediately. Set LmCompatibilityLevel = 5 on all DCs.</div>"
}
if ($blockedAll.Count -gt 0) {
    $alertsHtml += "<div class='alert alert-block'>🔒 <strong>Blocking Events Present:</strong> $($blockedAll.Count) NTLM blocking event(s) detected (4001–4006). NTLM is actively being denied on some systems.</div>"
}
if ($totalCount -eq 0) {
    $alertsHtml += "<div class='alert alert-info'>ℹ️ <strong>No NTLM events found</strong> in the $HoursBack-hour window. Verify that NTLM auditing is enabled on your DCs (AuditNTLMInDomain = 7, AuditReceivingNTLMTraffic ≥ 1).</div>"
}

#endregion

#region ── 8. Assemble Full HTML ─────────────────────────────────────────────

Write-Status "Assembling HTML report..."

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NTLM Analysis – $domainDNS – $($reportTime.ToString('yyyy-MM-dd HH:mm'))</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
/* ─── Reset & Base ─────────────────────────────────────────────────────── */
:root {
  --bg:      #0f172a; --card:  #1e293b; --card2: #162032;
  --border:  #334155; --text:  #e2e8f0; --muted: #64748b;
  --blue:    #3b82f6; --red:   #ef4444; --amber: #f59e0b;
  --green:   #10b981; --purple:#8b5cf6; --cyan:  #06b6d4;
  --good-bg: rgba(16,185,129,.12); --good-fg: #86efac;
  --warn-bg: rgba(245,158,11,.12); --warn-fg: #fde68a;
  --err-bg:  rgba(239,68,68,.12);  --err-fg:  #fca5a5;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;line-height:1.55}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
code{background:#0f172a;border:1px solid var(--border);border-radius:3px;padding:1px 5px;font-size:11px;font-family:Consolas,monospace}
.mono{font-family:Consolas,monospace;font-size:12px}
.small{font-size:11px}
.muted{color:var(--muted)}

/* ─── Layout ───────────────────────────────────────────────────────────── */
.wrap{max-width:1900px;margin:0 auto;padding:20px}

/* ─── Header ───────────────────────────────────────────────────────────── */
.header{background:linear-gradient(135deg,#1a3a5c 0%,#0f172a 100%);
  border:1px solid var(--border);border-radius:12px;padding:24px 32px;
  margin-bottom:20px;display:flex;align-items:center;gap:18px}
.header-icon{font-size:44px;flex-shrink:0}
.header-info h1{font-size:24px;font-weight:800;color:#fff}
.header-info .sub{color:var(--muted);font-size:12px;margin-top:4px}
.header-meta{margin-left:auto;text-align:right;color:var(--muted);font-size:12px;line-height:2}
.header-meta strong{color:var(--text)}

/* ─── Tabs ─────────────────────────────────────────────────────────────── */
.tabs{display:flex;gap:3px;background:var(--card);border:1px solid var(--border);
  border-radius:10px;padding:5px;margin-bottom:20px;flex-wrap:wrap}
.tab-btn{background:transparent;border:none;color:var(--muted);padding:9px 18px;
  border-radius:7px;cursor:pointer;font-size:12px;font-weight:500;transition:.15s;
  display:flex;align-items:center;gap:6px;white-space:nowrap}
.tab-btn:hover{background:rgba(59,130,246,.15);color:var(--text)}
.tab-btn.active{background:var(--blue);color:#fff}
.tab-pane{display:none}.tab-pane.active{display:block}

/* ─── KPI Cards ─────────────────────────────────────────────────────────── */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:20px}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:10px;
  padding:18px 16px;position:relative;overflow:hidden}
.kpi::before{content:'';position:absolute;inset:0 0 auto 0;height:3px;background:var(--kc,var(--blue))}
.kpi .label{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:6px}
.kpi .value{font-size:30px;font-weight:900;color:var(--kc,var(--text))}
.kpi .detail{font-size:10px;color:var(--muted);margin-top:3px}
.kpi .icon{position:absolute;right:12px;top:14px;font-size:26px;opacity:.2}

/* ─── Alerts ───────────────────────────────────────────────────────────── */
.alert{border-radius:8px;padding:12px 16px;margin-bottom:14px;font-size:12px;border-left:4px solid}
.alert-critical{background:rgba(239,68,68,.12);border-color:var(--red);color:#fca5a5}
.alert-block{background:rgba(245,158,11,.12);border-color:var(--amber);color:#fde68a}
.alert-info{background:rgba(59,130,246,.1);border-color:var(--blue);color:#93c5fd}
.alert-warn{background:rgba(245,158,11,.1);border-color:var(--amber);color:#fde68a}

/* ─── Chart Grid ────────────────────────────────────────────────────────── */
.chart-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:14px;margin-bottom:20px}
.chart-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px}
.chart-card h3{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;
  color:var(--muted);margin-bottom:14px}
.chart-card canvas{max-height:260px}
.chart-wide{grid-column:1/-1}

/* ─── Section Card ──────────────────────────────────────────────────────── */
.section{background:var(--card);border:1px solid var(--border);border-radius:10px;
  padding:18px;margin-bottom:16px}
.section h2{font-size:16px;font-weight:700;margin-bottom:4px;display:flex;align-items:center;gap:8px}
.section .desc{font-size:11px;color:var(--muted);margin-bottom:14px}

/* ─── Filter Bar ────────────────────────────────────────────────────────── */
.filter-bar{display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;
  background:#0a1628;border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:12px}
.fg{display:flex;flex-direction:column;gap:3px}
.fg label{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}
.filter-bar input,.filter-bar select{
  background:var(--card);border:1px solid var(--border);color:var(--text);
  border-radius:5px;padding:6px 9px;font-size:12px;min-width:150px;outline:none}
.filter-bar input:focus,.filter-bar select:focus{border-color:var(--blue)}
.btn{padding:6px 14px;border-radius:5px;border:none;cursor:pointer;font-size:12px;font-weight:500;transition:.15s}
.btn-reset{background:var(--border);color:var(--text)}.btn-reset:hover{opacity:.8}
.row-count{font-size:11px;color:var(--muted);margin-bottom:6px}

/* ─── Tables ────────────────────────────────────────────────────────────── */
.tbl-wrap{overflow:auto;border-radius:7px;border:1px solid var(--border);max-height:560px}
table{width:100%;border-collapse:collapse;font-size:12px}
thead th{
  background:#0a1628;color:var(--muted);font-size:10px;text-transform:uppercase;
  letter-spacing:.06em;padding:9px 11px;position:sticky;top:0;z-index:3;
  white-space:nowrap;border-bottom:1px solid var(--border);text-align:left;
  cursor:pointer;user-select:none}
thead th:hover{color:var(--text)}
thead th::after{content:' ⇅';opacity:.3;font-size:9px}
tbody tr{border-bottom:1px solid rgba(51,65,85,.4);transition:background .1s}
tbody tr:hover{background:rgba(59,130,246,.07)}
tbody td{padding:8px 11px;vertical-align:middle}
.sticky-col{position:sticky;left:0;background:var(--card);z-index:2}
.hidden{display:none!important}

/* ─── Row Color Classes ─────────────────────────────────────────────────── */
.row-v1{background:rgba(239,68,68,.1)!important}
.row-v2{background:rgba(245,158,11,.06)!important}
.row-blocked{background:rgba(239,68,68,.18)!important;border-left:3px solid var(--red)}
.row-err{background:rgba(239,68,68,.06)!important}

/* ─── DC Config cell classes ────────────────────────────────────────────── */
.cell-good{background:var(--good-bg);color:var(--good-fg)}
.cell-warn{background:var(--warn-bg);color:var(--warn-fg)}
.cell-error{background:var(--err-bg);color:var(--err-fg)}

/* ─── Badges ────────────────────────────────────────────────────────────── */
.eid-badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:11px;
  font-weight:700;background:rgba(59,130,246,.2);color:#93c5fd}
.eid-audit{background:rgba(245,158,11,.2);color:#fde68a}
.eid-blocked{background:rgba(239,68,68,.25);color:#fca5a5}
.vbadge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700}
.vbadge-v1{background:rgba(239,68,68,.3);color:#fca5a5}
.vbadge-v2{background:rgba(245,158,11,.25);color:#fde68a}
.vbadge-unk{background:rgba(100,116,139,.3);color:#94a3b8}

/* ─── Top-Talker mini-tables ────────────────────────────────────────────── */
.top-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;margin-bottom:20px}
.top-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px}
.top-card h3{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-bottom:10px}
.top-card table{width:100%}
.top-card thead th{font-size:10px;padding:5px 7px}
.top-card tbody td{padding:5px 7px}
.bar-cell{display:flex;align-items:center;gap:6px}
.bar-fill{height:7px;border-radius:4px;min-width:3px;flex-shrink:0}

/* ─── Reference tables ──────────────────────────────────────────────────── */
.ref-table td,.ref-table th{padding:8px 11px;vertical-align:top}
.phase-1{color:#fca5a5}.phase-2{color:#fde68a}.phase-3{color:#86efac}

/* ─── Scrollbar ──────────────────────────────────────────────────────────── */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:#334155;border-radius:3px}

/* ─── Footer ─────────────────────────────────────────────────────────────── */
.footer{text-align:center;color:var(--muted);font-size:11px;padding:20px 0;
  border-top:1px solid var(--border);margin-top:24px}
</style>
</head>
<body>
<div class="wrap">

<!-- ════════════════════ HEADER ════════════════════════════════════════════ -->
<div class="header">
  <div class="header-icon">🔐</div>
  <div class="header-info">
    <h1>NTLM Usage Analysis Report</h1>
    <div class="sub">Active Directory · Based on <a href="https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782" target="_blank">Microsoft AD Hardening Series Part 8 – Disabling NTLM</a></div>
  </div>
  <div class="header-meta">
    <div>Domain: <strong>$domainDNS</strong></div>
    <div>Generated: <strong>$($reportTime.ToString('yyyy-MM-dd HH:mm:ss'))</strong></div>
    <div>Analysis window: <strong>Last $HoursBack hours</strong></div>
    <div>From: <strong>$($startTime.ToString('yyyy-MM-dd HH:mm'))</strong> to <strong>$($reportTime.ToString('yyyy-MM-dd HH:mm'))</strong></div>
    <div>DCs queried: <strong>$($DomainControllers.Count)</strong></div>
  </div>
</div>

<!-- ════════════════════ TABS ══════════════════════════════════════════════ -->
<div class="tabs">
  <button class="tab-btn active" onclick="switchTab('dashboard',this)">📊 Dashboard</button>
  <button class="tab-btn" onclick="switchTab('dc-config',this)">⚙️ DC Configuration</button>
  <button class="tab-btn" onclick="switchTab('security',this)">🔑 Security Events (4776 / 4624)</button>
  <button class="tab-btn" onclick="switchTab('operational',this)">📋 NTLM Operational Log</button>
  <button class="tab-btn" onclick="switchTab('toptalkers',this)">🏆 Top Talkers</button>
  <button class="tab-btn" onclick="switchTab('reference',this)">📖 Reference</button>
</div>

<!-- ════════════════════════════════════════════════════════════════════════
     TAB: DASHBOARD
     ════════════════════════════════════════════════════════════════════════ -->
<div id="pane-dashboard" class="tab-pane active">

  $alertsHtml

  <!-- KPI Cards -->
  <div class="kpi-grid">
    <div class="kpi" style="--kc:var(--blue)">
      <div class="label">Total NTLM Events</div>
      <div class="value">$totalCount</div>
      <div class="detail">All sources · $HoursBack-hour window</div>
      <div class="icon">📊</div>
    </div>
    <div class="kpi" style="--kc:var(--red)">
      <div class="label">NTLMv1 / LM Events</div>
      <div class="value">$($ntlmv1All.Count)</div>
      <div class="detail">Critically vulnerable – fix first</div>
      <div class="icon">🚨</div>
    </div>
    <div class="kpi" style="--kc:var(--amber)">
      <div class="label">NTLMv2 Events</div>
      <div class="value">$($ntlmv2All.Count)</div>
      <div class="detail">Target for elimination</div>
      <div class="icon">⚠️</div>
    </div>
    <div class="kpi" style="--kc:var(--red)">
      <div class="label">Blocked Events</div>
      <div class="value">$($blockedAll.Count)</div>
      <div class="detail">Events 4001–4006 (active blocking)</div>
      <div class="icon">🔒</div>
    </div>
    <div class="kpi" style="--kc:var(--purple)">
      <div class="label">Unique Accounts</div>
      <div class="value">$uniqueAccounts</div>
      <div class="detail">Distinct accounts using NTLM</div>
      <div class="icon">👤</div>
    </div>
    <div class="kpi" style="--kc:var(--cyan)">
      <div class="label">Unique Workstations</div>
      <div class="value">$uniqueWS</div>
      <div class="detail">Source devices using NTLM</div>
      <div class="icon">💻</div>
    </div>
    <div class="kpi" style="--kc:var(--green)">
      <div class="label">DCs Queried</div>
      <div class="value">$($DomainControllers.Count)</div>
      <div class="detail">Domain Controllers</div>
      <div class="icon">🖥️</div>
    </div>
    <div class="kpi" style="--kc:#f97316">
      <div class="label">Security Log Events</div>
      <div class="value">$($securityEvents.Count)</div>
      <div class="detail">Events 4776 &amp; 4624</div>
      <div class="icon">🔑</div>
    </div>
    <div class="kpi" style="--kc:#ec4899">
      <div class="label">Operational Log Events</div>
      <div class="value">$($ntlmOpEvents.Count)</div>
      <div class="detail">Events 8001–8006 &amp; enhanced</div>
      <div class="icon">📋</div>
    </div>
  </div>

  <!-- Charts -->
  <div class="chart-grid">
    <div class="chart-card chart-wide">
      <h3>📈 NTLM Events Over Time (Hourly Trend)</h3>
      <canvas id="cTimeline"></canvas>
    </div>
    <div class="chart-card">
      <h3>🎯 Events by Event ID</h3>
      <canvas id="cEventIds"></canvas>
    </div>
    <div class="chart-card">
      <h3>🖥️ Events per Domain Controller</h3>
      <canvas id="cDCs"></canvas>
    </div>
    <div class="chart-card">
      <h3>👤 Top 10 Accounts Using NTLM</h3>
      <canvas id="cAccounts"></canvas>
    </div>
    <div class="chart-card">
      <h3>🔢 NTLM Version Distribution</h3>
      <canvas id="cVersions"></canvas>
    </div>
    <div class="chart-card">
      <h3>⚙️ Top Processes Using NTLM</h3>
      <canvas id="cProcesses"></canvas>
    </div>
  </div>

</div><!-- /dashboard -->

<!-- ════════════════════════════════════════════════════════════════════════
     TAB: DC CONFIGURATION
     ════════════════════════════════════════════════════════════════════════ -->
<div id="pane-dc-config" class="tab-pane">
  <div class="section">
    <h2>⚙️ Domain Controller NTLM Registry Configuration</h2>
    <div class="desc">Live registry values read from each DC. Color coding: 🟢 Compliant with MS hardening guidance &nbsp;|&nbsp; 🟡 Partial / Audit-only &nbsp;|&nbsp; 🔴 Not configured / potentially vulnerable</div>

    <div class="alert alert-info" style="margin-bottom:14px">
      ℹ️ <strong>Target state for full NTLM elimination:</strong>
      LmCompatibilityLevel = <strong>5</strong> ·
      AuditReceivingNTLMTraffic = <strong>2</strong> ·
      RestrictSendingNTLMTraffic = <strong>2</strong> ·
      RestrictReceivingNTLMTraffic = <strong>1 or 2</strong> ·
      AuditNTLMInDomain = <strong>7</strong> ·
      RestrictNTLMInDomain = <strong>7</strong>
    </div>

    <div class="tbl-wrap" style="max-height:none">
      <table>
        <thead>
          <tr>
            <th class="sticky-col">Domain Controller</th>
            <th>LM Compatibility Level<br><code>LmCompatibilityLevel</code></th>
            <th>Audit Incoming NTLM<br><code>AuditReceivingNTLMTraffic</code></th>
            <th>Audit/Restrict Outgoing NTLM<br><code>RestrictSendingNTLMTraffic</code></th>
            <th>Block Incoming NTLM<br><code>RestrictReceivingNTLMTraffic</code></th>
            <th>Audit NTLM in Domain (DC)<br><code>AuditNTLMInDomain</code></th>
            <th>Restrict NTLM in Domain (DC)<br><code>RestrictNTLMInDomain</code></th>
            <th>Server Exception List<br><code>NTLMServerExceptionList</code></th>
            <th>Client Allowed NTLM Servers<br><code>ClientAllowedNTLMServers</code></th>
          </tr>
        </thead>
        <tbody>
          $dcConfigRows
        </tbody>
      </table>
    </div>

    <!-- Registry Reference sub-table -->
    <div style="margin-top:20px">
      <h3 style="font-size:13px;font-weight:600;margin-bottom:10px;color:var(--muted)">📋 Full Registry Path Reference</h3>
      <div class="tbl-wrap" style="max-height:none">
        <table class="ref-table">
          <thead><tr><th>Setting</th><th>Full Registry Path</th><th>Audit Phase Value</th><th>Block Phase Value</th></tr></thead>
          <tbody>
            <tr><td>LM Compatibility Level</td><td><code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel</code></td><td>3 – NTLMv2 only (client)</td><td>5 – DC refuses LM &amp; NTLMv1</td></tr>
            <tr><td>Audit Incoming NTLM</td><td><code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic</code></td><td>1 – Domain accounts</td><td>2 – All accounts</td></tr>
            <tr><td>Audit/Restrict Outgoing NTLM</td><td><code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic</code></td><td>1 – Audit all</td><td>2 – Deny all</td></tr>
            <tr><td>Block Incoming NTLM</td><td><code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictReceivingNTLMTraffic</code></td><td>0 – Allow (audit first)</td><td>1 – Deny domain; 2 – Deny all</td></tr>
            <tr><td>Audit NTLM in Domain (DC only)</td><td><code>HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain</code></td><td>7 – Enable all</td><td>N/A (audit setting)</td></tr>
            <tr><td>Restrict NTLM in Domain (DC only)</td><td><code>HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RestrictNTLMInDomain</code></td><td>0 – Disable (audit phase)</td><td>7 – Deny all</td></tr>
            <tr><td>Server Exception List</td><td><code>HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\NTLMServerExceptionList</code></td><td colspan="2">List of servers exempt from domain-wide NTLM restriction (wildcards supported)</td></tr>
            <tr><td>Client Allowed NTLM Servers</td><td><code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\ClientAllowedNTLMServers</code></td><td colspan="2">List of remote servers allowed to use NTLM when outbound restriction is active</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div><!-- /dc-config -->

<!-- ════════════════════════════════════════════════════════════════════════
     TAB: SECURITY EVENTS
     ════════════════════════════════════════════════════════════════════════ -->
<div id="pane-security" class="tab-pane">
  <div class="section">
    <h2>🔑 Security Log Events – 4776 &amp; 4624</h2>
    <div class="desc">
      <strong>4776</strong> – Credential Validation (DC Security log) – provides account + source workstation but not the target resource &nbsp;|&nbsp;
      <strong>4624</strong> – NTLM Logon events (filtered to NTLM auth packages only) – provides user, client, target server &amp; NTLM version
    </div>

    <div class="filter-bar">
      <div class="fg">
        <label>🔍 Free-text search</label>
        <input type="text" id="s-txt" placeholder="account, workstation, server…" oninput="filterSec()">
      </div>
      <div class="fg">
        <label>Event ID</label>
        <select id="s-eid" onchange="filterSec()">
          <option value="">All</option>
          <option value="4776">4776 – Credential Validation</option>
          <option value="4624">4624 – NTLM Logon</option>
        </select>
      </div>
      <div class="fg">
        <label>NTLM Version</label>
        <select id="s-ver" onchange="filterSec()">
          <option value="">All</option>
          <option value="NTLMv1">NTLMv1</option>
          <option value="NTLMv2">NTLMv2</option>
        </select>
      </div>
      <div class="fg">
        <label>Domain Controller</label>
        <select id="s-dc" onchange="filterSec()">
          <option value="">All DCs</option>
          $dcFilterOpts
        </select>
      </div>
      <div class="fg" style="justify-content:flex-end">
        <label>&nbsp;</label>
        <button class="btn btn-reset" onclick="resetSec()">↺ Reset</button>
      </div>
    </div>

    <div class="row-count" id="s-count">Showing $($securityEvents.Count) events</div>
    <div class="tbl-wrap">
      <table id="sec-tbl">
        <thead>
          <tr>
            <th onclick="sortTbl('sec-tbl',0)">Time</th>
            <th onclick="sortTbl('sec-tbl',1)">Event ID</th>
            <th onclick="sortTbl('sec-tbl',2)">Type</th>
            <th onclick="sortTbl('sec-tbl',3)">DC</th>
            <th onclick="sortTbl('sec-tbl',4)">Account</th>
            <th onclick="sortTbl('sec-tbl',5)">Source Workstation</th>
            <th onclick="sortTbl('sec-tbl',6)">Target Server / IP</th>
            <th onclick="sortTbl('sec-tbl',7)">NTLM Version</th>
            <th onclick="sortTbl('sec-tbl',8)">Logon Type</th>
            <th onclick="sortTbl('sec-tbl',9)">Error Code</th>
          </tr>
        </thead>
        <tbody id="sec-body">
          $secEventRows
        </tbody>
      </table>
    </div>
  </div>
</div><!-- /security -->

<!-- ════════════════════════════════════════════════════════════════════════
     TAB: NTLM OPERATIONAL LOG
     ════════════════════════════════════════════════════════════════════════ -->
<div id="pane-operational" class="tab-pane">
  <div class="section">
    <h2>📋 NTLM Operational Log – Events 8001–8006 / 4001–4006 / Enhanced</h2>
    <div class="desc">
      Source: <code>Microsoft-Windows-NTLM/Operational</code> &nbsp;|&nbsp;
      Provides process-level detail including calling application, workstation, server &amp; NTLM version &nbsp;|&nbsp;
      <span style="color:var(--red)">Red rows</span> = BLOCKED &nbsp;·&nbsp;
      <span style="color:#fca5a5">Pink rows</span> = NTLMv1 detected
    </div>

    <div class="filter-bar">
      <div class="fg">
        <label>🔍 Free-text search</label>
        <input type="text" id="o-txt" placeholder="account, workstation, server, process…" oninput="filterOp()">
      </div>
      <div class="fg">
        <label>Event ID</label>
        <select id="o-eid" onchange="filterOp()">
          <option value="">All</option>
          <option value="8001">8001 – Outgoing (Audit)</option>
          <option value="8002">8002 – Incoming Local (Audit)</option>
          <option value="8003">8003 – Incoming Domain (Audit)</option>
          <option value="8004">8004 – DC Member Validation (Audit)</option>
          <option value="8005">8005 – DC Direct Validation (Audit)</option>
          <option value="8006">8006 – DC Trust Validation (Audit)</option>
          <option value="4001">4001 – Outgoing BLOCKED</option>
          <option value="4002">4002 – Incoming Local BLOCKED</option>
          <option value="4003">4003 – Incoming Domain BLOCKED</option>
          <option value="4004">4004 – DC Member Validation BLOCKED</option>
          <option value="4005">4005 – DC Direct Validation BLOCKED</option>
          <option value="4006">4006 – DC Trust Validation BLOCKED</option>
          <option value="4020">4020 – Enhanced Outgoing (WS2025)</option>
          <option value="4022">4022 – Enhanced Incoming (WS2025)</option>
          <option value="4032">4032 – Enhanced DC Validation (WS2025)</option>
        </select>
      </div>
      <div class="fg">
        <label>NTLM Version</label>
        <select id="o-ver" onchange="filterOp()">
          <option value="">All</option>
          <option value="NTLMv1">NTLMv1</option>
          <option value="NTLMv2">NTLMv2</option>
        </select>
      </div>
      <div class="fg">
        <label>Domain Controller</label>
        <select id="o-dc" onchange="filterOp()">
          <option value="">All DCs</option>
          $dcFilterOpts
        </select>
      </div>
      <div class="fg">
        <label>Status</label>
        <select id="o-blk" onchange="filterOp()">
          <option value="">Audit &amp; Blocked</option>
          <option value="true">Blocked only</option>
          <option value="false">Audit only</option>
        </select>
      </div>
      <div class="fg" style="justify-content:flex-end">
        <label>&nbsp;</label>
        <button class="btn btn-reset" onclick="resetOp()">↺ Reset</button>
      </div>
    </div>

    <div class="row-count" id="o-count">Showing $($ntlmOpEvents.Count) events</div>
    <div class="tbl-wrap">
      <table id="op-tbl">
        <thead>
          <tr>
            <th onclick="sortTbl('op-tbl',0)">Time</th>
            <th onclick="sortTbl('op-tbl',1)">Event ID</th>
            <th onclick="sortTbl('op-tbl',2)">Type</th>
            <th onclick="sortTbl('op-tbl',3)">DC</th>
            <th onclick="sortTbl('op-tbl',4)">Account</th>
            <th onclick="sortTbl('op-tbl',5)">Source Workstation</th>
            <th onclick="sortTbl('op-tbl',6)">Target Server</th>
            <th onclick="sortTbl('op-tbl',7)">NTLM Version</th>
            <th onclick="sortTbl('op-tbl',8)">Process / Application</th>
            <th onclick="sortTbl('op-tbl',9)">Reason for NTLM</th>
            <th onclick="sortTbl('op-tbl',10)">SPN</th>
          </tr>
        </thead>
        <tbody id="op-body">
          $opEventRows
        </tbody>
      </table>
    </div>
  </div>
</div><!-- /operational -->

<!-- ════════════════════════════════════════════════════════════════════════
     TAB: TOP TALKERS
     ════════════════════════════════════════════════════════════════════════ -->
<div id="pane-toptalkers" class="tab-pane">
  <div class="section" style="margin-bottom:16px">
    <h2>🏆 Top NTLM Consumers</h2>
    <div class="desc">Prioritize your remediation efforts using these rankings. Focus on eliminating NTLMv1 first, then target the highest-volume accounts, workstations and processes.</div>
  </div>

  <div class="top-grid">
    <div class="top-card">
      <h3>👤 Top 10 Accounts</h3>
      <table><thead><tr><th>Account</th><th>Events</th></tr></thead>
      <tbody>$rowsAccounts</tbody></table>
    </div>
    <div class="top-card">
      <h3>💻 Top 10 Source Workstations</h3>
      <table><thead><tr><th>Workstation</th><th>Events</th></tr></thead>
      <tbody>$rowsWS</tbody></table>
    </div>
    <div class="top-card">
      <h3>🖥️ Top 10 Destination Servers</h3>
      <table><thead><tr><th>Server / IP</th><th>Events</th></tr></thead>
      <tbody>$rowsServers</tbody></table>
    </div>
    <div class="top-card">
      <h3>⚙️ Top 10 Processes Using NTLM</h3>
      <table><thead><tr><th>Process / Application</th><th>Events</th></tr></thead>
      <tbody>$rowsProcesses</tbody></table>
    </div>
    <div class="top-card">
      <h3>🖥️ Events per Domain Controller</h3>
      <table><thead><tr><th>DC</th><th>Events</th></tr></thead>
      <tbody>$rowsDC</tbody></table>
    </div>
  </div>
</div><!-- /toptalkers -->

<!-- ════════════════════════════════════════════════════════════════════════
     TAB: REFERENCE
     ════════════════════════════════════════════════════════════════════════ -->
<div id="pane-reference" class="tab-pane">

  <div class="section">
    <h2>📖 Event ID Reference</h2>
    <div class="desc">Complete event ID reference from <a href="https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782" target="_blank">Microsoft AD Hardening Series Part 8</a></div>
    <div class="tbl-wrap" style="max-height:none">
      <table class="ref-table">
        <thead><tr><th>Event ID</th><th>Category</th><th>Logged On</th><th>Trigger Condition</th><th>Block Equiv.</th></tr></thead>
        <tbody>
          <tr><td><span class="eid-badge">4776</span></td><td>Credential Validation</td><td>Domain Controllers</td><td>Any NTLM auth forwarded to DC. Captures account + source workstation. Does NOT capture target resource.</td><td>–</td></tr>
          <tr><td><span class="eid-badge">4624</span></td><td>NTLM Logon (filtered)</td><td>Any Windows device</td><td>Successful logon using NTLM auth package. Captures user, client, target server &amp; NTLM version negotiated.</td><td>–</td></tr>
          <tr class="row-v1"><td><span class="eid-audit">8001</span></td><td>Outgoing NTLM – Audit</td><td>Client machines / any NTLM initiator</td><td>Any outgoing NTLM authentication from the device. Captures process name.</td><td><span class="eid-blocked">4001</span></td></tr>
          <tr><td><span class="eid-audit">8002</span></td><td>Incoming NTLM Local – Audit</td><td>Any Windows device incl. DCs</td><td>Incoming NTLM not requiring DC validation (local accounts, loopback auth, RPC EPM).</td><td><span class="eid-blocked">4002</span></td></tr>
          <tr><td><span class="eid-audit">8003</span></td><td>Incoming NTLM Domain – Audit</td><td>Domain member servers</td><td>Incoming NTLM using domain account; DC required for validation.</td><td><span class="eid-blocked">4003</span></td></tr>
          <tr><td><span class="eid-audit">8004</span></td><td>DC Validation – Member</td><td>Domain Controllers</td><td>NTLM credential validation request from domain member over secure channel.</td><td><span class="eid-blocked">4004</span></td></tr>
          <tr><td><span class="eid-audit">8005</span></td><td>DC Validation – Direct</td><td>Domain Controllers</td><td>NTLM auth directly to DC (Type 3 logon to the DC itself).</td><td><span class="eid-blocked">4005</span></td></tr>
          <tr><td><span class="eid-audit">8006</span></td><td>DC Validation – Trust</td><td>Domain Controllers</td><td>NTLM credential validation from trusted domain over secure channel.</td><td><span class="eid-blocked">4006</span></td></tr>
          <tr><td><span class="eid-badge">4020</span></td><td>Enhanced Outgoing (WS2025 / W11 24H2)</td><td>Client machines</td><td>Richer 8001 equivalent: includes NTLM version, SPN, reason NTLM was selected, negotiation flags.</td><td><span class="eid-blocked">4021</span></td></tr>
          <tr><td><span class="eid-badge">4022</span></td><td>Enhanced Incoming (WS2025 / W11 24H2)</td><td>Resource servers</td><td>Richer 8002/8003 equivalent: includes SPN being accessed, NTLM version negotiated.</td><td><span class="eid-blocked">4023</span></td></tr>
          <tr><td><span class="eid-badge">4032</span></td><td>Enhanced DC Validation (WS2025 / W11 24H2)</td><td>Domain Controllers</td><td>Game changer: detects NTLM version from DC logs alone. Previously required 4624 collection from all devices.</td><td><span class="eid-blocked">4033</span></td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <h2>📋 Remediation Roadmap</h2>
    <div class="tbl-wrap" style="max-height:none">
      <table class="ref-table">
        <thead><tr><th>Phase</th><th>Action</th><th>Priority</th><th>Notes</th></tr></thead>
        <tbody>
          <tr><td>1</td><td>Enable NTLM auditing on all DCs: AuditNTLMInDomain=7, AuditReceivingNTLMTraffic=1, RestrictSendingNTLMTraffic=1</td><td class="phase-1">🔴 Immediate</td><td>No impact on auth. Enables events 8004, 8001, 8002/8003.</td></tr>
          <tr><td>2</td><td>Baseline daily NTLM volume. Use this report + SIEM dashboards to track progress.</td><td class="phase-1">🔴 Immediate</td><td>Peter Drucker: "You can't manage what you can't measure."</td></tr>
          <tr><td>3</td><td>Eliminate NTLMv1 / LM: Set LmCompatibilityLevel = 5 on all DCs via GPO.</td><td class="phase-1">🔴 Immediate</td><td>WS2025 DCs still accept NTLMv1 for validation (compatible with lmcompat=4).</td></tr>
          <tr><td>4</td><td>Fix duplicate &amp; missing SPNs. Run <code>setspn -x</code> to find duplicates.</td><td class="phase-2">🟡 High</td><td>Missing SPNs cause Kerberos failures → NTLM fallback.</td></tr>
          <tr><td>5</td><td>Identify &amp; remediate IP-address-based connections (use TryIPSPN registry setting + add IP SPNs).</td><td class="phase-2">🟡 High</td><td>Windows never attempts Kerberos for IP addresses by default.</td></tr>
          <tr><td>6</td><td>Identify applications hardcoded to NTLM (use Process field in 8001/8003 events). Reconfigure to use Negotiate.</td><td class="phase-2">🟡 High</td><td>Telemetry shows ~50%+ of NTLM is application-configured.</td></tr>
          <tr><td>7</td><td>Enforce SMB Signing and disable SMBv1.</td><td class="phase-2">🟡 High</td><td>Address before NTLM — more immediately exploitable.</td></tr>
          <tr><td>8</td><td>Enable Protected Users security group for all privileged accounts.</td><td class="phase-2">🟡 High</td><td>Prevents NTLM use entirely for group members.</td></tr>
          <tr><td>9</td><td>Begin blocking outbound NTLM on Tier 0 devices (RestrictSendingNTLMTraffic=2), use exception list for dependencies.</td><td class="phase-3">🟢 Medium</td><td>Start small — one OU at a time. Monitor 4001 events.</td></tr>
          <tr><td>10</td><td>Extend blocking to Tier 1/2 servers and workstations incrementally.</td><td class="phase-3">🟢 Medium</td><td>Use server &amp; client exception lists during transition.</td></tr>
          <tr><td>11</td><td>Apply domain-wide DC restriction: RestrictNTLMInDomain = 7 (Deny all).</td><td class="phase-3">🟢 Final</td><td>The last step — only after all dependencies eliminated.</td></tr>
          <tr><td>12</td><td>Upgrade DCs to Windows Server 2025 for enhanced events (4020, 4022, 4032).</td><td class="phase-3">🟢 Strategic</td><td>4032 allows NTLMv1 detection from DC logs alone.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <h2>⚠️ Common NTLMv1 / NTLM Sources to Check</h2>
    <div class="tbl-wrap" style="max-height:none">
      <table class="ref-table">
        <thead><tr><th>Source</th><th>Details</th><th>Fix</th></tr></thead>
        <tbody>
          <tr><td>Local Accounts</td><td>Accessing resources with local accounts always uses NTLM (until LocalKDC is available in WS2025).</td><td>Replace with domain accounts or managed service accounts.</td></tr>
          <tr><td>IP Address Connections</td><td>Windows does not request Kerberos for IP address targets by default.</td><td>Use hostnames. Configure TryIPSPN + add IP SPNs if needed.</td></tr>
          <tr><td>Printers / Print Spooler</td><td>Print Nightmare patches changed RPC authentication to NTLM for named pipe connections.</td><td>Configure Printer RPC GPO settings; set RpcNamedPipeAuthentication=2 if needed.</td></tr>
          <tr><td>Applications Hardcoded to NTLM</td><td>Application explicitly selects NTLM instead of Negotiate.</td><td>Reconfigure application to use Negotiate. Contact vendor for hardcoded cases.</td></tr>
          <tr><td>Loopback Authentication</td><td>Services authenticating to themselves (e.g. RPC EPM, HTTP.sys, WinRM, ADWS).</td><td>Appears as SYSTEM account (PID 4). Use BackConnectionHostNames or DisableLoopbackCheck where appropriate.</td></tr>
          <tr><td>External / Forest Trusts</td><td>Authentication over external trusts defaults to NTLM.</td><td>Convert external trusts to forest trusts before restricting cross-domain NTLM.</td></tr>
          <tr><td>Vulnerability Scanners</td><td>Some scanners probe NTLM authentication to assess posture.</td><td>Expected behavior — not necessarily a dependency. Filter scanner IPs in analysis.</td></tr>
          <tr><td>Missing / Duplicate SPNs</td><td>Kerberos TGS-REQ fails → NTLM fallback.</td><td>Run <code>setspn -x</code> for duplicates. Enable Kerberos logging (LogLevel=1) to find missing SPNs via 4769 failures.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

</div><!-- /reference -->

<!-- ════════════════════ FOOTER ═══════════════════════════════════════════ -->
<div class="footer">
  NTLM Analysis Report · Domain: <strong>$domainDNS</strong> · Generated: $($reportTime.ToString('yyyy-MM-dd HH:mm:ss')) ·
  <a href="https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782" target="_blank">Microsoft AD Hardening Series Part 8</a> ·
  Ollischer IT Consulting
</div>

</div><!-- /wrap -->

<!-- ══════════════════════════════════════════════════════════════════════
     JAVASCRIPT
     ══════════════════════════════════════════════════════════════════════ -->
<script>
'use strict';

// ── Tab switching ─────────────────────────────────────────────────────────
function switchTab(id, btn) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('pane-' + id).classList.add('active');
  btn.classList.add('active');
}

// ── Sortable columns ──────────────────────────────────────────────────────
const _sortState = {};
function sortTbl(tableId, col) {
  const tbl  = document.getElementById(tableId);
  const body = tbl.querySelector('tbody');
  const rows = Array.from(body.querySelectorAll('tr:not(.hidden)'));
  const key  = tableId + '_' + col;
  _sortState[key] = !_sortState[key];
  const asc  = _sortState[key];

  rows.sort((a, b) => {
    const aT = a.cells[col]?.innerText.trim() ?? '';
    const bT = b.cells[col]?.innerText.trim() ?? '';
    const aN = parseFloat(aT), bN = parseFloat(bT);
    if (!isNaN(aN) && !isNaN(bN)) return asc ? aN - bN : bN - aN;
    if (!isNaN(Date.parse(aT)) && !isNaN(Date.parse(bT)))
      return asc ? new Date(aT) - new Date(bT) : new Date(bT) - new Date(aT);
    return asc ? aT.localeCompare(bT) : bT.localeCompare(aT);
  });
  rows.forEach(r => body.appendChild(r));
}

// ── Security Events filter ────────────────────────────────────────────────
function filterSec() {
  const txt = document.getElementById('s-txt').value.toLowerCase();
  const eid = document.getElementById('s-eid').value;
  const ver = document.getElementById('s-ver').value.toLowerCase();
  const dc  = document.getElementById('s-dc').value.toLowerCase();
  const rows = document.querySelectorAll('#sec-body .sec-row');
  let vis = 0;
  rows.forEach(r => {
    const show =
      (!txt || r.innerText.toLowerCase().includes(txt)) &&
      (!eid || r.dataset.eid === eid) &&
      (!ver || (r.dataset.ver || '').toLowerCase().includes(ver)) &&
      (!dc  || (r.dataset.dc  || '').toLowerCase() === dc);
    r.classList.toggle('hidden', !show);
    if (show) vis++;
  });
  document.getElementById('s-count').textContent =
    'Showing ' + vis + ' of ' + rows.length + ' events';
}
function resetSec() {
  ['s-txt','s-eid','s-ver','s-dc'].forEach(id => document.getElementById(id).value = '');
  filterSec();
}

// ── NTLM Operational filter ───────────────────────────────────────────────
function filterOp() {
  const txt = document.getElementById('o-txt').value.toLowerCase();
  const eid = document.getElementById('o-eid').value;
  const ver = document.getElementById('o-ver').value.toLowerCase();
  const dc  = document.getElementById('o-dc').value.toLowerCase();
  const blk = document.getElementById('o-blk').value;
  const rows = document.querySelectorAll('#op-body .op-row');
  let vis = 0;
  rows.forEach(r => {
    const isBlocked = r.dataset.blocked === 'true';
    const show =
      (!txt || r.innerText.toLowerCase().includes(txt)) &&
      (!eid || r.dataset.eid === eid) &&
      (!ver || (r.dataset.ver || '').toLowerCase().includes(ver)) &&
      (!dc  || (r.dataset.dc  || '').toLowerCase() === dc) &&
      (!blk || (blk === 'true' ? isBlocked : !isBlocked));
    r.classList.toggle('hidden', !show);
    if (show) vis++;
  });
  document.getElementById('o-count').textContent =
    'Showing ' + vis + ' of ' + rows.length + ' events';
}
function resetOp() {
  ['o-txt','o-eid','o-ver','o-dc','o-blk'].forEach(id => document.getElementById(id).value = '');
  filterOp();
}

// ── Charts ────────────────────────────────────────────────────────────────
const PALETTE = ['#3b82f6','#ef4444','#f59e0b','#10b981','#8b5cf6',
                 '#06b6d4','#f97316','#ec4899','#14b8a6','#84cc16',
                 '#6366f1','#a855f7','#fb923c','#22d3ee'];

const commonOpts = {
  responsive: true,
  maintainAspectRatio: true,
  plugins: {
    legend: { labels: { color: '#94a3b8', boxWidth: 11, font: { size: 11 } } },
    tooltip: {
      backgroundColor: '#1e293b', titleColor: '#e2e8f0',
      bodyColor: '#94a3b8', borderColor: '#334155', borderWidth: 1
    }
  },
  scales: {
    x: { ticks: { color: '#475569', font: { size: 10 } }, grid: { color: 'rgba(51,65,85,.35)' } },
    y: { ticks: { color: '#475569', font: { size: 10 } }, grid: { color: 'rgba(51,65,85,.35)' } }
  }
};

// Timeline
new Chart(document.getElementById('cTimeline'), {
  type: 'line',
  data: {
    labels: [$jsHourLabels],
    datasets: [{
      label: 'NTLM Events',
      data: [$jsHourCounts],
      borderColor: '#3b82f6',
      backgroundColor: 'rgba(59,130,246,.12)',
      fill: true, tension: 0.35, pointRadius: 3, pointHoverRadius: 5
    }]
  },
  options: { ...commonOpts }
});

// Event IDs bar chart
new Chart(document.getElementById('cEventIds'), {
  type: 'bar',
  data: {
    labels: [$jsEidLabels],
    datasets: [{
      label: 'Count',
      data: [$jsEidCounts],
      backgroundColor: PALETTE
    }]
  },
  options: { ...commonOpts, plugins: { ...commonOpts.plugins, legend: { display: false } } }
});

// DC doughnut
new Chart(document.getElementById('cDCs'), {
  type: 'doughnut',
  data: {
    labels: [$jsDcLabels],
    datasets: [{ data: [$jsDcCounts], backgroundColor: PALETTE, borderColor: '#1e293b', borderWidth: 2 }]
  },
  options: {
    responsive: true, maintainAspectRatio: true,
    plugins: { legend: { labels: { color: '#94a3b8' } }, tooltip: commonOpts.plugins.tooltip }
  }
});

// Top accounts horizontal bar
new Chart(document.getElementById('cAccounts'), {
  type: 'bar',
  data: {
    labels: [$jsAcctLabels],
    datasets: [{ label: 'Events', data: [$jsAcctCounts], backgroundColor: 'rgba(139,92,246,.7)', borderColor: '#8b5cf6', borderWidth: 1 }]
  },
  options: { ...commonOpts, indexAxis: 'y', plugins: { ...commonOpts.plugins, legend: { display: false } } }
});

// Version doughnut
new Chart(document.getElementById('cVersions'), {
  type: 'doughnut',
  data: {
    labels: ['NTLMv1 / LM ⚠️', 'NTLMv2', 'Unknown / N/A'],
    datasets: [{
      data: [$($ntlmv1All.Count), $($ntlmv2All.Count), $($totalCount - $ntlmv1All.Count - $ntlmv2All.Count)],
      backgroundColor: ['#ef4444','#f59e0b','#475569'],
      borderColor: '#1e293b', borderWidth: 2
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: true,
    plugins: { legend: { labels: { color: '#94a3b8' } }, tooltip: commonOpts.plugins.tooltip }
  }
});

// Top Processes horizontal bar
new Chart(document.getElementById('cProcesses'), {
  type: 'bar',
  data: {
    labels: [$jsProcLabels],
    datasets: [{ label: 'Events', data: [$jsProcCounts], backgroundColor: 'rgba(6,182,212,.7)', borderColor: '#06b6d4', borderWidth: 1 }]
  },
  options: { ...commonOpts, indexAxis: 'y', plugins: { ...commonOpts.plugins, legend: { display: false } } }
});
</script>
</body>
</html>
"@

#endregion

#region ── 9. Write Report & Open ────────────────────────────────────────────

$html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
Write-Status "Report written: $OutputPath" 'SUCCESS'

try { Start-Process $OutputPath } catch {}

Write-Host ''
Write-Host '══════════════════════════════════════════════════' -ForegroundColor DarkCyan
Write-Host '  NTLM Analysis Summary' -ForegroundColor Cyan
Write-Host '══════════════════════════════════════════════════' -ForegroundColor DarkCyan
Write-Host "  Domain             : $domainDNS"
Write-Host "  Analysis window    : Last $HoursBack hours"
Write-Host "  DCs queried        : $($DomainControllers.Count)"
Write-Host "  Total events       : $totalCount"
Write-Host "  NTLMv1 / LM events : $($ntlmv1All.Count)" -ForegroundColor $(if ($ntlmv1All.Count -gt 0) {'Red'} else {'Green'})
Write-Host "  NTLMv2 events      : $($ntlmv2All.Count)" -ForegroundColor $(if ($ntlmv2All.Count -gt 0) {'Yellow'} else {'Green'})
Write-Host "  NTLM blocked events: $($blockedAll.Count)"
Write-Host "  Unique accounts    : $uniqueAccounts"
Write-Host "  Report saved to    : $OutputPath" -ForegroundColor Green
Write-Host '══════════════════════════════════════════════════' -ForegroundColor DarkCyan

#endregion
