<# 
.SYNOPSIS
  Client-side detector for the effective Windows Hello for Business trust model
  (Certificate trust, Cloud Kerberos trust, or Key trust) with no RSAT dependency.

.NOTES
  Run in a regular PowerShell window on the affected client.
#>

# ---------- Helpers ----------
function Write-Section($t){ Write-Host "`n=== $t ===" -ForegroundColor Cyan }

function Get-PolicyValues {
  $paths = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork',
    # MDM/PolicyManager mirrors (some tenants push via PolicyManager instead of classic Policies)
    'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\Device\PassportForWork'
  )
  $names = @('UseCloudTrustForOnPremAuth','UseCertificateForOnPremAuth','UsePassportForWork','Enabled')

  $rows = @()
  foreach($p in $paths){
    if(Test-Path $p){
      # Check root
      foreach($n in $names){
        try{
          $v = (Get-ItemProperty -Path $p -Name $n -ErrorAction Stop).$n
          $rows += [pscustomobject]@{ Path=$p; Name=$n; Value=$v }
        }catch{}
      }
      # And any tenant subkeys
      Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
        foreach($n in $names){
          try{
            $v = (Get-ItemProperty -Path $_.PsPath -Name $n -ErrorAction Stop).$n
            $rows += [pscustomobject]@{ Path=$_.PsPath; Name=$n; Value=$v }
          }catch{}
        }
      }
    }
  }
  $rows
}

function Get-LocalHelloAuthCerts {
  # Look for likely WHfB auth certs in CurrentUser\My
  # Signals: template info extension, EKUs for Client Auth / Smart Card Logon, or “Hello” in names
  $found = @()
  try{
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","CurrentUser")
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    foreach($c in $store.Certificates){
      $hasClientAuth = $false
      $hasSmartCard  = $false
      $templateInfo  = $null
      foreach($eku in $c.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }){
        foreach($oid in $eku.EnhancedKeyUsages){
          if($oid.Value -eq '1.3.6.1.5.5.7.3.2'){ $hasClientAuth = $true }            # Client Authentication
          if($oid.Value -eq '1.3.6.1.4.1.311.20.2.2'){ $hasSmartCard  = $true }       # Smart Card Logon
        }
      }
      foreach($ext in $c.Extensions){
        if($ext.Oid.Value -eq '1.3.6.1.4.1.311.21.7'){ $templateInfo = $ext.Format($true) } # Certificate Template Information
      }
      $looksHello = ($c.Subject -like '*Windows Hello*' -or $c.FriendlyName -like '*Hello*' -or $templateInfo -match '(?i)hello|whfb')

      if($looksHello -or ($hasClientAuth -and $hasSmartCard)){
        $found += [pscustomobject]@{
          Subject      = $c.Subject
          Issuer       = $c.Issuer
          NotAfter     = $c.NotAfter
          HasClientAuth= $hasClientAuth
          HasSCLogon   = $hasSmartCard
          TemplateInfo = $templateInfo -replace "`r`n",' '
          Thumbprint   = $c.Thumbprint
        }
      }
    }
    $store.Close()
  } catch {}
  $found
}

function Get-DsRegStatusText {
  try{
    $out = & dsregcmd /status 2>$null
    if($LASTEXITCODE -eq 0 -and $out){ return ($out | Out-String) }
  }catch{}
  return $null
}

# ---------- Run ----------
Write-Section "Local policy state (PassportForWork)"
$pol = Get-PolicyValues
if($pol.Count -gt 0){
  $pol | Sort-Object Path,Name | Format-Table -AutoSize
}else{
  Write-Host "No PassportForWork policy values detected in common locations." -ForegroundColor Yellow
}

Write-Section "Local user certificate store (CurrentUser\\My)"
$certs = Get-LocalHelloAuthCerts
if($certs.Count -gt 0){
  $certs | Sort-Object NotAfter -Descending | Format-Table Subject,Issuer,NotAfter,HasClientAuth,HasSCLogon,@{n='Template';e={$_.TemplateInfo}} -AutoSize
}else{
  Write-Host "No likely Windows Hello for Business authentication certificates found." -ForegroundColor Yellow
}

Write-Section "dsregcmd snapshot (useful hints)"
$ds = Get-DsRegStatusText
if($ds){
  # Print a few lines that commonly help (tenant, join state, PRT, AzureAdPrt, etc.)
  ($ds -split "`r?`n") |
    Where-Object { $_ -match '^\s*(AzureAd|Device State|User State|Tenant Name|AzureAdPrt|Ngc Prt|WorkplaceJoined|DomainJoined)' } |
    ForEach-Object { $_ }
}else{
  Write-Host "dsregcmd not available or returned no output."
}

# ---------- Verdict ----------
Write-Section "Verdict"
$cloudTrust = ($pol | Where-Object { $_.Name -eq 'UseCloudTrustForOnPremAuth' -and $_.Value -eq 1 })
$certTrust  = ($pol | Where-Object { $_.Name -eq 'UseCertificateForOnPremAuth' -and $_.Value -eq 1 })
$hasHelloCert = $certs.Count -gt 0

$reasons = @()
if($certTrust){ $reasons += "Policy indicates CERTIFICATE trust (UseCertificateForOnPremAuth=1)." }
if($cloudTrust){ $reasons += "Policy indicates CLOUD KERBEROS trust (UseCloudTrustForOnPremAuth=1)." }
if($hasHelloCert){ $reasons += "A likely WHfB user authentication certificate is present in CurrentUser\My." }
if(-not $hasHelloCert){ $reasons += "No WHfB user authentication certificate found locally." }

# Decision rules
$verdict = "Inconclusive"
if($certTrust -and $hasHelloCert){
  $verdict = "Certificate trust"
}elseif($cloudTrust -and -not $certTrust -and -not $hasHelloCert){
  $verdict = "Cloud Kerberos trust (likely)"
}elseif(-not $cloudTrust -and -not $certTrust -and -not $hasHelloCert){
  $verdict = "Key trust (likely)"
}elseif($certTrust -and -not $hasHelloCert){
  $verdict = "Certificate trust configured by policy, but no local user cert found (provisioning issue or user hasn’t enrolled)."
}elseif($cloudTrust -and $certTrust){
  $verdict = "Conflicting policies: both Cloud and Certificate trust appear enabled. Certificate trust usually wins."
}elseif(-not $certTrust -and $hasHelloCert){
  $verdict = "A WHfB-like cert exists but no cert-trust policy is visible (might be MDM/tenant-scoped or legacy config)."
}

"Trust model guess : $verdict"
"Reasons           :"
$reasons | ForEach-Object { " - $_" }

Write-Host "`nNote: Key trust & cloud trust do NOT require a per-user WHfB certificate. Certificate trust does. If CA downtime breaks WHfB and no user cert is present, check domain controller certificates (Key trust dependency) and policy conflicts." -ForegroundColor DarkGray
