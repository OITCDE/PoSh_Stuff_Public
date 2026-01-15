# Exchange 2019 Certificate Request with Multiple SANs
# Run this script from Exchange Management Shell

# Microsoft Documentation Example
# https://learn.microsoft.com/en-us/exchange/architecture/client-access/create-ca-certificate-requests

# $txtrequest = New-ExchangeCertificate -PrivateKeyExportable $True -GenerateRequest -FriendlyName "Contoso.com SAN Cert" -SubjectName "C=US,CN=mail.contoso.com" -DomainName autodiscover.contoso.com,legacy.contoso.com,mail.contoso.net,autodiscover.contoso.net,legacy.contoso.net
# [System.IO.File]::WriteAllBytes('\\FileServer01\Data\Contoso SAN Cert.req', [System.Text.Encoding]::Unicode.GetBytes($txtrequest))

# Define your domain and certificate details
$DomainName = "domain.com"
$CertificateFriendlyName = "Exchange 2019 Certificate"
$OutputPath = "C:\Scripts\ExchangeCertRequest.req"

# Define Subject Alternate Names (SANs)
# Add or remove entries as needed for your environment
$SANs = @(
    "mail.$DomainName",
    "autodiscover.$DomainName",
    "webmail.$DomainName",
    "owa.$DomainName",
    "ews.$DomainName",
    "activesync.$DomainName",
    "outlook.$DomainName",
    "smtp.$DomainName"
)

# Optionally include the internal Exchange server name
$ExchangeServerName = $env:COMPUTERNAME
$SANs += "$ExchangeServerName.$DomainName"

# Create the certificate request
Write-Host "Creating certificate request with the following SANs:" -ForegroundColor Green
$SANs | ForEach-Object { Write-Host "  - $_" -ForegroundColor Cyan }

# Generate the certificate request
$CertRequest = New-ExchangeCertificate `
    -GenerateRequest `
    -SubjectName "CN=mail.$DomainName, OU=IT, O=Ollischer IT Consulting, L=YourCity, S=YourState, C=DE" `
    -DomainName $SANs `
    -FriendlyName $CertificateFriendlyName `
    -KeySize 2048 `
    -PrivateKeyExportable $true

# Save the certificate request to a file
Set-Content -Path $OutputPath -Value $CertRequest

Write-Host "`nCertificate request created successfully!" -ForegroundColor Green
Write-Host "File saved to: $OutputPath" -ForegroundColor Yellow
Write-Host "`nNext steps:" -ForegroundColor Green
Write-Host "1. Submit the .req file to your Certificate Authority" -ForegroundColor White
Write-Host "2. Once you receive the certificate, import it using:" -ForegroundColor White
Write-Host "   Import-ExchangeCertificate -FileData ([System.IO.File]::ReadAllBytes('C:\Path\To\Certificate.cer'))" -ForegroundColor Gray
Write-Host "3. Enable the certificate for Exchange services using:" -ForegroundColor White
Write-Host "   Enable-ExchangeCertificate -Thumbprint <thumbprint> -Services IIS,SMTP" -ForegroundColor Gray
