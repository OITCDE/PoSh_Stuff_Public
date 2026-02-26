# Script: Identify Users with SPNs Not Supporting AES Encryption
# Purpose: Find primary users with RC4-only Kerberos configurations

# Requires: Active Directory module and sufficient permissions

Import-Module ActiveDirectory

# Get all users with SPNs
$usersWithSPNs = Get-ADUser -Filter {servicePrincipalName -like "*"} -Properties servicePrincipalName, msDS-SupportedEncryptionTypes

# Define encryption type constants
$encryptionTypes = @{
    1  = "DES-CBC-CRC"
    2  = "RC4-HMAC"
    4  = "AES128-CTS-HMAC-SHA1-96"
    8  = "AES256-CTS-HMAC-SHA1-96"
    16 = "FAST Armored"
    32 = "FAST KDC"
}

# Array to store results
$results = @()

foreach ($user in $usersWithSPNs) {
    if ($user.servicePrincipalName) {
        # Get the encryption types supported
        $supportedEncryption = $user."msDS-SupportedEncryptionTypes"
        
        # Check if AES is supported
        $supportsAES = ($supportedEncryption -band 12) -eq 12  # 12 = 4+8 (AES128 + AES256)
        $supportsRC4 = ($supportedEncryption -band 2) -eq 2
        
        if (-not $supportsAES) {
            $results += [PSCustomObject]@{
                SamAccountName = $user.SamAccountName
                UserPrincipalName = $user.UserPrincipalName
                SPNCount = @($user.servicePrincipalName).Count
                SPNs = $user.servicePrincipalName -join "; "
                SupportsAES = $supportsAES
                SupportsRC4 = $supportsRC4
                EncryptionTypeValue = $supportedEncryption
                EncryptionTypes = if ($supportedEncryption) {
                    ($encryptionTypes.GetEnumerator() | Where-Object { $supportedEncryption -band $_.Key } | Select-Object -ExpandProperty Value) -join ", "
                } else {
                    "Not explicitly defined (defaults to RC4)"
                }
            }
        }
    }
}

# Display results
$results | Format-Table -AutoSize

# Export to CSV for further analysis
$results | Export-Csv -Path ".\RC4_Users_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation

Write-Host "`nTotal users without AES support: $($results.Count)"
Write-Host "CSV report saved to current directory"
