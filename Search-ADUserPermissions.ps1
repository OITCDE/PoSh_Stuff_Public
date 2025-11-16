# Active Directory ACE Search Script
# Searches for all permissions a specific user has on AD objects

param(
    [Parameter(Mandatory=$true, HelpMessage="Enter the username to search for")]
    [string]$TargetUser,
    
    [Parameter(Mandatory=$false, HelpMessage="Enter the search base (e.g., 'OU=Sales,DC=contoso,DC=com')")]
    [string]$SearchBase = (Get-ADRootDSE).defaultNamingContext
)

# Import Active Directory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Active Directory module not found. Please run this script on a domain-joined computer with RSAT installed."
    exit
}

# Get the target user's SID
try {
    $userObject = Get-ADUser -Identity $TargetUser -ErrorAction Stop
    $userSID = $userObject.SID
    Write-Host "Found user: $($userObject.Name) (SID: $userSID)`n" -ForegroundColor Green
} catch {
    Write-Error "User '$TargetUser' not found in Active Directory."
    exit
}

# Function to check ACEs on an object
function Get-ACEForUser {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ObjectDN,
        
        [Parameter(Mandatory=$true)]
        [System.Security.Principal.SecurityIdentifier]$UserSID
    )
    
    try {
        $object = Get-ADObject -Identity $ObjectDN -Properties nTSecurityDescriptor -ErrorAction Stop
        $acl = $object.nTSecurityDescriptor
        
        if ($null -eq $acl) {
            return $null
        }
        
        $relevantACEs = @()
        
        foreach ($ace in $acl.Access) {
            if ($ace.IdentityReference -match $UserSID -or $ace.IdentityReference -match $TargetUser) {
                $relevantACEs += $ace
            }
        }
        
        return $relevantACEs
    } catch {
        return $null
    }
}

# Search through all AD objects
Write-Host "Searching for permissions... This may take a moment.`n" -ForegroundColor Yellow

$results = @()

try {
    # Search all AD objects (users, computers, OUs, groups, etc.)
    $allObjects = Get-ADObject -Filter * -SearchBase $SearchBase -SearchScope Subtree -ErrorAction SilentlyContinue
    
    $objectCount = $allObjects.Count
    $processedCount = 0
    
    foreach ($obj in $allObjects) {
        $processedCount++
        
        # Display progress
        if ($processedCount % 100 -eq 0) {
            Write-Progress -Activity "Searching AD Objects" -Status "Processed: $processedCount / $objectCount" -PercentComplete (($processedCount / $objectCount) * 100)
        }
        
        $aces = Get-ACEForUser -ObjectDN $obj.DistinguishedName -UserSID $userSID
        
        if ($null -ne $aces -and $aces.Count -gt 0) {
            foreach ($ace in $aces) {
                $results += [PSCustomObject]@{
                    'Object Name' = $obj.Name
                    'Object Type' = $obj.ObjectClass
                    'Distinguished Name' = $obj.DistinguishedName
                    'Rights' = $ace.ActiveDirectoryRights
                    'Access Type' = $ace.AccessControlType
                    'Inheritance' = $ace.InheritanceType
                    'Applied To' = $ace.ObjectType
                }
            }
        }
    }
    
    Write-Progress -Activity "Searching AD Objects" -Completed
    
} catch {
    Write-Error "Error during search: $_"
}

# Display results
if ($results.Count -gt 0) {
    Write-Host "Found $($results.Count) permission(s):`n" -ForegroundColor Green
    $results | Format-Table -AutoSize -Wrap
    
    # Export to CSV option
    $exportPath = "$PSScriptRoot\AD_ACE_Report_$($TargetUser)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $results | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nResults exported to: $exportPath" -ForegroundColor Cyan
} else {
    Write-Host "No permissions found for user '$TargetUser' on objects in the search base." -ForegroundColor Yellow
}
