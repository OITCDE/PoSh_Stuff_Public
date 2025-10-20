<#
.SYNOPSIS
    Installs or upgrades Exchange Management Tools with proper upgrade detection.

.DESCRIPTION
    This script detects existing Exchange Management Tools installation, compares versions,
    and performs fresh installation OR upgrade using the correct Setup.exe parameters.
    Perfect for automated PAW deployments.

.PARAMETER ISOPath
    Path to the Exchange Server ISO file.

.PARAMETER TargetDir
    Installation directory. Default: C:\Program Files\Microsoft\Exchange Server\V15

.PARAMETER OrganizationName
    Exchange Organization name (only needed for first Exchange installation in forest).

.PARAMETER SendDiagnosticData
    Whether to send diagnostic data to Microsoft. Default: $false

.PARAMETER Force
    Force installation even if the ISO version is not newer than installed version.

.PARAMETER LogPath
    Path to log file. Default: C:\Logs\ExchangeMgmtTools_Install.log

.PARAMETER InstallTimeout
    Maximum time to wait for installation in minutes. Default: 30

.EXAMPLE
    .\Install-ExchangeManagementTools.ps1 -ISOPath "D:\ExchangeServerSE-x64.iso"

.NOTES
    Author: Alexander Ollischer - Ollischer IT Consulting
    Date: 20.10.2025
    Requires: Administrative privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ISOPath,
    
    [Parameter(Mandatory=$false)]
    [string]$TargetDir = "C:\Program Files\Microsoft\Exchange Server\V15",
    
    [Parameter(Mandatory=$false)]
    [string]$OrganizationName,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendDiagnosticData = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\Logs\ExchangeMgmtTools_Install.log",
    
    [Parameter(Mandatory=$false)]
    [int]$InstallTimeout = 30
)

#region Functions

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info',
        
        [Parameter(Mandatory=$false)]
        [switch]$NoNewLine
    )
    
    # Handle empty messages (for blank lines)
    if ([string]::IsNullOrWhiteSpace($Message)) {
        $logMessage = ""
        Write-Host ""
        
        # Create log directory if it doesn't exist
        $logDir = Split-Path -Path $LogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        
        Add-Content -Path $LogPath -Value $logMessage
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Create log directory if it doesn't exist
    $logDir = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    
    # Write to log file
    Add-Content -Path $LogPath -Value $logMessage
    
    # Write to console with color
    if ($NoNewLine) {
        switch ($Level) {
            'Info'    { Write-Host $logMessage -ForegroundColor Cyan -NoNewline }
            'Warning' { Write-Host $logMessage -ForegroundColor Yellow -NoNewline }
            'Error'   { Write-Host $logMessage -ForegroundColor Red -NoNewline }
            'Success' { Write-Host $logMessage -ForegroundColor Green -NoNewline }
        }
    }
    else {
        switch ($Level) {
            'Info'    { Write-Host $logMessage -ForegroundColor Cyan }
            'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
            'Error'   { Write-Host $logMessage -ForegroundColor Red }
            'Success' { Write-Host $logMessage -ForegroundColor Green }
        }
    }
}

function Get-OSType {
    [CmdletBinding()]
    param()
    
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $productType = $os.ProductType
        
        # ProductType: 1 = Workstation, 2 = Domain Controller, 3 = Server
        if ($productType -eq 1) {
            return @{
                IsServer = $false
                IsClient = $true
                ProductType = "Client"
                Caption = $os.Caption
                Version = $os.Version
            }
        }
        else {
            return @{
                IsServer = $true
                IsClient = $false
                ProductType = "Server"
                Caption = $os.Caption
                Version = $os.Version
            }
        }
    }
    catch {
        Write-Log "Error detecting OS type: $_" -Level Warning
        return @{
            IsServer = $false
            IsClient = $true
            ProductType = "Unknown"
            Caption = "Unknown"
            Version = "Unknown"
        }
    }
}

function Get-FileVersionInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        if (-not (Test-Path $FilePath)) {
            Write-Log "File not found: $FilePath" -Level Warning
            return $null
        }
        
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath)
        
        return [PSCustomObject]@{
            FilePath = $FilePath
            FileVersion = $versionInfo.FileVersion
            ProductVersion = $versionInfo.ProductVersion
            FileMajorPart = $versionInfo.FileMajorPart
            FileMinorPart = $versionInfo.FileMinorPart
            FileBuildPart = $versionInfo.FileBuildPart
            FilePrivatePart = $versionInfo.FilePrivatePart
            VersionObject = [System.Version]::new(
                $versionInfo.FileMajorPart,
                $versionInfo.FileMinorPart,
                $versionInfo.FileBuildPart,
                $versionInfo.FilePrivatePart
            )
        }
    }
    catch {
        Write-Log "Error reading version from $FilePath : $_" -Level Error
        return $null
    }
}

function Test-ExchangeManagementToolsInstalled {
    [CmdletBinding()]
    param()
    
    # Check for ExSetup.exe in the default installation path
    $exSetupPath = Join-Path $TargetDir "Bin\ExSetup.exe"
    
    if (Test-Path $exSetupPath) {
        Write-Log "Exchange Management Tools detected at: $exSetupPath" -Level Info
        return @{
            Installed = $true
            ExSetupPath = $exSetupPath
        }
    }
    
    # Alternative check: Registry
    $regPath = "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup"
    if (Test-Path $regPath) {
        $installPath = (Get-ItemProperty -Path $regPath -Name "MsiInstallPath" -ErrorAction SilentlyContinue).MsiInstallPath
        if ($installPath) {
            $exSetupPath = Join-Path $installPath "Bin\ExSetup.exe"
            if (Test-Path $exSetupPath) {
                Write-Log "Exchange Management Tools detected via registry: $exSetupPath" -Level Info
                return @{
                    Installed = $true
                    ExSetupPath = $exSetupPath
                }
            }
        }
    }
    
    Write-Log "Exchange Management Tools not detected" -Level Info
    return @{
        Installed = $false
        ExSetupPath = $null
    }
}

function Compare-ExchangeVersions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Version]$InstalledVersion,
        
        [Parameter(Mandatory=$true)]
        [System.Version]$ISOVersion
    )
    
    Write-Log "Comparing versions:" -Level Info
    Write-Log "  Installed: $InstalledVersion" -Level Info
    Write-Log "  ISO:       $ISOVersion" -Level Info
    
    if ($ISOVersion -gt $InstalledVersion) {
        Write-Log "ISO version is NEWER - Upgrade recommended" -Level Success
        return "Newer"
    }
    elseif ($ISOVersion -eq $InstalledVersion) {
        Write-Log "ISO version is SAME - No upgrade needed" -Level Warning
        return "Same"
    }
    else {
        Write-Log "ISO version is OLDER - Downgrade not recommended" -Level Warning
        return "Older"
    }
}

function Mount-ExchangeISO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ISOPath
    )
    
    try {
        Write-Log "Mounting ISO: $ISOPath" -Level Info
        $mountResult = Mount-DiskImage -ImagePath $ISOPath -PassThru -ErrorAction Stop
        $driveLetter = ($mountResult | Get-Volume).DriveLetter
        
        if (-not $driveLetter) {
            throw "Failed to get drive letter for mounted ISO"
        }
        
        Write-Log "ISO mounted successfully at drive ${driveLetter}:" -Level Success
        return $driveLetter
    }
    catch {
        Write-Log "Failed to mount ISO: $_" -Level Error
        throw
    }
}

function Dismount-ExchangeISO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ISOPath
    )
    
    try {
        Write-Log "Dismounting ISO: $ISOPath" -Level Info
        Dismount-DiskImage -ImagePath $ISOPath -ErrorAction Stop | Out-Null
        Write-Log "ISO dismounted successfully" -Level Success
    }
    catch {
        Write-Log "Failed to dismount ISO: $_" -Level Warning
    }
}

function Wait-ExchangeSetupCompletion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$ProcessId,
        
        [Parameter(Mandatory=$false)]
        [int]$TimeoutMinutes = 30
    )
    
    Write-Log "Monitoring Exchange Setup process (PID: $ProcessId)..." -Level Info
    Write-Log "Timeout: $TimeoutMinutes minutes" -Level Info
    
    $setupLogPath = "C:\ExchangeSetupLogs\ExchangeSetup.log"
    $startTime = Get-Date
    $lastLogSize = 0
    
    # Wait for log file to be created
    Write-Log "Waiting for setup log file to be created..." -Level Info
    $logWaitCount = 0
    while (-not (Test-Path $setupLogPath) -and $logWaitCount -lt 120) {
        Start-Sleep -Seconds 1
        $logWaitCount++
        
        # Check if process is still running
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $process) {
            Write-Log "Setup process exited before creating log file" -Level Warning
            return $true
        }
    }
    
    if (Test-Path $setupLogPath) {
        Write-Log "Setup log file detected: $setupLogPath" -Level Success
        Write-Log "Monitoring installation progress..." -Level Info
        Write-Log ""
    }
    else {
        Write-Log "Setup log file not created after 2 minutes - continuing anyway" -Level Warning
    }
    
    $lastLogLine = ""
    
    while ($true) {
        # Check if process is still running
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        
        if (-not $process) {
            Write-Log ""
            Write-Log "Setup process has exited" -Level Info
            
            # Give it a few seconds for final log writes
            Start-Sleep -Seconds 5
            
            # Check for any lingering Exchange setup processes
            $exSetupProcesses = Get-Process -Name "ExSetup" -ErrorAction SilentlyContinue
            if ($exSetupProcesses) {
                Write-Log "Waiting for ExSetup child processes to complete..." -Level Info
                $exSetupProcesses | Wait-Process -Timeout 300 -ErrorAction SilentlyContinue
            }
            
            break
        }
        
        # Check timeout
        $elapsed = (Get-Date) - $startTime
        if ($elapsed.TotalMinutes -ge $TimeoutMinutes) {
            Write-Log ""
            Write-Log "Installation timeout reached ($TimeoutMinutes minutes)" -Level Error
            return $false
        }
        
        # Monitor log file for activity
        if (Test-Path $setupLogPath) {
            $currentLogSize = (Get-Item $setupLogPath).Length
            
            if ($currentLogSize -gt $lastLogSize) {
                # Log file is growing - activity detected
                $lastLogSize = $currentLogSize
                
                # Try to read last line for progress indication
                try {
                    $lastLines = Get-Content $setupLogPath -Tail 3 -ErrorAction SilentlyContinue
                    foreach ($line in $lastLines) {
                        if ($line -ne $lastLogLine -and $line.Trim() -ne "") {
                            # Show progress for interesting lines
                            if ($line -match 'Copying|Installing|Configuring|Completed|Performing|Starting|Updating') {
                                Write-Host "." -NoNewline -ForegroundColor Gray
                                if ($line -match 'Completed') {
                                    Write-Host "✓" -NoNewline -ForegroundColor Green
                                }
                            }
                            $lastLogLine = $line
                        }
                    }
                }
                catch {
                    # Ignore errors reading log file
                }
            }
        }
        
        # Show heartbeat
        Write-Host "." -NoNewline -ForegroundColor DarkGray
        
        Start-Sleep -Seconds 5
    }
    
    Write-Log ""
    Write-Log "Setup process monitoring completed" -Level Success
    return $true
}

function Get-ExchangeSetupExitCode {
    [CmdletBinding()]
    param()
    
    $setupLogPath = "C:\ExchangeSetupLogs\ExchangeSetup.log"
    
    if (-not (Test-Path $setupLogPath)) {
        Write-Log "Setup log file not found at: $setupLogPath" -Level Warning
        return $null
    }
    
    try {
        # Read last 100 lines of log to find completion status
        $logContent = Get-Content $setupLogPath -Tail 100
        
        foreach ($line in $logContent) {
            # Look for completion messages
            if ($line -match "The Exchange Server setup operation completed successfully") {
                return 0
            }
            if ($line -match "Setup has failed|Setup failed|The Exchange Server setup operation didn't complete") {
                return 1
            }
            if ($line -match "Setup completed with warnings") {
                return 0  # Warnings are OK
            }
        }
        
        # Check for errors in last lines
        $errors = $logContent | Where-Object { $_ -match '\[ERROR\]' }
        if ($errors) {
            Write-Log "Errors found in setup log:" -Level Error
            foreach ($error in $errors | Select-Object -Last 3) {
                Write-Log "  $error" -Level Error
            }
            return 1
        }
        
        # No explicit status found - assume success if no errors
        return 0
    }
    catch {
        Write-Log "Error reading setup log: $_" -Level Warning
        return $null
    }
}

function Install-ExchangeManagementTools {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SetupPath,
        
        [Parameter(Mandatory=$false)]
        [string]$TargetDir,
        
        [Parameter(Mandatory=$false)]
        [string]$OrganizationName,
        
        [Parameter(Mandatory=$false)]
        [bool]$SendDiagnosticData,
        
        [Parameter(Mandatory=$false)]
        [bool]$IsClientOS,
        
        [Parameter(Mandatory=$false)]
        [bool]$IsUpgrade,
        
        [Parameter(Mandatory=$false)]
        [int]$TimeoutMinutes = 30
    )
    
    # Build command arguments based on upgrade vs fresh install
    $arguments = @()
    
    if ($IsUpgrade) {
        # For UPGRADES: Use /Mode:Upgrade (no /Role parameter!)
        Write-Log "Configuring UPGRADE mode" -Level Info
        $arguments += "/Mode:Upgrade"
    }
    else {
        # For FRESH INSTALL: Use /Role:ManagementTools
        Write-Log "Configuring FRESH INSTALL mode" -Level Info
        $arguments += "/Role:ManagementTools"
        
        # Add organization name if specified (only for fresh install)
        if ($OrganizationName) {
            $arguments += "/OrganizationName:`"$OrganizationName`""
            Write-Log "Organization name: $OrganizationName" -Level Info
        }
        
        # Add target directory if specified and not default (only for fresh install)
        if ($TargetDir -and $TargetDir -ne "C:\Program Files\Microsoft\Exchange Server\V15") {
            $arguments += "/TargetDir:`"$TargetDir`""
            Write-Log "Custom installation directory: $TargetDir" -Level Info
        }
    }
    
    # Add /InstallWindowsComponents ONLY for Server OS and NOT for upgrades
    if (-not $IsClientOS -and -not $IsUpgrade) {
        $arguments += "/InstallWindowsComponents"
        Write-Log "Server OS detected - Will auto-install Windows components" -Level Info
    }
    elseif ($IsClientOS) {
        Write-Log "Client OS detected - Skipping /InstallWindowsComponents switch" -Level Info
    }
    
    # Add license acceptance with diagnostic data choice
    if ($SendDiagnosticData) {
        $arguments += "/IAcceptExchangeServerLicenseTerms_DiagnosticDataON"
        Write-Log "Diagnostic data reporting: ENABLED" -Level Info
    } else {
        $arguments += "/IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF"
        Write-Log "Diagnostic data reporting: DISABLED" -Level Info
    }
    
    $commandLine = "$SetupPath $($arguments -join ' ')"
    Write-Log "Executing: $commandLine" -Level Info
    Write-Log "Installation started at $(Get-Date -Format 'HH:mm:ss')" -Level Info
    Write-Log ""
    
    # Ensure log directory exists
    $setupLogDir = "C:\ExchangeSetupLogs"
    if (-not (Test-Path $setupLogDir)) {
        Write-Log "Creating ExchangeSetupLogs directory..." -Level Info
        New-Item -Path $setupLogDir -ItemType Directory -Force | Out-Null
    }
    
    Write-Log "Starting Exchange Setup process..." -Level Info
    if ($IsUpgrade) {
        Write-Log "This is an UPGRADE - may take 10-20 minutes. Please be patient..." -Level Warning
    }
    else {
        Write-Log "This is a FRESH INSTALL - may take 5-15 minutes. Please be patient..." -Level Warning
    }
    Write-Log ""
    
    try {
        # Start the process without waiting
        $process = Start-Process -FilePath $SetupPath -ArgumentList $arguments -PassThru -NoNewWindow
        
        if (-not $process) {
            Write-Log "Failed to start setup process" -Level Error
            return $false
        }
        
        Write-Log "Setup process started (PID: $($process.Id))" -Level Success
        Write-Log ""
        
        # Monitor the installation process
        $monitorResult = Wait-ExchangeSetupCompletion -ProcessId $process.Id -TimeoutMinutes $TimeoutMinutes
        
        if (-not $monitorResult) {
            Write-Log "Setup monitoring indicated a timeout or failure" -Level Error
            return $false
        }
        
        # Get the actual exit code from log file
        Write-Log ""
        Write-Log "Analyzing setup results..." -Level Info
        $exitCode = Get-ExchangeSetupExitCode
        
        if ($exitCode -eq 0) {
            Write-Log "Exchange Management Tools installation/upgrade completed successfully!" -Level Success
            return $true
        }
        elseif ($null -eq $exitCode) {
            Write-Log "Could not determine exit code from log - checking installation..." -Level Warning
            # We'll verify the installation in the main script
            return $true
        }
        else {
            Write-Log "Installation failed with exit code: $exitCode" -Level Error
            Write-Log "Review setup logs at: C:\ExchangeSetupLogs\ExchangeSetup.log" -Level Warning
            
            # Show last 30 lines of log
            Write-Log ""
            Write-Log "Last lines from setup log:" -Level Info
            try {
                $lastLines = Get-Content "C:\ExchangeSetupLogs\ExchangeSetup.log" -Tail 30 -ErrorAction SilentlyContinue
                foreach ($line in $lastLines) {
                    if ($line -match '\[ERROR\]|\[WARNING\]|failed|error') {
                        Write-Log "  $line" -Level Warning
                    }
                }
            }
            catch {
                Write-Log "Could not read setup log" -Level Warning
            }
            
            return $false
        }
    }
    catch {
        Write-Log "Installation error: $_" -Level Error
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
        return $false
    }
}

#endregion

#region Main Script

Write-Log "========================================" -Level Info
Write-Log "Exchange Management Tools Install/Upgrade Script" -Level Info
Write-Log "========================================" -Level Info
Write-Log "Script started by: $env:USERNAME" -Level Info
Write-Log "Computer: $env:COMPUTERNAME" -Level Info
Write-Log "ISO Path: $ISOPath" -Level Info

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "ERROR: This script must be run as Administrator" -Level Error
    exit 1
}

Write-Log "Running with Administrator privileges ✓" -Level Success

# Detect OS Type
Write-Log ""
Write-Log "Detecting Operating System..." -Level Info
$osInfo = Get-OSType
Write-Log "OS: $($osInfo.Caption)" -Level Info
Write-Log "OS Version: $($osInfo.Version)" -Level Info
Write-Log "OS Type: $($osInfo.ProductType)" -Level Info

if ($osInfo.IsClient) {
    Write-Log "Client OS detected - This is typical for PAW deployments ✓" -Level Success
}

# Step 1: Check if Exchange Management Tools are installed
Write-Log ""
Write-Log "Step 1: Checking for existing Exchange Management Tools installation..." -Level Info
$installStatus = Test-ExchangeManagementToolsInstalled

$installedVersion = $null
$isUpgrade = $false

if ($installStatus.Installed) {
    $installedVersionInfo = Get-FileVersionInfo -FilePath $installStatus.ExSetupPath
    if ($installedVersionInfo) {
        $installedVersion = $installedVersionInfo.VersionObject
        Write-Log "Installed Version: $($installedVersionInfo.FileVersion) (Build $installedVersion)" -Level Success
        $isUpgrade = $true
    }
    else {
        Write-Log "Could not determine installed version" -Level Warning
    }
}
else {
    Write-Log "No existing installation found - Fresh install will be performed" -Level Info
    $isUpgrade = $false
}

# Step 2: Mount ISO and read version
Write-Log ""
Write-Log "Step 2: Mounting ISO and reading version..." -Level Info

$driveLetter = $null
$isoVersion = $null

try {
    $driveLetter = Mount-ExchangeISO -ISOPath $ISOPath
    $isoSetupPath = "${driveLetter}:\Setup.exe"
    
    if (-not (Test-Path $isoSetupPath)) {
        throw "Setup.exe not found in ISO at: $isoSetupPath"
    }
    
    $isoVersionInfo = Get-FileVersionInfo -FilePath $isoSetupPath
    if ($isoVersionInfo) {
        $isoVersion = $isoVersionInfo.VersionObject
        Write-Log "ISO Version: $($isoVersionInfo.FileVersion) (Build $isoVersion)" -Level Success
    }
    else {
        throw "Could not determine ISO version"
    }
    
    # Step 3: Compare versions and decide action
    Write-Log ""
    Write-Log "Step 3: Version comparison and decision..." -Level Info
    
    $shouldInstall = $false
    $installReason = ""
    
    if (-not $installStatus.Installed) {
        $shouldInstall = $true
        $installReason = "Fresh installation (no existing installation detected)"
        Write-Log $installReason -Level Info
    }
    elseif ($installedVersion -eq $null) {
        if ($Force) {
            $shouldInstall = $true
            $installReason = "Forced installation (could not determine installed version)"
            Write-Log $installReason -Level Warning
        }
        else {
            Write-Log "Cannot determine installed version and -Force not specified. Aborting." -Level Error
            exit 1
        }
    }
    else {
        $comparison = Compare-ExchangeVersions -InstalledVersion $installedVersion -ISOVersion $isoVersion
        
        switch ($comparison) {
            "Newer" {
                $shouldInstall = $true
                $installReason = "Upgrade (ISO version is newer than installed version)"
                Write-Log $installReason -Level Success
            }
            "Same" {
                if ($Force) {
                    $shouldInstall = $true
                    $installReason = "Forced reinstallation (versions are the same, but -Force specified)"
                    Write-Log $installReason -Level Warning
                }
                else {
                    Write-Log "ISO version matches installed version. No action needed." -Level Info
                    Write-Log "Use -Force to reinstall anyway." -Level Info
                }
            }
            "Older" {
                if ($Force) {
                    $shouldInstall = $true
                    $installReason = "Forced downgrade (ISO version is older, but -Force specified)"
                    Write-Log $installReason -Level Warning
                    Write-Log "WARNING: Downgrading is not recommended!" -Level Warning
                }
                else {
                    Write-Log "ISO version is older than installed version. Downgrade not recommended." -Level Warning
                    Write-Log "Use -Force to downgrade anyway (not recommended)." -Level Info
                }
            }
        }
    }
    
    # Step 4: Perform installation/upgrade if needed
    if ($shouldInstall) {
        Write-Log ""
        Write-Log "Step 4: Performing installation/upgrade..." -Level Info
        Write-Log "Reason: $installReason" -Level Info
        Write-Log "Mode: $(if($isUpgrade){'UPGRADE'}else{'FRESH INSTALL'})" -Level Info
        Write-Log ""
        
        $installSuccess = Install-ExchangeManagementTools `
            -SetupPath $isoSetupPath `
            -TargetDir $TargetDir `
            -OrganizationName $OrganizationName `
            -SendDiagnosticData $SendDiagnosticData.IsPresent `
            -IsClientOS $osInfo.IsClient `
            -IsUpgrade $isUpgrade `
            -TimeoutMinutes $InstallTimeout
        
        if ($installSuccess) {
            Write-Log ""
            Write-Log "========================================" -Level Success
            Write-Log "Installation/Upgrade completed successfully!" -Level Success
            Write-Log "========================================" -Level Success
            
            # Verify new installation
            Write-Log ""
            Write-Log "Verifying installation..." -Level Info
            Start-Sleep -Seconds 5  # Give registry time to update
            
            $newInstallStatus = Test-ExchangeManagementToolsInstalled
            if ($newInstallStatus.Installed) {
                $newVersionInfo = Get-FileVersionInfo -FilePath $newInstallStatus.ExSetupPath
                if ($newVersionInfo) {
                    Write-Log "Verified Version: $($newVersionInfo.FileVersion)" -Level Success
                    Write-Log "Installation Path: $($newInstallStatus.ExSetupPath)" -Level Success
                }
            }
            else {
                Write-Log "Warning: Installation reported success but verification failed" -Level Warning
                Write-Log "Check C:\ExchangeSetupLogs\ExchangeSetup.log for details" -Level Warning
            }
            
            Write-Log ""
            Write-Log "Next Steps:" -Level Info
            Write-Log "  1. Close and reopen PowerShell/PowerShell ISE" -Level Info
            Write-Log "  2. Load Exchange snap-in: Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn" -Level Info
            Write-Log "  3. Test with: Get-Command *-Mailbox" -Level Info
            
            $exitCode = 0
        }
        else {
            Write-Log ""
            Write-Log "========================================" -Level Error
            Write-Log "Installation/Upgrade FAILED" -Level Error
            Write-Log "========================================" -Level Error
            Write-Log "Check logs at:" -Level Error
            Write-Log "  - Script log: $LogPath" -Level Error
            Write-Log "  - Setup log: C:\ExchangeSetupLogs\ExchangeSetup.log" -Level Error
            Write-Log ""
            Write-Log "Troubleshooting steps:" -Level Warning
            Write-Log "  1. Review C:\ExchangeSetupLogs\ExchangeSetup.log for detailed errors" -Level Warning
            Write-Log "  2. Ensure Domain Controller is reachable" -Level Warning
            Write-Log "  3. Verify account has necessary AD permissions" -Level Warning
            Write-Log "  4. Check Windows Event Logs (Application and System)" -Level Warning
            $exitCode = 1
        }
    }
    else {
        Write-Log ""
        Write-Log "========================================" -Level Info
        Write-Log "No installation performed" -Level Info
        Write-Log "========================================" -Level Info
        $exitCode = 0
    }
}
catch {
    Write-Log "Critical error: $_" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    $exitCode = 1
}
finally {
    # Always dismount ISO
    if ($driveLetter) {
        Write-Log ""
        Dismount-ExchangeISO -ISOPath $ISOPath
    }
    
    Write-Log ""
    Write-Log "Script completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Info
    Write-Log "Full log available at: $LogPath" -Level Info
}

exit $exitCode

#endregion
