<#
.SYNOPSIS
    Windows Build Review Script - Security Configuration Assessment
    
.DESCRIPTION
    Performs a comprehensive security configuration review of Windows systems
    based on CIS Benchmarks, DISA STIG, and NCSC guidelines.
    Designed for authorised penetration testing and security assessments only.
    
.PARAMETER OutputPath
    Path for the output report file. Defaults to current directory with timestamp.
    
.PARAMETER SkipPrivEsc
    Skip privilege escalation checks (useful when running as admin only).
    
.PARAMETER HTMLReport
    Generate an HTML report in addition to the text report.
    
.EXAMPLE
    .\Windows-Build-Review.ps1
    
.EXAMPLE
    .\Windows-Build-Review.ps1 -OutputPath "C:\Temp\review.txt" -HTMLReport
    
.NOTES
    Version: 1.0.0
    Author: Security Assessment Script
    Requires: PowerShell 5.1+
    Run as Administrator for comprehensive results
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipPrivEsc,
    
    [Parameter(Mandatory = $false)]
    [switch]$HTMLReport
)

#===============================================================================
# Configuration
#===============================================================================
$Script:Version = "1.0.0"
$Script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:Hostname = $env:COMPUTERNAME
$Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Script:OutputBuffer = New-Object System.Text.StringBuilder
$Script:Findings = @()

if ([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = Join-Path $PWD "Windows-Review-$Hostname-$Timestamp.txt"
}

#===============================================================================
# Output Functions
#===============================================================================
function Write-Banner {
    param([string]$Text)
    $line = "=" * 80
    $output = "`n$line`n $Text`n$line`n"
    Write-Host $output -ForegroundColor Cyan
    [void]$Script:OutputBuffer.AppendLine($output)
}

function Write-Section {
    param([string]$Text)
    $output = "`n--- $Text ---`n"
    Write-Host $output -ForegroundColor Magenta
    [void]$Script:OutputBuffer.AppendLine($output)
}

function Write-SubSection {
    param([string]$Text)
    $output = "`n>> $Text"
    Write-Host $output -ForegroundColor Yellow
    [void]$Script:OutputBuffer.AppendLine($output)
}

function Write-Finding {
    param(
        [ValidateSet("Critical", "High", "Medium", "Low", "Info", "Pass", "Check")]
        [string]$Severity,
        [string]$Title,
        [string]$Detail = ""
    )
    
    $severityColors = @{
        "Critical" = "Red"
        "High"     = "DarkYellow"
        "Medium"   = "Yellow"
        "Low"      = "Cyan"
        "Info"     = "Blue"
        "Pass"     = "Green"
        "Check"    = "Magenta"
    }
    
    $tag = "[$($Severity.ToUpper())]"
    $color = $severityColors[$Severity]
    
    Write-Host "$tag " -ForegroundColor $color -NoNewline
    Write-Host $Title
    [void]$Script:OutputBuffer.AppendLine("$tag $Title")
    
    if ($Detail) {
        Write-Host "    $Detail" -ForegroundColor DarkGray
        [void]$Script:OutputBuffer.AppendLine("    $Detail")
    }
    
    # Store finding for summary
    $Script:Findings += [PSCustomObject]@{
        Severity = $Severity
        Title    = $Title
        Detail   = $Detail
    }
}

function Write-Output-Data {
    param([string]$Data)
    if ($Data) {
        $lines = $Data -split "`n"
        foreach ($line in $lines) {
            if ($line.Trim()) {
                Write-Host "    $line" -ForegroundColor DarkGray
                [void]$Script:OutputBuffer.AppendLine("    $line")
            }
        }
    }
}

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $value.$Name
    }
    catch {
        return $null
    }
}

function Get-ServiceBinaryPath {
    param([string]$PathName)
    if ($PathName -match '^"([^"]+)"') {
        return $Matches[1]
    }
    elseif ($PathName -match '^([^ ]+)') {
        return $Matches[1]
    }
    return $PathName
}

#===============================================================================
# PHASE 1: OPERATING SYSTEM AND PATCH LEVEL
#===============================================================================
function Invoke-Phase1-PatchLevel {
    Write-Banner "PHASE 1: OPERATING SYSTEM AND PATCH LEVEL"
    
    Write-Section "1.1 Operating System Information"
    
    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem
        $csInfo = Get-CimInstance Win32_ComputerSystem
        
        Write-Finding -Severity "Info" -Title "Operating System: $($osInfo.Caption)"
        Write-Finding -Severity "Info" -Title "Version: $($osInfo.Version) (Build $($osInfo.BuildNumber))"
        Write-Finding -Severity "Info" -Title "Architecture: $($osInfo.OSArchitecture)"
        Write-Finding -Severity "Info" -Title "Install Date: $($osInfo.InstallDate)"
        Write-Finding -Severity "Info" -Title "Last Boot: $($osInfo.LastBootUpTime)"
        
        # Domain membership
        if ($csInfo.PartOfDomain) {
            Write-Finding -Severity "Info" -Title "Domain: $($csInfo.Domain)"
        }
        else {
            Write-Finding -Severity "Info" -Title "Workgroup: $($csInfo.Workgroup) (Not domain joined)"
        }
        
        # Check for EOL versions
        $build = [int]$osInfo.BuildNumber
        if ($osInfo.Caption -match "Windows Server 2008|Windows Server 2003|Windows XP|Windows 7|Windows 8(?!\.1)") {
            Write-Finding -Severity "Critical" -Title "End-of-Life Operating System Detected" -Detail "This OS version is no longer supported and does not receive security updates"
        }
        elseif ($osInfo.Caption -match "Windows Server 2012(?! R2)") {
            Write-Finding -Severity "High" -Title "Windows Server 2012 (non-R2) - Extended Support Ended" -Detail "Upgrade to a supported version"
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not retrieve OS information: $_"
    }
    
    Write-Section "1.2 Installed Hotfixes"
    
    try {
        $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue
        $recentHotfixes = $hotfixes | Select-Object -First 10
        
        Write-Finding -Severity "Info" -Title "Total Hotfixes Installed: $($hotfixes.Count)"
        
        if ($recentHotfixes) {
            Write-Finding -Severity "Info" -Title "Most Recent Hotfixes:"
            $hotfixOutput = $recentHotfixes | Format-Table HotFixID, Description, InstalledOn -AutoSize | Out-String
            Write-Output-Data $hotfixOutput
        }
        
        # Check last patch date
        $lastPatch = $hotfixes | Where-Object { $_.InstalledOn } | Select-Object -First 1
        if ($lastPatch) {
            $daysSinceUpdate = (Get-Date) - $lastPatch.InstalledOn
            if ($daysSinceUpdate.Days -gt 90) {
                Write-Finding -Severity "High" -Title "System Not Patched in $($daysSinceUpdate.Days) Days" -Detail "Last update: $($lastPatch.InstalledOn)"
            }
            elseif ($daysSinceUpdate.Days -gt 30) {
                Write-Finding -Severity "Medium" -Title "System Not Patched in $($daysSinceUpdate.Days) Days" -Detail "Last update: $($lastPatch.InstalledOn)"
            }
            else {
                Write-Finding -Severity "Pass" -Title "System patched within last 30 days" -Detail "Last update: $($lastPatch.InstalledOn)"
            }
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not retrieve hotfix information"
    }
    
    Write-Section "1.3 Pending Updates"
    
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $pendingUpdates = $updateSearcher.Search("IsInstalled=0 and Type='Software'").Updates
        
        if ($pendingUpdates.Count -gt 0) {
            Write-Finding -Severity "Medium" -Title "$($pendingUpdates.Count) Pending Updates Available"
            
            $criticalUpdates = $pendingUpdates | Where-Object { $_.MsrcSeverity -eq "Critical" }
            if ($criticalUpdates.Count -gt 0) {
                Write-Finding -Severity "High" -Title "$($criticalUpdates.Count) Critical Updates Pending"
                foreach ($update in $criticalUpdates | Select-Object -First 5) {
                    Write-Output-Data "  - $($update.Title)"
                }
            }
        }
        else {
            Write-Finding -Severity "Pass" -Title "No pending updates detected"
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not check pending updates (may require Windows Update service)"
    }
    
    Write-Section "1.4 Installed Software"
    
    try {
        $software = @()
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($path in $regPaths) {
            $software += Get-ItemProperty $path -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher
        }
        
        $software = $software | Sort-Object DisplayName -Unique
        Write-Finding -Severity "Info" -Title "Installed Applications: $($software.Count)"
        
        # Check for known vulnerable software
        $riskyApps = $software | Where-Object { 
            $_.DisplayName -match "Java [678]\.|Adobe Flash|Adobe Reader (9|X|XI|2015)|Silverlight|QuickTime"
        }
        
        if ($riskyApps) {
            Write-Finding -Severity "High" -Title "Potentially Vulnerable Software Detected:"
            foreach ($app in $riskyApps) {
                Write-Output-Data "  - $($app.DisplayName) v$($app.DisplayVersion)"
            }
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not enumerate installed software"
    }
}

#===============================================================================
# PHASE 2: USER AND ACCOUNT REVIEW
#===============================================================================
function Invoke-Phase2-UserReview {
    Write-Banner "PHASE 2: USER AND ACCOUNT REVIEW"
    
    Write-Section "2.1 Local User Accounts"
    
    try {
        $localUsers = Get-LocalUser -ErrorAction Stop
        
        Write-Finding -Severity "Info" -Title "Local User Accounts Found: $($localUsers.Count)"
        $userOutput = $localUsers | Format-Table Name, Enabled, PasswordRequired, PasswordExpires, LastLogon -AutoSize | Out-String
        Write-Output-Data $userOutput
        
        # Built-in Administrator account
        $adminAccount = $localUsers | Where-Object { $_.SID -like "*-500" }
        if ($adminAccount) {
            if ($adminAccount.Enabled) {
                if ($adminAccount.Name -eq "Administrator") {
                    Write-Finding -Severity "Medium" -Title "Built-in Administrator Account Enabled with Default Name" -Detail "Consider renaming and disabling"
                }
                else {
                    Write-Finding -Severity "Low" -Title "Built-in Administrator Account Enabled (Renamed to: $($adminAccount.Name))"
                }
            }
            else {
                Write-Finding -Severity "Pass" -Title "Built-in Administrator account is disabled"
            }
        }
        
        # Guest account
        $guestAccount = $localUsers | Where-Object { $_.SID -like "*-501" }
        if ($guestAccount -and $guestAccount.Enabled) {
            Write-Finding -Severity "High" -Title "Guest Account is Enabled" -Detail "Guest account should be disabled"
        }
        else {
            Write-Finding -Severity "Pass" -Title "Guest account is disabled"
        }
        
        # Accounts without password required
        $noPassRequired = $localUsers | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled }
        if ($noPassRequired) {
            Write-Finding -Severity "High" -Title "Accounts Without Password Requirement:"
            foreach ($user in $noPassRequired) {
                Write-Output-Data "  - $($user.Name)"
            }
        }
        
        # Accounts with non-expiring passwords
        $nonExpiring = $localUsers | Where-Object { $_.PasswordExpires -eq $null -and $_.Enabled }
        if ($nonExpiring) {
            Write-Finding -Severity "Low" -Title "Accounts with Non-Expiring Passwords: $($nonExpiring.Count)"
            foreach ($user in $nonExpiring | Select-Object -First 10) {
                Write-Output-Data "  - $($user.Name)"
            }
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not enumerate local users (Get-LocalUser may not be available)"
        # Fallback to net user
        try {
            $netUsers = net user 2>$null
            Write-Output-Data ($netUsers | Out-String)
        }
        catch { }
    }
    
    Write-Section "2.2 Local Group Membership"
    
    try {
        $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        Write-Finding -Severity "Info" -Title "Local Administrators Group Members: $($adminGroup.Count)"
        $adminOutput = $adminGroup | Format-Table Name, ObjectClass, PrincipalSource -AutoSize | Out-String
        Write-Output-Data $adminOutput
        
        if ($adminGroup.Count -gt 5) {
            Write-Finding -Severity "Medium" -Title "Excessive Local Administrator Accounts" -Detail "$($adminGroup.Count) members in Administrators group"
        }
        
        # Remote Desktop Users
        $rdpGroup = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
        if ($rdpGroup) {
            Write-Finding -Severity "Info" -Title "Remote Desktop Users: $($rdpGroup.Count)"
            $rdpOutput = $rdpGroup | Format-Table Name, ObjectClass -AutoSize | Out-String
            Write-Output-Data $rdpOutput
        }
        
        # Remote Management Users
        $winrmGroup = Get-LocalGroupMember -Group "Remote Management Users" -ErrorAction SilentlyContinue
        if ($winrmGroup) {
            Write-Finding -Severity "Info" -Title "Remote Management Users: $($winrmGroup.Count)"
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not enumerate local groups"
    }
    
    Write-Section "2.3 Password Policy"
    
    try {
        $netAccounts = net accounts 2>&1
        Write-Finding -Severity "Info" -Title "Local Password Policy:"
        Write-Output-Data ($netAccounts | Out-String)
        
        # Parse and evaluate
        if ($netAccounts -match "Minimum password length:\s*(\d+)") {
            $minLength = [int]$Matches[1]
            if ($minLength -lt 14) {
                Write-Finding -Severity "Medium" -Title "Minimum Password Length Too Short: $minLength" -Detail "CIS recommends 14+ characters"
            }
            else {
                Write-Finding -Severity "Pass" -Title "Minimum password length meets requirements: $minLength"
            }
        }
        
        if ($netAccounts -match "Lockout threshold:\s*(\w+)") {
            $lockout = $Matches[1]
            if ($lockout -eq "Never") {
                Write-Finding -Severity "Medium" -Title "Account Lockout Threshold Not Configured" -Detail "Accounts are not locked after failed attempts"
            }
            elseif ([int]$lockout -gt 5) {
                Write-Finding -Severity "Low" -Title "Account Lockout Threshold May Be Too High: $lockout"
            }
            else {
                Write-Finding -Severity "Pass" -Title "Account lockout threshold configured: $lockout"
            }
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not retrieve password policy"
    }
}

#===============================================================================
# PHASE 3: REMOTE ACCESS CONFIGURATION
#===============================================================================
function Invoke-Phase3-RemoteAccess {
    Write-Banner "PHASE 3: REMOTE ACCESS CONFIGURATION"
    
    Write-Section "3.1 RDP Configuration"
    
    # RDP Enabled
    $rdpEnabled = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
    if ($rdpEnabled -eq 0) {
        Write-Finding -Severity "Info" -Title "RDP is Enabled"
        
        # NLA Requirement
        $nlaRequired = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication"
        if ($nlaRequired -eq 1) {
            Write-Finding -Severity "Pass" -Title "Network Level Authentication (NLA) is required"
        }
        else {
            Write-Finding -Severity "High" -Title "Network Level Authentication (NLA) Not Required" -Detail "RDP connections can be made without pre-authentication"
        }
        
        # Encryption Level
        $encLevel = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel"
        $encLevels = @{ 1 = "Low"; 2 = "Client Compatible"; 3 = "High"; 4 = "FIPS" }
        if ($encLevel) {
            if ($encLevel -lt 3) {
                Write-Finding -Severity "Medium" -Title "RDP Encryption Level: $($encLevels[$encLevel])" -Detail "Consider setting to High or FIPS"
            }
            else {
                Write-Finding -Severity "Pass" -Title "RDP Encryption Level: $($encLevels[$encLevel])"
            }
        }
        
        # Security Layer
        $secLayer = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer"
        $secLayers = @{ 0 = "RDP"; 1 = "Negotiate"; 2 = "TLS" }
        if ($secLayer -ne $null) {
            if ($secLayer -lt 2) {
                Write-Finding -Severity "Medium" -Title "RDP Security Layer: $($secLayers[$secLayer])" -Detail "Consider enforcing TLS"
            }
            else {
                Write-Finding -Severity "Pass" -Title "RDP Security Layer: TLS"
            }
        }
    }
    else {
        Write-Finding -Severity "Pass" -Title "RDP is Disabled"
    }
    
    Write-Section "3.2 WinRM Configuration"
    
    try {
        $winrmService = Get-Service WinRM -ErrorAction Stop
        if ($winrmService.Status -eq "Running") {
            Write-Finding -Severity "Info" -Title "WinRM Service is Running"
            
            # Check listeners
            try {
                $listeners = winrm enumerate winrm/config/listener 2>&1
                if ($listeners -match "HTTPS") {
                    Write-Finding -Severity "Pass" -Title "WinRM HTTPS listener configured"
                }
                elseif ($listeners -match "HTTP") {
                    Write-Finding -Severity "Medium" -Title "WinRM Using HTTP (Unencrypted)" -Detail "Configure HTTPS listener for encrypted management"
                }
            }
            catch { }
        }
        else {
            Write-Finding -Severity "Info" -Title "WinRM Service is not running"
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not check WinRM status"
    }
    
    Write-Section "3.3 SSH Configuration"
    
    try {
        $sshService = Get-Service sshd -ErrorAction SilentlyContinue
        if ($sshService) {
            if ($sshService.Status -eq "Running") {
                Write-Finding -Severity "Info" -Title "OpenSSH Server is Running"
            }
            else {
                Write-Finding -Severity "Info" -Title "OpenSSH Server installed but not running"
            }
        }
    }
    catch { }
}

#===============================================================================
# PHASE 4: SECURITY CONFIGURATION
#===============================================================================
function Invoke-Phase4-SecurityConfig {
    Write-Banner "PHASE 4: SECURITY CONFIGURATION"
    
    Write-Section "4.1 LSA Protection and Credential Security"
    
    # WDigest
    $wdigest = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential"
    if ($wdigest -eq 1) {
        Write-Finding -Severity "Critical" -Title "WDigest Authentication Enabled" -Detail "Cleartext credentials stored in LSASS memory"
    }
    elseif ($wdigest -eq 0) {
        Write-Finding -Severity "Pass" -Title "WDigest authentication is disabled"
    }
    else {
        Write-Finding -Severity "Pass" -Title "WDigest not configured (disabled by default on Windows 8.1+)"
    }
    
    # LSA Protection (RunAsPPL)
    $lsaPPL = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
    if ($lsaPPL -eq 1) {
        Write-Finding -Severity "Pass" -Title "LSA Protection (RunAsPPL) is enabled"
    }
    else {
        Write-Finding -Severity "High" -Title "LSA Protection (RunAsPPL) Not Enabled" -Detail "LSASS process not protected against credential dumping"
    }
    
    # Credential Guard
    try {
        $credGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        if ($credGuard.SecurityServicesRunning -contains 1) {
            Write-Finding -Severity "Pass" -Title "Credential Guard is running"
        }
        else {
            Write-Finding -Severity "High" -Title "Credential Guard Not Running" -Detail "Credentials not protected by virtualisation-based security"
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not check Credential Guard status (may require compatible hardware)"
    }
    
    # Cached Credentials
    $cachedLogons = Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount"
    if ($cachedLogons) {
        if ([int]$cachedLogons -gt 4) {
            Write-Finding -Severity "Low" -Title "Cached Logons Count: $cachedLogons" -Detail "Consider reducing on servers (CIS recommends 4 or less)"
        }
        else {
            Write-Finding -Severity "Pass" -Title "Cached logons count is acceptable: $cachedLogons"
        }
    }
    
    # LM Hash Storage
    $noLMHash = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash"
    if ($noLMHash -eq 1) {
        Write-Finding -Severity "Pass" -Title "LM hash storage is disabled"
    }
    else {
        Write-Finding -Severity "High" -Title "LM Hash Storage May Be Enabled" -Detail "Weak LM hashes may be stored"
    }
    
    # LAN Manager Authentication Level
    $lmLevel = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"
    $lmLevels = @{
        0 = "Send LM & NTLM responses"
        1 = "Send LM & NTLM - use NTLMv2 session security if negotiated"
        2 = "Send NTLM response only"
        3 = "Send NTLMv2 response only"
        4 = "Send NTLMv2 response only. Refuse LM"
        5 = "Send NTLMv2 response only. Refuse LM & NTLM"
    }
    if ($lmLevel -ne $null) {
        if ($lmLevel -lt 3) {
            Write-Finding -Severity "High" -Title "Weak LAN Manager Authentication Level: $lmLevel" -Detail $lmLevels[$lmLevel]
        }
        else {
            Write-Finding -Severity "Pass" -Title "LAN Manager Authentication Level: $lmLevel" -Detail $lmLevels[$lmLevel]
        }
    }
    
    Write-Section "4.2 SMB Configuration"
    
    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
        
        # SMBv1
        if ($smbConfig.EnableSMB1Protocol) {
            Write-Finding -Severity "High" -Title "SMBv1 Protocol is Enabled" -Detail "Vulnerable to EternalBlue and other exploits"
        }
        else {
            Write-Finding -Severity "Pass" -Title "SMBv1 protocol is disabled"
        }
        
        # SMB Signing
        if ($smbConfig.RequireSecuritySignature) {
            Write-Finding -Severity "Pass" -Title "SMB signing is required"
        }
        else {
            Write-Finding -Severity "Medium" -Title "SMB Signing Not Required" -Detail "Vulnerable to relay attacks"
        }
        
        # SMB Encryption
        if ($smbConfig.EncryptData) {
            Write-Finding -Severity "Pass" -Title "SMB encryption is enabled"
        }
        else {
            Write-Finding -Severity "Low" -Title "SMB Encryption Not Enabled" -Detail "Consider enabling for sensitive environments"
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not retrieve SMB configuration"
    }
    
    Write-Section "4.3 Network Security"
    
    # LLMNR
    $llmnr = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast"
    if ($llmnr -eq 0) {
        Write-Finding -Severity "Pass" -Title "LLMNR is disabled"
    }
    else {
        Write-Finding -Severity "Medium" -Title "LLMNR May Be Enabled" -Detail "Vulnerable to poisoning attacks (Responder)"
    }
    
    # NetBIOS over TCP/IP
    try {
        $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.TcpipNetbiosOptions -ne $null }
        $nbtEnabled = $adapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
        if ($nbtEnabled) {
            Write-Finding -Severity "Medium" -Title "NetBIOS over TCP/IP Enabled on Some Adapters" -Detail "Vulnerable to poisoning attacks"
        }
        else {
            Write-Finding -Severity "Pass" -Title "NetBIOS over TCP/IP is disabled"
        }
    }
    catch { }
    
    Write-Section "4.4 UAC Configuration"
    
    $uacEnabled = Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
    if ($uacEnabled -eq 1) {
        Write-Finding -Severity "Pass" -Title "UAC is enabled"
        
        $consentAdmin = Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin"
        if ($consentAdmin -eq 0) {
            Write-Finding -Severity "Medium" -Title "UAC Admin Approval Mode: Elevate without prompting" -Detail "Reduces UAC effectiveness"
        }
        
        $filterAdmin = Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy"
        if ($filterAdmin -eq 1) {
            Write-Finding -Severity "Medium" -Title "LocalAccountTokenFilterPolicy is Enabled" -Detail "Remote UAC filtering disabled - may be intentional for scanning"
        }
    }
    else {
        Write-Finding -Severity "High" -Title "UAC is Disabled" -Detail "User Account Control should be enabled"
    }
}

#===============================================================================
# PHASE 5: WINDOWS FIREWALL
#===============================================================================
function Invoke-Phase5-Firewall {
    Write-Banner "PHASE 5: WINDOWS FIREWALL CONFIGURATION"
    
    Write-Section "5.1 Firewall Profile Status"
    
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        
        foreach ($profile in $profiles) {
            if ($profile.Enabled) {
                Write-Finding -Severity "Pass" -Title "$($profile.Name) Profile: Enabled"
                Write-Output-Data "  Default Inbound: $($profile.DefaultInboundAction)"
                Write-Output-Data "  Default Outbound: $($profile.DefaultOutboundAction)"
            }
            else {
                Write-Finding -Severity "High" -Title "$($profile.Name) Firewall Profile is Disabled" -Detail "Windows Firewall should be enabled on all profiles"
            }
        }
    }
    catch {
        # Fallback to netsh
        try {
            $fwStatus = netsh advfirewall show allprofiles state
            Write-Output-Data ($fwStatus | Out-String)
            
            if ($fwStatus -match "State\s+OFF") {
                Write-Finding -Severity "High" -Title "One or More Firewall Profiles Disabled"
            }
        }
        catch {
            Write-Finding -Severity "Info" -Title "Could not check firewall status"
        }
    }
    
    Write-Section "5.2 Inbound Rules Analysis"
    
    try {
        $inboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction Stop
        Write-Finding -Severity "Info" -Title "Enabled Inbound Rules: $($inboundRules.Count)"
        
        # Check for overly permissive rules
        $anyRules = $inboundRules | ForEach-Object {
            $addressFilter = $_ | Get-NetFirewallAddressFilter
            if ($addressFilter.RemoteAddress -eq "Any" -and $_.Action -eq "Allow") {
                $_
            }
        }
        
        if ($anyRules) {
            Write-Finding -Severity "Medium" -Title "Inbound Rules Allowing Any Source: $($anyRules.Count)"
            $ruleOutput = $anyRules | Select-Object -First 10 DisplayName, Profile | Format-Table -AutoSize | Out-String
            Write-Output-Data $ruleOutput
        }
        
        # Check RDP rule specifically
        $rdpRules = $inboundRules | Where-Object { $_.DisplayName -match "Remote Desktop" }
        foreach ($rdpRule in $rdpRules) {
            $addressFilter = $rdpRule | Get-NetFirewallAddressFilter
            if ($addressFilter.RemoteAddress -eq "Any") {
                Write-Finding -Severity "High" -Title "RDP Accessible from Any IP Address" -Detail "Rule: $($rdpRule.DisplayName)"
            }
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not enumerate firewall rules"
    }
}

#===============================================================================
# PHASE 6: ANTIVIRUS AND ENDPOINT PROTECTION
#===============================================================================
function Invoke-Phase6-AntiVirus {
    Write-Banner "PHASE 6: ANTIVIRUS AND ENDPOINT PROTECTION"
    
    Write-Section "6.1 Installed AV Products"
    
    # SecurityCenter2 (workstations)
    try {
        $avProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
        if ($avProducts) {
            Write-Finding -Severity "Info" -Title "Registered AV Products:"
            foreach ($av in $avProducts) {
                Write-Output-Data "  - $($av.displayName)"
            }
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "SecurityCenter2 not available (may be a server)"
    }
    
    Write-Section "6.2 Windows Defender Status"
    
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        
        if ($defenderStatus.AntivirusEnabled) {
            Write-Finding -Severity "Pass" -Title "Windows Defender Antivirus is enabled"
        }
        else {
            Write-Finding -Severity "High" -Title "Windows Defender Antivirus is Disabled"
        }
        
        if ($defenderStatus.RealTimeProtectionEnabled) {
            Write-Finding -Severity "Pass" -Title "Real-time protection is enabled"
        }
        else {
            Write-Finding -Severity "Critical" -Title "Real-Time Protection is Disabled" -Detail "System is not protected against malware"
        }
        
        if ($defenderStatus.BehaviorMonitorEnabled) {
            Write-Finding -Severity "Pass" -Title "Behavior monitoring is enabled"
        }
        else {
            Write-Finding -Severity "Medium" -Title "Behavior Monitoring is Disabled"
        }
        
        # Signature age
        $sigAge = $defenderStatus.AntivirusSignatureAge
        if ($sigAge -gt 7) {
            Write-Finding -Severity "Medium" -Title "Antivirus Signatures Are $sigAge Days Old" -Detail "Update definitions"
        }
        else {
            Write-Finding -Severity "Pass" -Title "Antivirus signatures are current ($sigAge days old)"
        }
        
        # Tamper Protection
        $tamperProtection = Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection"
        if ($tamperProtection -eq 5) {
            Write-Finding -Severity "Pass" -Title "Tamper Protection is enabled"
        }
        else {
            Write-Finding -Severity "Medium" -Title "Tamper Protection May Not Be Enabled"
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not retrieve Windows Defender status"
    }
    
    Write-Section "6.3 Defender for Endpoint (MDE)"
    
    try {
        $senseService = Get-Service Sense -ErrorAction SilentlyContinue
        if ($senseService -and $senseService.Status -eq "Running") {
            Write-Finding -Severity "Pass" -Title "Microsoft Defender for Endpoint (MDE) service is running"
        }
        else {
            Write-Finding -Severity "Info" -Title "MDE service not detected or not running"
        }
    }
    catch { }
    
    Write-Section "6.4 Third-Party Security Software"
    
    $securityProcesses = @(
        "MsSense", "SenseCncProxy", "SenseIR",  # MDE
        "cb", "CbDefense",                        # Carbon Black
        "CylanceSvc", "CylanceUI",               # Cylance
        "CSFalconService",                        # CrowdStrike
        "SentinelAgent", "SentinelOne",          # SentinelOne
        "SEP", "Symantec",                        # Symantec
        "McAfee", "mfefire",                     # McAfee
        "sophoshealth",                           # Sophos
        "ESET"                                    # ESET
    )
    
    $runningSecSoftware = Get-Process | Where-Object { 
        $proc = $_.Name
        $securityProcesses | Where-Object { $proc -match $_ }
    }
    
    if ($runningSecSoftware) {
        Write-Finding -Severity "Info" -Title "Security Software Processes Detected:"
        foreach ($proc in $runningSecSoftware | Select-Object -Unique Name) {
            Write-Output-Data "  - $($proc.Name)"
        }
    }
}

#===============================================================================
# PHASE 7: AUDIT AND LOGGING
#===============================================================================
function Invoke-Phase7-AuditLogging {
    Write-Banner "PHASE 7: AUDIT POLICY AND LOGGING"
    
    Write-Section "7.1 Audit Policy Configuration"
    
    try {
        $auditPolicy = auditpol /get /category:* 2>&1
        
        # Check key audit categories
        $requiredAudits = @{
            "Credential Validation"    = "Success and Failure"
            "Logon"                    = "Success and Failure"
            "Logoff"                   = "Success"
            "Account Lockout"          = "Failure"
            "User Account Management"  = "Success and Failure"
            "Security Group Management" = "Success and Failure"
            "Process Creation"         = "Success"
            "Audit Policy Change"      = "Success"
            "Authentication Policy Change" = "Success"
            "Sensitive Privilege Use"  = "Success and Failure"
        }
        
        $missingAudits = @()
        foreach ($audit in $requiredAudits.Keys) {
            if ($auditPolicy -match "$audit\s+No Auditing") {
                $missingAudits += $audit
            }
        }
        
        if ($missingAudits.Count -gt 0) {
            Write-Finding -Severity "Medium" -Title "Audit Categories Not Configured: $($missingAudits.Count)"
            foreach ($missing in $missingAudits) {
                Write-Output-Data "  - $missing"
            }
        }
        else {
            Write-Finding -Severity "Pass" -Title "Key audit categories appear to be configured"
        }
        
        # Command line auditing
        $cmdLineAudit = Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled"
        if ($cmdLineAudit -eq 1) {
            Write-Finding -Severity "Pass" -Title "Command line process auditing is enabled"
        }
        else {
            Write-Finding -Severity "Medium" -Title "Command Line Process Auditing Not Enabled" -Detail "Reduces visibility into process execution"
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not retrieve audit policy"
    }
    
    Write-Section "7.2 Event Log Configuration"
    
    try {
        $logs = @("Security", "System", "Application", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational")
        
        foreach ($logName in $logs) {
            try {
                $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
                if ($log) {
                    $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
                    if ($sizeMB -lt 100 -and $logName -eq "Security") {
                        Write-Finding -Severity "Low" -Title "Security Log Size May Be Too Small: $sizeMB MB"
                    }
                    else {
                        Write-Finding -Severity "Info" -Title "$logName Log: $sizeMB MB max, $($log.RecordCount) records"
                    }
                }
            }
            catch { }
        }
    }
    catch { }
    
    Write-Section "7.3 PowerShell Logging"
    
    # Script Block Logging
    $scriptBlockLogging = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging"
    if ($scriptBlockLogging -eq 1) {
        Write-Finding -Severity "Pass" -Title "PowerShell Script Block Logging is enabled"
    }
    else {
        Write-Finding -Severity "High" -Title "PowerShell Script Block Logging Not Enabled" -Detail "Critical for detecting malicious PowerShell activity"
    }
    
    # Module Logging
    $moduleLogging = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging"
    if ($moduleLogging -eq 1) {
        Write-Finding -Severity "Pass" -Title "PowerShell Module Logging is enabled"
    }
    else {
        Write-Finding -Severity "Medium" -Title "PowerShell Module Logging Not Enabled"
    }
    
    # Transcription
    $transcription = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting"
    if ($transcription -eq 1) {
        Write-Finding -Severity "Pass" -Title "PowerShell Transcription is enabled"
    }
    else {
        Write-Finding -Severity "Low" -Title "PowerShell Transcription Not Enabled"
    }
    
    # PowerShell v2
    try {
        $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
        if ($psv2 -and $psv2.State -eq "Enabled") {
            Write-Finding -Severity "Medium" -Title "PowerShell v2 is Enabled" -Detail "Can be used to bypass script logging"
        }
        else {
            Write-Finding -Severity "Pass" -Title "PowerShell v2 is disabled"
        }
    }
    catch {
        # Try server method
        try {
            $psv2Feature = Get-WindowsFeature PowerShell-V2 -ErrorAction SilentlyContinue
            if ($psv2Feature -and $psv2Feature.Installed) {
                Write-Finding -Severity "Medium" -Title "PowerShell v2 is Enabled" -Detail "Can be used to bypass script logging"
            }
        }
        catch { }
    }
}

#===============================================================================
# PHASE 8: PRIVILEGE ESCALATION CHECKS
#===============================================================================
function Invoke-Phase8-PrivilegeEscalation {
    Write-Banner "PHASE 8: PRIVILEGE ESCALATION ANALYSIS"
    
    Write-Section "8.1 Current User Context"
    
    $whoami = whoami /all 2>&1
    Write-Finding -Severity "Info" -Title "Current User: $env:USERNAME"
    
    # Check for dangerous privileges
    $privs = whoami /priv 2>&1
    if ($privs -match "SeImpersonatePrivilege.*Enabled") {
        Write-Finding -Severity "High" -Title "SeImpersonatePrivilege is Enabled" -Detail "Potato-family attacks possible"
    }
    if ($privs -match "SeAssignPrimaryTokenPrivilege.*Enabled") {
        Write-Finding -Severity "High" -Title "SeAssignPrimaryTokenPrivilege is Enabled" -Detail "Token manipulation possible"
    }
    if ($privs -match "SeBackupPrivilege.*Enabled") {
        Write-Finding -Severity "Medium" -Title "SeBackupPrivilege is Enabled" -Detail "Can read any file on system"
    }
    if ($privs -match "SeRestorePrivilege.*Enabled") {
        Write-Finding -Severity "Medium" -Title "SeRestorePrivilege is Enabled" -Detail "Can write any file on system"
    }
    if ($privs -match "SeDebugPrivilege.*Enabled") {
        Write-Finding -Severity "High" -Title "SeDebugPrivilege is Enabled" -Detail "Can debug any process including LSASS"
    }
    
    Write-Section "8.2 AlwaysInstallElevated"
    
    $aieHKLM = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated"
    $aieHKCU = Test-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated"
    
    if ($aieHKLM -eq 1 -and $aieHKCU -eq 1) {
        Write-Finding -Severity "Critical" -Title "AlwaysInstallElevated is Enabled (Both HKLM and HKCU)" -Detail "Any user can install MSI packages as SYSTEM"
    }
    elseif ($aieHKLM -eq 1 -or $aieHKCU -eq 1) {
        Write-Finding -Severity "Medium" -Title "AlwaysInstallElevated Partially Configured" -Detail "HKLM: $aieHKLM, HKCU: $aieHKCU"
    }
    else {
        Write-Finding -Severity "Pass" -Title "AlwaysInstallElevated is not enabled"
    }
    
    Write-Section "8.3 Unquoted Service Paths"
    
    try {
        $unquotedServices = Get-CimInstance Win32_Service | Where-Object {
            $_.PathName -notmatch '^"' -and 
            $_.PathName -match ' ' -and
            $_.PathName -notmatch '^[A-Za-z]:\\Windows\\' -and
            $_.StartMode -ne 'Disabled'
        }
        
        if ($unquotedServices) {
            Write-Finding -Severity "High" -Title "Unquoted Service Paths Found: $($unquotedServices.Count)"
            foreach ($svc in $unquotedServices | Select-Object -First 10) {
                Write-Output-Data "  Service: $($svc.Name)"
                Write-Output-Data "  Path: $($svc.PathName)"
                Write-Output-Data "  Runs As: $($svc.StartName)"
                Write-Output-Data ""
            }
        }
        else {
            Write-Finding -Severity "Pass" -Title "No unquoted service paths found"
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not check for unquoted service paths"
    }
    
    Write-Section "8.4 Modifiable Services"
    
    try {
        $services = Get-CimInstance Win32_Service | Where-Object { $_.PathName }
        $modifiableServices = @()
        
        foreach ($svc in $services | Select-Object -First 50) {
            $binaryPath = Get-ServiceBinaryPath $svc.PathName
            if ($binaryPath -and (Test-Path $binaryPath -ErrorAction SilentlyContinue)) {
                try {
                    $acl = Get-Acl $binaryPath -ErrorAction SilentlyContinue
                    $vulnerable = $acl.Access | Where-Object {
                        $_.FileSystemRights -match "Write|Modify|FullControl" -and
                        $_.IdentityReference -notmatch "NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|NT SERVICE\\TrustedInstaller"
                    }
                    if ($vulnerable) {
                        $modifiableServices += [PSCustomObject]@{
                            Service = $svc.Name
                            Path    = $binaryPath
                            RunsAs  = $svc.StartName
                            Access  = ($vulnerable.IdentityReference -join ", ")
                        }
                    }
                }
                catch { }
            }
        }
        
        if ($modifiableServices) {
            Write-Finding -Severity "High" -Title "Services with Modifiable Binaries: $($modifiableServices.Count)"
            foreach ($mod in $modifiableServices | Select-Object -First 5) {
                Write-Output-Data "  Service: $($mod.Service) | RunsAs: $($mod.RunsAs)"
                Write-Output-Data "  Path: $($mod.Path)"
                Write-Output-Data "  Writable By: $($mod.Access)"
                Write-Output-Data ""
            }
        }
        else {
            Write-Finding -Severity "Pass" -Title "No modifiable service binaries found (sampled first 50 services)"
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not check service binary permissions"
    }
    
    Write-Section "8.5 Scheduled Tasks Analysis"
    
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
        $systemTasks = $tasks | Where-Object { $_.Principal.UserId -match "SYSTEM|LocalSystem" }
        
        Write-Finding -Severity "Info" -Title "Enabled Scheduled Tasks: $($tasks.Count) (SYSTEM: $($systemTasks.Count))"
        
        # Check for writable task binaries
        $vulnerableTasks = @()
        foreach ($task in $systemTasks | Select-Object -First 30) {
            foreach ($action in $task.Actions) {
                if ($action.Execute -and (Test-Path $action.Execute -ErrorAction SilentlyContinue)) {
                    try {
                        $acl = Get-Acl $action.Execute -ErrorAction SilentlyContinue
                        $vulnerable = $acl.Access | Where-Object {
                            $_.FileSystemRights -match "Write|Modify|FullControl" -and
                            $_.IdentityReference -notmatch "NT AUTHORITY|BUILTIN|TrustedInstaller"
                        }
                        if ($vulnerable) {
                            $vulnerableTasks += [PSCustomObject]@{
                                Task   = $task.TaskName
                                Binary = $action.Execute
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        
        if ($vulnerableTasks) {
            Write-Finding -Severity "High" -Title "Scheduled Tasks with Writable Binaries:"
            foreach ($vt in $vulnerableTasks) {
                Write-Output-Data "  Task: $($vt.Task)"
                Write-Output-Data "  Binary: $($vt.Binary)"
            }
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not enumerate scheduled tasks"
    }
    
    Write-Section "8.6 Stored Credentials"
    
    try {
        $cmdkey = cmdkey /list 2>&1
        if ($cmdkey -match "Target:") {
            Write-Finding -Severity "Medium" -Title "Stored Credentials Found in Credential Manager"
            Write-Output-Data ($cmdkey | Out-String)
        }
        else {
            Write-Finding -Severity "Pass" -Title "No stored credentials in Credential Manager"
        }
    }
    catch { }
}

#===============================================================================
# PHASE 9: CREDENTIAL EXPOSURE
#===============================================================================
function Invoke-Phase9-CredentialExposure {
    Write-Banner "PHASE 9: CREDENTIAL EXPOSURE ANALYSIS"
    
    Write-Section "9.1 Unattend/Sysprep Files"
    
    $unattendPaths = @(
        "C:\Unattend.xml",
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\Unattend\Unattend.xml",
        "C:\Windows\system32\sysprep\Unattend.xml",
        "C:\Windows\system32\sysprep\Panther\Unattend.xml",
        "C:\Windows\system32\sysprep\sysprep.xml"
    )
    
    $foundUnattend = @()
    foreach ($path in $unattendPaths) {
        if (Test-Path $path) {
            $foundUnattend += $path
            $content = Get-Content $path -ErrorAction SilentlyContinue
            if ($content -match "Password|AdministratorPassword") {
                Write-Finding -Severity "Critical" -Title "Unattend File Contains Password: $path"
            }
        }
    }
    
    if ($foundUnattend.Count -gt 0) {
        Write-Finding -Severity "High" -Title "Unattend/Sysprep Files Found: $($foundUnattend.Count)"
        foreach ($f in $foundUnattend) {
            Write-Output-Data "  - $f"
        }
    }
    else {
        Write-Finding -Severity "Pass" -Title "No unattend/sysprep files found in common locations"
    }
    
    Write-Section "9.2 PowerShell History"
    
    $historyPaths = Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue
    
    if ($historyPaths) {
        Write-Finding -Severity "Info" -Title "PowerShell History Files Found: $($historyPaths.Count)"
        
        foreach ($histFile in $historyPaths) {
            $content = Get-Content $histFile -ErrorAction SilentlyContinue
            $sensitiveLines = $content | Select-String -Pattern "password|credential|secret|key|token|convertto-securestring" -CaseSensitive:$false
            
            if ($sensitiveLines) {
                Write-Finding -Severity "High" -Title "Potential Credentials in PS History: $($histFile.FullName)"
                Write-Output-Data ($sensitiveLines | Select-Object -First 5 | Out-String)
            }
        }
    }
    
    Write-Section "9.3 Web Configuration Files"
    
    if (Test-Path "C:\inetpub") {
        try {
            $webConfigs = Get-ChildItem "C:\inetpub" -Recurse -Filter "web.config" -ErrorAction SilentlyContinue
            
            foreach ($config in $webConfigs | Select-Object -First 10) {
                $content = Get-Content $config.FullName -ErrorAction SilentlyContinue
                if ($content -match "connectionString|password=|pwd=") {
                    Write-Finding -Severity "High" -Title "Web.config May Contain Credentials: $($config.FullName)"
                }
            }
        }
        catch { }
    }
    
    Write-Section "9.4 GPP Password Check (SYSVOL)"
    
    if ($env:USERDNSDOMAIN) {
        try {
            $sysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL"
            if (Test-Path $sysvolPath) {
                $gppFiles = Get-ChildItem $sysvolPath -Recurse -Filter "*.xml" -ErrorAction SilentlyContinue |
                    Select-String -Pattern "cpassword" -ErrorAction SilentlyContinue
                
                if ($gppFiles) {
                    Write-Finding -Severity "Critical" -Title "GPP Passwords Found in SYSVOL" -Detail "Legacy Group Policy Preferences passwords"
                    foreach ($gpp in $gppFiles | Select-Object -First 5) {
                        Write-Output-Data "  - $($gpp.Path)"
                    }
                }
                else {
                    Write-Finding -Severity "Pass" -Title "No GPP passwords found in SYSVOL"
                }
            }
        }
        catch {
            Write-Finding -Severity "Info" -Title "Could not check SYSVOL for GPP passwords"
        }
    }
    
    Write-Section "9.5 LAPS Configuration"
    
    try {
        $lapsInstalled = Get-ChildItem "C:\Program Files\LAPS" -ErrorAction SilentlyContinue
        $lapsAdmPwd = Get-ADComputer $env:COMPUTERNAME -Properties ms-Mcs-AdmPwd -ErrorAction SilentlyContinue
        
        if ($lapsInstalled -or $lapsAdmPwd) {
            Write-Finding -Severity "Pass" -Title "LAPS appears to be deployed"
        }
        else {
            Write-Finding -Severity "Medium" -Title "LAPS Not Detected" -Detail "Local admin passwords may be shared across systems"
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not verify LAPS deployment (may not be domain joined)"
    }
}

#===============================================================================
# PHASE 10: WINDOWS SECURITY FEATURES
#===============================================================================
function Invoke-Phase10-SecurityFeatures {
    Write-Banner "PHASE 10: WINDOWS SECURITY FEATURES"
    
    Write-Section "10.1 BitLocker Status"
    
    try {
        $bitlocker = Get-BitLockerVolume -ErrorAction Stop
        
        foreach ($vol in $bitlocker) {
            if ($vol.ProtectionStatus -eq "On") {
                Write-Finding -Severity "Pass" -Title "BitLocker Enabled on $($vol.MountPoint)" -Detail "Encryption: $($vol.EncryptionMethod)"
            }
            else {
                if ($vol.MountPoint -eq "C:") {
                    Write-Finding -Severity "Medium" -Title "BitLocker Not Enabled on System Drive ($($vol.MountPoint))"
                }
                else {
                    Write-Finding -Severity "Low" -Title "BitLocker Not Enabled on $($vol.MountPoint)"
                }
            }
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not check BitLocker status (may require admin or may not be available)"
    }
    
    Write-Section "10.2 Secure Boot"
    
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($secureBoot) {
            Write-Finding -Severity "Pass" -Title "Secure Boot is enabled"
        }
        else {
            Write-Finding -Severity "Medium" -Title "Secure Boot is Not Enabled"
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "Could not check Secure Boot status (may not be supported)"
    }
    
    Write-Section "10.3 AppLocker / WDAC"
    
    try {
        $applockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        if ($applockerPolicy -and $applockerPolicy.RuleCollections.Count -gt 0) {
            Write-Finding -Severity "Pass" -Title "AppLocker policies are configured"
            Write-Finding -Severity "Info" -Title "Rule Collections: $($applockerPolicy.RuleCollections.Count)"
        }
        else {
            Write-Finding -Severity "Medium" -Title "No AppLocker Policies Configured" -Detail "Consider implementing application whitelisting"
        }
    }
    catch {
        Write-Finding -Severity "Info" -Title "AppLocker not available or no policies configured"
    }
    
    # WDAC
    try {
        $wdac = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        if ($wdac.CodeIntegrityPolicyEnforcementStatus -eq 2) {
            Write-Finding -Severity "Pass" -Title "WDAC is in enforcement mode"
        }
        elseif ($wdac.CodeIntegrityPolicyEnforcementStatus -eq 1) {
            Write-Finding -Severity "Info" -Title "WDAC is in audit mode"
        }
    }
    catch { }
    
    Write-Section "10.4 PowerShell Constrained Language Mode"
    
    $languageMode = $ExecutionContext.SessionState.LanguageMode
    Write-Finding -Severity "Info" -Title "PowerShell Language Mode: $languageMode"
    
    if ($languageMode -eq "ConstrainedLanguage") {
        Write-Finding -Severity "Pass" -Title "PowerShell is running in Constrained Language Mode"
    }
    elseif ($languageMode -eq "FullLanguage" -and -not $Script:IsAdmin) {
        Write-Finding -Severity "Low" -Title "PowerShell in Full Language Mode" -Detail "Consider Constrained Language Mode with AppLocker/WDAC"
    }
    
    Write-Section "10.5 Windows Scripting Host"
    
    $wshDisabled = Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled"
    if ($wshDisabled -eq 0) {
        Write-Finding -Severity "Pass" -Title "Windows Script Host is disabled"
    }
    else {
        Write-Finding -Severity "Low" -Title "Windows Script Host is Enabled" -Detail "Consider disabling if not required"
    }
}

#===============================================================================
# SUMMARY AND REPORT GENERATION
#===============================================================================
function Write-Summary {
    Write-Banner "ASSESSMENT SUMMARY"
    
    $criticalCount = ($Script:Findings | Where-Object Severity -eq "Critical").Count
    $highCount = ($Script:Findings | Where-Object Severity -eq "High").Count
    $mediumCount = ($Script:Findings | Where-Object Severity -eq "Medium").Count
    $lowCount = ($Script:Findings | Where-Object Severity -eq "Low").Count
    $passCount = ($Script:Findings | Where-Object Severity -eq "Pass").Count
    
    [void]$Script:OutputBuffer.AppendLine("Assessment Date: $(Get-Date)")
    [void]$Script:OutputBuffer.AppendLine("Target Host: $env:COMPUTERNAME")
    [void]$Script:OutputBuffer.AppendLine("Assessed By: $env:USERNAME")
    [void]$Script:OutputBuffer.AppendLine("Run As Administrator: $Script:IsAdmin")
    [void]$Script:OutputBuffer.AppendLine("")
    [void]$Script:OutputBuffer.AppendLine("FINDINGS SUMMARY")
    [void]$Script:OutputBuffer.AppendLine("================")
    [void]$Script:OutputBuffer.AppendLine("Critical: $criticalCount")
    [void]$Script:OutputBuffer.AppendLine("High:     $highCount")
    [void]$Script:OutputBuffer.AppendLine("Medium:   $mediumCount")
    [void]$Script:OutputBuffer.AppendLine("Low:      $lowCount")
    [void]$Script:OutputBuffer.AppendLine("Pass:     $passCount")
    [void]$Script:OutputBuffer.AppendLine("")
    
    Write-Host ""
    Write-Host "============================================" -ForegroundColor White
    Write-Host " FINDINGS SUMMARY" -ForegroundColor White
    Write-Host "============================================" -ForegroundColor White
    Write-Host " Critical: $criticalCount" -ForegroundColor Red
    Write-Host " High:     $highCount" -ForegroundColor DarkYellow
    Write-Host " Medium:   $mediumCount" -ForegroundColor Yellow
    Write-Host " Low:      $lowCount" -ForegroundColor Cyan
    Write-Host " Pass:     $passCount" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor White
    
    if ($criticalCount -gt 0) {
        [void]$Script:OutputBuffer.AppendLine("")
        [void]$Script:OutputBuffer.AppendLine("CRITICAL FINDINGS REQUIRING IMMEDIATE ATTENTION:")
        [void]$Script:OutputBuffer.AppendLine("------------------------------------------------")
        Write-Host ""
        Write-Host "CRITICAL FINDINGS REQUIRING IMMEDIATE ATTENTION:" -ForegroundColor Red
        
        foreach ($finding in ($Script:Findings | Where-Object Severity -eq "Critical")) {
            Write-Host "  - $($finding.Title)" -ForegroundColor Red
            [void]$Script:OutputBuffer.AppendLine("  - $($finding.Title)")
        }
    }
    
    if ($highCount -gt 0) {
        [void]$Script:OutputBuffer.AppendLine("")
        [void]$Script:OutputBuffer.AppendLine("HIGH SEVERITY FINDINGS:")
        [void]$Script:OutputBuffer.AppendLine("-----------------------")
        Write-Host ""
        Write-Host "HIGH SEVERITY FINDINGS:" -ForegroundColor DarkYellow
        
        foreach ($finding in ($Script:Findings | Where-Object Severity -eq "High")) {
            Write-Host "  - $($finding.Title)" -ForegroundColor DarkYellow
            [void]$Script:OutputBuffer.AppendLine("  - $($finding.Title)")
        }
    }
}

function Save-Report {
    try {
        $Script:OutputBuffer.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host ""
        Write-Host "[+] Report saved to: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Failed to save report: $_" -ForegroundColor Red
    }
    
    if ($HTMLReport) {
        $htmlPath = $OutputPath -replace "\.txt$", ".html"
        try {
            $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows Build Review - $env:COMPUTERNAME</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
        h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }
        h2 { color: #00d4ff; margin-top: 30px; }
        .critical { color: #ff4757; font-weight: bold; }
        .high { color: #ffa502; font-weight: bold; }
        .medium { color: #ffda79; }
        .low { color: #7bed9f; }
        .pass { color: #2ed573; }
        .info { color: #70a1ff; }
        pre { background: #16213e; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .summary { background: #16213e; padding: 20px; border-radius: 10px; margin: 20px 0; }
        .summary-item { display: inline-block; margin: 10px 20px; text-align: center; }
        .summary-count { font-size: 36px; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Windows Build Review Report</h1>
    <p><strong>Host:</strong> $env:COMPUTERNAME</p>
    <p><strong>Date:</strong> $(Get-Date)</p>
    <p><strong>Assessed By:</strong> $env:USERNAME</p>
    
    <div class="summary">
        <h2>Findings Summary</h2>
        <div class="summary-item"><div class="summary-count critical">$(($Script:Findings | Where-Object Severity -eq "Critical").Count)</div>Critical</div>
        <div class="summary-item"><div class="summary-count high">$(($Script:Findings | Where-Object Severity -eq "High").Count)</div>High</div>
        <div class="summary-item"><div class="summary-count medium">$(($Script:Findings | Where-Object Severity -eq "Medium").Count)</div>Medium</div>
        <div class="summary-item"><div class="summary-count low">$(($Script:Findings | Where-Object Severity -eq "Low").Count)</div>Low</div>
        <div class="summary-item"><div class="summary-count pass">$(($Script:Findings | Where-Object Severity -eq "Pass").Count)</div>Pass</div>
    </div>
    
    <h2>Critical &amp; High Findings</h2>
    <ul>
    $( ($Script:Findings | Where-Object { $_.Severity -in @("Critical", "High") } | ForEach-Object {
        "<li class='$($_.Severity.ToLower())'>[$($_.Severity.ToUpper())] $($_.Title)</li>"
    }) -join "`n    " )
    </ul>
    
    <h2>Full Report</h2>
    <pre>$([System.Web.HttpUtility]::HtmlEncode($Script:OutputBuffer.ToString()))</pre>
</body>
</html>
"@
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
            Write-Host "[+] HTML Report saved to: $htmlPath" -ForegroundColor Green
        }
        catch {
            Write-Host "[-] Failed to save HTML report: $_" -ForegroundColor Red
        }
    }
}

#===============================================================================
# MAIN EXECUTION
#===============================================================================
function Main {
    Clear-Host
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                     WINDOWS BUILD REVIEW SCRIPT                              ║" -ForegroundColor Cyan
    Write-Host "║                           Version $Script:Version                                   ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[*] Target Host: $env:COMPUTERNAME" -ForegroundColor Yellow
    Write-Host "[*] Assessment Date: $(Get-Date)" -ForegroundColor Yellow
    Write-Host "[*] Running as Administrator: $Script:IsAdmin" -ForegroundColor Yellow
    Write-Host "[*] Output File: $OutputPath" -ForegroundColor Yellow
    Write-Host ""
    
    if (-not $Script:IsAdmin) {
        Write-Host "[!] WARNING: Not running as Administrator. Some checks will be limited." -ForegroundColor DarkYellow
        Write-Host "[!] For comprehensive results, run as Administrator." -ForegroundColor DarkYellow
        Write-Host ""
    }
    
    [void]$Script:OutputBuffer.AppendLine("WINDOWS BUILD REVIEW REPORT")
    [void]$Script:OutputBuffer.AppendLine("===========================")
    [void]$Script:OutputBuffer.AppendLine("Generated: $(Get-Date)")
    [void]$Script:OutputBuffer.AppendLine("Host: $env:COMPUTERNAME")
    [void]$Script:OutputBuffer.AppendLine("User: $env:USERNAME")
    [void]$Script:OutputBuffer.AppendLine("Administrator: $Script:IsAdmin")
    [void]$Script:OutputBuffer.AppendLine("")
    
    # Run all phases
    Invoke-Phase1-PatchLevel
    Invoke-Phase2-UserReview
    Invoke-Phase3-RemoteAccess
    Invoke-Phase4-SecurityConfig
    Invoke-Phase5-Firewall
    Invoke-Phase6-AntiVirus
    Invoke-Phase7-AuditLogging
    
    if (-not $SkipPrivEsc) {
        Invoke-Phase8-PrivilegeEscalation
    }
    
    Invoke-Phase9-CredentialExposure
    Invoke-Phase10-SecurityFeatures
    
    # Generate summary and save
    Write-Summary
    Save-Report
    
    Write-Host ""
    Write-Host "[+] Assessment complete." -ForegroundColor Green
}

# Run the script
Main
