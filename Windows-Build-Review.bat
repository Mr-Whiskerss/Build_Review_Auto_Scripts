@echo off
REM ===============================================================================
REM Windows Build Review Script - Batch Version
REM Based on CIS Benchmarks and DISA STIG Guidelines
REM For authorised penetration testing and security assessments only
REM ===============================================================================
REM Usage: Run as Administrator for comprehensive results
REM        Windows-Build-Review.bat [output_file]
REM ===============================================================================

setlocal EnableDelayedExpansion

REM Configuration
set "VERSION=1.0.0"
set "TIMESTAMP=%DATE:~-4%%DATE:~4,2%%DATE:~7,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%"
set "TIMESTAMP=%TIMESTAMP: =0%"
set "HOSTNAME=%COMPUTERNAME%"
set "OUTPUT_FILE=%~1"

if "%OUTPUT_FILE%"=="" (
    set "OUTPUT_FILE=Windows-Review-%HOSTNAME%-%TIMESTAMP%.txt"
)

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    set "IS_ADMIN=YES"
) else (
    set "IS_ADMIN=NO"
)

REM Initialize output file
echo. > "%OUTPUT_FILE%"

REM ===============================================================================
REM Output Functions
REM ===============================================================================
call :Banner "WINDOWS BUILD REVIEW SCRIPT v%VERSION%"
call :Log "==============================================================================="
call :Log " Target Host: %COMPUTERNAME%"
call :Log " Assessment Date: %DATE% %TIME%"
call :Log " Running as Administrator: %IS_ADMIN%"
call :Log " Output File: %OUTPUT_FILE%"
call :Log "==============================================================================="
echo.

if "%IS_ADMIN%"=="NO" (
    call :Finding "INFO" "WARNING: Not running as Administrator - some checks will be limited"
    echo [!] WARNING: Run as Administrator for comprehensive results
    echo.
)

REM ===============================================================================
REM PHASE 1: OPERATING SYSTEM AND PATCH LEVEL
REM ===============================================================================
call :Banner "PHASE 1: OPERATING SYSTEM AND PATCH LEVEL"

call :Section "1.1 Operating System Information"
call :Log ""
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Original Install Date" /C:"System Boot Time" /C:"Domain" >> "%OUTPUT_FILE%"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Domain"

for /f "tokens=2 delims==" %%a in ('wmic os get Caption /value 2^>nul ^| find "="') do (
    echo     OS: %%a
    call :Log "    OS: %%a"
)

for /f "tokens=2 delims==" %%a in ('wmic os get Version /value 2^>nul ^| find "="') do (
    echo     Version: %%a
    call :Log "    Version: %%a"
)

for /f "tokens=2 delims==" %%a in ('wmic os get BuildNumber /value 2^>nul ^| find "="') do (
    echo     Build: %%a
    call :Log "    Build: %%a"
)

call :Section "1.2 Installed Hotfixes"
call :Log ""
echo Listing recent hotfixes...
wmic qfe list brief | findstr /i "KB" > "%TEMP%\hotfixes.tmp" 2>nul
for /f %%a in ('type "%TEMP%\hotfixes.tmp" ^| find /c /v ""') do (
    call :Finding "INFO" "Total Hotfixes Installed: %%a"
)
echo Recent hotfixes: >> "%OUTPUT_FILE%"
wmic qfe get HotFixID,Description,InstalledOn 2>nul | findstr /i "KB" >> "%OUTPUT_FILE%"
type "%TEMP%\hotfixes.tmp" 2>nul | more +1 | head 2>nul
del "%TEMP%\hotfixes.tmp" 2>nul

call :Section "1.3 Installed Software (Sample)"
call :Log ""
echo Enumerating installed software...
wmic product get Name,Version 2>nul | findstr /v "^$" >> "%OUTPUT_FILE%"

REM ===============================================================================
REM PHASE 2: USER AND ACCOUNT REVIEW
REM ===============================================================================
call :Banner "PHASE 2: USER AND ACCOUNT REVIEW"

call :Section "2.1 Local User Accounts"
call :Log ""
net user >> "%OUTPUT_FILE%" 2>nul
net user

call :Section "2.2 Local Administrators Group"
call :Log ""
net localgroup Administrators >> "%OUTPUT_FILE%" 2>nul
net localgroup Administrators
for /f %%a in ('net localgroup Administrators ^| find /c /v ""') do (
    set /a ADMIN_COUNT=%%a-6
)
if %ADMIN_COUNT% GTR 5 (
    call :Finding "MEDIUM" "Excessive Local Administrator Accounts: %ADMIN_COUNT% members"
) else (
    call :Finding "INFO" "Local Administrators: %ADMIN_COUNT% members"
)

call :Section "2.3 Remote Desktop Users"
call :Log ""
net localgroup "Remote Desktop Users" >> "%OUTPUT_FILE%" 2>nul
net localgroup "Remote Desktop Users" 2>nul

call :Section "2.4 Built-in Administrator Account"
call :Log ""
net user Administrator 2>nul | findstr /i "Account active" > "%TEMP%\admin.tmp"
type "%TEMP%\admin.tmp" | findstr /i "Yes" >nul
if %errorLevel%==0 (
    call :Finding "MEDIUM" "Built-in Administrator Account is ENABLED"
) else (
    call :Finding "PASS" "Built-in Administrator account is disabled"
)
net user Administrator >> "%OUTPUT_FILE%" 2>nul
del "%TEMP%\admin.tmp" 2>nul

call :Section "2.5 Guest Account"
call :Log ""
net user Guest 2>nul | findstr /i "Account active" > "%TEMP%\guest.tmp"
type "%TEMP%\guest.tmp" | findstr /i "Yes" >nul
if %errorLevel%==0 (
    call :Finding "HIGH" "Guest Account is ENABLED"
) else (
    call :Finding "PASS" "Guest account is disabled"
)
del "%TEMP%\guest.tmp" 2>nul

call :Section "2.6 Password Policy"
call :Log ""
net accounts >> "%OUTPUT_FILE%" 2>nul
net accounts

for /f "tokens=5" %%a in ('net accounts ^| findstr /i "Minimum password length"') do (
    if %%a LSS 14 (
        call :Finding "MEDIUM" "Minimum Password Length Too Short: %%a characters"
    ) else (
        call :Finding "PASS" "Minimum password length meets requirements: %%a"
    )
)

for /f "tokens=4" %%a in ('net accounts ^| findstr /i "Lockout threshold"') do (
    if "%%a"=="Never" (
        call :Finding "MEDIUM" "Account Lockout Threshold Not Configured"
    ) else (
        call :Finding "INFO" "Account lockout threshold: %%a"
    )
)

REM ===============================================================================
REM PHASE 3: REMOTE ACCESS CONFIGURATION
REM ===============================================================================
call :Banner "PHASE 3: REMOTE ACCESS CONFIGURATION"

call :Section "3.1 RDP Configuration"
call :Log ""

reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections 2>nul | findstr "0x0" >nul
if %errorLevel%==0 (
    call :Finding "INFO" "RDP is ENABLED"
    
    REM Check NLA
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication 2>nul | findstr "0x1" >nul
    if %errorLevel%==0 (
        call :Finding "PASS" "Network Level Authentication (NLA) is required"
    ) else (
        call :Finding "HIGH" "Network Level Authentication (NLA) NOT Required"
    )
    
    REM Check Security Layer
    for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer 2^>nul ^| findstr "SecurityLayer"') do (
        if "%%a"=="0x0" call :Finding "MEDIUM" "RDP Security Layer: RDP (weakest)"
        if "%%a"=="0x1" call :Finding "INFO" "RDP Security Layer: Negotiate"
        if "%%a"=="0x2" call :Finding "PASS" "RDP Security Layer: TLS"
    )
) else (
    call :Finding "PASS" "RDP is DISABLED"
)

reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections >> "%OUTPUT_FILE%" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication >> "%OUTPUT_FILE%" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer >> "%OUTPUT_FILE%" 2>nul

call :Section "3.2 WinRM Configuration"
call :Log ""
sc query WinRM 2>nul | findstr "RUNNING" >nul
if %errorLevel%==0 (
    call :Finding "INFO" "WinRM Service is RUNNING"
    winrm get winrm/config 2>nul >> "%OUTPUT_FILE%"
) else (
    call :Finding "INFO" "WinRM Service is not running"
)

REM ===============================================================================
REM PHASE 4: SECURITY CONFIGURATION
REM ===============================================================================
call :Banner "PHASE 4: SECURITY CONFIGURATION"

call :Section "4.1 Credential Security"
call :Log ""

REM WDigest
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "CRITICAL" "WDigest Authentication ENABLED - Cleartext creds in LSASS"
) else (
    call :Finding "PASS" "WDigest authentication is disabled or not configured"
)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential >> "%OUTPUT_FILE%" 2>nul

REM LSA Protection
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "LSA Protection (RunAsPPL) is enabled"
) else (
    call :Finding "HIGH" "LSA Protection (RunAsPPL) NOT Enabled"
)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL >> "%OUTPUT_FILE%" 2>nul

REM LM Hash Storage
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "LM hash storage is disabled"
) else (
    call :Finding "HIGH" "LM Hash Storage May Be Enabled"
)

REM LAN Manager Authentication Level
for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel 2^>nul ^| findstr "LmCompatibilityLevel"') do (
    set "LMLEVEL=%%a"
    if "%%a"=="0x0" call :Finding "HIGH" "LM Auth Level 0: Send LM and NTLM responses"
    if "%%a"=="0x1" call :Finding "HIGH" "LM Auth Level 1: Send LM and NTLM - use NTLMv2 if negotiated"
    if "%%a"=="0x2" call :Finding "MEDIUM" "LM Auth Level 2: Send NTLM response only"
    if "%%a"=="0x3" call :Finding "PASS" "LM Auth Level 3: Send NTLMv2 response only"
    if "%%a"=="0x4" call :Finding "PASS" "LM Auth Level 4: Send NTLMv2, refuse LM"
    if "%%a"=="0x5" call :Finding "PASS" "LM Auth Level 5: Send NTLMv2, refuse LM and NTLM"
)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel >> "%OUTPUT_FILE%" 2>nul

REM Cached Credentials
for /f "tokens=3" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount 2^>nul ^| findstr "CachedLogonsCount"') do (
    call :Finding "INFO" "Cached Logons Count: %%a"
    if %%a GTR 4 (
        call :Finding "LOW" "Cached Logons Count may be excessive for servers"
    )
)

call :Section "4.2 SMB Configuration"
call :Log ""

REM SMBv1 - Check via sc
sc query lanmanworkstation 2>nul | findstr "RUNNING" >nul
if %errorLevel%==0 (
    reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 2>nul | findstr "0x0" >nul
    if %errorLevel%==0 (
        call :Finding "PASS" "SMBv1 is disabled via registry"
    ) else (
        REM Check if feature is disabled
        sc query mrxsmb10 2>nul | findstr "STOPPED" >nul
        if %errorLevel%==0 (
            call :Finding "PASS" "SMBv1 service is stopped"
        ) else (
            call :Finding "HIGH" "SMBv1 May Be Enabled"
        )
    )
)

REM SMB Signing
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "SMB signing is required"
) else (
    call :Finding "MEDIUM" "SMB Signing NOT Required - vulnerable to relay attacks"
)
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" >> "%OUTPUT_FILE%" 2>nul

call :Section "4.3 Network Security"
call :Log ""

REM LLMNR
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast 2>nul | findstr "0x0" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "LLMNR is disabled"
) else (
    call :Finding "MEDIUM" "LLMNR May Be Enabled - vulnerable to poisoning attacks"
)

call :Section "4.4 UAC Configuration"
call :Log ""

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "UAC is enabled"
) else (
    call :Finding "HIGH" "UAC is DISABLED"
)

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin 2>nul | findstr "0x0" >nul
if %errorLevel%==0 (
    call :Finding "MEDIUM" "UAC Admin Prompt: Elevate without prompting"
)

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "MEDIUM" "LocalAccountTokenFilterPolicy is enabled (remote UAC filtering disabled)"
)

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" >> "%OUTPUT_FILE%" 2>nul

REM ===============================================================================
REM PHASE 5: WINDOWS FIREWALL
REM ===============================================================================
call :Banner "PHASE 5: WINDOWS FIREWALL CONFIGURATION"

call :Section "5.1 Firewall Profile Status"
call :Log ""

netsh advfirewall show allprofiles state >> "%OUTPUT_FILE%" 2>nul
netsh advfirewall show allprofiles state

netsh advfirewall show domainprofile state 2>nul | findstr "ON" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "Domain Profile: Enabled"
) else (
    call :Finding "HIGH" "Domain Firewall Profile is DISABLED"
)

netsh advfirewall show privateprofile state 2>nul | findstr "ON" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "Private Profile: Enabled"
) else (
    call :Finding "HIGH" "Private Firewall Profile is DISABLED"
)

netsh advfirewall show publicprofile state 2>nul | findstr "ON" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "Public Profile: Enabled"
) else (
    call :Finding "HIGH" "Public Firewall Profile is DISABLED"
)

call :Section "5.2 Firewall Rules (Inbound Allow)"
call :Log ""
echo Listing enabled inbound allow rules... >> "%OUTPUT_FILE%"
netsh advfirewall firewall show rule name=all dir=in 2>nul | findstr /i "Rule Name\|Enabled\|Action\|RemoteIP" | findstr /B "Rule" >> "%OUTPUT_FILE%"

REM ===============================================================================
REM PHASE 6: ANTIVIRUS AND ENDPOINT PROTECTION
REM ===============================================================================
call :Banner "PHASE 6: ANTIVIRUS AND ENDPOINT PROTECTION"

call :Section "6.1 Windows Defender Status"
call :Log ""

sc query WinDefend 2>nul | findstr "RUNNING" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "Windows Defender service is running"
) else (
    call :Finding "HIGH" "Windows Defender Service is NOT Running"
)

REM Check Defender via registry
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiSpyware 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "CRITICAL" "Windows Defender is DISABLED via registry"
)

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "CRITICAL" "Windows Defender is DISABLED via Group Policy"
)

REM Real-time protection
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "CRITICAL" "Real-Time Protection is DISABLED"
) else (
    call :Finding "PASS" "Real-Time Protection appears enabled"
)

REM Tamper Protection
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection 2>nul | findstr "0x5" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "Tamper Protection is enabled"
) else (
    call :Finding "MEDIUM" "Tamper Protection may not be enabled"
)

call :Section "6.2 Defender for Endpoint (MDE)"
call :Log ""

sc query Sense 2>nul | findstr "RUNNING" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "Microsoft Defender for Endpoint (MDE) is running"
) else (
    call :Finding "INFO" "MDE service not detected or not running"
)

call :Section "6.3 Third-Party AV Processes"
call :Log ""
echo Checking for security software processes... >> "%OUTPUT_FILE%"
tasklist 2>nul | findstr /i "cb cylance crowd falcon sentinel symantec mcafee sophos eset kaspersky malware bitdefender trend avast avg" >> "%OUTPUT_FILE%"
tasklist 2>nul | findstr /i "cb cylance crowd falcon sentinel symantec mcafee sophos eset kaspersky malware bitdefender trend avast avg"

REM ===============================================================================
REM PHASE 7: AUDIT POLICY AND LOGGING
REM ===============================================================================
call :Banner "PHASE 7: AUDIT POLICY AND LOGGING"

call :Section "7.1 Audit Policy"
call :Log ""
echo Current Audit Policy: >> "%OUTPUT_FILE%"
auditpol /get /category:* >> "%OUTPUT_FILE%" 2>nul

auditpol /get /category:* 2>nul | findstr /i "No Auditing" >nul
if %errorLevel%==0 (
    call :Finding "MEDIUM" "Some audit categories are set to 'No Auditing'"
)

REM Command line auditing
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "Command line process auditing is enabled"
) else (
    call :Finding "MEDIUM" "Command Line Process Auditing NOT Enabled"
)

call :Section "7.2 PowerShell Logging"
call :Log ""

REM Script Block Logging
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "PowerShell Script Block Logging is enabled"
) else (
    call :Finding "HIGH" "PowerShell Script Block Logging NOT Enabled"
)

REM Module Logging
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "PowerShell Module Logging is enabled"
) else (
    call :Finding "MEDIUM" "PowerShell Module Logging NOT Enabled"
)

REM Transcription
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "PowerShell Transcription is enabled"
) else (
    call :Finding "LOW" "PowerShell Transcription NOT Enabled"
)

REM ===============================================================================
REM PHASE 8: PRIVILEGE ESCALATION CHECKS
REM ===============================================================================
call :Banner "PHASE 8: PRIVILEGE ESCALATION ANALYSIS"

call :Section "8.1 Current User Privileges"
call :Log ""
whoami /priv >> "%OUTPUT_FILE%" 2>nul
whoami /groups >> "%OUTPUT_FILE%" 2>nul

whoami /priv 2>nul | findstr /i "SeImpersonatePrivilege.*Enabled" >nul
if %errorLevel%==0 (
    call :Finding "HIGH" "SeImpersonatePrivilege is ENABLED - Potato attacks possible"
)

whoami /priv 2>nul | findstr /i "SeDebugPrivilege.*Enabled" >nul
if %errorLevel%==0 (
    call :Finding "HIGH" "SeDebugPrivilege is ENABLED - Can debug any process"
)

whoami /priv 2>nul | findstr /i "SeBackupPrivilege.*Enabled" >nul
if %errorLevel%==0 (
    call :Finding "MEDIUM" "SeBackupPrivilege is ENABLED - Can read any file"
)

call :Section "8.2 AlwaysInstallElevated"
call :Log ""

set "AIE_HKLM=0"
set "AIE_HKCU=0"

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul | findstr "0x1" >nul
if %errorLevel%==0 set "AIE_HKLM=1"

reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul | findstr "0x1" >nul
if %errorLevel%==0 set "AIE_HKCU=1"

if "%AIE_HKLM%"=="1" if "%AIE_HKCU%"=="1" (
    call :Finding "CRITICAL" "AlwaysInstallElevated ENABLED (Both HKLM and HKCU) - Any user can install as SYSTEM"
) else if "%AIE_HKLM%"=="1" (
    call :Finding "MEDIUM" "AlwaysInstallElevated set in HKLM only"
) else if "%AIE_HKCU%"=="1" (
    call :Finding "MEDIUM" "AlwaysInstallElevated set in HKCU only"
) else (
    call :Finding "PASS" "AlwaysInstallElevated is not enabled"
)

call :Section "8.3 Unquoted Service Paths"
call :Log ""
echo Checking for unquoted service paths... >> "%OUTPUT_FILE%"

wmic service get name,displayname,pathname,startmode 2>nul | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """" > "%TEMP%\unquoted.tmp"
for /f %%a in ('type "%TEMP%\unquoted.tmp" ^| find /c /v ""') do (
    if %%a GTR 0 (
        call :Finding "HIGH" "Potential Unquoted Service Paths Found: %%a"
        type "%TEMP%\unquoted.tmp" >> "%OUTPUT_FILE%"
        echo Check manually - services with spaces in path and no quotes:
        type "%TEMP%\unquoted.tmp"
    ) else (
        call :Finding "PASS" "No obvious unquoted service paths found"
    )
)
del "%TEMP%\unquoted.tmp" 2>nul

call :Section "8.4 Stored Credentials"
call :Log ""
cmdkey /list >> "%OUTPUT_FILE%" 2>nul
cmdkey /list 2>nul | findstr /i "Target:" >nul
if %errorLevel%==0 (
    call :Finding "MEDIUM" "Stored Credentials Found in Credential Manager"
    cmdkey /list 2>nul | findstr /i "Target:"
) else (
    call :Finding "PASS" "No stored credentials in Credential Manager"
)

REM ===============================================================================
REM PHASE 9: CREDENTIAL EXPOSURE
REM ===============================================================================
call :Banner "PHASE 9: CREDENTIAL EXPOSURE ANALYSIS"

call :Section "9.1 Unattend/Sysprep Files"
call :Log ""

set "UNATTEND_FOUND=0"
for %%f in (
    "C:\Unattend.xml"
    "C:\Windows\Panther\Unattend.xml"
    "C:\Windows\Panther\Unattend\Unattend.xml"
    "C:\Windows\system32\sysprep\Unattend.xml"
    "C:\Windows\system32\sysprep\Panther\Unattend.xml"
    "C:\Windows\system32\sysprep\sysprep.xml"
) do (
    if exist %%f (
        call :Finding "HIGH" "Unattend/Sysprep file found: %%f"
        echo     %%f >> "%OUTPUT_FILE%"
        findstr /i "Password" %%f >nul 2>&1
        if !errorLevel!==0 (
            call :Finding "CRITICAL" "Password found in: %%f"
        )
        set "UNATTEND_FOUND=1"
    )
)
if "%UNATTEND_FOUND%"=="0" (
    call :Finding "PASS" "No unattend/sysprep files found in common locations"
)

call :Section "9.2 SAM/SYSTEM Backup Files"
call :Log ""

for %%f in (
    "C:\Windows\repair\SAM"
    "C:\Windows\repair\SYSTEM"
    "C:\Windows\System32\config\RegBack\SAM"
    "C:\Windows\System32\config\RegBack\SYSTEM"
) do (
    if exist %%f (
        call :Finding "HIGH" "SAM/SYSTEM backup found: %%f"
    )
)

call :Section "9.3 PowerShell History Files"
call :Log ""
echo Checking for PowerShell history files... >> "%OUTPUT_FILE%"
dir /s /b "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" 2>nul >> "%OUTPUT_FILE%"
for /f "delims=" %%f in ('dir /s /b "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" 2^>nul') do (
    call :Finding "INFO" "PowerShell history file: %%f"
    findstr /i "password credential secret token" "%%f" >nul 2>&1
    if !errorLevel!==0 (
        call :Finding "HIGH" "Potential credentials in PS history: %%f"
    )
)

REM ===============================================================================
REM PHASE 10: WINDOWS SECURITY FEATURES
REM ===============================================================================
call :Banner "PHASE 10: WINDOWS SECURITY FEATURES"

call :Section "10.1 BitLocker Status"
call :Log ""
manage-bde -status 2>nul >> "%OUTPUT_FILE%"
manage-bde -status C: 2>nul | findstr /i "Protection Status" | findstr /i "On" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "BitLocker is enabled on C: drive"
) else (
    call :Finding "MEDIUM" "BitLocker may not be enabled on C: drive"
)

call :Section "10.2 Credential Guard"
call :Log ""
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "Virtualization Based Security is enabled"
) else (
    call :Finding "HIGH" "Virtualization Based Security (Credential Guard) NOT Enabled"
)

reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags 2>nul >> "%OUTPUT_FILE%"

call :Section "10.3 Secure Boot"
call :Log ""
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State" /v UEFISecureBootEnabled 2>nul | findstr "0x1" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "Secure Boot is enabled"
) else (
    call :Finding "MEDIUM" "Secure Boot may not be enabled"
)

call :Section "10.4 Windows Script Host"
call :Log ""
reg query "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled 2>nul | findstr "0x0" >nul
if %errorLevel%==0 (
    call :Finding "PASS" "Windows Script Host is disabled"
) else (
    call :Finding "LOW" "Windows Script Host is enabled"
)

REM ===============================================================================
REM NETWORK INFORMATION
REM ===============================================================================
call :Banner "NETWORK INFORMATION"

call :Section "Listening Ports"
call :Log ""
netstat -ano | findstr "LISTENING" >> "%OUTPUT_FILE%" 2>nul
echo Listening ports logged to report file.

call :Section "Network Shares"
call :Log ""
net share >> "%OUTPUT_FILE%" 2>nul
net share

REM ===============================================================================
REM SUMMARY
REM ===============================================================================
call :Banner "ASSESSMENT COMPLETE"

echo.
echo ===============================================================================
echo  Report saved to: %OUTPUT_FILE%
echo ===============================================================================
echo.
echo Review the output file for detailed findings.
echo.
echo [*] Remember to check for:
echo     - CRITICAL: WDigest, AlwaysInstallElevated, Real-Time Protection
echo     - HIGH: NLA, SMBv1, LSA Protection, Unquoted Paths
echo     - MEDIUM: Password Policy, SMB Signing, LLMNR, Audit Policy
echo.

call :Log ""
call :Log "==============================================================================="
call :Log " Assessment completed at %DATE% %TIME%"
call :Log " Report saved to: %OUTPUT_FILE%"
call :Log "==============================================================================="

goto :EOF

REM ===============================================================================
REM HELPER FUNCTIONS
REM ===============================================================================

:Banner
echo.
echo ===============================================================================
echo  %~1
echo ===============================================================================
echo.
echo. >> "%OUTPUT_FILE%"
echo =============================================================================== >> "%OUTPUT_FILE%"
echo  %~1 >> "%OUTPUT_FILE%"
echo =============================================================================== >> "%OUTPUT_FILE%"
echo. >> "%OUTPUT_FILE%"
goto :EOF

:Section
echo.
echo --- %~1 ---
echo.
echo. >> "%OUTPUT_FILE%"
echo --- %~1 --- >> "%OUTPUT_FILE%"
echo. >> "%OUTPUT_FILE%"
goto :EOF

:Finding
set "SEV=%~1"
set "MSG=%~2"
if "%SEV%"=="CRITICAL" (
    echo [CRITICAL] %MSG%
    echo [CRITICAL] %MSG% >> "%OUTPUT_FILE%"
) else if "%SEV%"=="HIGH" (
    echo [HIGH] %MSG%
    echo [HIGH] %MSG% >> "%OUTPUT_FILE%"
) else if "%SEV%"=="MEDIUM" (
    echo [MEDIUM] %MSG%
    echo [MEDIUM] %MSG% >> "%OUTPUT_FILE%"
) else if "%SEV%"=="LOW" (
    echo [LOW] %MSG%
    echo [LOW] %MSG% >> "%OUTPUT_FILE%"
) else if "%SEV%"=="PASS" (
    echo [PASS] %MSG%
    echo [PASS] %MSG% >> "%OUTPUT_FILE%"
) else if "%SEV%"=="INFO" (
    echo [INFO] %MSG%
    echo [INFO] %MSG% >> "%OUTPUT_FILE%"
) else (
    echo [CHECK] %MSG%
    echo [CHECK] %MSG% >> "%OUTPUT_FILE%"
)
goto :EOF

:Log
echo %~1 >> "%OUTPUT_FILE%"
goto :EOF
