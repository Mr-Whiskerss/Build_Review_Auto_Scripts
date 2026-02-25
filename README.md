# Build Review Scripts

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg)](/Mr-Whiskerss/Build_Review_Auto_Scripts/blob/main)
[![Maintenance](https://img.shields.io/badge/Maintained-Yes-green.svg)](/Mr-Whiskerss/Build_Review_Auto_Scripts/blob/main)

Automated security configuration assessment scripts for Windows, Linux, and macOS systems. Based on CIS Benchmarks, DISA STIGs, and industry best practices.

> **For authorised security assessments only.** Always obtain proper written authorisation before running these scripts on any system.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Scripts Included](#scripts-included)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Linux Build Review](#linux-build-review)
  - [Windows Build Review (PowerShell)](#windows-build-review-powershell)
  - [Windows Build Review (Batch)](#windows-build-review-batch)
  - [macOS Security Audit](#macos-security-audit)
- [Assessment Coverage](#assessment-coverage)
- [Output Format](#output-format)
- [Severity Ratings](#severity-ratings)
- [Sample Output](#sample-output)
- [Integration with Reporting](#integration-with-reporting)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Overview

These scripts automate the manual configuration review phase of a security build review / hardening assessment. They enumerate system configuration, identify security misconfigurations, and produce output suitable for inclusion in penetration testing reports.

The scripts are designed to:

- Run without installing additional dependencies
- Produce consistent, parseable output
- Highlight findings by severity
- Cover common critical/high findings from CIS benchmarks and real-world assessments

---

## Features

- ✅ **No dependencies** — Uses native OS commands only
- ✅ **Severity-rated findings** — Critical, High, Medium, Low, Pass, Info
- ✅ **Report-ready output** — Clean text output for copy/paste into reports
- ✅ **Comprehensive coverage** — 10+ assessment phases per script
- ✅ **Graceful degradation** — Works with reduced privileges (with limited checks)
- ✅ **Cross-platform** — Separate scripts for Windows, Linux, and macOS
- ✅ **Multiple formats** — PowerShell, Batch, and Bash versions available

---

## Scripts Included

| Script | Platform | Description |
|--------|----------|-------------|
| `linux-build-review.sh` | Linux | Bash script for Linux/Unix systems |
| `Windows-Build-Review.ps1` | Windows | PowerShell script with HTML report option |
| `Windows-Build-Review.bat` | Windows | Batch script for restricted environments |
| `macos_security_audit.sh` | macOS | Bash script for macOS endpoints |

---

## Requirements

### Linux

- Bash 4.0+
- Root/sudo access recommended (some checks require elevated privileges)
- Tested on: Ubuntu 18.04+, Debian 10+, RHEL/CentOS 7+, Amazon Linux 2

### Windows

- Windows Server 2012 R2+ or Windows 8.1+
- PowerShell 5.1+ (for `.ps1` script)
- Administrator privileges recommended
- Tested on: Windows Server 2016/2019/2022, Windows 10/11

### macOS

- macOS 10.15 (Catalina) or later
- Bash shell
- Root/sudo access recommended (some checks require elevated privileges)
- Tested on: macOS Catalina, Big Sur, Monterey, Ventura, Sonoma, Sequoia

---

## Installation

### Option 1: Clone the Repository

```bash
git clone https://github.com/Mr-Whiskerss/Build_Review_Auto_Scripts.git
cd Build_Review_Auto_Scripts
```

### Option 2: Download Individual Scripts

```bash
# Linux
curl -O https://raw.githubusercontent.com/Mr-Whiskerss/Build_Review_Auto_Scripts/main/linux-build-review.sh
chmod +x linux-build-review.sh

# macOS
curl -O https://raw.githubusercontent.com/Mr-Whiskerss/Build_Review_Auto_Scripts/main/macos_security_audit.sh
chmod +x macos_security_audit.sh

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Mr-Whiskerss/Build_Review_Auto_Scripts/main/Windows-Build-Review.ps1" -OutFile "Windows-Build-Review.ps1"
```

### Option 3: Copy to Target System

For air-gapped environments, simply copy the appropriate script to the target system via USB or other approved transfer method.

---

## Usage

### Linux Build Review

```bash
# Basic usage (outputs to current directory)
sudo ./linux-build-review.sh

# Custom output file
sudo ./linux-build-review.sh -o /tmp/server-review.txt

# Quiet mode (no terminal output, file only)
sudo ./linux-build-review.sh -q -o /tmp/server-review.txt

# Show help
./linux-build-review.sh -h
```

**Options:**

| Option | Description |
|--------|-------------|
| `-o, --output <file>` | Specify output report file path |
| `-q, --quiet` | Suppress terminal output (file only) |
| `-h, --help` | Display help message |

### Windows Build Review (PowerShell)

```powershell
# Basic usage (outputs to current directory)
.\Windows-Build-Review.ps1

# Custom output file
.\Windows-Build-Review.ps1 -OutputPath "C:\Temp\server-review.txt"

# Generate HTML report as well
.\Windows-Build-Review.ps1 -HTMLReport

# Skip privilege escalation checks
.\Windows-Build-Review.ps1 -SkipPrivEsc

# Combined options
.\Windows-Build-Review.ps1 -OutputPath "C:\Temp\review.txt" -HTMLReport
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `-OutputPath <string>` | Specify output report file path |
| `-HTMLReport` | Generate an HTML report in addition to text |
| `-SkipPrivEsc` | Skip privilege escalation analysis phase |

**Execution Policy Note:**
If you encounter execution policy restrictions:

```powershell
# Option 1: Bypass for single execution
powershell -ExecutionPolicy Bypass -File .\Windows-Build-Review.ps1

# Option 2: Unblock the file
Unblock-File .\Windows-Build-Review.ps1
```

### Windows Build Review (Batch)

```batch
REM Basic usage
Windows-Build-Review.bat

REM Custom output file
Windows-Build-Review.bat C:\Temp\server-review.txt
```

> **Tip:** Use the batch version when PowerShell is restricted, blocked by AppLocker, or running in Constrained Language Mode.

### macOS Security Audit

```bash
# Basic usage (outputs to macos_audit_TIMESTAMP.txt)
sudo ./macos_security_audit.sh

# Custom output file
sudo ./macos_security_audit.sh -o /tmp/macos-review.txt

# Quiet mode (no colours/banner)
sudo ./macos_security_audit.sh -q -o /tmp/macos-review.txt

# Show help
./macos_security_audit.sh -h
```

**Options:**

| Option | Description |
|--------|-------------|
| `-o, --output <file>` | Specify output report file path |
| `-q, --quiet` | Suppress banner and colours |
| `-h, --help` | Display help message |

---

## Assessment Coverage

### Linux Script Phases

| Phase | Description | Key Checks |
|-------|-------------|------------|
| 1 | System Information | OS version, kernel, services, listening ports |
| 2 | User & Authentication | UID 0 accounts, SSH config, sudo, password policy |
| 3 | Filesystem & Permissions | SUID/SGID, world-writable files, sensitive file perms |
| 4 | Network Configuration | IP forwarding, ICMP redirects, firewall rules |
| 5 | Logging & Auditing | auditd, syslog, remote logging |
| 6 | PAM & Password Policy | pwquality, faillock, password hashing |
| 7 | Kernel & Boot Security | SELinux/AppArmor, GRUB password, Secure Boot |
| 8 | Credential Exposure | SSH keys, AWS creds, history files, config files |
| 9 | Cron & Scheduled Tasks | System/user crontabs, systemd timers |
| 10 | Third-Party Services | Web servers, databases, Docker |

### Windows Script Phases

| Phase | Description | Key Checks |
|-------|-------------|------------|
| 1 | Patch Level | OS version, hotfixes, pending updates, installed software |
| 2 | User & Account Review | Local users, groups, password policy, admin accounts |
| 3 | Remote Access | RDP (NLA, encryption), WinRM, SSH |
| 4 | Security Configuration | WDigest, LSA Protection, Credential Guard, SMB, LLMNR, UAC |
| 5 | Windows Firewall | Profile status, inbound rules, RDP exposure |
| 6 | Antivirus & EDR | Defender status, real-time protection, MDE, third-party AV |
| 7 | Audit & Logging | Audit policy, event logs, PowerShell logging |
| 8 | Privilege Escalation | AlwaysInstallElevated, unquoted paths, modifiable services |
| 9 | Credential Exposure | Unattend.xml, GPP passwords, PS history, LAPS |
| 10 | Security Features | BitLocker, Secure Boot, AppLocker/WDAC, CLM |

### macOS Script Phases

| Phase | Description | Key Checks |
|-------|-------------|------------|
| 1 | System Information | macOS version, hardware model, architecture (Intel/Apple Silicon) |
| 2 | System Integrity Protection | SIP status, Authenticated Root, custom configurations |
| 3 | Gatekeeper & XProtect | Gatekeeper status, XProtect version, MRT presence |
| 4 | FileVault | Encryption status, recovery keys, secure token users |
| 5 | User Account Security | Local users, admins, guest account, auto-login, root status, password policy, screen lock |
| 6 | Firewall | Application firewall, stealth mode, logging, allowed apps |
| 7 | Network Configuration | Listening services, SSH, screen/file sharing, Remote Apple Events, Bluetooth |
| 8 | Remote Management | MDM enrollment, configuration profiles, ARD status |
| 9 | Application Security | Non-Apple kexts, system extensions, launch daemons/agents, unsigned apps |
| 10 | Privacy & TCC | Full Disk Access, Accessibility, Screen Recording permissions, Siri, analytics |
| 11 | Security Software | EDR/AV detection (CrowdStrike, Carbon Black, SentinelOne, Defender, etc.) |
| 12 | Firmware & Hardware | Secure Boot policy, firmware password, T2/Apple Silicon, Activation Lock |
| 13 | Logging & Auditing | Audit configuration, auditd status, unified logging |
| 14 | Privilege Escalation | SUID binaries, NOPASSWD sudoers, world-writable directories |
| 15 | Software Updates | Auto-update settings, critical updates, available updates |

---

## Output Format

All scripts produce findings in a consistent format:

```
[SEVERITY] Finding Title
    Additional details or evidence
```

Example:

```
[CRITICAL] WDigest Authentication Enabled
    Cleartext credentials stored in LSASS memory

[HIGH] SSH Root Login Permitted
    PermitRootLogin is set to 'yes'

[PASS] SMBv1 protocol is disabled
```

---

## Severity Ratings

Findings are categorised using CVSS-aligned severity ratings:

| Severity | CVSS Score | Description | Example |
|----------|------------|-------------|---------|
| **CRITICAL** | 9.0 – 10.0 | Immediate remediation required | Cleartext admin credentials, RCE vulnerabilities |
| **HIGH** | 7.0 – 8.9 | Significant security risk | WDigest enabled, SSH root login, no AV |
| **MEDIUM** | 4.0 – 6.9 | Moderate risk, should be addressed | Weak password policy, SMB signing not required |
| **LOW** | 0.1 – 3.9 | Minor risk, best practice deviation | Banner disclosure, PS transcription disabled |
| **INFO** | N/A | Informational, no direct risk | System enumeration data |
| **PASS** | N/A | Security control validated | Expected secure configuration confirmed |
| **CHECK** | N/A | Requires manual verification | Non-standard SUID binary found |

---

## Sample Output

### Linux Sample

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                       LINUX BUILD REVIEW SCRIPT                              ║
║                              Version 1.0.0                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

[*] Target Host: webserver01.example.com
[*] Assessment Date: Mon 15 Jan 2024 10:30:00 GMT
[*] Output File: linux-review-webserver01-20240115_103000.txt

===============================================================================
 PHASE 2: USER AND AUTHENTICATION REVIEW
===============================================================================

--- 2.3 SSH Configuration Review ---

[PASS] PermitRootLogin: no
[MEDIUM] SSH Password Authentication Enabled
    Consider enforcing key-based authentication only
[PASS] PermitEmptyPasswords: no
[HIGH] NOPASSWD Sudo Entries Found
    Users can execute commands as root without password
    deploy  ALL=(ALL) NOPASSWD: ALL
```

### Windows Sample

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                     WINDOWS BUILD REVIEW SCRIPT                              ║
║                           Version 1.0.0                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

[*] Target Host: DC01
[*] Assessment Date: 15/01/2024 10:30:00
[*] Running as Administrator: True

===============================================================================
 PHASE 4: SECURITY CONFIGURATION
===============================================================================

--- 4.1 Credential Security ---

[CRITICAL] WDigest Authentication Enabled
    Cleartext credentials stored in LSASS memory
[HIGH] LSA Protection (RunAsPPL) NOT Enabled
    LSASS process not protected against credential dumping
[PASS] LAN Manager Authentication Level: 5
    Send NTLMv2 response only. Refuse LM & NTLM

============================================
 FINDINGS SUMMARY
============================================
 Critical: 2
 High:     5
 Medium:   8
 Low:      3
 Pass:     24
============================================
```

### macOS Sample

```
╔═══════════════════════════════════════════════════════════════════╗
║                  macOS Security Audit Script                      ║
║                        Version 1.0.0                              ║
╚═══════════════════════════════════════════════════════════════════╝

[*] Output saved to: macos_audit_20250225_103000.txt

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SYSTEM INTEGRITY PROTECTION (SIP)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    [PASS] SIP is enabled
    [PASS] Authenticated Root is enabled

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  FILEVAULT (FULL DISK ENCRYPTION)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    [PASS] FileVault is enabled
    [PASS] Personal recovery key exists

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  USER ACCOUNT SECURITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    [INFO] Local user accounts (UID > 500):
    [INFO]   - admin
    [INFO]   - testuser
    [PASS] Guest account is disabled
    [PASS] Auto-login is disabled
    [HIGH] Password NOT required after screen saver

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AUDIT SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Finding Summary:
  ───────────────────────────────────
  Critical:  0
  High:      1
  Medium:    3
  Low:       2
  Pass:      24
  Info:      15
  ───────────────────────────────────
  Total Findings: 6

  Overall Risk: MEDIUM
  Review and address medium findings as appropriate.

  Audit completed at: Wed Feb 25 10:30:00 GMT 2026
```

---

## Integration with Reporting

### Grep for Specific Severities

```bash
# Extract all critical and high findings
grep -E "^\[CRITICAL\]|^\[HIGH\]" report.txt

# Count findings by severity
grep -c "\[CRITICAL\]" report.txt
grep -c "\[HIGH\]" report.txt
```

### Convert to CSV (Basic)

```bash
# Linux/macOS
grep -E "^\[(CRITICAL|HIGH|MEDIUM|LOW)\]" report.txt | \
  sed 's/\[\(.*\)\] \(.*\)/\1,\2/' > findings.csv
```

### HTML Report (Windows PowerShell)

The PowerShell script supports native HTML report generation:

```powershell
.\Windows-Build-Review.ps1 -HTMLReport
```

### CI/CD Integration

```bash
# Run audit and fail on critical/high findings
sudo ./macos_security_audit.sh -q -o audit.txt
if grep -q "\[CRITICAL\]\|\[HIGH\]" audit.txt; then
    echo "Security audit failed"
    exit 1
fi
```

### Scheduled Audits

```bash
# Add to crontab for weekly audits (Linux/macOS)
0 9 * * 1 /path/to/macos_security_audit.sh -q -o /var/log/security_audit_$(date +\%Y\%m\%d).txt
```

---

## Post-Assessment Cleanup

Remember to clean up after your assessment:

### Linux

```bash
# Remove the script
rm -f linux-build-review.sh

# Clear history (if appropriate)
history -c
```

### Windows

```powershell
# Remove scripts
Remove-Item "Windows-Build-Review.ps1" -Force
Remove-Item "Windows-Build-Review.bat" -Force

# Clear PowerShell history (if appropriate)
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force
```

### macOS

```bash
# Remove the script
rm -f macos_security_audit.sh

# Clear history (if appropriate)
history -c
rm -f ~/.zsh_history ~/.bash_history
```

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Guidelines

1. Maintain zero external dependencies
2. Ensure scripts run on default OS installations
3. Follow existing code style and output format
4. Test on multiple OS versions before submitting
5. Update this README if adding new checks or features

### Adding New Checks

When adding new checks, please:

- Assign appropriate severity based on CVSS guidelines
- Include both the vulnerable and secure state detection
- Add error handling for missing commands/features
- Update the Assessment Coverage table

---

## Disclaimer

These scripts are provided for **authorised security testing and assessment purposes only**.

- Always obtain **written authorisation** before running these scripts on any system
- The authors are not responsible for any misuse or damage caused by these scripts
- These scripts may trigger security alerts — coordinate with the system owner
- Some checks may impact system performance — avoid running on production systems during peak hours
- Results should be verified manually — automated tools may produce false positives/negatives

**Use responsibly and ethically.**

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Acknowledgements

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) — Security configuration guidelines
- [DISA STIGs](https://public.cyber.mil/stigs/) — Security Technical Implementation Guides
- [NCSC Guidelines](https://www.ncsc.gov.uk/) — UK National Cyber Security Centre
- [HackTricks](https://book.hacktricks.xyz/) — Privilege escalation references
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Security testing resources
- [Objective-See](https://objective-see.org/tools.html) — macOS security tools and research

---

## Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/Mr-Whiskerss/Build_Review_Auto_Scripts/issues) page
2. Open a new issue with:
   - OS version and build number
   - Script version
   - Error message or unexpected behaviour
   - Steps to reproduce

---

**Made with ☕ for the security community**
