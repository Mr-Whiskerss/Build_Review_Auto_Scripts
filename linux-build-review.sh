#!/bin/bash
#===============================================================================
# Linux Build Review Script
# Based on CIS Benchmarks and DISA STIG Guidelines
# For authorised penetration testing and security assessments only
#===============================================================================
# Usage: sudo ./linux-build-review.sh [options]
# Options:
#   -o, --output <file>   Output report file (default: linux-review-<hostname>-<date>.txt)
#   -q, --quiet           Suppress terminal output (file only)
#   -h, --help            Show this help message
#===============================================================================

set -o pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
VERSION="1.0.0"
SCRIPT_NAME="Linux Build Review Script"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || echo "unknown")
DEFAULT_OUTPUT="linux-review-${HOSTNAME_SHORT}-${TIMESTAMP}.txt"
OUTPUT_FILE=""
QUIET_MODE=0

#-------------------------------------------------------------------------------
# Colour Definitions
#-------------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    ORANGE='\033[0;33m'
    YELLOW='\033[1;33m'
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    WHITE='\033[1;37m'
    GREY='\033[0;90m'
    NC='\033[0m'
    BOLD='\033[1m'
else
    RED='' ORANGE='' YELLOW='' GREEN='' BLUE='' CYAN='' MAGENTA='' WHITE='' GREY='' NC='' BOLD=''
fi

#-------------------------------------------------------------------------------
# Severity Tags
#-------------------------------------------------------------------------------
tag_critical() { echo -e "${RED}[CRITICAL]${NC}"; }
tag_high()     { echo -e "${ORANGE}[HIGH]${NC}"; }
tag_medium()   { echo -e "${YELLOW}[MEDIUM]${NC}"; }
tag_low()      { echo -e "${CYAN}[LOW]${NC}"; }
tag_info()     { echo -e "${BLUE}[INFO]${NC}"; }
tag_pass()     { echo -e "${GREEN}[PASS]${NC}"; }
tag_check()    { echo -e "${MAGENTA}[CHECK]${NC}"; }

#-------------------------------------------------------------------------------
# Output Functions
#-------------------------------------------------------------------------------
OUTPUT_BUFFER=""

log() {
    local msg="$1"
    OUTPUT_BUFFER+="$msg"$'\n'
    if [[ $QUIET_MODE -eq 0 ]]; then
        echo -e "$msg"
    fi
}

log_raw() {
    local msg="$1"
    OUTPUT_BUFFER+="$msg"
    if [[ $QUIET_MODE -eq 0 ]]; then
        echo -en "$msg"
    fi
}

banner() {
    log ""
    log "${BOLD}${WHITE}===============================================================================${NC}"
    log "${BOLD}${WHITE} $1${NC}"
    log "${BOLD}${WHITE}===============================================================================${NC}"
    log ""
}

section() {
    log ""
    log "${BOLD}${CYAN}--- $1 ---${NC}"
    log ""
}

subsection() {
    log ""
    log "${BOLD}${MAGENTA}>> $1${NC}"
}

finding() {
    local severity="$1"
    local title="$2"
    local detail="$3"
    
    case "$severity" in
        critical) log "$(tag_critical) ${BOLD}$title${NC}" ;;
        high)     log "$(tag_high) ${BOLD}$title${NC}" ;;
        medium)   log "$(tag_medium) ${BOLD}$title${NC}" ;;
        low)      log "$(tag_low) ${BOLD}$title${NC}" ;;
        info)     log "$(tag_info) $title" ;;
        pass)     log "$(tag_pass) $title" ;;
        check)    log "$(tag_check) $title" ;;
    esac
    
    if [[ -n "$detail" ]]; then
        log "    ${GREY}$detail${NC}"
    fi
}

cmd_output() {
    local output="$1"
    if [[ -n "$output" ]]; then
        while IFS= read -r line; do
            log "    ${GREY}$line${NC}"
        done <<< "$output"
    fi
}

save_report() {
    local clean_output
    clean_output=$(echo -e "$OUTPUT_BUFFER" | sed 's/\x1b\[[0-9;]*m//g')
    echo "$clean_output" > "$OUTPUT_FILE"
    echo -e "${GREEN}[+] Report saved to: ${OUTPUT_FILE}${NC}"
}

#-------------------------------------------------------------------------------
# Helper Functions
#-------------------------------------------------------------------------------
is_root() {
    [[ $EUID -eq 0 ]]
}

cmd_exists() {
    command -v "$1" &>/dev/null
}

get_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${ID:-unknown}"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

get_distro_family() {
    local distro
    distro=$(get_distro)
    case "$distro" in
        ubuntu|debian|kali|linuxmint|pop) echo "debian" ;;
        rhel|centos|fedora|rocky|alma|oracle|amzn) echo "rhel" ;;
        opensuse*|sles|suse) echo "suse" ;;
        arch|manjaro) echo "arch" ;;
        *) echo "unknown" ;;
    esac
}

file_exists() {
    [[ -f "$1" ]]
}

dir_exists() {
    [[ -d "$1" ]]
}

is_service_running() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

is_service_enabled() {
    systemctl is-enabled --quiet "$1" 2>/dev/null
}

#-------------------------------------------------------------------------------
# Usage
#-------------------------------------------------------------------------------
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -o, --output <file>   Output report file (default: $DEFAULT_OUTPUT)"
    echo "  -q, --quiet           Suppress terminal output (file only)"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Example:"
    echo "  sudo $0 -o /tmp/server-review.txt"
    exit 0
}

#-------------------------------------------------------------------------------
# Parse Arguments
#-------------------------------------------------------------------------------
parse_args() {
    OUTPUT_FILE="$DEFAULT_OUTPUT"
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -q|--quiet)
                QUIET_MODE=1
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
    done
}

#===============================================================================
# PHASE 1: SYSTEM INFORMATION ENUMERATION
#===============================================================================
phase1_system_info() {
    banner "PHASE 1: SYSTEM INFORMATION"
    
    section "1.1 Operating System Details"
    
    local os_info kernel_info hostname_info
    os_info=$(cat /etc/os-release 2>/dev/null | grep -E "^(NAME|VERSION|ID)=" | head -5)
    kernel_info=$(uname -a 2>/dev/null)
    hostname_info=$(hostnamectl 2>/dev/null || hostname -f 2>/dev/null)
    
    finding "info" "OS Release Information:"
    cmd_output "$os_info"
    
    finding "info" "Kernel Version:"
    cmd_output "$kernel_info"
    
    finding "info" "Hostname Information:"
    cmd_output "$hostname_info"
    
    # Check for EOL OS
    local os_version
    os_version=$(grep "^VERSION_ID" /etc/os-release 2>/dev/null | cut -d'"' -f2)
    local os_id
    os_id=$(grep "^ID=" /etc/os-release 2>/dev/null | cut -d'"' -f2 | cut -d'=' -f2)
    
    case "$os_id" in
        ubuntu)
            case "$os_version" in
                14.*|16.*|17.*|19.*|21.*|23.04)
                    finding "high" "End-of-Life Ubuntu Version Detected" "Ubuntu $os_version is no longer supported"
                    ;;
            esac
            ;;
        centos)
            case "$os_version" in
                6*|7*|8*)
                    finding "high" "CentOS Version May Be EOL" "CentOS $os_version - verify support status"
                    ;;
            esac
            ;;
    esac
    
    section "1.2 Running Services"
    
    local services
    services=$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | head -30)
    finding "info" "Running Services (systemd):"
    cmd_output "$services"
    
    section "1.3 Listening Ports and Processes"
    
    local listening
    if cmd_exists ss; then
        listening=$(ss -tulnp 2>/dev/null | grep -v "^Netid")
    elif cmd_exists netstat; then
        listening=$(netstat -tulnp 2>/dev/null | grep -v "^Proto")
    fi
    finding "info" "Listening Ports:"
    cmd_output "$listening"
    
    # Flag potentially dangerous services
    local dangerous_ports
    dangerous_ports=$(echo "$listening" | grep -E ":(21|23|25|110|143|445|3389|5900|6379|27017|9200)\s" 2>/dev/null)
    if [[ -n "$dangerous_ports" ]]; then
        finding "medium" "Potentially Sensitive Services Exposed:" "Review necessity of these services"
        cmd_output "$dangerous_ports"
    fi
}

#===============================================================================
# PHASE 2: USER AND AUTHENTICATION REVIEW
#===============================================================================
phase2_user_auth() {
    banner "PHASE 2: USER AND AUTHENTICATION REVIEW"
    
    section "2.1 User Account Analysis"
    
    # UID 0 accounts
    local uid0_accounts
    uid0_accounts=$(awk -F: '($3 == 0) {print $1}' /etc/passwd 2>/dev/null)
    local uid0_count
    uid0_count=$(echo "$uid0_accounts" | grep -c . 2>/dev/null || echo 0)
    
    if [[ $uid0_count -gt 1 ]]; then
        finding "critical" "Multiple UID 0 Accounts Detected" "Only root should have UID 0"
        cmd_output "$uid0_accounts"
    elif [[ $uid0_count -eq 1 && "$uid0_accounts" == "root" ]]; then
        finding "pass" "Only root has UID 0"
    fi
    
    # Interactive shell accounts
    subsection "Accounts with Interactive Shells"
    local interactive_shells
    interactive_shells=$(awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 != "/sbin/nologin") {print $1 " -> " $7}' /etc/passwd 2>/dev/null)
    finding "info" "Accounts with login shells:"
    cmd_output "$interactive_shells"
    
    # Accounts without passwords or locked
    subsection "Password Status Analysis"
    if is_root; then
        local empty_pass
        empty_pass=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
        if [[ -n "$empty_pass" ]]; then
            finding "critical" "Accounts with Empty Passwords:" "Immediate remediation required"
            cmd_output "$empty_pass"
        else
            finding "pass" "No accounts with empty passwords"
        fi
        
        local locked_accounts
        locked_accounts=$(awk -F: '($2 == "!" || $2 == "*" || $2 == "!!" || $2 ~ /^!/) {print $1}' /etc/shadow 2>/dev/null | head -20)
        finding "info" "Locked/No-Login Accounts (sample):"
        cmd_output "$locked_accounts"
    else
        finding "info" "Cannot read /etc/shadow (not root) - skipping password analysis"
    fi
    
    section "2.2 Privileged Group Membership"
    
    local priv_groups
    priv_groups=$(grep -E '^(sudo|wheel|admin|root|docker|lxd|disk):' /etc/group 2>/dev/null)
    finding "info" "Privileged Group Memberships:"
    cmd_output "$priv_groups"
    
    # Check for docker/lxd group (privesc risk)
    local docker_members
    docker_members=$(grep "^docker:" /etc/group 2>/dev/null | cut -d: -f4)
    if [[ -n "$docker_members" && "$docker_members" != "" ]]; then
        finding "high" "Users in Docker Group (Privilege Escalation Risk)" "Members: $docker_members"
    fi
    
    local lxd_members
    lxd_members=$(grep "^lxd:" /etc/group 2>/dev/null | cut -d: -f4)
    if [[ -n "$lxd_members" && "$lxd_members" != "" ]]; then
        finding "high" "Users in LXD Group (Privilege Escalation Risk)" "Members: $lxd_members"
    fi
    
    section "2.3 SSH Configuration Review"
    
    local sshd_config="/etc/ssh/sshd_config"
    local sshd_config_d="/etc/ssh/sshd_config.d"
    
    if file_exists "$sshd_config"; then
        finding "info" "SSH Configuration File: $sshd_config"
        
        # Helper to get effective SSH setting
        get_ssh_setting() {
            local setting="$1"
            local value
            # Check config.d first (takes precedence on modern systems)
            if dir_exists "$sshd_config_d"; then
                value=$(grep -hi "^$setting" "$sshd_config_d"/*.conf 2>/dev/null | tail -1 | awk '{print $2}')
            fi
            # Fall back to main config
            if [[ -z "$value" ]]; then
                value=$(grep -i "^$setting" "$sshd_config" 2>/dev/null | tail -1 | awk '{print $2}')
            fi
            echo "$value"
        }
        
        # PermitRootLogin
        local root_login
        root_login=$(get_ssh_setting "PermitRootLogin")
        case "${root_login,,}" in
            no|prohibit-password|forced-commands-only)
                finding "pass" "PermitRootLogin: $root_login"
                ;;
            yes|"")
                finding "high" "SSH Root Login Permitted" "PermitRootLogin is set to '${root_login:-yes (default)}'"
                ;;
            *)
                finding "check" "PermitRootLogin: $root_login" "Verify this setting is appropriate"
                ;;
        esac
        
        # PasswordAuthentication
        local pass_auth
        pass_auth=$(get_ssh_setting "PasswordAuthentication")
        case "${pass_auth,,}" in
            no)
                finding "pass" "PasswordAuthentication: no (key-based auth enforced)"
                ;;
            yes|"")
                finding "medium" "SSH Password Authentication Enabled" "Consider enforcing key-based authentication only"
                ;;
        esac
        
        # PermitEmptyPasswords
        local empty_pass_ssh
        empty_pass_ssh=$(get_ssh_setting "PermitEmptyPasswords")
        case "${empty_pass_ssh,,}" in
            no|"")
                finding "pass" "PermitEmptyPasswords: no"
                ;;
            yes)
                finding "critical" "SSH Allows Empty Passwords" "PermitEmptyPasswords is set to 'yes'"
                ;;
        esac
        
        # X11Forwarding
        local x11_fwd
        x11_fwd=$(get_ssh_setting "X11Forwarding")
        case "${x11_fwd,,}" in
            no)
                finding "pass" "X11Forwarding: no"
                ;;
            yes|"")
                finding "low" "X11 Forwarding Enabled" "Consider disabling if not required"
                ;;
        esac
        
        # MaxAuthTries
        local max_auth
        max_auth=$(get_ssh_setting "MaxAuthTries")
        if [[ -n "$max_auth" ]]; then
            if [[ $max_auth -le 3 ]]; then
                finding "pass" "MaxAuthTries: $max_auth"
            elif [[ $max_auth -le 6 ]]; then
                finding "low" "MaxAuthTries Could Be Lower" "Currently set to $max_auth (recommended: 3 or less)"
            else
                finding "medium" "MaxAuthTries Too High" "Currently set to $max_auth (recommended: 3 or less)"
            fi
        else
            finding "info" "MaxAuthTries: not set (default: 6)"
        fi
        
        # Protocol (legacy check)
        local protocol
        protocol=$(get_ssh_setting "Protocol")
        if [[ "$protocol" == "1" ]]; then
            finding "critical" "SSH Protocol 1 Enabled" "Protocol 1 is insecure and deprecated"
        fi
        
    else
        finding "info" "SSH configuration file not found at $sshd_config"
    fi
    
    section "2.4 Sudo Configuration Review"
    
    if file_exists /etc/sudoers; then
        # NOPASSWD entries
        local nopasswd
        nopasswd=$(grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | grep -v ":#")
        if [[ -n "$nopasswd" ]]; then
            finding "high" "NOPASSWD Sudo Entries Found" "Users can execute commands as root without password"
            cmd_output "$nopasswd"
        else
            finding "pass" "No NOPASSWD sudo entries found"
        fi
        
        # ALL=(ALL) entries
        local all_all
        all_all=$(grep -rE '^\s*[^#].*ALL\s*=\s*\(ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null)
        if [[ -n "$all_all" ]]; then
            finding "info" "Users/Groups with Full Sudo Privileges:"
            cmd_output "$all_all"
        fi
        
        # Check sudoers.d directory
        if dir_exists /etc/sudoers.d; then
            local sudoers_files
            sudoers_files=$(ls -la /etc/sudoers.d/ 2>/dev/null)
            finding "info" "Sudoers.d Directory Contents:"
            cmd_output "$sudoers_files"
        fi
    fi
    
    # Sudo version (CVE check)
    local sudo_version
    sudo_version=$(sudo --version 2>/dev/null | head -1)
    finding "info" "Sudo Version: $sudo_version"
    
    # Check for known vulnerable sudo versions (Baron Samedit CVE-2021-3156)
    if echo "$sudo_version" | grep -qE "1\.(8\.[0-9]|8\.1[0-9]|8\.2[0-9]|8\.30|8\.31|9\.0\.[0-1])"; then
        finding "check" "Sudo Version May Be Vulnerable to CVE-2021-3156 (Baron Samedit)" "Verify patching status"
    fi
}

#===============================================================================
# PHASE 3: FILESYSTEM AND PERMISSIONS
#===============================================================================
phase3_filesystem() {
    banner "PHASE 3: FILESYSTEM AND PERMISSIONS"
    
    section "3.1 SUID/SGID Binary Analysis"
    
    subsection "SUID Binaries"
    local suid_bins
    suid_bins=$(find / -perm -4000 -type f 2>/dev/null | head -50)
    finding "info" "SUID Binaries Found:"
    cmd_output "$suid_bins"
    
    # Check for unusual SUID binaries (potential backdoors or misconfigurations)
    local unusual_suid
    unusual_suid=$(echo "$suid_bins" | grep -vE "/(ping|sudo|su|passwd|chsh|chfn|mount|umount|newgrp|gpasswd|pkexec|crontab|ssh-keysign|Xorg|unix_chkpwd|at|fusermount|staprun)" 2>/dev/null)
    if [[ -n "$unusual_suid" ]]; then
        finding "check" "Non-Standard SUID Binaries (Review Required):" "Cross-reference with GTFOBins"
        cmd_output "$unusual_suid"
    fi
    
    subsection "SGID Binaries"
    local sgid_bins
    sgid_bins=$(find / -perm -2000 -type f 2>/dev/null | head -30)
    finding "info" "SGID Binaries Found (sample):"
    cmd_output "$sgid_bins"
    
    section "3.2 World-Writable Files and Directories"
    
    local world_writable_files
    world_writable_files=$(find / -xdev -perm -0002 -type f ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -30)
    if [[ -n "$world_writable_files" ]]; then
        finding "medium" "World-Writable Files Found:"
        cmd_output "$world_writable_files"
    else
        finding "pass" "No world-writable files found (excluding /proc, /sys)"
    fi
    
    local world_writable_dirs
    world_writable_dirs=$(find / -xdev -perm -0002 -type d ! -path "/tmp" ! -path "/var/tmp" ! -path "/dev/shm" ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -20)
    if [[ -n "$world_writable_dirs" ]]; then
        finding "medium" "World-Writable Directories (excluding /tmp, /var/tmp, /dev/shm):"
        cmd_output "$world_writable_dirs"
    else
        finding "pass" "No unexpected world-writable directories found"
    fi
    
    section "3.3 Sensitive File Permissions"
    
    # /etc/shadow
    local shadow_perms
    shadow_perms=$(ls -la /etc/shadow 2>/dev/null)
    finding "info" "/etc/shadow permissions:"
    cmd_output "$shadow_perms"
    
    if [[ $(stat -c %a /etc/shadow 2>/dev/null) != "640" && $(stat -c %a /etc/shadow 2>/dev/null) != "600" && $(stat -c %a /etc/shadow 2>/dev/null) != "000" ]]; then
        finding "high" "/etc/shadow Has Weak Permissions" "Should be 640 or more restrictive"
    else
        finding "pass" "/etc/shadow has appropriate permissions"
    fi
    
    # /etc/passwd
    local passwd_perms
    passwd_perms=$(ls -la /etc/passwd 2>/dev/null)
    if [[ -w /etc/passwd ]]; then
        finding "critical" "/etc/passwd is Writable" "Privilege escalation possible"
    else
        finding "pass" "/etc/passwd is not writable by current user"
    fi
    
    # /etc/sudoers
    local sudoers_perms
    sudoers_perms=$(ls -la /etc/sudoers 2>/dev/null)
    finding "info" "/etc/sudoers permissions:"
    cmd_output "$sudoers_perms"
    
    section "3.4 Mount Options Review"
    
    finding "info" "Current Mount Points:"
    local mounts
    mounts=$(mount | column -t 2>/dev/null)
    cmd_output "$mounts"
    
    # Check /tmp mount options
    local tmp_mount
    tmp_mount=$(mount | grep " /tmp " 2>/dev/null)
    if [[ -n "$tmp_mount" ]]; then
        if echo "$tmp_mount" | grep -qE "noexec.*nosuid|nosuid.*noexec"; then
            finding "pass" "/tmp has noexec and nosuid options"
        else
            finding "medium" "/tmp Missing Security Mount Options" "Consider adding noexec,nosuid,nodev"
        fi
    else
        finding "medium" "/tmp Not Mounted as Separate Partition" "Consider separate partition with noexec,nosuid,nodev"
    fi
    
    # Check /var/tmp mount options
    local var_tmp_mount
    var_tmp_mount=$(mount | grep " /var/tmp " 2>/dev/null)
    if [[ -z "$var_tmp_mount" ]]; then
        finding "low" "/var/tmp Not Mounted as Separate Partition"
    fi
    
    section "3.5 File Capabilities"
    
    if cmd_exists getcap; then
        local caps
        caps=$(getcap -r / 2>/dev/null | head -30)
        if [[ -n "$caps" ]]; then
            finding "info" "Files with Capabilities Set:"
            cmd_output "$caps"
            
            # Flag dangerous capabilities
            local dangerous_caps
            dangerous_caps=$(echo "$caps" | grep -E "cap_setuid|cap_setgid|cap_sys_admin|cap_sys_ptrace|cap_dac_override" 2>/dev/null)
            if [[ -n "$dangerous_caps" ]]; then
                finding "high" "Potentially Dangerous Capabilities Found:" "Review for privilege escalation vectors"
                cmd_output "$dangerous_caps"
            fi
        else
            finding "info" "No file capabilities found"
        fi
    else
        finding "info" "getcap not available - skipping capability check"
    fi
}

#===============================================================================
# PHASE 4: NETWORK CONFIGURATION
#===============================================================================
phase4_network() {
    banner "PHASE 4: NETWORK CONFIGURATION"
    
    section "4.1 Kernel Network Security Parameters"
    
    # IP Forwarding
    local ip_forward
    ip_forward=$(sysctl net.ipv4.ip_forward 2>/dev/null | awk '{print $3}')
    if [[ "$ip_forward" == "1" ]]; then
        finding "medium" "IPv4 Forwarding Enabled" "Should be disabled unless host is a router"
    else
        finding "pass" "IPv4 forwarding disabled"
    fi
    
    local ip6_forward
    ip6_forward=$(sysctl net.ipv6.conf.all.forwarding 2>/dev/null | awk '{print $3}')
    if [[ "$ip6_forward" == "1" ]]; then
        finding "medium" "IPv6 Forwarding Enabled"
    else
        finding "pass" "IPv6 forwarding disabled"
    fi
    
    # ICMP Redirects
    local accept_redirects
    accept_redirects=$(sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | awk '{print $3}')
    if [[ "$accept_redirects" == "1" ]]; then
        finding "low" "ICMP Redirect Acceptance Enabled" "Consider disabling"
    else
        finding "pass" "ICMP redirect acceptance disabled"
    fi
    
    # SYN Cookies
    local syncookies
    syncookies=$(sysctl net.ipv4.tcp_syncookies 2>/dev/null | awk '{print $3}')
    if [[ "$syncookies" == "1" ]]; then
        finding "pass" "TCP SYN cookies enabled"
    else
        finding "medium" "TCP SYN Cookies Disabled" "Vulnerable to SYN flood attacks"
    fi
    
    # Source routing
    local source_route
    source_route=$(sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null | awk '{print $3}')
    if [[ "$source_route" == "0" ]]; then
        finding "pass" "Source routing disabled"
    else
        finding "medium" "Source Routing Enabled" "Should be disabled"
    fi
    
    section "4.2 Firewall Configuration"
    
    local firewall_found=0
    
    # iptables
    if cmd_exists iptables; then
        local iptables_rules
        iptables_rules=$(iptables -L -n 2>/dev/null | grep -v "^Chain\|^target\|^$" | head -20)
        if [[ -n "$iptables_rules" ]]; then
            firewall_found=1
            finding "info" "iptables Rules (IPv4):"
            cmd_output "$(iptables -L -n -v 2>/dev/null | head -30)"
        fi
    fi
    
    # nftables
    if cmd_exists nft; then
        local nft_rules
        nft_rules=$(nft list ruleset 2>/dev/null)
        if [[ -n "$nft_rules" ]]; then
            firewall_found=1
            finding "info" "nftables Ruleset:"
            cmd_output "$(echo "$nft_rules" | head -30)"
        fi
    fi
    
    # UFW
    if cmd_exists ufw; then
        local ufw_status
        ufw_status=$(ufw status verbose 2>/dev/null)
        if echo "$ufw_status" | grep -q "Status: active"; then
            firewall_found=1
            finding "info" "UFW Status:"
            cmd_output "$ufw_status"
        fi
    fi
    
    # firewalld
    if cmd_exists firewall-cmd; then
        local firewalld_status
        firewalld_status=$(firewall-cmd --state 2>/dev/null)
        if [[ "$firewalld_status" == "running" ]]; then
            firewall_found=1
            finding "info" "firewalld Status:"
            cmd_output "$(firewall-cmd --list-all 2>/dev/null)"
        fi
    fi
    
    if [[ $firewall_found -eq 0 ]]; then
        finding "high" "No Active Host Firewall Detected" "Implement iptables, nftables, UFW, or firewalld"
    fi
}

#===============================================================================
# PHASE 5: LOGGING AND AUDITING
#===============================================================================
phase5_logging() {
    banner "PHASE 5: LOGGING AND AUDITING"
    
    section "5.1 Audit Daemon Status"
    
    if is_service_running auditd; then
        finding "pass" "auditd is running"
        
        local audit_rules
        audit_rules=$(auditctl -l 2>/dev/null | head -20)
        if [[ -n "$audit_rules" && ! "$audit_rules" =~ "No rules" ]]; then
            finding "info" "Active Audit Rules (sample):"
            cmd_output "$audit_rules"
        else
            finding "medium" "auditd Running But No Rules Configured"
        fi
    else
        finding "high" "Audit Daemon (auditd) Not Running" "Critical for security monitoring and compliance"
    fi
    
    section "5.2 Syslog Configuration"
    
    local syslog_running=0
    
    if is_service_running rsyslog; then
        finding "pass" "rsyslog is running"
        syslog_running=1
    elif is_service_running syslog-ng; then
        finding "pass" "syslog-ng is running"
        syslog_running=1
    elif is_service_running systemd-journald; then
        finding "info" "systemd-journald is running (no traditional syslog)"
        syslog_running=1
    fi
    
    if [[ $syslog_running -eq 0 ]]; then
        finding "high" "No Syslog Service Detected"
    fi
    
    # Check for remote logging
    local remote_log
    remote_log=$(grep -rE "^[^#].*@" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null)
    if [[ -n "$remote_log" ]]; then
        finding "pass" "Remote syslog forwarding configured"
        cmd_output "$remote_log"
    else
        finding "medium" "No Remote Log Forwarding Configured" "Logs should be shipped to central SIEM"
    fi
    
    section "5.3 Log File Permissions"
    
    finding "info" "Key Log Files:"
    local log_perms
    log_perms=$(ls -la /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages 2>/dev/null | head -10)
    cmd_output "$log_perms"
}

#===============================================================================
# PHASE 6: PAM AND PASSWORD POLICY
#===============================================================================
phase6_pam() {
    banner "PHASE 6: PAM AND PASSWORD POLICY"
    
    section "6.1 Password Complexity (pwquality)"
    
    if file_exists /etc/security/pwquality.conf; then
        finding "info" "pwquality.conf Settings:"
        local pwquality
        pwquality=$(grep -vE "^#|^$" /etc/security/pwquality.conf 2>/dev/null)
        if [[ -n "$pwquality" ]]; then
            cmd_output "$pwquality"
        else
            finding "medium" "pwquality.conf Exists But No Custom Settings"
        fi
    else
        finding "medium" "pwquality.conf Not Found" "Password complexity may not be enforced"
    fi
    
    section "6.2 Account Lockout Policy"
    
    local lockout_configured=0
    
    # Check faillock
    if file_exists /etc/security/faillock.conf; then
        finding "info" "faillock.conf Settings:"
        local faillock
        faillock=$(grep -vE "^#|^$" /etc/security/faillock.conf 2>/dev/null)
        cmd_output "$faillock"
        lockout_configured=1
    fi
    
    # Check PAM for faillock/tally
    local pam_lockout
    pam_lockout=$(grep -rE "pam_faillock|pam_tally" /etc/pam.d/ 2>/dev/null | grep -v "^#")
    if [[ -n "$pam_lockout" ]]; then
        finding "info" "PAM Account Lockout Configuration:"
        cmd_output "$pam_lockout"
        lockout_configured=1
    fi
    
    if [[ $lockout_configured -eq 0 ]]; then
        finding "medium" "No Account Lockout Policy Detected" "Vulnerable to brute force attacks"
    fi
    
    section "6.3 Password Hashing Algorithm"
    
    local hash_algo
    hash_algo=$(grep "^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null)
    if [[ -n "$hash_algo" ]]; then
        if echo "$hash_algo" | grep -qiE "SHA512|YESCRYPT"; then
            finding "pass" "Strong password hashing: $hash_algo"
        else
            finding "medium" "Weak Password Hashing Algorithm" "$hash_algo"
        fi
    fi
}

#===============================================================================
# PHASE 7: KERNEL AND BOOT SECURITY
#===============================================================================
phase7_kernel() {
    banner "PHASE 7: KERNEL AND BOOT SECURITY"
    
    section "7.1 Mandatory Access Control"
    
    # SELinux
    if cmd_exists getenforce; then
        local selinux_status
        selinux_status=$(getenforce 2>/dev/null)
        case "$selinux_status" in
            Enforcing)
                finding "pass" "SELinux is enforcing"
                ;;
            Permissive)
                finding "medium" "SELinux is Permissive" "Should be set to Enforcing"
                ;;
            Disabled)
                finding "high" "SELinux is Disabled" "No mandatory access control in place"
                ;;
        esac
    fi
    
    # AppArmor
    if cmd_exists aa-status; then
        local apparmor_status
        apparmor_status=$(aa-status 2>/dev/null | head -5)
        if [[ -n "$apparmor_status" ]]; then
            finding "info" "AppArmor Status:"
            cmd_output "$apparmor_status"
            
            local profiles_enforcing
            profiles_enforcing=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}')
            if [[ -n "$profiles_enforcing" && "$profiles_enforcing" -gt 0 ]]; then
                finding "pass" "AppArmor has $profiles_enforcing profiles in enforce mode"
            else
                finding "medium" "AppArmor Installed But No Profiles Enforcing"
            fi
        fi
    fi
    
    # Neither installed
    if ! cmd_exists getenforce && ! cmd_exists aa-status; then
        finding "high" "No MAC Framework (SELinux/AppArmor) Detected"
    fi
    
    section "7.2 Bootloader Security"
    
    # GRUB password
    local grub_pass
    grub_pass=$(grep -rE "^password" /etc/grub.d/ /boot/grub/grub.cfg /boot/grub2/grub.cfg 2>/dev/null | grep -v "password_pbkdf2 root")
    local grub_pass2
    grub_pass2=$(grep -rE "password_pbkdf2" /etc/grub.d/ /boot/grub/grub.cfg /boot/grub2/grub.cfg 2>/dev/null)
    
    if [[ -n "$grub_pass2" ]]; then
        finding "pass" "GRUB bootloader password is configured"
    else
        finding "medium" "No GRUB Bootloader Password" "Physical access could allow single-user mode boot"
    fi
    
    # Secure Boot
    if cmd_exists mokutil; then
        local secureboot
        secureboot=$(mokutil --sb-state 2>/dev/null)
        finding "info" "Secure Boot Status: $secureboot"
    fi
    
    section "7.3 Kernel Version"
    
    local kernel_version
    kernel_version=$(uname -r)
    finding "info" "Current Kernel: $kernel_version"
    finding "check" "Cross-reference with kernel.org and CVE databases for known vulnerabilities"
}

#===============================================================================
# PHASE 8: CREDENTIAL EXPOSURE ANALYSIS
#===============================================================================
phase8_credentials() {
    banner "PHASE 8: CREDENTIAL EXPOSURE ANALYSIS"
    
    section "8.1 SSH Keys"
    
    # Private keys in common locations
    local ssh_private_keys
    ssh_private_keys=$(find /home /root -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "id_dsa" 2>/dev/null)
    if [[ -n "$ssh_private_keys" ]]; then
        finding "info" "SSH Private Keys Found:"
        cmd_output "$ssh_private_keys"
        
        # Check permissions on private keys
        while IFS= read -r keyfile; do
            local key_perms
            key_perms=$(stat -c %a "$keyfile" 2>/dev/null)
            if [[ "$key_perms" != "600" && "$key_perms" != "400" ]]; then
                finding "medium" "SSH Private Key with Weak Permissions" "$keyfile has permissions $key_perms"
            fi
        done <<< "$ssh_private_keys"
    fi
    
    # Authorized keys
    local auth_keys
    auth_keys=$(find /home /root -name "authorized_keys" 2>/dev/null)
    if [[ -n "$auth_keys" ]]; then
        finding "info" "Authorized Keys Files:"
        cmd_output "$auth_keys"
    fi
    
    section "8.2 AWS/Cloud Credentials"
    
    local aws_creds
    aws_creds=$(find /home /root -path "*/.aws/credentials" 2>/dev/null)
    if [[ -n "$aws_creds" ]]; then
        finding "high" "AWS Credentials Files Found:" "Review for exposure and rotate if necessary"
        cmd_output "$aws_creds"
    fi
    
    local gcp_creds
    gcp_creds=$(find /home /root -name "*.json" -path "*/.config/gcloud/*" 2>/dev/null)
    if [[ -n "$gcp_creds" ]]; then
        finding "high" "GCP Service Account Keys Found:"
        cmd_output "$gcp_creds"
    fi
    
    local azure_creds
    azure_creds=$(find /home /root -path "*/.azure/*" -name "*.json" 2>/dev/null)
    if [[ -n "$azure_creds" ]]; then
        finding "medium" "Azure CLI Configuration Found:"
        cmd_output "$azure_creds"
    fi
    
    section "8.3 History Files"
    
    local history_files
    history_files=$(find /home /root -maxdepth 2 -name ".*history" -o -name ".bash_history" -o -name ".zsh_history" 2>/dev/null)
    if [[ -n "$history_files" ]]; then
        finding "info" "Shell History Files Found:"
        cmd_output "$history_files"
        
        # Sample check for passwords in history
        local history_passwords
        history_passwords=$(grep -hiE "password|passwd|pass=|secret|token|api_key" $history_files 2>/dev/null | head -10)
        if [[ -n "$history_passwords" ]]; then
            finding "high" "Potential Credentials in Shell History:" "Review and clear history files"
            cmd_output "$history_passwords"
        fi
    fi
    
    section "8.4 Configuration File Credential Search"
    
    finding "info" "Searching for credential keywords in config files (sample)..."
    local config_creds
    config_creds=$(find /etc /opt /var/www -type f \( -name "*.conf" -o -name "*.config" -o -name "*.cfg" -o -name "*.ini" -o -name "*.env" -o -name "*.yml" -o -name "*.yaml" \) 2>/dev/null | \
        xargs grep -l -iE "password\s*=|passwd\s*=|secret\s*=|api_key\s*=|token\s*=" 2>/dev/null | head -20)
    if [[ -n "$config_creds" ]]; then
        finding "check" "Files Potentially Containing Credentials:" "Manual review required"
        cmd_output "$config_creds"
    fi
    
    # .env files
    local env_files
    env_files=$(find /var/www /opt /home -name ".env" -o -name "*.env" 2>/dev/null | head -10)
    if [[ -n "$env_files" ]]; then
        finding "check" ".env Files Found (may contain secrets):"
        cmd_output "$env_files"
    fi
}

#===============================================================================
# PHASE 9: CRON AND SCHEDULED TASKS
#===============================================================================
phase9_cron() {
    banner "PHASE 9: CRON AND SCHEDULED TASKS"
    
    section "9.1 System Crontabs"
    
    if file_exists /etc/crontab; then
        finding "info" "/etc/crontab Contents:"
        local crontab_content
        crontab_content=$(grep -vE "^#|^$" /etc/crontab 2>/dev/null)
        cmd_output "$crontab_content"
    fi
    
    # Cron directories
    for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if dir_exists "$crondir"; then
            local cron_files
            cron_files=$(ls -la "$crondir" 2>/dev/null | grep -v "^total")
            finding "info" "$crondir Contents:"
            cmd_output "$cron_files"
        fi
    done
    
    section "9.2 User Crontabs"
    
    if is_root && dir_exists /var/spool/cron/crontabs; then
        local user_crons
        user_crons=$(ls /var/spool/cron/crontabs/ 2>/dev/null)
        if [[ -n "$user_crons" ]]; then
            finding "info" "User Crontabs Found:"
            for user in $user_crons; do
                finding "info" "Crontab for $user:"
                cmd_output "$(cat /var/spool/cron/crontabs/$user 2>/dev/null | grep -v "^#")"
            done
        fi
    fi
    
    section "9.3 Systemd Timers"
    
    local timers
    timers=$(systemctl list-timers --all --no-pager 2>/dev/null | head -20)
    finding "info" "Active Systemd Timers:"
    cmd_output "$timers"
    
    section "9.4 World-Writable Cron Scripts"
    
    local writable_cron
    writable_cron=$(find /etc/cron* /var/spool/cron -perm -0002 -type f 2>/dev/null)
    if [[ -n "$writable_cron" ]]; then
        finding "critical" "World-Writable Cron Scripts Found:" "Privilege escalation vector"
        cmd_output "$writable_cron"
    else
        finding "pass" "No world-writable cron scripts found"
    fi
}

#===============================================================================
# PHASE 10: SERVICES AND APPLICATIONS
#===============================================================================
phase10_services() {
    banner "PHASE 10: THIRD-PARTY SERVICES"
    
    section "10.1 Web Servers"
    
    # Apache
    if cmd_exists apache2 || cmd_exists httpd; then
        local apache_version
        apache_version=$(apache2 -v 2>/dev/null || httpd -v 2>/dev/null)
        finding "info" "Apache Version:"
        cmd_output "$apache_version"
        
        local server_tokens
        server_tokens=$(grep -riE "ServerTokens|ServerSignature" /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -v "^#")
        if [[ -n "$server_tokens" ]]; then
            finding "info" "Apache Server Token Settings:"
            cmd_output "$server_tokens"
        else
            finding "low" "Apache ServerTokens/ServerSignature Not Configured" "May disclose version info"
        fi
    fi
    
    # Nginx
    if cmd_exists nginx; then
        local nginx_version
        nginx_version=$(nginx -v 2>&1)
        finding "info" "Nginx Version: $nginx_version"
        
        local nginx_tokens
        nginx_tokens=$(grep -riE "server_tokens" /etc/nginx/ 2>/dev/null | grep -v "^#")
        if echo "$nginx_tokens" | grep -q "off"; then
            finding "pass" "Nginx server_tokens is disabled"
        else
            finding "low" "Nginx Server Tokens May Be Enabled" "Version disclosure"
        fi
    fi
    
    section "10.2 Database Servers"
    
    # MySQL/MariaDB
    if cmd_exists mysql; then
        local mysql_version
        mysql_version=$(mysql --version 2>/dev/null)
        finding "info" "MySQL/MariaDB: $mysql_version"
        
        # Check for root without password
        if mysql -u root -e "SELECT 1" 2>/dev/null; then
            finding "critical" "MySQL Root Access Without Password"
        fi
    fi
    
    # PostgreSQL
    if cmd_exists psql; then
        local psql_version
        psql_version=$(psql --version 2>/dev/null)
        finding "info" "PostgreSQL: $psql_version"
    fi
    
    section "10.3 Container Runtime"
    
    if cmd_exists docker; then
        local docker_version
        docker_version=$(docker --version 2>/dev/null)
        finding "info" "Docker: $docker_version"
        
        local docker_containers
        docker_containers=$(docker ps -a 2>/dev/null | tail -n +2)
        if [[ -n "$docker_containers" ]]; then
            finding "info" "Docker Containers:"
            cmd_output "$docker_containers"
        fi
        
        # Check Docker socket permissions
        local docker_sock_perms
        docker_sock_perms=$(ls -la /var/run/docker.sock 2>/dev/null)
        finding "info" "Docker Socket Permissions:"
        cmd_output "$docker_sock_perms"
    fi
}

#===============================================================================
# SUMMARY GENERATION
#===============================================================================
generate_summary() {
    banner "ASSESSMENT SUMMARY"
    
    log "Review Date: $(date)"
    log "Hostname: $(hostname -f 2>/dev/null || hostname)"
    log "OS: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)"
    log "Kernel: $(uname -r)"
    log ""
    log "This report was generated by an automated script. All findings should be"
    log "manually verified and cross-referenced with the target environment's"
    log "security policies and compliance requirements."
    log ""
    log "${BOLD}Severity Legend:${NC}"
    log "  $(tag_critical) - Immediate remediation required"
    log "  $(tag_high)     - High priority finding"
    log "  $(tag_medium)   - Moderate risk, should be addressed"
    log "  $(tag_low)      - Low risk, best practice recommendation"
    log "  $(tag_info)     - Informational"
    log "  $(tag_pass)     - Security control validated"
    log "  $(tag_check)    - Requires manual verification"
    log ""
}

#===============================================================================
# MAIN EXECUTION
#===============================================================================
main() {
    parse_args "$@"
    
    # Print banner
    log ""
    log "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    log "${BOLD}${CYAN}║                       LINUX BUILD REVIEW SCRIPT                              ║${NC}"
    log "${BOLD}${CYAN}║                              Version $VERSION                                  ║${NC}"
    log "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    log ""
    log "${YELLOW}[*] Target Host: $(hostname -f 2>/dev/null || hostname)${NC}"
    log "${YELLOW}[*] Assessment Date: $(date)${NC}"
    log "${YELLOW}[*] Output File: $OUTPUT_FILE${NC}"
    log ""
    
    # Root check
    if ! is_root; then
        log "${ORANGE}[!] Warning: Not running as root. Some checks will be limited.${NC}"
        log "${ORANGE}[!] For comprehensive results, run with: sudo $0${NC}"
        log ""
    fi
    
    # Run all phases
    phase1_system_info
    phase2_user_auth
    phase3_filesystem
    phase4_network
    phase5_logging
    phase6_pam
    phase7_kernel
    phase8_credentials
    phase9_cron
    phase10_services
    
    # Generate summary
    generate_summary
    
    # Save report
    save_report
    
    log ""
    log "${GREEN}[+] Assessment complete.${NC}"
}

# Execute main function
main "$@"
