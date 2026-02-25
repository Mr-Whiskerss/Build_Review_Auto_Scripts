#!/bin/bash

#===============================================================================
# macOS Security Audit Script
# Based on macOS Build Review Methodology
# 
# Usage: sudo ./macos_security_audit.sh [options]
#
# Options:
#   -o, --output FILE    Output report to file (default: stdout + macos_audit_TIMESTAMP.txt)
#   -q, --quiet          Suppress banner and colors
#   -h, --help           Show this help message
#
# Note: Run with sudo for complete results. Some checks require root privileges.
#===============================================================================

set -o pipefail

# Version
VERSION="1.0.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Counters
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0
PASS_COUNT=0

# Options
QUIET=false
OUTPUT_FILE=""
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DEFAULT_OUTPUT="macos_audit_${TIMESTAMP}.txt"

#===============================================================================
# Helper Functions
#===============================================================================

show_help() {
    echo "macOS Security Audit Script v${VERSION}"
    echo ""
    echo "Usage: sudo $0 [options]"
    echo ""
    echo "Options:"
    echo "  -o, --output FILE    Output report to file"
    echo "  -q, --quiet          Suppress banner and colors"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Note: Run with sudo for complete results."
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -q|--quiet)
                QUIET=true
                RED=''
                GREEN=''
                YELLOW=''
                BLUE=''
                CYAN=''
                PURPLE=''
                NC=''
                BOLD=''
                shift
                ;;
            -h|--help)
                show_help
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                ;;
        esac
    done
}

banner() {
    if [ "$QUIET" = false ]; then
        echo -e "${CYAN}"
        echo "╔═══════════════════════════════════════════════════════════════════╗"
        echo "║                  macOS Security Audit Script                      ║"
        echo "║                        Version ${VERSION}                              ║"
        echo "╚═══════════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
    fi
}

section_header() {
    echo ""
    echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}${BOLD}  $1${NC}"
    echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

subsection_header() {
    echo ""
    echo -e "${PURPLE}  ─── $1 ───${NC}"
}

# Result functions with severity tracking
result_critical() {
    echo -e "    ${RED}[CRITICAL]${NC} $1"
    ((CRITICAL_COUNT++))
}

result_high() {
    echo -e "    ${RED}[HIGH]${NC} $1"
    ((HIGH_COUNT++))
}

result_medium() {
    echo -e "    ${YELLOW}[MEDIUM]${NC} $1"
    ((MEDIUM_COUNT++))
}

result_low() {
    echo -e "    ${YELLOW}[LOW]${NC} $1"
    ((LOW_COUNT++))
}

result_pass() {
    echo -e "    ${GREEN}[PASS]${NC} $1"
    ((PASS_COUNT++))
}

result_info() {
    echo -e "    ${CYAN}[INFO]${NC} $1"
    ((INFO_COUNT++))
}

result_error() {
    echo -e "    ${RED}[ERROR]${NC} $1 (may require elevated privileges)"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}[!] Warning: Not running as root. Some checks may be incomplete.${NC}"
        echo -e "${YELLOW}[!] Run with: sudo $0${NC}"
        echo ""
    fi
}

#===============================================================================
# System Information
#===============================================================================

get_system_info() {
    section_header "SYSTEM INFORMATION"
    
    subsection_header "Basic Info"
    
    # macOS Version
    local macos_version=$(sw_vers -productVersion 2>/dev/null)
    local macos_build=$(sw_vers -buildVersion 2>/dev/null)
    local macos_name=$(sw_vers -productName 2>/dev/null)
    result_info "OS: ${macos_name} ${macos_version} (Build ${macos_build})"
    
    # Hardware
    local hw_model=$(sysctl -n hw.model 2>/dev/null)
    result_info "Hardware Model: ${hw_model}"
    
    # Check for Apple Silicon
    local cpu_brand=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
    if [[ "$cpu_brand" == *"Apple"* ]] || [[ "$hw_model" == *"Mac"*"1"* ]] || [[ "$hw_model" == *"Mac"*"2"* ]] || [[ "$hw_model" == *"Mac"*"3"* ]]; then
        result_info "Architecture: Apple Silicon"
    else
        result_info "Architecture: Intel"
    fi
    
    # Kernel
    local kernel=$(uname -r 2>/dev/null)
    result_info "Kernel Version: ${kernel}"
    
    # Hostname
    local hostname=$(hostname 2>/dev/null)
    result_info "Hostname: ${hostname}"
    
    # Serial Number
    local serial=$(system_profiler SPHardwareDataType 2>/dev/null | grep "Serial Number" | awk -F': ' '{print $2}')
    result_info "Serial Number: ${serial}"
    
    # Uptime
    local uptime_info=$(uptime 2>/dev/null)
    result_info "Uptime: ${uptime_info}"
}

#===============================================================================
# System Integrity Protection (SIP)
#===============================================================================

check_sip() {
    section_header "SYSTEM INTEGRITY PROTECTION (SIP)"
    
    local sip_status=$(csrutil status 2>/dev/null)
    
    if echo "$sip_status" | grep -q "enabled"; then
        result_pass "SIP is enabled"
        
        # Check individual components if partially enabled
        if echo "$sip_status" | grep -q "Custom Configuration"; then
            result_medium "SIP has custom configuration - review components"
            echo "$sip_status" | while read -r line; do
                if [[ "$line" == *":"* ]] && [[ "$line" != *"status"* ]]; then
                    result_info "  $line"
                fi
            done
        fi
    elif echo "$sip_status" | grep -q "disabled"; then
        result_critical "SIP is DISABLED - System is vulnerable to rootkits and malware"
    else
        result_error "Could not determine SIP status"
    fi
    
    # Check Authenticated Root (macOS 11+)
    local auth_root=$(csrutil authenticated-root status 2>/dev/null)
    if [ -n "$auth_root" ]; then
        if echo "$auth_root" | grep -q "enabled"; then
            result_pass "Authenticated Root is enabled"
        elif echo "$auth_root" | grep -q "disabled"; then
            result_high "Authenticated Root is disabled"
        fi
    fi
}

#===============================================================================
# Gatekeeper & XProtect
#===============================================================================

check_gatekeeper() {
    section_header "GATEKEEPER & MALWARE PROTECTION"
    
    subsection_header "Gatekeeper"
    
    local gk_status=$(spctl --status 2>/dev/null)
    
    if echo "$gk_status" | grep -q "enabled"; then
        result_pass "Gatekeeper is enabled"
    else
        result_critical "Gatekeeper is DISABLED - Unsigned apps can run freely"
    fi
    
    # Check assessment sources
    local gk_master=$(defaults read /Library/Preferences/com.apple.security GKAutoRearm 2>/dev/null)
    
    subsection_header "XProtect"
    
    # XProtect version/update
    local xprotect_plist="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist"
    local xprotect_alt="/System/Library/CoreServices/XProtect.bundle/Contents/version.plist"
    
    if [ -f "$xprotect_plist" ]; then
        local xp_version=$(defaults read "$xprotect_plist" CFBundleShortVersionString 2>/dev/null)
        result_info "XProtect Version: ${xp_version}"
    elif [ -f "$xprotect_alt" ]; then
        local xp_version=$(defaults read "$xprotect_alt" CFBundleShortVersionString 2>/dev/null)
        result_info "XProtect Version: ${xp_version}"
    fi
    
    # Check last XProtect update
    local xprotect_update=$(system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A5 "XProtect" | head -10)
    if [ -n "$xprotect_update" ]; then
        local last_update=$(echo "$xprotect_update" | grep "Install Date" | head -1 | awk -F': ' '{print $2}')
        if [ -n "$last_update" ]; then
            result_info "Last XProtect Update: ${last_update}"
        fi
    fi
    
    subsection_header "Malware Removal Tool (MRT)"
    
    local mrt_path="/Library/Apple/System/Library/CoreServices/MRT.app"
    local mrt_alt="/System/Library/CoreServices/MRT.app"
    
    if [ -d "$mrt_path" ] || [ -d "$mrt_alt" ]; then
        result_pass "MRT is present"
    else
        result_medium "MRT not found in expected location"
    fi
}

#===============================================================================
# FileVault
#===============================================================================

check_filevault() {
    section_header "FILEVAULT (FULL DISK ENCRYPTION)"
    
    local fv_status=$(fdesetup status 2>/dev/null)
    
    if echo "$fv_status" | grep -q "FileVault is On"; then
        result_pass "FileVault is enabled"
        
        # Check if encryption is complete
        if echo "$fv_status" | grep -q "Encryption in progress"; then
            result_medium "FileVault encryption is still in progress"
        fi
        
        # Check for recovery keys
        local has_institutional=$(fdesetup hasinstitutionalrecoverykey 2>/dev/null)
        local has_personal=$(fdesetup haspersonalrecoverykey 2>/dev/null)
        
        if echo "$has_institutional" | grep -q "true"; then
            result_pass "Institutional recovery key is escrowed"
        else
            result_info "No institutional recovery key"
        fi
        
        if echo "$has_personal" | grep -q "true"; then
            result_pass "Personal recovery key exists"
        else
            result_medium "No personal recovery key configured"
        fi
        
        # List FileVault users
        local fv_users=$(fdesetup list 2>/dev/null)
        if [ -n "$fv_users" ]; then
            result_info "FileVault enabled users:"
            echo "$fv_users" | while read -r user; do
                result_info "  - $user"
            done
        fi
        
    elif echo "$fv_status" | grep -q "FileVault is Off"; then
        result_critical "FileVault is DISABLED - Disk is not encrypted"
    else
        result_error "Could not determine FileVault status"
    fi
}

#===============================================================================
# User Account Security
#===============================================================================

check_user_accounts() {
    section_header "USER ACCOUNT SECURITY"
    
    subsection_header "User Accounts"
    
    # List non-system users
    local users=$(dscl . list /Users UniqueID 2>/dev/null | awk '$2 > 500 {print $1}')
    result_info "Local user accounts (UID > 500):"
    echo "$users" | while read -r user; do
        if [ -n "$user" ]; then
            result_info "  - $user"
        fi
    done
    
    # Admin users
    local admin_users=$(dscl . read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //')
    result_info "Admin group members: ${admin_users}"
    
    subsection_header "Guest Account"
    
    # Check guest account
    local guest_status=$(dscl . read /Users/Guest 2>/dev/null)
    if [ -n "$guest_status" ]; then
        local guest_enabled=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
        if [ "$guest_enabled" = "1" ]; then
            result_medium "Guest account is ENABLED"
        else
            result_pass "Guest account is disabled"
        fi
    else
        result_pass "Guest account does not exist"
    fi
    
    subsection_header "Auto-Login"
    
    # Check auto-login
    local auto_login=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
    if [ -n "$auto_login" ]; then
        result_high "Auto-login is ENABLED for user: ${auto_login}"
    else
        result_pass "Auto-login is disabled"
    fi
    
    subsection_header "Root Account"
    
    # Check if root is enabled
    local root_status=$(dscl . read /Users/root AuthenticationAuthority 2>/dev/null)
    if echo "$root_status" | grep -qi "DisabledUser"; then
        result_pass "Root account is disabled"
    elif [ -n "$root_status" ]; then
        result_critical "Root account may be ENABLED"
    else
        result_pass "Root account is disabled (no auth authority)"
    fi
    
    subsection_header "Password Policy"
    
    # Global password policy
    local pw_policy=$(pwpolicy -getglobalpolicy 2>/dev/null)
    if [ -n "$pw_policy" ] && [ "$pw_policy" != "No global policies" ]; then
        result_info "Global password policy is configured"
        # Parse some key settings
        if echo "$pw_policy" | grep -q "minChars"; then
            local min_chars=$(echo "$pw_policy" | grep -o 'minChars=[0-9]*' | cut -d= -f2)
            result_info "  Minimum password length: ${min_chars}"
        fi
    else
        result_medium "No global password policy configured"
    fi
    
    subsection_header "Screen Lock"
    
    # Screen saver password requirement
    local ss_password=$(defaults read com.apple.screensaver askForPassword 2>/dev/null)
    if [ "$ss_password" = "1" ]; then
        result_pass "Password required after screen saver"
        
        local ss_delay=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)
        if [ -n "$ss_delay" ]; then
            if [ "$ss_delay" -le 5 ]; then
                result_pass "Screen lock delay: ${ss_delay} seconds"
            else
                result_medium "Screen lock delay is ${ss_delay} seconds (recommended: 5 or less)"
            fi
        fi
    else
        result_high "Password NOT required after screen saver"
    fi
}

#===============================================================================
# Firewall
#===============================================================================

check_firewall() {
    section_header "FIREWALL CONFIGURATION"
    
    local fw_tool="/usr/libexec/ApplicationFirewall/socketfilterfw"
    
    if [ ! -x "$fw_tool" ]; then
        result_error "Firewall tool not found"
        return
    fi
    
    subsection_header "Firewall Status"
    
    # Global state
    local fw_state=$($fw_tool --getglobalstate 2>/dev/null)
    if echo "$fw_state" | grep -q "enabled"; then
        result_pass "Application Firewall is enabled"
    else
        result_high "Application Firewall is DISABLED"
    fi
    
    # Stealth mode
    local stealth=$($fw_tool --getstealthmode 2>/dev/null)
    if echo "$stealth" | grep -q "enabled"; then
        result_pass "Stealth mode is enabled"
    else
        result_medium "Stealth mode is disabled"
    fi
    
    # Block all incoming
    local block_all=$($fw_tool --getblockall 2>/dev/null)
    if echo "$block_all" | grep -q "DISABLED"; then
        result_info "Block all incoming: Disabled (normal operation)"
    else
        result_info "Block all incoming: Enabled (restrictive mode)"
    fi
    
    # Logging
    local logging=$($fw_tool --getloggingmode 2>/dev/null)
    if echo "$logging" | grep -q "on"; then
        result_pass "Firewall logging is enabled"
    else
        result_low "Firewall logging is disabled"
    fi
    
    # Auto-allow signed apps
    local allow_signed=$($fw_tool --getallowsigned 2>/dev/null)
    result_info "Auto-allow signed apps: ${allow_signed}"
    
    subsection_header "Allowed Applications"
    
    local allowed_apps=$($fw_tool --listapps 2>/dev/null)
    local app_count=$(echo "$allowed_apps" | grep -c "ALF" 2>/dev/null || echo "0")
    result_info "Applications with firewall exceptions: ${app_count}"
}

#===============================================================================
# Network Configuration
#===============================================================================

check_network() {
    section_header "NETWORK CONFIGURATION"
    
    subsection_header "Network Interfaces"
    
    # List interfaces
    local interfaces=$(networksetup -listallhardwareports 2>/dev/null)
    local active_ifaces=$(ifconfig 2>/dev/null | grep "^[a-z]" | cut -d: -f1)
    result_info "Active interfaces: $(echo $active_ifaces | tr '\n' ' ')"
    
    subsection_header "Listening Services"
    
    # Listening ports
    local listening=$(lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null | tail -n +2)
    if [ -n "$listening" ]; then
        local listen_count=$(echo "$listening" | wc -l | tr -d ' ')
        result_info "Services listening on TCP ports: ${listen_count}"
        
        # Show first few
        echo "$listening" | head -10 | while read -r line; do
            local proc=$(echo "$line" | awk '{print $1}')
            local port=$(echo "$line" | awk '{print $9}')
            result_info "  ${proc}: ${port}"
        done
        
        if [ "$listen_count" -gt 10 ]; then
            result_info "  ... and $((listen_count - 10)) more"
        fi
    else
        result_pass "No TCP services listening"
    fi
    
    subsection_header "Sharing Services"
    
    # Remote Login (SSH)
    local ssh_status=$(systemsetup -getremotelogin 2>/dev/null)
    if echo "$ssh_status" | grep -qi "on"; then
        result_medium "Remote Login (SSH) is ENABLED"
        
        # Check SSH config
        if [ -f "/etc/ssh/sshd_config" ]; then
            local permit_root=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
            if [ "$permit_root" = "yes" ]; then
                result_high "SSH: Root login is permitted"
            else
                result_pass "SSH: Root login is restricted"
            fi
            
            local pw_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
            if [ "$pw_auth" = "yes" ]; then
                result_medium "SSH: Password authentication is enabled"
            fi
        fi
    else
        result_pass "Remote Login (SSH) is disabled"
    fi
    
    # Screen Sharing
    local screen_sharing=$(launchctl list 2>/dev/null | grep -i screensharing)
    if [ -n "$screen_sharing" ]; then
        result_medium "Screen Sharing appears to be enabled"
    else
        result_pass "Screen Sharing is disabled"
    fi
    
    # File Sharing
    local file_sharing=$(launchctl list 2>/dev/null | grep -i "com.apple.smbd")
    if [ -n "$file_sharing" ]; then
        result_medium "File Sharing (SMB) is enabled"
    else
        result_pass "File Sharing (SMB) is disabled"
    fi
    
    # Remote Apple Events
    local remote_ae=$(systemsetup -getremoteappleevents 2>/dev/null)
    if echo "$remote_ae" | grep -qi "on"; then
        result_medium "Remote Apple Events is ENABLED"
    else
        result_pass "Remote Apple Events is disabled"
    fi
    
    subsection_header "AirDrop & Bluetooth"
    
    # Bluetooth
    local bt_power=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null)
    if [ "$bt_power" = "1" ]; then
        result_info "Bluetooth is enabled"
        
        # Discoverable?
        local bt_discover=$(defaults read /Library/Preferences/com.apple.Bluetooth BluetoothDiscoverable 2>/dev/null)
        if [ "$bt_discover" = "1" ]; then
            result_low "Bluetooth is discoverable"
        fi
    else
        result_info "Bluetooth is disabled"
    fi
}

#===============================================================================
# Remote Management & MDM
#===============================================================================

check_remote_management() {
    section_header "REMOTE MANAGEMENT & MDM"
    
    subsection_header "MDM Enrollment"
    
    local mdm_status=$(profiles status -type enrollment 2>/dev/null)
    if echo "$mdm_status" | grep -q "MDM enrollment: Yes"; then
        result_pass "Device is MDM enrolled"
        
        local mdm_server=$(echo "$mdm_status" | grep "MDM server" | cut -d: -f2-)
        if [ -n "$mdm_server" ]; then
            result_info "MDM Server:${mdm_server}"
        fi
    elif echo "$mdm_status" | grep -q "MDM enrollment: No"; then
        result_info "Device is not MDM enrolled"
    else
        result_info "MDM status: Unknown"
    fi
    
    # DEP enrolled?
    if echo "$mdm_status" | grep -q "Enrolled via DEP: Yes"; then
        result_info "Device was enrolled via DEP/ABM"
    fi
    
    subsection_header "Configuration Profiles"
    
    local profiles_list=$(profiles list 2>/dev/null)
    if [ -n "$profiles_list" ]; then
        local profile_count=$(echo "$profiles_list" | grep -c "attribute: name:" 2>/dev/null || echo "0")
        result_info "Installed configuration profiles: ${profile_count}"
        
        # List profile names
        echo "$profiles_list" | grep "attribute: name:" | while read -r line; do
            local pname=$(echo "$line" | cut -d: -f3-)
            result_info "  - ${pname}"
        done
    else
        result_info "No configuration profiles installed"
    fi
    
    subsection_header "Remote Desktop (ARD)"
    
    local ard_status=$(launchctl list 2>/dev/null | grep ARDAgent)
    if [ -n "$ard_status" ]; then
        result_medium "Apple Remote Desktop agent is running"
    else
        result_pass "Apple Remote Desktop is not active"
    fi
}

#===============================================================================
# Application Security
#===============================================================================

check_applications() {
    section_header "APPLICATION SECURITY"
    
    subsection_header "Non-Apple Kernel Extensions"
    
    # Check for third-party kexts
    local kexts=$(kextstat 2>/dev/null | grep -v "com.apple" | tail -n +2)
    if [ -n "$kexts" ]; then
        local kext_count=$(echo "$kexts" | wc -l | tr -d ' ')
        result_medium "Non-Apple kernel extensions loaded: ${kext_count}"
        echo "$kexts" | while read -r line; do
            local kext_id=$(echo "$line" | awk '{print $6}')
            result_info "  - ${kext_id}"
        done
    else
        result_pass "No third-party kernel extensions loaded"
    fi
    
    subsection_header "System Extensions"
    
    # System extensions (macOS 10.15+)
    local sysext=$(systemextensionsctl list 2>/dev/null)
    if [ -n "$sysext" ]; then
        local ext_count=$(echo "$sysext" | grep -c "enabled active" 2>/dev/null || echo "0")
        result_info "Active system extensions: ${ext_count}"
    fi
    
    subsection_header "Launch Daemons & Agents (Non-Apple)"
    
    # Third-party Launch Daemons
    local ld_count=0
    if [ -d "/Library/LaunchDaemons" ]; then
        local third_party_ld=$(ls /Library/LaunchDaemons/ 2>/dev/null | grep -v "^com.apple")
        if [ -n "$third_party_ld" ]; then
            ld_count=$(echo "$third_party_ld" | wc -l | tr -d ' ')
            result_info "Third-party Launch Daemons: ${ld_count}"
            echo "$third_party_ld" | head -10 | while read -r item; do
                result_info "  - ${item}"
            done
        fi
    fi
    
    # Third-party Launch Agents (System)
    local la_count=0
    if [ -d "/Library/LaunchAgents" ]; then
        local third_party_la=$(ls /Library/LaunchAgents/ 2>/dev/null | grep -v "^com.apple")
        if [ -n "$third_party_la" ]; then
            la_count=$(echo "$third_party_la" | wc -l | tr -d ' ')
            result_info "Third-party Launch Agents (System): ${la_count}"
            echo "$third_party_la" | head -10 | while read -r item; do
                result_info "  - ${item}"
            done
        fi
    fi
    
    if [ "$ld_count" -eq 0 ] && [ "$la_count" -eq 0 ]; then
        result_info "No third-party launch items found in system directories"
    fi
    
    subsection_header "Unsigned Applications"
    
    # Check for unsigned apps (sample of /Applications)
    local unsigned_count=0
    for app in /Applications/*.app; do
        if [ -d "$app" ]; then
            local sig_check=$(codesign -dv "$app" 2>&1)
            if echo "$sig_check" | grep -q "code object is not signed"; then
                ((unsigned_count++))
                result_high "Unsigned application: $(basename "$app")"
            fi
        fi
    done
    
    if [ "$unsigned_count" -eq 0 ]; then
        result_pass "All applications in /Applications are signed"
    fi
}

#===============================================================================
# Privacy & TCC
#===============================================================================

check_privacy() {
    section_header "PRIVACY & TCC PERMISSIONS"
    
    subsection_header "TCC Database"
    
    local tcc_system="/Library/Application Support/com.apple.TCC/TCC.db"
    local tcc_user="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
    
    # System TCC
    if [ -f "$tcc_system" ] && [ -r "$tcc_system" ]; then
        result_info "Checking system TCC database..."
        
        # Full Disk Access
        local fda=$(sqlite3 "$tcc_system" "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;" 2>/dev/null)
        if [ -n "$fda" ]; then
            result_info "Apps with Full Disk Access:"
            echo "$fda" | while read -r app; do
                result_info "  - ${app}"
            done
        fi
        
        # Accessibility
        local accessibility=$(sqlite3 "$tcc_system" "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND auth_value=2;" 2>/dev/null)
        if [ -n "$accessibility" ]; then
            local acc_count=$(echo "$accessibility" | wc -l | tr -d ' ')
            result_info "Apps with Accessibility permissions: ${acc_count}"
        fi
        
        # Screen Recording
        local screen_rec=$(sqlite3 "$tcc_system" "SELECT client FROM access WHERE service='kTCCServiceScreenCapture' AND auth_value=2;" 2>/dev/null)
        if [ -n "$screen_rec" ]; then
            result_info "Apps with Screen Recording permission:"
            echo "$screen_rec" | while read -r app; do
                result_info "  - ${app}"
            done
        fi
    else
        result_info "Cannot read system TCC database (requires Full Disk Access)"
    fi
    
    subsection_header "Location Services"
    
    local location_enabled=$(defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd 2>/dev/null | grep -i "LocationServicesEnabled" | head -1)
    if echo "$location_enabled" | grep -q "1"; then
        result_info "Location Services is enabled"
    else
        result_info "Location Services status: Unknown or disabled"
    fi
    
    subsection_header "Siri & Analytics"
    
    # Siri
    local siri_enabled=$(defaults read com.apple.assistant.support "Assistant Enabled" 2>/dev/null)
    if [ "$siri_enabled" = "1" ]; then
        result_low "Siri is enabled"
    else
        result_pass "Siri is disabled"
    fi
    
    # Analytics
    local analytics=$(defaults read "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" AutoSubmit 2>/dev/null)
    if [ "$analytics" = "1" ]; then
        result_low "Diagnostic data sharing is enabled"
    else
        result_pass "Diagnostic data sharing is disabled"
    fi
}

#===============================================================================
# Security Software (EDR/AV)
#===============================================================================

check_security_software() {
    section_header "SECURITY SOFTWARE"
    
    subsection_header "Endpoint Detection & Response"
    
    local edr_found=false
    
    # CrowdStrike Falcon
    if launchctl list 2>/dev/null | grep -qi "crowdstrike\|falcon"; then
        result_pass "CrowdStrike Falcon detected"
        edr_found=true
    fi
    
    # Carbon Black
    if launchctl list 2>/dev/null | grep -qi "carbonblack\|cb."; then
        result_pass "Carbon Black detected"
        edr_found=true
    fi
    
    # SentinelOne
    if launchctl list 2>/dev/null | grep -qi "sentinel"; then
        result_pass "SentinelOne detected"
        edr_found=true
    fi
    
    # Microsoft Defender
    if [ -d "/Applications/Microsoft Defender.app" ] || launchctl list 2>/dev/null | grep -qi "microsoft.wdav"; then
        result_pass "Microsoft Defender detected"
        edr_found=true
    fi
    
    # Symantec/Broadcom
    if launchctl list 2>/dev/null | grep -qi "symantec\|sep"; then
        result_pass "Symantec Endpoint Protection detected"
        edr_found=true
    fi
    
    # Sophos
    if launchctl list 2>/dev/null | grep -qi "sophos"; then
        result_pass "Sophos detected"
        edr_found=true
    fi
    
    # Kaspersky
    if launchctl list 2>/dev/null | grep -qi "kaspersky"; then
        result_pass "Kaspersky detected"
        edr_found=true
    fi
    
    # ESET
    if launchctl list 2>/dev/null | grep -qi "eset"; then
        result_pass "ESET detected"
        edr_found=true
    fi
    
    # Jamf Protect
    if launchctl list 2>/dev/null | grep -qi "jamf.protect"; then
        result_pass "Jamf Protect detected"
        edr_found=true
    fi
    
    if [ "$edr_found" = false ]; then
        result_medium "No common EDR/AV solution detected"
    fi
}

#===============================================================================
# Firmware & Hardware Security
#===============================================================================

check_firmware_security() {
    section_header "FIRMWARE & HARDWARE SECURITY"
    
    subsection_header "Secure Boot"
    
    # Check architecture
    local cpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
    local hw_model=$(sysctl -n hw.model 2>/dev/null)
    
    if [[ "$cpu" == *"Apple"* ]]; then
        # Apple Silicon
        result_info "Apple Silicon detected - checking secure boot..."
        
        local boot_policy=$(bputil -d 2>/dev/null)
        if [ -n "$boot_policy" ]; then
            if echo "$boot_policy" | grep -q "Full Security"; then
                result_pass "Secure Boot: Full Security mode"
            elif echo "$boot_policy" | grep -q "Reduced Security"; then
                result_medium "Secure Boot: Reduced Security mode"
            elif echo "$boot_policy" | grep -q "Permissive Security"; then
                result_high "Secure Boot: Permissive Security mode"
            fi
        else
            result_info "Could not determine secure boot policy"
        fi
    else
        # Intel with T2
        local t2_check=$(system_profiler SPiBridgeDataType 2>/dev/null)
        if [ -n "$t2_check" ]; then
            result_info "T2 Security Chip detected"
            
            # Firmware password
            local fw_pass=$(firmwarepasswd -check 2>/dev/null)
            if echo "$fw_pass" | grep -q "Yes"; then
                result_pass "Firmware password is set"
            else
                result_critical "Firmware password is NOT set"
            fi
        else
            result_info "No T2 chip detected (older Intel Mac)"
            
            # Check firmware password on non-T2
            local fw_pass=$(firmwarepasswd -check 2>/dev/null)
            if echo "$fw_pass" | grep -q "Yes"; then
                result_pass "Firmware password is set"
            else
                result_high "Firmware password is NOT set"
            fi
        fi
    fi
    
    subsection_header "Activation Lock"
    
    local activation_lock=$(system_profiler SPHardwareDataType 2>/dev/null | grep "Activation Lock Status")
    if [ -n "$activation_lock" ]; then
        if echo "$activation_lock" | grep -qi "enabled"; then
            result_pass "Activation Lock is enabled"
        else
            result_info "Activation Lock is disabled"
        fi
    fi
}

#===============================================================================
# Logging & Auditing
#===============================================================================

check_logging() {
    section_header "LOGGING & AUDITING"
    
    subsection_header "Audit Configuration"
    
    # Check audit_control
    if [ -f "/etc/security/audit_control" ]; then
        result_pass "Audit configuration file exists"
        
        local audit_flags=$(grep "^flags:" /etc/security/audit_control 2>/dev/null | cut -d: -f2)
        if [ -n "$audit_flags" ]; then
            result_info "Audit flags: ${audit_flags}"
        fi
        
        # Check if auditd is running
        local auditd=$(launchctl list 2>/dev/null | grep "com.apple.auditd")
        if [ -n "$auditd" ]; then
            result_pass "Audit daemon is running"
        else
            result_medium "Audit daemon is not running"
        fi
    else
        result_medium "Audit configuration file not found"
    fi
    
    subsection_header "Install Log"
    
    if [ -f "/var/log/install.log" ]; then
        result_pass "Install log exists"
        local install_log_size=$(ls -lh /var/log/install.log 2>/dev/null | awk '{print $5}')
        result_info "Install log size: ${install_log_size}"
    fi
    
    subsection_header "Unified Logging"
    
    local log_config=$(log config --status 2>/dev/null)
    if [ -n "$log_config" ]; then
        result_info "Unified logging is configured"
    fi
}

#===============================================================================
# Privilege Escalation Vectors
#===============================================================================

check_privesc() {
    section_header "PRIVILEGE ESCALATION VECTORS"
    
    subsection_header "SUID Binaries"
    
    # Find SUID binaries (non-Apple)
    local suid_bins=$(find /usr/local /opt /Applications -perm -4000 -type f 2>/dev/null)
    if [ -n "$suid_bins" ]; then
        result_medium "SUID binaries found in non-system locations:"
        echo "$suid_bins" | while read -r bin; do
            result_info "  - ${bin}"
        done
    else
        result_pass "No SUID binaries in common third-party locations"
    fi
    
    subsection_header "Sudo Configuration"
    
    # Check NOPASSWD in sudoers
    local nopasswd=$(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#")
    if [ -n "$nopasswd" ]; then
        result_medium "NOPASSWD entries found in sudoers:"
        echo "$nopasswd" | while read -r line; do
            result_info "  ${line}"
        done
    else
        result_pass "No NOPASSWD entries in sudoers"
    fi
    
    # Check for timestamp_timeout
    local timeout=$(grep "timestamp_timeout" /etc/sudoers 2>/dev/null)
    if [ -n "$timeout" ]; then
        result_info "Sudo timeout configured: ${timeout}"
    fi
    
    subsection_header "World-Writable Directories"
    
    # Check common paths for world-writable
    local ww_dirs=$(find /usr/local /opt /Applications -type d -perm -0002 2>/dev/null | head -10)
    if [ -n "$ww_dirs" ]; then
        result_medium "World-writable directories found:"
        echo "$ww_dirs" | while read -r dir; do
            result_info "  - ${dir}"
        done
    else
        result_pass "No world-writable directories in common locations"
    fi
}

#===============================================================================
# Software Updates
#===============================================================================

check_updates() {
    section_header "SOFTWARE UPDATES"
    
    subsection_header "Update Configuration"
    
    # Auto-update settings
    local auto_check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
    if [ "$auto_check" = "1" ]; then
        result_pass "Automatic update check is enabled"
    else
        result_medium "Automatic update check is disabled"
    fi
    
    local auto_download=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null)
    if [ "$auto_download" = "1" ]; then
        result_pass "Automatic download is enabled"
    else
        result_info "Automatic download is disabled"
    fi
    
    local critical_updates=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
    if [ "$critical_updates" = "1" ]; then
        result_pass "Critical updates auto-install is enabled"
    else
        result_medium "Critical updates auto-install is disabled"
    fi
    
    subsection_header "Available Updates"
    
    result_info "Checking for available updates..."
    local updates=$(softwareupdate -l 2>&1)
    if echo "$updates" | grep -q "No new software available"; then
        result_pass "System is up to date"
    else
        result_medium "Updates may be available - run 'softwareupdate -l' for details"
    fi
}

#===============================================================================
# Summary Report
#===============================================================================

print_summary() {
    section_header "AUDIT SUMMARY"
    
    echo ""
    echo -e "  ${BOLD}Finding Summary:${NC}"
    echo -e "  ───────────────────────────────────"
    echo -e "  ${RED}Critical:${NC}  ${CRITICAL_COUNT}"
    echo -e "  ${RED}High:${NC}      ${HIGH_COUNT}"
    echo -e "  ${YELLOW}Medium:${NC}    ${MEDIUM_COUNT}"
    echo -e "  ${YELLOW}Low:${NC}       ${LOW_COUNT}"
    echo -e "  ${GREEN}Pass:${NC}      ${PASS_COUNT}"
    echo -e "  ${CYAN}Info:${NC}      ${INFO_COUNT}"
    echo -e "  ───────────────────────────────────"
    
    local total_findings=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT))
    echo -e "  ${BOLD}Total Findings:${NC} ${total_findings}"
    echo ""
    
    # Risk rating
    if [ "$CRITICAL_COUNT" -gt 0 ]; then
        echo -e "  ${RED}${BOLD}Overall Risk: CRITICAL${NC}"
        echo -e "  ${RED}Immediate remediation required for critical findings.${NC}"
    elif [ "$HIGH_COUNT" -gt 0 ]; then
        echo -e "  ${RED}${BOLD}Overall Risk: HIGH${NC}"
        echo -e "  ${RED}High-priority findings should be addressed promptly.${NC}"
    elif [ "$MEDIUM_COUNT" -gt 0 ]; then
        echo -e "  ${YELLOW}${BOLD}Overall Risk: MEDIUM${NC}"
        echo -e "  ${YELLOW}Review and address medium findings as appropriate.${NC}"
    elif [ "$LOW_COUNT" -gt 0 ]; then
        echo -e "  ${GREEN}${BOLD}Overall Risk: LOW${NC}"
        echo -e "  ${GREEN}Minor issues identified - review at convenience.${NC}"
    else
        echo -e "  ${GREEN}${BOLD}Overall Risk: MINIMAL${NC}"
        echo -e "  ${GREEN}No significant security issues identified.${NC}"
    fi
    
    echo ""
    echo -e "  ${CYAN}Audit completed at: $(date)${NC}"
    echo ""
}

#===============================================================================
# Main Execution
#===============================================================================

main() {
    parse_args "$@"
    
    # Set up output file if specified
    if [ -n "$OUTPUT_FILE" ]; then
        exec > >(tee -a "$OUTPUT_FILE") 2>&1
    else
        exec > >(tee -a "$DEFAULT_OUTPUT") 2>&1
        echo -e "${CYAN}[*] Output saved to: ${DEFAULT_OUTPUT}${NC}"
    fi
    
    banner
    check_root
    
    get_system_info
    check_sip
    check_gatekeeper
    check_filevault
    check_user_accounts
    check_firewall
    check_network
    check_remote_management
    check_applications
    check_privacy
    check_security_software
    check_firmware_security
    check_logging
    check_privesc
    check_updates
    print_summary
}

# Run main function
main "$@"
