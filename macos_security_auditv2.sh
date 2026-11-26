#!/bin/bash
#===============================================================================
# macOS Security Audit Script
# Based on macOS Build Review Methodology
#
# Usage: sudo ./macos_security_audit.sh [options]
#
# Options:
#   -o, --output FILE    Write the report to FILE
#                        (default: ./macos_audit_<host>_<timestamp>.txt)
#   -q, --quiet          Suppress banner and colours
#       --no-color       Disable colours only
#       --skip-updates   Skip the (slow, network-dependent) softwareupdate -l check
#   -h, --help           Show this help message
#
# Exit codes:
#   0  no Critical or High findings     1  High findings present
#   2  Critical findings present        64 bad command-line usage
#
# Notes:
#   * Run with sudo for complete results. For the TCC checks, the terminal app
#     also needs Full Disk Access.
#   * Compatible with the stock macOS /bin/bash (3.2): no associative arrays,
#     mapfile, or ${var,,} expansions.
#   * The report contains host identifiers (hostname, serial number, user names)
#     and is written with 0600 permissions.
#===============================================================================

set -o pipefail
umask 077

VERSION="2.0.0"

#===============================================================================
# Defaults & state
#===============================================================================

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
PURPLE=$'\033[0;35m'
BOLD=$'\033[1m'
NC=$'\033[0m'

CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0
PASS_COUNT=0

QUIET=false
USE_COLOR=true
SKIP_UPDATES=false
OUTPUT_FILE=""
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Populated by init_context
OS_VERSION=""
OS_MAJOR=0
IS_ARM=false
CONSOLE_USER=""
CONSOLE_UID=""
LAUNCHD_DISABLED=""

#===============================================================================
# Helper functions
#===============================================================================

show_help() {
    cat <<EOF
macOS Security Audit Script v${VERSION}

Usage: sudo $0 [options]

Options:
  -o, --output FILE    Write the report to FILE
                       (default: ./macos_audit_<host>_<timestamp>.txt)
  -q, --quiet          Suppress banner and colours
      --no-color       Disable colours only
      --skip-updates   Skip the slow softwareupdate -l check
  -h, --help           Show this help message

Exit codes: 0 = no Critical/High, 1 = High present, 2 = Critical present
EOF
}

usage_error() {
    echo "Error: $1" >&2
    echo "Run '$0 --help' for usage." >&2
    exit 64
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -o|--output)
                [ -n "${2:-}" ] && [ "${2#-}" = "$2" ] || usage_error "$1 requires a file name"
                OUTPUT_FILE="$2"
                shift 2
                ;;
            --output=*)
                OUTPUT_FILE="${1#*=}"
                [ -n "$OUTPUT_FILE" ] || usage_error "--output requires a file name"
                shift
                ;;
            -q|--quiet)
                QUIET=true
                USE_COLOR=false
                shift
                ;;
            --no-color|--no-colour)
                USE_COLOR=false
                shift
                ;;
            --skip-updates)
                SKIP_UPDATES=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                usage_error "unknown option: $1"
                ;;
        esac
    done
}

disable_colors() {
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; PURPLE=''; BOLD=''; NC=''
}

banner() {
    [ "$QUIET" = true ] && return
    printf '%s\n' "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                  macOS Security Audit Script                      ║"
    printf '║                        Version %-35s║\n' "${VERSION}"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    printf '%s\n' "${NC}"
}

section_header() {
    local rule="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    printf '%s\n' "${BLUE}${BOLD}${rule}${NC}"
    printf '%s\n' "${BLUE}${BOLD}  $1${NC}"
    printf '%s\n' "${BLUE}${BOLD}${rule}${NC}"
}

subsection_header() {
    echo ""
    printf '%s\n' "${PURPLE}  ─── $1 ───${NC}"
}

# Result functions. Arithmetic assignment is used instead of ((x++)) because
# ((x++)) returns status 1 when x is 0, which breaks under `set -e`.
result_critical() { printf '    %s %s\n' "${RED}${BOLD}[CRITICAL]${NC}" "$1"; CRITICAL_COUNT=$((CRITICAL_COUNT + 1)); }
result_high()     { printf '    %s %s\n' "${RED}[HIGH]${NC}" "$1";             HIGH_COUNT=$((HIGH_COUNT + 1)); }
result_medium()   { printf '    %s %s\n' "${YELLOW}[MEDIUM]${NC}" "$1";        MEDIUM_COUNT=$((MEDIUM_COUNT + 1)); }
result_low()      { printf '    %s %s\n' "${YELLOW}[LOW]${NC}" "$1";           LOW_COUNT=$((LOW_COUNT + 1)); }
result_pass()     { printf '    %s %s\n' "${GREEN}[PASS]${NC}" "$1";           PASS_COUNT=$((PASS_COUNT + 1)); }
result_info()     { printf '    %s %s\n' "${CYAN}[INFO]${NC}" "$1";            INFO_COUNT=$((INFO_COUNT + 1)); }
result_error()    { printf '    %s %s\n' "${RED}[ERROR]${NC}" "$1"; }

# Detail lines belong to the finding above them and are not counted.
detail() { printf '           %s\n' "$1"; }

# Print each non-empty line of $1 as a detail line, optionally capped at $2.
# Uses a here-string, not a pipe, so it runs in the current shell.
list_details() {
    local text="$1" max="${2:-0}" n=0 line total
    [ -z "$text" ] && return
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        n=$((n + 1))
        if [ "$max" -gt 0 ] && [ "$n" -gt "$max" ]; then
            total=$(count_lines "$text")
            detail "... and $((total - max)) more"
            break
        fi
        detail "- $line"
    done <<< "$text"
}

# Count non-empty lines without the `grep -c || echo 0` double-output bug.
count_lines() {
    [ -z "$1" ] && { echo 0; return; }
    printf '%s\n' "$1" | grep -c '[^[:space:]]'
}

have() { command -v "$1" >/dev/null 2>&1; }

# Read a system preference. An MDM-managed value takes precedence.
#   read_pref <domain or /path/to/plist> <key>
read_pref() {
    local domain="$1" key="$2" name val
    name="${domain##*/}"
    name="${name%.plist}"
    if val=$(defaults read "/Library/Managed Preferences/${name}" "$key" 2>/dev/null); then
        echo "$val"
        return 0
    fi
    defaults read "$domain" "$key" 2>/dev/null
}

# Run a command as the logged-in console user (so per-user preferences are read
# from the right account rather than root's).
run_as_user() {
    [ -z "$CONSOLE_USER" ] && return 1
    if [ "$EUID" -eq 0 ]; then
        launchctl asuser "$CONSOLE_UID" sudo -u "$CONSOLE_USER" "$@"
    elif [ "$(id -un)" = "$CONSOLE_USER" ]; then
        "$@"
    else
        return 1
    fi
}

# Read a per-user preference: user-managed, then computer-managed, then local.
#   read_user_pref [-currentHost] <domain> <key>
read_user_pref() {
    local host_flag=""
    if [ "$1" = "-currentHost" ]; then host_flag="-currentHost"; shift; fi
    local domain="$1" key="$2" val
    if [ -n "$CONSOLE_USER" ] && \
       val=$(defaults read "/Library/Managed Preferences/${CONSOLE_USER}/${domain}" "$key" 2>/dev/null); then
        echo "$val"; return 0
    fi
    if val=$(defaults read "/Library/Managed Preferences/${domain}" "$key" 2>/dev/null); then
        echo "$val"; return 0
    fi
    # shellcheck disable=SC2086  # host_flag is intentionally unquoted (may be empty)
    run_as_user defaults $host_flag read "$domain" "$key" 2>/dev/null
}

# Is a launchd system service enabled? Handles both the "false" (<=12) and
# "enabled" (13+) spellings used by `launchctl print-disabled`.
service_enabled() {
    printf '%s\n' "$LAUNCHD_DISABLED" | grep -Eq "\"$1\" => (false|enabled)"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        printf '%s\n' "${YELLOW}[!] Warning: not running as root. Many checks will be incomplete.${NC}"
        printf '%s\n' "${YELLOW}[!] Run with: sudo $0${NC}"
        echo ""
    fi
}

init_context() {
    OS_VERSION=$(sw_vers -productVersion 2>/dev/null)
    OS_MAJOR=${OS_VERSION%%.*}
    case "$OS_MAJOR" in ''|*[!0-9]*) OS_MAJOR=0 ;; esac

    # hw.optional.arm64 is 1 on Apple Silicon even when running under Rosetta.
    [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = "1" ] && IS_ARM=true

    CONSOLE_USER=$(stat -f%Su /dev/console 2>/dev/null)
    case "$CONSOLE_USER" in
        ""|root|loginwindow|_mbsetupuser) CONSOLE_USER="${SUDO_USER:-}" ;;
    esac
    [ "$CONSOLE_USER" = "root" ] && CONSOLE_USER=""
    [ -n "$CONSOLE_USER" ] && CONSOLE_UID=$(id -u "$CONSOLE_USER" 2>/dev/null)

    LAUNCHD_DISABLED=$(launchctl print-disabled system 2>/dev/null)
}

#===============================================================================
# System information
#===============================================================================

get_system_info() {
    section_header "SYSTEM INFORMATION"
    subsection_header "Basic Info"

    result_info "OS: $(sw_vers -productName 2>/dev/null) ${OS_VERSION} (Build $(sw_vers -buildVersion 2>/dev/null))"
    result_info "Hardware Model: $(sysctl -n hw.model 2>/dev/null)"
    if [ "$IS_ARM" = true ]; then
        result_info "Architecture: Apple Silicon"
    else
        result_info "Architecture: Intel"
    fi
    result_info "Kernel Version: $(uname -r 2>/dev/null)"
    result_info "Hostname: $(hostname 2>/dev/null)"

    local serial
    serial=$(ioreg -c IOPlatformExpertDevice -d 2 2>/dev/null | awk -F'"' '/IOPlatformSerialNumber/ {print $4}')
    [ -n "$serial" ] && result_info "Serial Number: ${serial}"

    result_info "Uptime: $(uptime 2>/dev/null | sed 's/^ *//')"
    if [ -n "$CONSOLE_USER" ]; then
        result_info "Per-user checks evaluated for: ${CONSOLE_USER}"
    else
        result_info "No console user found; per-user checks will be skipped"
    fi
}

#===============================================================================
# System Integrity Protection
#===============================================================================

check_sip() {
    section_header "SYSTEM INTEGRITY PROTECTION (SIP)"

    local sip_status first
    sip_status=$(csrutil status 2>/dev/null)
    first=$(printf '%s\n' "$sip_status" | head -1)

    if printf '%s' "$first" | grep -q "Custom Configuration"; then
        result_high "SIP has a custom configuration (partially disabled)"
        list_details "$(printf '%s\n' "$sip_status" | grep -i ': *disabled' | sed 's/^[[:space:]]*//')"
    elif printf '%s' "$first" | grep -q "status: enabled"; then
        result_pass "SIP is enabled"
    elif printf '%s' "$first" | grep -q "status: disabled"; then
        result_critical "SIP is DISABLED - system is exposed to rootkits and persistent malware"
    else
        result_error "Could not determine SIP status"
    fi

    if [ "$OS_MAJOR" -ge 11 ]; then
        local auth_root
        auth_root=$(csrutil authenticated-root status 2>/dev/null)
        if printf '%s' "$auth_root" | grep -q "status: enabled"; then
            result_pass "Authenticated Root (sealed system volume) is enabled"
        elif printf '%s' "$auth_root" | grep -q "status: disabled"; then
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

    local gk_status
    gk_status=$(spctl --status 2>/dev/null)
    if printf '%s' "$gk_status" | grep -q "assessments enabled"; then
        result_pass "Gatekeeper is enabled"
    elif printf '%s' "$gk_status" | grep -q "assessments disabled"; then
        result_critical "Gatekeeper is DISABLED - unsigned/unnotarised apps can run freely"
    else
        result_error "Could not determine Gatekeeper status"
    fi

    subsection_header "XProtect"

    local xp_version=""
    if have xprotect; then
        xp_version=$(xprotect version 2>/dev/null | head -1)
    fi
    if [ -z "$xp_version" ]; then
        local p
        for p in "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" \
                 "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist" \
                 "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" \
                 "/System/Library/CoreServices/XProtect.bundle/Contents/version.plist"; do
            if [ -f "$p" ]; then
                xp_version=$(defaults read "${p%.plist}" CFBundleShortVersionString 2>/dev/null)
                break
            fi
        done
    fi
    if [ -n "$xp_version" ]; then
        result_info "XProtect version: ${xp_version}"
    else
        result_medium "Could not find XProtect definitions"
    fi

    # Most recent XProtect package install (pkgutil gives epoch times, so we can
    # take the newest rather than the first entry).
    local newest=0 pkg t
    while IFS= read -r pkg; do
        [ -z "$pkg" ] && continue
        t=$(pkgutil --pkg-info "$pkg" 2>/dev/null | awk '/install-time/ {print $2}')
        [ -n "$t" ] && [ "$t" -gt "$newest" ] && newest=$t
    done <<< "$(pkgutil --pkgs 2>/dev/null | grep -i xprotect)"
    if [ "$newest" -gt 0 ]; then
        result_info "Last XProtect package install: $(date -r "$newest" '+%Y-%m-%d')"
    fi

    subsection_header "XProtect Remediator / MRT"
    if [ -d "/Library/Apple/System/Library/CoreServices/XProtect.app" ]; then
        result_pass "XProtect Remediator is present"
    elif [ -d "/Library/Apple/System/Library/CoreServices/MRT.app" ] || \
         [ -d "/System/Library/CoreServices/MRT.app" ]; then
        result_pass "Malware Removal Tool (MRT) is present"
    else
        result_medium "Neither XProtect Remediator nor MRT was found"
    fi
}

#===============================================================================
# FileVault
#===============================================================================

check_filevault() {
    section_header "FILEVAULT (FULL DISK ENCRYPTION)"

    local fv_status
    fv_status=$(fdesetup status 2>/dev/null)

    if printf '%s' "$fv_status" | grep -q "FileVault is On"; then
        result_pass "FileVault is enabled"

        if printf '%s' "$fv_status" | grep -q "Encryption in progress"; then
            result_medium "FileVault encryption is still in progress"
        fi

        local inst pers
        inst=$(fdesetup hasinstitutionalrecoverykey 2>/dev/null)
        pers=$(fdesetup haspersonalrecoverykey 2>/dev/null)

        [ "$inst" = "true" ] && result_pass "Institutional recovery key is present"
        [ "$pers" = "true" ] && result_pass "Personal recovery key exists"
        if [ "$inst" != "true" ] && [ "$pers" != "true" ]; then
            if [ "$EUID" -eq 0 ]; then
                result_medium "No FileVault recovery key (personal or institutional) is configured"
            else
                result_error "Could not query FileVault recovery keys (requires root)"
            fi
        fi

        local fv_users
        fv_users=$(fdesetup list 2>/dev/null | cut -d, -f1)
        if [ -n "$fv_users" ]; then
            result_info "FileVault-enabled users: $(count_lines "$fv_users")"
            list_details "$fv_users"
        fi

    elif printf '%s' "$fv_status" | grep -q "FileVault is Off"; then
        result_critical "FileVault is DISABLED - disk is not encrypted"
    else
        result_error "Could not determine FileVault status"
    fi
}

#===============================================================================
# User accounts
#===============================================================================

check_user_accounts() {
    section_header "USER ACCOUNT SECURITY"
    subsection_header "User Accounts"

    local users admins admin_count
    users=$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2 > 500 {print $1}')
    result_info "Local user accounts (UID > 500): $(count_lines "$users")"
    list_details "$users"

    admins=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/^GroupMembership: *//' | tr ' ' '\n' | grep -v '^root$')
    admin_count=$(count_lines "$admins")
    result_info "Admin group members (excluding root): ${admin_count}"
    list_details "$admins"
    if [ "$admin_count" -gt 2 ]; then
        result_low "${admin_count} admin accounts - review whether all need admin rights"
    fi

    subsection_header "Guest Access"

    local guest_enabled
    guest_enabled=$(read_pref /Library/Preferences/com.apple.loginwindow GuestEnabled)
    if [ "$guest_enabled" = "1" ]; then
        result_medium "Guest account login is ENABLED"
    else
        result_pass "Guest account login is disabled"
    fi

    local smb_guest
    smb_guest=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess 2>/dev/null)
    if [ "$smb_guest" = "1" ]; then
        result_medium "Guest access to shared folders (SMB) is ENABLED"
    fi

    subsection_header "Auto-Login"

    local auto_login
    auto_login=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
    if [ -n "$auto_login" ]; then
        result_high "Auto-login is ENABLED for user: ${auto_login}"
    elif [ -f /etc/kcpassword ]; then
        result_medium "/etc/kcpassword exists (auto-login credential remnant)"
    else
        result_pass "Auto-login is disabled"
    fi

    subsection_header "Root Account"

    local root_auth
    root_auth=$(dscl . -read /Users/root AuthenticationAuthority 2>/dev/null)
    if printf '%s' "$root_auth" | grep -q "DisabledUser"; then
        result_pass "Root account is disabled"
    elif printf '%s' "$root_auth" | grep -q "ShadowHash"; then
        result_high "Root account is ENABLED (has a password)"
    else
        result_pass "Root account is disabled (no authentication authority)"
    fi

    subsection_header "Password Policy"

    local pw_policy managed_pc
    pw_policy=$(pwpolicy -getaccountpolicies 2>/dev/null)
    managed_pc=$(ls /Library/Managed\ Preferences/com.apple.mobiledevice.passwordpolicy.plist 2>/dev/null)
    if [ -n "$managed_pc" ]; then
        result_pass "Password policy is managed by a configuration profile"
    elif printf '%s' "$pw_policy" | grep -q "policyCategoryPasswordContent"; then
        result_pass "Local password content policy is configured"
        local min_len
        min_len=$(printf '%s' "$pw_policy" | grep -Eo 'policyAttributePassword matches[^<]*\{[0-9]+,' | grep -Eo '[0-9]+' | head -1)
        [ -n "$min_len" ] && detail "Minimum length (from regex): ${min_len}"
    else
        result_medium "No password content policy configured"
    fi

    subsection_header "Screen Lock"

    if [ -z "$CONSOLE_USER" ]; then
        result_info "Screen lock not checked (no console user)"
        return
    fi

    local sl delay=""
    sl=$(run_as_user sysadminctl -screenLock status 2>&1)
    if printf '%s' "$sl" | grep -q "screenLock is off"; then
        result_high "Password is NOT required after sleep/screen saver"
    elif printf '%s' "$sl" | grep -q "screenLock is immediate"; then
        delay=0
    elif printf '%s' "$sl" | grep -q "screenLock delay is"; then
        delay=$(printf '%s' "$sl" | grep -Eo 'delay is [0-9]+' | grep -Eo '[0-9]+')
    else
        # Fallback for older macOS
        local ask
        ask=$(read_user_pref com.apple.screensaver askForPassword)
        if [ "$ask" = "1" ]; then
            delay=$(read_user_pref com.apple.screensaver askForPasswordDelay)
            [ -z "$delay" ] && delay=0
            delay=${delay%%.*}
        elif [ "$ask" = "0" ]; then
            result_high "Password is NOT required after sleep/screen saver"
        else
            result_error "Could not determine screen lock setting"
        fi
    fi
    if [ -n "$delay" ]; then
        if [ "$delay" -le 5 ]; then
            result_pass "Password required after sleep/screen saver (delay: ${delay}s)"
        else
            result_medium "Screen lock delay is ${delay}s (recommended: 5s or less)"
        fi
    fi

    local idle
    idle=$(read_user_pref -currentHost com.apple.screensaver idleTime)
    idle=${idle%%.*}
    if [ -n "$idle" ]; then
        if [ "$idle" -eq 0 ]; then
            result_low "Screen saver is set to never start"
        elif [ "$idle" -gt 1200 ]; then
            result_low "Screen saver idle time is $((idle / 60)) minutes (recommended: 20 or less)"
        else
            result_pass "Screen saver idle time: $((idle / 60)) minutes"
        fi
    fi
}

#===============================================================================
# Firewall
#===============================================================================

check_firewall() {
    section_header "FIREWALL CONFIGURATION"

    local fw="/usr/libexec/ApplicationFirewall/socketfilterfw"
    if [ ! -x "$fw" ]; then
        result_error "Firewall tool not found"
        return
    fi

    subsection_header "Firewall Status"

    # Output wording differs between macOS releases, so match loosely.
    local state state_num
    state=$("$fw" --getglobalstate 2>/dev/null)
    state_num=$(printf '%s' "$state" | grep -Eo 'State = [0-9]' | grep -Eo '[0-9]')
    if [ "$state_num" = "1" ] || [ "$state_num" = "2" ] || \
       { [ -z "$state_num" ] && printf '%s' "$state" | grep -qi "enabled"; }; then
        result_pass "Application Firewall is enabled"
    else
        result_high "Application Firewall is DISABLED"
    fi

    if "$fw" --getstealthmode 2>/dev/null | grep -Eqi "enabled|is on"; then
        result_pass "Stealth mode is enabled"
    else
        result_low "Stealth mode is disabled"
    fi

    if "$fw" --getblockall 2>/dev/null | grep -Eqi "set to enabled|block all enabled"; then
        result_info "Block all incoming: enabled (restrictive mode)"
    else
        result_info "Block all incoming: disabled (normal operation)"
    fi

    if "$fw" --getloggingmode 2>/dev/null | grep -Eqi "mode is on|enabled"; then
        result_pass "Firewall logging is enabled"
    else
        result_low "Firewall logging is disabled"
    fi

    result_info "Auto-allow signed software: $("$fw" --getallowsigned 2>/dev/null | tr '\n' ' ')"

    subsection_header "Allowed Applications"
    local app_count
    app_count=$("$fw" --listapps 2>/dev/null | grep -Eio 'total number of apps = [0-9]+' | grep -Eo '[0-9]+')
    result_info "Applications with firewall rules: ${app_count:-unknown}"
}

#===============================================================================
# Network & sharing
#===============================================================================

check_network() {
    section_header "NETWORK CONFIGURATION"

    subsection_header "Network Interfaces"
    result_info "Interfaces that are up: $(ifconfig -lu 2>/dev/null)"

    subsection_header "Listening Services"

    # De-duplicate IPv4/IPv6 entries; flag anything bound to all interfaces.
    local listening count exposed
    listening=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR > 1 {print $1 " " $9}' | sort -u)
    if [ -n "$listening" ]; then
        count=$(count_lines "$listening")
        result_info "Listening TCP sockets: ${count}"
        list_details "$listening" 15
        exposed=$(printf '%s\n' "$listening" | grep -E ' (\*|0\.0\.0\.0|\[::\]):' | awk '{print $1}' | sort -u | tr '\n' ' ')
        if [ -n "$exposed" ]; then
            result_info "Listening on all interfaces (review): ${exposed}"
        fi
        [ "$EUID" -ne 0 ] && detail "(only the current user's processes are visible without root)"
    else
        result_pass "No TCP services listening"
    fi

    subsection_header "Sharing Services"

    if service_enabled "com.openssh.sshd"; then
        result_medium "Remote Login (SSH) is ENABLED"
        check_sshd_config
    else
        result_pass "Remote Login (SSH) is disabled"
    fi

    if service_enabled "com.apple.screensharing"; then
        result_medium "Screen Sharing is ENABLED"
    else
        result_pass "Screen Sharing is disabled"
    fi

    if service_enabled "com.apple.smbd"; then
        result_medium "File Sharing (SMB) is ENABLED"
        local shares
        shares=$(sharing -l 2>/dev/null | awk -F':[[:space:]]+' '/^name:/ {print $2}')
        list_details "$shares"
    else
        result_pass "File Sharing (SMB) is disabled"
    fi

    if service_enabled "com.apple.AEServer"; then
        result_medium "Remote Apple Events is ENABLED"
    else
        result_pass "Remote Apple Events is disabled"
    fi

    if cupsctl 2>/dev/null | grep -q '_share_printers=1'; then
        result_low "Printer Sharing is ENABLED"
    else
        result_pass "Printer Sharing is disabled"
    fi

    if defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null | grep -q "Enabled = 1"; then
        result_medium "Internet Sharing is ENABLED"
    else
        result_pass "Internet Sharing is disabled"
    fi

    subsection_header "Bluetooth"

    local bt_power
    bt_power=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null)
    if [ "$bt_power" = "1" ]; then
        result_info "Bluetooth is on"
    else
        result_info "Bluetooth is off"
    fi
}

# Evaluate the *effective* sshd configuration (includes sshd_config.d/ and
# built-in defaults) rather than grepping only the main file.
check_sshd_config() {
    local cfg
    cfg=$(sshd -T 2>/dev/null)
    if [ -z "$cfg" ]; then
        detail "(could not read effective sshd config; run as root)"
        return
    fi

    local root_login pw_auth kbd
    root_login=$(printf '%s\n' "$cfg" | awk '$1 == "permitrootlogin" {print $2}')
    pw_auth=$(printf '%s\n' "$cfg" | awk '$1 == "passwordauthentication" {print $2}')
    kbd=$(printf '%s\n' "$cfg" | awk '$1 == "kbdinteractiveauthentication" || $1 == "challengeresponseauthentication" {print $2; exit}')

    case "$root_login" in
        yes) result_high "SSH: root login with password is permitted" ;;
        no)  result_pass "SSH: root login is disabled" ;;
        *)   result_pass "SSH: root login restricted (${root_login})" ;;
    esac

    if [ "$pw_auth" = "yes" ] || [ "$kbd" = "yes" ]; then
        result_medium "SSH: password-based authentication is enabled (prefer keys only)"
    else
        result_pass "SSH: password authentication is disabled"
    fi
}

#===============================================================================
# Remote management & MDM
#===============================================================================

check_remote_management() {
    section_header "REMOTE MANAGEMENT & MDM"
    subsection_header "MDM Enrollment"

    local mdm_status
    mdm_status=$(profiles status -type enrollment 2>/dev/null)
    if printf '%s' "$mdm_status" | grep -q "MDM enrollment: Yes"; then
        result_pass "Device is MDM enrolled"
        local mdm_server
        mdm_server=$(printf '%s\n' "$mdm_status" | grep "MDM server" | cut -d: -f2- | sed 's/^ *//')
        [ -n "$mdm_server" ] && detail "MDM server: ${mdm_server}"
    elif printf '%s' "$mdm_status" | grep -q "MDM enrollment: No"; then
        result_info "Device is not MDM enrolled"
    else
        result_info "MDM status: unknown"
    fi
    if printf '%s' "$mdm_status" | grep -q "Enrolled via DEP: Yes"; then
        result_info "Device was enrolled via Automated Device Enrollment (DEP/ABM)"
    fi

    subsection_header "Configuration Profiles"

    local names
    names=$(profiles list 2>/dev/null | grep "attribute: name:" | sed 's/.*attribute: name: *//')
    if [ -n "$names" ]; then
        result_info "Installed configuration profiles: $(count_lines "$names")"
        list_details "$names"
    else
        result_info "No configuration profiles found"
    fi

    subsection_header "Remote Management (ARD)"

    if pgrep -x ARDAgent >/dev/null 2>&1 || \
       grep -q "enabled" "/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd" 2>/dev/null; then
        result_medium "Remote Management (ARD agent) is ENABLED"
    else
        result_pass "Remote Management (ARD) is not active"
    fi
}

#===============================================================================
# Application security
#===============================================================================

check_applications() {
    section_header "APPLICATION SECURITY"
    subsection_header "Third-Party Kernel Extensions"

    local raw kexts
    if [ "$OS_MAJOR" -ge 11 ] && have kmutil; then
        raw=$(kmutil showloaded --list-only 2>/dev/null)
    else
        raw=$(kextstat 2>/dev/null)
    fi
    kexts=$(printf '%s\n' "$raw" | grep -Eo '[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+){2,}' | grep -v '^com\.apple\.' | sort -u)
    if [ -n "$kexts" ]; then
        result_medium "Third-party kernel extensions loaded: $(count_lines "$kexts")"
        list_details "$kexts"
    else
        result_pass "No third-party kernel extensions loaded"
    fi

    subsection_header "System Extensions"

    local sysext active
    sysext=$(systemextensionsctl list 2>/dev/null)
    if [ -n "$sysext" ]; then
        active=$(printf '%s\n' "$sysext" | grep "activated enabled" | awk -F'\t' '{print $NF}' | sed 's/^[[:space:]]*//')
        result_info "Active system extensions: $(count_lines "$active")"
        list_details "$active"
    fi

    subsection_header "Launch Daemons & Agents (Non-Apple)"

    local dir items found=false
    for dir in /Library/LaunchDaemons /Library/LaunchAgents; do
        [ -d "$dir" ] || continue
        items=$(ls "$dir" 2>/dev/null | grep -v '^com\.apple\.')
        if [ -n "$items" ]; then
            found=true
            result_info "Third-party items in ${dir}: $(count_lines "$items")"
            list_details "$items" 15
        fi
    done
    [ "$found" = false ] && result_info "No third-party launch items in system directories"

    subsection_header "Application Code Signatures"

    local app out bad=0
    for app in /Applications/*.app /Applications/Utilities/*.app; do
        [ -d "$app" ] || continue
        out=$(codesign --verify --strict "$app" 2>&1) && continue
        bad=$((bad + 1))
        if printf '%s' "$out" | grep -q "not signed at all"; then
            result_high "Unsigned application: ${app#/Applications/}"
        else
            result_medium "Invalid/broken signature: ${app#/Applications/}"
        fi
    done
    [ "$bad" -eq 0 ] && result_pass "All applications in /Applications have valid signatures"
}

#===============================================================================
# Privacy & TCC
#===============================================================================

tcc_clients() {
    local db="$1" svc="$2" out
    out=$(sqlite3 "$db" "SELECT client FROM access WHERE service='${svc}' AND auth_value=2;" 2>/dev/null) || \
        out=$(sqlite3 "$db" "SELECT client FROM access WHERE service='${svc}' AND allowed=1;" 2>/dev/null)
    printf '%s' "$out"
}

check_privacy() {
    section_header "PRIVACY & TCC PERMISSIONS"
    subsection_header "TCC Database (system)"

    local db="/Library/Application Support/com.apple.TCC/TCC.db"
    # -r is always true for root; actually opening the DB is the real test.
    if [ -f "$db" ] && sqlite3 "$db" "SELECT 1 FROM access LIMIT 1;" >/dev/null 2>&1; then
        local pair svc label clients
        for pair in "kTCCServiceSystemPolicyAllFiles|Full Disk Access" \
                    "kTCCServiceAccessibility|Accessibility" \
                    "kTCCServiceScreenCapture|Screen Recording" \
                    "kTCCServiceListenEvent|Input Monitoring"; do
            svc=${pair%%|*}
            label=${pair#*|}
            clients=$(tcc_clients "$db" "$svc")
            result_info "${label}: $(count_lines "$clients") app(s)"
            list_details "$clients"
        done
    else
        result_error "Cannot read system TCC database (grant the terminal Full Disk Access)"
    fi

    subsection_header "Location Services"

    local loc
    loc=$(sudo -u _locationd defaults -currentHost read com.apple.locationd LocationServicesEnabled 2>/dev/null)
    case "$loc" in
        1) result_info "Location Services is enabled" ;;
        0) result_info "Location Services is disabled" ;;
        *) result_info "Location Services status: unknown" ;;
    esac

    subsection_header "Siri & Analytics"

    if [ -n "$CONSOLE_USER" ]; then
        local siri
        siri=$(read_user_pref com.apple.assistant.support "Assistant Enabled")
        if [ "$siri" = "1" ]; then
            result_low "Siri is enabled"
        else
            result_pass "Siri is disabled"
        fi
    fi

    local analytics
    analytics=$(read_pref "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" AutoSubmit)
    if [ "$analytics" = "1" ]; then
        result_low "Sharing of Mac analytics with Apple is enabled"
    else
        result_pass "Sharing of Mac analytics with Apple is disabled"
    fi
}

#===============================================================================
# Security software (EDR/AV)
#===============================================================================

check_security_software() {
    section_header "SECURITY SOFTWARE"
    subsection_header "Endpoint Detection & Response"

    # Match on vendor bundle-ID prefixes across loaded services, system
    # extensions and installed daemons. Broad substrings such as "sep", "eset"
    # or "cb." caused false positives in v1.
    local haystack
    haystack=$(
        launchctl list 2>/dev/null
        systemextensionsctl list 2>/dev/null
        ls /Library/LaunchDaemons 2>/dev/null
    )

    local found=false entry name pattern
    for entry in \
        "CrowdStrike Falcon|com\.crowdstrike" \
        "Microsoft Defender|com\.microsoft\.wdav" \
        "SentinelOne|com\.sentinelone" \
        "VMware/Broadcom Carbon Black|com\.(vmware\.)?carbonblack" \
        "Symantec/Broadcom Endpoint|com\.(symantec|broadcom)" \
        "Sophos|com\.sophos" \
        "Palo Alto Cortex XDR|com\.paloaltonetworks" \
        "Trellix/McAfee|com\.(mcafee|trellix)" \
        "Elastic Endpoint|co\.elastic" \
        "Kaspersky|com\.kaspersky" \
        "ESET|com\.eset\." \
        "Bitdefender|com\.bitdefender" \
        "Malwarebytes|com\.malwarebytes" \
        "Jamf Protect|com\.jamf\.protect"; do
        name=${entry%%|*}
        pattern=${entry#*|}
        if printf '%s\n' "$haystack" | grep -Eqi "$pattern"; then
            result_pass "${name} detected"
            found=true
        fi
    done

    [ "$found" = false ] && result_medium "No common EDR/AV solution detected"
}

#===============================================================================
# Firmware & hardware security
#===============================================================================

check_firmware_security() {
    section_header "FIRMWARE & HARDWARE SECURITY"
    subsection_header "Secure Boot"

    if [ "$IS_ARM" = true ]; then
        local policy mode
        policy=$(bputil -d 2>/dev/null)
        mode=$(printf '%s\n' "$policy" | grep -i "security mode" | head -1)
        if printf '%s' "$mode" | grep -qi "full"; then
            result_pass "Startup security: Full Security"
        elif printf '%s' "$mode" | grep -qi "reduced"; then
            result_medium "Startup security: Reduced Security"
        elif printf '%s' "$mode" | grep -qi "permissive"; then
            result_high "Startup security: Permissive Security"
        else
            result_error "Could not determine startup security policy"
        fi
        result_info "Firmware passwords are not used on Apple Silicon (Recovery requires an admin)"
    else
        local has_t2 sb
        has_t2=$(system_profiler SPiBridgeDataType 2>/dev/null | grep -i "Model Name")
        if [ -n "$has_t2" ]; then
            result_info "T2 Security Chip detected"
            sb=$(nvram 94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy 2>/dev/null | awk '{print $2}')
            case "$sb" in
                %02) result_pass "Secure Boot: Full Security" ;;
                %01) result_medium "Secure Boot: Medium Security" ;;
                %00) result_high "Secure Boot: No Security" ;;
                *)   result_error "Could not determine Secure Boot policy" ;;
            esac
        else
            result_info "No T2 chip (older Intel Mac)"
        fi

        if firmwarepasswd -check 2>/dev/null | grep -q "Password Enabled: Yes"; then
            result_pass "Firmware password is set"
        elif [ "$EUID" -eq 0 ]; then
            if [ -n "$has_t2" ]; then
                result_low "Firmware password is not set"
            else
                result_medium "Firmware password is not set"
            fi
        else
            result_error "Could not check firmware password (requires root)"
        fi
    fi

    subsection_header "Activation Lock"

    local al
    al=$(system_profiler SPHardwareDataType 2>/dev/null | grep "Activation Lock Status" | awk -F': ' '{print $2}')
    [ -n "$al" ] && result_info "Activation Lock: ${al}"
}

#===============================================================================
# Logging & auditing
#===============================================================================

check_logging() {
    section_header "LOGGING & AUDITING"
    subsection_header "Audit (OpenBSM)"

    if [ "$OS_MAJOR" -ge 14 ]; then
        result_info "OpenBSM auditing is deprecated on macOS 14+; use the Endpoint Security framework / EDR telemetry"
    elif [ -f /etc/security/audit_control ]; then
        local flags
        flags=$(grep '^flags:' /etc/security/audit_control 2>/dev/null | cut -d: -f2)
        [ -n "$flags" ] && result_info "Audit flags: ${flags}"
        if launchctl list 2>/dev/null | grep -q "com.apple.auditd"; then
            result_pass "Audit daemon is loaded"
        else
            result_medium "Audit daemon is not loaded"
        fi
    else
        result_medium "Audit configuration file not found"
    fi

    subsection_header "Install Log"
    if [ -f /var/log/install.log ]; then
        result_info "Install log size: $(du -h /var/log/install.log 2>/dev/null | awk '{print $1}')"
    else
        result_low "/var/log/install.log is missing"
    fi
}

#===============================================================================
# Privilege escalation vectors
#===============================================================================

check_privesc() {
    section_header "PRIVILEGE ESCALATION VECTORS"
    subsection_header "SUID/SGID Binaries (third-party locations)"

    local suid
    suid=$(find /usr/local /opt /Applications -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    if [ -n "$suid" ]; then
        result_medium "SUID/SGID binaries in non-system locations: $(count_lines "$suid")"
        list_details "$suid" 20
    else
        result_pass "No SUID/SGID binaries in common third-party locations"
    fi

    subsection_header "Sudo Configuration"

    # -h drops the filename prefix so comment lines can be filtered properly.
    local nopasswd
    nopasswd=$(grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null)
    if [ -n "$nopasswd" ]; then
        result_medium "NOPASSWD entries in sudoers: $(count_lines "$nopasswd")"
        list_details "$nopasswd"
    elif [ -r /etc/sudoers ]; then
        result_pass "No NOPASSWD entries in sudoers"
    else
        result_error "Cannot read /etc/sudoers"
    fi

    local timeout
    timeout=$(grep -rhE '^[^#]*timestamp_timeout' /etc/sudoers /etc/sudoers.d 2>/dev/null)
    [ -n "$timeout" ] && result_info "Sudo timeout: ${timeout}"

    subsection_header "Launch Item Permissions"

    # A non-root-writable plist in these dirs is a direct path to root.
    local weak
    weak=$(find /Library/LaunchDaemons /Library/LaunchAgents -type f \( ! -user root -o -perm -0002 -o -perm -0020 \) 2>/dev/null)
    if [ -n "$weak" ]; then
        result_high "Launch items writable by non-root users: $(count_lines "$weak")"
        list_details "$weak"
    else
        result_pass "System launch item plists are root-owned and not group/world-writable"
    fi

    subsection_header "World-Writable Directories"

    local ww
    ww=$(find /usr/local /opt /Applications -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null)
    if [ -n "$ww" ]; then
        result_medium "World-writable directories (no sticky bit): $(count_lines "$ww")"
        list_details "$ww" 10
    else
        result_pass "No world-writable directories in common locations"
    fi
}

#===============================================================================
# Software updates
#===============================================================================

check_update_key() {
    local key="$1" label="$2" sev_off="$3" val
    val=$(read_pref /Library/Preferences/com.apple.SoftwareUpdate "$key")
    case "$val" in
        1) result_pass "${label}: enabled" ;;
        0) "result_${sev_off}" "${label}: DISABLED" ;;
        *) result_info "${label}: not explicitly set (OS default applies; enforce via MDM)" ;;
    esac
}

check_updates() {
    section_header "SOFTWARE UPDATES"
    subsection_header "Update Configuration"

    check_update_key AutomaticCheckEnabled            "Automatic update check"            medium
    check_update_key AutomaticDownload                "Automatic download"                low
    check_update_key CriticalUpdateInstall            "Security responses & system files" medium
    check_update_key ConfigDataInstall                "XProtect/config data updates"      medium
    check_update_key AutomaticallyInstallMacOSUpdates "Automatic macOS updates"           low

    subsection_header "Available Updates"

    if [ "$SKIP_UPDATES" = true ]; then
        result_info "Skipped (--skip-updates)"
        return
    fi

    result_info "Checking for available updates (this can take a minute)..."
    local updates labels
    updates=$(softwareupdate -l 2>&1)
    labels=$(printf '%s\n' "$updates" | grep -E '^\* Label:' | sed 's/^\* Label: *//')
    if [ -n "$labels" ]; then
        result_medium "Pending updates: $(count_lines "$labels")"
        list_details "$labels"
    elif printf '%s' "$updates" | grep -q "No new software available"; then
        result_pass "System is up to date"
    else
        result_error "Could not check for updates (network or Software Update service issue)"
    fi
}

#===============================================================================
# Summary
#===============================================================================

print_summary() {
    section_header "AUDIT SUMMARY"
    echo ""
    printf '%s\n' "  ${BOLD}Finding Summary:${NC}"
    echo "  ───────────────────────────────────"
    printf '  %-20s %s\n' "${RED}Critical:${NC}" "$CRITICAL_COUNT"
    printf '  %-20s %s\n' "${RED}High:${NC}"     "$HIGH_COUNT"
    printf '  %-20s %s\n' "${YELLOW}Medium:${NC}" "$MEDIUM_COUNT"
    printf '  %-20s %s\n' "${YELLOW}Low:${NC}"   "$LOW_COUNT"
    printf '  %-20s %s\n' "${GREEN}Pass:${NC}"   "$PASS_COUNT"
    printf '  %-20s %s\n' "${CYAN}Info:${NC}"    "$INFO_COUNT"
    echo "  ───────────────────────────────────"
    printf '%s\n' "  ${BOLD}Total Findings:${NC} $((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT))"
    echo ""

    if [ "$CRITICAL_COUNT" -gt 0 ]; then
        printf '%s\n' "  ${RED}${BOLD}Overall Risk: CRITICAL${NC}" "  ${RED}Immediate remediation required.${NC}"
    elif [ "$HIGH_COUNT" -gt 0 ]; then
        printf '%s\n' "  ${RED}${BOLD}Overall Risk: HIGH${NC}" "  ${RED}High-priority findings should be addressed promptly.${NC}"
    elif [ "$MEDIUM_COUNT" -gt 0 ]; then
        printf '%s\n' "  ${YELLOW}${BOLD}Overall Risk: MEDIUM${NC}" "  ${YELLOW}Review and address medium findings as appropriate.${NC}"
    elif [ "$LOW_COUNT" -gt 0 ]; then
        printf '%s\n' "  ${GREEN}${BOLD}Overall Risk: LOW${NC}" "  ${GREEN}Minor issues identified.${NC}"
    else
        printf '%s\n' "  ${GREEN}${BOLD}Overall Risk: MINIMAL${NC}" "  ${GREEN}No significant issues identified.${NC}"
    fi
    echo ""
    printf '%s\n' "  ${CYAN}Audit completed at: $(date)${NC}"
    echo ""
}

#===============================================================================
# Main
#===============================================================================

run_audit() {
    banner
    check_root
    init_context

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

    if [ "$CRITICAL_COUNT" -gt 0 ]; then return 2; fi
    if [ "$HIGH_COUNT" -gt 0 ]; then return 1; fi
    return 0
}

main() {
    parse_args "$@"

    if [ "$(uname -s)" != "Darwin" ]; then
        echo "Error: this script only runs on macOS." >&2
        exit 1
    fi

    [ -t 1 ] || USE_COLOR=false
    [ "$USE_COLOR" = false ] && disable_colors

    [ -z "$OUTPUT_FILE" ] && OUTPUT_FILE="macos_audit_$(hostname -s 2>/dev/null)_${TIMESTAMP}.txt"

    local tmp rc
    tmp=$(mktemp "${TMPDIR:-/tmp}/macos_audit.XXXXXX") || { echo "Error: cannot create temp file" >&2; exit 1; }
    trap 'rm -f "$tmp"' EXIT

    # Running the audit as a plain pipeline (rather than `exec > >(tee ...)`)
    # guarantees all output is flushed before we continue.
    run_audit 2>&1 | tee "$tmp"
    rc=${PIPESTATUS[0]}

    # Save a colour-free copy of the report.
    if sed $'s/\033\\[[0-9;]*m//g' "$tmp" > "$OUTPUT_FILE"; then
        [ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER" "$OUTPUT_FILE" 2>/dev/null
        echo "[*] Report saved to: ${OUTPUT_FILE}"
    else
        echo "Error: could not write report to ${OUTPUT_FILE}" >&2
    fi

    exit "$rc"
}

main "$@"
