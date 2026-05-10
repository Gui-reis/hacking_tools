#!/bin/sh

# LinPEAS Lite - simplified Linux privilege escalation enumeration helper
# Intended for authorized labs, CTFs, and systems you own/have permission to test.
# Passive enumeration only: does not exploit, brute-force, scan networks, or modify files.

VERSION="0.1"
HOSTNAME_VALUE="$(hostname 2>/dev/null || echo unknown)"
CURRENT_USER="$(whoami 2>/dev/null || id -un 2>/dev/null || echo unknown)"

# Colors: disabled automatically when stdout is not a terminal or when -n is used.
USE_COLOR=1
[ ! -t 1 ] && USE_COLOR=0

while getopts "nh" opt; do
  case "$opt" in
    n) USE_COLOR=0 ;;
    h)
      cat <<EOF
LinPEAS Lite v$VERSION

Usage: $0 [-n]

Options:
  -n   Disable colors
  -h   Show this help

This script performs passive local enumeration only.
EOF
      exit 0
      ;;
  esac
done

if [ "$USE_COLOR" -eq 1 ]; then
  RED='\033[1;31m'
  YELLOW='\033[1;33m'
  GREEN='\033[1;32m'
  BLUE='\033[1;34m'
  GRAY='\033[1;90m'
  NC='\033[0m'
else
  RED=''
  YELLOW=''
  GREEN=''
  BLUE=''
  GRAY=''
  NC=''
fi

print_banner() {
  printf "%b\n" "${BLUE}LinPEAS Lite v$VERSION${NC} - passive privilege escalation enumeration"
  printf "%b\n" "Host: ${HOSTNAME_VALUE} | User: ${CURRENT_USER}"
  printf "%b\n\n" "Authorized use only."
}

section() {
  printf "\n%b\n" "${BLUE}========== $1 ==========${NC}"
}

info() {
  printf "%b\n" "${GREEN}[INFO]${NC} $1"
}

warn() {
  printf "%b\n" "${YELLOW}[HIGH]${NC} $1"
}

crit() {
  printf "%b\n" "${RED}[CRITICAL]${NC} $1"
}

note() {
  printf "%b\n" "${GRAY}  $1${NC}"
}

run_cmd() {
  # $1 = command description
  # $2 = command
  note "$1"
  sh -c "$2" 2>/dev/null | sed 's/^/  /'
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

is_writable() {
  [ -e "$1" ] && [ -w "$1" ]
}

check_identity_system() {
  section "1. Identity and system"

  run_cmd "Current identity:" "id"
  run_cmd "Kernel and architecture:" "uname -a"

  if [ -f /etc/os-release ]; then
    run_cmd "OS release:" "cat /etc/os-release | grep -E '^(PRETTY_NAME|NAME|VERSION)='"
  fi

  if [ -f /.dockerenv ] || grep -qaE 'docker|lxc|kubepods|containerd' /proc/1/cgroup 2>/dev/null; then
    warn "Container indicators found. Container escape paths may be relevant."
    run_cmd "Container cgroup hints:" "cat /proc/1/cgroup | head -20"
  else
    info "No obvious container indicator found."
  fi
}

check_sudo_groups() {
  section "2. Sudo and groups"

  groups_output="$(id 2>/dev/null)"
  echo "$groups_output" | sed 's/^/  /'

  for group in sudo wheel docker lxd adm disk shadow root; do
    echo "$groups_output" | grep -qw "$group" && warn "Current user appears to be in interesting group: $group"
  done

  if command_exists sudo; then
    note "sudo -l without password, if allowed by policy/cache:"
    sudo -n -l 2>/dev/null | sed 's/^/  /'
    if [ "${PIPESTATUS:-0}" ]; then :; fi

    sudo_nl="$(sudo -n -l 2>/dev/null)"
    if echo "$sudo_nl" | grep -qi 'NOPASSWD'; then
      crit "NOPASSWD sudo rule detected. Check listed binaries on GTFOBins."
    elif [ -n "$sudo_nl" ]; then
      warn "sudo -l returned data. Review allowed commands carefully."
    else
      info "No passwordless sudo info available with sudo -n -l."
    fi
  else
    info "sudo command not found."
  fi
}

check_suid_sgid() {
  section "3. SUID and SGID binaries"

  note "Known SUID binaries are normal. Focus on uncommon/custom paths like /opt, /home, /tmp, /usr/local."

  suid_results="$(find / -xdev -perm -4000 -type f 2>/dev/null | sort)"
  if [ -n "$suid_results" ]; then
    echo "$suid_results" | sed 's/^/  /'
    echo "$suid_results" | grep -E '^/(home|opt|tmp|var/tmp|usr/local)/' >/dev/null 2>&1 && crit "SUID binary found in uncommon writable-ish/custom path. Investigate first."
  else
    info "No SUID binaries found on current filesystem boundary."
  fi

  sgid_results="$(find / -xdev -perm -2000 -type f 2>/dev/null | sort | head -50)"
  if [ -n "$sgid_results" ]; then
    note "First SGID binaries found:"
    echo "$sgid_results" | sed 's/^/  /'
  fi
}

check_capabilities() {
  section "4. Capabilities"

  if ! command_exists getcap; then
    info "getcap not found. Skipping capabilities."
    return
  fi

  caps="$(getcap -r / 2>/dev/null | sort)"
  if [ -z "$caps" ]; then
    info "No capabilities found or insufficient permissions to list them."
    return
  fi

  echo "$caps" | sed 's/^/  /'

  echo "$caps" | grep -E 'cap_setuid|cap_setgid|cap_dac_read_search|cap_dac_override' >/dev/null 2>&1 \
    && crit "Dangerous capability detected. cap_setuid/cap_setgid/cap_dac_* can be privilege escalation relevant."
}

check_cron_timers() {
  section "5. Cron jobs and systemd timers"

  [ -f /etc/crontab ] && run_cmd "/etc/crontab:" "cat /etc/crontab"

  for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [ -d "$dir" ] && run_cmd "Listing $dir:" "ls -la $dir"
  done

  if command_exists systemctl; then
    run_cmd "Systemd timers:" "systemctl list-timers --all --no-pager | head -80"
  fi

  note "Writable cron-related files/directories:"
  writable_cron="$(find /etc/cron* -writable 2>/dev/null)"
  if [ -n "$writable_cron" ]; then
    echo "$writable_cron" | sed 's/^/  /'
    crit "Writable cron path found. If root executes it, this may be exploitable."
  else
    info "No writable cron paths found under /etc/cron*."
  fi
}

check_processes_ports() {
  section "6. Processes and local ports"

  run_cmd "Root-owned processes with command preview:" "ps aux | awk '\$1 == \"root\" {print}' | head -40"

  if command_exists ss; then
    run_cmd "Listening TCP/UDP sockets:" "ss -tulpn"
  elif command_exists netstat; then
    run_cmd "Listening TCP/UDP sockets:" "netstat -tulpn"
  else
    info "Neither ss nor netstat found."
  fi

  note "Local-only services on 127.0.0.1 may be interesting for pivoting/tunneling in labs."
}

check_sensitive_files() {
  section "7. Sensitive files and credentials"

  note "SSH material in home directories:"
  find /home /root -maxdepth 3 \( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name 'authorized_keys' \) -type f -readable 2>/dev/null | sed 's/^/  /'

  note "Common credential/config files in likely locations:"
  find /home /var/www /opt /srv /tmp -maxdepth 4 -type f \( \
    -name '.env' -o -name '*.env' -o -name 'config.php' -o -name 'wp-config.php' -o \
    -name 'settings.py' -o -name 'database.yml' -o -name '*.bak' -o -name '*.old' -o \
    -name '*.backup' -o -name '*.sql' -o -name '.bash_history' \
  \) -readable 2>/dev/null | sed 's/^/  /'

  note "Quick keyword search in small readable config-like files:"
  find /home /var/www /opt /srv -maxdepth 4 -type f -readable -size -200k 2>/dev/null \
    | grep -Ei '(env|config|settings|database|backup|history|credential|secret|token|key|pass)' \
    | head -80 \
    | while read -r file; do
        match="$(grep -IinE 'password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|DB_PASSWORD|AWS_|BEGIN .*PRIVATE KEY' "$file" 2>/dev/null | head -3)"
        if [ -n "$match" ]; then
          warn "Potential secret in $file"
          echo "$match" | sed 's/^/    /'
        fi
      done
}

check_dangerous_permissions() {
  section "8. Dangerous permissions"

  for file in /etc/passwd /etc/shadow /etc/sudoers; do
    if is_writable "$file"; then
      crit "$file is writable by current user."
      ls -la "$file" 2>/dev/null | sed 's/^/  /'
    else
      info "$file is not writable by current user."
    fi
  done

  note "Writable files/directories in sensitive/custom locations:"
  find /etc /opt /usr/local/bin /usr/local/sbin /var/www -xdev -writable 2>/dev/null | head -100 | sed 's/^/  /'

  note "World-writable directories outside common noisy paths:"
  find / -xdev -type d -perm -0002 2>/dev/null \
    | grep -Ev '^/(proc|sys|dev|run|tmp|var/tmp)(/|$)' \
    | head -80 \
    | sed 's/^/  /'
}

print_banner
check_identity_system
check_sudo_groups
check_suid_sgid
check_capabilities
check_cron_timers
check_processes_ports
check_sensitive_files
check_dangerous_permissions

printf "\n%b\n" "${BLUE}Done.${NC} Review [CRITICAL] and [HIGH] findings first."
