import sys
import os
import json
import subprocess
import time
import re
from datetime import datetime
from collections import defaultdict

# ==========================================
# INPUT VALIDATION
# ==========================================
if len(sys.argv) < 2:
    print("Usage: python runner.py <file>")
    sys.exit(1)

target_file = sys.argv[1]

if not os.path.exists(target_file):
    print("File not found:", target_file)
    sys.exit(1)

# ==========================================
# RUNTIME CONTAINERS
# ==========================================
spawned_processes = set()
network_connections = []
file_created = set()
file_written = set()
file_deleted = set()
sensitive_access = set()
commands_detected = set()
domains_contacted = set()
syscall_counter = defaultdict(int)
timeline = []

sensitive_paths = [
    "/etc/passwd",
    "/etc/shadow",
    "/root",
    ".ssh",
    "/home",
    "/tmp"
]

suspicious_commands = [
    "curl","wget","bash","sh","nc","netcat",
    "chmod","chown","python","node"
]

# ==========================================
# STRACE EXECUTION
# ==========================================
print("Starting decoy sandbox execution...")

start_time = time.time()

process = subprocess.Popen(
    [
        "strace",
        "-ff",
        "-tt",
        "-e",
        "trace=execve,clone,fork,vfork,open,openat,write,connect,sendto,recvfrom,unlink,rename",
        "python",
        target_file
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

try:
    stdout, stderr = process.communicate(timeout=20)
except subprocess.TimeoutExpired:
    process.kill()
    stdout, stderr = process.communicate()

runtime = round(time.time() - start_time, 3)

# ==========================================
# STRACE PARSER
# ==========================================
for line in stderr.split("\n"):

    if not line.strip():
        continue

    # count syscalls
    syscall = line.split("(")[0].split()[-1]
    syscall_counter[syscall] += 1

    # timeline
    timeline.append({
        "timestamp": datetime.utcnow().isoformat(),
        "event": syscall,
        "detail": line.strip()
    })

    # --------------------------------------
    # PROCESS DETECTION
    # --------------------------------------
    if "execve(" in line:
        match = re.search(r'execve\("([^"]+)"', line)
        if match:
            proc = os.path.basename(match.group(1))
            spawned_processes.add(proc)

            if proc in suspicious_commands:
                commands_detected.add(proc)

    # --------------------------------------
    # NETWORK DETECTION
    # --------------------------------------
    if "connect(" in line:
        ip_match = re.search(r'inet_addr\("([^"]+)"\)', line)
        port_match = re.search(r'htons\((\d+)\)', line)

        if ip_match:
            ip = ip_match.group(1)
            port = port_match.group(1) if port_match else "unknown"

            network_connections.append({
                "ip": ip,
                "port": port
            })

    # --------------------------------------
    # FILE SYSTEM ACTIVITY
    # --------------------------------------
    if "open(" in line or "openat(" in line:
        file_match = re.search(r'"([^"]+)"', line)
        if file_match:
            f = file_match.group(1)

            if "O_CREAT" in line:
                file_created.add(f)

            if "O_WRONLY" in line or "O_RDWR" in line:
                file_written.add(f)

            for s in sensitive_paths:
                if s in f:
                    sensitive_access.add(f)

    # --------------------------------------
    # FILE DELETION
    # --------------------------------------
    if "unlink(" in line:
        match = re.search(r'"([^"]+)"', line)
        if match:
            file_deleted.add(match.group(1))

# ==========================================
# BEHAVIOR SCORING
# ==========================================
score = 0

score += min(len(network_connections),5)
score += min(len(spawned_processes),3)
score += min(len(file_written),3)

if sensitive_access:
    score += 3

if commands_detected:
    score += 2

# ==========================================
# MITRE ATT&CK MAPPING
# ==========================================
mitre = []

if commands_detected:
    mitre.append("T1059 Command and Scripting Interpreter")

if network_connections:
    mitre.append("T1071 Application Layer Protocol")

if sensitive_access:
    mitre.append("T1005 Data from Local System")

if file_written:
    mitre.append("T1105 Ingress Tool Transfer")

# ==========================================
# LOG STRUCTURE
# ==========================================
os.makedirs("decoy_logs", exist_ok=True)

run_id = os.getenv("GITHUB_RUN_NUMBER", str(int(time.time())))

log = {
    "run_id": run_id,
    "package": target_file,
    "runtime_seconds": runtime,

    "process_activity": list(spawned_processes),

    "network_activity": {
        "connections": len(network_connections),
        "details": network_connections
    },

    "filesystem_activity": {
        "files_created": list(file_created),
        "files_written": list(file_written),
        "files_deleted": list(file_deleted)
    },

    "sensitive_access": list(sensitive_access),

    "commands_detected": list(commands_detected),

    "syscall_stats": dict(syscall_counter),

    "behavior_score": score,

    "mitre_techniques": mitre,

    "timeline": timeline[:50],

    "timestamp": datetime.utcnow().isoformat()
}

# ==========================================
# SAVE LOGS
# ==========================================
with open(f"decoy_logs/log_{run_id}.json","w") as f:
    json.dump(log,f,indent=4)

with open("decoy_logs/latest.json","w") as f:
    json.dump(log,f,indent=4)

history_path="decoy_logs/history.json"

if os.path.exists(history_path):
    with open(history_path,"r") as f:
        history=json.load(f)
else:
    history=[]

history.append(log)

with open(history_path,"w") as f:
    json.dump(history[-50:],f,indent=4)

print("Decoy analysis complete.")
print("Behavior score:",score)

sys.exit(0)
