import sys
import os
import json
import subprocess
import time
import re
import hashlib
import tarfile
import urllib.request
from datetime import datetime
from collections import defaultdict 

# ==========================================
# INPUT VALIDATION
# ==========================================

if len(sys.argv) < 2:
    print("Usage: python runner.py <package>")
    sys.exit(1)

target_file = sys.argv[1]

if not os.path.exists(target_file):
    print("File not found:", target_file)
    sys.exit(1)

# ==========================================
# FILE HASH
# ==========================================

def file_hash(path):
    h = hashlib.sha256()
    with open(path,"rb") as f:
        h.update(f.read())
    return h.hexdigest()

package_hash = file_hash(target_file)

# ==========================================
# RUNTIME DATA STRUCTURES
# ==========================================

spawned_processes=set()
network_connections=[]
file_created=set()
file_written=set()
file_deleted=set()
sensitive_access=set()
commands_detected=set()
syscall_counter=defaultdict(int)
timeline=[]

sensitive_paths=[
"/etc/passwd",
"/etc/shadow",
"/root",
".ssh",
"/home",
"/tmp"
]

suspicious_commands=[
"curl","wget","bash","sh","nc","netcat",
"chmod","chown","python","node"
]

# ==========================================
# THREAT INTELLIGENCE LOOKUP
# ==========================================

def enrich_ip(ip):

    try:
        url=f"http://ip-api.com/json/{ip}"
        response=urllib.request.urlopen(url,timeout=3)
        data=json.loads(response.read().decode())

        return {
            "ip":ip,
            "country":data.get("country"),
            "asn":data.get("as"),
            "org":data.get("org"),
            "isp":data.get("isp")
        }

    except:
        return {"ip":ip}

# ==========================================
# EXTRACT PACKAGE
# ==========================================

print("Extracting package...")

sandbox_dir="sandbox_env"
os.makedirs(sandbox_dir,exist_ok=True)

extract_dir=os.path.join(sandbox_dir,"package")

if os.path.exists(extract_dir):
    subprocess.run(["rm","-rf",extract_dir])

os.makedirs(extract_dir)

try:
    with tarfile.open(target_file,"r:*") as tar:
        tar.extractall(extract_dir)
except:
    print("Extraction failed")

# ==========================================
# DETECT PACKAGE TYPE
# ==========================================

is_npm=False
is_python=False

for root,dirs,files in os.walk(extract_dir):

    if "package.json" in files:
        is_npm=True

    if "setup.py" in files or "pyproject.toml" in files:
        is_python=True

# ==========================================
# COMMAND TO EXECUTE
# ==========================================

cmd=None

if is_npm:

    print("Detected NPM package")

    cmd=[
    "npm",
    "install"
    ]

elif is_python:

    print("Detected Python package")

    cmd=[
    "pip",
    "install",
    "."
    ]

else:

    print("Unknown package type")

    cmd=[
    "python",
    target_file
    ]

# ==========================================
# eBPF MONITORING (TRACEe)
# ==========================================

print("Starting eBPF monitoring...")

tracee_process=None
tracee_log="tracee_output.json"

try:

    tracee_process=subprocess.Popen(
        [
        "tracee",
        "-o",
        "json"
        ],
        stdout=open(tracee_log,"w"),
        stderr=subprocess.DEVNULL
    )

    time.sleep(2)

except:
    print("Tracee not available, fallback to strace")

# ==========================================
# STRACE FALLBACK
# ==========================================

start_time=time.time()

process=subprocess.Popen(

[
"strace",
"-ff",
"-tt",
"-e",
"trace=execve,clone,fork,vfork,open,openat,write,connect,sendto,recvfrom,unlink,rename"
]+cmd,

cwd=extract_dir,

stdout=subprocess.PIPE,
stderr=subprocess.PIPE,
text=True

)

try:
    stdout,stderr=process.communicate(timeout=30)
except subprocess.TimeoutExpired:
    process.kill()
    stdout,stderr=process.communicate()

runtime=round(time.time()-start_time,3)

if tracee_process:
    tracee_process.kill()

# ==========================================
# PARSE STRACE
# ==========================================

for line in stderr.split("\n"):

    if not line.strip():
        continue

    syscall=line.split("(")[0].split()[-1]
    syscall_counter[syscall]+=1

    timeline.append({
    "timestamp":datetime.utcnow().isoformat(),
    "event":syscall,
    "detail":line.strip()
    })

    # PROCESS DETECTION
    if "execve(" in line:

        match=re.search(r'execve\("([^"]+)"',line)

        if match:

            proc=os.path.basename(match.group(1))
            spawned_processes.add(proc)

            if proc in suspicious_commands:
                commands_detected.add(proc)

    # NETWORK DETECTION
    if "connect(" in line:

        ip_match=re.search(r'inet_addr\("([^"]+)"\)',line)
        port_match=re.search(r'htons\((\d+)\)',line)

        if ip_match:

            ip=ip_match.group(1)
            port=port_match.group(1) if port_match else "unknown"

            network_connections.append({
            "ip":ip,
            "port":port
            })

    # FILE SYSTEM
    if "open(" in line or "openat(" in line:

        file_match=re.search(r'"([^"]+)"',line)

        if file_match:

            f=file_match.group(1)

            if "O_CREAT" in line:
                file_created.add(f)

            if "O_WRONLY" in line or "O_RDWR" in line:
                file_written.add(f)

            for s in sensitive_paths:

                if s in f:
                    sensitive_access.add(f)

    # FILE DELETE
    if "unlink(" in line:

        match=re.search(r'"([^"]+)"',line)

        if match:
            file_deleted.add(match.group(1))

# ==========================================
# THREAT INTELLIGENCE ENRICHMENT
# ==========================================

ti_connections=[]

for n in network_connections:

    enriched=enrich_ip(n["ip"])

    ti_connections.append({
        "ip":n["ip"],
        "port":n["port"],
        "country":enriched.get("country"),
        "asn":enriched.get("asn"),
        "org":enriched.get("org")
    })

# ==========================================
# BEHAVIOR SCORING
# ==========================================

score=0

score+=min(len(network_connections),5)
score+=min(len(spawned_processes),3)
score+=min(len(file_written),3)

if sensitive_access:
    score+=3

if commands_detected:
    score+=2

# ==========================================
# MITRE ATTACK
# ==========================================

mitre=[]

if commands_detected:
    mitre.append("T1059 Command Interpreter")

if network_connections:
    mitre.append("T1071 Application Layer Protocol")

if sensitive_access:
    mitre.append("T1005 Data from Local System")

if file_written:
    mitre.append("T1105 Ingress Tool Transfer")

# ==========================================
# SAVE LOG
# ==========================================

os.makedirs("decoy_logs",exist_ok=True)

run_id=os.getenv("GITHUB_RUN_NUMBER",str(int(time.time())))

log={

"run_id":run_id,

"package":{
"name":os.path.basename(target_file),
"path":target_file,
"hash":package_hash
},

"runtime_seconds":runtime,

"process_activity":list(spawned_processes),

"network_activity":{
"connections":len(network_connections),
"details":ti_connections
},

"filesystem_activity":{
"files_created":list(file_created),
"files_written":list(file_written),
"files_deleted":list(file_deleted)
},

"sensitive_access":list(sensitive_access),

"commands_detected":list(commands_detected),

"syscall_stats":dict(syscall_counter),

"behavior_score":score,

"mitre_techniques":mitre,

"timeline":timeline[:50],

"timestamp":datetime.utcnow().isoformat()

}

with open(f"decoy_logs/log_{run_id}.json","w") as f:
    json.dump(log,f,indent=4)

with open("decoy_logs/latest.json","w") as f:
    json.dump(log,f,indent=4)

print("Analysis finished")
print("Behavior score:",score)
