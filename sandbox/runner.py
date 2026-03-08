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

# ==============================
# INPUT VALIDATION
# ==============================

if len(sys.argv) < 2:
    print("Usage: python runner.py <package>")
    sys.exit(1)

target_file = sys.argv[1]

if not os.path.exists(target_file):
    print("File not found:", target_file)
    sys.exit(1)

# ==============================
# HASH
# ==============================

def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

package_hash = file_hash(target_file)

# ==============================
# DATA STRUCTURES
# ==============================

spawned_processes = set()
network_connections = []
dns_queries = []
file_created = set()
file_written = set()
file_deleted = set()
sensitive_access = set()
commands_detected = set()
ioc_domains = set()
ioc_ips = set()

syscall_counter = defaultdict(int)
timeline = []

# ==============================
# HEURISTIC MALWARE FAMILIES
# ==============================

family_signatures = {
    "cryptominer": ["xmrig","miner","stratum"],
    "data_exfiltration": ["curl","wget","ftp","upload"],
    "reverse_shell": ["nc","netcat","bash -i","sh -i"],
    "credential_stealer": ["/etc/passwd","/etc/shadow",".ssh"],
}

# ==============================
# THREAT INTEL
# ==============================

def enrich_ip(ip):

    try:
        url = f"http://ip-api.com/json/{ip}"
        r = urllib.request.urlopen(url, timeout=3)
        data = json.loads(r.read().decode())

        return {
            "ip": ip,
            "country": data.get("country"),
            "asn": data.get("as"),
            "org": data.get("org")
        }

    except:
        return {"ip": ip}

# ==============================
# EXTRACT PACKAGE
# ==============================

sandbox_dir = "sandbox_env"
os.makedirs(sandbox_dir, exist_ok=True)

extract_dir = os.path.join(sandbox_dir,"package")

if os.path.exists(extract_dir):
    subprocess.run(["rm","-rf",extract_dir])

os.makedirs(extract_dir)

with tarfile.open(target_file,"r:*") as tar:
    tar.extractall(extract_dir)

# ==============================
# DETECT PACKAGE TYPE
# ==============================

is_npm=False
is_python=False

for root,dirs,files in os.walk(extract_dir):

    if "package.json" in files:
        is_npm=True

    if "setup.py" in files or "pyproject.toml" in files:
        is_python=True

# ==============================
# COMMAND
# ==============================

if is_npm:
    cmd=["npm","install","--ignore-scripts=false"]

elif is_python:
    cmd=["pip","install","."]

else:
    cmd=["python",target_file]

# ==============================
# STRACE
# ==============================

start=time.time()

process=subprocess.Popen(

[
"strace",
"-ff",
"-tt",
"-e",
"trace=execve,clone,fork,vfork,open,openat,write,connect,sendto,recvfrom,unlink"
]+cmd,

cwd=extract_dir,
stdout=subprocess.PIPE,
stderr=subprocess.PIPE,
text=True
)

try:
    stdout,stderr=process.communicate(timeout=40)
except:
    process.kill()
    stdout,stderr=process.communicate()

runtime=round(time.time()-start,3)

# ==============================
# PARSE STRACE
# ==============================

for line in stderr.split("\n"):

    line=line.strip()
    if not line:
        continue

    match=re.match(r".*? ([a-zA-Z_]+)\(",line)

    if not match:
        continue

    syscall=match.group(1)
    syscall_counter[syscall]+=1

    timeline.append({
        "timestamp":datetime.utcnow().isoformat(),
        "event":syscall,
        "detail":line
    })

    # ==========================
    # PROCESS
    # ==========================

    if "execve(" in line:

        p=re.search(r'execve\("([^"]+)"',line)

        if p:

            proc=os.path.basename(p.group(1))
            spawned_processes.add(proc)
            commands_detected.add(proc)

    # ==========================
    # CONNECT
    # ==========================

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

            ioc_ips.add(ip)

    # ==========================
    # DNS via sendto
    # ==========================

    if "sendto(" in line:

        network_connections.append({
            "ip":"unknown",
            "port":"dns"
        })

        dns_queries.append("dns_request")

    # ==========================
    # FILE
    # ==========================

    if "open(" in line or "openat(" in line:

        m=re.search(r'"([^"]+)"',line)

        if m:

            f=m.group(1)

            if "O_CREAT" in line:
                file_created.add(f)

            if "O_WRONLY" in line or "O_RDWR" in line:
                file_written.add(f)

            if "/etc/passwd" in f or ".ssh" in f:
                sensitive_access.add(f)

# ==============================
# MALWARE FAMILY DETECTION
# ==============================

detected_family="unknown"

all_text=" ".join(commands_detected)+" ".join(sensitive_access)

for fam,patterns in family_signatures.items():

    for p in patterns:

        if p in all_text:
            detected_family=fam

# ==============================
# BEHAVIOR SCORE
# ==============================

score=0

score+=len(network_connections)*2
score+=len(commands_detected)
score+=len(sensitive_access)*2

# ==============================
# ATTACK GRAPH
# ==============================

attack_graph={

"nodes":[
{"id":"package","label":"Package"},
{"id":"process","label":"Process"},
{"id":"network","label":"Network"},
{"id":"filesystem","label":"Filesystem"}
],

"edges":[
{"from":"package","to":"process"},
{"from":"process","to":"filesystem"},
{"from":"process","to":"network"}
]

}

# ==============================
# SAVE LOG
# ==============================

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
"details":network_connections
},

"dns_activity":dns_queries,

"filesystem_activity":{
"files_created":list(file_created),
"files_written":list(file_written),
"files_deleted":list(file_deleted)
},

"sensitive_access":list(sensitive_access),

"commands_detected":list(commands_detected),

"ioc":{
"ips":list(ioc_ips),
"domains":list(ioc_domains)
},

"malware_family":detected_family,

"syscall_stats":dict(syscall_counter),

"behavior_score":score,

"attack_graph":attack_graph,

"timeline":timeline[:50],

"timestamp":datetime.utcnow().isoformat()

}

with open(f"decoy_logs/log_{run_id}.json","w") as f:
    json.dump(log,f,indent=4)

with open("decoy_logs/latest.json","w") as f:
    json.dump(log,f,indent=4)

print("Analysis finished")
print("Behavior score:",score)
