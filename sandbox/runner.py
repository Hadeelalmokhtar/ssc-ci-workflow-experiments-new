import sys
import os
import json
import subprocess
import time
import math
import ast
import re
from datetime import datetime

# ==============================
# Validate Input
# ==============================
if len(sys.argv) < 2:
    print("Usage: python runner.py <file_path>")
    sys.exit(1)

file_path = sys.argv[1]

if not os.path.exists(file_path):
    print("File not found:", file_path)
    sys.exit(1)

# ==============================
# 1️ Entropy Calculation
# ==============================
def calculate_entropy(data):
    if not data:
        return 0
    prob = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum(p * math.log2(p) for p in prob)

with open(file_path, "r", errors="ignore") as f:
    content = f.read()

file_entropy = round(calculate_entropy(content), 4)

# ==============================
# 2️ AST Analysis
# ==============================
suspicious_imports = []
command_injection = []
obfuscation_flags = []

danger_modules = ["os", "subprocess", "socket", "requests"]
danger_functions = ["system", "popen", "exec", "eval"]

tree = ast.parse(content)

for node in ast.walk(tree):

    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name.split(".")[0] in danger_modules:
                suspicious_imports.append(alias.name)

    if isinstance(node, ast.ImportFrom):
        if node.module and node.module.split(".")[0] in danger_modules:
            suspicious_imports.append(node.module)

    if isinstance(node, ast.Call):
        if hasattr(node.func, "attr"):
            if node.func.attr in danger_functions:
                command_injection.append(node.func.attr)

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if "base64" in node.value.lower():
            obfuscation_flags.append("base64 usage")
        if re.search(r'\\x[0-9a-fA-F]{2}', node.value):
            obfuscation_flags.append("hex encoded string")

# ==============================
# 3️ Strace Execution
# ==============================
print("Starting dynamic execution...")

start_time = time.time()

try:
    process = subprocess.Popen(
        ["strace", "-f", "-e", "trace=execve,open,connect,fork",
         "python", file_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    stdout, stderr = process.communicate(timeout=10)

except Exception as e:
    print("Strace failed:", e)
    stderr = ""
    process = subprocess.CompletedProcess([], 0)

execution_time = round(time.time() - start_time, 3)

syscalls_detected = []
for line in stderr.split("\n"):
    if any(x in line for x in ["execve", "connect", "open", "fork"]):
        syscalls_detected.append(line.strip())

# ==============================
# 4️ Behavior Scoring
# ==============================
behavior_score = 0

if file_entropy > 4.5:
    behavior_score += 2

if suspicious_imports:
    behavior_score += 2

if command_injection:
    behavior_score += 3

if obfuscation_flags:
    behavior_score += 2

if len(syscalls_detected) > 3:
    behavior_score += 2

# ==============================
# 5️ MITRE Mapping
# ==============================
mitre_techniques = []

if command_injection:
    mitre_techniques.append("T1059 - Command and Scripting Interpreter")

if obfuscation_flags:
    mitre_techniques.append("T1027 - Obfuscated Files or Information")

if suspicious_imports:
    mitre_techniques.append("T1204 - User Execution")

if len(syscalls_detected) > 3:
    mitre_techniques.append("T1055 - Process Injection")

# ==============================
# 6️ Multi-Log Architecture
# ==============================
os.makedirs("decoy_logs", exist_ok=True)

run_id = os.getenv("GITHUB_RUN_NUMBER", str(int(time.time())))

dynamic_log = {
    "run_id": run_id,
    "package": file_path,
    "file_entropy": file_entropy,
    "execution_time": execution_time,
    "suspicious_imports": suspicious_imports,
    "command_injection_calls": command_injection,
    "obfuscation_flags": obfuscation_flags,
    "system_calls_detected": syscalls_detected[:20],
    "behavior_score": behavior_score,
    "mitre_techniques": mitre_techniques,
    "timestamp": datetime.utcnow().isoformat()
}

# Unique log
with open(f"decoy_logs/log_{run_id}.json", "w") as f:
    json.dump(dynamic_log, f, indent=4)

# Update latest.json
with open("decoy_logs/latest.json", "w") as f:
    json.dump(dynamic_log, f, indent=4)

# Update history.json
history_path = "decoy_logs/history.json"

if os.path.exists(history_path):
    with open(history_path, "r") as f:
        history = json.load(f)
else:
    history = []

history.append(dynamic_log)

with open(history_path, "w") as f:
    json.dump(history[-50:], f, indent=4)

print("Dynamic multi-log updated successfully.")
print("Behavior Score:", behavior_score)

sys.exit(0)
