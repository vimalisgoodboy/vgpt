import os, json, requests, threading, subprocess, logging
from datetime import datetime
from flask import Flask, render_template_string
from flask_socketio import SocketIO
from prompt_toolkit import PromptSession
from rich import print

# ---------- CONFIG ----------
logging.getLogger('werkzeug').disabled = True
session = PromptSession()

RUN_DIR = "strix_runs"
os.makedirs(RUN_DIR, exist_ok=True)

MEMORY_FILE = f"{RUN_DIR}/memory.json"
GRAPH_FILE = f"{RUN_DIR}/graph.json"
LOG_FILE = f"{RUN_DIR}/logs.json"

CACHE = {}
TARGET_DATA = {}
MEMORY = {"history": [], "notes": {}}
GRAPH = {"nodes": [], "edges": []}
LOGS = []

# ---------- LOAD ----------
if os.path.exists(MEMORY_FILE):
    MEMORY = json.load(open(MEMORY_FILE))

if os.path.exists(GRAPH_FILE):
    GRAPH = json.load(open(GRAPH_FILE))

# ---------- FLASK ----------
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

HTML = """
<html>
<body style="background:#0d1117;color:#00ff9f;font-family:monospace">
<h1>🔥 Target Intelligence</h1>
<div id="log"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
<script>
var socket = io();
socket.on('update', function(data){
 let d=document.getElementById("log");
 let p=document.createElement("p");
 p.innerText=data;
 d.prepend(p);
});
</script>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(HTML)

def run_server():
    socketio.run(app, port=5000)

threading.Thread(target=run_server, daemon=True).start()

# ---------- HELPERS ----------
def push(msg):
    socketio.emit("update", msg)
    LOGS.append({"time": str(datetime.now()), "msg": msg})
    json.dump(LOGS, open(LOG_FILE, "w"), indent=2)

def ai(prompt):
    try:
        r = requests.post("http://localhost:11434/api/generate", json={
            "model": "llama3",
            "prompt": prompt,
            "stream": False
        })
        return r.json()["response"]
    except:
        return "AI error"

# ---------- AGENTS ----------

def recon(target):
    if target in CACHE:
        return CACHE[target]
    try:
        result = subprocess.check_output(["nmap", "-sV", "-Pn", target], text=True)
        CACHE[target] = result
        return result
    except:
        return ""

def http_agent(target):
    try:
        r = requests.get(f"http://{target}", timeout=3)
        return f"{r.status_code} {r.headers.get('Server','Unknown')}"
    except:
        return "No HTTP"

def osint(target):
    try:
        return requests.get(f"http://ip-api.com/json/{target}").json()
    except:
        return {}

def parse_nmap(out):
    ports, services = [], []
    for l in out.split("\n"):
        if "/tcp" in l and "open" in l:
            p = l.split()
            ports.append(p[0])
            services.append(" ".join(p[2:]))
    return ports, services

def classify(text):
    t = text.lower()
    if "critical" in t or "exploit" in t:
        return "HIGH"
    if "warning" in t:
        return "MEDIUM"
    return "LOW"

# ---------- ORCHESTRATOR ----------
def orchestrator(target):
    push(f"[START] {target}")

    for step in range(2):
        push(f"[LOOP] iteration {step+1}")

        scan = [None]
        http = [None]
        intel = [None]

        def t1(): scan[0] = recon(target)
        def t2(): http[0] = http_agent(target)
        def t3(): intel[0] = osint(target)

        threads = [threading.Thread(target=t) for t in [t1,t2,t3]]
        [t.start() for t in threads]
        [t.join() for t in threads]

        if not scan[0]:
            push("Scan failed")
            return

        ports, services = parse_nmap(scan[0])

        analysis = ai(f"Analyze services: {services}")
        severity = classify(analysis)

        TARGET_DATA[target] = {
            "ports": ports,
            "services": services,
            "http": http[0],
            "osint": intel[0],
            "analysis": analysis,
            "severity": severity,
            "raw": scan[0]
        }

        MEMORY["history"].append(target)
        MEMORY["notes"][target] = services

        GRAPH["nodes"].append(target)
        for p in ports:
            GRAPH["edges"].append([target, p])

        json.dump(MEMORY, open(MEMORY_FILE,"w"),indent=2)
        json.dump(GRAPH, open(GRAPH_FILE,"w"),indent=2)

        push(f"{target} → {len(ports)} ports → {severity}")

    generate_report(target)

# ---------- REPORT ----------
def generate_report(target):
    d = TARGET_DATA.get(target, {})

    html = "<html><body style='background:black;color:#00ff9f'>"
    html += f"<h1>{target}</h1>"

    html += "<h2>Ports</h2>" + str(d.get("ports"))
    html += "<h2>Services</h2>" + str(d.get("services"))
    html += f"<h2>HTTP</h2>{d.get('http')}"
    html += "<h2>OSINT</h2><pre>"+json.dumps(d.get("osint"),indent=2)+"</pre>"
    html += f"<h2>Severity</h2>{d.get('severity')}"
    html += "<h2>Raw</h2><pre>"+str(d.get("raw"))+"</pre>"

    html += "</body></html>"

    open("report.html","w").write(html)
    push("Report updated")

# ---------- AUTONOMOUS MODE ----------

def planner(goal, context):
    prompt = f"""
You are an autonomous penetration testing planner.

Goal:
{goal}

Context:
{context}

Decide next action from:
scan, http, osint, analyze, report, stop

Respond ONLY JSON:
{{"action":"...","reason":"..."}}
"""
    try:
        return json.loads(ai(prompt))
    except:
        return {"action":"stop","reason":"error"}

def execute_action(action, target):
    if action == "scan":
        return recon(target)
    elif action == "http":
        return http_agent(target)
    elif action == "osint":
        return osint(target)
    elif action == "analyze":
        return ai(str(TARGET_DATA.get(target, {})))
    elif action == "report":
        generate_report(target)
        return "report done"
    return ""

def autonomous_mode(target):
    push(f"[AUTO START] {target}")

    goal = f"Find weaknesses in {target}"
    context = {}

    for step in range(6):
        plan = planner(goal, context)
        action = plan.get("action")

        push(f"[AUTO] {action} → {plan.get('reason')}")

        if action == "stop":
            break

        result = execute_action(action, target)
        context[action] = str(result)[:1000]

        MEMORY["notes"][target] = context
        json.dump(MEMORY, open(MEMORY_FILE,"w"), indent=2)

    generate_report(target)
    push("[AUTO DONE]")

# ---------- CLI ----------
print("\n🔥 AI Pentest Command Center")
print("Dashboard → http://localhost:5000\n")

while True:
    cmd = session.prompt(">>> ").strip()

    if cmd == "exit":
        break

    elif cmd.startswith("scan"):
        threading.Thread(target=orchestrator, args=(cmd.split()[1],)).start()

    elif cmd.startswith("multi"):
        for t in cmd.split()[1:]:
            threading.Thread(target=orchestrator, args=(t,)).start()

    elif cmd == "auto":
        orchestrator("127.0.0.1")

    elif cmd.startswith("goal"):
        threading.Thread(target=autonomous_mode, args=(cmd.split()[1],)).start()

    elif cmd == "memory":
        print(json.dumps(MEMORY, indent=2))

    elif cmd == "replay":
        print(json.dumps(LOGS, indent=2))

    else:
        print(ai(cmd))
