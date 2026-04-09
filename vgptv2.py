import os, json, requests, threading, subprocess, logging
from datetime import datetime
from flask import Flask, render_template_string
from flask_socketio import SocketIO
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.completion import WordCompleter
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint
import re
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
try:
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
try:
    from openvas_lib import VulnscanManager, VulnscanException
    OPENVAS_AVAILABLE = True
except ImportError:
    OPENVAS_AVAILABLE = False

# ---------- CONFIG ----------
logging.getLogger('werkzeug').disabled = True
console = Console()

session = PromptSession(history=InMemoryHistory())

RUN_DIR = "strix_runs"
os.makedirs(RUN_DIR, exist_ok=True)

MEMORY_FILE = f"{RUN_DIR}/memory.json"
GRAPH_FILE = f"{RUN_DIR}/graph.json"
LOG_FILE = f"{RUN_DIR}/logs.json"
AI_CACHE_FILE = f"{RUN_DIR}/ai_cache.json"
PLUGIN_DIR = f"{RUN_DIR}/plugins"
os.makedirs(PLUGIN_DIR, exist_ok=True)

CACHE = {}
TARGET_DATA = {}
MEMORY = {"history": [], "notes": {}}
GRAPH = {"nodes": [], "edges": []}
LOGS = []
AI_CACHE = {}
PLUGINS = {}
OFFLINE_MODE = False
TARGET_QUEUE = []
SESSION_DATA = {"shared_sessions": []}

# ---------- LOAD ----------
if os.path.exists(MEMORY_FILE):
    MEMORY = json.load(open(MEMORY_FILE))

if os.path.exists(GRAPH_FILE):
    GRAPH = json.load(open(GRAPH_FILE))

if os.path.exists(AI_CACHE_FILE):
    AI_CACHE = json.load(open(AI_CACHE_FILE))

# ---------- FLASK ----------
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

HTML = """
<html>
<body style="background:#0d1117;color:#00ff9f;font-family:monospace">
<h1>🔥 Target Intelligence Dashboard</h1>
<div id="targets"></div>
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
socket.on('target_update', function(data){
 let t=document.getElementById("targets");
 t.innerHTML = data;
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
def push(msg, color="white"):
    socketio.emit("update", msg)
    LOGS.append({"time": str(datetime.now()), "msg": msg, "color": color})
    json.dump(LOGS, open(LOG_FILE, "w"), indent=2)
    styled_msg = Text(msg, style=color)
    console.print(styled_msg)

def update_dashboard():
    html = "<h2>Active Targets</h2><ul>"
    for target, data in TARGET_DATA.items():
        html += f"<li><strong>{target}</strong> - Severity: {data.get('severity', 'Unknown')}</li>"
    html += "</ul>"
    socketio.emit("target_update", html)

def ai(prompt):
    if prompt in AI_CACHE and OFFLINE_MODE:
        return AI_CACHE[prompt]
    try:
        r = requests.post("http://localhost:11434/api/generate", json={
            "model": "llama3",
            "prompt": prompt,
            "stream": False
        })
        response = r.json()["response"]
        AI_CACHE[prompt] = response
        json.dump(AI_CACHE, open(AI_CACHE_FILE, "w"), indent=2)
        return response
    except:
        if prompt in AI_CACHE:
            return AI_CACHE[prompt]
        return "AI error"

def parse_command(cmd):
    # Use AI to parse natural language commands
    prompt = f"""
Parse this user input into a command for the pentest tool.

Input: {cmd}

Available commands:
- scan <target>
- multi <target1> <target2> ...
- auto <target>
- goal <target>
- memory
- replay
- fast_scan <target>
- detailed_scan <target>
- manual <command>
- view_report <target>
- exit

Respond with the parsed command or 'unknown' if unclear.
"""
    parsed = ai(prompt).strip()
    if parsed.startswith("scan") or parsed.startswith("multi") or etc.:
        return parsed
    return cmd  # fallback

# ---------- AGENTS ----------

def recon(target):
    if target in CACHE:
        return CACHE[target]
    try:
        push(f"Executing: nmap -sV -Pn {target}", "blue")
        result = subprocess.check_output(["nmap", "-sV", "-Pn", target], text=True)
        CACHE[target] = result
        return result
    except Exception as e:
        push(f"Recon failed: {e}", "red")
        return ""

def http_agent(target):
    try:
        push(f"Executing: HTTP check on {target}", "blue")
        r = requests.get(f"http://{target}", timeout=3)
        return f"{r.status_code} {r.headers.get('Server','Unknown')}"
    except:
        return "No HTTP"

def osint(target):
    try:
        push(f"Executing: OSINT on {target}", "blue")
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

# ---------- NEW FEATURES ----------

def vuln_scan(target, services):
    push(f"Vulnerability scan for {target}", "blue")
    vulns = []
    for service in services:
        if "apache" in service.lower():
            vulns.append("Potential Apache vuln: Check for CVE-2021-41773")
        if "ssh" in service.lower():
            vulns.append("SSH: Ensure no weak keys")
    # OpenVAS integration
    if OPENVAS_AVAILABLE:
        try:
            scanner = VulnscanManager("localhost", "admin", "admin")
            scan_id = scanner.launch_scan(target, profile="Full and fast")
            vulns.extend(scanner.get_results(scan_id))
        except:
            pass
    return vulns

def exploit_sim(target, vulns):
    push(f"Simulating exploits for {target}", "blue")
    sims = []
    for vuln in vulns:
        if "apache" in vuln:
            sims.append("Simulated: Path traversal exploit")
    return sims

def multi_target_campaign(targets):
    for target in targets:
        threading.Thread(target=orchestrator, args=(target,)).start()

def generate_pdf_report(target):
    if not REPORTLAB_AVAILABLE:
        push("ReportLab not available for PDF", "red")
        return
    d = TARGET_DATA.get(target, {})
    filename = f"{RUN_DIR}/report_{target}.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    c.drawString(100, 750, f"Report for {target}")
    c.drawString(100, 730, f"Ports: {d.get('ports')}")
    c.drawString(100, 710, f"Services: {d.get('services')}")
    c.save()
    # Plotly chart
    if PLOTLY_AVAILABLE:
        ports = len(d.get('ports', []))
        vulns = len(d.get('vulns', []))
        fig = go.Figure(data=[go.Bar(x=['Ports', 'Vulns'], y=[ports, vulns])])
        fig.write_image(f"{RUN_DIR}/chart_{target}.png")
        push(f"Chart saved: {RUN_DIR}/chart_{target}.png", "green")
    push(f"PDF report saved: {filename}", "green")

def ai_recommendations(target):
    prompt = f"Advanced recommendations for {target}: {TARGET_DATA.get(target, {})}"
    return ai(prompt)

def load_plugins():
    for file in os.listdir(PLUGIN_DIR):
        if file.endswith(".py"):
            # Simple plugin loader
            try:
                exec(open(f"{PLUGIN_DIR}/{file}").read(), globals())
                push(f"Loaded plugin: {file}", "green")
            except Exception as e:
                push(f"Failed to load plugin {file}: {e}", "red")

def anomaly_detection(logs):
    if not SKLEARN_AVAILABLE:
        return []
    # Simple ML for anomaly
    data = [[len(log)] for log in logs[-100:]]
    if len(data) < 10:
        return []
    model = IsolationForest(contamination=0.1)
    model.fit(data)
    preds = model.predict(data)
    anomalies = [logs[i] for i, p in enumerate(preds) if p == -1]
    # Add AI analysis of anomalies
    for anomaly in anomalies:
        analysis = ai(f"Analyze this log anomaly: {anomaly}")
        push(f"Anomaly analysis: {analysis[:100]}", "yellow")
    return anomalies

def compliance_check(target, findings):
    checks = []
    if "http" in findings:
        checks.append("OWASP: Check for XSS/CSRF")
        checks.append("PCI: Ensure HTTPS")
        checks.append("GDPR: Data protection compliance")
    if "ssh" in findings:
        checks.append("NIST: Use strong ciphers")
        checks.append("HIPAA: Secure access")
    return checks

def run_workflow(workflow_name, target):
    workflows = {
        "full_recon": ["scan", "http", "osint", "analyze", "vuln_scan", "report"],
        "quick_check": ["scan", "analyze"],
        "compliance_audit": ["scan", "compliance", "report"]
    }
    if workflow_name in workflows:
        for action in workflows[workflow_name]:
            result = execute_action(action, target)
            push(f"Workflow {workflow_name}: {action} -> {str(result)[:50]}", "cyan")
    else:
        push("Unknown workflow", "red")

def share_session(target):
    session = TARGET_DATA.get(target, {})
    SESSION_DATA["shared_sessions"].append(session)
    json.dump(SESSION_DATA, open(f"{RUN_DIR}/sessions.json", "w"), indent=2)
    push(f"Session for {target} shared", "green")

def multi_target_campaign(targets):
    TARGET_QUEUE.extend(targets)
    for target in TARGET_QUEUE:
        threading.Thread(target=orchestrator, args=(target,)).start()
    TARGET_QUEUE.clear()

def toggle_offline():
    global OFFLINE_MODE
    OFFLINE_MODE = not OFFLINE_MODE
    push(f"Offline mode: {OFFLINE_MODE}", "yellow")

# ---------- MODES ----------

def fast_scan(target):
    push(f"[FAST SCAN START] {target}", "green")
    scan = recon(target)
    if not scan:
        return
    ports, services = parse_nmap(scan)
    TARGET_DATA[target] = {
        "ports": ports,
        "services": services,
        "raw": scan
    }
    push(f"{target} → {len(ports)} ports", "green")
    update_dashboard()

def detailed_scan(target):
    orchestrator(target)

def manual_mode(command):
    try:
        push(f"Executing manual: {command}", "blue")
        result = subprocess.check_output(command, shell=True, text=True)
        push(result, "white")
    except Exception as e:
        push(f"Manual command failed: {e}", "red")

def view_report(target):
    if target in TARGET_DATA:
        d = TARGET_DATA[target]
        table = Table(title=f"Report for {target}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="magenta")
        for k, v in d.items():
            table.add_row(k, str(v)[:100])
        console.print(table)
    else:
        push(f"No report for {target}", "red")

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
            "raw": scan[0],
            "vulns": vuln_scan(target, services),
            "exploit_sims": exploit_sim(target, TARGET_DATA[target].get("vulns", [])),
            "compliance": compliance_check(target, services)
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
    update_dashboard()

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
    html += "<h2>Vulnerabilities</h2>" + str(d.get("vulns"))
    html += "<h2>Exploit Simulations</h2>" + str(d.get("exploit_sims"))
    html += "<h2>Compliance</h2>" + str(d.get("compliance"))
    html += "<h2>Raw</h2><pre>"+str(d.get("raw"))+"</pre>"

    html += "</body></html>"

    open(f"{RUN_DIR}/report_{target}.html","w").write(html)
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
scan, http, osint, analyze, vuln_scan, exploit_sim, compliance, report, stop

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
    elif action == "vuln_scan":
        services = TARGET_DATA.get(target, {}).get("services", [])
        return vuln_scan(target, services)
    elif action == "exploit_sim":
        vulns = TARGET_DATA.get(target, {}).get("vulns", [])
        return exploit_sim(target, vulns)
    elif action == "compliance":
        findings = TARGET_DATA.get(target, {}).get("services", [])
        return compliance_check(target, findings)
    elif action == "report":
        generate_report(target)
        generate_pdf_report(target)
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

# ---------- WELCOME INTERFACE ----------
def show_welcome():
    console.clear()
    panel = Panel.fit(
        "[bold green]Welcome to VGPT[/bold green]\n\n"
        "Select a mode:\n"
        "1. Auto Mode\n"
        "2. Fast Scan\n"
        "3. Detailed Scan\n"
        "4. Manual Mode\n"
        "5. Report Viewer\n"
        "6. Multi-Target Campaign\n"
        "7. Anomaly Detection\n"
        "8. Toggle Offline Mode\n"
        "9. Load Plugins\n"
        "10. AI Recommendations\n"
        "11. Team Chat\n"
        "12. Run Workflow\n"
        "13. Share Session\n"
        "14. Exit\n\n"
        "[cyan]Dashboard: http://localhost:5000[/cyan]",
        title="🔥 VGPT Pentest Tool",
        border_style="green"
    )
    console.print(panel)

def get_mode_choice():
    while True:
        try:
            choice = int(session.prompt("Enter mode number: ").strip())
            if 1 <= choice <= 14:
                return choice
            else:
                console.print("[red]Invalid choice. Try again.[/red]")
        except ValueError:
            console.print("[red]Please enter a number.[/red]")

# ---------- CLI ----------
def main_cli():
    show_welcome()
    load_plugins()
    while True:
        choice = get_mode_choice()
        if choice == 14:
            break
        elif choice == 1:
            target = session.prompt("Enter target for Auto Mode: ").strip()
            threading.Thread(target=autonomous_mode, args=(target,)).start()
        elif choice == 2:
            target = session.prompt("Enter target for Fast Scan: ").strip()
            threading.Thread(target=fast_scan, args=(target,)).start()
        elif choice == 3:
            target = session.prompt("Enter target for Detailed Scan: ").strip()
            threading.Thread(target=orchestrator, args=(target,)).start()
        elif choice == 4:
            cmd = session.prompt("Enter manual command: ").strip()
            manual_mode(cmd)
        elif choice == 5:
            target = session.prompt("Enter target to view report: ").strip()
            view_report(target)
        elif choice == 6:
            targets = session.prompt("Enter targets (space-separated): ").strip().split()
            multi_target_campaign(targets)
        elif choice == 7:
            anomalies = anomaly_detection([log["msg"] for log in LOGS])
            console.print(f"Anomalies: {anomalies}")
        elif choice == 8:
            toggle_offline()
        elif choice == 9:
            load_plugins()
            push("Plugins reloaded", "green")
        elif choice == 10:
            target = session.prompt("Enter target for AI Recommendations: ").strip()
            recs = ai_recommendations(target)
            push(recs, "blue")
        elif choice == 11:
            msg = session.prompt("Team message: ").strip()
            push(f"[TEAM] {msg}", "magenta")
        elif choice == 12:
            workflow = session.prompt("Workflow name (full_recon, quick_check, compliance_audit): ").strip()
            target = session.prompt("Target: ").strip()
            run_workflow(workflow, target)
        elif choice == 13:
            target = session.prompt("Target to share: ").strip()
            share_session(target)

if __name__ == "__main__":
    main_cli()</content>
<parameter name="filePath">/workspaces/vgpt-playground/vgptv2.py
