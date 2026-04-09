import requests
import threading
import subprocess
import logging
from flask import Flask, render_template_string
from flask_socketio import SocketIO

from rich import print
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter

# ---------- CONFIG ----------
logging.getLogger('werkzeug').disabled = True

SCORE = 0
LEADERBOARD = {"You": 0}

session = PromptSession()

commands = [
    "scan",
    "recon",
    "suggest",
    "leaderboard",
    "chat",
    "help",
    "exit"
]
completer = WordCompleter(commands, ignore_case=True)

# ---------- FLASK ----------
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

HTML = """
<!DOCTYPE html>
<html>
<body style="background:black;color:#00ff9f;font-family:monospace">
<h1>🔥 Live Dashboard</h1>
<div id="log"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
<script>
var socket = io();
socket.on('update', function(data) {
    let d = document.getElementById("log");
    let p = document.createElement("p");
    p.innerText = data;
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

def ai(prompt):
    try:
        res = requests.post("http://localhost:11434/api/generate", json={
            "model": "llama3",
            "prompt": prompt,
            "stream": False
        })
        return res.json()["response"]
    except:
        return "[red]AI error[/red]"

# ---------- SAFE RECON ----------
def run_nmap(target):
    print(f"[green][+] Running safe recon on {target}[/green]")
    push(f"🔍 Recon started on {target}")

    try:
        result = subprocess.check_output(
            ["nmap", "-sV", "-Pn", target],
            stderr=subprocess.STDOUT,
            text=True
        )
        print("[cyan]" + result + "[/cyan]")
        push("Nmap scan completed")

        return result

    except Exception as e:
        err = f"[red]Error running nmap: {e}[/red]"
        print(err)
        push(err)
        return ""

# ---------- AI ANALYSIS ----------
def analyze_and_suggest(scan_output, target):
    print("[yellow][+] Analyzing results...[/yellow]")
    push("🧠 AI analyzing scan results")

    prompt = f"""
You are a cybersecurity assistant.

Target: {target}

Scan result:
{scan_output}

1. Summarize findings
2. Identify possible weak points (no exploitation)
3. Suggest safe next steps (tools, checks)
4. Keep it simple
"""

    response = ai(prompt)

    print(f"[blue][AI][/blue]\n{response}")
    push(response)

# ---------- WORKFLOW ----------
def safe_workflow(target):
    global SCORE

    scan = run_nmap(target)

    if not scan:
        return

    analyze_and_suggest(scan, target)

    SCORE += 10
    LEADERBOARD["You"] = SCORE
    push(f"🏆 Score: {SCORE}")

# ---------- CLI ----------
print("\n[bold green]🔥 KaliGPT SAFE RECON MODE[/bold green]")
print("[cyan]Dashboard → http://localhost:5000[/cyan]\n")

print("[yellow]Commands:[/yellow]")
print("scan <ip>        → basic recon")
print("recon <ip>       → recon + AI analysis")
print("suggest <text>   → ask next steps")
print("leaderboard")
print("chat")
print("help")
print("exit\n")

# ---------- LOOP ----------
while True:
    try:
        cmd = session.prompt("[bold green]>>> [/bold green]", completer=completer).strip()

        if cmd == "exit":
            print("[red]Exiting...[/red]")
            break

        elif cmd.startswith("scan"):
            parts = cmd.split()
            if len(parts) < 2:
                print("[red]Usage: scan <ip>[/red]")
                continue
            run_nmap(parts[1])

        elif cmd.startswith("recon"):
            parts = cmd.split()
            if len(parts) < 2:
                print("[red]Usage: recon <ip>[/red]")
                continue
            threading.Thread(target=safe_workflow, args=(parts[1],)).start()

        elif cmd.startswith("suggest"):
            query = cmd.replace("suggest", "").strip()
            print(ai(f"Suggest safe next pentest steps: {query}"))

        elif cmd == "leaderboard":
            print("\n[bold yellow]🏆 Leaderboard[/bold yellow]")
            for k, v in LEADERBOARD.items():
                print(f"[green]{k}[/green]: {v}")

        elif cmd == "chat":
            q = session.prompt("[blue]Ask → [/blue]")
            print(ai(q))

        elif cmd == "help":
            print("""
[cyan]Available Commands:[/cyan]

scan <ip>        → run nmap scan
recon <ip>       → scan + AI analysis
suggest <text>   → safe next steps
chat             → ask AI
exit             → quit
""")

        else:
            print(ai(cmd))

    except KeyboardInterrupt:
        continue
