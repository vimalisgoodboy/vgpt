#!/bin/bash

echo "🔥 VGPT Ultimate Edition - Full Setup for Kali Linux 🔥"

# ---------- COLORS ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }

# ---------- CHECK ROOT ----------
if [[ $EUID -eq 0 ]]; then
    warning "Don't run as root. Using sudo where needed..."
fi

# ---------- UPDATE SYSTEM ----------
info "Updating system..."
sudo apt update -y && sudo apt upgrade -y

# ---------- CORE DEPENDENCIES ----------
info "Installing core dependencies..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    curl \
    wget \
    build-essential \
    libssl-dev \
    libffi-dev

# ---------- SECURITY & PENTEST TOOLS ----------
info "Installing pentest tools..."
sudo apt install -y \
    nmap \
    masscan \
    nikto \
    dirb \
    gobuster \
    sqlmap \
    whatweb \
    wpscan \
    netcat-traditional \
    socat \
    dnsutils \
    whois

# ---------- CREATE & ACTIVATE VIRTUALENV ----------
info "Setting up Python virtual environment..."
rm -rf venv
python3 -m venv venv
source venv/bin/activate

# ---------- UPGRADE PIP ----------
pip install --upgrade pip setuptools wheel

# ---------- INSTALL PYTHON DEPENDENCIES ----------
info "Installing Python packages..."
pip install \
    flask==2.3.3 \
    flask-socketio==5.3.6 \
    requests==2.31.0 \
    rich==13.7.1 \
    python-nmap==0.7.1 \
    reportlab==4.0.9 \
    PyPDF2==3.0.1 \
    ollama==0.1.7 \
    pyyaml==6.0.1 \
    sqlite3 \
    pathlib

# ---------- FIX NMAP ISSUE (CRITICAL) ----------
info "Fixing python-nmap permissions..."
sudo chown -R $USER:$USER /usr/share/nmap/
sudo chmod -R 755 /usr/share/nmap/

# ---------- OLLAMA INSTALLATION ----------
info "Installing Ollama AI..."
if ! command -v ollama &> /dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
    success "Ollama installed"
else
    info "Ollama already installed"
fi

# ---------- START OLLAMA SERVICE ----------
info "Starting Ollama service..."
ollama serve > /dev/null 2&1 &
sleep 8

# ---------- DOWNLOAD LLAMA3 MODEL ----------
info "Downloading Llama3 model (2GB - this takes ~5-10 min)..."
if ! ollama list | grep -q llama3; then
    ollama pull llama3:8b
    success "Llama3 model downloaded"
else
    info "Llama3 model already available"
fi

# ---------- CREATE DIRECTORIES ----------
mkdir -p history reports payloads

# ---------- TEST DEPENDENCIES ----------
info "Testing installation..."
python3 -c "import nmap, flask, rich, ollama; print('✅ All Python modules OK')" || error "Python modules failed"
nmap --version | head -1 && success "Nmap OK" || error "Nmap failed"
ollama list | grep llama3 && success "AI model ready" || warning "AI model not ready"

# ---------- CREATE LAUNCH SCRIPT ----------
cat > launch.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
echo "🚀 Starting VGPT Ultimate..."
python vgpt.py --dashboard
EOF
chmod +x launch.sh

# ---------- FINAL CHECKS ----------
success "✅ SETUP COMPLETE!"
echo ""
echo "🎯 LAUNCH OPTIONS:"
echo "   ./launch.sh                    # Web Dashboard (recommended)"
echo "   python vgpt.py                 # Interactive CLI"
echo "   python vgpt.py --target 10.0.0.1 --mode 18  # Quick scan"
echo ""
echo "📁 Files created:"
echo "   • venv/                 # Python environment"
echo "   • vgpt.py               # Main application"
echo "   • dashboard.html        # Web UI"
echo "   • launch.sh             # Easy launcher"
echo "   • vgpt_findings.db      # Findings database"
echo ""
warning "💡 TIP: Keep 'venv/bin/activate' sourced in new terminals"
echo ""
read -p "Launch dashboard now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ./launch.sh
fi
