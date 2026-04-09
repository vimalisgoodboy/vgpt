#!/bin/bash

echo "🔥 Starting Full KaliGPT Setup..."

# ---------- UPDATE ----------
sudo apt update -y

# ---------- BASIC TOOLS ----------
sudo apt install -y python3 python3-venv python3-pip git curl

# ---------- SECURITY TOOLS ----------
sudo apt install -y nmap nikto

# ---------- FIX PYTHON (KALI ISSUE) ----------
python3 -m venv venv
source venv/bin/activate

# ---------- INSTALL PYTHON LIBS ----------
pip install --upgrade pip

pip install flask flask-socketio requests rich prompt_toolkit reportlab scikit-learn plotly openvas_lib

# ---------- INSTALL OLLAMA ----------
echo "🔥 Installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh

# ---------- START OLLAMA ----------
ollama serve > /dev/null 2>&1 &

sleep 5

# ---------- DOWNLOAD MODEL ----------
echo "🔥 Downloading AI model..."
ollama pull llama3

# ---------- DONE ----------
echo ""
echo "✅ INSTALLATION COMPLETE"
echo ""
echo "Starting VGPT..."
python vgptv2.py
