#!/bin/bash
set -e

echo "[*] Installing Kali dependencies..."
sudo apt update
sudo apt install -y python3-pip python3-venv python3-dev \
    nmap gobuster curl dnsutils dirb wordlists build-essential

echo "[*] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Installing Python dependencies..."
pip install --upgrade pip wheel setuptools
pip install -r requirements.txt

echo "[*] Setting Nmap capabilities..."
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(readlink -f $(which python3)) || true

echo "[*] Creating smartvapt alias..."
SMARTVAPT_DIR="$(pwd)"
ALIAS_LINE="alias smartvapt='cd $SMARTVAPT_DIR && source venv/bin/activate && streamlit run main.py'"
if ! grep -q "alias smartvapt=" ~/.bashrc; then
    echo "$ALIAS_LINE" >> ~/.bashrc
    echo "[+] Alias added"
fi

echo ""
echo "SmartVAPT installed."
echo "Run: source ~/.bashrc && smartvapt"
