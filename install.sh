#!/bin/bash

echo "🔧 [1/4] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is not installed. Please install Python3 first."
    exit 1
fi

echo "🔧 [2/4] Checking for pip..."
if ! command -v pip3 &> /dev/null; then
    echo "⚠️ pip3 not found. Installing pip..."
    sudo apt update
    sudo apt install -y python3-pip
else
    echo "✅ pip3 is already installed."
fi

echo "🔧 [3/4] Installing required Python packages..."
REQUIRED_PACKAGES=("rich")
for package in "${REQUIRED_PACKAGES[@]}"; do
    pip3 install --upgrade "$package"
done

echo "🔧 [4/4] Verifying journalctl command..."
if ! command -v journalctl &> /dev/null; then
    echo "❌ journalctl not found. This script requires a systemd-based Linux system."
    exit 1
fi

echo "✅ Installation completed successfully."
echo "👉 You can now run the tool with: python3 log_analyzer.py"
