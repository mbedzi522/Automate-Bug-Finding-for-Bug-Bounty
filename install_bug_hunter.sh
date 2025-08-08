#!/bin/bash

# Bug Hunter Tool Installation Script
# Version 1.0.0

set -e

echo "🔍 Bug Hunter Tool Installation Script"
echo "======================================"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "⚠️  This script should not be run as root for security reasons."
   echo "   Please run as a regular user with sudo privileges."
   exit 1
fi

# Check OS compatibility
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "❌ This tool is designed for Linux systems only."
    exit 1
fi

# Update package repositories
echo "📦 Updating package repositories..."
sudo apt update

# Install system dependencies
echo "🔧 Installing system dependencies..."
sudo apt install -y python3 python3-pip python3-venv git wget unzip nmap nikto dirb sqlmap gobuster

# Install Nuclei
echo "⚡ Installing Nuclei..."
if ! command -v nuclei &> /dev/null; then
    wget -O nuclei.zip https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
    unzip nuclei.zip
    sudo mv nuclei /usr/local/bin/
    rm nuclei.zip
    echo "✅ Nuclei installed successfully"
else
    echo "✅ Nuclei already installed"
fi

# Create virtual environment
echo "🐍 Setting up Python virtual environment..."
python3 -m venv bug_hunter_env
source bug_hunter_env/bin/activate

# Install Python dependencies
echo "📚 Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install -r bug_hunter/requirements.txt

# Install Sublist3r
echo "🔍 Installing Sublist3r..."
pip3 install sublist3r

# Update Nuclei templates
echo "📋 Updating Nuclei templates..."
nuclei -update-templates

# Set permissions
echo "🔐 Setting appropriate permissions..."
chmod +x bug_hunter/main.py

# Create symlink for easy access
echo "🔗 Creating system-wide access..."
sudo ln -sf $(pwd)/bug_hunter/main.py /usr/local/bin/bug-hunter

echo ""
echo "🎉 Installation completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Activate the virtual environment: source bug_hunter_env/bin/activate"
echo "2. Set your Gemini API key: export GEMINI_API_KEY='your_api_key'"
echo "3. Test the installation: python3 bug_hunter/main.py --help"
echo "4. Run your first scan: python3 bug_hunter/main.py -t httpbin.org --recon-only"
echo ""
echo "📖 For detailed documentation, see bug_hunter_documentation.md"
echo "🔍 Happy bug hunting!"

