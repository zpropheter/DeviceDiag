#!/bin/bash
# Sydiagnose Analyzer launcher
# Installs Flask if needed, then starts the web app.

set -e

cd "$(dirname "$0")"

# Check for Python 3
if ! command -v python3 &>/dev/null; then
    echo "Error: python3 not found. Install Python 3.9+ and try again."
    exit 1
fi

# Install/upgrade Flask quietly
echo "Checking dependencies…"
pip3 install -q -r requirements.txt

echo ""
echo "======================================================"
echo "  Sydiagnose Analyzer"
echo "  http://localhost:5001"
echo "  Press Ctrl+C to stop"
echo "======================================================"
echo ""

python3 app.py
