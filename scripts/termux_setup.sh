#!/data/data/com.termux/files/usr/bin/bash
# VAJRAKAVACH 2070 — Termux Quick Setup & Launch Script
# Founder & Project Developer: Divyesh Bambhaniya

set -e

echo "=================================================="
echo "  VAJRAKAVACH 2070 — Termux Setup & Verification"
echo "=================================================="

if command -v pkg >/dev/null 2>&1; then
  pkg update -y
  pkg install -y python git unzip
fi

echo "[1/2] Running automated security & functional tests..."
python3 -m unittest discover -s tests -v

echo "[2/2] Starting VAJRAKAVACH 2070 on http://127.0.0.1:8080 ..."
python3 -m backend.app
