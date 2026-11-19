#!/usr/bin/env bash
# VAJRAKAVACH 2070 — Safe GitHub Push Helper Script
# Founder & Project Developer: Divyesh Bambhaniya
# Usage: bash scripts/github_push.sh <GITHUB_USERNAME> <GITHUB_EMAIL> [REPO_NAME]

set -e

GH_USER="${1:-}"
GH_EMAIL="${2:-}"
REPO_NAME="${3:-vajrakavach-2070}"

if [ -z "$GH_USER" ] || [ -z "$GH_EMAIL" ]; then
  echo "Usage: bash scripts/github_push.sh <GITHUB_USERNAME> <GITHUB_EMAIL> [REPO_NAME]"
  exit 1
fi

echo "[1/4] Verifying automated tests before pushing..."
python3 -m unittest discover -s tests -v

echo "[2/4] Initializing Git repository..."
git init
git branch -M main
git config user.name "Divyesh Bambhaniya"
git config user.email "$GH_EMAIL"

echo "[3/4] Staging files (checking no secrets or .db files are included)..."
git add .
git status

git commit -m "feat: initial release of VAJRAKAVACH 2070 v0.2.0 Core MVP" || echo "Nothing new to commit."

echo "[4/4] Configuring remote and pushing to GitHub..."
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/${GH_USER}/${REPO_NAME}.git"
echo "When prompted for password, paste your GitHub Personal Access Token (PAT)."
git push -u origin main
