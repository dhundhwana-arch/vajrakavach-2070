# 📱 Termux Setup & GitHub Push Guide — VAJRAKAVACH 2070

**Founder & Developer:** Divyesh Bambhaniya

## Step 1: Unzip & Run on Termux (Android)

```bash
# Storage permission & required packages
termux-setup-storage
pkg update -y && pkg install -y python git unzip

# Copy ZIP from Downloads and unzip
mkdir -p ~/projects && cd ~/projects
cp /sdcard/Download/vajrakavach-2070-mvp.zip .
unzip -o vajrakavach-2070-mvp.zip
cd vajrakavach-2070

# Run automated tests first to verify everything passes!
python3 -m unittest discover -s tests -v

# Start VAJRAKAVACH 2070 server
python3 -m backend.app
```

Open your Android browser (Chrome/Brave) and go to:
`http://127.0.0.1:8080`

## Step 2: Push Directly to GitHub from Termux

1. Create a new empty repository on GitHub named `vajrakavach-2070` (keep it Private or Public as you prefer; do NOT add README/LICENSE on GitHub since they are already in this folder).
2. Generate a GitHub Personal Access Token (PAT) with `repo` scope at `https://github.com/settings/tokens`.
3. Run these commands inside `~/projects/vajrakavach-2070`:

```bash
git init
git branch -M main
git config user.name "Divyesh Bambhaniya"
git config user.email "YOUR_GITHUB_EMAIL@example.com"

git add .
git status   # Confirm NO .db or .env files are staged!
git commit -m "feat: initial release of VAJRAKAVACH 2070 v0.2.0 Core MVP"

git remote add origin https://github.com/YOUR_GITHUB_USERNAME/vajrakavach-2070.git
git push -u origin main
```

When Git asks for your **Password**, paste your **GitHub Personal Access Token (PAT)**.
