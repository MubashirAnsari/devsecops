# Setup Guide

Complete guide to deploying the security harness across multiple GitHub repositories.

---

## Prerequisites

- GitHub Pro or higher (for branch rulesets)
- Self-hosted runner VM (Ubuntu, ARM64 recommended)
- Notion account (for weekly reporting)
- Google Chat space (for alerts)

---

## Step 1 — Prepare the Runner VM

### Install security tools

```bash
# Gitleaks
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_arm64.tar.gz
tar -xzf gitleaks_8.18.0_linux_arm64.tar.gz
sudo mv gitleaks /usr/local/bin/

# TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Python tools
pip install bandit pip-audit

# JavaScript tools
npm install -g eslint \
  eslint-plugin-security \
  eslint-plugin-no-unsanitized \
  @typescript-eslint/parser \
  @typescript-eslint/eslint-plugin \
  --prefix /home/ubuntu/.npm-global

# Ruby tools
gem install brakeman bundler-audit
```

### Configure Google Chat webhook

```bash
sudo mkdir -p /etc/github-runner
sudo tee /etc/github-runner/secrets.env << 'ENVEOF'
GOOGLE_CHAT_WEBHOOK=https://chat.googleapis.com/v1/spaces/YOUR_SPACE/messages?key=YOUR_KEY
ENVEOF
sudo chmod 600 /etc/github-runner/secrets.env
```

---

## Step 2 — Deploy to a Repository

### Copy workflow files

```bash
mkdir -p YOUR_REPO/.github/workflows
cp security-scan.yml YOUR_REPO/.github/workflows/
cp .eslintrc-security.json YOUR_REPO/
```

### Install self-hosted runner

```bash
mkdir actions-runner-YOUR-REPO
cd actions-runner-YOUR-REPO
curl -o actions-runner-linux-arm64-2.334.0.tar.gz -L \
  https://github.com/actions/runner/releases/download/v2.334.0/actions-runner-linux-arm64-2.334.0.tar.gz
tar xzf ./actions-runner-linux-arm64-2.334.0.tar.gz

# Get token from: github.com/YOUR-ORG/YOUR-REPO/settings/actions/runners/new
./config.sh --url https://github.com/YOUR-ORG/YOUR-REPO --token YOUR_TOKEN
sudo ./svc.sh install
sudo ./svc.sh start
```

### Create PR and merge

```bash
git checkout -b feature/add-security-scan
git add .github/workflows/security-scan.yml .eslintrc-security.json
git commit -m "Add security scan workflow"
git push origin feature/add-security-scan
# Open PR on GitHub and merge
```

---

## Step 3 — Set Up Weekly Notion Report

### Create Notion database

Create a new Notion database with these properties:

| Property | Type |
|---|---|
| Repo name | Title |
| Mode | Select: report, enforce |
| Findings count | Number |
| Severity | Select: 🔴 Critical, 🟠 High, 🟡 Medium, 🔵 Low, ✅ Clean |
| Trend | Select: 🆕 New, ↑ Worse, ↓ Improved, → Unchanged |
| Report date | Date |
| Repo link | URL |

### Create Notion integration
notion.so → Settings → Connections → New integration
→ Name: Security Reports
→ Capabilities: Read + Write
→ Copy token (starts with secret_...)
→ Connect integration to your database

### Create reporting repo

```bash
# Create a new GitHub repo for the weekly report
# Add these secrets:
# GH_PAT          — Personal access token (repo + issues read)
# NOTION_TOKEN    — Your Notion integration token
# NOTION_DATABASE_ID — Your database ID from Notion URL
# NOTION_PARENT_PAGE_ID — Parent page ID for executive dashboard
# GH_ORG          — Your GitHub org/username
```

### Add workflow to reporting repo

```yaml
# .github/workflows/weekly-report.yml
name: Weekly Security Report
on:
  schedule:
    - cron: '0 4 * * 1'  # Monday 4am UTC
  workflow_dispatch:

jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install requests
      - run: python reporting/weekly-report.py
        env:
          GH_PAT: ${{ secrets.GH_PAT }}
          NOTION_TOKEN: ${{ secrets.NOTION_TOKEN }}
          NOTION_DATABASE_ID: ${{ secrets.NOTION_DATABASE_ID }}
          NOTION_PARENT_PAGE_ID: ${{ secrets.NOTION_PARENT_PAGE_ID }}
          GH_ORG: ${{ secrets.GH_ORG }}
```

---

## Step 4 — Enable Enforcement (When Ready)

### Report mode first

Keep all repos in report mode for 2-4 weeks. Monitor findings via Notion. Ask teams to add fixes to sprint goals.

### Enable branch ruleset
GitHub Repo → Settings → Rules → Rulesets → New ruleset
→ Target branches: main, prod
→ Required status checks: Security Scan
→ Block force pushes: ✅
→ Mode: Enforce

Enable on `main/prod` first, then `stg`, then `qa`.

---

## Disk Management

Each self-hosted runner uses ~580MB for binaries. Add a nightly cron job to clean report artifacts:

```bash
crontab -e
# Add:
0 2 * * * find /home/ubuntu -path "*/actions-runner-*/work/*.json" -delete && \
          find /home/ubuntu -path "*/actions-runner-*/work/*.txt" -delete
```

---

## Troubleshooting

### ESLint TypeScript parser error
Error: Cannot find module '@typescript-eslint/parser'
Fix — add `NODE_PATH` to the ESLint command in `security-scan.yml`:
```yaml
NODE_PATH=/home/ubuntu/.npm-global/lib/node_modules eslint ...
```

### pip-audit requirements.txt not found
The workflow searches recursively for `requirements.txt`. If your file is in a subdirectory, ensure it's named `requirements.txt`.

### Runner disk full
Add more disk to your VM or reduce number of runners by switching to GitHub-hosted runners (`runs-on: ubuntu-latest`) for lower-priority repos.
