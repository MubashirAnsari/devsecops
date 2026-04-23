#!/bin/bash

# ══════════════════════════════════════════════════════════════════
# prowler_scan.sh — Daily AWS CSPM scan
# Part of: cspm-aws-wazuh pipeline
#
# Runs Prowler against AWS, diffs against previous scan,
# and writes only NEW findings to Wazuh agent file.
# ══════════════════════════════════════════════════════════════════

# ── Config — edit these ──────────────────────────────────────────
PROWLER_DIR="/home/ubuntu/prowler"          # path to prowler venv
OUTPUT_DIR="/var/log/prowler"               # scan output directory
WAZUH_FILE="/var/ossec/logs/prowler_findings.json"
PREVIOUS="$OUTPUT_DIR/prowler_previous.json"
TODAY_FLAT="/tmp/prowler_today_flat.json"
DATE=$(date +%Y-%m-%d_%H%M)
AWS_REGION="us-east-1"                      # change to your region
# ─────────────────────────────────────────────────────────────────

# AWS credentials — point to the user running Prowler
export AWS_SHARED_CREDENTIALS_FILE=/home/ubuntu/.aws/credentials
export AWS_CONFIG_FILE=/home/ubuntu/.aws/config

cd "$PROWLER_DIR"
source venv/bin/activate

echo "[$(date)] Prowler scan started" >> "$OUTPUT_DIR/cron.log"

# Run Prowler — critical and high severity only, OCSF format
prowler aws \
  --severity critical high \
  --region "$AWS_REGION" \
  --output-formats json-ocsf \
  --output-filename "prowler-$DATE" \
  --output-directory "$OUTPUT_DIR" \
  >> "$OUTPUT_DIR/cron.log" 2>&1

# Find latest OCSF output file
LATEST=$(ls -t "$OUTPUT_DIR"/prowler-*.ocsf.json 2>/dev/null | head -1)

if [ -z "$LATEST" ]; then
  echo "[$(date)] ERROR: No output file found" >> "$OUTPUT_DIR/cron.log"
  exit 1
fi

# ── Flatten to stable fields only ───────────────────────────────
# Excludes volatile fields (scan_id, created_time) to prevent
# false positives in the diff comparison
jq -c '.[] | select(.status_code == "FAIL") | {
  prowler_finding: true,
  event_code: .metadata.event_code,
  title: .finding_info.title,
  status_code: .status_code,
  severity: .severity,
  region: .cloud.region,
  account: .cloud.account.uid,
  resource: .resources[0].uid,
  resource_type: .resources[0].type,
  message: .message,
  remediation: .remediation.desc
}' "$LATEST" > "$TODAY_FLAT"

TOTAL=$(wc -l < "$TODAY_FLAT")

# ── Diff against previous scan ───────────────────────────────────
if [ -f "$PREVIOUS" ]; then
  sort "$TODAY_FLAT" > /tmp/prowler_sorted_today.json
  sort "$PREVIOUS"   > /tmp/prowler_sorted_prev.json
  comm -23 /tmp/prowler_sorted_today.json /tmp/prowler_sorted_prev.json > /tmp/prowler_new.json
  NEW_COUNT=$(wc -l < /tmp/prowler_new.json)
  echo "[$(date)] Total: $TOTAL | New since last scan: $NEW_COUNT" >> "$OUTPUT_DIR/cron.log"
else
  cp "$TODAY_FLAT" /tmp/prowler_new.json
  NEW_COUNT=$TOTAL
  echo "[$(date)] First run — sending all $TOTAL findings" >> "$OUTPUT_DIR/cron.log"
fi

# ── Write to Wazuh agent file ────────────────────────────────────
# Stop agent, truncate file + reset position tracking, restart
# This ensures Wazuh always reads from position 0 on fresh file
# and prevents findings being skipped due to file position caching
sudo systemctl stop wazuh-agent
sudo truncate -s 0 "$WAZUH_FILE"
sudo truncate -s 0 /var/ossec/queue/logcollector/file_status.json
sudo systemctl start wazuh-agent
sleep 5

# Append new findings — Wazuh logcollector picks up from position 0
cat /tmp/prowler_new.json >> "$WAZUH_FILE"

# ── Save baseline for tomorrow's diff ────────────────────────────
cp "$TODAY_FLAT" "$PREVIOUS"

echo "[$(date)] Done — $NEW_COUNT new findings written to $WAZUH_FILE" >> "$OUTPUT_DIR/cron.log"
