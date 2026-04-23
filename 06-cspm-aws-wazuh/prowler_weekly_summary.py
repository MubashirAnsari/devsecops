#!/usr/bin/env python3
"""
prowler_weekly_summary.py — Weekly CSPM posture report
Part of: cspm-aws-wazuh pipeline

Reads the latest Prowler OCSF scan file and sends a
Google Chat Cards v2 weekly summary every Monday at 8 AM.

Includes:
- Overall posture score
- CIS AWS Benchmark score (v6.0 primary)
- Week-over-week trend
- Findings breakdown by severity
- Top failing AWS services
- CIS score by version with progress bars
- Top 5 failing CIS controls
- Top 5 open critical findings
"""

import json
import glob
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

# ── Config — edit these ──────────────────────────────────────────
WEBHOOK_URL  = "YOUR_GOOGLE_CHAT_WEBHOOK_URL"
SCAN_DIR     = "/var/log/prowler"
LOG_FILE     = "/var/log/prowler/weekly_summary.log"
AWS_ACCOUNT  = "YOUR_AWS_ACCOUNT_ID"
NOTION_URL   = "YOUR_NOTION_DATABASE_URL"
CIS_PRIMARY  = "CIS-6.0"
# ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [weekly-summary] %(levelname)s: %(message)s"
)
log = logging.getLogger(__name__)

SERVICE_ICONS = {
    "s3": "S3", "ec2": "EC2", "iam": "IAM", "ecs": "ECS",
    "vpc": "VPC", "kms": "KMS", "sns": "SNS", "cloudfront": "CF",
    "cloudwatch": "CW", "cloudtrail": "CT", "codebuild": "CB",
    "awslambda": "Lambda", "guardduty": "GD", "securityhub": "SH",
}

def extract_service(event_code):
    for svc in SERVICE_ICONS:
        if event_code.startswith(svc):
            return svc
    return "etc"

def load_latest_scan():
    files = sorted(glob.glob(f"{SCAN_DIR}/prowler-*.ocsf.json"), reverse=True)
    if not files:
        log.error("No OCSF scan files found")
        return None, None
    log.info(f"Loading: {files[0]}")
    with open(files[0]) as f:
        return json.load(f), files[0]

def load_previous_scan():
    files = sorted(glob.glob(f"{SCAN_DIR}/prowler-*.ocsf.json"), reverse=True)
    if len(files) < 2:
        return None
    with open(files[1]) as f:
        return json.load(f)

def build_metrics(findings):
    metrics = {
        "total": len(findings),
        "total_pass": 0,
        "total_fail": 0,
        "by_severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        "by_service": {},
        "fail_critical": [],
        "fail_high_services": {},
        "checks_run": set(),
        "cis_pass": 0,
        "cis_fail": 0,
        "cis_versions": {},
        "cis_top_fail": {},
    }
    for f in findings:
        status     = f.get("status_code", "")
        severity   = f.get("severity", "")
        event_code = f.get("metadata", {}).get("event_code", "")
        service    = extract_service(event_code)
        compliance = f.get("unmapped", {}).get("compliance", {})

        metrics["checks_run"].add(event_code)

        if status == "PASS":
            metrics["total_pass"] += 1
        elif status == "FAIL":
            metrics["total_fail"] += 1
            metrics["by_severity"][severity] = metrics["by_severity"].get(severity, 0) + 1
            metrics["by_service"][service]   = metrics["by_service"].get(service, 0) + 1

            if severity == "Critical" and len(metrics["fail_critical"]) < 5:
                res = (f.get("resources") or [{}])[0].get("uid", "N/A")
                if len(res) > 55:
                    parts = res.split(":")
                    res = "...:" + parts[-1] if parts else res[-55:]
                metrics["fail_critical"].append({
                    "title":      f.get("finding_info", {}).get("title", "N/A")[:60],
                    "event_code": event_code,
                    "resource":   res,
                })

            if severity == "High":
                metrics["fail_high_services"][service] = metrics["fail_high_services"].get(service, 0) + 1

        # CIS compliance tracking
        cis = {k: v for k, v in compliance.items() if k.startswith("CIS-")}
        if cis:
            if status == "PASS":
                metrics["cis_pass"] += 1
            elif status == "FAIL":
                metrics["cis_fail"] += 1
                metrics["cis_top_fail"][event_code] = metrics["cis_top_fail"].get(event_code, 0) + 1
            for version, controls in cis.items():
                if version not in metrics["cis_versions"]:
                    metrics["cis_versions"][version] = {"pass": 0, "fail": 0}
                if status == "PASS":
                    metrics["cis_versions"][version]["pass"] += 1
                elif status == "FAIL":
                    metrics["cis_versions"][version]["fail"] += 1

    metrics["checks_run"] = len(metrics["checks_run"])
    return metrics

def posture_score(metrics):
    if metrics["total"] == 0:
        return 0
    return round((metrics["total_pass"] / metrics["total"]) * 100)

def cis_score(metrics):
    total = metrics["cis_pass"] + metrics["cis_fail"]
    if total == 0:
        return 0
    return round((metrics["cis_pass"] / total) * 100)

def cis_grade(score):
    if score >= 90: return "Excellent", "#1B5E20"
    if score >= 80: return "Good",      "#2E7D32"
    if score >= 70: return "Fair",      "#F57F17"
    if score >= 50: return "Poor",      "#E65100"
    return           "Critical",        "#B71C1C"

def posture_grade(score):
    if score >= 85: return "GOOD",       "#1B5E20"
    if score >= 70: return "FAIR",       "#F57F17"
    if score >= 50: return "NEEDS WORK", "#E65100"
    return           "AT RISK",          "#B71C1C"

def wow_trend(curr_metrics, prev_findings):
    if not prev_findings:
        return "First scan baseline", "#5F6368"
    prev = build_metrics(prev_findings)
    diff = curr_metrics["total_fail"] - prev["total_fail"]
    if diff > 0:  return f"+{diff} new failures vs last scan", "#B71C1C"
    if diff < 0:  return f"{diff} fewer failures vs last scan", "#1B5E20"
    return "No change vs last scan", "#5F6368"

def http_post(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        log.error(f"HTTP {e.code}: {e.read().decode()[:200]}")
        return e.code
    except Exception as e:
        log.error(f"Error: {e}")
        return 0

def build_card(metrics, p_score, c_score, wow_text, wow_color):
    now        = datetime.now(timezone.utc)
    week_start = (now - timedelta(days=7)).strftime("%b %d")
    week_end   = now.strftime("%b %d, %Y")
    p_grade, p_color = posture_grade(p_score)
    c_grade, c_color = cis_grade(c_score)

    top_services = sorted(metrics["by_service"].items(), key=lambda x: x[1], reverse=True)[:4]
    service_text = "  |  ".join([f"{SERVICE_ICONS.get(s, s.upper())}: {c}" for s, c in top_services]) or "None"

    top_high = sorted(metrics["fail_high_services"].items(), key=lambda x: x[1], reverse=True)[:4]
    high_text = "  |  ".join([f"{SERVICE_ICONS.get(s, s.upper())}: {c}" for s, c in top_high]) or "None"

    # CIS version scores — latest 3
    cis_priority = ["CIS-6.0", "CIS-5.0", "CIS-4.0.1", "CIS-3.0", "CIS-2.0"]
    cis_lines = []
    for v in cis_priority:
        if v in metrics["cis_versions"]:
            vc    = metrics["cis_versions"][v]
            total = vc["pass"] + vc["fail"]
            vs    = round((vc["pass"] / total) * 100) if total > 0 else 0
            bar   = "█" * (vs // 10) + "░" * (10 - vs // 10)
            cis_lines.append(f"{v}: {vs}%  {bar}  ({vc['pass']}/{total})")
        if len(cis_lines) == 3:
            break
    cis_versions_text = "\n".join(cis_lines)

    # Top 5 failing CIS controls
    top_cis_fails = sorted(metrics["cis_top_fail"].items(), key=lambda x: x[1], reverse=True)[:5]
    cis_fail_widgets = []
    for check, count in top_cis_fails:
        svc = extract_service(check)
        cis_fail_widgets.append({
            "decoratedText": {
                "topLabel": f"{SERVICE_ICONS.get(svc, svc.upper())} - {count} resources affected",
                "text": f"<b>{check}</b>",
                "startIcon": {"knownIcon": "BOOKMARK"}
            }
        })
    if not cis_fail_widgets:
        cis_fail_widgets.append({
            "decoratedText": {
                "text": "<b>No CIS failures detected</b>",
                "startIcon": {"knownIcon": "CHECKMARK"}
            }
        })

    # Critical findings widgets
    crit_widgets = []
    if metrics["fail_critical"]:
        for f in metrics["fail_critical"]:
            crit_widgets.append({
                "decoratedText": {
                    "topLabel": f["event_code"],
                    "text": f"<b>{f['title']}</b>",
                    "bottomLabel": f["resource"],
                    "startIcon": {"knownIcon": "BOOKMARK"}
                }
            })
    else:
        crit_widgets.append({
            "decoratedText": {
                "text": "<b>No critical findings this week</b>",
                "startIcon": {"knownIcon": "CHECKMARK"}
            }
        })

    return {
        "cardsV2": [{
            "cardId": f"weekly-{now.strftime('%Y%m%d')}",
            "card": {
                "header": {
                    "title": "Weekly Cloud Security Posture Report",
                    "subtitle": f"AWS {AWS_ACCOUNT}  |  {week_start} - {week_end}",
                    "imageUrl": "https://raw.githubusercontent.com/prowler-cloud/prowler/master/docs/img/prowler-logo-shadow.png",
                    "imageType": "CIRCLE"
                },
                "sections": [
                    {
                        "header": "Security Posture Overview",
                        "collapsible": False,
                        "widgets": [
                            {"columns": {"columnItems": [
                                {"horizontalSizeStyle": "FILL_AVAILABLE_SPACE", "widgets": [{"decoratedText": {"topLabel": "OVERALL POSTURE", "text": f"<font color='{p_color}'><b>{p_score}% - {p_grade}</b></font>", "startIcon": {"knownIcon": "STAR"}}}]},
                                {"horizontalSizeStyle": "FILL_AVAILABLE_SPACE", "widgets": [{"decoratedText": {"topLabel": f"CIS BENCHMARK ({CIS_PRIMARY})", "text": f"<font color='{c_color}'><b>{c_score}% - {c_grade}</b></font>", "startIcon": {"knownIcon": "TICKET"}}}]}
                            ]}},
                            {"columns": {"columnItems": [
                                {"horizontalSizeStyle": "FILL_AVAILABLE_SPACE", "widgets": [{"decoratedText": {"topLabel": "WEEK OVER WEEK", "text": f"<font color='{wow_color}'><b>{wow_text}</b></font>", "startIcon": {"knownIcon": "TRENDING"}}}]},
                                {"horizontalSizeStyle": "FILL_AVAILABLE_SPACE", "widgets": [{"decoratedText": {"topLabel": "CHECKS / RESOURCES", "text": f"<b>{metrics['checks_run']} / {metrics['total']}</b>", "startIcon": {"knownIcon": "CLOUD"}}}]}
                            ]}}
                        ]
                    },
                    {
                        "header": "Findings Breakdown",
                        "collapsible": False,
                        "widgets": [
                            {"columns": {"columnItems": [
                                {"horizontalSizeStyle": "FILL_AVAILABLE_SPACE", "widgets": [
                                    {"decoratedText": {"topLabel": "PASS", "text": f"<font color='#1B5E20'><b>{metrics['total_pass']}</b></font>"}},
                                    {"decoratedText": {"topLabel": "FAIL", "text": f"<font color='#B71C1C'><b>{metrics['total_fail']}</b></font>"}}
                                ]},
                                {"horizontalSizeStyle": "FILL_AVAILABLE_SPACE", "widgets": [
                                    {"decoratedText": {"topLabel": "CRITICAL", "text": f"<font color='#B71C1C'><b>{metrics['by_severity']['Critical']}</b></font>"}},
                                    {"decoratedText": {"topLabel": "HIGH", "text": f"<font color='#E65100'><b>{metrics['by_severity']['High']}</b></font>"}}
                                ]}
                            ]}},
                            {"decoratedText": {"topLabel": "TOP FAILING SERVICES", "text": service_text, "startIcon": {"knownIcon": "CLOUD"}}}
                        ]
                    },
                    {
                        "header": "CIS AWS Benchmark Scores",
                        "collapsible": False,
                        "widgets": [
                            {"columns": {"columnItems": [
                                {"horizontalSizeStyle": "FILL_AVAILABLE_SPACE", "widgets": [{"decoratedText": {"topLabel": "CIS PASS", "text": f"<font color='#1B5E20'><b>{metrics['cis_pass']}</b></font>", "startIcon": {"knownIcon": "CHECKMARK"}}}]},
                                {"horizontalSizeStyle": "FILL_AVAILABLE_SPACE", "widgets": [{"decoratedText": {"topLabel": "CIS FAIL", "text": f"<font color='#B71C1C'><b>{metrics['cis_fail']}</b></font>", "startIcon": {"knownIcon": "DESCRIPTION"}}}]}
                            ]}},
                            {"decoratedText": {"topLabel": "SCORE BY VERSION (latest 3)", "text": cis_versions_text, "startIcon": {"knownIcon": "BOOKMARK"}, "wrapText": True}}
                        ]
                    },
                    {"header": "Top Failing CIS Controls", "collapsible": True, "uncollapsibleWidgetsCount": 3, "widgets": cis_fail_widgets},
                    {"header": "Open Critical Findings (Top 5)", "collapsible": True, "uncollapsibleWidgetsCount": 2, "widgets": crit_widgets},
                    {"header": "High Findings by Service", "collapsible": True, "uncollapsibleWidgetsCount": 1, "widgets": [{"decoratedText": {"topLabel": "HIGH FINDINGS BREAKDOWN", "text": high_text, "startIcon": {"knownIcon": "DESCRIPTION"}}}]},
                    {"widgets": [{"buttonList": {"buttons": [
                        {"text": "Open CPSM-AWS in Notion", "color": {"red": 0.22, "green": 0.22, "blue": 0.22, "alpha": 1.0}, "onClick": {"openLink": {"url": NOTION_URL}}},
                        {"text": "Prowler Docs", "onClick": {"openLink": {"url": "https://hub.prowler.com"}}}
                    ]}}]}
                ]
            }
        }]
    }

if __name__ == "__main__":
    log.info("Weekly summary started")
    findings, scan_file = load_latest_scan()
    if not findings:
        log.error("No findings loaded - exiting")
        exit(1)
    previous            = load_previous_scan()
    metrics             = build_metrics(findings)
    p_score             = posture_score(metrics)
    c_score             = cis_score(metrics)
    wow_text, wow_color = wow_trend(metrics, previous)
    log.info(f"Posture: {p_score}% | CIS: {c_score}% | Total: {metrics['total']} | Fail: {metrics['total_fail']} | Critical: {metrics['by_severity']['Critical']}")
    card   = build_card(metrics, p_score, c_score, wow_text, wow_color)
    status = http_post(WEBHOOK_URL, card)
    if status == 200:
        log.info("Weekly summary sent successfully")
    else:
        log.error(f"Send failed - HTTP {status}")
