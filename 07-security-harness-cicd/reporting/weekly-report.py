import os
import requests
from datetime import datetime, timezone, timedelta

# ── Configuration ─────────────────────────────────────────────────────────────
# Set these as GitHub Actions secrets in your reporting repo
GH_PAT              = os.environ["GH_PAT"]
NOTION_TOKEN        = os.environ["NOTION_TOKEN"]
NOTION_DATABASE_ID  = os.environ["NOTION_DATABASE_ID"]
NOTION_PARENT_PAGE_ID = os.environ["NOTION_PARENT_PAGE_ID"]
GH_ORG              = os.environ["GH_ORG"]  # your GitHub org or username

GH_HEADERS = {
    "Authorization": f"token {GH_PAT}",
    "Accept": "application/vnd.github.v3+json"
}

NOTION_HEADERS = {
    "Authorization": f"Bearer {NOTION_TOKEN}",
    "Content-Type": "application/json",
    "Notion-Version": "2022-06-28"
}

# ── Repo List ──────────────────────────────────────────────────────────────────
# Add your repos here
REPOS = [
    "your-repo-1",
    "your-repo-2",
    "your-repo-3",
    # Add more repos...
]

TEST_MODE = False  # Set True to test with 1 repo only


# ── Helper Functions ───────────────────────────────────────────────────────────

def get_mode(repo):
    """Check if repo has active ruleset enforcement."""
    url = f"https://api.github.com/repos/{GH_ORG}/{repo}/rulesets"
    resp = requests.get(url, headers=GH_HEADERS)
    if resp.status_code != 200:
        return "report"
    for ruleset in resp.json():
        if ruleset.get("enforcement") == "active":
            return "enforce"
    return "report"


def get_pr_comment(repo):
    """Get most recent security scan PR comment."""
    url = f"https://api.github.com/repos/{GH_ORG}/{repo}/issues/comments"
    params = {"per_page": 100, "sort": "created", "direction": "desc"}
    resp = requests.get(url, headers=GH_HEADERS, params=params)
    if resp.status_code != 200:
        return None, None
    for comment in resp.json():
        body = comment.get("body", "")
        if "Powered by" in body and ("Security Scan Passed" in body or "Security Scan Failed" in body):
            return body, comment.get("html_url", "")
    return None, None


def parse_findings(body):
    """Parse PR comment into categorized findings."""
    if not body or "Security Scan Passed" in body:
        return {"total": 0, "secrets": [], "xss": [], "regex": [],
                "cves_python": [], "cves_js": [], "cves_ruby": [],
                "unpinned": [], "brakeman": [], "passed": True}

    secrets, xss, regex = [], [], []
    cves_python, cves_js, cves_ruby = [], [], []
    unpinned, brakeman = [], []
    current_section = None

    for line in body.split("\n"):
        s = line.strip()
        if "Secrets Detected" in s or "Verified Secrets" in s:
            current_section = "secrets"
        elif "JavaScript Security Issues" in s:
            current_section = "js"
        elif "Python Security Issues" in s or "Python CVEs" in s:
            current_section = "python"
        elif "JS Dependency" in s:
            current_section = "js_cve"
        elif "Ruby Security Issues" in s:
            current_section = "brakeman"
        elif "Ruby Gem CVEs" in s:
            current_section = "ruby_cve"
        elif "Unpinned Dependencies" in s:
            current_section = "unpinned"
        elif s.startswith("- **") and "line" in s:
            if current_section == "secrets":
                secrets.append(s[2:])
            elif current_section == "js":
                if "no-unsanitized" in s:
                    xss.append(s[2:])
                elif "detect-unsafe-regex" in s:
                    regex.append(s[2:])
            elif current_section == "python":
                cves_python.append(s[2:])
            elif current_section == "js_cve":
                cves_js.append(s[2:])
            elif current_section == "brakeman":
                brakeman.append(s[2:])
            elif current_section == "ruby_cve":
                cves_ruby.append(s[2:])
        elif s.startswith("- `") and current_section == "unpinned":
            unpinned.append(s[2:])

    total = sum(len(x) for x in [secrets, xss, regex, cves_python, cves_js, cves_ruby, unpinned, brakeman])
    return {"total": total, "secrets": secrets, "xss": xss, "regex": regex,
            "cves_python": cves_python, "cves_js": cves_js, "cves_ruby": cves_ruby,
            "unpinned": unpinned, "brakeman": brakeman, "passed": total == 0}


def get_severity_tier(findings):
    if findings == 0:       return "clean"
    elif findings >= 100:   return "critical"
    elif findings >= 20:    return "high"
    elif findings >= 5:     return "medium"
    else:                   return "low"


def get_trend(current, previous):
    if previous is None:    return "new", 0
    delta = current - previous
    if delta > 0:           return "worse", delta
    elif delta < 0:         return "better", abs(delta)
    else:                   return "unchanged", 0


def get_last_week_findings():
    """Query Notion for last week's findings for trend tracking."""
    last_week = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    url = f"https://api.notion.com/v1/databases/{NOTION_DATABASE_ID}/query"
    payload = {"filter": {"and": [
        {"property": "Report date", "date": {"equals": last_week}},
        {"property": "Repo name", "title": {"does_not_contain": "Summary"}}
    ]}}
    resp = requests.post(url, headers=NOTION_HEADERS, json=payload)
    if resp.status_code != 200:
        return {}
    data = {}
    for page in resp.json().get("results", []):
        props = page.get("properties", {})
        name_parts = props.get("Repo name", {}).get("title", [])
        name = name_parts[0]["text"]["content"] if name_parts else ""
        findings = props.get("Findings count", {}).get("number", 0) or 0
        if name:
            data[name] = findings
    return data


def post_to_notion(repo, mode, findings_data, report_date, last_week, pr_url):
    """Post repo findings to Notion database with page body details."""
    repo_url = f"https://github.com/{GH_ORG}/{repo}"
    total = findings_data["total"]

    severity_map = {
        "critical": "🔴 Critical", "high": "🟠 High",
        "medium": "🟡 Medium", "low": "🔵 Low", "clean": "✅ Clean"
    }
    severity = severity_map[get_severity_tier(total)]

    prev = last_week.get(repo)
    trend_status, delta = get_trend(total, prev)
    trend_map = {
        "new": "🆕 New", "worse": f"↑ Worse (+{delta})",
        "better": f"↓ Improved (-{delta})", "unchanged": "→ Unchanged"
    }
    trend = trend_map[trend_status]

    # Build page body blocks
    blocks = build_page_blocks(repo, mode, findings_data, report_date, pr_url, last_week)

    payload = {
        "parent": {"database_id": NOTION_DATABASE_ID},
        "properties": {
            "Repo name": {"title": [{"text": {"content": repo}}]},
            "Mode": {"select": {"name": mode}},
            "Findings count": {"number": total},
            "Report date": {"date": {"start": report_date}},
            "Repo link": {"url": repo_url},
            "Severity": {"select": {"name": severity}},
            "Trend": {"select": {"name": trend}}
        },
        "children": blocks
    }

    resp = requests.post("https://api.notion.com/v1/pages", headers=NOTION_HEADERS, json=payload)
    if resp.status_code != 200:
        print(f"    Notion error: {resp.status_code} - {resp.text[:200]}")
    return resp.status_code == 200


def build_page_blocks(repo, mode, findings_data, report_date, pr_url, last_week):
    """Build Notion page body with findings breakdown."""
    total = findings_data["total"]
    prev = last_week.get(repo)
    trend_status, delta = get_trend(total, prev)
    trend_text = {
        "new": "🆕 First scan", "worse": f"↑ Worse (+{delta})",
        "better": f"↓ Improved (-{delta}) ✅", "unchanged": "→ Unchanged"
    }[trend_status]

    severity_map = {
        "critical": "🔴 Critical", "high": "🟠 High",
        "medium": "🟡 Medium", "low": "🔵 Low", "clean": "✅ Clean"
    }

    blocks = [
        {"object": "block", "type": "divider", "divider": {}},
        {"object": "block", "type": "heading_2", "heading_2": {"rich_text": [{"type": "text", "text": {"content": "📊 Summary"}}]}},
        {"object": "block", "type": "bulleted_list_item", "bulleted_list_item": {"rich_text": [{"type": "text", "text": {"content": f"Total findings: {total}"}}]}},
        {"object": "block", "type": "bulleted_list_item", "bulleted_list_item": {"rich_text": [{"type": "text", "text": {"content": f"Severity: {severity_map[get_severity_tier(total)]}"}}]}},
        {"object": "block", "type": "bulleted_list_item", "bulleted_list_item": {"rich_text": [{"type": "text", "text": {"content": f"Trend: {trend_text}"}}]}},
        {"object": "block", "type": "divider", "divider": {}},
    ]

    def add_section(title, items, empty_msg):
        if items:
            blocks.append({"object": "block", "type": "heading_3", "heading_3": {"rich_text": [{"type": "text", "text": {"content": f"{title} ({len(items)})"}}]}})
            for item in items[:15]:
                blocks.append({"object": "block", "type": "bulleted_list_item", "bulleted_list_item": {"rich_text": [{"type": "text", "text": {"content": item[:300]}}]}})
            if len(items) > 15:
                blocks.append({"object": "block", "type": "bulleted_list_item", "bulleted_list_item": {"rich_text": [{"type": "text", "text": {"content": f"... and {len(items)-15} more — see PR comment"}, "annotations": {"color": "gray"}}]}})
        else:
            blocks.append({"object": "block", "type": "bulleted_list_item", "bulleted_list_item": {"rich_text": [{"type": "text", "text": {"content": empty_msg}, "annotations": {"color": "gray"}}]}})
        blocks.append({"object": "block", "type": "divider", "divider": {}})

    add_section("🔑 Secrets", findings_data["secrets"], "✅ No secrets detected")
    add_section("🟨 XSS risks", findings_data["xss"], "✅ No XSS risks")
    add_section("⚠��� Unsafe regex", findings_data["regex"], "✅ No unsafe regex")
    add_section("🐍 Python CVEs", findings_data["cves_python"], "✅ No Python CVEs")
    add_section("📦 JS CVEs", findings_data["cves_js"], "✅ No JS CVEs")
    add_section("💎 Ruby issues", findings_data["brakeman"], "✅ No Ruby issues")
    add_section("📌 Unpinned deps", findings_data["unpinned"], "✅ All deps pinned")

    if pr_url:
        blocks.append({"object": "block", "type": "paragraph", "paragraph": {"rich_text": [
            {"type": "text", "text": {"content": "🔗 Full findings: "}},
            {"type": "text", "text": {"content": pr_url, "link": {"url": pr_url}}, "annotations": {"color": "blue"}}
        ]}})

    return blocks


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    now = datetime.now(timezone.utc)
    report_date = now.strftime("%Y-%m-%d")
    repos_to_run = REPOS[:1] if TEST_MODE else REPOS

    print(f"Generating security report ({report_date})")
    print(f"Mode: {'TEST' if TEST_MODE else 'FULL'} — {len(repos_to_run)} repos")

    print("Fetching last week's data...")
    last_week = get_last_week_findings()
    print(f"Last week: {len(last_week)} repos found")

    total_with_findings = 0
    results = []

    for repo in repos_to_run:
        print(f"Processing {repo}...")
        mode = get_mode(repo)
        body, pr_url = get_pr_comment(repo)
        findings_data = parse_findings(body)
        if findings_data["total"] > 0:
            total_with_findings += 1
        results.append((repo, mode, findings_data["total"]))

        if post_to_notion(repo, mode, findings_data, report_date, last_week, pr_url):
            print(f"  ✅ {repo}: {findings_data['total']} findings")
        else:
            print(f"  ❌ FAILED: {repo}")

    print(f"\nPosted {len(results)}/{len(repos_to_run)} repos")
    print(f"Repos with findings: {total_with_findings}/{len(repos_to_run)}")


if __name__ == "__main__":
    main()
