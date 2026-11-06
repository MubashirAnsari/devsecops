"""
GitHub webhook receiver for SIEM ingestion (AWS Lambda, Python 3.12+).

Flow: GitHub repo webhook -> Lambda function URL -> S3 (raw/ + events/) -> S3 event -> SQS -> SIEM.

Checks, in order (cheapest first, fail closed):
  1. POST only                                   -> 405
  2. Source IP inside GitHub "hooks" ranges      -> 403 (503 if the range list cannot be loaded)
  3. Content-Type application/json               -> 415
  4. X-Hub-Signature-256 HMAC is valid           -> 401
  5. X-GitHub-Delivery looks like a GUID         -> 400
Then writes the full payload to raw/ and a small flat record to events/, and returns 202.

Every decision is logged as one JSON line, so the SIEM can alert on the receiver's own failures.

Environment variables:
  BUCKET     S3 bucket name
  SECRET_ID  Secrets Manager secret id that holds the webhook secret (plain string)
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import time
import urllib.request

import boto3
from botocore.config import Config

# Short timeouts so one slow AWS call cannot use up the whole Lambda time limit.
_CFG = Config(connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 2, "mode": "standard"})
S3 = boto3.client("s3", config=_CFG)
SM = boto3.client("secretsmanager", config=_CFG)

BUCKET = os.environ["BUCKET"]
SECRET_ID = os.environ["SECRET_ID"]

META_URL = "https://api.github.com/meta"
META_TTL = 3600          # refresh GitHub hook ranges every hour
META_MAX_STALE = 86400   # reuse the last good list for up to 24 h if refresh fails
DELIVERY_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
# "Merge pull request #12 from ..." or a squash/rebase title ending in "(#12)"
PR_MERGE_RE = re.compile(r"^Merge pull request #\d+ |\(#\d+\)$")

_meta = {"nets": None, "fetched": 0.0}
_secret = {"value": None}


def log(**kw):
    print(json.dumps(kw, default=str))


def resp(code, msg):
    return {"statusCode": code, "headers": {"Content-Type": "text/plain"}, "body": msg}


# ---------------------------------------------------------------- IP allowlist
def _fetch_hook_ranges():
    req = urllib.request.Request(META_URL, headers={"Accept": "application/vnd.github+json",
                                                     "User-Agent": "github-webhook-receiver"})
    with urllib.request.urlopen(req, timeout=3) as r:
        data = json.loads(r.read())
    return [ipaddress.ip_network(c) for c in data["hooks"]]


def hook_ranges():
    now = time.time()
    if _meta["nets"] is not None and now - _meta["fetched"] < META_TTL:
        return _meta["nets"]
    try:
        nets = _fetch_hook_ranges()
        _meta.update(nets=nets, fetched=now)
        log(result="meta_refreshed", hook_ranges=len(nets))
        return nets
    except Exception as e:  # keep the last good list for a while, then fail closed
        log(result="meta_refresh_failed", error=repr(e)[:300])
        if _meta["nets"] is not None and now - _meta["fetched"] < META_MAX_STALE:
            return _meta["nets"]
        return None


def ip_allowed(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets if n.version == addr.version)


# ---------------------------------------------------------------- signature
def webhook_secret():
    if _secret["value"] is None:
        _secret["value"] = SM.get_secret_value(SecretId=SECRET_ID)["SecretString"].strip()
    return _secret["value"]


def signature_ok(body_bytes, header):
    if not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(webhook_secret().encode(), body_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


# ---------------------------------------------------------------- flatten
def flatten(event, p):
    repo = p.get("repository") or {}
    sender = p.get("sender") or {}
    g = {
        "event": event,
        "action": p.get("action"),
        "repo": repo.get("full_name"),
        "repo_visibility": repo.get("visibility"),
        "default_branch": repo.get("default_branch"),
        "sender": sender.get("login"),
        "sender_type": sender.get("type"),
    }
    if event == "push":
        default_ref = "refs/heads/" + (repo.get("default_branch") or "")
        head = p.get("head_commit") or {}
        committer = head.get("committer") or {}
        first_line = (head.get("message") or "").splitlines()[0] if head.get("message") else ""
        g.update(ref=p.get("ref"), forced=p.get("forced"), created=p.get("created"),
                 deleted=p.get("deleted"), commits_count=len(p.get("commits") or []),
                 pusher=(p.get("pusher") or {}).get("name"),
                 is_default_branch=p.get("ref") == default_ref,
                 head_committer=committer.get("username") or committer.get("name"),
                 # GitHub UI merges are committed by "web-flow" with a PR-style message
                 via_pr_merge=committer.get("username") == "web-flow" and bool(PR_MERGE_RE.search(first_line)))
    elif event == "pull_request":
        pr = p.get("pull_request") or {}
        g.update(pr_number=pr.get("number"), pr_author=(pr.get("user") or {}).get("login"),
                 pr_merged=pr.get("merged"), pr_merged_by=(pr.get("merged_by") or {}).get("login"),
                 pr_base=(pr.get("base") or {}).get("ref"), pr_head=(pr.get("head") or {}).get("ref"))
    elif event == "member":
        changes = p.get("changes") or {}
        perm = changes.get("permission") or {}
        g.update(member=(p.get("member") or {}).get("login"),
                 permission_to=perm.get("to"), permission_from=perm.get("from"))
    elif event == "branch_protection_rule":
        g.update(rule_name=(p.get("rule") or {}).get("name"))
    elif event == "repository_ruleset":
        rs = p.get("repository_ruleset") or {}
        g.update(ruleset_name=rs.get("name"), ruleset_enforcement=rs.get("enforcement"))
    elif event == "deploy_key":
        k = p.get("key") or {}
        # the public key itself stays in raw/ only
        g.update(deploy_key_id=k.get("id"), deploy_key_title=k.get("title"),
                 deploy_key_read_only=k.get("read_only"), deploy_key_created_at=k.get("created_at"))
    elif event in ("create", "delete"):
        g.update(ref=p.get("ref"), ref_type=p.get("ref_type"))
    # drop empty values so SIEM rules never match on null
    return {k: v for k, v in g.items() if v is not None}


# ---------------------------------------------------------------- handler
def lambda_handler(event, context):
    http = (event.get("requestContext") or {}).get("http") or {}
    method = http.get("method", "")
    src = http.get("sourceIp", "")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}

    if method != "POST":
        return resp(405, "method not allowed")

    nets = hook_ranges()
    if nets is None:
        log(result="rejected", reason="allowlist_unavailable", source_ip=src)
        return resp(503, "unavailable")
    if not ip_allowed(src, nets):
        log(result="rejected", reason="ip_not_allowed", source_ip=src)
        return resp(403, "forbidden")

    if not headers.get("content-type", "").lower().startswith("application/json"):
        log(result="rejected", reason="bad_content_type", source_ip=src)
        return resp(415, "application/json required")

    body = event.get("body") or ""
    body_bytes = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode()

    if not signature_ok(body_bytes, headers.get("x-hub-signature-256")):
        log(result="rejected", reason="bad_signature", source_ip=src)
        return resp(401, "invalid signature")

    delivery = headers.get("x-github-delivery", "")
    gh_event = headers.get("x-github-event", "unknown")
    if not DELIVERY_RE.match(delivery):
        log(result="rejected", reason="bad_delivery_id", source_ip=src)
        return resp(400, "bad delivery id")

    payload = json.loads(body_bytes)
    day = time.strftime("%Y/%m/%d", time.gmtime())
    raw_key = f"raw/{day}/{delivery}.json"
    record = {
        "integration": "github-webhook",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "delivery": delivery,
        "source_ip": src,
        "raw_key": raw_key,
        "github": flatten(gh_event, payload),
    }
    # raw first (evidence), then the flat record that triggers the SIEM pipeline
    S3.put_object(Bucket=BUCKET, Key=raw_key, Body=body_bytes, ContentType="application/json")
    S3.put_object(Bucket=BUCKET, Key=f"events/{day}/{delivery}.json",
                  Body=json.dumps(record).encode(), ContentType="application/json")
    log(result="stored", event=gh_event, repo=record["github"].get("repo"), delivery=delivery)
    return resp(202, "stored")
