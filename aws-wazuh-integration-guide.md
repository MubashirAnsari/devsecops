# AWS + Wazuh Integration Guide
### Unified Security Monitoring for AWS CloudTrail Events

> **Audience:** Intermediate — assumes familiarity with AWS IAM, S3, and basic Linux/Wazuh administration.  
> **Wazuh Version:** 4.x | **Tested on:** AWS us-east-1 (multi-region)

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Step 1 — Verify CloudTrail Setup](#step-1--verify-cloudtrail-setup)
5. [Step 2 — Create IAM User with Least Privilege](#step-2--create-iam-user-with-least-privilege)
6. [Step 3 — Configure Wazuh AWS Module](#step-3--configure-wazuh-aws-module)
7. [Step 4 — Tune OpenSearch Heap](#step-4--tune-opensearch-heap)
8. [Step 5 — Verify Alerts Are Flowing](#step-5--verify-alerts-are-flowing)
10. [What You'll Monitor](#what-youll-monitor)
11. [Compliance Coverage](#compliance-coverage)
12. [Why Bucket Mode (Not SQS)](#why-bucket-mode-not-sqs)
13. [Troubleshooting](#troubleshooting)
14. [Infrastructure Reference](#infrastructure-reference)

---

## Overview

This guide documents how to integrate AWS CloudTrail with Wazuh using **native bucket mode**, which automatically activates Wazuh's 50+ built-in AWS detection rules — covering console logins, IAM changes, CloudTrail tampering, S3 modifications, and more — with zero custom rules required.

**The core problem this solves:** Wazuh is excellent at monitoring endpoints and servers, but out of the box it has no visibility into your AWS environment. CloudTrail captures everything happening in AWS, but without a SIEM pulling those logs, alerts don't happen. This integration closes that gap.

**End result:**
- Real-time AWS threat detection across all regions
- 50+ built-in detection rules active immediately
- Compliance tagging for PCI DSS, HIPAA, GDPR, NIST 800-53, SOC 2
- Unified dashboard: endpoints + AWS in one place
- Cost: $0 in additional licensing

---

## Architecture

```
AWS Account
│
├── CloudTrail (all regions, management events)
│        │
│        └── S3 Bucket: yourbucketname
│                   │
│                   └── IAM User: wazuh-aws (can create any username)
│                         (read-only, scoped to this bucket only)
│
└────────────────────────────────────────────────────┐
                                                     ▼
                                          Wazuh Manager (EC2)
                                          AWS module — bucket mode
                                          Poll interval: 5 minutes
                                                     │
                                                     ▼
                                          50+ built-in AWS rules
                                          (MITRE ATT&CK mapped,
                                           compliance tagged)
                                                     │
                                                     ▼
                                          Wazuh Dashboard
                                          (Endpoints + AWS unified)
```

**Key design decision:** Bucket mode automatically sets the `aws.source` field that Wazuh's built-in rules require. Subscriber/SQS mode is faster but doesn't set this field — meaning all 50+ rules remain inactive. The 5-minute polling delay is a worthwhile tradeoff for full rule coverage.

---

## Prerequisites

Before starting, confirm you have:

- [ ] Wazuh Manager installed and running (v4.x)
- [ ] AWS account with CloudTrail already enabled
- [ ] Access to the Wazuh Manager via SSH
- [ ] AWS IAM permissions to create users and policies
- [ ] OpenSearch/Elasticsearch backing your Wazuh dashboard

---

## Step 1 — Verify CloudTrail Setup

You need a CloudTrail trail that:
- Logs **management events** (not just data events)
- Covers **all regions**
- Delivers logs to an **S3 bucket**

### Check your existing trail

```bash
aws cloudtrail describe-trails --include-shadow-trails
```

Look for:
```json
{
  "IsMultiRegionTrail": true,
  "IncludeGlobalServiceEvents": true,
  "S3BucketName": "your-cloudtrail-bucket"
}
```

If `IsMultiRegionTrail` is `false`, update it:

```bash
aws cloudtrail update-trail \
  --name your-trail-name \
  --is-multi-region-trail
```

### Note your S3 bucket name

You'll need it in Step 3. The logs land in this structure:

```
s3://your-bucket/AWSLogs/{account-id}/CloudTrail/{region}/{year}/{month}/{day}/
```

---

## Step 2 — Create IAM User with Least Privilege

Never use your root account or a broad IAM user. Create a dedicated read-only user scoped only to the CloudTrail bucket.

### 2a. Create the IAM policy

In the AWS Console → IAM → Policies → Create Policy, use this JSON:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WazuhCloudTrailRead",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::your-cloudtrail-bucket",
        "arn:aws:s3:::your-cloudtrail-bucket/*"
      ]
    }
  ]
}
```

Name it `WazuhLeastPrivilegePolicy`.

> **Why so restrictive?** This user cannot write, cannot access other AWS services, and cannot log into the AWS console. If these credentials are ever leaked, the blast radius is minimal — an attacker can only read CloudTrail logs, which are already semi-public audit records.

### 2b. Create the IAM user

```bash
# Create user
aws iam create-user --user-name wazuh-aws-reader

# Attach the policy
aws iam attach-user-policy \
  --user-name wazuh-aws-reader \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT_ID:policy/WazuhLeastPrivilegePolicy

# Create access keys
aws iam create-access-key --user-name wazuh-aws-reader
```

**Save the `AccessKeyId` and `SecretAccessKey` — you'll need them in the next step.** These are only shown once.

---

## Step 3 — Configure Wazuh AWS Module

SSH into your Wazuh Manager and edit the main config file:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add the following block inside the `<ossec_config>` root element:

```xml
<wodle name="aws-s3">
  <disabled>no</disabled>
  <interval>5m</interval>
  <run_on_start>yes</run_on_start>
  <skip_on_error>yes</skip_on_error>

  <bucket type="cloudtrail">
    <name>your-cloudtrail-bucket</name>
    <access_key>AKIAITESTDNN7EXAMPLE</access_key>
    <secret_key>wJalrXUEXAMple/EMAPle/bPxRfiCYEXAMPLEKEY</secret_key>
    <only_logs_after>2024-01-01</only_logs_after>
    <regions>us-east-1,us-west-2,eu-west-1</regions>
  </bucket>
</wodle>
```

**Config notes:**

| Parameter | What it does |
|---|---|
| `interval` | How often Wazuh polls the S3 bucket (5 minutes is recommended) |
| `type="cloudtrail"` | Tells Wazuh to parse these as CloudTrail logs and set `aws.source` |
| `only_logs_after` | Prevents Wazuh from processing your entire CloudTrail history on first run — set to today or a recent date |
| `regions` | Comma-separated list of regions to pull. Match what CloudTrail covers. |

> **Credentials alternative:** Instead of hardcoding keys in ossec.conf, you can configure an AWS credentials file at `/var/ossec/.aws/credentials` and omit the `<access_key>` and `<secret_key>` lines. This is cleaner for production.

### Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
```

### Verify the module started

```bash
sudo tail -f /var/ossec/logs/ossec.log | grep aws-s3
```

You should see lines like:
```
INFO: (aws-s3) Starting AWS S3 module.
INFO: (aws-s3) Fetching logs from: your-cloudtrail-bucket
```

---

## Step 4 — Suppress False Positives from Internal Tools

After enabling the AWS module, you may notice alerts being incorrectly triggered by internal tools — CI/CD systems, monitoring agents, deployment pipelines, or other automation that logs to syslog or generates events with patterns that overlap with Wazuh's AWS rules.

This is common in environments with active automation. The fix is straightforward: create local rule overrides. **Never edit files under `/var/ossec/ruleset/rules/` directly** — they get overwritten on Wazuh updates.

### Find the conflicting rule

When you see a suspicious false positive alert, note the rule ID from the Wazuh dashboard or alerts log:

```bash
sudo grep "aws" /var/ossec/logs/alerts/alerts.json | python3 -m json.tool | grep -E "rule|program|source"
```

Look for events where `rule.groups` contains `aws` but the source is clearly an internal tool, not CloudTrail.

### Create a local override

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

The general pattern for suppressing a false positive on a specific rule:

```xml
<group name="local_overrides">
  <rule id="100200" level="0">
    <if_sid>CONFLICTING_RULE_ID</if_sid>
    <field name="program_name">your-internal-tool</field>
    <description>Suppress false positive: internal tool matching AWS rule pattern</description>
  </rule>
</group>
```

Replace `CONFLICTING_RULE_ID` with the rule ID from your investigation, and `your-internal-tool` with the program name shown in the alert. Use `level="0"` to suppress without deleting the underlying rule.

Restart after saving:

```bash
sudo systemctl restart wazuh-manager
```

> **Tip:** If you're not sure whether a false positive is environment-specific, check the [Wazuh community forums](https://groups.google.com/g/wazuh) — some rule conflicts are known issues with fixes already documented.

---

## Step 4 — Tune OpenSearch Heap

The default OpenSearch heap (2GB) is insufficient once you add AWS CloudTrail volume on top of endpoint agents. With agents plus CloudTrail, the dashboard becomes unstable without this change.

### Edit the JVM options

```bash
sudo nano /etc/wazuh-indexer/jvm.options
```

Find and update:

```
# Before
-Xms2g
-Xmx2g

# After
-Xms6g
-Xmx6g
```

**Rule of thumb:** Set heap to no more than 50% of available RAM, and no more than 31GB (JVM limitation). For a dedicated Wazuh server with 16GB RAM, 6-8GB heap is appropriate.

### Restart the indexer

```bash
sudo systemctl restart wazuh-indexer
```

---

## Step 5 — Verify Alerts Are Flowing

### Trigger a test event

The easiest test: log into the AWS Console and then check Wazuh for a login alert.

Alternatively, make a deliberate API call that should trigger a rule:

```bash
# This will generate an "access denied" event if the user lacks permissions
aws s3 ls s3://some-bucket-you-dont-have-access-to \
  --profile wazuh-aws-reader
```

### Check Wazuh dashboard

1. Open your Wazuh dashboard
2. Go to **Security Events** → filter by `rule.groups: aws`
3. You should see events with `aws.source: cloudtrail`

### Check via CLI

```bash
sudo grep "aws" /var/ossec/logs/alerts/alerts.json | tail -20 | python3 -m json.tool
```

### Confirm `aws.source` is set

This is the most important check. If `aws.source` is not present in events, the 50+ built-in rules won't fire.

```bash
sudo grep "aws.source" /var/ossec/logs/alerts/alerts.json | head -5
```

---

## What You'll Monitor

Once running, Wazuh's built-in rules cover:

| Category | What's Detected |
|---|---|
| **Console logins** | Success, failure, MFA usage, brute force |
| **Root account activity** | Any API call made using root credentials |
| **Access denied** | Unauthorized API calls across all services |
| **IAM changes** | User creation/deletion, policy modifications, key rotation |
| **CloudTrail tampering** | Logging disabled, trail deleted or modified |
| **S3 changes** | Bucket policy modified, public access enabled, mass deletion |
| **KMS events** | Key disabled, deletion scheduled |
| **Network changes** | Security group modified, VPC changes |
| **AWS Config** | Configuration recorder stopped or deleted |

All rules are maintained by the Wazuh team and mapped to MITRE ATT&CK techniques.

---

## Compliance Coverage

Every AWS alert is automatically tagged with relevant compliance frameworks — usable directly as audit evidence:

| Framework | Controls Covered |
|---|---|
| **PCI DSS** | Audit logging, access control — 10.2.x, 10.6.x |
| **HIPAA** | Audit controls — 164.312.b |
| **GDPR** | Security monitoring — IV_32.2, IV_35.7.d |
| **NIST 800-53** | Access control, accountability — AC.7, AU.6, AU.14 |
| **SOC 2 / TSC** | Logical access, change management — CC6.1, CC6.8, CC7.2, CC7.3 |

In the Wazuh dashboard, filter by `rule.pci_dss`, `rule.hipaa`, `rule.gdpr`, etc. to pull compliance-specific views.

---

## Why Bucket Mode (Not SQS)

This is the most important architectural decision in this setup and the one most people get wrong.

| | Bucket Mode | SQS/Subscriber Mode |
|---|---|---|
| **`aws.source` field set** | ✅ Yes | ❌ No |
| **50+ built-in rules active** | ✅ All of them | ❌ None of them |
| **Latency** | ~5 minutes | Near real-time |
| **Setup complexity** | Low | Higher (requires SNS + SQS) |
| **Custom rules needed** | No | Yes, for everything |

SQS mode is real-time but doesn't populate the `aws.source` field that Wazuh's built-in rules use for matching. This means you'd get raw logs but zero automatic detections — you'd have to write every rule yourself and you'd inevitably have gaps.

Bucket mode's 5-minute polling delay is a worthwhile tradeoff for getting all 50+ rules working out of the box, fully maintained, MITRE-mapped, and compliance-tagged.

---

## Troubleshooting

**No events appearing after restart**

1. Check the module is running: `sudo grep "aws-s3" /var/ossec/logs/ossec.log`
2. Verify credentials work: `aws s3 ls s3://your-bucket --profile wazuh-aws-reader`
3. Check `only_logs_after` — if set to a future date, no logs will be fetched

**Events appear but no rules firing**

Check that `aws.source` is present in your events (see Step 5). If missing, your bucket `type` is not set to `cloudtrail` in ossec.conf.

**Dashboard crashing or slow**

Heap too low — revisit Step 4. Check current heap usage: `curl -s http://localhost:9200/_cat/nodes?v | grep heap`

**Old CloudTrail logs being re-processed**

Update `only_logs_after` to today's date. Wazuh uses a state file to track processed logs — if this gets corrupted, delete it: `/var/ossec/wodles/s3/buckets_s3.db`

**False positives from internal tools or automation**

Follow Step 4. Wazuh's AWS rule patterns are broad and can match log output from CI/CD systems, monitoring agents, or other internal automation. Use local rule overrides to suppress them without modifying the built-in ruleset.

---

## Infrastructure Reference

| Item | Value |
|---|---|
| Wazuh Manager | EC2 — us-east-1 |
| IAM User | `wazuh-aws-reader` |
| IAM Policy | `WazuhLeastPrivilegePolicy` |
| CloudTrail scope | All 17 AWS regions, management events |
| Polling interval | 5 minutes |
| Built-in AWS rules | 50+ |
| Heap (OpenSearch) | 6GB (increased from 2GB) |

---

## Resources

- [Wazuh AWS Module Documentation](https://documentation.wazuh.com/current/amazon/index.html)
- [Wazuh Built-in AWS Rules](https://github.com/wazuh/wazuh/tree/main/ruleset/rules) — search for `aws`
- [AWS CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
- [IAM Least Privilege Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

---

*Guide prepared by Mubashir — April 2026 | Classification: Public*

