# 🚨 Fix Wazuh Alert Outage: OpenSearch Shard Limit

[![Wazuh](https://img.shields.io/badge/Wazuh-4.x-blue)](https://wazuh.com/)
[![OpenSearch](https://img.shields.io/badge/OpenSearch-1.x-green)](https://opensearch.org/)

---

## 📌 Problem

Your Wazuh manager suddenly stops generating alerts. Agents show as connected, but the dashboard goes silent.

**Root cause:** OpenSearch hits the default `1000 shards per node` limit due to accumulated daily `wazuh-alerts-*` indices.

---

## ⚠️ Symptoms in Logs

```bash
sudo tail -f /var/log/filebeat/filebeat

Example error:

ERROR: this action would add [3] total shards,
but this cluster currently has [1000]/[1000] maximum shards open

⚡ Quick Fix (Restore Alerts Immediately)

1. Check current shard count

curl -k -u admin:your_password \
"https://localhost:9200/_cat/shards?h=index,shard,prirep,state" | wc -l

2. Increase shard limit temporarily

curl -k -u admin:your_password -X PUT \
"https://localhost:9200/_cluster/settings" \
-H 'Content-Type: application/json' -d'
{
  "persistent": {
    "cluster.max_shards_per_node": 2000
  }
}'

3. Verify alerts resume

sudo tail -f /var/log/filebeat/filebeat

Look for:

Published events
Connection established

🛠️ Permanent Fix: Automate Index Deletion with ISM

This automatically deletes alert indices older than 6 months.

1. Create ISM policy

curl -k -u admin:your_password -X PUT \
"https://localhost:9200/_plugins/_ism/policies/wazuh" \
-H 'Content-Type: application/json' -d'
{
  "policy": {
    "description": "Delete Wazuh alert indices after 6 months",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": {
              "min_index_age": "180d"
            }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [
          {
            "delete": {}
          }
        ],
        "transitions": []
      }
    ],
    "ism_template": {
      "index_patterns": ["wazuh-alerts-*"],
      "priority": 100
    }
  }
}'

2. Attach policy to existing indices

curl -k -u admin:your_password -X POST \
"https://localhost:9200/_plugins/_ism/add/wazuh-alerts-*" \
-H 'Content-Type: application/json' -d'
{
  "policy_id": "wazuh"
}'

3. Verify policy is applied

curl -k -u admin:your_password \
"https://localhost:9200/wazuh-alerts-4.x-2026.03.01/_plugins/_ism/explain"

4. Ensure future indices get the policy (check template)

curl -k -u admin:your_password \
"https://localhost:9200/_index_template/wazuh-alerts-template?pretty" | grep -A 2 "policy_id"

If missing, add it:

curl -k -u admin:your_password -X PUT \
"https://localhost:9200/_index_template/wazuh-alerts-template" \
-H 'Content-Type: application/json' -d'
{
  "index_patterns": ["wazuh-alerts-*"],
  "template": {
    "settings": {
      "index.plugins.index_state_management.policy_id": "wazuh"
    }
  },
  "composed_of": ["wazuh-alerts-mappings"]
}'

⏳ Customize Retention Period

Change min_index_age in the policy:

Retention	Value
30 days	    "30d"
90 days	    "90d"
180 days	"180d"
1 year	    "365d"

✅ Verify Everything is Working

Check total shard count

curl -k -u admin:your_password \
"https://localhost:9200/_cluster/health?pretty"

Monitor Filebeat in real time

sudo tail -f /var/log/filebeat/filebeat

## Note for Archives

If you have archives enabled in Filebeat (`/etc/filebeat/filebeat.yml`), apply the same ISM policy to `wazuh-archives-*` indices:

```bash
curl -k -u admin:your_password -X POST "https://localhost:9200/_plugins/_ism/add/wazuh-archives-*" -H 'Content-Type: application/json' -d'
{
  "policy_id": "wazuh"
}'
Also update the index_patterns in the policy to include both patterns:
"index_patterns": ["wazuh-alerts-*", "wazuh-archives-*"]

🤝 Contributing

Open an issue or PR for improvements.

📄 License

MIT
