# Fix Wazuh Alert Outage: OpenSearch Shard Limit

[![Wazuh](https://img.shields.io/badge/Wazuh-4.x-blue)](https://wazuh.com/)
[![OpenSearch](https://img.shields.io/badge/OpenSearch-1.x-green)](https://opensearch.org/)

## Problem

Your Wazuh manager suddenly stops generating alerts. Agents show as connected, but the dashboard goes silent.

**Root cause:** OpenSearch hits the default `1000 shards per node` limit due to accumulated daily `wazuh-alerts-*` indices.

**Symptoms in logs:**
```bash
sudo tail -f /var/log/filebeat/filebeat
# ERROR: this action would add [3] total shards,
# but this cluster currently has [1000]/[1000] maximum shards open
Good news: No alerts are lost – Filebeat queues them locally until the indexer is back online.

Quick Fix (Restore alerts immediately)
1. Check current shard count
bash
curl -k -u admin:your_password "https://localhost:9200/_cat/shards?h=index,shard,prirep,state" | wc -l
2. Increase shard limit temporarily
bash
curl -k -u admin:your_password -X PUT "https://localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "cluster.max_shards_per_node": 2000
  }
}'
3. Verify alerts resume
bash
sudo tail -f /var/log/filebeat/filebeat
# Look for "Published events" or "Connection established"
Permanent Fix: Automate Index Deletion with ISM
This automatically deletes alert indices older than 6 months.

1. Create ISM policy
bash
curl -k -u admin:your_password -X PUT "https://localhost:9200/_plugins/_ism/policies/wazuh" -H 'Content-Type: application/json' -d'
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
bash
curl -k -u admin:your_password -X POST "https://localhost:9200/_plugins/_ism/add/wazuh-alerts-*" -H 'Content-Type: application/json' -d'
{
  "policy_id": "wazuh"
}'
3. Verify policy is applied
bash
curl -k -u admin:your_password "https://localhost:9200/wazuh-alerts-4.x-2026.03.01/_plugins/_ism/explain"
4. Ensure future indices get the policy (check template)
bash
curl -k -u admin:your_password "https://localhost:9200/_index_template/wazuh-alerts-template?pretty" | grep -A 2 "policy_id"
If missing, add it:

bash
curl -k -u admin:your_password -X PUT "https://localhost:9200/_index_template/wazuh-alerts-template" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["wazuh-alerts-*"],
  "template": {
    "settings": {
      "index.plugins.index_state_management.policy_id": "wazuh"
    }
  },
  "composed_of": ["wazuh-alerts-mappings"]
}'
Customize Retention Period
Change min_index_age in the policy:

Retention	Value
30 days	"30d"
90 days	"90d"
180 days	"180d"
1 year	"365d"
Verify Everything is Working
Check total shard count
bash
curl -k -u admin:your_password "https://localhost:9200/_cluster/health?pretty"
Monitor Filebeat in real time
bash
sudo tail -f /var/log/filebeat/filebeat
Watch indices being deleted automatically
bash
watch -n 10 'curl -k -u admin:your_password "https://localhost:9200/_cat/indices/wazuh-alerts-*?v" | wc -l'
Security: Change Exposed Admin Password
If your password was exposed, change it immediately:

bash
# Generate new hash
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh

# Edit internal users file
sudo vi /etc/wazuh-indexer/opensearch-security/internal_users.yml

# Apply changes
cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools/
sudo ./securityadmin.sh -cd ../../../security/ -icl -nhnv -cacert ../../../config/root-ca.pem -cert ../../../config/kirk.pem -key ../../../config/kirk-key.pem

# Update Filebeat config
sudo vi /etc/filebeat/filebeat.yml
sudo systemctl restart filebeat
FAQ
Q: Do I lose alerts during the outage?
A: No. Filebeat queues them locally and retries until successful.

Q: Can I set retention shorter than 30 days?
A: Yes – use "7d" for weekly deletion.

Q: Will this affect performance?
A: Deleting old indices improves performance by reducing shard count and disk usage.

Q: What if I need to keep data longer than 6 months?
A: Increase min_index_age accordingly, but monitor disk space and shard count.

Q: Does this work with Elasticsearch instead of OpenSearch?
A: Yes, but use the ILM endpoint (/_ilm/policy) instead of /_plugins/_ism.

Contributing
Open an issue or PR for improvements.

License
MIT

Support
Wazuh Documentation

OpenSearch ISM Guide