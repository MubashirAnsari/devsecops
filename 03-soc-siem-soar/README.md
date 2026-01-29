# SOC Visibility with SIEM & SOAR – Case Study

## Context
After strengthening access control (Jump Server) and secrets management (Passbolt), the next critical gap became clear:
**limited visibility into what was actually happening across systems**.

Logs existed, but they were:
- Distributed across hosts and services
- Hard to correlate during investigations
- Often reviewed only after incidents occurred

This made detection reactive and investigations time-consuming.

## Objective
The goal was to build a **practical SOC capability** focused on visibility, detection, and response — not just log collection.

Key objectives:
- Centralize security-relevant logs
- Detect suspicious activity instead of relying on assumptions
- Enable structured incident handling
- Lay the foundation for automated response

## Approach
In collaboration with the **Catalytic team**, and with strong support from **Sulaiman**, we designed and implemented an end-to-end **SIEM and SOAR workflow**.

The stack included:
- **Wazuh** – centralized log collection and security monitoring
- **TheHive** – incident management, case tracking, and triage
- **Shuffle** – security automation and response orchestration
- **MISP & Cortex** – threat intelligence sharing and alert enrichment

The focus was on **signal quality**, clear workflows, and repeatable response processes rather than generating excessive alerts.

## Outcome
- Centralized visibility across systems and workloads
- Improved detection of security-relevant events
- Faster and more structured incident investigations
- Reduced manual effort through automation
- More confidence during incident response and reviews

This shifted the security posture from reactive firefighting toward proactive monitoring and response.

## Key Learnings
- Visibility changes how security decisions are made
- SIEM is only effective when paired with clear processes
- Automation amplifies good workflows, not bad ones
- Collaboration is critical for building mature SOC capabilities

## Control Alignment
- ISO 27001:2022 – Logging & Monitoring
- Incident Detection & Response
- Security Event Management
- Continuous Monitoring & Improvement

## Notes
This case study is intentionally anonymized and generalized.
No real alerts, logs, IPs, system names, configurations, or proprietary details are included.

The focus is on **security architecture, decision-making, and outcomes** rather than implementation specifics.
