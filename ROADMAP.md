# Bro Hunter Roadmap

## Current State (Reality Check - Feb 21, 2026)

Core platform is much further along than the old roadmap implied.

### Already Built
- Zeek + Suricata log ingestion
- PCAP upload and workflow pipeline (`/api/v1/ingest/pcap`, `/api/v1/workflow/upload-and-analyze`)
- Explainable threat scoring + tuning endpoints/UI
- MITRE ATT&CK mapping
- Beaconing detection
- DNS threat analysis (DGA, tunneling, fast-flux)
- Threat timeline + host risk timeline
- Session reconstruction (API + UI)
- IOC export (CSV, STIX, OpenIOC)
- TLS intelligence (JA3/JA3S + certificate anomaly analysis)
- HTTP anomaly analysis
- Lateral movement detection
- Webhook management (Discord/Slack/generic)
- PDF report generation
- Hunt hypotheses
- Finding annotations
- Trend analysis
- Sigma import/conversion
- Live capture (tcpdump to PCAP)

---

## Phase 1: Core Hardening ✅ COMPLETE
- [x] PCAP upload and auto-parse
- [x] Threat timeline view
- [x] IOC export (CSV, STIX 2.1, Suricata rules/OpenIOC)
- [x] Scoring engine tuning UI
- [x] Session reconstruction

## Phase 2: Detection Expansion ✅ COMPLETE
- [x] JA3/JA3S fingerprinting
- [x] SSL certificate anomaly detection
- [x] Lateral movement detection
- [x] Data exfiltration scoring
- [x] HTTP anomaly detection

## Phase 3: Integration 🚧 IN PROGRESS (STARTED)
- [ ] MCP server integration (query Bro Hunter from Claude/GPT)
- [x] TheHive case creation from findings/cases (initial API wiring)
- [ ] Wazuh alert correlation (match network IOCs against host-based alerts)
- [ ] MISP feed import (enrich findings with known threat intel)
- [x] Webhook alerts (Slack/Discord/generic)

## Phase 4: Live Operations
- [ ] Live Zeek log tailing (real-time analysis, not just archived)
- [ ] Suricata EVE JSON streaming
- [ ] Dashboard auto-refresh with new findings
- [ ] Alert suppression rules
- [ ] Multi-sensor support

## Phase 5: Reporting & Collaboration
- [x] PDF investigation reports
- [x] Hunt hypothesis templates
- [x] Finding annotations
- [ ] Collaborative hunting (multi-analyst workflows)
- [x] Trend analysis (week-over-week)

## Stretch Goals
- [x] Sigma rule support
- [ ] YARA integration for payload inspection
- [ ] Network topology inference from traffic patterns
- [ ] ML baseline (normal vs anomalous profiling at production depth)

---

## Next Up (Immediate)
1. Wazuh correlation endpoint and matching pipeline
2. MISP feed import/enrichment
3. MCP server wrapper for agent-native querying
