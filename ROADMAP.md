# Bro Hunter Roadmap

## Current State (v0.1 - Concept Build)
- Zeek + Suricata log ingestion
- Explainable threat scoring engine
- MITRE ATT&CK technique mapping
- Beaconing detection (periodicity analysis)
- DNS threat analysis (DGA, tunneling, fast-flux)
- 5 visual themes
- Offline log analysis

## Phase 1: Core Hardening
- [ ] PCAP upload and auto-parse (drag-drop a .pcap, get results)
- [ ] Threat timeline view (chronological attack narrative)
- [ ] IOC export (CSV, STIX 2.1, Suricata rules)
- [ ] Scoring engine tuning UI (adjust weights without touching code)
- [ ] Session reconstruction (follow a single host through all its connections)

## Phase 2: Detection Expansion
- [ ] JA3/JA3S fingerprinting (TLS client/server fingerprints)
- [ ] SSL certificate anomaly detection (self-signed, expired, mismatched CN)
- [ ] Lateral movement detection (SMB, RDP, WMI patterns across internal hosts)
- [ ] Data exfiltration scoring (unusual upload volumes, encoding patterns)
- [ ] HTTP anomaly detection (user-agent analysis, unusual methods, large POSTs)

## Phase 3: Integration
- [ ] MCP server integration (query Bro Hunter from Claude/GPT)
- [ ] TheHive case creation from findings
- [ ] Wazuh alert correlation (match network IOCs against host-based alerts)
- [ ] MISP feed import (enrich findings with known threat intel)
- [ ] Webhook alerts (Slack, Discord, Telegram on high-severity findings)

## Phase 4: Live Operations
- [ ] Live Zeek log tailing (real-time analysis, not just archived)
- [ ] Suricata EVE JSON streaming
- [ ] Dashboard auto-refresh with new findings
- [ ] Alert suppression rules (reduce noise for known-good traffic)
- [ ] Multi-sensor support (ingest from multiple Zeek/Suricata instances)

## Phase 5: Reporting
- [ ] PDF investigation reports (executive summary + technical detail)
- [ ] Hunt hypothesis templates (structured hunting workflows)
- [ ] Finding annotations (analyst notes attached to specific events)
- [ ] Collaborative hunting (multiple analysts, shared findings)
- [ ] Trend analysis (week-over-week threat landscape for your network)

## Stretch Goals
- [ ] Sigma rule support (convert Sigma to Suricata/Zeek queries)
- [ ] YARA integration for payload inspection
- [ ] Network topology inference from traffic patterns
- [ ] Machine learning baseline (normal vs anomalous traffic profiles)
