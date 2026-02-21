# Bro Hunter Roadmap

## Reality Check (Feb 21, 2026)
You're right. We are **past Phase 3**.

Based on commit history, the project has already completed:
- Phase 1A: PCAP Upload + Threat Timeline
- Phase 1B: IOC Export + Session Reconstruction + Scoring Tuner
- Phase 2: Threat Intel + Reports + Analytics + Live Capture
- Phase 3: PCAP Workflow + Settings + Search + Notifications
- Phase 4A: Packet Inspector + Demo Mode + Dashboard polish
- Phase 4B: Custom Detection Rules + Sigma Import
- Phase 4C/4D: Case Management + Add-to-Case flows
- Phase 5: Reporting + Analyst Workflow + Trends + Host Deep Dive
- Phase 6: Detection Depth + Integration Polish

## Phase 7: External Integrations (Current)
- [x] TheHive case export endpoint scaffold (`/api/v1/integrations/thehive/cases/from-case/{case_id}`)
- [x] Wazuh alert correlation endpoint (case IOC matching against host alerts)
- [ ] MISP feed import and enrichment
- [ ] MCP server wrapper for agent-native querying

## Phase 8: Live Operations
- [ ] Live Zeek log tailing (realtime, not batch)
- [ ] Suricata EVE streaming ingest
- [ ] Dashboard auto-refresh with incremental findings
- [ ] Alert suppression/noise controls
- [ ] Multi-sensor support

## Phase 9: Team Workflow
- [x] PDF reports
- [x] Hunt hypotheses
- [x] Annotations
- [x] Trend analysis
- [ ] Collaborative analyst workflow (shared queues/assignment locking)

## Immediate Next Build
1. Wazuh correlation service + router
2. MISP enrichment pipeline
3. MCP wrapper API
