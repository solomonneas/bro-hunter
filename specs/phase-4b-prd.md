# Phase 4B PRD: Alerting/Rules + Sigma Import

## Context
Bro Hunter Phase 4A adds packet inspection + dashboard polish. Phase 4B adds custom detection rules and Sigma rule import for threat hunting workflows.

## Existing Architecture
- Backend: FastAPI at `api/`, routers in `api/routers/`, services in `api/services/`
- Frontend: React+TS+Vite+Tailwind in `web/`, V3 variant is root, sidebar nav
- Config: `api/config.py` (pydantic-settings), env prefix `BROHUNTER_`
- State: Custom pub/sub store (NOT zustand)
- Data: Zeek JSON logs + demo data in `data/demo/`
- Sidebar nav: `web/src/variants/v3/Layout.tsx`

## Feature 1: Custom Detection Rules Engine

### Backend (`api/services/rule_engine.py`, `api/routers/rules.py`)
- Rule model: `{ id, name, description, severity (low/medium/high/critical), enabled, conditions[], actions[], created_at, updated_at, hit_count }`
- Conditions: field-based matching against connection/DNS/HTTP data
  - Operators: eq, neq, contains, regex, gt, lt, in, not_in, cidr_match
  - Fields: src_ip, dst_ip, src_port, dst_port, proto, conn_state, service, dns_query, http_method, http_uri, http_status, user_agent, tls_server_name, bytes_orig, bytes_resp, duration
  - Logical grouping: AND/OR between conditions
- Actions: tag, set_severity, add_to_hunt, alert
- `POST /api/v1/rules` — create rule
- `GET /api/v1/rules` — list all rules
- `PUT /api/v1/rules/{id}` — update rule
- `DELETE /api/v1/rules/{id}` — delete rule
- `POST /api/v1/rules/{id}/test` — test rule against current dataset, return matches
- `POST /api/v1/rules/evaluate` — run all enabled rules against loaded data
- Rules stored in `data/rules.json` (JSON file, no DB needed)
- Rule evaluation: iterate connections, apply condition tree, collect matches

### Frontend (`web/src/components/RuleBuilder.tsx`, `web/src/variants/v3/pages/Rules.tsx`)
- **Rule List View**: table of all rules with name, severity badge, enabled toggle, hit count, actions (edit/delete/test)
- **Rule Builder**: visual condition builder
  - Add condition rows: [field dropdown] [operator dropdown] [value input]
  - AND/OR toggle between condition groups
  - Severity selector (color-coded: green/yellow/orange/red)
  - Action checkboxes
  - "Test Rule" button: shows match count + sample matches inline
- **Rule Templates**: pre-built rules for common threats
  - C2 Beaconing (regular intervals to external IP)
  - DNS Tunneling (long query names, high entropy)
  - Large Data Exfil (bytes_resp > threshold to external)
  - Port Scanning (many dst_ports from same src)
  - Suspicious User-Agent (contains curl/wget/python-requests)

## Feature 2: Sigma Rule Import

### Backend (`api/services/sigma_converter.py`, `api/routers/sigma.py`)
- `POST /api/v1/sigma/import` — upload Sigma YAML, convert to Bro Hunter rule format
- `POST /api/v1/sigma/import-batch` — upload multiple Sigma files
- `GET /api/v1/sigma/templates` — list bundled Sigma rules
- Sigma YAML parser: extract detection logic (selection, condition, filter)
- Map Sigma fields to Bro Hunter fields (e.g., `DestinationIp` → `dst_ip`, `DestinationPort` → `dst_port`)
- Handle Sigma modifiers: `contains`, `startswith`, `endswith`, `re`, `all`, `base64`
- Bundle 10-15 network-focused Sigma rules in `data/sigma/` for demo
  - DNS tunneling detection
  - Suspicious outbound connections
  - Known C2 ports
  - TOR exit node connections
  - Crypto mining pool connections
  - ICMP tunneling
  - DNS over HTTPS
  - Beaconing patterns
  - Large DNS TXT records
  - Unusual protocol on standard ports

### Frontend additions to Rules page
- "Import Sigma" button: file upload dialog (accepts .yml/.yaml)
- Imported rules show "Sigma" badge
- Preview before import: show parsed conditions + field mapping

## New Sidebar Entry
Add "Rules" between "Tuning" and "Settings" in V3 sidebar nav.

## Files to Create
- `api/services/rule_engine.py` — rule CRUD, evaluation engine, condition matching
- `api/services/sigma_converter.py` — Sigma YAML to Bro Hunter rule converter
- `api/routers/rules.py` — rule CRUD endpoints
- `api/routers/sigma.py` — Sigma import endpoints
- `web/src/components/RuleBuilder.tsx` — visual rule builder component
- `web/src/components/SigmaImport.tsx` — Sigma file upload + preview
- `web/src/variants/v3/pages/Rules.tsx` — page wrapper
- `data/sigma/` — bundled Sigma rule YAML files (10-15 rules)
- `data/rules.json` — empty initial rules store
- `tests/test_rule_engine.py`
- `tests/test_sigma_converter.py`

## Files to Modify
- `api/main.py` — add rules + sigma routers
- `web/src/variants/v3/Layout.tsx` — add Rules to sidebar

## DO NOT
- Use zustand (custom pub/sub store)
- Add framer-motion
- Break existing endpoints
- Import heavy Sigma libraries (write a lightweight parser)
