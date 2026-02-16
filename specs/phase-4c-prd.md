# Phase 4C PRD: Case Management + Investigation Bundles

## Context
Bro Hunter Phases 4A-4B add packet inspection, dashboard polish, and detection rules. Phase 4C adds the ability to save hunts as cases, annotate findings, and export investigation bundles.

## Existing Architecture
- Backend: FastAPI at `api/`, routers in `api/routers/`, services in `api/services/`
- Frontend: React+TS+Vite+Tailwind in `web/`, V3 variant is root, sidebar nav
- Config: `api/config.py` (pydantic-settings), env prefix `BROHUNTER_`
- State: Custom pub/sub store (NOT zustand)
- Sidebar nav: `web/src/variants/v3/Layout.tsx`

## Feature 1: Case Management

### Backend (`api/services/case_manager.py`, `api/routers/cases.py`)
- Case model:
```python
{
    "id": "uuid",
    "title": "string",
    "description": "string",
    "status": "open|investigating|escalated|resolved|closed",
    "severity": "low|medium|high|critical",
    "assignee": "string (optional)",
    "tags": ["string"],
    "created_at": "datetime",
    "updated_at": "datetime",
    "findings": [Finding],
    "notes": [Note],
    "timeline": [TimelineEvent],
    "iocs": [IOC],
    "related_connections": ["uid"],
    "related_rules": ["rule_id"],
    "attachments": [Attachment]
}
```
- Finding model: `{ id, type (connection|dns|alert|rule_match|manual), summary, severity, data (json), added_at }`
- Note model: `{ id, content (markdown), author, created_at, updated_at }`
- TimelineEvent model: `{ id, timestamp, event_type, description, auto_generated (bool) }`
- Endpoints:
  - `POST /api/v1/cases` — create case
  - `GET /api/v1/cases` — list cases (filterable by status, severity, tags)
  - `GET /api/v1/cases/{id}` — get case detail
  - `PUT /api/v1/cases/{id}` — update case metadata
  - `DELETE /api/v1/cases/{id}` — delete case
  - `POST /api/v1/cases/{id}/findings` — add finding to case
  - `POST /api/v1/cases/{id}/notes` — add note
  - `PUT /api/v1/cases/{id}/notes/{note_id}` — edit note
  - `POST /api/v1/cases/{id}/iocs` — add IOC to case
  - `GET /api/v1/cases/{id}/timeline` — get auto-generated timeline
- Cases stored in `data/cases/` directory (one JSON file per case)
- Auto-timeline: automatically log events when findings/notes/IOCs are added or status changes

### Frontend (`web/src/variants/v3/pages/Cases.tsx`, `web/src/components/CaseDetail.tsx`)
- **Case List View**: 
  - Card grid or table view toggle
  - Status badges (color-coded), severity indicators
  - Quick filters: status, severity, date range
  - "New Case" button
- **Case Detail View**:
  - Header: title, status dropdown, severity dropdown, tags (editable)
  - Tabbed content: Findings | Notes | IOCs | Timeline
  - **Findings tab**: list of linked connections/alerts/rule matches with "View" links to relevant pages
  - **Notes tab**: markdown editor (simple textarea + preview toggle), chronological list
  - **IOCs tab**: table of extracted IOCs with type (IP, domain, hash, URL), value, source, verdict
  - **Timeline tab**: vertical timeline showing all case events chronologically
- **"Add to Case" action**: available throughout the app
  - On connection rows → "Add to Case" button → case selector dropdown
  - On threat entries → same pattern
  - On rule match results → same pattern
  - Creates a Finding automatically with context

## Feature 2: Investigation Bundle Export

### Backend (`api/services/bundle_exporter.py`, `api/routers/bundles.py`)
- `POST /api/v1/cases/{id}/export` — generate investigation bundle
- Bundle formats:
  - **JSON**: full case data + all findings + notes + IOCs + related connection data
  - **HTML**: self-contained investigation report (dark theme, printable)
    - Executive summary section
    - Finding details with evidence
    - IOC table
    - Timeline visualization
    - MITRE ATT&CK mapping if techniques were identified
    - Notes section
  - **STIX 2.1**: case as STIX Report object, IOCs as Indicators, relationships
- `GET /api/v1/cases/{id}/export/html` — preview HTML report in browser
- HTML report: standalone (all CSS inline), professional dark theme matching V3 style

### Frontend additions
- "Export" dropdown button on case detail page: JSON, HTML, STIX
- HTML preview opens in new tab
- Download buttons for JSON and STIX

## New Sidebar Entry
Add "Cases" between "Reports" and "Tuning" in V3 sidebar nav.

## Files to Create
- `api/services/case_manager.py` — case CRUD, finding management, auto-timeline
- `api/services/bundle_exporter.py` — JSON/HTML/STIX export
- `api/routers/cases.py` — case endpoints
- `api/routers/bundles.py` — export endpoints
- `web/src/components/CaseDetail.tsx` — case detail view with tabs
- `web/src/components/CaseCard.tsx` — case card for list view
- `web/src/components/AddToCase.tsx` — reusable "Add to Case" dropdown button
- `web/src/components/MarkdownEditor.tsx` — simple textarea + preview for notes
- `web/src/components/CaseTimeline.tsx` — vertical timeline component
- `web/src/variants/v3/pages/Cases.tsx` — page wrapper with list + detail routing
- `data/cases/` — directory for case JSON files (create empty)
- `tests/test_case_manager.py`
- `tests/test_bundle_exporter.py`

## Files to Modify
- `api/main.py` — add cases + bundles routers
- `web/src/variants/v3/Layout.tsx` — add Cases to sidebar
- Various existing pages (Connections, Threats, HuntResults) — add "Add to Case" button

## DO NOT
- Use zustand (custom pub/sub store)
- Add framer-motion or heavy markdown libraries (simple textarea + dangerouslySetInnerHTML with basic markdown regex is fine)
- Break existing endpoints
- Over-engineer the markdown editor (textarea + preview toggle is enough)
