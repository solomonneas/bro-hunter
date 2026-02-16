# Phase 4A PRD: PCAP Deep-Dive + Dashboard Polish

## Context
Bro Hunter is at Phase 3 (workflow wizard, global search, settings, notifications). Phase 4A adds packet-level inspection and upgrades the dashboard visuals. The app runs on Railway (brohunter.solomonneas.dev) with graceful degradation when Zeek/Suricata aren't installed.

## Existing Architecture
- Backend: FastAPI at `api/`, routers in `api/routers/`, services in `api/services/`
- Frontend: React+TS+Vite+Tailwind in `web/`, V3 variant is root, sidebar nav
- Config: `api/config.py` (pydantic-settings), env prefix `BROHUNTER_`
- Data: Zeek JSON logs in `data/real-sample/` and `data/zeek/`
- State: Custom pub/sub store (NOT zustand)
- Railway: Python 3.12 + Node 20, SPA served by FastAPI catch-all
- Rate limiting already in place

## Demo Data Strategy
- Ship sanitized real Zeek logs in `data/demo/` (scrubbed from `data/real-sample/`)
- Scrub: replace real IPs with RFC5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), randomize UIDs, strip any hostnames
- Backend: add `BROHUNTER_DEMO_MODE=true` env var. When set, auto-loads demo data on startup
- Frontend: add a "Demo Mode" / "Live Mode" toggle in Settings page. Demo mode uses bundled data; Live mode expects local Zeek/Suricata
- Show a subtle banner "Running with sanitized demo data" when in demo mode

## Feature 1: PCAP Deep-Dive (Packet Inspector)

### Backend (`api/routers/packets.py`, `api/services/packet_inspector.py`)
- `GET /api/v1/packets/{connection_uid}` — return packet-level details for a connection
  - Parse from Zeek conn.log enriched with associated logs (dns, http, ssl, files)
  - Return: timestamps, src/dst with ports, protocol details, payload size per packet, flags
  - For HTTP: method, URI, status, user-agent, content-type
  - For DNS: query, response, TTL
  - For SSL/TLS: server_name, cipher, certificate chain summary
- `GET /api/v1/packets/{connection_uid}/flow` — bidirectional flow timeline
  - Ordered list of events (conn start, DNS query, HTTP request, alert, conn end)
  - Each event has: timestamp, direction (orig→resp / resp→orig), type, summary
- `GET /api/v1/packets/payload-preview/{connection_uid}` — safe payload preview
  - Hex + ASCII dump style (like Wireshark packet bytes pane)
  - For demo mode: generate synthetic payload previews
  - Max 4KB preview, truncate with indicator
- In demo mode, all endpoints return realistic mock data derived from the demo dataset

### Frontend (`web/src/components/PacketInspector.tsx`, `web/src/variants/v3/pages/PacketView.tsx`)
- New sidebar page: "Packet View" (or accessible by clicking any connection row)
- **Connection Summary Header**: src ↔ dst, protocol, duration, bytes, threat score
- **Flow Visualization**: vertical timeline showing bidirectional events
  - Left side = originator, right side = responder
  - Color-coded by event type (DNS=blue, HTTP=green, Alert=red, TLS=purple)
  - Timestamps on center spine
- **Protocol Details Panel**: tabbed view (HTTP | DNS | TLS | Files | Raw)
  - Each tab shows parsed protocol-specific fields
- **Hex/ASCII Payload Viewer**: monospace grid, highlighted bytes for pattern matches
  - Toggle between hex, ASCII, and combined view
- **"Drill from anywhere" pattern**: any connection ID in the app becomes a clickable link to this view

## Feature 2: Dashboard Polish (Charts + UX)

### Install recharts
```bash
cd web && npm install recharts
```

### Upgrade `web/src/components/AnalyticsDashboard.tsx`
- Replace current bar charts with recharts:
  - **Protocol Breakdown**: horizontal bar chart with gradient fills
  - **Top Talkers**: bar chart, clickable bars → filter to that IP
  - **Traffic Timeline**: area chart with brush (zoomable time range)
  - **Threat Heatmap**: keep current table but add color intensity scaling
- Add **Threat Score Distribution** chart: histogram of all scored connections
- Add **MITRE Coverage Radar**: radar chart showing technique coverage across tactics
- All charts: dark theme (bg transparent, grid #2a2a38, text #888), consistent color palette matching V3 theme

### Dashboard page (`web/src/variants/v3/pages/Dashboard.tsx`)
- Add summary stat cards at top: Total Connections, Threats Found, Avg Score, Top Protocol, Demo/Live indicator
- Responsive grid: 2 cols on desktop, 1 col on mobile
- Smooth entry animations (CSS only, no framer-motion dep)

### Global UX Polish
- Loading skeletons for all data-fetching components (pulse animation)
- Empty states with helpful messaging ("Upload a PCAP or enable demo mode to get started")
- Consistent error boundaries per-panel (don't crash the whole page)

## New Sidebar Entry
Add "Packets" between "Sessions" and "Analytics" in the V3 sidebar nav.

## Files to Create
- `api/services/packet_inspector.py` — packet detail extraction + demo mock data
- `api/services/demo_data.py` — demo data loader, IP scrubber, synthetic payloads
- `api/routers/packets.py` — REST endpoints
- `web/src/components/PacketInspector.tsx` — main packet view component
- `web/src/components/FlowTimeline.tsx` — bidirectional flow visualization
- `web/src/components/HexViewer.tsx` — hex/ASCII payload viewer
- `web/src/components/LoadingSkeleton.tsx` — reusable skeleton component
- `web/src/variants/v3/pages/Packets.tsx` — page wrapper
- `data/demo/` — sanitized demo logs (conn, dns, http, notice)
- `api/services/ip_scrubber.py` — one-time script to sanitize real-sample → demo

## Files to Modify
- `api/main.py` — add packets router, demo data init
- `api/config.py` — add `demo_mode: bool = False` setting
- `web/src/variants/v3/Layout.tsx` — add Packets to sidebar
- `web/src/variants/v3/pages/Dashboard.tsx` — upgrade with recharts
- `web/src/components/AnalyticsDashboard.tsx` — recharts upgrade
- `web/src/variants/v3/pages/Settings.tsx` — add Demo/Live toggle
- `web/package.json` — add recharts dependency

## Tests
- `tests/test_packet_inspector.py`
- `tests/test_demo_data.py`

## DO NOT
- Use zustand (project uses custom pub/sub store)
- Add framer-motion (CSS animations only)
- Break existing API endpoints
- Include real IPs/hostnames in demo data
- Use Sonnet model
