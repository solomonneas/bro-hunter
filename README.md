<p align="center">
  <img src="https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=white" alt="React" />
  <img src="https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript" />
  <img src="https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Tailwind_CSS-3-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white" alt="Tailwind CSS" />
  <img src="https://img.shields.io/badge/Vite-7-646CFF?style=flat-square&logo=vite&logoColor=white" alt="Vite" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License" />
</p>

# 🎯 Solomon's Bro Hunter

**Hunt threats in network traffic with explainable scoring and MITRE ATT&CK mapping.**

Bro Hunter is a threat hunting platform that processes Zeek and Suricata network logs to identify threats, score them with explainable AI, and correlate indicators across MITRE ATT&CK techniques. Built for network forensics teams who need to see the evidence.

![Bro Hunter](docs/screenshots/dashboard.png)

---

## Features

- **Zeek & Suricata Log Analysis** - Parse network logs and extract threat indicators
- **Explainable Threat Scoring** - AI-powered scores with reasoning chain included
- **MITRE ATT&CK Mapping** - Automatic technique and tactic correlation
- **Beaconing Detection** - Identify periodic C2 communication patterns
- **DNS Threat Analysis** - Detect DGA, tunneling, and fast-flux networks
- **Network Forensics** - Drill into flow data, DNS queries, and SSL certificates
- **5 Visual Themes** - Tactical, Analyst, Terminal, Command, Cyber variants
- **Offline-First** - Works with archived logs, no live streaming required

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/solomonneas/bro-hunter.git
cd bro-hunter

# Install and run frontend
npm install
npm run dev

# In another terminal, start the backend
cd api
pip install -r requirements.txt
python main.py
```

Frontend runs on **http://localhost:5174**
Backend API on **http://localhost:8000**

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | React 18 | Interactive dashboards |
| **Language** | TypeScript 5 | Type safety |
| **Styling** | Tailwind CSS 3 | Utility-first CSS |
| **Charts** | Recharts | Threat visualization and timeline graphs |
| **Data** | TanStack Query | Async data fetching and caching |
| **Bundler** | Vite 7 | Dev server and build |
| **Backend** | FastAPI | REST API and log processing |
| **Compute** | Python 3.9+ | Threat scoring algorithms |
| **Icons** | Lucide React | Consistent icon set |

---

## Threat Scoring

Bro Hunter uses a multi-factor scoring system:

1. **Indicator Confidence** - IOC reputation across sources
2. **Behavior Match** - Pattern recognition (beaconing, tunneling, etc.)
3. **Evidence Weight** - How much supporting data backs the score
4. **MITRE Alignment** - Technique frequency and criticality

Scores range from 0 (benign) to 100 (critical threat) with a clear reasoning chain explaining each component.

---

## Project Structure

```text
bro-hunter/
├── web/                      # React frontend
│   ├── src/
│   │   ├── components/       # Reusable UI components
│   │   ├── pages/            # Page views (Dashboard, Threats, Analysis)
│   │   ├── store/            # Zustand state store
│   │   ├── utils/            # Helpers (scoring, parsing, formatting)
│   │   └── variants/         # 5 theme variants
│   ├── package.json
│   └── vite.config.ts
├── api/                      # FastAPI backend
│   ├── main.py               # Entry point
│   ├── parsers/              # Log parsers (Zeek, Suricata)
│   ├── scoring/              # Threat scoring module
│   ├── mitre/                # ATT&CK correlation
│   └── requirements.txt
├── data/                     # Sample logs and fixtures
└── README.md
```

---

## Logs Ingestion

Place Zeek or Suricata logs in the `data/` directory and import them via the dashboard:

**Zeek logs:** `conn.log`, `dns.log`, `ssl.log`, `http.log`
**Suricata:** `eve.json` (JSON output format)

The backend parses and indexes them for fast querying.

---

## Rate Limiting

PCAP uploads are rate-limited by default to prevent abuse on public deployments:

- **5 uploads per hour** per IP
- **15 uploads per day** per IP

### Configuration

Control rate limiting via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `BROHUNTER_RATE_LIMIT_ENABLED` | `true` | Set to `false` to disable rate limiting entirely |
| `BROHUNTER_RATE_LIMIT_HOURLY` | `5` | Max uploads per hour per IP |
| `BROHUNTER_RATE_LIMIT_DAILY` | `15` | Max uploads per day per IP |

### Self-Hosted / Cloned Deployments

If you're running Bro Hunter on your own infrastructure and don't need rate limiting:

```bash
# Disable rate limiting entirely
export BROHUNTER_RATE_LIMIT_ENABLED=false

# Or increase the limits
export BROHUNTER_RATE_LIMIT_HOURLY=100
export BROHUNTER_RATE_LIMIT_DAILY=500
```

In Docker / Railway, set these as environment variables in your deployment config.

---

## Integrations (Phase 7)

Bro Hunter now includes initial external integration endpoints for TheHive, Wazuh, and MISP.

### Environment Variables

Set these on the API service:

```bash
# TheHive
THEHIVE_URL=https://thehive.example.com
THEHIVE_API_KEY=your_thehive_api_key
THEHIVE_AUTH_SCHEME=Bearer

# Wazuh
WAZUH_URL=https://wazuh.example.com
WAZUH_API_KEY=your_wazuh_api_key
WAZUH_AUTH_SCHEME=Bearer
WAZUH_ALERTS_PATH=/alerts

# MISP
MISP_URL=https://misp.example.com
MISP_API_KEY=your_misp_api_key
MISP_SEARCH_PATH=/attributes/restSearch
```

### Endpoints

- `GET /api/v1/integrations/status`
- `POST /api/v1/integrations/thehive/cases/from-case/{case_id}`
- `POST /api/v1/integrations/wazuh/correlate/case/{case_id}?limit_per_ioc=25`
- `POST /api/v1/integrations/misp/enrich/case/{case_id}?limit_per_ioc=25`

### Example cURL

```bash
# Check integration config status
curl -s http://localhost:8000/api/v1/integrations/status

# Export a case to TheHive
curl -X POST "http://localhost:8000/api/v1/integrations/thehive/cases/from-case/<case_id>" \
  -H "X-API-Key: $BROHUNTER_API_KEY"

# Correlate case IOCs with Wazuh alerts
curl -X POST "http://localhost:8000/api/v1/integrations/wazuh/correlate/case/<case_id>?limit_per_ioc=25" \
  -H "X-API-Key: $BROHUNTER_API_KEY"

# Enrich case IOCs from MISP
curl -X POST "http://localhost:8000/api/v1/integrations/misp/enrich/case/<case_id>?limit_per_ioc=25" \
  -H "X-API-Key: $BROHUNTER_API_KEY"
```

## License

MIT - see [LICENSE](LICENSE) for details.
