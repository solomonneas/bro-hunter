# Hunter - Network Threat Hunting Platform

**Hunt threats in network traffic with explainable AI-powered analysis.**

Hunter is a network security analysis platform that processes Zeek and Suricata logs to identify threats, map them to MITRE ATT&CK techniques, and provide actionable intelligence with full explainability.

## Features

- **Multi-Source Log Analysis**: Parse and correlate Zeek and Suricata network logs
- **Beaconing Detection**: Identify C2 communication via periodic callback patterns
- **DNS Threat Analysis**: Detect DNS tunneling, DGA domains, and fast-flux networks
- **Threat Scoring**: AI-powered threat scoring with detailed explanations
- **MITRE ATT&CK Mapping**: Automatic mapping of threats to ATT&CK techniques and tactics
- **Interactive Dashboards**: Real-time visualizations with dark NOC-style UI
- **Explainable Results**: Every threat score includes reasoning and evidence
- **Static Analysis**: Works with archived logs - no live streaming required for MVP

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        HUNTER PLATFORM                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐         ┌──────────────┐                 │
│  │   Frontend   │◄───────►│   Backend    │                 │
│  │              │         │              │                 │
│  │  React +     │  HTTP   │  FastAPI +   │                 │
│  │  TypeScript  │  REST   │  Python      │                 │
│  │  TailwindCSS │         │  Pydantic    │                 │
│  └──────────────┘         └───────┬──────┘                 │
│                                   │                         │
│                          ┌────────▼────────┐                │
│                          │  Log Parsers    │                │
│                          │  - Zeek         │                │
│                          │  - Suricata     │                │
│                          └────────┬────────┘                │
│                                   │                         │
│                          ┌────────▼────────┐                │
│                          │ Threat Analysis │                │
│                          │  - Scoring      │                │
│                          │  - Indicators   │                │
│                          │  - MITRE Maps   │                │
│                          └─────────────────┘                │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                     DATA SOURCES                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐         ┌──────────────┐                 │
│  │  Zeek Logs   │         │ Suricata Eve │                 │
│  │              │         │              │                 │
│  │  conn.log    │         │  eve.json    │                 │
│  │  dns.log     │         │  (alerts)    │                 │
│  │  http.log    │         │  (flows)     │                 │
│  │  ssl.log     │         │  (dns)       │                 │
│  │  x509.log    │         │  (http)      │                 │
│  │  files.log   │         │  (tls)       │                 │
│  │  notice.log  │         └──────────────┘                 │
│  └──────────────┘                                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
hunter/
├── api/                    # FastAPI backend
│   ├── main.py            # Application entry point
│   ├── config.py          # Configuration management
│   ├── models/            # Pydantic data models
│   │   ├── zeek.py       # Zeek log models
│   │   ├── suricata.py   # Suricata log models
│   │   └── threat.py     # Threat analysis models
│   ├── routers/           # API endpoints
│   │   ├── logs.py       # Log ingestion routes
│   │   └── analysis.py   # Analysis routes
│   ├── services/          # Business logic
│   └── parsers/           # Log parsers
│
├── web/                   # React frontend
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── hooks/        # Custom React hooks
│   │   ├── types/        # TypeScript definitions
│   │   ├── pages/        # Page components
│   │   ├── App.tsx       # Root component
│   │   └── main.tsx      # Entry point
│   ├── index.html        # HTML template
│   ├── vite.config.ts    # Vite configuration
│   └── tailwind.config.js # Tailwind theme
│
├── fixtures/              # Sample log data
│   ├── conn.log.json     # 50+ Zeek connection logs
│   ├── dns.log.json      # 50+ DNS queries
│   ├── http.log.json     # 50+ HTTP requests
│   ├── ssl.log.json      # 50+ TLS handshakes
│   ├── x509.log.json     # 50+ certificates
│   ├── files.log.json    # 50+ file transfers
│   ├── notice.log.json   # 50+ Zeek notices
│   └── eve.json          # 30+ Suricata alerts
│
├── requirements.txt       # Python dependencies
├── package.json          # Node.js dependencies
├── Makefile              # Development tasks
└── README.md             # This file
```

## Setup Instructions

### Prerequisites

- Python 3.10 or higher
- Node.js 18 or higher
- npm or yarn

### Backend Setup

1. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the backend:
   ```bash
   uvicorn api.main:app --reload
   ```

   The API will be available at `http://localhost:8000`

### Frontend Setup

1. Navigate to the web directory:
   ```bash
   cd web
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Run the development server:
   ```bash
   npm run dev
   ```

   The frontend will be available at `http://localhost:5173`

### Quick Start with Make

For convenience, use the Makefile:

```bash
make dev        # Start both backend and frontend
make build      # Build production bundles
make clean      # Clean build artifacts
make test       # Run tests
make fixtures   # Regenerate fixture data
```

## API Endpoints

### Health & Status

- `GET /` - API health check
- `GET /health` - Detailed health status

### Log Management

- `POST /api/v1/logs/upload/zeek` - Upload Zeek logs
- `POST /api/v1/logs/upload/suricata` - Upload Suricata logs
- `GET /api/v1/logs/stats` - Get log statistics

### Threat Analysis

- `GET /api/v1/analysis/threats` - Get threat scores
- `GET /api/v1/analysis/indicators` - Get threat indicators
- `GET /api/v1/analysis/mitre` - Get MITRE ATT&CK mappings
- `POST /api/v1/analysis/hunt` - Execute threat hunt
- `GET /api/v1/analysis/hunt/{hunt_id}` - Get hunt results

### Beaconing Detection

- `GET /api/v1/hunt/beacons` - Detect C2 beaconing patterns
- `GET /api/v1/hunt/beacons/{src_ip}/{dst_ip}` - Get detailed beacon analysis
- `GET /api/v1/hunt/beacons/stats` - Get beacon statistics

### DNS Threat Detection

- `GET /api/v1/hunt/dns/threats` - Get comprehensive DNS threat summary
- `GET /api/v1/hunt/dns/tunneling` - Detect DNS tunneling
- `GET /api/v1/hunt/dns/dga` - Detect DGA domains
- `GET /api/v1/hunt/dns/fast-flux` - Detect fast-flux DNS
- `GET /api/v1/hunt/dns/suspicious-patterns` - Detect suspicious DNS patterns
- `GET /api/v1/hunt/dns/stats` - Get DNS threat statistics

## Development Workflow

### Running Tests

```bash
# Backend tests
pytest

# Frontend tests (when implemented)
cd web && npm test
```

### Code Style

- **Backend**: Follow PEP 8, use type hints
- **Frontend**: ESLint + Prettier with TypeScript strict mode

### Adding New Log Types

1. Define Pydantic model in `api/models/`
2. Add TypeScript interface in `web/src/types/index.ts`
3. Create parser in `api/parsers/`
4. Add fixture generator in `fixtures/generate_fixtures.py`

## Feature Roadmap

### MVP (v0.1.0) - Current
- [x] Project scaffolding
- [x] Zeek log models (10 types)
- [x] Suricata log models (5 types)
- [x] Threat scoring models
- [x] Basic API endpoints
- [x] React + TypeScript frontend
- [x] Dark theme UI
- [x] Fixture data (400+ entries)

### Phase 2 (v0.2.0)
- [ ] Log parsing implementation
- [ ] Basic threat scoring engine
- [ ] MITRE ATT&CK technique mapping
- [ ] Interactive data tables
- [ ] Time series charts
- [ ] Threat indicator dashboard

### Phase 3 (v0.3.0)
- [ ] Advanced threat hunting queries
- [ ] Behavioral analysis
- [ ] Anomaly detection (statistical)
- [ ] Export reports (PDF/JSON)
- [ ] Multi-file batch processing

### Phase 4 (v0.4.0)
- [ ] ML-based threat prediction
- [ ] Custom hunt rule editor
- [ ] Alert correlation engine
- [ ] Integration with threat intel feeds
- [ ] Multi-user support

## Configuration

### Backend Configuration

Environment variables (prefix with `HUNTER_`):

- `HUNTER_MAX_FILE_SIZE`: Maximum upload size (default: 100MB)
- `HUNTER_HIGH_THREAT_THRESHOLD`: High threat score threshold (default: 0.75)
- `HUNTER_MEDIUM_THREAT_THRESHOLD`: Medium threat threshold (default: 0.50)

### Frontend Configuration

Vite proxy configuration in `web/vite.config.ts` proxies `/api` requests to the backend.

## Dark Theme Colors

Hunter uses a Watchtower NOC-inspired dark theme:

- **Background**: `#0a0e17` - Deep navy black
- **Surface**: `#111827` - Dark slate
- **Accent Cyan**: `#06b6d4` - Primary highlights
- **Accent Red**: `#ef4444` - Critical threats
- **Accent Amber**: `#f59e0b` - Warnings
- **Accent Green**: `#22c55e` - Success/safe

## Documentation

- [Beaconing Detection Guide](BEACON_DETECTION.md) - C2 communication pattern analysis
- [DNS Threat Detection Guide](DNS_THREAT_DETECTION.md) - DNS tunneling, DGA, and fast-flux detection
- [Log Ingestion Guide](LOG_INGESTION_README.md) - Parsing Zeek and Suricata logs
- [Implementation Summary](IMPLEMENTATION_SUMMARY.md) - Architecture and design decisions

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - See LICENSE file for details

## Acknowledgments

- **Zeek Network Security Monitor** - https://zeek.org/
- **Suricata IDS/IPS** - https://suricata.io/
- **MITRE ATT&CK** - https://attack.mitre.org/

---

**Built for threat hunters, by threat hunters.** 🎯
