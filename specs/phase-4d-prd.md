# Phase 4D PRD: ML Anomaly Detection + Baseline Profiling

## Context
Bro Hunter Phases 4A-4C add packet inspection, rules, and case management. Phase 4D adds statistical anomaly detection and traffic baseline profiling. No heavy ML libraries needed; this uses pure statistical methods (z-scores, IQR, clustering via numpy only).

## Existing Architecture
- Backend: FastAPI at `api/`, routers in `api/routers/`, services in `api/services/`
- Frontend: React+TS+Vite+Tailwind in `web/`, V3 variant is root, sidebar nav
- Config: `api/config.py` (pydantic-settings), env prefix `BROHUNTER_`
- State: Custom pub/sub store (NOT zustand)
- recharts already installed (from Phase 4A)
- Demo data in `data/demo/`

## Feature 1: Traffic Baseline Profiling

### Backend (`api/services/baseline_profiler.py`, `api/routers/baseline.py`)
- `POST /api/v1/baseline/build` — analyze loaded data and build baseline profile
- `GET /api/v1/baseline` — get current baseline
- `POST /api/v1/baseline/compare` — compare new data against baseline
- Baseline model:
```python
{
    "built_at": "datetime",
    "connection_count": int,
    "time_range": {"start": float, "end": float},
    "protocol_distribution": {"tcp": 0.65, "udp": 0.30, "icmp": 0.05},
    "port_profile": {
        "top_dst_ports": [{"port": 443, "pct": 0.45}, ...],
        "top_src_ports": [{"port": 52341, "pct": 0.01}, ...],
    },
    "traffic_volume": {
        "bytes_per_hour_mean": float,
        "bytes_per_hour_std": float,
        "connections_per_hour_mean": float,
        "connections_per_hour_std": float,
    },
    "duration_stats": {
        "mean": float, "median": float, "std": float,
        "p95": float, "p99": float,
    },
    "dns_profile": {
        "unique_queries_per_hour_mean": float,
        "avg_query_length": float,
        "top_queried_domains": [{"domain": "example.com", "count": 100}],
    },
    "host_profile": {
        "internal_hosts": int,
        "external_hosts": int,
        "top_talkers": [{"ip": "...", "bytes": int, "connections": int}],
    }
}
```
- Store baseline in `data/baseline.json`
- Comparison returns deviations: which metrics are outside 2σ of baseline

### Frontend (`web/src/components/BaselineView.tsx`)
- "Build Baseline" button (shows progress)
- Baseline summary cards: protocol mix, avg volume, host count, DNS stats
- Deviation indicators: green (within baseline), yellow (1-2σ), red (>2σ)
- Charts: baseline vs current overlay (using recharts)

## Feature 2: Anomaly Detection Engine

### Backend (`api/services/anomaly_detector.py`, `api/routers/anomalies.py`)
- `POST /api/v1/anomalies/detect` — run anomaly detection on loaded data
- `GET /api/v1/anomalies` — get detected anomalies
- `GET /api/v1/anomalies/{id}` — get anomaly detail
- Detection methods (pure Python + numpy):
  1. **Volume Anomalies**: z-score on bytes/connections per time bucket. Flag buckets > 2σ.
  2. **Protocol Anomalies**: chi-squared test on protocol distribution vs baseline.
  3. **Port Anomalies**: new ports not seen in baseline, unusual port usage spikes.
  4. **DNS Anomalies**: 
     - Query length outliers (z-score > 3)
     - Entropy-based DGA detection (Shannon entropy > 3.5 on query name)
     - Unusual query volume per host
  5. **Behavioral Anomalies**:
     - New external hosts not in baseline
     - Connection duration outliers
     - Data ratio anomalies (bytes_orig >> bytes_resp or vice versa)
  6. **Temporal Anomalies**: 
     - Activity outside normal hours (if baseline shows patterns)
     - Sudden burst detection (sliding window, >3σ spike)
  7. **Host Anomalies**:
     - Hosts connecting to unusually many destinations (fan-out)
     - Hosts with new protocols they haven't used before
- Anomaly model:
```python
{
    "id": "uuid",
    "type": "volume|protocol|port|dns|behavioral|temporal|host",
    "severity": "low|medium|high|critical",
    "description": "string",
    "evidence": {"metric": "value", "baseline": "value", "deviation": float},
    "affected_hosts": ["ip"],
    "affected_connections": ["uid"],
    "detected_at": "datetime",
    "mitre_techniques": ["T1071", ...],  # optional mapping
}
```
- Install numpy: `cd api && pip install numpy` (add to requirements.txt)

### Frontend (`web/src/components/AnomalyDashboard.tsx`, `web/src/variants/v3/pages/Anomalies.tsx`)
- **Anomaly Overview**: 
  - Summary bar: total anomalies by severity (critical/high/medium/low)
  - Anomaly type breakdown (donut chart via recharts)
- **Anomaly List**: 
  - Filterable by type, severity
  - Each row: type icon, description, severity badge, affected hosts, timestamp
  - Click to expand: full evidence details, affected connections (linked to connection/packet views)
- **Anomaly Timeline**: 
  - recharts area chart showing anomaly density over time
  - Hover shows anomaly details at that time point
- **Host Anomaly Map**:
  - Table of hosts with anomaly scores
  - Sparkline per host showing their anomaly trend
  - Click host → filter anomalies to that host
- **Baseline Comparison Panel** (embedded in anomaly page):
  - Side-by-side: baseline metrics vs current
  - Color-coded deviation indicators

## New Sidebar Entry
Add "Anomalies" between "Analytics" and "Threat Intel" in V3 sidebar nav.

## Files to Create
- `api/services/baseline_profiler.py` — baseline building + comparison
- `api/services/anomaly_detector.py` — all 7 detection methods
- `api/routers/baseline.py` — baseline endpoints
- `api/routers/anomalies.py` — anomaly detection endpoints
- `web/src/components/AnomalyDashboard.tsx` — anomaly overview + charts
- `web/src/components/BaselineView.tsx` — baseline display + comparison
- `web/src/components/AnomalyTimeline.tsx` — temporal anomaly chart
- `web/src/components/HostAnomalyMap.tsx` — per-host anomaly scores
- `web/src/variants/v3/pages/Anomalies.tsx` — page wrapper
- `data/baseline.json` — empty initial baseline
- `tests/test_baseline_profiler.py`
- `tests/test_anomaly_detector.py`

## Files to Modify
- `api/main.py` — add baseline + anomalies routers
- `api/requirements.txt` — add numpy
- `web/src/variants/v3/Layout.tsx` — add Anomalies to sidebar

## DO NOT
- Use scikit-learn, tensorflow, or any heavy ML library (numpy only for stats)
- Use zustand (custom pub/sub store)
- Add framer-motion
- Break existing endpoints
- Make anomaly detection slow (keep it under 5 seconds for 2500 connections)
