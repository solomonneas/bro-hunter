"""Hunt hypotheses service with file-backed JSON storage and template seeding."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4


class HuntHypothesesService:
    VALID_STATUS = {"draft", "active", "completed"}

    def __init__(self, hypotheses_dir: Optional[Path] = None):
        base_dir = Path(__file__).resolve().parents[2]
        self.hypotheses_dir = hypotheses_dir or (base_dir / "data" / "hypotheses")
        self.hypotheses_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _hypothesis_path(self, hypothesis_id: str) -> Path:
        return self.hypotheses_dir / f"{hypothesis_id}.json"

    def _seed_if_empty(self) -> None:
        if any(self.hypotheses_dir.glob("*.json")):
            return

        templates = [
            {
                "title": "C2 Beaconing Detection",
                "description": "Identify periodic outbound communication patterns consistent with command-and-control beaconing.",
                "mitre_techniques": ["T1071", "T1041"],
                "data_sources": ["conn.log", "dns.log", "beacons"],
                "status": "active",
                "tags": ["c2", "beaconing", "command-and-control"],
                "steps": [
                    {
                        "description": "Find hosts with periodic outbound connections to a single destination.",
                        "query_hint": "Group connections by src_ip/dst_ip and flag low interval variance over time",
                        "expected_result": "Small set of internal hosts with recurring intervals to one external endpoint",
                    },
                    {
                        "description": "Review beacon detections with score > 0.8 for identified hosts.",
                        "query_hint": "Filter beacons where beacon_score > 0.8 and src_ip in candidate host list",
                        "expected_result": "High-confidence beacon sessions linked to suspicious endpoints",
                    },
                    {
                        "description": "Correlate suspicious destinations with DNS lookup behavior.",
                        "query_hint": "Join conn destinations with dns queries to detect DGAs/new domains/low TTL",
                        "expected_result": "Domain context that reinforces C2 suspicion",
                    },
                ],
            },
            {
                "title": "DNS Tunneling Investigation",
                "description": "Hunt for DNS abuse patterns that indicate covert data transfer over DNS.",
                "mitre_techniques": ["T1071.004", "T1048"],
                "data_sources": ["dns.log", "conn.log"],
                "status": "active",
                "tags": ["dns", "tunneling", "exfiltration"],
                "steps": [
                    {
                        "description": "Identify domains with unusually high subdomain cardinality.",
                        "query_hint": "Count unique subdomains per base domain and rank descending",
                        "expected_result": "Outlier domains with abnormal subdomain churn",
                    },
                    {
                        "description": "Analyze TXT query frequency and payload characteristics.",
                        "query_hint": "Filter qtype_name=TXT and inspect record length/entropy",
                        "expected_result": "Suspicious TXT usage inconsistent with normal operations",
                    },
                    {
                        "description": "Search for encoded or chunked payload patterns in DNS labels.",
                        "query_hint": "Detect base64-like/hex-like labels and sequential chunk patterns",
                        "expected_result": "Evidence of encoded data movement via DNS",
                    },
                ],
            },
            {
                "title": "Data Exfiltration Hunt",
                "description": "Detect potential outbound data exfiltration using transfer and protocol anomalies.",
                "mitre_techniques": ["T1041", "T1567"],
                "data_sources": ["conn.log", "files.log", "http.log"],
                "status": "draft",
                "tags": ["exfiltration", "egress", "anomaly"],
                "steps": [
                    {
                        "description": "Find large outbound transfers by bytes sent and session duration.",
                        "query_hint": "Sort outbound flows by orig_bytes and long duration sessions",
                        "expected_result": "Top candidates for exfiltration review",
                    },
                    {
                        "description": "Detect unusual protocols operating on standard ports.",
                        "query_hint": "Compare service/proto values against expected port mappings (e.g., non-HTTPS on 443)",
                        "expected_result": "Protocol/port mismatches indicating covert channels",
                    },
                    {
                        "description": "Flag asymmetric traffic ratios indicating one-way bulk movement.",
                        "query_hint": "Compute orig_bytes/resp_bytes ratios and filter extreme outliers",
                        "expected_result": "Sessions with exfiltration-like outbound dominance",
                    },
                ],
            },
            {
                "title": "Lateral Movement Detection",
                "description": "Uncover suspicious east-west activity consistent with lateral movement.",
                "mitre_techniques": ["T1021", "T1078"],
                "data_sources": ["conn.log", "smb.log", "rdp.log", "auth.log"],
                "status": "draft",
                "tags": ["lateral-movement", "internal", "credentials"],
                "steps": [
                    {
                        "description": "Identify internal SMB/RDP/WMI connection spikes or anomalies.",
                        "query_hint": "Filter private-to-private traffic on 445/3389/135 and compare to baseline",
                        "expected_result": "Hosts with unusual remote admin traffic",
                    },
                    {
                        "description": "Find newly observed host-to-host communication pairs.",
                        "query_hint": "Diff recent internal edges against historical baseline graph",
                        "expected_result": "Novel internal paths requiring validation",
                    },
                    {
                        "description": "Review credential usage patterns across systems and time windows.",
                        "query_hint": "Correlate auth events for shared credentials across multiple hosts",
                        "expected_result": "Potential credential reuse or lateral pivot indicators",
                    },
                ],
            },
            {
                "title": "Rogue Service Discovery",
                "description": "Detect unauthorized services and suspicious listening behavior inside the environment.",
                "mitre_techniques": ["T1571", "T1105"],
                "data_sources": ["conn.log", "service_inventory", "suricata"],
                "status": "draft",
                "tags": ["rogue-service", "ports", "discovery"],
                "steps": [
                    {
                        "description": "Detect unexpected listening services on internal hosts.",
                        "query_hint": "Compare observed server ports to approved service inventory",
                        "expected_result": "Hosts exposing unapproved services",
                    },
                    {
                        "description": "Identify new traffic on unusual or high-risk ports.",
                        "query_hint": "Flag first-seen destination ports and low-prevalence services",
                        "expected_result": "Recently introduced service endpoints",
                    },
                    {
                        "description": "Validate protocol/service consistency for suspicious endpoints.",
                        "query_hint": "Match application protocol signatures against expected service labels",
                        "expected_result": "Protocol mismatches indicating masquerading or tunneling",
                    },
                ],
            },
        ]

        for template in templates:
            self.create(template)

    def _normalize_steps(self, steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for idx, step in enumerate(steps):
            normalized.append(
                {
                    "index": int(step.get("index", idx)),
                    "description": step.get("description", ""),
                    "query_hint": step.get("query_hint", ""),
                    "expected_result": step.get("expected_result", ""),
                    "actual_result": step.get("actual_result"),
                    "completed": bool(step.get("completed", False)),
                }
            )
        return normalized

    def _read(self, hypothesis_id: str) -> dict[str, Any]:
        path = self._hypothesis_path(hypothesis_id)
        if not path.exists():
            raise FileNotFoundError(f"Hypothesis not found: {hypothesis_id}")
        return json.loads(path.read_text(encoding="utf-8"))

    def _write(self, hypothesis: dict[str, Any]) -> dict[str, Any]:
        hypothesis["updated_at"] = self._now_iso()
        completed = all(step.get("completed") for step in hypothesis.get("steps", [])) and len(hypothesis.get("steps", [])) > 0
        if completed:
            hypothesis["status"] = "completed"
            hypothesis["completed_at"] = hypothesis.get("completed_at") or self._now_iso()
        elif hypothesis.get("status") == "completed":
            hypothesis["status"] = "active"
            hypothesis["completed_at"] = None

        path = self._hypothesis_path(hypothesis["id"])
        path.write_text(json.dumps(hypothesis, indent=2), encoding="utf-8")
        return hypothesis

    def list_all(self, status: Optional[str] = None) -> list[dict[str, Any]]:
        self._seed_if_empty()
        items: list[dict[str, Any]] = []
        for path in sorted(self.hypotheses_dir.glob("*.json"), reverse=True):
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if status and item.get("status") != status:
                continue
            items.append(item)
        return items

    def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = self._now_iso()
        status = payload.get("status", "draft")
        if status not in self.VALID_STATUS:
            raise ValueError(f"Invalid status: {status}")

        hypothesis = {
            "id": str(uuid4()),
            "title": payload["title"],
            "description": payload.get("description", ""),
            "mitre_techniques": payload.get("mitre_techniques", []),
            "data_sources": payload.get("data_sources", []),
            "steps": self._normalize_steps(payload.get("steps", [])),
            "status": status,
            "created_at": now,
            "updated_at": now,
            "completed_at": payload.get("completed_at"),
            "tags": payload.get("tags", []),
        }
        return self._write(hypothesis)

    def get(self, hypothesis_id: str) -> dict[str, Any]:
        self._seed_if_empty()
        return self._read(hypothesis_id)

    def update(self, hypothesis_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        hypothesis = self._read(hypothesis_id)

        for field in ["title", "description", "mitre_techniques", "data_sources", "tags"]:
            if field in payload:
                hypothesis[field] = payload[field]

        if "status" in payload:
            if payload["status"] not in self.VALID_STATUS:
                raise ValueError(f"Invalid status: {payload['status']}")
            hypothesis["status"] = payload["status"]
            if payload["status"] != "completed":
                hypothesis["completed_at"] = None
            elif not hypothesis.get("completed_at"):
                hypothesis["completed_at"] = self._now_iso()

        if "steps" in payload:
            hypothesis["steps"] = self._normalize_steps(payload["steps"])

        return self._write(hypothesis)

    def delete(self, hypothesis_id: str) -> None:
        path = self._hypothesis_path(hypothesis_id)
        if not path.exists():
            raise FileNotFoundError(f"Hypothesis not found: {hypothesis_id}")
        path.unlink()

    def complete_step(self, hypothesis_id: str, step_index: int, actual_result: Optional[str]) -> dict[str, Any]:
        hypothesis = self._read(hypothesis_id)
        step = next((s for s in hypothesis.get("steps", []) if int(s.get("index", -1)) == int(step_index)), None)
        if not step:
            raise FileNotFoundError(f"Step not found: {step_index}")

        step["completed"] = True
        step["actual_result"] = actual_result

        if hypothesis.get("status") == "draft":
            hypothesis["status"] = "active"

        self._write(hypothesis)
        return step


hunt_hypotheses_service = HuntHypothesesService()
