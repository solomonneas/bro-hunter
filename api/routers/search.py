"""
Global Search Router: search across IPs, domains, alerts, and connections.
"""
from collections import Counter
from typing import Optional
from fastapi import APIRouter, Query, HTTPException

from api.services.log_store import LogStore, log_store

router = APIRouter()


def _get_store() -> LogStore:
    return log_store


@router.get("")
async def global_search(q: str = Query(..., min_length=1, max_length=200)):
    """Search across IPs, domains, alerts, and connections."""
    query = q.strip().lower()
    store = _get_store()

    results = {
        "query": q,
        "ips": [],
        "domains": [],
        "alerts": [],
        "connections": [],
    }

    # Search connections by IP
    connections = store.get_connections()
    src_counts = Counter(getattr(c, "src_ip", "") for c in connections)
    dst_counts = Counter(getattr(c, "dst_ip", "") for c in connections)
    seen_ips = set()
    for conn in connections:
        src = getattr(conn, "src_ip", "")
        dst = getattr(conn, "dst_ip", "")

        if query in src.lower():
            if src not in seen_ips:
                seen_ips.add(src)
                results["ips"].append({
                    "ip": src,
                    "type": "source",
                    "connection_count": src_counts.get(src, 0),
                })

        if query in dst.lower():
            if dst not in seen_ips:
                seen_ips.add(dst)
                results["ips"].append({
                    "ip": dst,
                    "type": "destination",
                    "connection_count": dst_counts.get(dst, 0),
                })

        # Match connection by src or dst
        if query in src.lower() or query in dst.lower():
            port = getattr(conn, "dst_port", 0)
            proto = getattr(conn, "proto", "tcp")
            results["connections"].append({
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": port,
                "proto": proto,
                "duration": getattr(conn, "duration", 0),
            })

    # Search DNS queries
    dns_queries = store.get_dns_queries() if hasattr(store, "get_dns_queries") else []
    seen_domains = set()
    for dns in dns_queries:
        domain = getattr(dns, "query", "")
        if query in domain.lower() and domain not in seen_domains:
            seen_domains.add(domain)
            results["domains"].append({
                "domain": domain,
                "query_type": getattr(dns, "qtype_name", ""),
                "src_ip": getattr(dns, "src_ip", ""),
            })

    # Search alerts
    alerts = store.get_alerts() if hasattr(store, "get_alerts") else []
    for alert in alerts:
        sig = getattr(alert, "signature", "")
        src = getattr(alert, "src_ip", "")
        dst = getattr(alert, "dst_ip", "")
        if query in sig.lower() or query in src.lower() or query in dst.lower():
            results["alerts"].append({
                "signature": sig,
                "src_ip": src,
                "dst_ip": dst,
                "severity": getattr(alert, "severity", 0),
                "category": getattr(alert, "category", ""),
            })

    # Limit results
    for key in ["ips", "domains", "alerts", "connections"]:
        results[key] = results[key][:50]

    results["total"] = sum(len(results[k]) for k in ["ips", "domains", "alerts", "connections"])
    return results
