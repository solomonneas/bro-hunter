"""
Unified data models and normalization layer for Zeek and Suricata logs.
Provides a common Connection model with normalization functions.
"""
from typing import Optional, Union, Any
from datetime import datetime
from pydantic import BaseModel, Field
import logging

from api.models.zeek import ConnLog, DnsLog, HttpLog
from api.models.suricata import SuricataAlert, SuricataFlow, SuricataDns, SuricataHttp
from api.parsers.zeek_parser import ZeekParser
from api.parsers.suricata_parser import SuricataParser

logger = logging.getLogger(__name__)


class Connection(BaseModel):
    """
    Unified connection model that normalizes Zeek and Suricata data.
    This provides a common interface for analyzing network connections.
    """

    uid: str = Field(..., description="Unique connection identifier")
    src_ip: str = Field(..., description="Source IP address")
    src_port: int = Field(..., description="Source port")
    dst_ip: str = Field(..., description="Destination IP address")
    dst_port: int = Field(..., description="Destination port")
    proto: str = Field(..., description="Protocol (tcp/udp/icmp)")
    service: Optional[str] = Field(None, description="Detected service/app protocol")
    duration: Optional[float] = Field(None, description="Connection duration in seconds")
    bytes_sent: Optional[int] = Field(None, description="Bytes sent from source")
    bytes_recv: Optional[int] = Field(None, description="Bytes received at source")
    timestamp: datetime = Field(..., description="Connection timestamp")
    tags: list[str] = Field(default_factory=list, description="Tags for classification")
    source: str = Field(..., description="Log source (zeek/suricata)")

    # Additional metadata
    conn_state: Optional[str] = Field(None, description="Connection state")
    pkts_sent: Optional[int] = Field(None, description="Packets sent")
    pkts_recv: Optional[int] = Field(None, description="Packets received")


class DnsQuery(BaseModel):
    """
    Unified DNS query model for both Zeek and Suricata.
    """

    timestamp: datetime = Field(..., description="Query timestamp")
    src_ip: str = Field(..., description="Source IP address")
    src_port: int = Field(..., description="Source port")
    dst_ip: str = Field(..., description="Destination IP (DNS server)")
    dst_port: int = Field(..., description="Destination port")
    query: str = Field(..., description="DNS query domain")
    qtype: Optional[str] = Field(None, description="Query type (A, AAAA, etc.)")
    rcode: Optional[str] = Field(None, description="Response code")
    answers: list[str] = Field(default_factory=list, description="DNS answers")
    source: str = Field(..., description="Log source (zeek/suricata)")


class Alert(BaseModel):
    """
    Unified alert model for Suricata IDS alerts.
    """

    timestamp: datetime = Field(..., description="Alert timestamp")
    src_ip: str = Field(..., description="Source IP address")
    src_port: int = Field(..., description="Source port")
    dst_ip: str = Field(..., description="Destination IP address")
    dst_port: int = Field(..., description="Destination port")
    proto: str = Field(..., description="Protocol")
    signature: str = Field(..., description="Alert signature/rule")
    signature_id: int = Field(..., description="Signature ID")
    category: str = Field(..., description="Alert category")
    severity: int = Field(..., description="Severity level")
    action: str = Field(..., description="Action taken (allowed/blocked)")


def normalize_zeek_conn(conn: ConnLog) -> Connection:
    """
    Normalize Zeek connection log to unified Connection model.

    Args:
        conn: Zeek ConnLog entry

    Returns:
        Normalized Connection object
    """
    return Connection(
        uid=conn.uid,
        src_ip=conn.id_orig_h,
        src_port=conn.id_orig_p,
        dst_ip=conn.id_resp_h,
        dst_port=conn.id_resp_p,
        proto=conn.proto.lower(),
        service=conn.service,
        duration=conn.duration,
        bytes_sent=conn.orig_bytes,
        bytes_recv=conn.resp_bytes,
        timestamp=ZeekParser.parse_timestamp(conn.ts),
        tags=[],
        source="zeek",
        conn_state=conn.conn_state,
        pkts_sent=conn.orig_pkts,
        pkts_recv=conn.resp_pkts,
    )


def normalize_suricata_flow(flow: SuricataFlow) -> Connection:
    """
    Normalize Suricata flow to unified Connection model.

    Args:
        flow: Suricata SuricataFlow entry

    Returns:
        Normalized Connection object
    """
    flow_data = flow.flow

    return Connection(
        uid=str(flow.flow_id),
        src_ip=flow.src_ip,
        src_port=flow.src_port,
        dst_ip=flow.dest_ip,
        dst_port=flow.dest_port,
        proto=flow.proto.lower(),
        service=flow.app_proto,
        duration=flow_data.get("age"),
        bytes_sent=flow_data.get("bytes_toserver"),
        bytes_recv=flow_data.get("bytes_toclient"),
        timestamp=SuricataParser.parse_timestamp(flow.timestamp),
        tags=[],
        source="suricata",
        conn_state=flow_data.get("state"),
        pkts_sent=flow_data.get("pkts_toserver"),
        pkts_recv=flow_data.get("pkts_toclient"),
    )


def normalize_zeek_dns(dns: DnsLog) -> DnsQuery:
    """
    Normalize Zeek DNS log to unified DnsQuery model.

    Args:
        dns: Zeek DnsLog entry

    Returns:
        Normalized DnsQuery object
    """
    return DnsQuery(
        timestamp=ZeekParser.parse_timestamp(dns.ts),
        src_ip=dns.id_orig_h,
        src_port=dns.id_orig_p,
        dst_ip=dns.id_resp_h,
        dst_port=dns.id_resp_p,
        query=dns.query or "",
        qtype=dns.qtype_name,
        rcode=dns.rcode_name,
        answers=dns.answers or [],
        source="zeek",
    )


def normalize_suricata_dns(dns: SuricataDns) -> DnsQuery:
    """
    Normalize Suricata DNS event to unified DnsQuery model.

    Args:
        dns: Suricata SuricataDns entry

    Returns:
        Normalized DnsQuery object
    """
    dns_data = dns.dns

    return DnsQuery(
        timestamp=SuricataParser.parse_timestamp(dns.timestamp),
        src_ip=dns.src_ip,
        src_port=dns.src_port,
        dst_ip=dns.dest_ip,
        dst_port=dns.dest_port,
        query=dns_data.get("rrname", ""),
        qtype=dns_data.get("rrtype"),
        rcode=dns_data.get("rcode"),
        answers=dns_data.get("answers", []),
        source="suricata",
    )


def normalize_suricata_alert(alert_entry: SuricataAlert) -> Alert:
    """
    Normalize Suricata alert to unified Alert model.

    Args:
        alert_entry: Suricata SuricataAlert entry

    Returns:
        Normalized Alert object
    """
    alert_data = alert_entry.alert

    return Alert(
        timestamp=SuricataParser.parse_timestamp(alert_entry.timestamp),
        src_ip=alert_entry.src_ip,
        src_port=alert_entry.src_port,
        dst_ip=alert_entry.dest_ip,
        dst_port=alert_entry.dest_port,
        proto=alert_entry.proto,
        signature=alert_data.get("signature", ""),
        signature_id=alert_data.get("signature_id", 0),
        category=alert_data.get("category", ""),
        severity=alert_data.get("severity", 0),
        action=alert_data.get("action", "unknown"),
    )


def normalize_log_entry(
    entry: Union[ConnLog, DnsLog, HttpLog, SuricataAlert, SuricataFlow, SuricataDns, SuricataHttp],
    log_type: str
) -> Union[Connection, DnsQuery, Alert, None]:
    """
    Normalize any supported log entry to unified model.

    Args:
        entry: Log entry (Zeek or Suricata)
        log_type: Type of log entry

    Returns:
        Normalized unified model or None if not supported
    """
    try:
        # Zeek normalization
        if isinstance(entry, ConnLog):
            return normalize_zeek_conn(entry)
        elif isinstance(entry, DnsLog):
            return normalize_zeek_dns(entry)

        # Suricata normalization
        elif isinstance(entry, SuricataFlow):
            return normalize_suricata_flow(entry)
        elif isinstance(entry, SuricataDns):
            return normalize_suricata_dns(entry)
        elif isinstance(entry, SuricataAlert):
            return normalize_suricata_alert(entry)

        else:
            logger.warning(f"Unsupported entry type for normalization: {type(entry)}")
            return None

    except Exception as e:
        logger.error(f"Error normalizing log entry: {e}")
        return None
