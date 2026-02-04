"""
Pydantic models for Suricata IDS/IPS eve.json logs.
Covers alerts, flows, DNS, HTTP, and TLS events.
"""
from typing import Optional, Any
from pydantic import BaseModel, Field


class SuricataAlert(BaseModel):
    """Suricata alert event from eve.json."""

    timestamp: str = Field(..., description="ISO 8601 timestamp")
    flow_id: Optional[int] = Field(None, description="Flow identifier")
    in_iface: Optional[str] = Field(None, description="Input interface")
    event_type: str = Field(..., description="Event type (alert)")
    src_ip: str = Field(..., description="Source IP address")
    src_port: int = Field(..., description="Source port")
    dest_ip: str = Field(..., description="Destination IP address")
    dest_port: int = Field(..., description="Destination port")
    proto: str = Field(..., description="Protocol (TCP/UDP/ICMP)")
    tx_id: Optional[int] = Field(None, description="Transaction ID")

    # Alert details
    alert: dict[str, Any] = Field(
        ...,
        description="Alert details (action, gid, signature_id, rev, signature, category, severity)",
    )

    # Payload
    payload: Optional[str] = Field(None, description="Base64 encoded payload")
    payload_printable: Optional[str] = Field(None, description="Printable payload")
    stream: Optional[int] = Field(None, description="Stream number")
    packet: Optional[str] = Field(None, description="Base64 packet")
    packet_info: Optional[dict[str, Any]] = Field(None, description="Packet metadata")

    # Application layer
    app_proto: Optional[str] = Field(None, description="Application protocol")
    http: Optional[dict[str, Any]] = Field(None, description="HTTP metadata")
    dns: Optional[dict[str, Any]] = Field(None, description="DNS metadata")
    tls: Optional[dict[str, Any]] = Field(None, description="TLS metadata")
    ssh: Optional[dict[str, Any]] = Field(None, description="SSH metadata")
    smtp: Optional[dict[str, Any]] = Field(None, description="SMTP metadata")
    fileinfo: Optional[dict[str, Any]] = Field(None, description="File metadata")

    # Flow metadata
    flow: Optional[dict[str, Any]] = Field(None, description="Flow metadata")


class SuricataFlow(BaseModel):
    """Suricata flow event from eve.json."""

    timestamp: str = Field(..., description="ISO 8601 timestamp")
    flow_id: int = Field(..., description="Flow identifier")
    in_iface: Optional[str] = Field(None, description="Input interface")
    event_type: str = Field(..., description="Event type (flow)")
    src_ip: str = Field(..., description="Source IP address")
    src_port: int = Field(..., description="Source port")
    dest_ip: str = Field(..., description="Destination IP address")
    dest_port: int = Field(..., description="Destination port")
    proto: str = Field(..., description="Protocol (TCP/UDP/ICMP)")

    # Application layer
    app_proto: Optional[str] = Field(None, description="Application protocol")
    app_proto_tc: Optional[str] = Field(None, description="App proto to client")
    app_proto_ts: Optional[str] = Field(None, description="App proto to server")

    # Flow statistics
    flow: dict[str, Any] = Field(
        ...,
        description="Flow details (pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient, start, end, age, state, reason, alerted)",
    )

    # TCP specific
    tcp: Optional[dict[str, Any]] = Field(None, description="TCP flags and state")

    # Community ID
    community_id: Optional[str] = Field(None, description="Community ID flow hash")


class SuricataDns(BaseModel):
    """Suricata DNS event from eve.json."""

    timestamp: str = Field(..., description="ISO 8601 timestamp")
    flow_id: Optional[int] = Field(None, description="Flow identifier")
    in_iface: Optional[str] = Field(None, description="Input interface")
    event_type: str = Field(..., description="Event type (dns)")
    src_ip: str = Field(..., description="Source IP address")
    src_port: int = Field(..., description="Source port")
    dest_ip: str = Field(..., description="Destination IP address")
    dest_port: int = Field(..., description="Destination port")
    proto: str = Field(..., description="Protocol (UDP/TCP)")

    # DNS details
    dns: dict[str, Any] = Field(
        ...,
        description="DNS query/response (type, id, rrname, rrtype, rcode, answers, grouped)",
    )

    # Community ID
    community_id: Optional[str] = Field(None, description="Community ID flow hash")


class SuricataHttp(BaseModel):
    """Suricata HTTP event from eve.json."""

    timestamp: str = Field(..., description="ISO 8601 timestamp")
    flow_id: int = Field(..., description="Flow identifier")
    in_iface: Optional[str] = Field(None, description="Input interface")
    event_type: str = Field(..., description="Event type (http)")
    src_ip: str = Field(..., description="Source IP address")
    src_port: int = Field(..., description="Source port")
    dest_ip: str = Field(..., description="Destination IP address")
    dest_port: int = Field(..., description="Destination port")
    proto: str = Field(..., description="Protocol (TCP)")

    # Transaction ID
    tx_id: int = Field(..., description="HTTP transaction ID")

    # HTTP details
    http: dict[str, Any] = Field(
        ...,
        description="HTTP request/response (hostname, url, http_user_agent, http_content_type, http_method, protocol, status, length)",
    )

    # Fileinfo
    fileinfo: Optional[dict[str, Any]] = Field(None, description="File metadata")

    # Community ID
    community_id: Optional[str] = Field(None, description="Community ID flow hash")


class SuricataTls(BaseModel):
    """Suricata TLS event from eve.json."""

    timestamp: str = Field(..., description="ISO 8601 timestamp")
    flow_id: int = Field(..., description="Flow identifier")
    in_iface: Optional[str] = Field(None, description="Input interface")
    event_type: str = Field(..., description="Event type (tls)")
    src_ip: str = Field(..., description="Source IP address")
    src_port: int = Field(..., description="Source port")
    dest_ip: str = Field(..., description="Destination IP address")
    dest_port: int = Field(..., description="Destination port")
    proto: str = Field(..., description="Protocol (TCP)")

    # TLS details
    tls: dict[str, Any] = Field(
        ...,
        description="TLS handshake (subject, issuerdn, serial, fingerprint, sni, version, notbefore, notafter, ja3, ja3s)",
    )

    # Community ID
    community_id: Optional[str] = Field(None, description="Community ID flow hash")
