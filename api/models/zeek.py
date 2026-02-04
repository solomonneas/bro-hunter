"""
Pydantic models for Zeek network security monitor logs.
Covers all major Zeek log types with field validation.
"""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field


class ConnLog(BaseModel):
    """Zeek connection log (conn.log) - TCP/UDP/ICMP connections."""

    ts: float = Field(..., description="Timestamp of connection start")
    uid: str = Field(..., description="Unique connection identifier")
    id_orig_h: str = Field(..., description="Source IP address")
    id_orig_p: int = Field(..., description="Source port")
    id_resp_h: str = Field(..., description="Destination IP address")
    id_resp_p: int = Field(..., description="Destination port")
    proto: str = Field(..., description="Transport protocol (tcp/udp/icmp)")
    service: Optional[str] = Field(None, description="Detected service")
    duration: Optional[float] = Field(None, description="Connection duration")
    orig_bytes: Optional[int] = Field(None, description="Bytes from originator")
    resp_bytes: Optional[int] = Field(None, description="Bytes from responder")
    conn_state: Optional[str] = Field(None, description="Connection state")
    local_orig: Optional[bool] = Field(None, description="Origin is local")
    local_resp: Optional[bool] = Field(None, description="Responder is local")
    missed_bytes: Optional[int] = Field(None, description="Missed bytes")
    history: Optional[str] = Field(None, description="Connection state history")
    orig_pkts: Optional[int] = Field(None, description="Packets from originator")
    orig_ip_bytes: Optional[int] = Field(None, description="IP bytes from originator")
    resp_pkts: Optional[int] = Field(None, description="Packets from responder")
    resp_ip_bytes: Optional[int] = Field(None, description="IP bytes from responder")
    tunnel_parents: Optional[list[str]] = Field(None, description="Tunnel UIDs")


class DnsLog(BaseModel):
    """Zeek DNS log (dns.log) - DNS queries and responses."""

    ts: float = Field(..., description="Timestamp of DNS request")
    uid: str = Field(..., description="Unique connection identifier")
    id_orig_h: str = Field(..., description="Source IP address")
    id_orig_p: int = Field(..., description="Source port")
    id_resp_h: str = Field(..., description="Destination IP address")
    id_resp_p: int = Field(..., description="Destination port")
    proto: str = Field(..., description="Transport protocol")
    trans_id: Optional[int] = Field(None, description="DNS transaction ID")
    query: Optional[str] = Field(None, description="DNS query domain")
    qclass: Optional[int] = Field(None, description="Query class")
    qclass_name: Optional[str] = Field(None, description="Query class name")
    qtype: Optional[int] = Field(None, description="Query type")
    qtype_name: Optional[str] = Field(None, description="Query type name")
    rcode: Optional[int] = Field(None, description="Response code")
    rcode_name: Optional[str] = Field(None, description="Response code name")
    AA: Optional[bool] = Field(None, description="Authoritative answer")
    TC: Optional[bool] = Field(None, description="Truncated response")
    RD: Optional[bool] = Field(None, description="Recursion desired")
    RA: Optional[bool] = Field(None, description="Recursion available")
    Z: Optional[int] = Field(None, description="Reserved field")
    answers: Optional[list[str]] = Field(None, description="DNS response answers")
    TTLs: Optional[list[float]] = Field(None, description="Answer TTLs")
    rejected: Optional[bool] = Field(None, description="Query rejected")


class HttpLog(BaseModel):
    """Zeek HTTP log (http.log) - HTTP requests and responses."""

    ts: float = Field(..., description="Timestamp of HTTP transaction")
    uid: str = Field(..., description="Unique connection identifier")
    id_orig_h: str = Field(..., description="Source IP address")
    id_orig_p: int = Field(..., description="Source port")
    id_resp_h: str = Field(..., description="Destination IP address")
    id_resp_p: int = Field(..., description="Destination port")
    trans_depth: Optional[int] = Field(None, description="Pipelined request depth")
    method: Optional[str] = Field(None, description="HTTP method")
    host: Optional[str] = Field(None, description="Host header value")
    uri: Optional[str] = Field(None, description="Request URI")
    referrer: Optional[str] = Field(None, description="Referrer header")
    version: Optional[str] = Field(None, description="HTTP version")
    user_agent: Optional[str] = Field(None, description="User-Agent header")
    request_body_len: Optional[int] = Field(None, description="Request body length")
    response_body_len: Optional[int] = Field(None, description="Response body length")
    status_code: Optional[int] = Field(None, description="HTTP status code")
    status_msg: Optional[str] = Field(None, description="HTTP status message")
    info_code: Optional[int] = Field(None, description="Informational code")
    info_msg: Optional[str] = Field(None, description="Informational message")
    tags: Optional[list[str]] = Field(None, description="Tags added to request")
    username: Optional[str] = Field(None, description="Username from auth")
    password: Optional[str] = Field(None, description="Password from auth")
    proxied: Optional[list[str]] = Field(None, description="Proxy chain")
    orig_fuids: Optional[list[str]] = Field(None, description="Originator file UIDs")
    orig_filenames: Optional[list[str]] = Field(None, description="Originator filenames")
    orig_mime_types: Optional[list[str]] = Field(None, description="Originator MIME types")
    resp_fuids: Optional[list[str]] = Field(None, description="Responder file UIDs")
    resp_filenames: Optional[list[str]] = Field(None, description="Responder filenames")
    resp_mime_types: Optional[list[str]] = Field(None, description="Responder MIME types")


class SslLog(BaseModel):
    """Zeek SSL/TLS log (ssl.log) - TLS handshake information."""

    ts: float = Field(..., description="Timestamp of SSL handshake")
    uid: str = Field(..., description="Unique connection identifier")
    id_orig_h: str = Field(..., description="Source IP address")
    id_orig_p: int = Field(..., description="Source port")
    id_resp_h: str = Field(..., description="Destination IP address")
    id_resp_p: int = Field(..., description="Destination port")
    version: Optional[str] = Field(None, description="TLS version")
    cipher: Optional[str] = Field(None, description="Cipher suite")
    curve: Optional[str] = Field(None, description="Elliptic curve")
    server_name: Optional[str] = Field(None, description="SNI server name")
    resumed: Optional[bool] = Field(None, description="Session resumed")
    last_alert: Optional[str] = Field(None, description="Last TLS alert")
    next_protocol: Optional[str] = Field(None, description="ALPN next protocol")
    established: Optional[bool] = Field(None, description="Handshake established")
    cert_chain_fuids: Optional[list[str]] = Field(None, description="Certificate file UIDs")
    client_cert_chain_fuids: Optional[list[str]] = Field(
        None, description="Client cert file UIDs"
    )
    subject: Optional[str] = Field(None, description="Certificate subject")
    issuer: Optional[str] = Field(None, description="Certificate issuer")
    client_subject: Optional[str] = Field(None, description="Client cert subject")
    client_issuer: Optional[str] = Field(None, description="Client cert issuer")
    validation_status: Optional[str] = Field(None, description="Cert validation status")


class X509Log(BaseModel):
    """Zeek X.509 certificate log (x509.log) - Certificate details."""

    ts: float = Field(..., description="Timestamp of certificate observation")
    fingerprint: str = Field(..., description="Certificate fingerprint (SHA1)")
    certificate_version: Optional[int] = Field(None, description="X.509 version")
    certificate_serial: Optional[str] = Field(None, description="Serial number")
    certificate_subject: Optional[str] = Field(None, description="Subject DN")
    certificate_issuer: Optional[str] = Field(None, description="Issuer DN")
    certificate_not_valid_before: Optional[float] = Field(
        None, description="Valid from timestamp"
    )
    certificate_not_valid_after: Optional[float] = Field(
        None, description="Valid until timestamp"
    )
    certificate_key_alg: Optional[str] = Field(None, description="Public key algorithm")
    certificate_sig_alg: Optional[str] = Field(None, description="Signature algorithm")
    certificate_key_type: Optional[str] = Field(None, description="Key type")
    certificate_key_length: Optional[int] = Field(None, description="Key length in bits")
    certificate_exponent: Optional[str] = Field(None, description="RSA exponent")
    certificate_curve: Optional[str] = Field(None, description="EC curve name")
    san_dns: Optional[list[str]] = Field(None, description="SAN DNS names")
    san_uri: Optional[list[str]] = Field(None, description="SAN URIs")
    san_email: Optional[list[str]] = Field(None, description="SAN email addresses")
    san_ip: Optional[list[str]] = Field(None, description="SAN IP addresses")
    basic_constraints_ca: Optional[bool] = Field(None, description="Is CA certificate")
    basic_constraints_path_len: Optional[int] = Field(
        None, description="Path length constraint"
    )


class FilesLog(BaseModel):
    """Zeek files log (files.log) - File transfers over network."""

    ts: float = Field(..., description="Timestamp of file observation")
    fuid: str = Field(..., description="File unique identifier")
    tx_hosts: Optional[list[str]] = Field(None, description="Transmitting hosts")
    rx_hosts: Optional[list[str]] = Field(None, description="Receiving hosts")
    conn_uids: Optional[list[str]] = Field(None, description="Connection UIDs")
    source: Optional[str] = Field(None, description="Source protocol")
    depth: Optional[int] = Field(None, description="Depth in protocol stack")
    analyzers: Optional[list[str]] = Field(None, description="Analyzers applied")
    mime_type: Optional[str] = Field(None, description="MIME type")
    filename: Optional[str] = Field(None, description="Filename")
    duration: Optional[float] = Field(None, description="File transfer duration")
    local_orig: Optional[bool] = Field(None, description="Origin is local")
    is_orig: Optional[bool] = Field(None, description="From originator")
    seen_bytes: Optional[int] = Field(None, description="Bytes seen")
    total_bytes: Optional[int] = Field(None, description="Total bytes")
    missing_bytes: Optional[int] = Field(None, description="Missing bytes")
    overflow_bytes: Optional[int] = Field(None, description="Overflow bytes")
    timedout: Optional[bool] = Field(None, description="Transfer timed out")
    parent_fuid: Optional[str] = Field(None, description="Parent file UID")
    md5: Optional[str] = Field(None, description="MD5 hash")
    sha1: Optional[str] = Field(None, description="SHA1 hash")
    sha256: Optional[str] = Field(None, description="SHA256 hash")
    extracted: Optional[str] = Field(None, description="Extracted file path")


class NoticeLog(BaseModel):
    """Zeek notice log (notice.log) - Security notices and alerts."""

    ts: float = Field(..., description="Timestamp of notice")
    uid: Optional[str] = Field(None, description="Connection UID")
    id_orig_h: Optional[str] = Field(None, description="Source IP address")
    id_orig_p: Optional[int] = Field(None, description="Source port")
    id_resp_h: Optional[str] = Field(None, description="Destination IP address")
    id_resp_p: Optional[int] = Field(None, description="Destination port")
    fuid: Optional[str] = Field(None, description="File UID")
    file_mime_type: Optional[str] = Field(None, description="File MIME type")
    file_desc: Optional[str] = Field(None, description="File description")
    proto: Optional[str] = Field(None, description="Transport protocol")
    note: str = Field(..., description="Notice type")
    msg: Optional[str] = Field(None, description="Human-readable message")
    sub: Optional[str] = Field(None, description="Sub-message")
    src: Optional[str] = Field(None, description="Source address")
    dst: Optional[str] = Field(None, description="Destination address")
    p: Optional[int] = Field(None, description="Port")
    n: Optional[int] = Field(None, description="Count/number")
    peer_descr: Optional[str] = Field(None, description="Peer description")
    actions: Optional[list[str]] = Field(None, description="Actions taken")
    suppress_for: Optional[float] = Field(None, description="Suppression interval")
    remote_location_country_code: Optional[str] = Field(None, description="Country code")
    remote_location_region: Optional[str] = Field(None, description="Region")
    remote_location_city: Optional[str] = Field(None, description="City")
    remote_location_latitude: Optional[float] = Field(None, description="Latitude")
    remote_location_longitude: Optional[float] = Field(None, description="Longitude")


class WeirdLog(BaseModel):
    """Zeek weird log (weird.log) - Unusual network activity."""

    ts: float = Field(..., description="Timestamp of weird event")
    uid: Optional[str] = Field(None, description="Connection UID")
    id_orig_h: Optional[str] = Field(None, description="Source IP address")
    id_orig_p: Optional[int] = Field(None, description="Source port")
    id_resp_h: Optional[str] = Field(None, description="Destination IP address")
    id_resp_p: Optional[int] = Field(None, description="Destination port")
    name: str = Field(..., description="Weird event name")
    addl: Optional[str] = Field(None, description="Additional information")
    notice: Optional[bool] = Field(None, description="Notice generated")
    peer: Optional[str] = Field(None, description="Peer that noticed")


class DpdLog(BaseModel):
    """Zeek DPD log (dpd.log) - Dynamic protocol detection."""

    ts: float = Field(..., description="Timestamp of detection")
    uid: str = Field(..., description="Connection UID")
    id_orig_h: str = Field(..., description="Source IP address")
    id_orig_p: int = Field(..., description="Source port")
    id_resp_h: str = Field(..., description="Destination IP address")
    id_resp_p: int = Field(..., description="Destination port")
    proto: str = Field(..., description="Transport protocol")
    analyzer: str = Field(..., description="Analyzer name")
    failure_reason: Optional[str] = Field(None, description="Why detection failed")


class SmtpLog(BaseModel):
    """Zeek SMTP log (smtp.log) - Email traffic."""

    ts: float = Field(..., description="Timestamp of SMTP session")
    uid: str = Field(..., description="Connection UID")
    id_orig_h: str = Field(..., description="Source IP address")
    id_orig_p: int = Field(..., description="Source port")
    id_resp_h: str = Field(..., description="Destination IP address")
    id_resp_p: int = Field(..., description="Destination port")
    trans_depth: Optional[int] = Field(None, description="Transaction depth")
    helo: Optional[str] = Field(None, description="HELO/EHLO value")
    mailfrom: Optional[str] = Field(None, description="MAIL FROM address")
    rcptto: Optional[list[str]] = Field(None, description="RCPT TO addresses")
    date: Optional[str] = Field(None, description="Date header")
    from_: Optional[str] = Field(None, alias="from", description="From header")
    to: Optional[list[str]] = Field(None, description="To header")
    cc: Optional[list[str]] = Field(None, description="CC header")
    reply_to: Optional[str] = Field(None, description="Reply-To header")
    msg_id: Optional[str] = Field(None, description="Message-ID header")
    in_reply_to: Optional[str] = Field(None, description="In-Reply-To header")
    subject: Optional[str] = Field(None, description="Subject header")
    x_originating_ip: Optional[str] = Field(None, description="X-Originating-IP")
    first_received: Optional[str] = Field(None, description="First Received header")
    second_received: Optional[str] = Field(None, description="Second Received header")
    last_reply: Optional[str] = Field(None, description="Last SMTP reply")
    path: Optional[list[str]] = Field(None, description="Message path")
    user_agent: Optional[str] = Field(None, description="User-Agent header")
    tls: Optional[bool] = Field(None, description="Connection uses TLS")
    fuids: Optional[list[str]] = Field(None, description="File UIDs")
    is_webmail: Optional[bool] = Field(None, description="Webmail detected")
