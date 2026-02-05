"""
Allowlists for filtering known-good periodic traffic.
These prevent false positives in beacon detection.
"""
from typing import Set


class BeaconAllowlist:
    """
    Manages allowlists for beacon detection.
    Filters out known-good periodic traffic that shouldn't be flagged as beaconing.
    """

    # Common DNS resolvers (Google, Cloudflare, Quad9, OpenDNS)
    DNS_RESOLVERS: Set[str] = {
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "9.9.9.9",
        "149.112.112.112",
        "208.67.222.222",
        "208.67.220.220",
    }

    # Common NTP servers
    NTP_SERVERS: Set[str] = {
        "time.google.com",
        "time.cloudflare.com",
        "pool.ntp.org",
        "time.windows.com",
        "time.apple.com",
        "time.nist.gov",
    }

    # Common NTP server IPs (pool.ntp.org rotates, but these are common)
    NTP_SERVER_IPS: Set[str] = {
        "216.229.0.179",  # NIST time servers
        "132.163.97.1",
        "132.163.97.2",
        "129.6.15.28",
        "129.6.15.29",
    }

    # Well-known services that beacon legitimately
    KNOWN_PERIODIC_SERVICES: Set[str] = {
        "ntp",
        "dns",
    }

    # Ports for known periodic services
    KNOWN_PERIODIC_PORTS: Set[int] = {
        53,   # DNS
        123,  # NTP
    }

    @classmethod
    def is_allowed_dst(cls, dst_ip: str, dst_port: int, service: str = None) -> bool:
        """
        Check if a destination should be filtered out (allowed).

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            service: Optional service name

        Returns:
            True if this destination should be filtered out (is known-good)
        """
        # Check DNS resolvers
        if dst_port == 53 or dst_ip in cls.DNS_RESOLVERS:
            return True

        # Check NTP servers
        if dst_port == 123 or dst_ip in cls.NTP_SERVER_IPS:
            return True

        # Check service name
        if service and service.lower() in cls.KNOWN_PERIODIC_SERVICES:
            return True

        # Check port
        if dst_port in cls.KNOWN_PERIODIC_PORTS:
            return True

        return False

    @classmethod
    def is_allowed_pair(cls, src_ip: str, dst_ip: str, dst_port: int, service: str = None) -> bool:
        """
        Check if a specific src->dst pair should be filtered.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port
            service: Optional service name

        Returns:
            True if this pair should be filtered out
        """
        # Use the destination check for now
        # Can be extended with src_ip specific rules if needed
        return cls.is_allowed_dst(dst_ip, dst_port, service)

    @classmethod
    def add_custom_allowlist_ip(cls, ip: str, list_type: str = "dns"):
        """
        Add a custom IP to an allowlist.

        Args:
            ip: IP address to add
            list_type: Type of list ("dns", "ntp", or "custom")
        """
        if list_type == "dns":
            cls.DNS_RESOLVERS.add(ip)
        elif list_type == "ntp":
            cls.NTP_SERVER_IPS.add(ip)
        else:
            # Could extend with custom allowlist in the future
            pass

    @classmethod
    def remove_custom_allowlist_ip(cls, ip: str):
        """
        Remove a custom IP from all allowlists.

        Args:
            ip: IP address to remove
        """
        cls.DNS_RESOLVERS.discard(ip)
        cls.NTP_SERVER_IPS.discard(ip)
