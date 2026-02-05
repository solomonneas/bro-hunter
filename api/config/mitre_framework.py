"""
MITRE ATT&CK Framework Data

This module provides a static mapping of MITRE ATT&CK techniques and tactics
relevant to network-based threat hunting. The framework is used for mapping
detections to adversary behaviors and building attack narratives.

Data structure based on MITRE ATT&CK v14 (Enterprise).
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class MitreTactic:
    """MITRE ATT&CK tactic definition."""
    tactic_id: str
    name: str
    description: str


@dataclass
class MitreTechnique:
    """MITRE ATT&CK technique definition."""
    technique_id: str
    name: str
    description: str
    tactics: List[str]  # Tactic IDs this technique belongs to
    detection: str
    platforms: List[str]


# MITRE ATT&CK Tactics (focused on network-observable tactics)
TACTICS: Dict[str, MitreTactic] = {
    "TA0001": MitreTactic(
        tactic_id="TA0001",
        name="Initial Access",
        description="Trying to get into your network"
    ),
    "TA0002": MitreTactic(
        tactic_id="TA0002",
        name="Execution",
        description="Trying to run malicious code"
    ),
    "TA0003": MitreTactic(
        tactic_id="TA0003",
        name="Persistence",
        description="Trying to maintain their foothold"
    ),
    "TA0004": MitreTactic(
        tactic_id="TA0004",
        name="Privilege Escalation",
        description="Trying to gain higher-level permissions"
    ),
    "TA0005": MitreTactic(
        tactic_id="TA0005",
        name="Defense Evasion",
        description="Trying to avoid being detected"
    ),
    "TA0006": MitreTactic(
        tactic_id="TA0006",
        name="Credential Access",
        description="Trying to steal account names and passwords"
    ),
    "TA0007": MitreTactic(
        tactic_id="TA0007",
        name="Discovery",
        description="Trying to figure out your environment"
    ),
    "TA0008": MitreTactic(
        tactic_id="TA0008",
        name="Lateral Movement",
        description="Trying to move through your environment"
    ),
    "TA0009": MitreTactic(
        tactic_id="TA0009",
        name="Collection",
        description="Trying to gather data of interest"
    ),
    "TA0010": MitreTactic(
        tactic_id="TA0010",
        name="Exfiltration",
        description="Trying to steal data"
    ),
    "TA0011": MitreTactic(
        tactic_id="TA0011",
        name="Command and Control",
        description="Trying to communicate with compromised systems"
    ),
    "TA0040": MitreTactic(
        tactic_id="TA0040",
        name="Impact",
        description="Trying to manipulate, interrupt, or destroy systems and data"
    ),
}


# MITRE ATT&CK Techniques (focused on network-observable techniques)
TECHNIQUES: Dict[str, MitreTechnique] = {
    # Command and Control
    "T1071": MitreTechnique(
        technique_id="T1071",
        name="Application Layer Protocol",
        description="Adversaries may communicate using application layer protocols to avoid detection",
        tactics=["TA0011"],
        detection="Monitor for unusual network traffic patterns, beaconing behavior",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1071.001": MitreTechnique(
        technique_id="T1071.001",
        name="Web Protocols",
        description="Adversaries may communicate using HTTP/HTTPS protocols",
        tactics=["TA0011"],
        detection="Monitor for periodic HTTP/HTTPS connections, unusual user agents",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1071.004": MitreTechnique(
        technique_id="T1071.004",
        name="DNS",
        description="Adversaries may communicate using DNS protocol",
        tactics=["TA0011"],
        detection="Monitor for high DNS query volumes, unusual subdomains, encoded data in queries",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1573": MitreTechnique(
        technique_id="T1573",
        name="Encrypted Channel",
        description="Adversaries may employ encrypted channels to hide C2 communications",
        tactics=["TA0011"],
        detection="Monitor for encrypted connections to unusual destinations, SSL/TLS anomalies",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1090": MitreTechnique(
        technique_id="T1090",
        name="Proxy",
        description="Adversaries may use proxies to avoid direct connections",
        tactics=["TA0011"],
        detection="Monitor for connections through known proxy services, proxy chains",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1095": MitreTechnique(
        technique_id="T1095",
        name="Non-Application Layer Protocol",
        description="Adversaries may use non-application layer protocols for C2",
        tactics=["TA0011"],
        detection="Monitor for unusual protocol usage, custom protocols",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),

    # Exfiltration
    "T1041": MitreTechnique(
        technique_id="T1041",
        name="Exfiltration Over C2 Channel",
        description="Adversaries may steal data over their C2 channel",
        tactics=["TA0010"],
        detection="Monitor for large data transfers over C2 channels, unusual upload patterns",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1048": MitreTechnique(
        technique_id="T1048",
        name="Exfiltration Over Alternative Protocol",
        description="Adversaries may steal data over a protocol other than typical C2",
        tactics=["TA0010"],
        detection="Monitor for data transfers over unusual protocols",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1048.003": MitreTechnique(
        technique_id="T1048.003",
        name="Exfiltration Over Unencrypted Non-C2 Protocol",
        description="Adversaries may steal data over unencrypted protocols like DNS",
        tactics=["TA0010"],
        detection="Monitor for DNS queries with encoded data, high DNS traffic volumes",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1029": MitreTechnique(
        technique_id="T1029",
        name="Scheduled Transfer",
        description="Adversaries may schedule data exfiltration at specific intervals",
        tactics=["TA0010"],
        detection="Monitor for regular data transfer patterns, scheduled network activity",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1030": MitreTechnique(
        technique_id="T1030",
        name="Data Transfer Size Limits",
        description="Adversaries may exfiltrate data in small chunks to avoid detection",
        tactics=["TA0010"],
        detection="Monitor for consistent small data transfers over time",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),

    # Discovery
    "T1046": MitreTechnique(
        technique_id="T1046",
        name="Network Service Discovery",
        description="Adversaries may attempt to discover network services",
        tactics=["TA0007"],
        detection="Monitor for port scanning, service enumeration activity",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1018": MitreTechnique(
        technique_id="T1018",
        name="Remote System Discovery",
        description="Adversaries may attempt to get a listing of other systems",
        tactics=["TA0007"],
        detection="Monitor for network scanning, hostname lookups",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1590": MitreTechnique(
        technique_id="T1590",
        name="Gather Victim Network Information",
        description="Adversaries may gather information about the victim's networks",
        tactics=["TA0001"],
        detection="Monitor for network reconnaissance activity",
        platforms=["Network"]
    ),
    "T1590.002": MitreTechnique(
        technique_id="T1590.002",
        name="DNS",
        description="Adversaries may gather information via DNS enumeration",
        tactics=["TA0001"],
        detection="Monitor for excessive NXDOMAIN responses, unusual query types",
        platforms=["Network"]
    ),

    # Defense Evasion
    "T1568": MitreTechnique(
        technique_id="T1568",
        name="Dynamic Resolution",
        description="Adversaries may dynamically establish connections to C2 infrastructure",
        tactics=["TA0011"],
        detection="Monitor for fast-flux DNS, DGA activity",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1568.001": MitreTechnique(
        technique_id="T1568.001",
        name="Fast Flux DNS",
        description="Adversaries may use Fast Flux DNS to hide C2 infrastructure",
        tactics=["TA0011"],
        detection="Monitor for domains resolving to many IPs, frequently changing IPs",
        platforms=["Network"]
    ),
    "T1568.002": MitreTechnique(
        technique_id="T1568.002",
        name="Domain Generation Algorithms",
        description="Adversaries may use DGAs to periodically generate domain names for C2",
        tactics=["TA0011"],
        detection="Monitor for algorithmically generated domains, high entropy domains",
        platforms=["Network"]
    ),
    "T1001": MitreTechnique(
        technique_id="T1001",
        name="Data Obfuscation",
        description="Adversaries may obfuscate C2 traffic to avoid detection",
        tactics=["TA0011"],
        detection="Monitor for encoded data in network traffic, steganography",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),

    # Initial Access
    "T1190": MitreTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        description="Adversaries may exploit vulnerabilities in Internet-facing systems",
        tactics=["TA0001"],
        detection="Monitor for exploitation attempts, vulnerability scanning",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1133": MitreTechnique(
        technique_id="T1133",
        name="External Remote Services",
        description="Adversaries may leverage external remote services for initial access",
        tactics=["TA0001", "TA0003"],
        detection="Monitor for unusual remote access connections",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),

    # Lateral Movement
    "T1021": MitreTechnique(
        technique_id="T1021",
        name="Remote Services",
        description="Adversaries may use remote services to move laterally",
        tactics=["TA0008"],
        detection="Monitor for unusual remote service connections, RDP, SSH, etc.",
        platforms=["Linux", "Windows", "macOS", "Network"]
    ),
    "T1021.001": MitreTechnique(
        technique_id="T1021.001",
        name="Remote Desktop Protocol",
        description="Adversaries may use RDP for lateral movement",
        tactics=["TA0008"],
        detection="Monitor for unusual RDP connections, especially lateral",
        platforms=["Windows", "Network"]
    ),
    "T1021.004": MitreTechnique(
        technique_id="T1021.004",
        name="SSH",
        description="Adversaries may use SSH for lateral movement",
        tactics=["TA0008"],
        detection="Monitor for unusual SSH connections, especially lateral",
        platforms=["Linux", "macOS", "Network"]
    ),
}


class MitreFramework:
    """
    MITRE ATT&CK framework lookup and mapping utilities.

    Provides methods to:
    - Look up techniques and tactics by ID
    - Find techniques by tactic
    - Map detection types to techniques
    - Validate MITRE IDs
    """

    def __init__(self):
        self.tactics = TACTICS
        self.techniques = TECHNIQUES

    def get_tactic(self, tactic_id: str) -> Optional[MitreTactic]:
        """Get tactic by ID."""
        return self.tactics.get(tactic_id)

    def get_technique(self, technique_id: str) -> Optional[MitreTechnique]:
        """Get technique by ID."""
        return self.techniques.get(technique_id)

    def get_techniques_by_tactic(self, tactic_id: str) -> List[MitreTechnique]:
        """Get all techniques for a given tactic."""
        return [
            tech for tech in self.techniques.values()
            if tactic_id in tech.tactics
        ]

    def get_tactics_for_technique(self, technique_id: str) -> List[MitreTactic]:
        """Get all tactics for a given technique."""
        technique = self.get_technique(technique_id)
        if not technique:
            return []
        return [self.tactics[tid] for tid in technique.tactics if tid in self.tactics]

    def validate_technique_id(self, technique_id: str) -> bool:
        """Check if a technique ID is valid."""
        return technique_id in self.techniques

    def validate_tactic_id(self, tactic_id: str) -> bool:
        """Check if a tactic ID is valid."""
        return tactic_id in self.tactics

    def get_all_tactics(self) -> List[MitreTactic]:
        """Get all tactics."""
        return list(self.tactics.values())

    def get_all_techniques(self) -> List[MitreTechnique]:
        """Get all techniques."""
        return list(self.techniques.values())


# Global framework instance
mitre_framework = MitreFramework()
