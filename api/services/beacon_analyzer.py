"""
Beacon detection service for identifying C2 (command and control) communication patterns.
Analyzes connection patterns to identify hosts making periodic callbacks to external IPs.
"""
from typing import Optional
from collections import defaultdict
from datetime import datetime
import logging
import statistics
import math

from api.parsers.unified import Connection
from api.models.beacon import (
    BeaconResult,
    BeaconDetailedResult,
    BeaconIntervalHistogram,
)
from api.config.allowlists import BeaconAllowlist

logger = logging.getLogger(__name__)


class BeaconAnalyzer:
    """
    Analyzes network connections to detect beaconing behavior.

    Beaconing is characterized by:
    - Regular/periodic connection intervals (low jitter)
    - Consistent data sizes
    - Multiple connections over time
    - External destination IPs
    """

    def __init__(
        self,
        min_connections: int = 10,
        max_jitter_pct: float = 20.0,
        min_time_span_hours: float = 1.0,
        score_threshold: float = 70.0,
    ):
        """
        Initialize beacon analyzer with configuration.

        Args:
            min_connections: Minimum connections required to consider as beacon
            max_jitter_pct: Maximum jitter percentage for high-confidence beacon
            min_time_span_hours: Minimum time span (hours) for analysis
            score_threshold: Minimum score to report as beacon
        """
        self.min_connections = min_connections
        self.max_jitter_pct = max_jitter_pct
        self.min_time_span_seconds = min_time_span_hours * 3600
        self.score_threshold = score_threshold

    def analyze_connections(
        self,
        connections: list[Connection],
        include_allowlisted: bool = False,
    ) -> list[BeaconResult]:
        """
        Analyze connections to detect beaconing patterns.

        Args:
            connections: List of connections to analyze
            include_allowlisted: If False, filter out known-good periodic traffic

        Returns:
            List of detected beacons sorted by score (highest first)
        """
        logger.info(f"Analyzing {len(connections)} connections for beaconing patterns")

        # Group connections by src_ip -> dst_ip:dst_port pairs
        connection_groups = self._group_connections(connections)

        logger.info(f"Found {len(connection_groups)} unique connection pairs")

        beacons = []

        for (src_ip, dst_ip, dst_port, proto, service), conn_list in connection_groups.items():
            # Skip if too few connections
            if len(conn_list) < self.min_connections:
                continue

            # Skip allowlisted destinations unless explicitly requested
            if not include_allowlisted:
                if BeaconAllowlist.is_allowed_pair(src_ip, dst_ip, dst_port, service):
                    logger.debug(f"Skipping allowlisted pair: {src_ip} -> {dst_ip}:{dst_port}")
                    continue

            # Analyze this connection pair
            beacon = self._analyze_connection_pair(
                src_ip, dst_ip, dst_port, proto, service, conn_list
            )

            if beacon and beacon.beacon_score >= self.score_threshold:
                beacons.append(beacon)

        # Sort by score (highest first)
        beacons.sort(key=lambda b: b.beacon_score, reverse=True)

        logger.info(f"Detected {len(beacons)} beacons above threshold {self.score_threshold}")

        return beacons

    def analyze_connection_pair_detailed(
        self,
        connections: list[Connection],
        src_ip: str,
        dst_ip: str,
    ) -> Optional[BeaconDetailedResult]:
        """
        Perform detailed analysis on a specific src->dst pair with histogram data.

        Args:
            connections: List of all connections
            src_ip: Source IP to analyze
            dst_ip: Destination IP to analyze

        Returns:
            Detailed beacon result with histogram, or None if not enough data
        """
        # Filter connections for this specific pair
        pair_connections = [
            c for c in connections
            if c.src_ip == src_ip and c.dst_ip == dst_ip
        ]

        if len(pair_connections) < self.min_connections:
            return None

        # Group by port (use the most common port for this pair)
        port_groups = defaultdict(list)
        for conn in pair_connections:
            port_groups[conn.dst_port].append(conn)

        # Use the port with most connections
        dst_port, conn_list = max(port_groups.items(), key=lambda x: len(x[1]))
        proto = conn_list[0].proto
        service = conn_list[0].service

        # Perform analysis
        beacon = self._analyze_connection_pair(
            src_ip, dst_ip, dst_port, proto, service, conn_list
        )

        if not beacon:
            return None

        # Calculate intervals
        sorted_conns = sorted(conn_list, key=lambda c: c.timestamp)
        timestamps = [c.timestamp.timestamp() for c in sorted_conns]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]

        # Calculate data sizes
        data_sizes = []
        for conn in sorted_conns:
            total_bytes = 0
            if conn.bytes_sent:
                total_bytes += conn.bytes_sent
            if conn.bytes_recv:
                total_bytes += conn.bytes_recv
            if total_bytes > 0:
                data_sizes.append(total_bytes)

        # Create histogram
        histogram = self._create_histogram(intervals)

        # Create detailed result
        detailed = BeaconDetailedResult(
            **beacon.model_dump(),
            interval_histogram=histogram,
            all_intervals=intervals,
            all_timestamps=timestamps,
            all_data_sizes=data_sizes,
        )

        return detailed

    def _group_connections(
        self,
        connections: list[Connection],
    ) -> dict[tuple[str, str, int, str, Optional[str]], list[Connection]]:
        """
        Group connections by (src_ip, dst_ip, dst_port, proto, service).

        Args:
            connections: List of connections

        Returns:
            Dictionary mapping connection tuple to list of connections
        """
        groups = defaultdict(list)

        for conn in connections:
            key = (
                conn.src_ip,
                conn.dst_ip,
                conn.dst_port,
                conn.proto,
                conn.service,
            )
            groups[key].append(conn)

        return groups

    def _analyze_connection_pair(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
        service: Optional[str],
        connections: list[Connection],
    ) -> Optional[BeaconResult]:
        """
        Analyze a specific connection pair for beaconing behavior.

        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            dst_port: Destination port
            proto: Protocol
            service: Service name
            connections: List of connections for this pair

        Returns:
            BeaconResult if beaconing detected, None otherwise
        """
        # Sort by timestamp
        sorted_conns = sorted(connections, key=lambda c: c.timestamp)

        # Calculate time span
        first_timestamp = sorted_conns[0].timestamp.timestamp()
        last_timestamp = sorted_conns[-1].timestamp.timestamp()
        time_span = last_timestamp - first_timestamp

        # Skip if time span too short
        if time_span < self.min_time_span_seconds:
            return None

        # Calculate intervals between connections
        timestamps = [c.timestamp.timestamp() for c in sorted_conns]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]

        if not intervals:
            return None

        # Calculate interval statistics
        avg_interval = statistics.mean(intervals)
        median_interval = statistics.median(intervals)
        min_interval = min(intervals)
        max_interval = max(intervals)

        # Calculate standard deviation and coefficient of variation (jitter)
        if len(intervals) > 1:
            std_dev = statistics.stdev(intervals)
            jitter_pct = (std_dev / avg_interval * 100) if avg_interval > 0 else 100.0
        else:
            std_dev = 0.0
            jitter_pct = 0.0

        # Calculate data size statistics
        data_sizes = []
        for conn in sorted_conns:
            total_bytes = 0
            if conn.bytes_sent:
                total_bytes += conn.bytes_sent
            if conn.bytes_recv:
                total_bytes += conn.bytes_recv
            if total_bytes > 0:
                data_sizes.append(total_bytes)

        if data_sizes:
            data_size_avg = statistics.mean(data_sizes)
            data_size_variance = statistics.variance(data_sizes) if len(data_sizes) > 1 else 0.0
        else:
            data_size_avg = None
            data_size_variance = None

        # Calculate beacon score
        score, confidence, reasons = self._calculate_beacon_score(
            connection_count=len(connections),
            time_span=time_span,
            intervals=intervals,
            jitter_pct=jitter_pct,
            data_sizes=data_sizes,
            avg_interval=avg_interval,
        )

        # Determine MITRE techniques
        mitre_techniques = self._get_mitre_techniques(score, proto, dst_port)

        # Create result
        result = BeaconResult(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto=proto,
            connection_count=len(connections),
            time_span_seconds=time_span,
            avg_interval_seconds=avg_interval,
            median_interval_seconds=median_interval,
            min_interval_seconds=min_interval,
            max_interval_seconds=max_interval,
            interval_std_dev=std_dev,
            jitter_pct=jitter_pct,
            data_size_avg=data_size_avg,
            data_size_variance=data_size_variance,
            beacon_score=score,
            confidence=confidence,
            reasons=reasons,
            mitre_techniques=mitre_techniques,
            first_seen=first_timestamp,
            last_seen=last_timestamp,
        )

        return result

    def _calculate_beacon_score(
        self,
        connection_count: int,
        time_span: float,
        intervals: list[float],
        jitter_pct: float,
        data_sizes: list[int],
        avg_interval: float,
    ) -> tuple[float, float, list[str]]:
        """
        Calculate beacon score using multiple statistical methods.

        Args:
            connection_count: Number of connections
            time_span: Total time span in seconds
            intervals: List of intervals between connections
            jitter_pct: Jitter percentage (coefficient of variation)
            data_sizes: List of data sizes
            avg_interval: Average interval

        Returns:
            Tuple of (score, confidence, reasons)
        """
        score = 0.0
        confidence = 0.0
        reasons = []

        # Component 1: Interval regularity (40 points)
        # Low jitter = high score
        if jitter_pct <= 5.0:
            regularity_score = 40.0
            reasons.append(f"Very low jitter ({jitter_pct:.1f}%) indicates highly regular intervals")
        elif jitter_pct <= 10.0:
            regularity_score = 35.0
            reasons.append(f"Low jitter ({jitter_pct:.1f}%) indicates regular intervals")
        elif jitter_pct <= self.max_jitter_pct:
            regularity_score = 30.0 * (1.0 - (jitter_pct / self.max_jitter_pct))
            reasons.append(f"Moderate jitter ({jitter_pct:.1f}%)")
        else:
            regularity_score = 10.0 * (1.0 - min((jitter_pct - self.max_jitter_pct) / 80.0, 1.0))
            reasons.append(f"High jitter ({jitter_pct:.1f}%) reduces regularity score")

        score += regularity_score

        # Component 2: Connection count and coverage (25 points)
        # More connections = higher confidence
        if connection_count >= 100:
            count_score = 25.0
            reasons.append(f"{connection_count} connections provide strong evidence")
        elif connection_count >= 50:
            count_score = 20.0
            reasons.append(f"{connection_count} connections provide good evidence")
        elif connection_count >= self.min_connections * 2:
            count_score = 15.0
            reasons.append(f"{connection_count} connections above minimum threshold")
        else:
            count_score = 10.0
            reasons.append(f"{connection_count} connections at minimum threshold")

        score += count_score

        # Component 3: Time span coverage (15 points)
        # Longer observation period = higher confidence
        time_span_hours = time_span / 3600
        if time_span_hours >= 24:
            coverage_score = 15.0
            reasons.append(f"Observed over {time_span_hours:.1f} hours (full day+)")
        elif time_span_hours >= 8:
            coverage_score = 12.0
            reasons.append(f"Observed over {time_span_hours:.1f} hours")
        elif time_span_hours >= 4:
            coverage_score = 8.0
            reasons.append(f"Observed over {time_span_hours:.1f} hours")
        else:
            coverage_score = 5.0

        score += coverage_score

        # Component 4: Data size consistency (10 points)
        if data_sizes and len(data_sizes) > 1:
            data_variance = statistics.variance(data_sizes)
            data_mean = statistics.mean(data_sizes)
            data_cv = (math.sqrt(data_variance) / data_mean * 100) if data_mean > 0 else 100.0

            if data_cv <= 10.0:
                data_score = 10.0
                reasons.append(f"Very consistent data sizes (CV: {data_cv:.1f}%)")
            elif data_cv <= 30.0:
                data_score = 7.0
                reasons.append(f"Consistent data sizes (CV: {data_cv:.1f}%)")
            elif data_cv <= 50.0:
                data_score = 4.0
                reasons.append(f"Somewhat consistent data sizes (CV: {data_cv:.1f}%)")
            else:
                data_score = 2.0
                reasons.append(f"Variable data sizes (CV: {data_cv:.1f}%)")
        else:
            data_score = 5.0  # Neutral score if no data size info

        score += data_score

        # Component 5: Interval distribution entropy (10 points)
        # Calculate histogram entropy - lower entropy = more regular
        histogram_score = self._calculate_histogram_score(intervals)
        score += histogram_score

        if histogram_score >= 8.0:
            reasons.append("Interval distribution is highly concentrated")
        elif histogram_score >= 5.0:
            reasons.append("Interval distribution shows some concentration")

        # Calculate confidence based on sample size and time span
        confidence = min(
            1.0,
            (connection_count / 100.0) * 0.6 +
            (min(time_span_hours, 24.0) / 24.0) * 0.4
        )

        return score, confidence, reasons

    def _calculate_histogram_score(self, intervals: list[float]) -> float:
        """
        Calculate score based on interval histogram entropy.
        Lower entropy (more concentrated) = higher score.

        Args:
            intervals: List of intervals

        Returns:
            Score from 0-10
        """
        if len(intervals) < 2:
            return 5.0

        # Create histogram with 10 bins
        min_val = min(intervals)
        max_val = max(intervals)

        if max_val - min_val < 1.0:
            # All intervals very similar
            return 10.0

        num_bins = min(10, len(intervals) // 2)
        bin_width = (max_val - min_val) / num_bins

        bins = [0] * num_bins
        for interval in intervals:
            bin_idx = min(int((interval - min_val) / bin_width), num_bins - 1)
            bins[bin_idx] += 1

        # Calculate entropy
        total = sum(bins)
        entropy = 0.0
        for count in bins:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        # Max entropy for n bins is log2(n)
        max_entropy = math.log2(num_bins)

        # Normalize to 0-1, then invert (lower entropy = higher score)
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
        score = (1.0 - normalized_entropy) * 10.0

        return score

    def _create_histogram(self, intervals: list[float], num_bins: int = 20) -> BeaconIntervalHistogram:
        """
        Create histogram for interval distribution visualization.

        Args:
            intervals: List of intervals
            num_bins: Number of histogram bins

        Returns:
            BeaconIntervalHistogram object
        """
        if not intervals:
            return BeaconIntervalHistogram(
                bin_edges=[],
                bin_counts=[],
                bin_centers=[],
            )

        min_val = min(intervals)
        max_val = max(intervals)

        # Handle case where all intervals are the same
        if max_val - min_val < 0.01:
            max_val = min_val + 1.0

        bin_width = (max_val - min_val) / num_bins
        bin_edges = [min_val + i * bin_width for i in range(num_bins + 1)]
        bin_counts = [0] * num_bins
        bin_centers = [(bin_edges[i] + bin_edges[i+1]) / 2 for i in range(num_bins)]

        for interval in intervals:
            bin_idx = min(int((interval - min_val) / bin_width), num_bins - 1)
            bin_counts[bin_idx] += 1

        return BeaconIntervalHistogram(
            bin_edges=bin_edges,
            bin_counts=bin_counts,
            bin_centers=bin_centers,
        )

    def _get_mitre_techniques(self, score: float, proto: str, dst_port: int) -> list[str]:
        """
        Determine MITRE ATT&CK techniques based on beacon characteristics.

        Args:
            score: Beacon score
            proto: Protocol
            dst_port: Destination port

        Returns:
            List of MITRE technique IDs
        """
        techniques = []

        # All beacons indicate C2 communication
        techniques.append("T1071")  # Application Layer Protocol

        # Check for common C2 ports/protocols
        if dst_port == 443 or dst_port == 8443:
            techniques.append("T1071.001")  # Web Protocols (HTTPS)
        elif dst_port == 80 or dst_port == 8080:
            techniques.append("T1071.001")  # Web Protocols (HTTP)
        elif dst_port == 53:
            techniques.append("T1071.004")  # DNS

        # High-score beacons likely use encrypted channels
        if score >= 80.0 and dst_port in [443, 8443]:
            techniques.append("T1573")  # Encrypted Channel

        return techniques
