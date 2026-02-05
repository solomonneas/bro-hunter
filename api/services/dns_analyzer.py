"""
DNS threat analysis service for detecting tunneling, DGA domains, and suspicious patterns.
Analyzes DNS queries to identify C2 channels and data exfiltration via DNS.
"""
from typing import Optional
from collections import defaultdict, Counter
from datetime import datetime
import logging
import statistics
import math
import re

from api.parsers.unified import DnsQuery
from api.models.dns_threat import (
    DnsTunnelingResult,
    DgaResult,
    DnsFastFluxResult,
    SuspiciousDnsPattern,
    DnsThreatSummary,
)

logger = logging.getLogger(__name__)


class DnsAnalyzer:
    """
    Analyzes DNS queries to detect various threat patterns:
    - DNS tunneling (data exfiltration via subdomain encoding)
    - DGA domains (algorithmically generated domains)
    - Fast-flux DNS (rapidly changing IP addresses)
    - Other suspicious DNS patterns
    """

    # Common English bigrams for DGA detection (frequency per 1000 letters)
    COMMON_BIGRAMS = {
        'th': 33.0, 'he': 30.7, 'in': 26.7, 'er': 23.1, 'an': 21.9,
        're': 17.5, 'on': 17.0, 'at': 14.9, 'en': 14.5, 'nd': 14.4,
        'ti': 14.0, 'es': 13.7, 'or': 13.6, 'te': 13.0, 'of': 12.5,
        'ed': 12.5, 'is': 12.4, 'it': 12.3, 'al': 12.0, 'ar': 11.9,
        'st': 11.6, 'to': 11.5, 'nt': 11.4, 'ng': 10.9, 'se': 10.8,
        'ha': 10.6, 'as': 10.3, 'ou': 10.3, 'io': 10.1, 've': 10.0,
    }

    # Common TLDs (trusted)
    COMMON_TLDS = {
        'com', 'net', 'org', 'edu', 'gov', 'mil',
        'co.uk', 'uk', 'ca', 'au', 'de', 'fr', 'jp',
    }

    # Suspicious TLDs often used by malware
    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq',  # Free domains
        'xyz', 'top', 'win', 'bid', 'loan',  # Commonly abused
    }

    def __init__(
        self,
        tunneling_threshold: float = 60.0,
        dga_threshold: float = 65.0,
        fast_flux_threshold: float = 70.0,
        min_queries_tunneling: int = 10,
        min_queries_dga: int = 3,
        min_queries_fast_flux: int = 5,
    ):
        """
        Initialize DNS analyzer with detection thresholds.

        Args:
            tunneling_threshold: Minimum score to report as tunneling
            dga_threshold: Minimum score to report as DGA
            fast_flux_threshold: Minimum score to report as fast-flux
            min_queries_tunneling: Minimum queries for tunneling detection
            min_queries_dga: Minimum queries for DGA detection
            min_queries_fast_flux: Minimum queries for fast-flux detection
        """
        self.tunneling_threshold = tunneling_threshold
        self.dga_threshold = dga_threshold
        self.fast_flux_threshold = fast_flux_threshold
        self.min_queries_tunneling = min_queries_tunneling
        self.min_queries_dga = min_queries_dga
        self.min_queries_fast_flux = min_queries_fast_flux

    def analyze_dns_threats(
        self,
        dns_queries: list[DnsQuery],
    ) -> DnsThreatSummary:
        """
        Perform comprehensive DNS threat analysis on all queries.

        Args:
            dns_queries: List of DNS queries to analyze

        Returns:
            DnsThreatSummary with all detected threats
        """
        logger.info(f"Analyzing {len(dns_queries)} DNS queries for threats")

        analysis_start = datetime.now().timestamp()

        # Detect various threat types
        tunneling_results = self.detect_dns_tunneling(dns_queries)
        dga_results = self.detect_dga_domains(dns_queries)
        fast_flux_results = self.detect_fast_flux(dns_queries)
        pattern_results = self.detect_suspicious_patterns(dns_queries)

        analysis_end = datetime.now().timestamp()

        # Get data time range
        if dns_queries:
            timestamps = [q.timestamp.timestamp() for q in dns_queries]
            data_start = min(timestamps)
            data_end = max(timestamps)
        else:
            data_start = None
            data_end = None

        summary = DnsThreatSummary(
            total_queries_analyzed=len(dns_queries),
            tunneling_detections=len(tunneling_results),
            dga_detections=len(dga_results),
            fast_flux_detections=len(fast_flux_results),
            other_patterns=len(pattern_results),
            top_tunneling=tunneling_results[:10],
            top_dga=dga_results[:10],
            top_fast_flux=fast_flux_results[:10],
            top_patterns=pattern_results[:10],
            analysis_start=analysis_start,
            analysis_end=analysis_end,
            data_time_range_start=data_start,
            data_time_range_end=data_end,
        )

        logger.info(
            f"DNS threat analysis complete: {len(tunneling_results)} tunneling, "
            f"{len(dga_results)} DGA, {len(fast_flux_results)} fast-flux, "
            f"{len(pattern_results)} other patterns"
        )

        return summary

    def detect_dns_tunneling(
        self,
        dns_queries: list[DnsQuery],
    ) -> list[DnsTunnelingResult]:
        """
        Detect DNS tunneling based on subdomain entropy and query patterns.

        Args:
            dns_queries: List of DNS queries

        Returns:
            List of tunneling detections sorted by score
        """
        # Group queries by (src_ip, base_domain)
        query_groups = self._group_queries_by_domain(dns_queries)

        results = []

        for (src_ip, base_domain), queries in query_groups.items():
            if len(queries) < self.min_queries_tunneling:
                continue

            result = self._analyze_tunneling_pattern(src_ip, base_domain, queries)
            if result and result.tunneling_score >= self.tunneling_threshold:
                results.append(result)

        # Sort by score
        results.sort(key=lambda r: r.tunneling_score, reverse=True)
        return results

    def detect_dga_domains(
        self,
        dns_queries: list[DnsQuery],
    ) -> list[DgaResult]:
        """
        Detect DGA (Domain Generation Algorithm) domains using lexical analysis.

        Args:
            dns_queries: List of DNS queries

        Returns:
            List of DGA detections sorted by score
        """
        # Group queries by (src_ip, domain)
        domain_groups = defaultdict(list)
        for query in dns_queries:
            key = (query.src_ip, query.query.lower())
            domain_groups[key].append(query)

        results = []

        for (src_ip, domain), queries in domain_groups.items():
            if len(queries) < self.min_queries_dga:
                continue

            result = self._analyze_dga_domain(src_ip, domain, queries)
            if result and result.dga_score >= self.dga_threshold:
                results.append(result)

        # Sort by score
        results.sort(key=lambda r: r.dga_score, reverse=True)
        return results

    def detect_fast_flux(
        self,
        dns_queries: list[DnsQuery],
    ) -> list[DnsFastFluxResult]:
        """
        Detect fast-flux DNS based on rapidly changing IP addresses.

        Args:
            dns_queries: List of DNS queries

        Returns:
            List of fast-flux detections sorted by score
        """
        # Group queries by domain and track answers
        domain_answers = defaultdict(list)

        for query in dns_queries:
            if query.answers:
                for answer in query.answers:
                    domain_answers[query.query.lower()].append({
                        'timestamp': query.timestamp.timestamp(),
                        'answer': answer,
                        'src_ip': query.src_ip,
                    })

        results = []

        for domain, answer_list in domain_answers.items():
            if len(answer_list) < self.min_queries_fast_flux:
                continue

            result = self._analyze_fast_flux_domain(domain, answer_list)
            if result and result.fast_flux_score >= self.fast_flux_threshold:
                results.append(result)

        # Sort by score
        results.sort(key=lambda r: r.fast_flux_score, reverse=True)
        return results

    def detect_suspicious_patterns(
        self,
        dns_queries: list[DnsQuery],
    ) -> list[SuspiciousDnsPattern]:
        """
        Detect other suspicious DNS patterns.

        Args:
            dns_queries: List of DNS queries

        Returns:
            List of suspicious pattern detections
        """
        results = []

        # Pattern 1: Excessive NXDOMAIN responses
        nxdomain_patterns = self._detect_excessive_nxdomain(dns_queries)
        results.extend(nxdomain_patterns)

        # Pattern 2: Unusual query types
        unusual_query_patterns = self._detect_unusual_query_types(dns_queries)
        results.extend(unusual_query_patterns)

        # Pattern 3: High query rate to single domain
        high_rate_patterns = self._detect_high_query_rate(dns_queries)
        results.extend(high_rate_patterns)

        # Sort by score
        results.sort(key=lambda r: r.suspicion_score, reverse=True)
        return results

    def _group_queries_by_domain(
        self,
        queries: list[DnsQuery],
    ) -> dict[tuple[str, str], list[DnsQuery]]:
        """
        Group queries by (src_ip, base_domain).
        Extracts base domain from full query (removes subdomain).

        Args:
            queries: List of DNS queries

        Returns:
            Dictionary mapping (src_ip, base_domain) to query list
        """
        groups = defaultdict(list)

        for query in queries:
            base_domain = self._extract_base_domain(query.query)
            key = (query.src_ip, base_domain)
            groups[key].append(query)

        return groups

    def _extract_base_domain(self, fqdn: str) -> str:
        """
        Extract base domain from FQDN.
        e.g., "a1b2c3.malware.example.com" -> "example.com"

        Args:
            fqdn: Fully qualified domain name

        Returns:
            Base domain (last two parts typically)
        """
        parts = fqdn.lower().rstrip('.').split('.')
        if len(parts) >= 2:
            # Handle common multi-part TLDs
            if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in {'co.uk', 'com.au', 'co.jp'}:
                return '.'.join(parts[-3:])
            return '.'.join(parts[-2:])
        return fqdn.lower()

    def _analyze_tunneling_pattern(
        self,
        src_ip: str,
        base_domain: str,
        queries: list[DnsQuery],
    ) -> Optional[DnsTunnelingResult]:
        """
        Analyze queries for DNS tunneling indicators.

        Args:
            src_ip: Source IP
            base_domain: Base domain
            queries: List of queries to this domain

        Returns:
            DnsTunnelingResult if tunneling detected, None otherwise
        """
        # Extract subdomains
        subdomains = []
        for query in queries:
            subdomain = query.query.lower().rstrip('.').replace(f'.{base_domain}', '')
            if subdomain and subdomain != base_domain:
                subdomains.append(subdomain)

        if not subdomains:
            return None

        # Calculate entropy for each subdomain
        entropies = [self._calculate_entropy(s) for s in subdomains]
        avg_entropy = statistics.mean(entropies)
        max_entropy = max(entropies)

        # Calculate subdomain lengths
        lengths = [len(s) for s in subdomains]
        avg_length = statistics.mean(lengths)
        max_length = max(lengths)

        # Count query types
        txt_count = sum(1 for q in queries if q.qtype and 'TXT' in q.qtype.upper())
        nxdomain_count = sum(1 for q in queries if q.rcode and 'NXDOMAIN' in q.rcode.upper())

        # Count unusual query types
        unusual_qtypes = []
        for query in queries:
            if query.qtype and query.qtype.upper() not in {'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'PTR'}:
                if query.qtype not in unusual_qtypes:
                    unusual_qtypes.append(query.qtype)

        # Estimate data exfiltrated (rough estimate based on subdomain content)
        estimated_bytes = sum(len(s) * 0.75 for s in subdomains)  # Assume ~75% efficiency

        # Calculate score
        score, confidence, reasons = self._calculate_tunneling_score(
            query_count=len(queries),
            unique_subdomains=len(set(subdomains)),
            avg_entropy=avg_entropy,
            max_entropy=max_entropy,
            avg_length=avg_length,
            max_length=max_length,
            txt_count=txt_count,
            nxdomain_count=nxdomain_count,
            unusual_qtype_count=len(unusual_qtypes),
        )

        # Get timestamps
        timestamps = [q.timestamp.timestamp() for q in queries]
        first_seen = min(timestamps)
        last_seen = max(timestamps)
        time_span = last_seen - first_seen

        # MITRE mapping
        mitre_techniques = ['T1071.004']  # Application Layer Protocol: DNS
        if txt_count > 0:
            mitre_techniques.append('T1048.003')  # Exfiltration Over Alternative Protocol: DNS
        if score >= 80:
            mitre_techniques.append('T1041')  # Exfiltration Over C2 Channel

        result = DnsTunnelingResult(
            domain=base_domain,
            src_ip=src_ip,
            query_count=len(queries),
            unique_subdomains=len(set(subdomains)),
            avg_subdomain_entropy=avg_entropy,
            max_subdomain_entropy=max_entropy,
            avg_subdomain_length=avg_length,
            max_subdomain_length=max_length,
            txt_record_queries=txt_count,
            nxdomain_responses=nxdomain_count,
            unusual_query_types=unusual_qtypes,
            estimated_bytes_exfiltrated=int(estimated_bytes),
            tunneling_score=score,
            confidence=confidence,
            reasons=reasons,
            mitre_techniques=mitre_techniques,
            first_seen=first_seen,
            last_seen=last_seen,
            time_span_seconds=time_span,
        )

        return result

    def _calculate_tunneling_score(
        self,
        query_count: int,
        unique_subdomains: int,
        avg_entropy: float,
        max_entropy: float,
        avg_length: float,
        max_length: int,
        txt_count: int,
        nxdomain_count: int,
        unusual_qtype_count: int,
    ) -> tuple[float, float, list[str]]:
        """
        Calculate DNS tunneling score based on multiple indicators.

        Args:
            query_count: Number of queries
            unique_subdomains: Number of unique subdomains
            avg_entropy: Average subdomain entropy
            max_entropy: Maximum entropy observed
            avg_length: Average subdomain length
            max_length: Maximum subdomain length
            txt_count: Number of TXT queries
            nxdomain_count: Number of NXDOMAIN responses
            unusual_qtype_count: Number of unusual query types

        Returns:
            Tuple of (score, confidence, reasons)
        """
        score = 0.0
        confidence = 0.0
        reasons = []

        # Component 1: Subdomain entropy (30 points)
        # High entropy indicates random/encoded data
        if avg_entropy >= 4.0:
            entropy_score = 30.0
            reasons.append(f"Very high subdomain entropy ({avg_entropy:.2f}) indicates data encoding")
        elif avg_entropy >= 3.5:
            entropy_score = 25.0
            reasons.append(f"High subdomain entropy ({avg_entropy:.2f}) suggests encoded data")
        elif avg_entropy >= 3.0:
            entropy_score = 20.0
            reasons.append(f"Elevated subdomain entropy ({avg_entropy:.2f})")
        else:
            entropy_score = 10.0 * (avg_entropy / 3.0)
            if avg_entropy >= 2.5:
                reasons.append(f"Moderate subdomain entropy ({avg_entropy:.2f})")

        score += entropy_score

        # Component 2: Subdomain length (20 points)
        # Long subdomains can carry more data
        if avg_length >= 40:
            length_score = 20.0
            reasons.append(f"Very long subdomains (avg {avg_length:.0f} chars) typical of tunneling")
        elif avg_length >= 25:
            length_score = 15.0
            reasons.append(f"Long subdomains (avg {avg_length:.0f} chars)")
        elif avg_length >= 15:
            length_score = 10.0
            reasons.append(f"Above-average subdomain length ({avg_length:.0f} chars)")
        else:
            length_score = 5.0

        score += length_score

        # Component 3: Query volume (15 points)
        if query_count >= 100:
            volume_score = 15.0
            reasons.append(f"High query volume ({query_count} queries)")
        elif query_count >= 50:
            volume_score = 12.0
            reasons.append(f"Significant query volume ({query_count} queries)")
        elif query_count >= 20:
            volume_score = 8.0
        else:
            volume_score = 5.0

        score += volume_score

        # Component 4: Unique subdomain diversity (15 points)
        # Many unique subdomains suggests data encoding
        uniqueness_ratio = unique_subdomains / query_count if query_count > 0 else 0
        if uniqueness_ratio >= 0.8:
            diversity_score = 15.0
            reasons.append(f"High subdomain uniqueness ({uniqueness_ratio:.0%}) indicates data encoding")
        elif uniqueness_ratio >= 0.5:
            diversity_score = 10.0
            reasons.append(f"Moderate subdomain diversity ({uniqueness_ratio:.0%})")
        else:
            diversity_score = 5.0

        score += diversity_score

        # Component 5: TXT record abuse (10 points)
        if txt_count > 0:
            txt_ratio = txt_count / query_count
            if txt_ratio >= 0.5:
                txt_score = 10.0
                reasons.append(f"Heavy TXT record usage ({txt_count}/{query_count}) for data exfiltration")
            elif txt_ratio >= 0.2:
                txt_score = 7.0
                reasons.append(f"Significant TXT record queries ({txt_count})")
            else:
                txt_score = 4.0
                reasons.append(f"TXT record queries present ({txt_count})")
        else:
            txt_score = 0.0

        score += txt_score

        # Component 6: NXDOMAIN responses (5 points)
        # Some tunneling tools use NXDOMAIN responses to encode data
        if nxdomain_count > 0:
            nxdomain_ratio = nxdomain_count / query_count
            if nxdomain_ratio >= 0.5:
                nxdomain_score = 5.0
                reasons.append(f"High NXDOMAIN rate ({nxdomain_ratio:.0%}) may indicate data encoding")
            else:
                nxdomain_score = 3.0
        else:
            nxdomain_score = 0.0

        score += nxdomain_score

        # Component 7: Unusual query types (5 points)
        if unusual_qtype_count > 0:
            unusual_score = 5.0
            reasons.append(f"Unusual query types observed: {unusual_qtype_count}")
        else:
            unusual_score = 0.0

        score += unusual_score

        # Calculate confidence
        confidence = min(1.0, (query_count / 50.0) * 0.7 + (uniqueness_ratio * 0.3))

        return score, confidence, reasons

    def _analyze_dga_domain(
        self,
        src_ip: str,
        domain: str,
        queries: list[DnsQuery],
    ) -> Optional[DgaResult]:
        """
        Analyze domain for DGA characteristics using lexical analysis.

        Args:
            src_ip: Source IP
            domain: Domain name to analyze
            queries: Queries to this domain

        Returns:
            DgaResult if DGA detected, None otherwise
        """
        # Extract domain without TLD for analysis
        domain_parts = domain.rstrip('.').split('.')
        if len(domain_parts) < 2:
            return None

        domain_name = domain_parts[-2]  # Second-level domain
        tld = '.'.join(domain_parts[-1:])

        # Skip very short domains (likely legitimate)
        if len(domain_name) < 6:
            return None

        # Calculate lexical features
        entropy = self._calculate_entropy(domain_name)
        consonant_ratio = self._calculate_consonant_ratio(domain_name)
        digit_ratio = self._calculate_digit_ratio(domain_name)
        bigram_score = self._calculate_bigram_score(domain_name)
        meaningful_parts = self._count_meaningful_parts(domain_name)

        # TLD analysis
        tld_common = tld in self.COMMON_TLDS
        tld_suspicious = tld in self.SUSPICIOUS_TLDS

        # Count response types
        nxdomain_count = sum(1 for q in queries if q.rcode and 'NXDOMAIN' in q.rcode.upper())
        success_count = sum(1 for q in queries if q.rcode and q.rcode.upper() in {'NOERROR', 'SUCCESS'})

        # Calculate DGA score
        score, confidence, reasons = self._calculate_dga_score(
            domain_name=domain_name,
            entropy=entropy,
            consonant_ratio=consonant_ratio,
            digit_ratio=digit_ratio,
            bigram_score=bigram_score,
            meaningful_parts=meaningful_parts,
            tld_common=tld_common,
            tld_suspicious=tld_suspicious,
            nxdomain_count=nxdomain_count,
            query_count=len(queries),
        )

        # Get timestamps
        timestamps = [q.timestamp.timestamp() for q in queries]
        first_seen = min(timestamps)
        last_seen = max(timestamps)

        # MITRE mapping
        mitre_techniques = ['T1071.004']  # Application Layer Protocol: DNS
        if score >= 80:
            mitre_techniques.append('T1568.002')  # Dynamic Resolution: Domain Generation Algorithms

        result = DgaResult(
            domain=domain,
            src_ip=src_ip,
            domain_entropy=entropy,
            consonant_ratio=consonant_ratio,
            digit_ratio=digit_ratio,
            bigram_score=bigram_score,
            meaningful_parts=meaningful_parts,
            query_count=len(queries),
            nxdomain_count=nxdomain_count,
            success_count=success_count,
            tld=tld,
            tld_common=tld_common,
            dga_score=score,
            confidence=confidence,
            reasons=reasons,
            mitre_techniques=mitre_techniques,
            first_seen=first_seen,
            last_seen=last_seen,
        )

        return result

    def _calculate_entropy(self, s: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Args:
            s: Input string

        Returns:
            Entropy value (higher = more random)
        """
        if not s:
            return 0.0

        # Count character frequencies
        counter = Counter(s.lower())
        length = len(s)

        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    def _calculate_consonant_ratio(self, s: str) -> float:
        """
        Calculate ratio of consonants to vowels.

        Args:
            s: Input string

        Returns:
            Consonant ratio (higher = less English-like)
        """
        vowels = set('aeiou')
        s_lower = s.lower()

        vowel_count = sum(1 for c in s_lower if c in vowels)
        consonant_count = sum(1 for c in s_lower if c.isalpha() and c not in vowels)

        if vowel_count == 0:
            return 10.0  # Very high ratio if no vowels

        return consonant_count / vowel_count

    def _calculate_digit_ratio(self, s: str) -> float:
        """
        Calculate ratio of digits in string.

        Args:
            s: Input string

        Returns:
            Digit ratio (0-1)
        """
        if not s:
            return 0.0

        digit_count = sum(1 for c in s if c.isdigit())
        return digit_count / len(s)

    def _calculate_bigram_score(self, s: str) -> float:
        """
        Calculate bigram frequency score based on English language.
        Lower score = less English-like (more likely DGA).

        Args:
            s: Input string

        Returns:
            Bigram score (0-100, lower = less English-like)
        """
        s_lower = s.lower()
        if len(s_lower) < 2:
            return 0.0

        # Extract bigrams
        bigrams = [s_lower[i:i+2] for i in range(len(s_lower) - 1)]

        # Calculate average frequency
        total_freq = 0.0
        count = 0

        for bigram in bigrams:
            if bigram.isalpha():
                freq = self.COMMON_BIGRAMS.get(bigram, 0.0)
                total_freq += freq
                count += 1

        if count == 0:
            return 0.0

        avg_freq = total_freq / count

        # Normalize to 0-100 scale (typical avg is ~10-15 for English)
        score = min(100.0, (avg_freq / 15.0) * 100.0)

        return score

    def _count_meaningful_parts(self, s: str) -> int:
        """
        Count meaningful word parts in domain name.

        Args:
            s: Input string

        Returns:
            Number of recognizable word parts
        """
        # Simple heuristic: look for common word patterns
        common_words = {
            'mail', 'web', 'www', 'ftp', 'admin', 'api', 'app', 'blog',
            'cdn', 'cloud', 'data', 'dev', 'docs', 'file', 'help', 'host',
            'info', 'login', 'media', 'mobile', 'news', 'server', 'shop',
            'site', 'test', 'user', 'video', 'wiki',
        }

        s_lower = s.lower()
        count = 0

        for word in common_words:
            if word in s_lower:
                count += 1

        return count

    def _calculate_dga_score(
        self,
        domain_name: str,
        entropy: float,
        consonant_ratio: float,
        digit_ratio: float,
        bigram_score: float,
        meaningful_parts: int,
        tld_common: bool,
        tld_suspicious: bool,
        nxdomain_count: int,
        query_count: int,
    ) -> tuple[float, float, list[str]]:
        """
        Calculate DGA score based on lexical features.

        Returns:
            Tuple of (score, confidence, reasons)
        """
        score = 0.0
        confidence = 0.0
        reasons = []

        # Component 1: Entropy (25 points)
        if entropy >= 3.8:
            entropy_score = 25.0
            reasons.append(f"Very high entropy ({entropy:.2f}) indicates random generation")
        elif entropy >= 3.3:
            entropy_score = 20.0
            reasons.append(f"High entropy ({entropy:.2f}) suggests algorithmic generation")
        elif entropy >= 2.8:
            entropy_score = 15.0
            reasons.append(f"Elevated entropy ({entropy:.2f})")
        else:
            entropy_score = 10.0 * (entropy / 2.8)

        score += entropy_score

        # Component 2: Bigram analysis (25 points)
        # Lower bigram score = less English-like = more likely DGA
        if bigram_score <= 20.0:
            bigram_points = 25.0
            reasons.append(f"Very low bigram score ({bigram_score:.1f}) - not English-like")
        elif bigram_score <= 40.0:
            bigram_points = 20.0
            reasons.append(f"Low bigram score ({bigram_score:.1f}) - unusual letter combinations")
        elif bigram_score <= 60.0:
            bigram_points = 10.0
            reasons.append(f"Below-average bigram score ({bigram_score:.1f})")
        else:
            bigram_points = 0.0

        score += bigram_points

        # Component 3: Consonant ratio (15 points)
        if consonant_ratio >= 4.0:
            consonant_points = 15.0
            reasons.append(f"Very high consonant ratio ({consonant_ratio:.1f}) - unusual")
        elif consonant_ratio >= 3.0:
            consonant_points = 10.0
            reasons.append(f"High consonant ratio ({consonant_ratio:.1f})")
        elif consonant_ratio >= 2.5:
            consonant_points = 5.0
        else:
            consonant_points = 0.0

        score += consonant_points

        # Component 4: Digit presence (10 points)
        if digit_ratio >= 0.3:
            digit_points = 10.0
            reasons.append(f"High digit ratio ({digit_ratio:.0%}) unusual for legitimate domains")
        elif digit_ratio >= 0.2:
            digit_points = 7.0
            reasons.append(f"Moderate digit presence ({digit_ratio:.0%})")
        elif digit_ratio > 0:
            digit_points = 3.0
        else:
            digit_points = 0.0

        score += digit_points

        # Component 5: Meaningful parts (10 points - inverse)
        if meaningful_parts == 0:
            meaning_points = 10.0
            reasons.append("No recognizable word parts - likely generated")
        elif meaningful_parts == 1:
            meaning_points = 5.0
        else:
            meaning_points = 0.0

        score += meaning_points

        # Component 6: TLD analysis (10 points)
        if tld_suspicious:
            tld_points = 10.0
            reasons.append("Suspicious TLD commonly used by malware")
        elif not tld_common:
            tld_points = 5.0
            reasons.append("Uncommon TLD")
        else:
            tld_points = 0.0

        score += tld_points

        # Component 7: NXDOMAIN responses (5 points)
        if nxdomain_count > 0:
            nxdomain_ratio = nxdomain_count / query_count
            if nxdomain_ratio >= 0.8:
                nxdomain_points = 5.0
                reasons.append(f"High NXDOMAIN rate ({nxdomain_ratio:.0%}) typical of DGA probing")
            else:
                nxdomain_points = 2.0
        else:
            nxdomain_points = 0.0

        score += nxdomain_points

        # Calculate confidence
        confidence = min(1.0, (query_count / 10.0) * 0.5 + 0.5)

        return score, confidence, reasons

    def _analyze_fast_flux_domain(
        self,
        domain: str,
        answer_list: list[dict],
    ) -> Optional[DnsFastFluxResult]:
        """
        Analyze domain for fast-flux characteristics.

        Args:
            domain: Domain name
            answer_list: List of DNS answers with timestamps

        Returns:
            DnsFastFluxResult if fast-flux detected, None otherwise
        """
        # Extract unique IPs
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        unique_ips = set()

        for answer_data in answer_list:
            answer = answer_data['answer']
            if ip_pattern.match(answer):
                unique_ips.add(answer)

        if len(unique_ips) < 3:
            return None

        # Calculate time span
        timestamps = [a['timestamp'] for a in answer_list]
        first_seen = min(timestamps)
        last_seen = max(timestamps)
        time_span = last_seen - first_seen

        if time_span < 3600:  # Less than 1 hour
            return None

        # Calculate IP change rate
        time_span_hours = time_span / 3600
        ip_changes_per_hour = len(unique_ips) / time_span_hours if time_span_hours > 0 else 0

        # Analyze TTL (if available - would need to be added to DnsQuery model)
        # For now, use placeholder
        avg_ttl = 300.0  # Typical fast-flux TTL is low (5 minutes)
        min_ttl = 60.0

        # Calculate score
        score, confidence, reasons = self._calculate_fast_flux_score(
            unique_ips=len(unique_ips),
            query_count=len(answer_list),
            ip_changes_per_hour=ip_changes_per_hour,
            avg_ttl=avg_ttl,
            time_span_hours=time_span_hours,
        )

        # MITRE mapping
        mitre_techniques = ['T1071.004']  # Application Layer Protocol: DNS
        if score >= 80:
            mitre_techniques.append('T1568.001')  # Dynamic Resolution: Fast Flux DNS

        result = DnsFastFluxResult(
            domain=domain,
            unique_ips=len(unique_ips),
            ip_list=list(unique_ips),
            avg_ttl=avg_ttl,
            min_ttl=min_ttl,
            query_count=len(answer_list),
            ip_changes_per_hour=ip_changes_per_hour,
            distinct_asns=0,  # Would need ASN lookup
            distinct_countries=0,  # Would need GeoIP lookup
            fast_flux_score=score,
            confidence=confidence,
            reasons=reasons,
            mitre_techniques=mitre_techniques,
            first_seen=first_seen,
            last_seen=last_seen,
            time_span_seconds=time_span,
        )

        return result

    def _calculate_fast_flux_score(
        self,
        unique_ips: int,
        query_count: int,
        ip_changes_per_hour: float,
        avg_ttl: float,
        time_span_hours: float,
    ) -> tuple[float, float, list[str]]:
        """
        Calculate fast-flux score.

        Returns:
            Tuple of (score, confidence, reasons)
        """
        score = 0.0
        confidence = 0.0
        reasons = []

        # Component 1: Number of unique IPs (40 points)
        if unique_ips >= 20:
            ip_score = 40.0
            reasons.append(f"Very high number of unique IPs ({unique_ips})")
        elif unique_ips >= 10:
            ip_score = 30.0
            reasons.append(f"High number of unique IPs ({unique_ips})")
        elif unique_ips >= 5:
            ip_score = 20.0
            reasons.append(f"Multiple unique IPs ({unique_ips})")
        else:
            ip_score = 10.0

        score += ip_score

        # Component 2: IP change rate (30 points)
        if ip_changes_per_hour >= 5.0:
            rate_score = 30.0
            reasons.append(f"Very high IP change rate ({ip_changes_per_hour:.1f}/hour)")
        elif ip_changes_per_hour >= 2.0:
            rate_score = 25.0
            reasons.append(f"High IP change rate ({ip_changes_per_hour:.1f}/hour)")
        elif ip_changes_per_hour >= 1.0:
            rate_score = 15.0
            reasons.append(f"Moderate IP change rate ({ip_changes_per_hour:.1f}/hour)")
        else:
            rate_score = 5.0

        score += rate_score

        # Component 3: Low TTL (20 points)
        if avg_ttl <= 300:
            ttl_score = 20.0
            reasons.append(f"Low TTL ({avg_ttl:.0f}s) enables rapid IP rotation")
        elif avg_ttl <= 600:
            ttl_score = 15.0
            reasons.append(f"Below-average TTL ({avg_ttl:.0f}s)")
        elif avg_ttl <= 1800:
            ttl_score = 10.0
        else:
            ttl_score = 0.0

        score += ttl_score

        # Component 4: Observation period (10 points)
        if time_span_hours >= 24:
            period_score = 10.0
            reasons.append(f"Observed over {time_span_hours:.1f} hours")
        elif time_span_hours >= 12:
            period_score = 7.0
        elif time_span_hours >= 4:
            period_score = 5.0
        else:
            period_score = 2.0

        score += period_score

        # Calculate confidence
        confidence = min(1.0, (query_count / 20.0) * 0.6 + (time_span_hours / 24.0) * 0.4)

        return score, confidence, reasons

    def _detect_excessive_nxdomain(
        self,
        dns_queries: list[DnsQuery],
    ) -> list[SuspiciousDnsPattern]:
        """
        Detect hosts generating excessive NXDOMAIN responses.

        Args:
            dns_queries: List of DNS queries

        Returns:
            List of suspicious patterns
        """
        # Group by source IP
        ip_queries = defaultdict(list)
        for query in dns_queries:
            ip_queries[query.src_ip].append(query)

        results = []

        for src_ip, queries in ip_queries.items():
            nxdomain_count = sum(1 for q in queries if q.rcode and 'NXDOMAIN' in q.rcode.upper())

            if nxdomain_count < 10:
                continue

            nxdomain_ratio = nxdomain_count / len(queries)

            if nxdomain_ratio >= 0.5:
                score = 70.0 + (nxdomain_ratio * 30.0)
                confidence = min(1.0, nxdomain_count / 50.0)

                timestamps = [q.timestamp.timestamp() for q in queries]

                result = SuspiciousDnsPattern(
                    pattern_type="excessive_nxdomain",
                    src_ip=src_ip,
                    query_count=len(queries),
                    unique_domains=len(set(q.query for q in queries)),
                    anomaly_indicators=[
                        f"NXDOMAIN rate: {nxdomain_ratio:.0%}",
                        f"Total NXDOMAIN: {nxdomain_count}",
                    ],
                    suspicion_score=score,
                    confidence=confidence,
                    reasons=[
                        f"High NXDOMAIN response rate ({nxdomain_ratio:.0%})",
                        f"{nxdomain_count} failed DNS lookups may indicate scanning or DGA probing",
                    ],
                    mitre_techniques=['T1046', 'T1590.002'],  # Network Service Discovery, DNS enumeration
                    first_seen=min(timestamps),
                    last_seen=max(timestamps),
                )

                results.append(result)

        return results

    def _detect_unusual_query_types(
        self,
        dns_queries: list[DnsQuery],
    ) -> list[SuspiciousDnsPattern]:
        """
        Detect unusual DNS query types that may indicate reconnaissance or tunneling.

        Args:
            dns_queries: List of DNS queries

        Returns:
            List of suspicious patterns
        """
        # Group by source IP and query type
        ip_qtype_counts = defaultdict(lambda: defaultdict(int))

        for query in dns_queries:
            if query.qtype and query.qtype.upper() not in {'A', 'AAAA', 'CNAME', 'MX', 'PTR', 'NS'}:
                ip_qtype_counts[query.src_ip][query.qtype] += 1

        results = []

        for src_ip, qtype_counts in ip_qtype_counts.items():
            total_unusual = sum(qtype_counts.values())

            if total_unusual < 5:
                continue

            score = min(80.0, 40.0 + (total_unusual * 2.0))
            confidence = min(1.0, total_unusual / 20.0)

            # Get timestamps
            ip_queries = [q for q in dns_queries if q.src_ip == src_ip]
            timestamps = [q.timestamp.timestamp() for q in ip_queries]

            result = SuspiciousDnsPattern(
                pattern_type="unusual_query_types",
                src_ip=src_ip,
                query_count=len(ip_queries),
                anomaly_indicators=[f"{qtype}: {count}" for qtype, count in qtype_counts.items()],
                suspicion_score=score,
                confidence=confidence,
                reasons=[
                    f"Unusual DNS query types: {', '.join(qtype_counts.keys())}",
                    f"{total_unusual} non-standard queries may indicate reconnaissance or tunneling",
                ],
                mitre_techniques=['T1590.002', 'T1071.004'],  # DNS enumeration, DNS protocol
                first_seen=min(timestamps),
                last_seen=max(timestamps),
            )

            results.append(result)

        return results

    def _detect_high_query_rate(
        self,
        dns_queries: list[DnsQuery],
    ) -> list[SuspiciousDnsPattern]:
        """
        Detect abnormally high query rates to single domains.

        Args:
            dns_queries: List of DNS queries

        Returns:
            List of suspicious patterns
        """
        # Group by (src_ip, domain)
        ip_domain_queries = defaultdict(list)

        for query in dns_queries:
            key = (query.src_ip, query.query.lower())
            ip_domain_queries[key].append(query)

        results = []

        for (src_ip, domain), queries in ip_domain_queries.items():
            if len(queries) < 50:
                continue

            # Calculate time span
            timestamps = [q.timestamp.timestamp() for q in queries]
            time_span = max(timestamps) - min(timestamps)

            if time_span < 60:  # Less than 1 minute
                continue

            queries_per_minute = (len(queries) / time_span) * 60

            if queries_per_minute >= 10:
                score = min(90.0, 60.0 + (queries_per_minute * 2.0))
                confidence = min(1.0, len(queries) / 100.0)

                result = SuspiciousDnsPattern(
                    pattern_type="high_query_rate",
                    domain=domain,
                    src_ip=src_ip,
                    query_count=len(queries),
                    anomaly_indicators=[
                        f"Query rate: {queries_per_minute:.1f}/minute",
                        f"Time span: {time_span:.0f}s",
                    ],
                    suspicion_score=score,
                    confidence=confidence,
                    reasons=[
                        f"Very high query rate ({queries_per_minute:.1f} queries/minute) to {domain}",
                        "May indicate automated tunneling, exfiltration, or beaconing",
                    ],
                    mitre_techniques=['T1071.004', 'T1041'],  # DNS protocol, C2 exfiltration
                    first_seen=min(timestamps),
                    last_seen=max(timestamps),
                )

                results.append(result)

        return results
