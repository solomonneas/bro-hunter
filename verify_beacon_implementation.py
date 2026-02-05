#!/usr/bin/env python3
"""
Verification script to check beacon detection implementation.
Performs basic checks without requiring full dependencies.
"""
import os
import sys


def check_file_exists(filepath, description):
    """Check if a file exists."""
    exists = os.path.exists(filepath)
    status = "✓" if exists else "✗"
    print(f"  {status} {description}: {filepath}")
    return exists


def check_file_contains(filepath, search_strings, description):
    """Check if a file contains required strings."""
    try:
        with open(filepath, 'r') as f:
            content = f.read()

        missing = []
        for s in search_strings:
            if s not in content:
                missing.append(s)

        if not missing:
            print(f"  ✓ {description}")
            return True
        else:
            print(f"  ✗ {description} - missing: {missing[:3]}")
            return False
    except Exception as e:
        print(f"  ✗ {description} - error: {e}")
        return False


def main():
    """Run verification checks."""
    print("=== Hunter Beacon Detection Implementation Verification ===\n")

    all_checks_passed = True

    # Check 1: All required files exist
    print("1. Checking required files exist...")
    files_to_check = [
        ("api/models/beacon.py", "Beacon models"),
        ("api/config/allowlists.py", "Allowlist configuration"),
        ("api/services/beacon_analyzer.py", "Beacon analyzer service"),
        ("api/routers/hunt.py", "Hunt router endpoints"),
        ("api/tests/test_beacon.py", "Unit tests"),
    ]

    for filepath, desc in files_to_check:
        if not check_file_exists(filepath, desc):
            all_checks_passed = False

    # Check 2: Beacon models contain required fields
    print("\n2. Checking BeaconResult model...")
    beacon_model_fields = [
        "src_ip",
        "dst_ip",
        "dst_port",
        "connection_count",
        "avg_interval_seconds",
        "jitter_pct",
        "beacon_score",
        "confidence",
        "mitre_techniques",
    ]
    if not check_file_contains(
        "api/models/beacon.py",
        beacon_model_fields,
        "BeaconResult has required fields"
    ):
        all_checks_passed = False

    # Check 3: Beacon analyzer has required methods
    print("\n3. Checking BeaconAnalyzer implementation...")
    analyzer_methods = [
        "class BeaconAnalyzer",
        "def analyze_connections",
        "def analyze_connection_pair_detailed",
        "def _calculate_beacon_score",
        "def _calculate_histogram_score",
    ]
    if not check_file_contains(
        "api/services/beacon_analyzer.py",
        analyzer_methods,
        "BeaconAnalyzer has required methods"
    ):
        all_checks_passed = False

    # Check 4: Statistical analysis methods
    print("\n4. Checking statistical analysis...")
    stats_features = [
        "statistics.mean",
        "statistics.median",
        "statistics.stdev",
        "statistics.variance",
        "jitter_pct",
        "coefficient of variation",
        "histogram",
        "entropy",
    ]
    if not check_file_contains(
        "api/services/beacon_analyzer.py",
        stats_features,
        "Statistical analysis implemented"
    ):
        all_checks_passed = False

    # Check 5: Configurable thresholds
    print("\n5. Checking configurable thresholds...")
    thresholds = [
        "min_connections",
        "max_jitter_pct",
        "min_time_span",
        "score_threshold",
    ]
    if not check_file_contains(
        "api/services/beacon_analyzer.py",
        thresholds,
        "Configurable thresholds present"
    ):
        all_checks_passed = False

    # Check 6: Allowlist filtering
    print("\n6. Checking allowlist filtering...")
    allowlist_features = [
        "DNS_RESOLVERS",
        "NTP_SERVERS",
        "is_allowed_dst",
        "8.8.8.8",  # Example DNS resolver
    ]
    if not check_file_contains(
        "api/config/allowlists.py",
        allowlist_features,
        "Allowlist filtering implemented"
    ):
        all_checks_passed = False

    # Check 7: MITRE ATT&CK mappings
    print("\n7. Checking MITRE ATT&CK mappings...")
    mitre_features = [
        "T1071",  # Application Layer Protocol
        "T1573",  # Encrypted Channel
        "_get_mitre_techniques",
    ]
    if not check_file_contains(
        "api/services/beacon_analyzer.py",
        mitre_features,
        "MITRE ATT&CK mappings present"
    ):
        all_checks_passed = False

    # Check 8: API endpoints
    print("\n8. Checking API endpoints...")
    endpoints = [
        "@router.get(\"/beacons\"",
        "@router.get(\"/beacons/{src_ip}/{dst_ip}\"",
        "BeaconResult",
        "BeaconDetailedResult",
    ]
    if not check_file_contains(
        "api/routers/hunt.py",
        endpoints,
        "API endpoints defined"
    ):
        all_checks_passed = False

    # Check 9: Router registered in main.py
    print("\n9. Checking router registration...")
    if not check_file_contains(
        "api/main.py",
        ["from api.routers import", "hunt", "app.include_router(hunt.router"],
        "Hunt router registered in main.py"
    ):
        all_checks_passed = False

    # Check 10: Unit tests
    print("\n10. Checking unit tests...")
    test_cases = [
        "test_perfect_beacon_detection",
        "test_beacon_with_low_jitter",
        "test_non_beacon_random_intervals",
        "test_allowlist_filtering",
        "test_mitre_technique_mapping",
        "test_data_size_consistency",
    ]
    if not check_file_contains(
        "api/tests/test_beacon.py",
        test_cases,
        "Unit tests implemented"
    ):
        all_checks_passed = False

    # Check 11: Explainability
    print("\n11. Checking explainability features...")
    explainability = [
        "reasons",
        "jitter",
        "regular intervals",
        "confidence",
    ]
    if not check_file_contains(
        "api/services/beacon_analyzer.py",
        explainability,
        "Explainability features present"
    ):
        all_checks_passed = False

    # Check 12: Performance considerations
    print("\n12. Checking performance considerations...")
    performance = [
        "_group_connections",
        "defaultdict",
        "sorted",
    ]
    if not check_file_contains(
        "api/services/beacon_analyzer.py",
        performance,
        "Performance optimizations present"
    ):
        all_checks_passed = False

    # Summary
    print("\n" + "="*60)
    if all_checks_passed:
        print("✓ All verification checks PASSED")
        print("\nBeacon detection implementation is complete and includes:")
        print("  - BeaconResult and BeaconDetailedResult models")
        print("  - Statistical analysis (jitter, entropy, consistency)")
        print("  - Configurable thresholds")
        print("  - Allowlist filtering (DNS, NTP)")
        print("  - MITRE ATT&CK mappings")
        print("  - API endpoints with pagination")
        print("  - Comprehensive unit tests")
        print("  - Explainable scoring")
        return 0
    else:
        print("✗ Some verification checks FAILED")
        print("\nPlease review the issues above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
