"""Tests for Sigma converter."""

from api.services.sigma_converter import convert_sigma_yaml


def test_convert_basic_sigma_rule():
    sigma = """
title: Suspicious User-Agent
description: Detect scripted user agents
level: high
detection:
  selection:
    UserAgent|contains: python-requests
  condition: selection
"""
    converted = convert_sigma_yaml(sigma)

    assert converted.name == "Suspicious User-Agent"
    assert converted.severity == "high"
    assert len(converted.conditions) == 1
    assert converted.conditions[0].field == "user_agent"
    assert converted.conditions[0].operator == "contains"


def test_convert_startswith_modifier():
    sigma = """
title: DoH Traffic
detection:
  selection:
    Url|startswith: /dns-query
  condition: selection
"""
    converted = convert_sigma_yaml(sigma)
    assert converted.conditions[0].operator == "regex"
    assert str(converted.conditions[0].value).startswith("^")
