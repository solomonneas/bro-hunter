from pathlib import Path

from api.services.case_manager import CaseManager


def test_case_crud_and_timeline(tmp_path: Path):
    manager = CaseManager(cases_dir=tmp_path)

    created = manager.create_case({"title": "Suspicious DNS", "description": "Investigate possible tunneling"})
    assert created["title"] == "Suspicious DNS"
    assert created["status"] == "open"

    case_id = created["id"]
    finding = manager.add_finding(case_id, {"type": "dns", "summary": "High-entropy queries", "severity": "high"})
    assert finding["type"] == "dns"

    note = manager.add_note(case_id, {"content": "Initial triage complete", "author": "analyst"})
    assert note["author"] == "analyst"

    ioc = manager.add_ioc(case_id, {"type": "domain", "value": "example-bad.tld", "source": "dns"})
    assert ioc["type"] == "domain"

    updated = manager.update_case(case_id, {"status": "investigating"})
    assert updated["status"] == "investigating"

    timeline = manager.get_timeline(case_id)
    assert len(timeline) >= 4


def test_case_filters(tmp_path: Path):
    manager = CaseManager(cases_dir=tmp_path)
    manager.create_case({"title": "Case A", "severity": "critical", "tags": ["dns", "c2"]})
    manager.create_case({"title": "Case B", "severity": "low", "tags": ["benign"]})

    critical = manager.list_cases(severity="critical")
    assert len(critical) == 1

    with_dns_tag = manager.list_cases(tags=["dns"])
    assert len(with_dns_tag) == 1
