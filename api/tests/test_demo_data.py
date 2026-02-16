from api.services.demo_data import DemoDataService, sanitize_ip
from api.services.log_store import LogStore


def test_demo_loader_populates_store():
    store = LogStore()
    stats = DemoDataService().load_into_store(store)
    assert stats["connections"] > 0
    assert stats["dns_queries"] > 0


def test_sanitize_ip_maps_to_docs_ranges():
    mapped = sanitize_ip("8.8.8.8")
    assert mapped.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
