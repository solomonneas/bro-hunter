from api.services.packet_inspector import packet_inspector
from api.services.demo_data import DemoDataService
from api.services.log_store import log_store


def setup_module():
    DemoDataService().load_into_store(log_store)


def test_packet_detail_found():
    uid = log_store.connections[0].uid
    detail = packet_inspector.get_connection_detail(uid)
    assert detail is not None
    assert detail["uid"] == uid
    assert "packets" in detail


def test_flow_and_payload():
    uid = log_store.connections[0].uid
    flow = packet_inspector.get_flow(uid)
    payload = packet_inspector.get_payload_preview(uid)
    assert flow is not None and len(flow) >= 2
    assert payload is not None
    assert "preview" in payload
