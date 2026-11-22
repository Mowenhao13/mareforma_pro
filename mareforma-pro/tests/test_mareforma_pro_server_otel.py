"""Local collector protocol, SQLite persistence, and OTel projection."""

from __future__ import annotations

import json
import os
from pathlib import Path

from mareforma_pro.collector import RootlessCollector
from mareforma_pro.evidence import (
    OPAQUE_COMPUTED_NO_EXTERNAL_SOURCE,
    SOURCE_NOT_APPLICABLE,
    ScopeEvidence,
)
from mareforma_pro.otel import (
    AsyncJsonlSpanExporter,
    process_spans_from_evidence,
    scope_span_from_evidence,
)
from mareforma_pro.server import CollectorClient, CollectorServer
from mareforma_pro.store import ReceiptStore


def test_collector_server_round_trip(tmp_path: Path):
    socket_path = tmp_path / "collector.sock"
    db_path = tmp_path / "receipts.sqlite"
    store = ReceiptStore(db_path)
    collector = RootlessCollector("secret", store=store)
    server = CollectorServer(socket_path, collector, auth_token="token")
    server.serve_in_thread()
    try:
        client = CollectorClient(socket_path, token="token")
        opened = client.request(
            {
                "op": "open_scope",
                "scope_id": "scp_1",
                "root_passthrough": True,
            }
        )
        assert opened["ok"] is True
        ingested = client.request(
            {
                "op": "ingest_events",
                "scope_id": "scp_1",
                "observed_files": ["/data/a.csv"],
            }
        )
        assert ingested["ok"] is True
        closed = client.request({"op": "close_scope", "scope_id": "scp_1"})
        assert closed["ok"] is True
        assert collector.verify(closed["receipt"]).evidence.observed_files == ("/data/a.csv",)
        assert store.load("scp_1") is not None
    finally:
        server.shutdown()
        store.close()


def test_collector_server_rejects_bad_token(tmp_path: Path):
    server = CollectorServer(
        tmp_path / "collector.sock",
        RootlessCollector("secret"),
        auth_token="token",
    )
    server.serve_in_thread()
    try:
        response = CollectorClient(
            tmp_path / "collector.sock", token="bad"
        ).request({"op": "health"})
        assert response["ok"] is False
        assert response["error"] == "unauthorized"
    finally:
        server.shutdown()


def test_collector_server_round_trips_url_manifest_and_source_requirement(tmp_path: Path):
    socket_path = tmp_path / "collector.sock"
    collector = RootlessCollector("secret")
    server = CollectorServer(socket_path, collector)
    server.serve_in_thread()
    try:
        client = CollectorClient(socket_path)
        opened = client.request(
            {
                "op": "open_scope",
                "scope_id": "scp_url",
                "evidence_level": "APPLICATION_HTTP",
                "read_semantics": "URL_READ",
                "collector_mode": "application_http",
            }
        )
        assert opened["ok"] is True
        ingested = client.request(
            {
                "op": "ingest_events",
                "scope_id": "scp_url",
                "observed_urls": ["https://api.example.org/v1/protein?token=secret"],
                "payload_digests": ["sha256:" + "a" * 64],
            }
        )
        assert ingested["ok"] is True
        closed = client.request({"op": "close_scope", "scope_id": "scp_url"})
        receipt = closed["receipt"]
        assert receipt["observed_urls"] == ["https://api.example.org/v1/protein"]
        assert "secret" not in json.dumps(receipt)

        opened_compute = client.request(
            {
                "op": "open_scope",
                "scope_id": "scp_compute",
                "source_requirement": SOURCE_NOT_APPLICABLE,
            }
        )
        assert opened_compute["ok"] is True
        closed_compute = client.request(
            {"op": "close_scope", "scope_id": "scp_compute"}
        )
        verified = collector.verify(closed_compute["receipt"])
        assert verified.evidence.source_requirement == SOURCE_NOT_APPLICABLE
        verdict = collector.verify(closed_compute["receipt"])
        from mareforma_pro.observe import verdict_from_evidence

        computed = verdict_from_evidence(verdict, cites=None)
        assert OPAQUE_COMPUTED_NO_EXTERNAL_SOURCE in computed.opaque_reasons
    finally:
        server.shutdown()


def test_collector_server_rejects_invalid_source_requirement(tmp_path: Path):
    socket_path = tmp_path / "collector.sock"
    server = CollectorServer(socket_path, RootlessCollector("secret"))
    server.serve_in_thread()
    try:
        response = CollectorClient(socket_path).request(
            {
                "op": "open_scope",
                "scope_id": "scp_bad",
                "source_requirement": "sometimes",
            }
        )
        assert response["ok"] is False
        assert "source_requirement" in response["error"]
    finally:
        server.shutdown()


def test_otel_span_and_jsonl_export(tmp_path: Path):
    collector = RootlessCollector("secret")
    collector.open_scope("scp_otel", root_passthrough=True)
    collector.ingest_events(
        "scp_otel",
        observed_files=["/data/a.csv"],
        observed_urls=["https://api.example.org/v1/protein?token=secret"],
    )
    evidence = collector.close_scope("scp_otel")
    span = scope_span_from_evidence(evidence, verdict="GROUNDED")
    assert span["name"] == "mareforma.scope"
    assert span["attributes"]["mareforma.scope_id"] == "scp_otel"
    assert span["attributes"]["mareforma.observed_urls"] == [
        "https://api.example.org/v1/protein"
    ]
    out = tmp_path / "spans.jsonl"
    exporter = AsyncJsonlSpanExporter(out)
    exporter.export(span)
    exporter.close()
    record = json.loads(out.read_text().strip())
    assert record["attributes"]["mareforma.grounding"] == "GROUNDED"


def test_collector_server_rejects_a_different_uid(tmp_path: Path, monkeypatch):
    import mareforma_pro.server as server_module

    monkeypatch.setattr(
        server_module,
        "_peer_credentials",
        lambda _connection: (123, os.getuid() + 1, os.getgid()),
    )
    server = CollectorServer(
        tmp_path / "collector.sock",
        RootlessCollector("secret"),
    )
    server.serve_in_thread()
    try:
        response = CollectorClient(tmp_path / "collector.sock").request({"op": "health"})
        assert response == {"ok": False, "error": "peer_uid_mismatch"}
    finally:
        server.shutdown()



def test_otel_process_tree_becomes_nested_spans():
    evidence = ScopeEvidence(
        scope_id="scp_tree",
        opened_at=10.0,
        closed_at=11.0,
        processes=(
            {"pid": 10, "syscall": "execve", "binary": "/bin/sh"},
            {"pid": 11, "parent_pid": 10, "syscall": "clone"},
            {"pid": 11, "syscall": "execve", "binary": "/bin/cat"},
        ),
    )
    spans = process_spans_from_evidence(evidence, verdict="GROUNDED")
    assert spans[0]["name"] == "mareforma.scope"
    child = {span["attributes"]["mareforma.process.pid"]: span for span in spans[1:]}
    assert child[10]["parent_span_id"] == spans[0]["span_id"]
    assert child[11]["parent_span_id"] == child[10]["span_id"]
    assert child[11]["attributes"]["mareforma.process.binary"] == "/bin/cat"
    assert child[11]["trace_id"] == spans[0]["trace_id"]

def test_collector_exports_root_and_process_spans_on_close(tmp_path: Path):
    out = tmp_path / "auto-spans.jsonl"
    exporter = AsyncJsonlSpanExporter(out)
    collector = RootlessCollector("secret", span_exporter=exporter)
    collector.open_scope("scp_auto", root_passthrough=True)
    collector.ingest_events("scp_auto", observed_files=["/data/a.csv"])
    collector.close_scope("scp_auto")
    exporter.close()
    records = [json.loads(line) for line in out.read_text().splitlines()]
    assert records[0]["name"] == "mareforma.scope"
    assert records[0]["attributes"]["mareforma.scope_id"] == "scp_auto"


def test_exporter_failure_does_not_change_the_receipt(tmp_path: Path):
    class BrokenExporter:
        def export(self, span):
            raise RuntimeError("telemetry is down")

    collector = RootlessCollector("secret", span_exporter=BrokenExporter())
    collector.open_scope("scp_broken_export", root_passthrough=True)
    collector.ingest_events("scp_broken_export", observed_files=["/data/a.csv"])
    evidence = collector.close_scope("scp_broken_export")
    assert collector.verify(evidence).evidence.observed_files == ("/data/a.csv",)
