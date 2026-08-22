"""The HTTP API.

Owner: Member 7 (QA) with Member 6 (API).

Rather than shelling out to `python server.py`, these tests start the same
ThreadingHTTPServer in a background thread on an ephemeral port. That is
faster, gives real tracebacks when something breaks, and avoids a flaky
"wait for the process to boot" sleep.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine import config, store        # noqa: E402
import server as server_module          # noqa: E402


@pytest.fixture
def api(tmp_path, monkeypatch, flask_scan):
    """A running API with one stored scan, on its own port and data directory."""
    scans = tmp_path / "scans"
    exports = tmp_path / "exports"
    scans.mkdir()
    exports.mkdir()
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "SCANS_DIR", scans)
    monkeypatch.setattr(config, "EXPORTS_DIR", exports)

    store.save_scan({
        "id": "api-test-scan",
        "repo": "vuln-flask",
        "repo_path": "testdata/vuln-flask",
        "started_at": "2026-08-13T09:00:00",
        "duration_ms": 10,
        "summary": {"raw_findings": len(flask_scan["raw"]),
                    "confirmed": len(flask_scan["confirmed"]),
                    "suppressed": len(flask_scan["suppressed"]),
                    "validator": "offline"},
        "findings": [dict(finding) for finding in flask_scan["findings"]],
        "comparison": None,
    })

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server_module.Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    class Client:
        base = f"http://127.0.0.1:{port}"

        def call(self, method: str, path: str, body=None):
            data = json.dumps(body).encode() if body is not None else None
            request = urllib.request.Request(
                self.base + path, data=data, method=method,
                headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

        def get(self, path):
            return self.call("GET", path)

        def post(self, path, body=None):
            return self.call("POST", path, body or {})

    yield Client()
    httpd.shutdown()


# ==========================================================================

class TestReadEndpoints:
    def test_health(self, api):
        status, body = api.get("/api/health")
        assert status == 200
        assert body["status"] == "ok"
        assert "llm_model" in body

    def test_health_separates_configured_from_actually_used(self, api):
        """A configured key is not a working key, and the payload must say so.

        The header used to render `llm_configured` as "validator: Claude
        <model>", which claimed a model that had never answered whenever the
        key was rejected. These are three distinct facts and the API has to
        keep them distinct.
        """
        _, body = api.get("/api/health")

        assert body["llm_provider"] in ("anthropic", "openai", "offline")
        assert isinstance(body["llm_configured"], bool)
        # None until something has been scanned; a provider name afterwards.
        assert body["llm_last_used"] is None or isinstance(body["llm_last_used"], str)

        # The model must match the provider that would be tried, not a
        # hardcoded default -- the old field always said Claude even when
        # OpenAI was the configured provider.
        assert body["llm_model"] == config.llm_model_for(body["llm_provider"])

    def test_list_scans(self, api):
        status, body = api.get("/api/scans")
        assert status == 200
        assert body["scans"][0]["id"] == "api-test-scan"
        assert body["scans"][0]["confirmed"] == 11

    def test_get_one_scan(self, api):
        status, body = api.get("/api/scans/api-test-scan")
        assert status == 200
        assert body["repo"] == "vuln-flask"
        assert len(body["findings"]) == 17

    def test_unknown_scan_is_404(self, api):
        status, body = api.get("/api/scans/does-not-exist")
        assert status == 404
        assert "error" in body

    def test_list_findings_filters_by_status(self, api):
        _, confirmed = api.get("/api/findings?status=confirmed")
        _, suppressed = api.get("/api/findings?status=suppressed")
        assert confirmed["count"] == 11
        assert suppressed["count"] == 6

    def test_list_findings_filters_by_severity(self, api):
        _, body = api.get("/api/findings?status=confirmed&severity=critical")
        assert all(f["severity"] == "critical" for f in body["findings"])

    def test_get_one_finding(self, api):
        _, listing = api.get("/api/findings?status=confirmed")
        finding_id = listing["findings"][0]["id"]
        status, body = api.get(f"/api/findings/{finding_id}")
        assert status == 200
        assert body["finding"]["id"] == finding_id
        assert body["finding"]["taint_path"]

    def test_sla_endpoint(self, api):
        status, body = api.get("/api/sla")
        assert status == 200
        assert "policy_hours" in body
        assert len(body["findings"]) == 11

    def test_dedupe_endpoint(self, api):
        status, body = api.get("/api/dedupe")
        assert status == 200
        assert body["summary"]["findings_before"] == 11
        assert "clusters" in body

    def test_approvals_endpoint(self, api):
        status, body = api.get("/api/approvals")
        assert status == 200
        assert body["counts"]["pending_approval"] == 11

    def test_unknown_route_lists_what_is_available(self, api):
        status, body = api.get("/api/nope")
        assert status == 404
        assert body["available"]


class TestWriteEndpoints:
    def _first_confirmed(self, api):
        _, listing = api.get("/api/findings?status=confirmed")
        return listing["findings"][0]["id"]

    def test_the_approval_gate_over_http(self, api):
        finding_id = self._first_confirmed(api)

        status, refused = api.post(f"/api/findings/{finding_id}/apply", {"actor": "qa"})
        assert status == 400
        assert "not been approved" in refused["error"]

        status, approved = api.post(f"/api/findings/{finding_id}/approve",
                                    {"actor": "lead", "note": "checked"})
        assert status == 200 and approved["ok"]

        status, applied = api.post(f"/api/findings/{finding_id}/apply", {"actor": "lead"})
        assert status == 200 and applied["ok"]
        assert "patch" in applied

    def test_reject_requires_a_reason_over_http(self, api):
        finding_id = self._first_confirmed(api)
        status, body = api.post(f"/api/findings/{finding_id}/reject",
                                {"actor": "dev", "reason": ""})
        assert status == 400
        assert "reason" in body["error"]

    def test_starting_a_scan_returns_a_job_and_finishes(self, api):
        status, started = api.post("/api/scans", {
            "repo_path": "testdata/safe-app", "use_llm": False, "with_baseline": False})
        assert status == 202
        job_id = started["job_id"]

        for _ in range(60):
            _, job = api.get(f"/api/scans/status/{job_id}")
            if job["state"] in ("done", "error"):
                break
            time.sleep(0.25)

        assert job["state"] == "done", job
        _, scan = api.get(f"/api/scans/{job['scan_id']}")
        assert scan["summary"]["confirmed"] == 0

    def test_starting_a_scan_without_a_path_is_rejected(self, api):
        status, body = api.post("/api/scans", {})
        assert status == 400
        assert "repo_path" in body["error"]

    def test_defectdojo_export(self, api):
        status, body = api.post("/api/export/defectdojo", {"scan_id": "api-test-scan"})
        assert status == 200
        assert body["findings_exported"] == 11
        assert Path(body["path"]).exists()

    def test_malformed_json_body_is_a_400_not_a_500(self, api):
        request = urllib.request.Request(
            api.base + "/api/scans", data=b"{ not json",
            method="POST", headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(request, timeout=10)
            pytest.fail("expected an error response")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
            assert "valid JSON" in json.loads(exc.read())["error"]


class TestCors:
    def test_preflight_is_answered(self, api):
        request = urllib.request.Request(
            api.base + "/api/scans", method="OPTIONS")
        with urllib.request.urlopen(request, timeout=10) as response:
            assert response.status == 204
            assert response.headers["Access-Control-Allow-Origin"] == "*"

    def test_responses_carry_cors_headers(self, api):
        with urllib.request.urlopen(api.base + "/api/health", timeout=10) as response:
            assert response.headers["Access-Control-Allow-Origin"] == "*"
