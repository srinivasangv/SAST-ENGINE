"""Storage, the approval gate, SLA escalation, and the DefectDojo export.

Owner: Member 7 (QA) with Member 6 (workflow).

Every test here writes to a temporary data directory, so running the suite
never touches the scans a demo depends on.
"""

from __future__ import annotations

import json
import time

import pytest

from engine import approvals, config, defectdojo, sla, store


@pytest.fixture
def isolated_data(tmp_path, monkeypatch):
    """Point the store at a throwaway directory for the duration of one test."""
    scans = tmp_path / "scans"
    exports = tmp_path / "exports"
    scans.mkdir()
    exports.mkdir()
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "SCANS_DIR", scans)
    monkeypatch.setattr(config, "EXPORTS_DIR", exports)
    return tmp_path


@pytest.fixture
def stored_scan(isolated_data, flask_scan):
    scan = {
        "id": "test-scan-001",
        "repo": "vuln-flask",
        "repo_path": "testdata/vuln-flask",
        # NOW, not a fixed date -- see tests/test_requirements.py for why.
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "duration_ms": 42,
        "summary": {"raw_findings": len(flask_scan["raw"]),
                    "confirmed": len(flask_scan["confirmed"]),
                    "suppressed": len(flask_scan["suppressed"])},
        "findings": flask_scan["findings"],
    }
    store.save_scan(scan)
    return scan


# ==========================================================================
# store.py
# ==========================================================================

class TestStore:
    def test_round_trip(self, stored_scan):
        loaded = store.load_scan("test-scan-001")
        assert loaded["repo"] == "vuln-flask"
        assert len(loaded["findings"]) == len(stored_scan["findings"])

    def test_missing_scan_returns_none(self, isolated_data):
        assert store.load_scan("nope") is None

    def test_a_corrupt_file_is_skipped_not_fatal(self, isolated_data, stored_scan):
        (config.SCANS_DIR / "broken.json").write_text("{ not json")
        # Listing must still work -- one bad file cannot break the dashboard.
        assert len(store.list_scans()) == 1

    def test_two_scans_are_independent(self, isolated_data, stored_scan):
        second = dict(stored_scan, id="test-scan-002", repo="vuln-express")
        store.save_scan(second)
        assert len(store.list_scans()) == 2
        assert store.load_scan("test-scan-001")["repo"] == "vuln-flask"
        assert store.load_scan("test-scan-002")["repo"] == "vuln-express"

    def test_find_and_update_a_finding(self, stored_scan):
        finding_id = stored_scan["findings"][0]["id"]
        store.update_finding(finding_id, {"marker": "touched"})
        _, reloaded = store.find_finding(finding_id)
        assert reloaded["marker"] == "touched"


# ==========================================================================
# approvals.py -- the human gate
# ==========================================================================

class TestApprovalGate:
    def _confirmed_id(self, scan):
        return next(f["id"] for f in scan["findings"] if f["status"] == "confirmed")

    def test_a_fix_starts_out_pending(self, stored_scan):
        finding_id = self._confirmed_id(stored_scan)
        _, finding = store.find_finding(finding_id)
        assert finding["fix_status"] == "pending_approval"

    def test_applying_without_approval_is_refused(self, stored_scan):
        """THE GATE. This is the test that must never be deleted."""
        finding_id = self._confirmed_id(stored_scan)
        result = approvals.apply_fix(finding_id, actor="someone")
        assert result["ok"] is False
        assert "not been approved" in result["error"]

        _, finding = store.find_finding(finding_id)
        assert finding["fix_status"] == "pending_approval", "state must not have moved"

    def test_approve_then_apply(self, stored_scan):
        finding_id = self._confirmed_id(stored_scan)

        approved = approvals.approve(finding_id, actor="security-lead", note="checked by hand")
        assert approved["ok"]
        assert approved["finding"]["fix_status"] == "approved"

        applied = approvals.apply_fix(finding_id, actor="security-lead")
        assert applied["ok"]
        assert "patch" in applied
        assert applied["finding"]["fix_status"] == "applied"

    def test_rejection_requires_a_reason(self, stored_scan):
        finding_id = self._confirmed_id(stored_scan)
        assert approvals.reject(finding_id, actor="dev", reason="")["ok"] is False
        assert approvals.reject(finding_id, actor="dev", reason="wrong fix")["ok"] is True

    def test_a_rejected_fix_records_who_and_why(self, stored_scan):
        finding_id = self._confirmed_id(stored_scan)
        approvals.reject(finding_id, actor="alice", reason="this endpoint is internal only")
        _, finding = store.find_finding(finding_id)
        assert finding["fix_status"] == "rejected"
        assert finding["approval_actor"] == "alice"
        assert "internal only" in finding["approval_note"]

    def test_an_applied_fix_cannot_be_re_approved(self, stored_scan):
        finding_id = self._confirmed_id(stored_scan)
        approvals.approve(finding_id, actor="lead")
        approvals.apply_fix(finding_id, actor="lead")
        assert approvals.approve(finding_id, actor="lead")["ok"] is False

    def test_a_rejected_fix_can_be_reopened(self, stored_scan):
        finding_id = self._confirmed_id(stored_scan)
        approvals.reject(finding_id, actor="dev", reason="not now")
        assert approvals.reopen(finding_id, actor="lead")["ok"] is True

    def test_a_suppressed_finding_has_nothing_to_approve(self, stored_scan):
        suppressed_id = next(
            f["id"] for f in stored_scan["findings"] if f["status"] == "suppressed")
        result = approvals.approve(suppressed_id, actor="lead")
        assert result["ok"] is False
        assert "confirmed" in result["error"]

    def test_every_decision_is_recorded_in_history(self, stored_scan):
        finding_id = self._confirmed_id(stored_scan)
        approvals.reject(finding_id, actor="dev", reason="wrong")
        approvals.reopen(finding_id, actor="lead")
        approvals.approve(finding_id, actor="lead", note="second look")
        _, finding = store.find_finding(finding_id)
        assert len(finding["approval_history"]) == 3
        assert [entry["to"] for entry in finding["approval_history"]] == [
            "rejected", "pending_approval", "approved"]

    def test_the_queue_groups_by_state(self, stored_scan):
        finding_id = self._confirmed_id(stored_scan)
        approvals.approve(finding_id, actor="lead")
        queue = approvals.queue()
        assert queue["counts"]["approved"] == 1
        assert queue["counts"]["pending_approval"] == len(
            [f for f in stored_scan["findings"] if f["status"] == "confirmed"]) - 1


# ==========================================================================
# sla.py against stored data
# ==========================================================================

class TestSlaReport:
    def test_a_fresh_scan_has_no_breaches(self, stored_scan):
        sla.apply_to_scan(stored_scan)
        store.save_scan(stored_scan)
        report = sla.report()
        assert report["breached"] == 0

    def test_an_aged_finding_breaches_and_escalates(self, stored_scan):
        sla.apply_to_scan(stored_scan)
        store.save_scan(stored_scan)

        finding_id = next(f["id"] for f in stored_scan["findings"]
                          if f["status"] == "confirmed")
        # Age this one finding past its 24-hour critical budget.
        report = sla.report(age_override={finding_id: 200.0})

        assert report["breached"] == 1
        escalation = report["escalations"][0]
        assert escalation["finding_id"] == finding_id
        assert escalation["overdue_by_hours"] > 0
        assert escalation["escalate_to"]


# ==========================================================================
# defectdojo.py
# ==========================================================================

class TestDefectDojoExport:
    def test_exports_only_confirmed_findings_by_default(self, stored_scan, isolated_data):
        result = defectdojo.export(stored_scan)
        document = json.loads(open(result["path"]).read())
        assert result["findings_exported"] == len(
            [f for f in stored_scan["findings"] if f["status"] == "confirmed"])
        assert all(entry["active"] for entry in document["findings"])

    def test_can_include_suppressed_as_false_positives(self, stored_scan, isolated_data):
        result = defectdojo.export(stored_scan, include_suppressed=True)
        document = json.loads(open(result["path"]).read())
        assert result["findings_exported"] == len(stored_scan["findings"])
        assert any(entry["false_p"] for entry in document["findings"])

    def test_the_shape_matches_generic_findings_import(self, stored_scan):
        document = defectdojo.to_defectdojo(stored_scan)
        for entry in document["findings"]:
            for field in ("title", "description", "severity", "date", "file_path", "line"):
                assert field in entry
            assert entry["severity"] in ("Critical", "High", "Medium", "Low", "Info")
            assert isinstance(entry["cwe"], int)

    def test_the_description_carries_the_taint_path_and_the_verdict(self, stored_scan):
        document = defectdojo.to_defectdojo(stored_scan)
        first = document["findings"][0]
        assert "Taint path:" in first["description"]
        assert "Validated by" in first["description"]
        assert first["steps_to_reproduce"], "a ticket without a repro is not actionable"


# ==========================================================================
# Regression: re-scanning the same repository must not inflate the dashboard
# ==========================================================================

class TestRescanDoesNotDuplicate:
    def test_scanning_the_same_repo_twice_shows_each_finding_once(
            self, isolated_data, flask_scan):
        """QA-013.

        Finding ids are stable across re-scans by design, so the same finding
        appearing in two scan files is one finding, not two. Before this was
        fixed, five scans of one repo showed 55 findings in the dashboard and
        an 84% "dedupe reduction" that was really the same finding counted
        five times.
        """
        for index in (1, 2, 3):
            store.save_scan({
                "id": f"rescan-{index}",
                "repo": "vuln-flask",
                "started_at": f"2026-08-13T0{index}:00:00",
                "summary": {},
                "findings": [dict(finding) for finding in flask_scan["findings"]],
            })

        confirmed = store.all_findings(status="confirmed")
        assert len(confirmed) == 11, "each finding must appear once, not three times"

        # And the newest scan wins, so an approval recorded today is not
        # hidden behind a stale copy from an older scan file.
        assert all(f["scan_id"] == "rescan-3" for f in confirmed)

        assert len(store.all_findings(status="confirmed", latest_only=False)) == 33

    def test_the_approval_queue_is_not_inflated_either(self, isolated_data, flask_scan):
        for index in (1, 2):
            store.save_scan({
                "id": f"queue-{index}", "repo": "vuln-flask",
                "started_at": f"2026-08-13T0{index}:00:00", "summary": {},
                "findings": [dict(finding) for finding in flask_scan["findings"]],
            })
        assert approvals.queue()["counts"]["pending_approval"] == 11
