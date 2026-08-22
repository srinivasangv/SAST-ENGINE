"""Joern and DefectDojo.

Owner: Member 1 (Joern) and Member 5 (DefectDojo), tests by Member 7.

Both integrations talk to heavyweight external systems -- a JVM toolchain and
a Docker stack -- so every test here **skips itself** when the system is not
available rather than failing the build. The engine is designed to degrade to
the builtin engine and the file export, and the tests reflect that.

Run them with the real systems up:

    JAVA_HOME=~/.local/opt/jdk21 .venv/bin/pytest tests/test_integrations.py -v
"""

from __future__ import annotations

import json
import os

import pytest

from engine import baseline, defectdojo, joern_engine, pipeline, rules

joern_installed = pytest.mark.skipif(
    not joern_engine.joern_available(),
    reason=f"joern unavailable: {joern_engine.unavailable_reason()}")

dojo_up = pytest.mark.skipif(
    not defectdojo.health().get("authenticated"),
    reason="DefectDojo is not running or no API token is configured")


# ==========================================================================
# Joern -- things that need no JVM
# ==========================================================================

class TestJoernOffline:
    def test_language_detection(self, repos):
        assert joern_engine.detect_language(repos["vuln-flask"]) == "python"
        assert joern_engine.detect_language(repos["vuln-express"]) == "javascript"

    def test_the_script_uses_def_not_val_for_traversals(self):
        """Regression guard for the bug that cost us an afternoon.

        A Joern traversal is a single-use iterator. `val src = cpg.call...`
        followed by reading `src.size` consumes it, and the reachableByFlows
        that follows silently finds nothing. Every traversal must be a `def`.
        """
        script = joern_engine.build_script("/tmp/x", "/tmp/out.json", "proj")
        for name in ("srcT", "snkT", "ssrfT", "subT"):
            assert f"def {name}" in script, f"{name} must be a def, not a val"
            assert f"val {name}" not in script

    def test_get_is_not_a_sink_name(self):
        """`get` in the sink list poisons the whole query.

        `requests.get` is an SSRF sink but `request.args.get` is a source.
        Listing `get` in both sets makes Joern return zero flows, so SSRF is
        matched by methodFullName in a separate query instead.
        """
        names = joern_engine.SINK_NAMES.split("|")
        assert "get" not in names
        assert "post" not in names
        assert "requests" in joern_engine.SSRF_FULLNAME

    def test_unavailable_reason_is_actionable(self, monkeypatch):
        monkeypatch.setattr(joern_engine, "joern_binary", lambda: None)
        reason = joern_engine.unavailable_reason()
        assert "joern-cli" in reason and "JOERN_HOME" in reason

    def test_a_missing_joern_degrades_instead_of_raising(self, monkeypatch, repos):
        monkeypatch.setattr(joern_engine, "joern_binary", lambda: None)
        result = joern_engine.prepare_and_scan(repos["vuln-flask"], "vuln-flask")
        assert result["available"] is False
        assert result["error"]

    def test_classify_disambiguates_exec_by_language(self):
        """`exec` is Python code injection and JS command injection.

        Getting this wrong labels a shell injection as CWE-94 instead of
        CWE-78, which is the difference between two different fixes.
        """
        js_call = {"name": "exec", "methodFullName": "child_process.exec"}
        name, category = joern_engine._classify(
            js_call, "child_process.exec('ping ' + host)", "javascript")
        assert category == "command_injection"

        py_call = {"name": "eval", "methodFullName": "__builtin.eval"}
        name, category = joern_engine._classify(py_call, "eval(expression)", "python")
        assert category == "code_injection"


# ==========================================================================
# Joern -- the real thing
# ==========================================================================

@joern_installed
class TestJoernLive:
    @pytest.fixture(scope="class")
    @staticmethod
    def flask_joern(repos):
        # Class-scoped so one 15-second Joern run serves the whole class.
        return joern_engine.prepare_and_scan(repos["vuln-flask"], "vuln-flask")

    def test_it_builds_a_cpg(self, flask_joern):
        assert flask_joern["available"], flask_joern.get("error")
        assert flask_joern["raw"]["methods"] > 0
        assert flask_joern["raw"]["calls"] > 100

    def test_its_dataflow_engine_produces_flows(self, flask_joern):
        """The whole point of using Joern. Zero flows means the query broke."""
        assert flask_joern["raw"]["flows"] > 0, (
            "Joern found no data flows. Check that the traversals are `def` "
            "and that `get` is not in the sink name list.")

    def test_it_finds_every_planted_vulnerability(self, flask_joern, ground_truth):
        score = baseline.grade(flask_joern["findings"], "vuln-flask", ground_truth)
        assert score["false_negatives"] == 0, (
            f"Joern missed: {score['detail']['false_negatives']}")
        assert score["recall"] == 1.0

    def test_it_traces_across_functions(self, flask_joern):
        """VULN-11 is reached only through build_report()."""
        lines = {f["line"] for f in flask_joern["findings"]}
        assert 128 in lines, "the inter-procedural flow into build_report() was lost"

    def test_it_is_noisier_than_our_validated_output(self, flask_joern, ground_truth):
        """Joern has excellent recall and reports decoys too -- that is the gap."""
        score = baseline.grade(flask_joern["findings"], "vuln-flask", ground_truth)
        assert score["false_positives"] > 0, (
            "if Joern had no false positives there would be nothing to demonstrate")

    def test_findings_carry_every_key_stage_3_needs(self, flask_joern):
        required = {
            "id", "category", "title", "cwe", "severity", "file", "line",
            "function", "sink", "sink_code", "language", "entry",
            "http_reachable", "sanitizers", "guarded", "unreachable",
            "taint_path", "snippet", "status", "engine",
        }
        for finding in flask_joern["findings"]:
            assert not (required - set(finding))
            assert finding["engine"] == "joern"

    def test_it_detects_sanitizers_on_the_path(self, flask_joern):
        decoy = [f for f in flask_joern["findings"] if f["line"] == 141]
        assert decoy, "DECOY-1 was not reported"
        assert "shlex.quote" in decoy[0]["sanitizers"]

    def test_structural_flags_recover_what_joern_does_not_report(self, flask_joern):
        """Joern's flow output carries no guard or dead-code information.

        Without the AST pass in structural_flags(), DECOY-3 (allowlist) and
        DECOY-4 (`if False:`) survive validation on the Joern path, because
        the deterministic validator cannot suppress what it was never told.
        """
        by_line = {f["line"]: f for f in flask_joern["findings"]}
        assert by_line[169]["unreachable"] is True, "DECOY-4 dead code not detected"
        assert by_line[160]["guarded"] is True, "DECOY-3 allowlist guard not detected"

    def test_javascript_is_classified_correctly(self, repos):
        result = joern_engine.prepare_and_scan(repos["vuln-express"], "vuln-express")
        assert result["available"], result.get("error")
        assert result["language"] == "javascript"
        exec_findings = [f for f in result["findings"] if "exec" in f["sink"]]
        assert exec_findings, "child_process.exec was not found"
        assert all(f["category"] == "command_injection" for f in exec_findings), (
            "child_process.exec must be command injection, not Python's eval")

    def test_the_pipeline_can_run_on_joern(self, repos, ground_truth):
        scan = pipeline.run(repos["vuln-flask"], repo_name="vuln-flask",
                            engine="joern", use_llm=False,
                            with_baseline=False, save=False)
        assert scan["engine"] == "joern"
        assert all(f["engine"] == "joern" for f in scan["findings"])
        score = baseline.grade(
            [f for f in scan["findings"] if f["status"] == "confirmed"],
            "vuln-flask", ground_truth)
        assert score["false_negatives"] == 0
        assert score["false_positives"] == 0, (
            "validation should have removed every decoy Joern reported")


# ==========================================================================
# DefectDojo -- things that need no server
# ==========================================================================

class TestDefectDojoOffline:
    def test_the_import_document_omits_the_rejected_field(self, flask_scan):
        """DefectDojo rejects `duplicate` with 'Not allowed fields are present'."""
        scan = {"id": "t", "repo": "vuln-flask", "started_at": "2026-08-13T09:00:00",
                "findings": flask_scan["findings"]}
        document = defectdojo.to_defectdojo(scan)
        for entry in document["findings"]:
            assert "duplicate" not in entry

    def test_the_document_shape_is_generic_findings_import(self, flask_scan):
        scan = {"id": "t", "repo": "vuln-flask", "started_at": "2026-08-13T09:00:00",
                "findings": flask_scan["findings"]}
        document = defectdojo.to_defectdojo(scan)
        assert document["findings"]
        for entry in document["findings"]:
            for field in ("title", "description", "severity", "date", "file_path", "line"):
                assert field in entry
            assert entry["severity"] in ("Critical", "High", "Medium", "Low", "Info")
            assert isinstance(entry["cwe"], int)

    def test_the_engine_is_recorded_as_a_tag(self, flask_scan):
        scan = {"id": "t", "repo": "vuln-flask", "started_at": "2026-08-13T09:00:00",
                "findings": flask_scan["findings"]}
        document = defectdojo.to_defectdojo(scan)
        assert any(tag.startswith("engine:") for tag in document["findings"][0]["tags"])

    def test_push_without_a_token_fails_clearly(self, monkeypatch, flask_scan):
        monkeypatch.setattr(defectdojo, "api_token", lambda: "")
        result = defectdojo.push({"id": "t", "repo": "r", "findings": []})
        assert result["ok"] is False
        assert result["stage"] == "auth"
        assert "token" in result["error"]

    def test_an_unreachable_server_is_reported_not_raised(self, monkeypatch):
        monkeypatch.setattr(defectdojo, "api_token", lambda: "fake-token")
        status = defectdojo.health("http://127.0.0.1:9")
        assert status["reachable"] is False
        assert "cannot reach" in status["error"]


# ==========================================================================
# DefectDojo -- against the live instance
# ==========================================================================

@dojo_up
class TestDefectDojoLive:
    def test_health(self):
        status = defectdojo.health()
        assert status["reachable"] and status["authenticated"]

    def test_product_and_engagement_are_idempotent(self):
        url = defectdojo.DEFAULT_URL
        first = defectdojo.find_or_create_product(url, "SAST Engine Test Product")
        second = defectdojo.find_or_create_product(url, "SAST Engine Test Product")
        assert first["ok"] and second["ok"]
        assert first["id"] == second["id"]
        assert second["created"] is False

        engagement = defectdojo.find_or_create_engagement(url, first["id"], "pytest")
        again = defectdojo.find_or_create_engagement(url, first["id"], "pytest")
        assert engagement["id"] == again["id"]
        assert again["created"] is False

    def test_a_real_push_lands_and_can_be_read_back(self, flask_scan):
        scan = {
            "id": "pytest-scan",
            "repo": "vuln-flask-pytest",
            "started_at": "2026-08-13T09:00:00",
            "findings": [dict(f) for f in flask_scan["findings"]],
        }
        result = defectdojo.push(scan, engagement_name="pytest push")

        assert result["ok"], result.get("error")
        assert result["submitted"] == 11
        # Reading it back is the point: an import that reports success but
        # stored nothing is a failure we would otherwise never notice.
        assert result["stored"] == result["submitted"], (
            f"submitted {result['submitted']} but DefectDojo stored {result['stored']}")

        readback = defectdojo.findings_in_defectdojo(test_id=result["test_id"])
        assert readback["ok"]
        assert readback["count"] == 11
        assert all(f["severity"] in ("Critical", "High", "Medium", "Low", "Info")
                   for f in readback["findings"])
