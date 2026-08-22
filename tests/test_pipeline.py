"""Integration and end-to-end tests.

Owner: Member 7 (QA).

Integration: each stage's output is a valid input for the next one.
End-to-end:  running the whole pipeline on the corpus produces what we expect.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


# ==========================================================================
# Stage handover contracts
# ==========================================================================

class TestStageContracts:
    def test_prepare_gives_scan_what_it_needs(self, flask_scan):
        repo = flask_scan["repo"]
        assert repo.functions, "Stage 2 cannot work without functions"
        assert repo.file_lines, "snippets in the report need the source lines"
        for function in repo.functions:
            assert function.lang in ("python", "javascript")
            assert isinstance(function.body, list)

    def test_scan_gives_validate_a_complete_finding(self, flask_scan):
        required = {
            "id", "category", "title", "cwe", "severity", "file", "line",
            "function", "sink", "sink_code", "language", "entry",
            "http_reachable", "sanitizers", "guarded", "unreachable",
            "taint_path", "snippet", "status",
        }
        for finding in flask_scan["raw"]:
            missing = required - set(finding)
            assert not missing, f"finding is missing {missing}"

    def test_validate_stamps_every_finding(self, flask_scan):
        for finding in flask_scan["findings"]:
            assert finding["status"] in ("confirmed", "suppressed")
            assert "validation" in finding
            assert "reasoning" in finding["validation"]

    def test_prove_only_touches_confirmed_findings(self, flask_scan):
        for finding in flask_scan["findings"]:
            if finding["status"] == "confirmed":
                assert finding["poc"]["command"]
                assert finding["suggested_fix"]["file"] == finding["file"]
                assert finding["fix_status"] == "pending_approval"
            else:
                assert "poc" not in finding

    def test_finding_ids_are_unique_and_stable(self, flask_scan, repos):
        from engine import stage1_prepare, stage2_scan

        ids = [f["id"] for f in flask_scan["raw"]]
        assert len(ids) == len(set(ids)), "duplicate finding ids"

        # Re-scanning the same code must produce the same ids, or approvals
        # recorded against a finding would be lost on every scan.
        repo = stage1_prepare.prepare(repos["vuln-flask"], repo_name="vuln-flask")
        again = [f["id"] for f in stage2_scan.scan(repo)]
        assert ids == again

    def test_every_taint_path_starts_at_a_source_and_ends_at_a_sink(self, flask_scan):
        for finding in flask_scan["raw"]:
            path = finding["taint_path"]
            assert len(path) >= 2, f"path too short for {finding['id']}"
            assert ("enters via" in path[0]["description"]
                    or "parameter" in path[0]["description"])
            assert "reaches the dangerous call" in path[-1]["description"]


# ==========================================================================
# End to end on the corpus
# ==========================================================================

class TestEndToEnd:
    def test_flask_service_finds_every_planted_vulnerability(self, flask_scan):
        assert len(flask_scan["confirmed"]) == 11
        assert len(flask_scan["suppressed"]) == 6

    def test_express_service(self, express_scan):
        assert len(express_scan["confirmed"]) == 6
        assert len(express_scan["suppressed"]) == 4

    def test_the_safe_app_produces_no_confirmed_findings(self, safe_scan):
        assert safe_scan["confirmed"] == [], (
            "the safe app is the false-positive control: any confirmed finding "
            "here is a false positive")

    def test_all_eight_vulnerability_classes_are_covered(self, flask_scan, express_scan):
        categories = {f["category"] for f in flask_scan["confirmed"] + express_scan["confirmed"]}
        expected = {
            "command_injection", "code_injection", "sql_injection", "ssti",
            "deserialization", "ssrf", "path_traversal", "open_redirect", "xss",
        }
        assert expected <= categories, f"missing: {expected - categories}"

    def test_inter_procedural_taint_reaches_a_helper(self, flask_scan):
        helper = [f for f in flask_scan["confirmed"] if f["function"] == "build_report"]
        assert len(helper) == 1, "the taint through build_report() was not followed"
        finding = helper[0]
        # It must still know the URL an attacker would call.
        assert finding["route_path"] == "/report"
        assert "/report" in finding["poc"]["command"]

    def test_both_languages_are_scanned(self, flask_scan, express_scan):
        assert flask_scan["repo"].languages == {"python": 1}
        assert express_scan["repo"].languages == {"javascript": 1}


# ==========================================================================
# The CLI
# ==========================================================================

class TestCommandLine:
    def _run(self, *arguments) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "scan.py", *arguments],
            cwd=ROOT, capture_output=True, text=True, timeout=300)

    def test_scanning_a_vulnerable_repo_reports_findings_and_exits_nonzero(self):
        result = self._run("testdata/vuln-flask", "--no-llm", "--no-baseline")
        assert result.returncode == 1, "a scan that found bugs must fail a CI gate"
        assert "Stage 3 confirmed : 11" in result.stdout
        assert "OS Command Injection" in result.stdout

    def test_scanning_a_clean_repo_exits_zero(self):
        result = self._run("testdata/safe-app", "--no-llm", "--no-baseline")
        assert result.returncode == 0
        assert "Stage 3 confirmed : 0" in result.stdout

    def test_json_output_is_valid_json(self):
        import json
        result = self._run("testdata/safe-app", "--no-llm", "--no-baseline", "--json")
        payload = json.loads(result.stdout)
        assert payload["repo"] == "safe-app"

    def test_a_missing_path_fails_cleanly(self):
        result = self._run("/no/such/place", "--no-llm", "--no-baseline")
        assert result.returncode == 2
        assert "does not exist" in result.stderr

    def test_show_suppressed_prints_the_reasons(self):
        result = self._run("testdata/vuln-flask", "--no-llm", "--no-baseline",
                           "--show-suppressed")
        assert "SUPPRESSED" in result.stdout
        assert "shlex.quote" in result.stdout
