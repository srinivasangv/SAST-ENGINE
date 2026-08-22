"""The QA scenario matrix, executed.

Owner: Member 7 (QA).

Every test in this file is numbered to match the table in docs/qa.md. If a row
in that table has no test here, the row is a claim rather than a result -- so
`test_every_scenario_has_a_test` at the bottom checks the count.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from engine import (approvals, baseline, config, dedupe, llm, pipeline,
                    sla, stage1_prepare, stage2_scan, stage3_validate, store)

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = {}


def scenario(number: int, description: str):
    """Register a scenario so the matrix in the docs stays honest."""
    SCENARIOS[number] = description

    def decorate(function):
        function.__doc__ = f"Scenario {number}: {description}"
        return function

    return decorate


# ==========================================================================

@scenario(1, "Scan the vulnerable Flask service -> at least 10 true positives")
def test_scenario_01(flask_scan):
    assert len(flask_scan["confirmed"]) >= 10


@scenario(2, "Scan the safe app -> zero findings after validation")
def test_scenario_02(safe_scan):
    assert safe_scan["confirmed"] == []


@scenario(3, "Decoy: sanitised input -> found by Stage 2, suppressed by Stage 3")
def test_scenario_03(flask_scan):
    # DECOY-1: shlex.quote before os.system
    raw = [f for f in flask_scan["raw"] if f["line"] == 141]
    assert len(raw) == 1, "Stage 2 must still report a sanitised path"
    assert raw[0]["sanitizers"] == ["shlex.quote"]

    validated = [f for f in flask_scan["findings"] if f["line"] == 141][0]
    assert validated["status"] == "suppressed"
    assert "shlex.quote" in validated["suppression_reason"]


@scenario(4, "Decoy: value cast to int -> suppressed")
def test_scenario_04(flask_scan):
    finding = [f for f in flask_scan["findings"] if f["line"] == 150][0]
    assert finding["status"] == "suppressed"
    assert "int" in finding["suppression_reason"]


@scenario(5, "Cross-repo duplicate -> two findings collapse into one cluster")
def test_scenario_05(flask_scan, express_scan):
    confirmed = flask_scan["confirmed"] + express_scan["confirmed"]
    result = dedupe.cluster(confirmed)

    cross = [c for c in result["clusters"] if c["cross_repo"]]
    assert cross, "no pattern was found in more than one repository"

    command_injection = [c for c in cross if c["category"] == "command_injection"]
    assert command_injection, "VULN-1 (Python) and VULN-12 (JavaScript) should cluster"

    repos = command_injection[0]["repos"]
    assert "vuln-flask" in repos and "vuln-express" in repos

    languages = {location["language"] for location in command_injection[0]["locations"]}
    assert languages == {"python", "javascript"}, "the cluster must span both languages"


@scenario(6, "Baseline SAST comparison (Joern, plus Semgrep) -> table and FP-suppression rate")
def test_scenario_06(flask_scan, repos, ground_truth):
    comparison = baseline.compare(
        "vuln-flask", repos["vuln-flask"],
        flask_scan["raw"], flask_scan["confirmed"], ground_truth,
        with_semgrep=baseline.semgrep_available())

    assert comparison["suppression"]["fp_suppression_rate"] > 0

    table = baseline.format_table(comparison)
    assert "Joern (baseline SAST)" in table
    assert "Ours: Stage 3 after validation" in table
    if baseline.semgrep_available():
        assert "Semgrep (secondary baseline)" in table

    # Against the primary baseline: Joern has real data-flow analysis, so
    # beating it is the claim that actually matters.
    if comparison["joern"]["available"]:
        assert comparison["vs_joern"]["precision_gain"] > 0
        assert comparison["vs_joern"]["recall_gain"] >= 0


@scenario(7, "Every confirmed finding has a runnable proof of concept")
def test_scenario_07(flask_scan, express_scan):
    for finding in flask_scan["confirmed"] + express_scan["confirmed"]:
        poc = finding.get("poc", {})
        assert poc.get("command"), f"{finding['id']} has no PoC"
        assert poc.get("expected"), f"{finding['id']} does not say what should happen"
        if poc["reachable"]:
            assert poc["command"].startswith("curl")
            assert poc["url"].endswith(finding["route_path"])


@scenario(8, "Auto-fix approval gate: a fix cannot be applied before approval")
def test_scenario_08(stored_scan_fixture):
    finding_id = stored_scan_fixture
    refused = approvals.apply_fix(finding_id, actor="attacker")
    assert refused["ok"] is False
    assert "not been approved" in refused["error"]

    approvals.approve(finding_id, actor="security-lead", note="reviewed")
    allowed = approvals.apply_fix(finding_id, actor="security-lead")
    assert allowed["ok"] is True
    assert "patch" in allowed


@scenario(9, "Auto-fix rejection is recorded with a reason")
def test_scenario_09(stored_scan_fixture):
    finding_id = stored_scan_fixture
    assert approvals.reject(finding_id, actor="dev", reason="")["ok"] is False

    result = approvals.reject(finding_id, actor="dev", reason="endpoint is behind auth")
    assert result["ok"] is True
    assert result["finding"]["fix_status"] == "rejected"
    assert "behind auth" in result["finding"]["approval_note"]


@scenario(10, "SLA breach: an aged finding breaches and escalates")
def test_scenario_10(stored_scan_fixture):
    report = sla.report(age_override={stored_scan_fixture: 500.0})
    assert report["breached"] >= 1
    escalation = [e for e in report["escalations"] if e["finding_id"] == stored_scan_fixture]
    assert escalation, "the aged finding did not escalate"
    assert escalation[0]["escalate_to"]


@scenario(11, "Offline fallback: no API key -> the pipeline still completes")
def test_scenario_11(repos, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    assert config.llm_available() is False

    repo = stage1_prepare.prepare(repos["vuln-flask"], repo_name="vuln-flask")
    findings = stage2_scan.scan(repo)
    result = stage3_validate.validate(findings)

    assert result["summary"]["confirmed"] == 11
    assert result["summary"]["validators_used"] == {"offline": 17}
    for finding in findings:
        assert finding["validation"]["validator"] == "offline"
        assert finding["validation"]["fallback_reason"]


@scenario(12, "A file that will not parse is recorded and the scan continues")
def test_scenario_12(tmp_path):
    (tmp_path / "good.py").write_text(
        "from flask import request\n"
        "import os\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    os.system('ls ' + request.args.get('c'))\n")
    (tmp_path / "broken.py").write_text("def oops(:\n    this is not python\n")

    repo = stage1_prepare.prepare(tmp_path, repo_name="mixed")

    assert len(repo.parse_errors) == 1
    assert "broken.py" in repo.parse_errors[0]["file"]
    assert "good.py" in repo.files, "the scan must not stop at the broken file"
    assert len(stage2_scan.scan(repo)) == 1, "the good file still produced its finding"


@scenario(13, "An empty repository is handled gracefully, not as a crash")
def test_scenario_13(tmp_path):
    result = pipeline.run(tmp_path, repo_name="empty", with_baseline=False,
                          use_llm=False, save=False)
    assert result["summary"]["raw_findings"] == 0
    assert result["summary"]["confirmed"] == 0
    assert result["stages"]["prepare"]["files"] == 0


@scenario(14, "Two scans produce two independent, complete result files")
def test_scenario_14(tmp_path, monkeypatch, repos):
    scans = tmp_path / "scans"
    scans.mkdir()
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "SCANS_DIR", scans)

    results = {}
    errors = []

    def work(name: str, path) -> None:
        try:
            results[name] = pipeline.run(path, repo_name=name, use_llm=False,
                                         with_baseline=False)
        except Exception as exc:                   # noqa: BLE001
            errors.append(f"{name}: {exc}")

    threads = [
        threading.Thread(target=work, args=("vuln-flask", repos["vuln-flask"])),
        threading.Thread(target=work, args=("vuln-express", repos["vuln-express"])),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    assert not errors, errors
    assert len(results) == 2
    assert results["vuln-flask"]["id"] != results["vuln-express"]["id"]
    assert len(store.list_scans()) == 2
    assert results["vuln-flask"]["summary"]["confirmed"] == 11
    assert results["vuln-express"]["summary"]["confirmed"] == 6


# ==========================================================================
# Support
# ==========================================================================

@pytest.fixture
def stored_scan_fixture(tmp_path, monkeypatch, flask_scan):
    """A saved scan in a throwaway directory; yields a confirmed finding id."""
    scans = tmp_path / "scans"
    scans.mkdir()
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "SCANS_DIR", scans)
    monkeypatch.setattr(config, "EXPORTS_DIR", tmp_path / "exports")

    scan = {
        "id": "scenario-scan",
        "repo": "vuln-flask",
        "started_at": "2026-08-13T09:00:00",
        "summary": {},
        "findings": [dict(finding) for finding in flask_scan["findings"]],
    }
    store.save_scan(scan)
    return next(f["id"] for f in scan["findings"] if f["status"] == "confirmed")


def test_every_scenario_in_the_docs_has_a_test():
    """The matrix in docs/qa.md must match what actually runs."""
    assert sorted(SCENARIOS) == list(range(1, 15)), (
        f"scenarios registered: {sorted(SCENARIOS)}")
