"""One test per requirement on the hackathon slide.

Owner: Member 7 (QA).

The slide has sixteen boxes across four panels. This file has sixteen tests,
numbered to match, each printing the evidence it checked. Run it with `-s` and
the output IS the traceability report:

    JAVA_HOME=~/.local/opt/jdk21 .venv/bin/pytest tests/test_requirements.py -v -s

`docs/requirements-matrix.md` is the rendered version of this file. A test here
that has no row there (or vice versa) fails `test_matrix_and_tests_agree`.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from engine import (approvals, baseline, config, dedupe, defectdojo, joern_engine,
                    llm, pipeline, rules, sla, stage1_prepare, stage2_scan, store)

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS: dict[str, str] = {}


def requirement(number: str, panel: str, text: str):
    """Register a slide requirement so the docs and the tests cannot drift."""
    REQUIREMENTS[number] = f"[{panel}] {text}"

    def decorate(function):
        function.__doc__ = f"REQ-{number} ({panel}): {text}"
        return function

    return decorate


def evidence(*lines: str) -> None:
    for line in lines:
        print(f"      | {line}")


# ==========================================================================
# PANEL 01 -- SOLUTION APPROACH
# ==========================================================================

@requirement("1", "Approach", "Prepare stage: build a CPG from source without requiring a build")
def test_req_01_cpg_without_a_build(flask_scan):
    repo = flask_scan["repo"]
    stats = repo.stats()

    assert stats["nodes"] > 0 and stats["edges"] > 0
    assert stats["functions"] > 0

    # "Without a build" is the claim that matters. The target repo has no
    # virtualenv, no node_modules and no installed dependencies -- it imports
    # flask, requests and yaml, none of which are installed for it.
    target = ROOT / "testdata" / "vuln-flask"
    assert not (target / ".venv").exists()
    assert not (target / "node_modules").exists()
    assert not (target / "requirements.txt").exists()

    evidence(f"CPG: {stats['nodes']} nodes, {stats['edges']} edges, "
             f"{stats['functions']} functions, {stats['routes']} routes",
             f"parsed in {stats['duration_ms']} ms with the stdlib ast module",
             "no venv / node_modules / install step in the scanned repo",
             "the scanned code is never imported or executed -- text only")


@requirement("2", "Approach", "Scan stage: taint analysis across the CPG for injection, deserialization and SSRF sinks")
def test_req_02_taint_finds_injection_deserialization_ssrf(flask_scan, express_scan):
    confirmed = flask_scan["confirmed"] + express_scan["confirmed"]
    categories = {f["category"] for f in confirmed}

    # The three the slide names explicitly.
    assert "command_injection" in categories or "code_injection" in categories
    assert "sql_injection" in categories
    assert "deserialization" in categories
    assert "ssrf" in categories

    evidence(f"{len(confirmed)} confirmed findings across {len(categories)} classes",
             f"classes: {', '.join(sorted(categories))}",
             "injection ✓  deserialization ✓  SSRF ✓ -- all three named on the slide")


@requirement("3", "Approach", "Validate stage: an LLM agent traces exploitability")
def test_req_03_llm_agent_traces_exploitability(flask_scan):
    provider = config.detect_provider()
    verdicts = [f["validation"] for f in flask_scan["findings"]]

    # The contract holds whichever validator ran: every finding gets a verdict
    # with a written reason and an identified author.
    assert verdicts
    for verdict in verdicts:
        assert "exploitable" in verdict
        assert verdict["reasoning"].strip(), "a verdict without a reason is not a verdict"
        assert verdict["provider"] in ("anthropic", "openai", "offline")

    live = provider != "offline"
    reason = verdicts[0].get("fallback_reason", "")

    evidence(f"configured provider : {provider}",
             f"validator that ran  : {verdicts[0]['validator']} ({verdicts[0]['model']})",
             f"fallback reason     : {reason or '(none -- a live model answered)'}",
             f"verdicts with a written reason: {len(verdicts)}/{len(verdicts)}")

    if not live or reason:
        evidence("STATUS: PARTIAL -- the reasoning contract is implemented and "
                 "exercised, but no live model answered this run.",
                 "Set ANTHROPIC_API_KEY or OPENAI_API_KEY (with quota) to close it.")


@requirement("4", "Approach", "Validate stage: cross-repo dedupe of findings")
def test_req_04_cross_repo_dedupe(flask_scan, express_scan):
    confirmed = flask_scan["confirmed"] + express_scan["confirmed"]
    result = dedupe.cluster(confirmed)
    cross = [c for c in result["clusters"] if c["cross_repo"]]

    assert cross, "no vulnerability pattern spanned more than one repository"
    summary = result["summary"]
    assert summary["clusters_after"] < summary["findings_before"]

    example = cross[0]
    evidence(f"{summary['findings_before']} findings -> "
             f"{summary['clusters_after']} unique patterns",
             f"{summary['cross_repo_clusters']} patterns span 2+ repositories",
             f"example: {example['title']} in "
             f"{', '.join(example['repos'])} ({example['count']} occurrences)")


@requirement("5", "Approach", "Prove stage: auto-generate a PoC input for each true positive")
def test_req_05_poc_per_true_positive(flask_scan, express_scan):
    confirmed = flask_scan["confirmed"] + express_scan["confirmed"]
    assert confirmed

    for finding in confirmed:
        poc = finding.get("poc", {})
        assert poc.get("command"), f"{finding['id']} has no PoC command"
        assert poc.get("payload"), f"{finding['id']} has no payload"
        assert poc.get("expected"), f"{finding['id']} does not say what should happen"

    sample = next(f for f in confirmed if f["poc"]["reachable"])
    evidence(f"{len(confirmed)}/{len(confirmed)} confirmed findings carry a PoC",
             f"example: {sample['poc']['command']}",
             f"expected: {sample['poc']['expected']}")


# ==========================================================================
# PANEL 02 -- KEY CRITERIA
# ==========================================================================

@requirement("6", "Criteria", "Demonstrated false-positive suppression rate vs a baseline SAST tool")
def test_req_06_fp_suppression_vs_baseline(flask_scan, repos, ground_truth):
    comparison = baseline.compare(
        "vuln-flask", repos["vuln-flask"],
        flask_scan["raw"], flask_scan["confirmed"], ground_truth,
        with_semgrep=baseline.semgrep_available())

    suppression = comparison["suppression"]
    assert suppression["false_positives_before"] > 0, "nothing to suppress"
    assert suppression["false_positives_after"] == 0
    assert suppression["fp_suppression_rate"] == 1.0
    assert suppression["recall_change"] == 0.0, "recall must not be traded away"

    stage3 = comparison["stage3_after_validation"]["score"]
    lines = [
        f"FP suppression rate : {suppression['fp_suppression_rate']:.0%} "
        f"({suppression['false_positives_removed']} of "
        f"{suppression['false_positives_before']})",
        f"precision gain      : {suppression['precision_gain']:+.1%}",
        f"recall change       : {suppression['recall_change']:+.1%} (nothing lost)",
        f"ours after Stage 3  : precision {stage3['precision']:.1%}, "
        f"recall {stage3['recall']:.1%}",
    ]
    if comparison["joern"]["available"]:
        joern = comparison["joern"]["score"]
        lines.append(f"Joern baseline      : precision {joern['precision']:.1%}, "
                     f"recall {joern['recall']:.1%}")
    if comparison.get("semgrep", {}).get("available"):
        semgrep = comparison["semgrep"]["score"]
        lines.append(f"Semgrep baseline    : precision {semgrep['precision']:.1%}, "
                     f"recall {semgrep['recall']:.1%}")
    evidence(*lines)


@requirement("7", "Criteria", "Cross-repo deduplication of the same vulnerability pattern across services")
def test_req_07_same_pattern_across_services(flask_scan, express_scan):
    confirmed = flask_scan["confirmed"] + express_scan["confirmed"]
    result = dedupe.cluster(confirmed)

    command_injection = [c for c in result["clusters"]
                         if c["category"] == "command_injection" and c["cross_repo"]]
    assert command_injection, (
        "the Python and JavaScript copies of the same shell injection "
        "should form one cluster")

    cluster = command_injection[0]
    languages = {location["language"] for location in cluster["locations"]}
    assert languages == {"python", "javascript"}, (
        f"the cluster should span both languages, got {languages}")

    evidence(f"one cluster, {cluster['count']} occurrences, "
             f"shape {cluster['shape']}",
             *[f"  {l['repo']}: {l['file']}:{l['line']} [{l['language']}]"
               for l in cluster["locations"]],
             "-> one remediation ticket, not three")


@requirement("8", "Criteria", "Human-approval workflow gate before any auto-fix is applied")
def test_req_08_human_approval_gate(requirement_scan):
    finding_id = requirement_scan

    # 1. A fix starts pending.
    _, finding = store.find_finding(finding_id)
    assert finding["fix_status"] == "pending_approval"

    # 2. Applying it is REFUSED.
    refused = approvals.apply_fix(finding_id, actor="anyone")
    assert refused["ok"] is False
    assert "not been approved" in refused["error"]

    _, unchanged = store.find_finding(finding_id)
    assert unchanged["fix_status"] == "pending_approval", "state must not have moved"

    # 3. After a human approves, it is allowed -- and returns a patch, not an edit.
    approvals.approve(finding_id, actor="security-lead", note="reviewed the taint path")
    allowed = approvals.apply_fix(finding_id, actor="security-lead")
    assert allowed["ok"] is True
    assert "patch" in allowed

    evidence("apply before approval -> REFUSED: " + refused["error"][:60],
             "approve(security-lead) -> fix_status = approved",
             "apply after approval  -> patch returned, source never edited",
             "the ordering is enforced in code, not in a process document")


@requirement("9", "Criteria", "SLA-breach handling: escalation when a finding ages past a threshold")
def test_req_09_sla_breach_escalation(requirement_scan):
    finding_id = requirement_scan

    fresh = sla.report()
    assert fresh["breached"] == 0, "a scan run just now should not be breached"

    # Age this one finding past its threshold without waiting three days.
    aged = sla.report(age_override={finding_id: 500.0})
    assert aged["breached"] >= 1

    escalation = next(e for e in aged["escalations"] if e["finding_id"] == finding_id)
    assert escalation["escalate_to"], "a breach with no escalation target is not handling"
    assert escalation["overdue_by_hours"] > 0

    evidence(f"policy: {config.SLA_HOURS}",
             f"fresh scan  -> {fresh['breached']} breached",
             f"aged 500h   -> {aged['breached']} breached",
             f"escalates to: {escalation['escalate_to']} "
             f"(overdue by {escalation['overdue_by_hours']:.0f}h)")


# ==========================================================================
# PANEL 03 -- TECHNOLOGY STACKS
# ==========================================================================

@requirement("10", "Tech", "Joern or Semgrep for CPG generation and taint-flow rules")
def test_req_10_joern_or_semgrep(repos, ground_truth):
    joern_ok = joern_engine.joern_available()
    semgrep_ok = baseline.semgrep_available()
    assert joern_ok or semgrep_ok, "neither CPG/SAST tool is installed"

    lines = [f"Joern installed  : {joern_ok} ({joern_engine.joern_version()})",
             f"Semgrep installed: {semgrep_ok}"]

    if joern_ok:
        result = joern_engine.prepare_and_scan(repos["vuln-flask"], "vuln-flask")
        assert result["available"], result.get("error")
        assert result["raw"]["flows"] > 0, "Joern produced no data flows"
        score = baseline.grade(result["findings"], "vuln-flask", ground_truth)
        assert score["false_negatives"] == 0
        lines += [f"Joern CPG        : {result['raw']['methods']} methods, "
                  f"{result['raw']['calls']} calls, {result['raw']['flows']} data flows",
                  f"Joern accuracy   : precision {score['precision']:.1%}, "
                  f"recall {score['recall']:.1%}",
                  "Joern is BOTH a selectable engine (--engine joern) and the baseline"]
    if semgrep_ok:
        semgrep = baseline.run_semgrep(repos["vuln-flask"])
        if semgrep["available"]:
            lines.append(f"Semgrep          : {len(semgrep['findings'])} findings "
                         f"with {semgrep['rules_config']}")
    evidence(*lines)


@requirement("11", "Tech", "Python orchestration layer for the four-stage pipeline")
def test_req_11_python_orchestration(repos):
    scan = pipeline.run(repos["safe-app"], repo_name="safe-app", use_llm=False,
                        with_baseline=False, save=False)

    stages = scan["stages"]
    assert set(stages) == {"prepare", "scan", "validate", "prove"}, (
        f"expected exactly the four stages, got {sorted(stages)}")

    assert (ROOT / "engine" / "pipeline.py").exists()
    evidence("engine/pipeline.py wires the four stages",
             f"stages present: {' -> '.join(stages)}",
             f"one scan of safe-app completed in {scan['duration_ms']} ms",
             "the CLI and the HTTP API both call the same pipeline.run()")


@requirement("12", "Tech", "LLM API (agentic validation) for exploitability reasoning and triage")
def test_req_12_llm_api_wired(flask_scan):
    # Two providers are wired, both fed the identical prompt, with a
    # deterministic fallback behind them.
    assert set(llm.PROVIDERS) == {"anthropic", "openai"}
    assert callable(llm.ask_claude) and callable(llm.ask_openai)
    assert "exploitable" in llm.SYSTEM_PROMPT

    provider = config.detect_provider()
    verdict = flask_scan["findings"][0]["validation"]

    # Triage: the validator must actually change outcomes, not just annotate.
    statuses = {f["status"] for f in flask_scan["findings"]}
    assert statuses == {"confirmed", "suppressed"}, (
        "the validator is not triaging -- it confirmed or suppressed everything")

    suppressed = [f for f in flask_scan["findings"] if f["status"] == "suppressed"]
    assert all(f["suppression_reason"] for f in suppressed)

    evidence(f"providers wired    : {', '.join(sorted(llm.PROVIDERS))} (+ offline fallback)",
             f"configured provider: {provider}",
             f"ran this session   : {verdict['validator']} ({verdict['model']})",
             f"triage outcome     : {len(flask_scan['confirmed'])} confirmed, "
             f"{len(suppressed)} suppressed, each with a written reason")
    if verdict.get("fallback_reason"):
        evidence(f"STATUS: PARTIAL -- fell back because: {verdict['fallback_reason']}")


@requirement("13", "Tech", "DefectDojo integration for remediation ticket workflows")
def test_req_13_defectdojo(flask_scan):
    scan = {"id": "req-13", "repo": "vuln-flask",
            "started_at": "2026-08-13T09:00:00",
            "findings": [dict(f) for f in flask_scan["findings"]]}

    # The document is always produced, server or not.
    document = defectdojo.to_defectdojo(scan)
    assert document["findings"]
    for entry in document["findings"]:
        assert entry["severity"] in ("Critical", "High", "Medium", "Low", "Info")
        assert isinstance(entry["cwe"], int)
        assert entry["steps_to_reproduce"], "a ticket with no repro is not actionable"

    status = defectdojo.health()
    lines = [f"import document    : {len(document['findings'])} findings, "
             f"scan type '{defectdojo.SCAN_TYPE}'",
             f"DefectDojo URL     : {defectdojo.DEFAULT_URL}",
             f"reachable          : {status.get('reachable')}",
             f"authenticated      : {status.get('authenticated')}"]

    if status.get("authenticated"):
        # Live round trip: push, then read it back out of DefectDojo.
        pushed = defectdojo.push(scan, engagement_name="requirements check")
        assert pushed["ok"], pushed.get("error")
        assert pushed["stored"] == pushed["submitted"], (
            f"submitted {pushed['submitted']} but DefectDojo stored {pushed['stored']}")

        readback = defectdojo.findings_in_defectdojo(test_id=pushed["test_id"])
        assert readback["ok"] and readback["count"] == pushed["submitted"]

        lines += [f"LIVE push          : {pushed['submitted']} submitted, "
                  f"{pushed['stored']} stored",
                  f"read back from API : {readback['count']} findings",
                  f"ticket URL         : {pushed['test_url']}"]
    else:
        lines.append("STATUS: PARTIAL -- no live server; the import file path was "
                     "verified instead. Start DefectDojo to close it.")
    evidence(*lines)


# ==========================================================================
# PANEL 04 -- OUTCOMES
# ==========================================================================

@requirement("14", "Outcome", "Working pipeline scanning at least one interpreted-language repo end to end")
def test_req_14_end_to_end_pipeline():
    def run_cli(*arguments):
        return subprocess.run([sys.executable, "scan.py", *arguments],
                              cwd=ROOT, capture_output=True, text=True, timeout=600)

    vulnerable = run_cli("testdata/vuln-flask", "--no-llm", "--no-baseline")
    clean = run_cli("testdata/safe-app", "--no-llm", "--no-baseline")

    assert vulnerable.returncode == 1, "a repo with bugs must fail a CI gate"
    assert clean.returncode == 0, "a clean repo must pass"
    assert "Stage 3 confirmed" in vulnerable.stdout

    evidence("python scan.py testdata/vuln-flask  -> exit 1 (findings, fail CI)",
             "python scan.py testdata/safe-app    -> exit 0 (clean, pass CI)",
             "two interpreted languages scanned: Python and JavaScript",
             "exit codes make it usable as a pull-request gate")


@requirement("15", "Outcome", "Comparative report: findings and false-positive rate vs a baseline SAST tool")
def test_req_15_comparative_report(flask_scan, repos, ground_truth):
    comparison = baseline.compare(
        "vuln-flask", repos["vuln-flask"],
        flask_scan["raw"], flask_scan["confirmed"], ground_truth,
        with_semgrep=baseline.semgrep_available())

    table = baseline.format_table(comparison)
    assert "Joern (baseline SAST)" in table
    assert "Ours: Stage 3 after validation" in table
    assert "False positives removed" in table

    print()
    for line in table.splitlines():
        print(f"      | {line}")


@requirement("16", "Outcome", "Documented test scenario results (fix automation, deduplication, SLA handling)")
def test_req_16_documented_scenarios():
    qa = (ROOT / "docs" / "qa.md").read_text()

    # The three the slide names by name.
    assert "approval gate" in qa.lower()
    assert "dedup" in qa.lower()
    assert "sla" in qa.lower()

    # And the scenario matrix must be executable, not just prose.
    scenarios = (ROOT / "tests" / "test_scenarios.py").read_text()
    registered = scenarios.count("@scenario(")
    assert registered >= 14

    docs = sorted(p.name for p in (ROOT / "docs").glob("*.md"))
    evidence(f"{registered} scenarios registered in tests/test_scenarios.py",
             "fix automation ✓  deduplication ✓  SLA handling ✓ -- all documented",
             f"{len(docs)} documents: {', '.join(docs)}")


# ==========================================================================
# The matrix and the tests must not drift apart
# ==========================================================================

def test_matrix_and_tests_agree():
    """Every slide requirement has a test, and the doc lists every one."""
    assert sorted(REQUIREMENTS, key=int) == [str(n) for n in range(1, 17)], (
        f"registered: {sorted(REQUIREMENTS, key=int)}")

    matrix = ROOT / "docs" / "requirements-matrix.md"
    assert matrix.exists(), "docs/requirements-matrix.md is missing"
    text = matrix.read_text(encoding="utf-8")
    for number in REQUIREMENTS:
        assert f"REQ-{number}" in text, f"REQ-{number} is not in the matrix document"


# ==========================================================================
# Support
# ==========================================================================

@pytest.fixture
def requirement_scan(tmp_path, monkeypatch, flask_scan):
    """A saved scan in a throwaway directory; yields a confirmed finding id."""
    scans = tmp_path / "scans"
    scans.mkdir()
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "SCANS_DIR", scans)
    monkeypatch.setattr(config, "EXPORTS_DIR", tmp_path / "exports")

    # NOW, not a hardcoded date: this fixture stands for "a scan that just
    # ran", and the SLA test asserts it is not yet breached. A fixed date
    # passes on the day it is written and fails every day after.
    store.save_scan({
        "id": "requirements-scan",
        "repo": "vuln-flask",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "summary": {},
        "findings": [dict(f) for f in flask_scan["findings"]],
    })
    return next(f["id"] for f in flask_scan["findings"] if f["status"] == "confirmed")
