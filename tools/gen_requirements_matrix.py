#!/usr/bin/env python3
"""Generate docs/requirements-matrix.md from a real test run.

Owner: Member 7 (QA).

Runs tests/test_requirements.py, captures the evidence each test printed, and
writes the traceability document. Generating it means the document cannot
claim something the tests did not actually prove.

    JAVA_HOME=~/.local/opt/jdk21 .venv/bin/python tools/gen_requirements_matrix.py
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine import config  # noqa: E402

# Before importing `defectdojo`, which reads its URL from the environment at
# import time. Without this the matrix reports "not connected" while the
# tests it is summarising were talking to a live instance.
config.load_dotenv()

from engine import baseline, defectdojo, joern_engine  # noqa: E402
from tests.test_requirements import REQUIREMENTS  # noqa: E402

PANELS = {
    "Approach": "01 · Solution Approach",
    "Criteria": "02 · Key Criteria",
    "Tech": "03 · Technology Stacks",
    "Outcome": "04 · Outcomes",
}


def run_tests() -> tuple[str, dict[str, list[str]], dict[str, str]]:
    """Run the requirement tests and pull out each one's evidence."""
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_requirements.py", "-v", "-s",
         "--no-header", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True, timeout=3600)
    output = completed.stdout + completed.stderr

    evidence: dict[str, list[str]] = {}
    outcome: dict[str, str] = {}
    current: str | None = None

    for line in output.splitlines():
        started = re.search(r"test_req_(\d+)_\w+", line)
        if started:
            current = str(int(started.group(1)))
            evidence.setdefault(current, [])
        if current and line.strip().startswith("|"):
            evidence[current].append(line.strip().lstrip("| ").rstrip())
        for status in ("PASSED", "FAILED", "ERROR"):
            if current and status in line:
                outcome[current] = status
                current = None
                break
    return output, evidence, outcome


def status_for(number: str, outcome: dict[str, str], lines: list[str]) -> str:
    if outcome.get(number) != "PASSED":
        return "❌ FAILED"
    # A test can pass and still report that a live system was unavailable.
    if any("STATUS: PARTIAL" in line for line in lines):
        return "⚠️ PARTIAL"
    return "✅ MET"


def probe_llm(provider: str) -> tuple[str, str]:
    """Actually call the configured provider once and report what came back.

    "A key is set" and "the LLM works" are different claims, and a matrix that
    reports the first while implying the second is the exact dishonesty this
    document exists to prevent. So spend one real request on a throwaway
    finding and record the answer -- including the failure, which is the
    interesting case here.
    """
    if provider == "offline":
        return "offline", "no provider configured"

    from engine import llm, store

    # Probe with a REAL finding out of the last scan, never a hand-built stub.
    # A stub that is missing a field fails inside the offline fallback and
    # gets reported as a provider failure, which would make this row lie in
    # the one direction it must never lie in.
    findings = store.all_findings(latest_only=True)
    if not findings:
        return "unknown", "no stored finding to probe with — run a scan first"

    verdict = llm.judge(dict(findings[0]))
    if verdict.get("fallback_reason"):
        reason = " ".join(verdict["fallback_reason"].split())
        if len(reason) > 150:
            reason = reason[:147] + "..."
        return "offline", f"fell back — {reason}"
    return verdict.get("provider", provider), "responded"


def main() -> int:
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    output, evidence, outcome = run_tests()

    passed = sum(1 for v in outcome.values() if v == "PASSED")
    partial = sum(1 for n, v in outcome.items()
                  if v == "PASSED" and any("STATUS: PARTIAL" in l
                                           for l in evidence.get(n, [])))
    met = passed - partial

    provider = config.detect_provider()
    dojo = defectdojo.health()
    live_provider, live_detail = probe_llm(provider)

    out = [
        "# Requirements Traceability Matrix",
        "",
        "Every box on the hackathon slide, mapped to the test that proves it and",
        "the evidence that test printed. **This file is generated from a real run** —",
        "it cannot claim something the tests did not actually check.",
        "",
        "```bash",
        "JAVA_HOME=~/.local/opt/jdk21 .venv/bin/python tools/gen_requirements_matrix.py",
        "```",
        "",
        f"Generated: **{started}**",
        "",
        "## Summary",
        "",
        f"| | |",
        f"|---|---|",
        f"| Requirements on the slide | **16** |",
        f"| Fully met | **{met}** |",
        f"| Partially met | **{partial}** |",
        f"| Failing | **{16 - passed}** |",
        "",
        "### Environment at generation time",
        "",
        "| Component | State |",
        "|---|---|",
        f"| LLM provider configured | `{provider}` |",
        f"| LLM model | `{config.llm_model_for(provider)}` |",
        f"| **LLM that actually answered** | `{live_provider}` — {live_detail} |",
        f"| Joern | {'available — ' + joern_engine.joern_version() if joern_engine.joern_available() else 'not installed'} |",
        f"| Semgrep | {'available' if baseline.semgrep_available() else 'not installed'} |",
        f"| DefectDojo | {'connected at ' + defectdojo.DEFAULT_URL if dojo.get('authenticated') else 'not connected'} |",
        "",
    ]

    if partial:
        out += [
            "> ⚠️ **Partially met** means the capability is implemented and exercised,",
            "> but an external system it depends on was unavailable during this run.",
            "> Each one says below exactly what would close it.",
            "",
        ]

    out.append("---")
    out.append("")

    for panel, heading in PANELS.items():
        rows = [(n, t) for n, t in sorted(REQUIREMENTS.items(), key=lambda kv: int(kv[0]))
                if t.startswith(f"[{panel}]")]
        if not rows:
            continue
        out += [f"## {heading}", ""]
        for number, text in rows:
            lines = evidence.get(number, [])
            requirement_text = text.split("] ", 1)[1]
            out += [
                f"### REQ-{number} — {requirement_text}",
                "",
                f"**Status:** {status_for(number, outcome, lines)}  ",
                f"**Proven by:** `tests/test_requirements.py::test_req_{int(number):02d}_*`",
                "",
            ]
            if lines:
                out += ["```", *lines, "```", ""]
            else:
                out += ["_(no evidence captured)_", ""]
        out.append("---")
        out.append("")

    out += [
        "## How to re-verify",
        "",
        "```bash",
        "# Every requirement, one by one, with its evidence",
        "JAVA_HOME=~/.local/opt/jdk21 .venv/bin/python -m pytest tests/test_requirements.py -v -s",
        "",
        "# Regenerate this document from that run",
        "JAVA_HOME=~/.local/opt/jdk21 .venv/bin/python tools/gen_requirements_matrix.py",
        "```",
        "",
        "`test_matrix_and_tests_agree` fails the build if a requirement here has no",
        "test, or a test has no row here.",
        "",
        "## Seeing it rather than reading it",
        "",
        "[demo-video.md](demo-video.md) documents a recorded 4:36 walkthrough",
        "(`demo/output/sast-engine-demo.mp4`) that demonstrates 14 of these 16",
        "requirements on screen against the live application. The two it cannot",
        "show live are the same two marked partial here, for the same reason.",
        "",
    ]

    target = ROOT / "docs" / "requirements-matrix.md"
    target.write_text("\n".join(out))
    print(f"wrote {target}")
    print(f"  {met} met, {partial} partial, {16 - passed} failing")
    return 0 if passed == 16 else 1


if __name__ == "__main__":
    sys.exit(main())
