"""Compare our results against a baseline SAST tool, and grade both.

Owner: Member 4 (Dedupe + Baseline).

The baseline is **Joern**. That is a deliberate choice and a harder test than
the alternative: Joern is a mature CPG-based analyser with its own
inter-procedural data-flow engine, so beating it means beating real data-flow
analysis rather than beating regular expressions.

Semgrep is still supported and still measured, but it is now opt-in
(`--with-semgrep`). Keeping it costs nothing and it answers the "how do you
compare to what teams actually run in CI" question; it is simply no longer
the headline comparison.

The table has three rows plus an optional fourth:

    Joern (baseline, no validation)  what a real SAST tool reports on its own
    Ours - Stage 2                   our pattern matching, deliberately noisy
    Ours - Stage 3                   after LLM validation
    Semgrep (optional)               the CI-grade regex baseline

If Stage 3 does not beat Stage 2 on precision without losing recall, the
approach did not work and this module will say so.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from . import config, joern_engine

# --------------------------------------------------------------------------
# Semgrep -- optional secondary baseline
# --------------------------------------------------------------------------

SEMGREP_CONFIG = "p/security-audit"
SEMGREP_TIMEOUT_SECONDS = 300

# ORDER MATTERS: the first row whose hint appears in the rule id wins, so the
# most specific patterns come first. An earlier version listed path_traversal
# above open_redirect with "open-" as a hint, which scored Semgrep's
# `flask.security.open-redirect` rule as a path traversal.
SEMGREP_CATEGORY_HINTS = [
    ("open_redirect", ("open-redirect", "redirect")),
    ("ssti", ("render-template-str", "ssti", "jinja", "template-injection")),
    ("deserialization", ("pickle", "deserializ", "marshal", "yaml.load", "unsafe-yaml")),
    ("sql_injection", ("sql", "sqli", "tainted-sql")),
    ("ssrf", ("ssrf", "request-forgery", "server-side-request")),
    ("command_injection", ("command-injection", "shell-injection", "os-system",
                           "subprocess", "dangerous-subprocess", "child-process",
                           "exec-detected")),
    ("code_injection", ("eval", "code-injection", "user-eval")),
    ("path_traversal", ("path-traversal", "traversal", "readfile", "tainted-path",
                        "insecure-file")),
    ("xss", ("xss", "autoescape", "mark-safe", "cross-site-scripting")),
]


def semgrep_available() -> bool:
    return _semgrep_binary() is not None


def _semgrep_binary() -> str | None:
    local = config.ROOT / ".venv" / "bin" / "semgrep"
    if local.exists():
        return str(local)
    return shutil.which("semgrep")


def run_semgrep(repo_path: str | Path, rules_config: str = SEMGREP_CONFIG) -> dict[str, Any]:
    """Run Semgrep and normalise its findings into our shape."""
    binary = _semgrep_binary()
    if binary is None:
        return {"available": False, "findings": [],
                "error": "semgrep is not installed (pip install semgrep)"}

    command = [binary, "--config", rules_config, "--json", "--quiet",
               "--no-git-ignore", "--metrics", "off", str(repo_path)]
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=SEMGREP_TIMEOUT_SECONDS, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"available": False, "findings": [], "error": f"{type(exc).__name__}: {exc}"}

    if not completed.stdout.strip():
        return {"available": False, "findings": [],
                "error": completed.stderr.strip()[:400] or "semgrep produced no output"}

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"available": False, "findings": [],
                "error": "could not parse semgrep JSON output"}

    root = Path(repo_path).resolve()
    findings = []
    for result in payload.get("results", []):
        try:
            relative = str(Path(result["path"]).resolve().relative_to(root))
        except (ValueError, OSError):
            relative = result.get("path", "")
        extra = result.get("extra", {})
        rule_id = result.get("check_id", "")
        findings.append({
            "tool": "semgrep",
            "rule": rule_id,
            "file": relative,
            "line": result.get("start", {}).get("line", 0),
            "category": _map_category(rule_id, extra.get("message", "")),
            "severity": str(extra.get("severity", "warning")).lower(),
            "message": extra.get("message", "").strip(),
        })

    return {"available": True, "findings": findings, "rules_config": rules_config}


def _map_category(rule_id: str, message: str) -> str:
    haystack = f"{rule_id} {message}".lower()
    for category, hints in SEMGREP_CATEGORY_HINTS:
        if any(hint in haystack for hint in hints):
            return category
    return "other"


# --------------------------------------------------------------------------
# Joern -- the primary baseline
# --------------------------------------------------------------------------


def run_joern_baseline(repo_path: str | Path, repo_name: str) -> dict[str, Any]:
    """Joern's own findings, with no validation applied.

    This is the fair baseline: what a real CPG-based SAST tool reports before
    anybody reasons about the results.
    """
    if not joern_engine.joern_available():
        return {"available": False, "findings": [],
                "error": joern_engine.unavailable_reason()}

    result = joern_engine.prepare_and_scan(repo_path, repo_name)
    if not result.get("available"):
        return {"available": False, "findings": [], "error": result.get("error", "")}

    return {
        "available": True,
        "findings": result["findings"],
        "version": result.get("version", ""),
        "duration_ms": result.get("duration_ms", 0),
        "raw": result.get("raw", {}),
    }


# --------------------------------------------------------------------------
# The oracle
# --------------------------------------------------------------------------


def load_ground_truth(path: str | Path | None = None) -> dict[str, Any]:
    location = Path(path) if path else config.ROOT / "testdata" / "ground_truth.json"
    return json.loads(location.read_text())


def grade(findings: list[dict[str, Any]], repo_name: str,
          ground_truth: dict[str, Any] | None = None,
          line_tolerance: int = 2) -> dict[str, Any]:
    """Score findings against the hand-labelled oracle."""
    truth = ground_truth or load_ground_truth()
    repo_truth = truth["repos"].get(repo_name)
    if repo_truth is None:
        return {"error": f"no ground truth for repository '{repo_name}'"}

    expected = repo_truth["expected"]
    exploitable = [e for e in expected if e["exploitable"]]

    matched_markers: set[str] = set()
    true_positives, false_positives = [], []

    for finding in findings:
        entry = _match(finding, expected, line_tolerance)
        if entry is None:
            false_positives.append({**_brief(finding), "reason": "not in ground truth"})
            continue
        matched_markers.add(entry["marker"])
        if entry["exploitable"]:
            true_positives.append({**_brief(finding), "marker": entry["marker"]})
        else:
            false_positives.append({
                **_brief(finding), "marker": entry["marker"],
                "reason": entry.get("reason", "labelled not exploitable")})

    false_negatives = [
        {"marker": e["marker"], "file": e["file"], "line": e["line"],
         "category": e["category"], "note": e.get("note", "")}
        for e in exploitable if e["marker"] not in matched_markers
    ]

    tp, fp, fn = len(true_positives), len(false_positives), len(false_negatives)
    return {
        "repo": repo_name,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
        "recall": round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
        "f1": round(2 * tp / (2 * tp + fp + fn), 4) if (2 * tp + fp + fn) else 0.0,
        "detail": {"true_positives": true_positives,
                   "false_positives": false_positives,
                   "false_negatives": false_negatives},
    }


def _match(finding: dict[str, Any], expected: list[dict[str, Any]],
           tolerance: int) -> dict[str, Any] | None:
    file = finding.get("file", "")
    line = finding.get("line", 0)
    category = finding.get("category", "")
    for entry in expected:
        if entry["file"] != file:
            continue
        if abs(entry["line"] - line) > tolerance:
            continue
        if category != "other" and entry["category"] != category:
            continue
        return entry
    return None


def _brief(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "file": finding.get("file", ""),
        "line": finding.get("line", 0),
        "category": finding.get("category", ""),
        "rule": finding.get("rule") or finding.get("sink", ""),
    }


# --------------------------------------------------------------------------
# The comparison table
# --------------------------------------------------------------------------


def compare(repo_name: str, repo_path: str | Path,
            raw_findings: list[dict[str, Any]],
            validated_findings: list[dict[str, Any]],
            ground_truth: dict[str, Any] | None = None,
            with_semgrep: bool = False,
            joern_findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Joern vs our Stage 2 vs our Stage 3, all graded identically.

    `joern_findings` can be passed in when the pipeline already ran Joern, so
    a 15-second CPG build is not paid twice.
    """
    truth = ground_truth or load_ground_truth()

    if joern_findings is not None:
        joern = {"available": True, "findings": joern_findings}
    else:
        joern = run_joern_baseline(repo_path, repo_name)

    joern_score = (grade(joern["findings"], repo_name, truth)
                   if joern["available"] else {"error": joern.get("error", "unavailable")})

    stage2_score = grade(raw_findings, repo_name, truth)
    stage3_score = grade(validated_findings, repo_name, truth)

    raw_count = len(raw_findings)
    validated_count = len(validated_findings)

    stage2_fp = stage2_score.get("false_positives", 0)
    stage3_fp = stage3_score.get("false_positives", 0)
    fp_removed = stage2_fp - stage3_fp

    comparison: dict[str, Any] = {
        "repo": repo_name,
        "joern": {
            "available": joern["available"],
            "error": joern.get("error"),
            "version": joern.get("version", ""),
            "total_findings": len(joern["findings"]),
            "score": joern_score,
        },
        "stage2_pattern_matching": {"total_findings": raw_count, "score": stage2_score},
        "stage3_after_validation": {"total_findings": validated_count, "score": stage3_score},
        "suppression": {
            "raw_findings": raw_count,
            "confirmed_findings": validated_count,
            "suppressed": raw_count - validated_count,
            "suppression_rate": round((raw_count - validated_count) / raw_count, 4)
                                if raw_count else 0.0,
            "false_positives_before": stage2_fp,
            "false_positives_after": stage3_fp,
            "false_positives_removed": fp_removed,
            "fp_suppression_rate": round(fp_removed / stage2_fp, 4) if stage2_fp else 0.0,
            "precision_gain": round(
                stage3_score.get("precision", 0) - stage2_score.get("precision", 0), 4),
            "recall_change": round(
                stage3_score.get("recall", 0) - stage2_score.get("recall", 0), 4),
        },
    }

    # How much of Joern's noise did reasoning remove? This is the headline
    # against the primary baseline.
    if joern["available"] and "error" not in joern_score:
        joern_fp = joern_score.get("false_positives", 0)
        comparison["vs_joern"] = {
            "joern_false_positives": joern_fp,
            "our_false_positives": stage3_fp,
            "false_positives_removed": joern_fp - stage3_fp,
            "precision_gain": round(
                stage3_score.get("precision", 0) - joern_score.get("precision", 0), 4),
            "recall_gain": round(
                stage3_score.get("recall", 0) - joern_score.get("recall", 0), 4),
        }

    ours = {(f.get("file"), f.get("category")) for f in validated_findings}
    theirs = {(f.get("file"), f.get("category")) for f in joern["findings"]}
    comparison["overlap"] = {
        "both_tools": len(ours & theirs),
        "only_ours": len(ours - theirs),
        "only_baseline": len(theirs - ours),
    }

    if with_semgrep:
        semgrep = run_semgrep(repo_path)
        comparison["semgrep"] = {
            "available": semgrep["available"],
            "error": semgrep.get("error"),
            "rules_config": semgrep.get("rules_config"),
            "total_findings": len(semgrep["findings"]),
            "score": (grade(semgrep["findings"], repo_name, truth)
                      if semgrep["available"]
                      else {"error": semgrep.get("error", "unavailable")}),
        }

    return comparison


def format_table(comparison: dict[str, Any]) -> str:
    """A plain-text comparison table for the CLI and the deck."""
    rows = []
    header = (f"{'':34} {'findings':>9} {'TP':>4} {'FP':>4} {'FN':>4} "
              f"{'precision':>10} {'recall':>8}")
    rows.append(header)
    rows.append("-" * len(header))

    def add(label: str, block: dict[str, Any] | None) -> None:
        if block is None:
            return
        score = block.get("score", {})
        if "error" in score:
            rows.append(f"{label:34} {'unavailable':>9}   ({str(score['error'])[:38]})")
            return
        rows.append(
            f"{label:34} {block.get('total_findings', 0):>9} "
            f"{score.get('true_positives', 0):>4} {score.get('false_positives', 0):>4} "
            f"{score.get('false_negatives', 0):>4} "
            f"{score.get('precision', 0):>10.2%} {score.get('recall', 0):>8.2%}")

    add("Joern (baseline SAST)", comparison.get("joern"))
    if "semgrep" in comparison:
        add("Semgrep (secondary baseline)", comparison["semgrep"])
    add("Ours: Stage 2 pattern matching", comparison["stage2_pattern_matching"])
    add("Ours: Stage 3 after validation", comparison["stage3_after_validation"])

    suppression = comparison["suppression"]
    rows.append("")
    rows.append(f"False positives removed by LLM validation : "
                f"{suppression['false_positives_removed']} of "
                f"{suppression['false_positives_before']} "
                f"({suppression['fp_suppression_rate']:.1%})")
    rows.append(f"Precision gain from Stage 3               : "
                f"{suppression['precision_gain']:+.1%}")
    rows.append(f"Recall change from Stage 3                : "
                f"{suppression['recall_change']:+.1%}")

    if "vs_joern" in comparison:
        vs = comparison["vs_joern"]
        rows.append("")
        rows.append(f"vs Joern -- precision {vs['precision_gain']:+.1%}, "
                    f"recall {vs['recall_gain']:+.1%}, "
                    f"{vs['false_positives_removed']} fewer false positives")
    return "\n".join(rows)
