"""The four stages, wired together.

Owner: Member 6 (API + Workflow), with every other member owning one stage.

    prepare()  ->  scan()  ->  validate()  ->  prove()
       M1           M2            M3            M5

Stages 1 and 2 have two interchangeable implementations:

    engine="builtin"  our stdlib-ast parser and taint walk -- fast, readable
    engine="joern"    Joern's CPG and its own data-flow engine -- deep, slow
    engine="both"     run both; findings are merged and tagged with `engine`

Stages 3 and 4 do not care which produced a finding. That is the whole point
of freezing the finding dictionary on day one: one validator, one prover, two
front ends.

Then the cross-cutting steps: dedupe (M4), SLA (M6), the baseline comparison
(M4), and an optional push to DefectDojo (M5).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

from . import (baseline, dedupe, defectdojo, joern_engine, sla, stage1_prepare,
               stage2_scan, stage3_validate, stage4_prove, store)

ENGINES = ("builtin", "joern", "both")


def run(repo_path: str | Path,
        repo_name: str | None = None,
        use_llm: bool | None = None,
        engine: str = "builtin",
        with_baseline: bool = True,
        with_semgrep: bool = False,
        push_to_defectdojo: bool = False,
        save: bool = True,
        on_stage: Callable[[str, str], None] | None = None) -> dict[str, Any]:
    """Run all four stages over one repository and return the full result."""
    started = time.time()
    started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    path = Path(repo_path)
    name = repo_name or path.resolve().name

    if engine not in ENGINES:
        raise ValueError(f"engine must be one of {ENGINES}, got {engine!r}")

    def announce(stage: str, message: str) -> None:
        if on_stage is not None:
            on_stage(stage, message)

    # ---- Stages 1 and 2 --------------------------------------------------
    builtin_repo = None
    joern_result = None
    findings: list[dict[str, Any]] = []
    engine_stats: dict[str, Any] = {}

    if engine in ("builtin", "both"):
        announce("prepare", f"parsing {path} with the builtin engine")
        builtin_repo = stage1_prepare.prepare(path, repo_name=name)
        stats = builtin_repo.stats()
        announce("prepare", f"{stats['files']} files, {stats['nodes']} CPG nodes, "
                            f"{stats['functions']} functions")

        announce("scan", "tracing attacker input to dangerous calls")
        builtin_findings = stage2_scan.scan(builtin_repo)
        for finding in builtin_findings:
            finding.setdefault("engine", "builtin")
        findings.extend(builtin_findings)
        engine_stats["builtin"] = {**stats, "findings": len(builtin_findings)}
        announce("scan", f"{len(builtin_findings)} potential findings (builtin)")

    if engine in ("joern", "both"):
        announce("prepare", "building a Code Property Graph with Joern (this takes ~15s)")
        joern_result = joern_engine.prepare_and_scan(path, name)

        if joern_result.get("available"):
            joern_findings = joern_result["findings"]
            joern_stats = joern_result["repo"].stats()
            announce("prepare", f"Joern: {joern_result['raw']['methods']} methods, "
                                f"{joern_result['raw']['calls']} calls")
            announce("scan", f"{len(joern_findings)} data-flow findings (joern)")

            if engine == "both":
                # Same bug found by both engines is one finding. The builtin
                # one wins because it carries the route and the guard flags.
                existing = {(f["file"], f["line"], f["category"]) for f in findings}
                joern_findings = [
                    f for f in joern_findings
                    if (f["file"], f["line"], f["category"]) not in existing]
                announce("scan", f"{len(joern_findings)} of them are new")

            findings.extend(joern_findings)
            engine_stats["joern"] = {**joern_stats, "findings": len(joern_findings),
                                     "version": joern_result.get("version", ""),
                                     "raw": joern_result["raw"]}
        else:
            announce("prepare", f"Joern unavailable: {joern_result.get('error', '')[:90]}")
            engine_stats["joern"] = {"error": joern_result.get("error", "")}
            if engine == "joern":
                # Asked for Joern only and it cannot run -- fall back rather
                # than returning an empty scan that looks like a clean repo.
                announce("prepare", "falling back to the builtin engine")
                builtin_repo = stage1_prepare.prepare(path, repo_name=name)
                builtin_findings = stage2_scan.scan(builtin_repo)
                for finding in builtin_findings:
                    finding.setdefault("engine", "builtin")
                findings.extend(builtin_findings)
                engine_stats["builtin"] = {**builtin_repo.stats(),
                                           "findings": len(builtin_findings)}

    # The repo used for CPG stats and source snippets in the report.
    repo = builtin_repo
    if repo is None and joern_result and joern_result.get("available"):
        repo = joern_result["repo"]
    if repo is None:
        repo = stage1_prepare.prepare(path, repo_name=name)

    raw_snapshot = [dict(finding) for finding in findings]

    # ---- Stage 3: VALIDATE ----------------------------------------------
    announce("validate", "judging exploitability")
    validation = stage3_validate.validate(findings, use_llm=use_llm)
    confirmed = stage3_validate.confirmed_only(findings)
    announce("validate", f"{validation['summary']['confirmed']} confirmed, "
                         f"{validation['summary']['suppressed']} suppressed")

    # ---- Stage 4: PROVE --------------------------------------------------
    prove_started = time.time()
    announce("prove", "generating proof-of-concept and fixes")
    stage4_prove.prove(findings)
    prove_ms = int((time.time() - prove_started) * 1000)
    announce("prove", f"{len(confirmed)} proofs generated")

    # ---- Cross-cutting ---------------------------------------------------
    announce("dedupe", "clustering identical patterns")
    clustering = dedupe.cluster(confirmed)

    comparison: dict[str, Any] | None = None
    if with_baseline:
        announce("baseline", "comparing against Joern")
        try:
            comparison = baseline.compare(
                name, path, raw_snapshot, confirmed,
                with_semgrep=with_semgrep,
                # Reuse the Joern run we already paid for.
                joern_findings=(joern_result["findings"]
                                if joern_result and joern_result.get("available")
                                else None))
        except FileNotFoundError:
            comparison = {"error": "no ground truth entry for this repository"}
        except Exception as exc:                   # noqa: BLE001
            comparison = {"error": f"{type(exc).__name__}: {exc}"}

    duration_ms = int((time.time() - started) * 1000)
    validators = validation["summary"]["validators_used"]
    primary_validator = max(validators, key=validators.get) if validators else "none"

    stats = repo.stats()
    result: dict[str, Any] = {
        "id": store.new_scan_id(),
        "repo": name,
        "repo_path": str(path.resolve()),
        "started_at": started_at,
        "duration_ms": duration_ms,
        "engine": engine,

        "stages": {
            "prepare": {"duration_ms": stats.get("duration_ms", 0), **stats},
            "scan": {"raw_findings": len(findings), "by_engine": engine_stats},
            "validate": validation["summary"],
            "prove": {"duration_ms": prove_ms, "proofs": len(confirmed)},
        },

        "summary": {
            "raw_findings": len(findings),
            "confirmed": validation["summary"]["confirmed"],
            "suppressed": validation["summary"]["suppressed"],
            "suppression_rate": validation["summary"]["suppression_rate"],
            "validator": primary_validator,
            "engine": engine,
            "by_severity": _count(confirmed, "severity"),
            "by_category": _count(confirmed, "category"),
            "by_engine": _count(confirmed, "engine"),
        },

        "cpg": repo.cpg.to_dict(limit=250),
        "findings": findings,
        "dedupe": clustering,
        "comparison": comparison,
        "parse_errors": repo.parse_errors,
    }

    sla.apply_to_scan(result)

    if save:
        store.save_scan(result)

    # ---- Optional: push to a live DefectDojo -----------------------------
    if push_to_defectdojo:
        announce("defectdojo", "pushing findings to DefectDojo")
        pushed = defectdojo.push(result)
        result["defectdojo"] = pushed
        if pushed.get("ok"):
            announce("defectdojo",
                     f"{pushed.get('stored', 0)} findings in DefectDojo "
                     f"({pushed.get('test_url', '')})")
        else:
            announce("defectdojo", f"push failed at {pushed.get('stage')}: "
                                   f"{str(pushed.get('error', ''))[:90]}")
        if save:
            store.save_scan(result)

    return result


def run_many(repo_paths: list[str | Path], **kwargs: Any) -> dict[str, Any]:
    """Scan several repositories and dedupe across all of them."""
    scans = []
    every_confirmed: list[dict[str, Any]] = []

    for repo_path in repo_paths:
        scan = run(repo_path, **kwargs)
        scans.append(scan)
        every_confirmed.extend(
            f for f in scan["findings"] if f.get("status") == "confirmed")

    return {
        "scans": scans,
        "cross_repo_dedupe": dedupe.cluster(every_confirmed),
        "totals": {
            "repos": len(scans),
            "raw_findings": sum(s["summary"]["raw_findings"] for s in scans),
            "confirmed": sum(s["summary"]["confirmed"] for s in scans),
            "suppressed": sum(s["summary"]["suppressed"] for s in scans),
        },
    }


def _count(findings: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        key = str(finding.get(field, "unknown"))
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: -item[1]))
