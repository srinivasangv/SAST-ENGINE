#!/usr/bin/env python3
"""Command-line entry point.

    python scan.py testdata/vuln-flask
    python scan.py testdata/vuln-flask testdata/vuln-express   # cross-repo dedupe
    python scan.py testdata/vuln-flask --no-llm                # force offline
    python scan.py testdata/vuln-flask --no-baseline           # skip Semgrep
    python scan.py testdata/vuln-flask --json                  # machine-readable

Owner: Member 6 (API + Workflow).
"""

from __future__ import annotations

import argparse
import json
import sys

from engine import config

# Load .env.local first: `defectdojo` reads its URL from the environment when
# it is imported, so the credentials have to be in place before that happens.
config.load_dotenv()

from engine import baseline, pipeline  # noqa: E402

# ANSI colours, switched off automatically when the output is piped.
COLOUR = sys.stdout.isatty()


def paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOUR else text


SEVERITY_COLOUR = {
    "critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "90",
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Multi-stage agentic SAST engine: Prepare -> Scan -> Validate -> Prove")
    parser.add_argument("repos", nargs="+", help="one or more repository paths to scan")
    parser.add_argument("--no-llm", action="store_true",
                        help="force the offline validator even if an API key is set")
    parser.add_argument("--engine", choices=("builtin", "joern", "both"),
                        default="builtin",
                        help="which CPG/taint engine to scan with (default: builtin)")
    parser.add_argument("--no-baseline", action="store_true",
                        help="skip the Joern baseline comparison (much faster)")
    parser.add_argument("--with-semgrep", action="store_true",
                        help="also measure Semgrep as a secondary baseline")
    parser.add_argument("--defectdojo", action="store_true",
                        help="push confirmed findings to a live DefectDojo instance")
    parser.add_argument("--json", action="store_true",
                        help="print the full result as JSON instead of a report")
    parser.add_argument("--show-suppressed", action="store_true",
                        help="also list the findings that were suppressed, with reasons")
    arguments = parser.parse_args()

    use_llm = False if arguments.no_llm else None
    if use_llm is None and not config.llm_available():
        print(paint(f"note: {config.LLM_API_KEY_ENV} is not set -- "
                    f"using the offline validator\n", "33"))

    results = []
    for repo in arguments.repos:
        try:
            result = pipeline.run(
                repo, use_llm=use_llm,
                engine=arguments.engine,
                with_baseline=not arguments.no_baseline,
                with_semgrep=arguments.with_semgrep,
                push_to_defectdojo=arguments.defectdojo,
                on_stage=None if arguments.json else _progress)
        except FileNotFoundError as exc:
            print(paint(f"error: {exc}", "1;31"), file=sys.stderr)
            return 2
        results.append(result)
        if not arguments.json:
            _report(result, show_suppressed=arguments.show_suppressed)

    if arguments.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2, default=str))
    elif len(results) > 1:
        _cross_repo(results)

    total_confirmed = sum(r["summary"]["confirmed"] for r in results)
    return 1 if total_confirmed else 0


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def _progress(stage: str, message: str) -> None:
    print(f"  {paint(stage.upper().ljust(9), '1;36')} {message}")


def _report(result: dict, show_suppressed: bool = False) -> None:
    summary = result["summary"]
    print()
    print(paint("=" * 78, "1;34"))
    print(paint(f" {result['repo']}  ({result['repo_path']})", "1;37"))
    print(paint("=" * 78, "1;34"))

    prepare = result["stages"]["prepare"]
    print(f"  files parsed      : {prepare['files']}  "
          f"({', '.join(f'{k} {v}' for k, v in prepare['languages'].items()) or 'none'})")
    print(f"  CPG               : {prepare['nodes']} nodes, {prepare['edges']} edges, "
          f"{prepare['functions']} functions, {prepare['routes']} HTTP routes")
    if result["parse_errors"]:
        print(paint(f"  files skipped     : {len(result['parse_errors'])} "
                    f"(see parse_errors in the JSON)", "33"))

    print()
    print(f"  Stage 2 reported  : {summary['raw_findings']}")
    print(f"  Stage 3 confirmed : {paint(str(summary['confirmed']), '1;31')}")
    print(f"  Stage 3 suppressed: {paint(str(summary['suppressed']), '32')} "
          f"({summary['suppression_rate']:.0%} of everything reported)")
    print(f"  validated by      : {summary['validator']}")
    print(f"  scanned by        : {summary.get('engine', 'builtin')} engine")
    by_engine = summary.get("by_engine") or {}
    if len(by_engine) > 1:
        print("                      "
              + ", ".join(f"{k}: {v}" for k, v in by_engine.items()))

    confirmed = [f for f in result["findings"] if f["status"] == "confirmed"]
    if confirmed:
        print()
        print(paint("  CONFIRMED VULNERABILITIES", "1;31"))
        for finding in confirmed:
            colour = SEVERITY_COLOUR.get(finding["severity"], "0")
            print(f"    {paint(finding['severity'].upper().ljust(9), colour)} "
                  f"{finding['cwe']:<8} {finding['file']}:{finding['line']}  "
                  f"{finding['title']}")
            print(f"      {paint('path', '90')}  " + _short_path(finding))
            poc = finding.get("poc", {})
            if poc.get("command"):
                print(f"      {paint('PoC ', '90')}  {poc['command']}")
            fix = finding.get("suggested_fix", {})
            if fix.get("replacement"):
                print(f"      {paint('fix ', '90')}  {fix['replacement']}")
            size = finding.get("cluster_size", 1)
            if size > 1:
                repos = finding.get("cluster_repos", [])
                where = (f"across {', '.join(repos)}" if len(repos) > 1
                         else f"{size} times in this repository")
                print(f"      {paint('dupe', '90')}  same pattern {where}")
            print()

    suppressed = [f for f in result["findings"] if f["status"] == "suppressed"]
    if suppressed and show_suppressed:
        print(paint("  SUPPRESSED (reported by pattern matching, dismissed by validation)", "32"))
        for finding in suppressed:
            print(f"    {finding['cwe']:<8} {finding['file']}:{finding['line']}  "
                  f"{finding['title']}")
            print(f"      {paint('why', '90')}   {finding.get('suppression_reason', '')}")
        print()
    elif suppressed:
        print(paint(f"  ({len(suppressed)} findings suppressed -- "
                    f"re-run with --show-suppressed to see why)", "32"))
        print()

    clusters = result.get("dedupe", {}).get("summary", {})
    if clusters.get("duplicates_removed"):
        print(f"  dedupe            : {clusters['findings_before']} findings -> "
              f"{clusters['clusters_after']} unique patterns "
              f"({clusters['duplicates_removed']} duplicates collapsed)")

    pushed = result.get("defectdojo")
    if pushed:
        print()
        if pushed.get("ok"):
            print(paint("  DEFECTDOJO", "1;35"))
            print(f"    {pushed.get('stored', 0)} findings imported "
                  f"(submitted {pushed.get('submitted', 0)})")
            print(f"    {pushed.get('test_url', '')}")
        else:
            print(paint(f"  DefectDojo push failed at {pushed.get('stage')}: "
                        f"{str(pushed.get('error', ''))[:70]}", "33"))

    comparison = result.get("comparison")
    if comparison and "error" not in comparison:
        print()
        print(paint("  COMPARISON vs BASELINE SAST", "1;35"))
        for line in baseline.format_table(comparison).splitlines():
            print(f"    {line}")
    elif comparison:
        print(paint(f"  comparison unavailable: {comparison['error']}", "33"))

    print()
    print(f"  saved to          : data/scans/{result['id']}.json")
    print(f"  total time        : {result['duration_ms']} ms")
    print()


def _short_path(finding: dict) -> str:
    steps = finding.get("taint_path", [])
    if not steps:
        return "(none)"
    first, last = steps[0], steps[-1]
    middle = f" -> ... ({len(steps) - 2} steps)" if len(steps) > 2 else ""
    return f"line {first['line']} {first['description']}{middle} -> line {last['line']} {last['description']}"


def _cross_repo(results: list[dict]) -> None:
    from engine import dedupe as dedupe_module

    every = [f for r in results for f in r["findings"] if f["status"] == "confirmed"]
    clustering = dedupe_module.cluster(every)
    cross = [c for c in clustering["clusters"] if c["cross_repo"]]

    print(paint("=" * 78, "1;34"))
    print(paint(" CROSS-REPOSITORY DEDUPLICATION", "1;37"))
    print(paint("=" * 78, "1;34"))
    print(f"  {clustering['summary']['findings_before']} confirmed findings across "
          f"{len(results)} repositories")
    print(f"  {clustering['summary']['clusters_after']} unique vulnerability patterns")
    print(f"  {clustering['summary']['cross_repo_clusters']} patterns appear in "
          f"more than one repository")
    print()
    for cluster in cross:
        print(f"  {paint(cluster['title'], '1;33')}  ({cluster['cwe']}, shape {cluster['shape']})")
        for location in cluster["locations"]:
            print(f"    - {location['repo']}: {location['file']}:{location['line']} "
                  f"[{location['language']}]")
        print(f"    {paint('one ticket, not ' + str(cluster['count']), '90')}")
        print()


if __name__ == "__main__":
    sys.exit(main())
