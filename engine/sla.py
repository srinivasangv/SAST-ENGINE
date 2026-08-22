"""SLA ageing and escalation.

Owner: Member 6 (API + Workflow).

A finding that nobody fixes is not a finding, it is a liability. Each severity
gets a clock (engine/config.py -> SLA_HOURS). When a confirmed finding is
older than its clock allows, it breaches and escalates to the owner listed in
SLA_ESCALATION.

`age_hours` is injectable so the tests can age a finding by three days without
waiting three days.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from . import config, store

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"


def now_iso() -> str:
    return time.strftime(TIME_FORMAT)


def hours_since(timestamp: str | None) -> float:
    """How many hours ago was this? Returns 0.0 for anything unparseable."""
    if not timestamp:
        return 0.0
    text = timestamp.replace("Z", "").split(".")[0]
    try:
        opened = datetime.strptime(text, TIME_FORMAT)
    except ValueError:
        return 0.0
    return max(0.0, (datetime.now() - opened).total_seconds() / 3600.0)


def evaluate(finding: dict[str, Any], age_hours: float | None = None) -> dict[str, Any]:
    """Work out the SLA state of one finding."""
    severity = str(finding.get("severity", "medium")).lower()
    budget = config.SLA_HOURS.get(severity, config.SLA_HOURS["medium"])

    if age_hours is None:
        age_hours = hours_since(finding.get("opened_at") or finding.get("scan_started_at"))

    # A fix that has been applied stops the clock.
    resolved = finding.get("fix_status") == "applied"
    breached = (not resolved) and age_hours > budget
    remaining = budget - age_hours

    state = "resolved" if resolved else ("breached" if breached else
                                         ("at_risk" if remaining <= budget * 0.25 else "on_track"))

    return {
        "finding_id": finding.get("id"),
        "severity": severity,
        "state": state,
        "age_hours": round(age_hours, 2),
        "budget_hours": budget,
        "hours_remaining": round(remaining, 2),
        "overdue_by_hours": round(age_hours - budget, 2) if breached else 0.0,
        "breached": breached,
        "escalate_to": config.SLA_ESCALATION.get(severity, "team-lead") if breached else "",
        "opened_at": finding.get("opened_at") or finding.get("scan_started_at"),
    }


def apply_to_scan(scan: dict[str, Any]) -> dict[str, Any]:
    """Stamp every confirmed finding in a scan with its SLA state."""
    opened_at = scan.get("started_at", now_iso())
    breached = 0

    for finding in scan.get("findings", []):
        if finding.get("status") != "confirmed":
            continue
        finding.setdefault("opened_at", opened_at)
        status = evaluate(finding)
        finding["sla"] = status
        if status["breached"]:
            breached += 1

    scan.setdefault("summary", {})["sla_breached"] = breached
    return scan


def report(age_override: dict[str, float] | None = None) -> dict[str, Any]:
    """The SLA view across every stored scan -- what the dashboard shows."""
    findings = store.all_findings(status="confirmed")
    overrides = age_override or {}

    rows = []
    for finding in findings:
        status = evaluate(finding, age_hours=overrides.get(finding["id"]))
        rows.append({
            **status,
            "repo": finding.get("repo"),
            "scan_id": finding.get("scan_id"),
            "title": finding.get("title"),
            "cwe": finding.get("cwe"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "fix_status": finding.get("fix_status", "pending_approval"),
        })

    # Worst first: breached, then closest to breaching.
    order = {"breached": 0, "at_risk": 1, "on_track": 2, "resolved": 3}
    rows.sort(key=lambda r: (order.get(r["state"], 9), -r["age_hours"]))

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["state"]] = counts.get(row["state"], 0) + 1

    escalations = [
        {"finding_id": r["finding_id"], "severity": r["severity"], "title": r["title"],
         "file": r["file"], "line": r["line"], "overdue_by_hours": r["overdue_by_hours"],
         "escalate_to": r["escalate_to"]}
        for r in rows if r["breached"]
    ]

    return {
        "policy_hours": config.SLA_HOURS,
        "escalation_targets": config.SLA_ESCALATION,
        "findings": rows,
        "counts": counts,
        "breached": len(escalations),
        "escalations": escalations,
        "generated_at": now_iso(),
    }
