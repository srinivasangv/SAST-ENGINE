"""STAGE 3 of 4 -- VALIDATE.

Owner: Member 3 (Validate / LLM agent).

This is the stage the whole project is really about. Stage 2 behaves like a
good pattern matcher: it reports every path it can find, including the ones
that are already defended. Stage 3 reads the evidence and decides which of
those are actually exploitable.

Two rules we hold to:

  1. A suppressed finding is never deleted. It stays in the report with
     `status = "suppressed"` and the reason written out. If we deleted them we
     would have no way to show a false-positive suppression rate, and no way
     for a reviewer to disagree with us.

  2. Every verdict records who made it -- `claude` or `offline`. A number on a
     slide is worthless if you cannot say which validator produced it.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from . import llm


def validate(findings: list[dict[str, Any]],
             use_llm: bool | None = None,
             progress: Callable[[int, int], None] | None = None) -> dict[str, Any]:
    """Judge every finding. Returns the findings plus a summary of the stage."""
    started = time.time()
    confirmed = 0
    suppressed = 0
    validators: dict[str, int] = {}

    for index, finding in enumerate(findings, start=1):
        verdict = llm.judge(finding, use_llm=use_llm)

        finding["validation"] = verdict
        finding["stage"] = "validate"

        if verdict["exploitable"]:
            finding["status"] = "confirmed"
            # The validator may disagree with the rule table's default severity.
            finding["severity"] = verdict.get("severity") or finding["severity"]
            confirmed += 1
        else:
            finding["status"] = "suppressed"
            finding["suppression_reason"] = verdict["reasoning"]
            suppressed += 1

        name = verdict.get("validator", "unknown")
        validators[name] = validators.get(name, 0) + 1

        if progress is not None:
            progress(index, len(findings))

    total = len(findings)
    return {
        "findings": findings,
        "summary": {
            "raw_findings": total,
            "confirmed": confirmed,
            "suppressed": suppressed,
            "suppression_rate": round(suppressed / total, 4) if total else 0.0,
            "validators_used": validators,
            "duration_ms": int((time.time() - started) * 1000),
        },
    }


def confirmed_only(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The findings a human should actually look at."""
    return [f for f in findings if f.get("status") == "confirmed"]


def suppressed_only(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The findings we chose not to raise, with the reason attached."""
    return [f for f in findings if f.get("status") == "suppressed"]
