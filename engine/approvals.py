"""The human-approval gate.

Owner: Member 6 (API + Workflow).

Stage 4 writes a suggested fix onto every confirmed finding. Nothing applies
it. A fix moves through exactly one path:

    pending_approval  --approve-->  approved   --apply-->  applied
                      --reject -->  rejected

`approve()` records who approved it and when. `apply_fix()` is the only
function that would ever touch a source file, and it refuses to run unless the
fix has already been approved. That ordering is the whole point of the gate:
it is enforced in code, not in a process document that someone forgets.

For the hackathon `apply_fix()` deliberately stops short of editing files and
returns the patch instead. Auto-editing source in a demo is how you lose a
demo, and a security fix is exactly the kind of change that deserves a human's
eyes on the diff.
"""

from __future__ import annotations

import time
from typing import Any

from . import store

PENDING = "pending_approval"
APPROVED = "approved"
REJECTED = "rejected"
APPLIED = "applied"

VALID_TRANSITIONS = {
    PENDING: {APPROVED, REJECTED},
    APPROVED: {APPLIED, REJECTED},
    REJECTED: {PENDING},          # a reviewer may reopen a rejected fix
    APPLIED: set(),               # terminal
}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _transition(finding_id: str, target: str, actor: str,
                note: str = "") -> dict[str, Any]:
    located = store.find_finding(finding_id)
    if located is None:
        return {"ok": False, "error": f"no finding with id {finding_id}"}

    _, finding = located
    if finding.get("status") != "confirmed":
        return {"ok": False,
                "error": "only a confirmed finding has a fix to approve "
                         f"(this one is '{finding.get('status')}')"}

    current = finding.get("fix_status", PENDING)
    if target not in VALID_TRANSITIONS.get(current, set()):
        return {"ok": False,
                "error": f"cannot move a fix from '{current}' to '{target}'"}

    history = list(finding.get("approval_history", []))
    history.append({"at": _now(), "actor": actor, "from": current,
                    "to": target, "note": note})

    updated = store.update_finding(finding_id, {
        "fix_status": target,
        "approval_actor": actor,
        "approval_note": note,
        "approval_updated_at": _now(),
        "approval_history": history,
    })
    return {"ok": True, "finding": updated}


def approve(finding_id: str, actor: str, note: str = "") -> dict[str, Any]:
    """A human signs off on the suggested fix."""
    return _transition(finding_id, APPROVED, actor, note)


def reject(finding_id: str, actor: str, reason: str) -> dict[str, Any]:
    """A human rejects the suggested fix. A reason is required."""
    if not reason.strip():
        return {"ok": False, "error": "a rejection must include a reason"}
    return _transition(finding_id, REJECTED, actor, reason)


def reopen(finding_id: str, actor: str, note: str = "") -> dict[str, Any]:
    """Move a rejected fix back into the queue."""
    return _transition(finding_id, PENDING, actor, note)


def apply_fix(finding_id: str, actor: str) -> dict[str, Any]:
    """Apply an approved fix.

    THE GATE: this refuses to do anything unless the fix is already approved.
    Even then it does not edit the file -- it returns the patch for a human to
    apply, and records that the decision was taken.
    """
    located = store.find_finding(finding_id)
    if located is None:
        return {"ok": False, "error": f"no finding with id {finding_id}"}

    _, finding = located
    if finding.get("fix_status") != APPROVED:
        return {"ok": False,
                "error": "the fix has not been approved by a human yet "
                         f"(status is '{finding.get('fix_status', PENDING)}'). "
                         "Approve it first."}

    fix = finding.get("suggested_fix", {})
    patch = (
        f"--- {fix.get('file')}:{fix.get('line')} (current)\n"
        f"-   {fix.get('current', '')}\n"
        f"+++ {fix.get('file')}:{fix.get('line')} (suggested)\n"
        f"+   {fix.get('replacement') or fix.get('guidance', '')}\n"
    )
    if fix.get("import_needed"):
        patch = f"+   {fix['import_needed']}\n" + patch

    result = _transition(finding_id, APPLIED, actor, "patch handed to the developer")
    if not result["ok"]:
        return result
    return {"ok": True, "finding": result["finding"], "patch": patch,
            "note": "The engine never edits source files on its own. Apply this "
                    "patch, run your tests, and re-scan to confirm the finding is gone."}


def queue() -> dict[str, Any]:
    """Everything waiting on a human, grouped by state."""
    confirmed = store.all_findings(status="confirmed")
    buckets: dict[str, list[dict[str, Any]]] = {
        PENDING: [], APPROVED: [], REJECTED: [], APPLIED: []}

    for finding in confirmed:
        state = finding.get("fix_status", PENDING)
        buckets.setdefault(state, []).append({
            "id": finding["id"],
            "scan_id": finding.get("scan_id"),
            "repo": finding.get("repo"),
            "severity": finding.get("severity"),
            "title": finding.get("title"),
            "cwe": finding.get("cwe"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "fix": finding.get("suggested_fix", {}).get("replacement", ""),
            "actor": finding.get("approval_actor"),
            "note": finding.get("approval_note"),
            "updated_at": finding.get("approval_updated_at"),
        })

    return {
        "pending_approval": buckets[PENDING],
        "approved": buckets[APPROVED],
        "rejected": buckets[REJECTED],
        "applied": buckets[APPLIED],
        "counts": {state: len(items) for state, items in buckets.items()},
    }
