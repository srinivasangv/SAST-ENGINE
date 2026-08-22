"""Storage: one JSON file per scan.

Owner: Member 6 (API + Workflow).

There is no database. A scan result is a JSON file under data/scans/, which
means you can inspect it with `cat`, diff two runs with `diff`, and delete a
bad run with `rm`. For a five-day project that is the right trade: no schema,
no migrations, no ORM to explain, and the on-disk format is the same thing the
API returns.

Writes go to a temporary file and are then renamed. Renaming is atomic on
POSIX, so a crash halfway through a write cannot leave a half-written scan
that breaks the dashboard on the next load.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

from . import config


def new_scan_id() -> str:
    """Sortable and unique: 20260813-142530-a1b2c3."""
    return f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"


def scan_path(scan_id: str):
    return config.SCANS_DIR / f"{scan_id}.json"


def save_scan(scan: dict[str, Any]) -> str:
    """Write a scan result atomically. Returns the path written."""
    config.ensure_dirs()
    path = scan_path(scan["id"])
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(scan, indent=2, default=str))
    os.replace(temporary, path)          # atomic on POSIX
    return str(path)


def load_scan(scan_id: str) -> dict[str, Any] | None:
    path = scan_path(scan_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def list_scans() -> list[dict[str, Any]]:
    """A summary of every stored scan, newest first."""
    config.ensure_dirs()
    summaries = []
    for path in sorted(config.SCANS_DIR.glob("*.json"), reverse=True):
        try:
            scan = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue          # a partially written or hand-edited file: skip it
        summaries.append({
            "id": scan.get("id"),
            "repo": scan.get("repo"),
            "repo_path": scan.get("repo_path"),
            "started_at": scan.get("started_at"),
            "duration_ms": scan.get("duration_ms"),
            "raw_findings": scan.get("summary", {}).get("raw_findings", 0),
            "confirmed": scan.get("summary", {}).get("confirmed", 0),
            "suppressed": scan.get("summary", {}).get("suppressed", 0),
            "validator": scan.get("summary", {}).get("validator", "unknown"),
        })
    return summaries


def delete_scan(scan_id: str) -> bool:
    path = scan_path(scan_id)
    if path.exists():
        path.unlink()
        return True
    return False


def find_finding(finding_id: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Locate a finding across every scan. Returns (scan, finding)."""
    config.ensure_dirs()
    for path in sorted(config.SCANS_DIR.glob("*.json"), reverse=True):
        try:
            scan = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        for finding in scan.get("findings", []):
            if finding.get("id") == finding_id:
                return scan, finding
    return None


def update_finding(finding_id: str, changes: dict[str, Any]) -> dict[str, Any] | None:
    """Apply changes to a finding and re-save its scan."""
    located = find_finding(finding_id)
    if located is None:
        return None
    scan, finding = located
    finding.update(changes)
    save_scan(scan)
    return finding


def all_findings(status: str | None = None, latest_only: bool = True) -> list[dict[str, Any]]:
    """Every finding from every scan, optionally filtered by status.

    `latest_only` keeps just the newest occurrence of each finding id.

    Finding ids are a hash of repo + file + line + sink + category, so
    re-scanning an unchanged repository produces the SAME ids. Without this
    filter, scanning one repo five times would show 55 findings in the
    dashboard, five approval-queue entries for one fix, and a dedupe
    "reduction" of 84% that is really just the same finding counted again.
    Scans are walked newest-first, so the first id we see is the current one.
    """
    config.ensure_dirs()
    collected: list[dict[str, Any]] = []
    seen: set[str] = set()

    for path in sorted(config.SCANS_DIR.glob("*.json"), reverse=True):
        try:
            scan = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        for finding in scan.get("findings", []):
            if status is not None and finding.get("status") != status:
                continue
            finding_id = finding.get("id", "")
            if latest_only and finding_id in seen:
                continue
            seen.add(finding_id)
            enriched = dict(finding)
            enriched["scan_id"] = scan.get("id")
            enriched["scan_started_at"] = scan.get("started_at")
            collected.append(enriched)
    return collected
