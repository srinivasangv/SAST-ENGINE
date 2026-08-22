#!/usr/bin/env python3
"""The JSON API the React dashboard talks to.

Owner: Member 6 (API + Workflow).

Built on http.server from the standard library. No Flask, no FastAPI, no
uvicorn. The whole web layer is this one file, and a fresher can read it top
to bottom and know exactly what happens to a request.

    python server.py            # http://127.0.0.1:8000

Routes are a list of (method, regex, handler) tuples. `_dispatch` walks the
list, and the first pattern that matches wins. That is all a router is.
"""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from engine import config

# Read .env.local BEFORE the other engine modules import. `defectdojo` reads
# its URL from the environment at import time, so loading the file afterwards
# would leave it pointing at the default while the token pointed elsewhere.
config.load_dotenv()

from engine import (approvals, baseline, defectdojo, dedupe,  # noqa: E402
                    joern_engine, pipeline, sla, store)

# One scan at a time. Scanning is CPU-bound and two concurrent scans just make
# each other slower, but requests for results must never block behind one.
SCAN_LOCK = threading.Lock()

# Scans started through the API run in a thread, so the browser gets an
# immediate response and polls for progress.
RUNNING: dict[str, dict[str, Any]] = {}


# --------------------------------------------------------------------------
# Handlers. Each one takes (match, query, body) and returns (status, payload).
# --------------------------------------------------------------------------


def last_validator() -> str | None:
    """Which validator actually answered on the most recent scan.

    "A key is set" and "the LLM worked" are different claims. `llm_configured`
    only ever meant the first, but the dashboard was rendering it as the
    second -- so a key that returns 401 showed up in the header as
    "validator: Claude". This reads the provider recorded on a real verdict,
    which is a fact rather than a hope, and costs nothing: the scan is already
    on disk. Returns None when nothing has been scanned yet.
    """
    for finding in store.all_findings(latest_only=True):
        validation = finding.get("validation") or {}
        provider = validation.get("provider") or validation.get("validator")
        if provider:
            return provider
    return None


def health(match, query, body) -> tuple[int, Any]:
    dojo = defectdojo.health()
    provider = config.detect_provider()
    return 200, {
        "status": "ok",
        "llm_configured": config.llm_available(),
        "llm_provider": provider,
        "llm_model": config.llm_model_for(provider),
        "llm_last_used": last_validator(),
        "scans_stored": len(store.list_scans()),
        "engines": {
            "builtin": True,
            "joern": joern_engine.joern_available(),
            "joern_version": joern_engine.joern_version(),
            "joern_error": joern_engine.unavailable_reason(),
        },
        "semgrep_available": baseline.semgrep_available(),
        "defectdojo": {
            "url": defectdojo.DEFAULT_URL,
            "configured": defectdojo.configured(),
            "reachable": dojo.get("reachable", False),
            "authenticated": dojo.get("authenticated", False),
            "error": dojo.get("error", ""),
        },
    }


def list_scans(match, query, body) -> tuple[int, Any]:
    return 200, {"scans": store.list_scans(), "running": list(RUNNING.values())}


def start_scan(match, query, body) -> tuple[int, Any]:
    repo_path = (body or {}).get("repo_path")
    if not repo_path:
        return 400, {"error": "repo_path is required"}

    use_llm = (body or {}).get("use_llm")          # None means "decide for me"
    with_baseline = bool((body or {}).get("with_baseline", True))
    with_semgrep = bool((body or {}).get("with_semgrep", False))
    push_dojo = bool((body or {}).get("push_to_defectdojo", False))
    engine = (body or {}).get("engine", "builtin")
    if engine not in pipeline.ENGINES:
        return 400, {"error": f"engine must be one of {list(pipeline.ENGINES)}"}
    job_id = store.new_scan_id()

    RUNNING[job_id] = {"job_id": job_id, "repo_path": repo_path,
                       "state": "queued", "stage": "", "message": ""}

    def work() -> None:
        def on_stage(stage: str, message: str) -> None:
            RUNNING[job_id].update(state="running", stage=stage, message=message)

        with SCAN_LOCK:
            try:
                result = pipeline.run(repo_path, use_llm=use_llm, engine=engine,
                                      with_baseline=with_baseline,
                                      with_semgrep=with_semgrep,
                                      push_to_defectdojo=push_dojo,
                                      on_stage=on_stage)
                RUNNING[job_id].update(state="done", scan_id=result["id"],
                                       stage="done",
                                       message=f"{result['summary']['confirmed']} confirmed, "
                                               f"{result['summary']['suppressed']} suppressed")
            except Exception as exc:               # noqa: BLE001
                RUNNING[job_id].update(state="error", stage="error",
                                       message=f"{type(exc).__name__}: {exc}")
                traceback.print_exc()

    threading.Thread(target=work, daemon=True).start()
    return 202, {"job_id": job_id, "state": "queued",
                 "poll": f"/api/scans/status/{job_id}"}


def scan_status(match, query, body) -> tuple[int, Any]:
    job = RUNNING.get(match.group("job_id"))
    if job is None:
        return 404, {"error": "no such job"}
    return 200, job


def get_scan(match, query, body) -> tuple[int, Any]:
    scan = store.load_scan(match.group("scan_id"))
    if scan is None:
        return 404, {"error": "no such scan"}
    return 200, scan


def delete_scan(match, query, body) -> tuple[int, Any]:
    if store.delete_scan(match.group("scan_id")):
        return 200, {"deleted": True}
    return 404, {"error": "no such scan"}


def list_findings(match, query, body) -> tuple[int, Any]:
    status = _first(query, "status")
    findings = store.all_findings(status=status)

    severity = _first(query, "severity")
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    repo = _first(query, "repo")
    if repo:
        findings = [f for f in findings if f.get("repo") == repo]

    return 200, {"findings": findings, "count": len(findings)}


def get_finding(match, query, body) -> tuple[int, Any]:
    located = store.find_finding(match.group("finding_id"))
    if located is None:
        return 404, {"error": "no such finding"}
    scan, finding = located
    return 200, {"finding": finding, "scan_id": scan.get("id"), "repo": scan.get("repo")}


def approve_finding(match, query, body) -> tuple[int, Any]:
    payload = body or {}
    result = approvals.approve(match.group("finding_id"),
                               actor=payload.get("actor", "unknown"),
                               note=payload.get("note", ""))
    return (200 if result["ok"] else 400), result


def reject_finding(match, query, body) -> tuple[int, Any]:
    payload = body or {}
    result = approvals.reject(match.group("finding_id"),
                              actor=payload.get("actor", "unknown"),
                              reason=payload.get("reason", ""))
    return (200 if result["ok"] else 400), result


def apply_finding_fix(match, query, body) -> tuple[int, Any]:
    payload = body or {}
    result = approvals.apply_fix(match.group("finding_id"),
                                 actor=payload.get("actor", "unknown"))
    return (200 if result["ok"] else 400), result


def approval_queue(match, query, body) -> tuple[int, Any]:
    return 200, approvals.queue()


def sla_report(match, query, body) -> tuple[int, Any]:
    return 200, sla.report()


def dedupe_report(match, query, body) -> tuple[int, Any]:
    """Cluster across every stored scan -- this is the cross-repo view."""
    confirmed = store.all_findings(status="confirmed")
    return 200, dedupe.cluster(confirmed)


def comparison_report(match, query, body) -> tuple[int, Any]:
    """The Semgrep comparison for each scan that has one."""
    comparisons = []
    for summary in store.list_scans():
        scan = store.load_scan(summary["id"])
        if scan and scan.get("comparison") and "error" not in scan["comparison"]:
            comparisons.append({"scan_id": scan["id"], "repo": scan["repo"],
                                **scan["comparison"]})
    return 200, {"comparisons": comparisons}


def defectdojo_status(match, query, body) -> tuple[int, Any]:
    """Is DefectDojo up, and what have we pushed into it?"""
    status = defectdojo.health()
    payload = {"url": defectdojo.get_base_url(),
               "configured": defectdojo.configured(), **status}
    if status.get("authenticated"):
        recent = defectdojo.findings_in_defectdojo(limit=25)
        payload["findings_in_defectdojo"] = recent.get("count", 0)
        payload["recent"] = recent.get("findings", [])
    return 200, payload


def push_defectdojo(match, query, body) -> tuple[int, Any]:
    """Push a stored scan into a live DefectDojo instance."""
    payload = body or {}
    scan_id = payload.get("scan_id")
    if not scan_id:
        return 400, {"error": "scan_id is required"}
    scan = store.load_scan(scan_id)
    if scan is None:
        return 404, {"error": "no such scan"}

    result = defectdojo.push(
        scan,
        include_suppressed=bool(payload.get("include_suppressed", False)),
        close_old=bool(payload.get("close_old", False)))
    if result.get("ok"):
        scan["defectdojo"] = result
        store.save_scan(scan)
    return (200 if result.get("ok") else 400), result


def export_defectdojo(match, query, body) -> tuple[int, Any]:
    payload = body or {}
    scan_id = payload.get("scan_id")
    if not scan_id:
        return 400, {"error": "scan_id is required"}
    scan = store.load_scan(scan_id)
    if scan is None:
        return 404, {"error": "no such scan"}
    result = defectdojo.export(
        scan, include_suppressed=bool(payload.get("include_suppressed", False)))
    return 200, result


def upload_project(match, query, body) -> tuple[int, Any]:
    if not body:
        return 400, {"error": "request body required"}

    filename = body.get("filename", "project_file.py")
    content = body.get("content")
    data_b64 = body.get("data_b64") or body.get("base64")

    clean_name = re.sub(r"[^\w\-.]", "_", Path(filename).stem) or "uploaded-project"
    target_dir = config.DATA_DIR / "uploads" / clean_name
    target_dir.mkdir(parents=True, exist_ok=True)

    if data_b64:
        import base64
        import io
        import zipfile
        raw_bytes = base64.b64decode(data_b64)
        if filename.lower().endswith(".zip") or zipfile.is_zipfile(io.BytesIO(raw_bytes)):
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                zf.extractall(target_dir)
        else:
            (target_dir / filename).write_bytes(raw_bytes)
    elif content is not None:
        (target_dir / filename).write_text(content, encoding="utf-8")
    else:
        return 400, {"error": "content or data_b64 field required"}

    try:
        rel_path = str(target_dir.relative_to(config.ROOT))
    except Exception:
        rel_path = str(target_dir)

    return 200, {
        "ok": True,
        "repo_path": rel_path,
        "repo_name": clean_name,
        "message": f"Project uploaded successfully to {rel_path}"
    }


def root_index(match, query, body) -> tuple[int, Any]:
    return 200, {
        "message": "SAST Engine API is running. The browser UI dashboard runs at http://localhost:5173",
        "dashboard_url": "http://localhost:5173",
        "health_url": "http://127.0.0.1:8000/api/health"
    }


ROUTES: list[tuple[str, str, Callable]] = [
    ("GET",    r"^/$",                                        root_index),
    ("POST",   r"^/api/upload$",                              upload_project),
    ("GET",    r"^/api/health$",                              health),
    ("GET",    r"^/api/scans$",                               list_scans),
    ("POST",   r"^/api/scans$",                               start_scan),
    ("GET",    r"^/api/scans/status/(?P<job_id>[\w\-]+)$",    scan_status),
    ("GET",    r"^/api/scans/(?P<scan_id>[\w\-]+)$",          get_scan),
    ("DELETE", r"^/api/scans/(?P<scan_id>[\w\-]+)$",          delete_scan),
    ("GET",    r"^/api/findings$",                            list_findings),
    ("GET",    r"^/api/findings/(?P<finding_id>[\w]+)$",      get_finding),
    ("POST",   r"^/api/findings/(?P<finding_id>[\w]+)/approve$", approve_finding),
    ("POST",   r"^/api/findings/(?P<finding_id>[\w]+)/reject$",  reject_finding),
    ("POST",   r"^/api/findings/(?P<finding_id>[\w]+)/apply$",   apply_finding_fix),
    ("GET",    r"^/api/approvals$",                           approval_queue),
    ("GET",    r"^/api/sla$",                                 sla_report),
    ("GET",    r"^/api/dedupe$",                              dedupe_report),
    ("GET",    r"^/api/comparison$",                          comparison_report),
    ("POST",   r"^/api/export/defectdojo$",                   export_defectdojo),
    ("GET",    r"^/api/defectdojo$",                          defectdojo_status),
    ("POST",   r"^/api/defectdojo/push$",                     push_defectdojo),
]

COMPILED = [(method, re.compile(pattern), handler) for method, pattern, handler in ROUTES]


def _first(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    return values[0] if values else None


# --------------------------------------------------------------------------
# The HTTP plumbing
# --------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = "sast-engine/1.0"

    def address_string(self) -> str:
        return self.client_address[0]

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_OPTIONS(self) -> None:
        # The browser sends this before a cross-origin POST. Answer it or the
        # dashboard's requests never arrive.
        self.send_response(204)
        self._cors()
        self.end_headers()

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        body: dict[str, Any] | None = None
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                self._respond(400, {"error": "request body is not valid JSON"})
                return

        for route_method, pattern, handler in COMPILED:
            if route_method != method:
                continue
            match = pattern.match(parsed.path)
            if match is None:
                continue
            try:
                status, payload = handler(match, query, body)
            except Exception as exc:               # noqa: BLE001
                traceback.print_exc()
                status, payload = 500, {"error": f"{type(exc).__name__}: {exc}"}
            self._respond(status, payload)
            return

        self._respond(404, {"error": f"no route for {method} {parsed.path}",
                            "available": sorted({p for _, p, _ in ROUTES})})

    def _respond(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, indent=2, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _cors(self) -> None:
        # The dashboard runs on :5173 in development, this API on :8000.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, format: str, *args) -> None:
        print(f"  {self.command:6} {self.path}  ->  {args[1] if len(args) > 1 else ''}")


def main() -> None:
    config.ensure_dirs()
    server = ThreadingHTTPServer((config.SERVER_HOST, config.SERVER_PORT), Handler)
    print(f"SAST engine API on http://{config.SERVER_HOST}:{config.SERVER_PORT}")
    print(f"  LLM validator: "
          f"{'Claude ' + config.LLM_MODEL if config.llm_available() else 'offline fallback'}")
    print(f"  engines      : builtin"
          + (f", joern ({joern_engine.joern_version()})"
             if joern_engine.joern_available() else " (joern not installed)"))
    dojo = defectdojo.health()
    print(f"  defectdojo   : "
          + ("connected at " + defectdojo.DEFAULT_URL if dojo.get("authenticated")
             else f"not connected ({str(dojo.get('error', ''))[:60]})"))
    print(f"  stored scans : {len(store.list_scans())}")
    print("  press Ctrl-C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
        server.shutdown()


if __name__ == "__main__":
    main()
