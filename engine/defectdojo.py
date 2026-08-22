"""DefectDojo integration -- a real API client, not just a file writer.

Owner: Member 5 (Prove + Integrations).

DefectDojo is where remediation actually gets tracked. This module does the
whole round trip against a live instance:

    product  ->  engagement  ->  import-scan  ->  read the findings back

`push()` is the one to call. It is idempotent on the product and engagement
(it looks them up by name before creating), so re-running a scan adds a new
test to the same engagement rather than a duplicate product.

`export()` still writes the Generic Findings Import file to disk. That is the
offline path -- it works with no server, and it is what you upload by hand
through the DefectDojo UI. Same document either way, so the two cannot drift.

Everything here uses `urllib` from the standard library. Adding `requests`
for six HTTP calls would not have earned its place.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from . import config

# Where DefectDojo lives, and how we authenticate. Both are overridable so a
# CI job can point at its own instance without editing code.
DEFAULT_URL = "http://localhost:8080"
TOKEN_ENV = "DEFECTDOJO_TOKEN"
TOKEN_FILE = Path.home() / ".dd_token"

def get_base_url() -> str:
    config.load_dotenv()
    return os.environ.get("DEFECTDOJO_URL") or DEFAULT_URL

DEFAULT_PRODUCT = "SAST Engine"
DEFAULT_PRODUCT_TYPE = "Research and Development"
SCAN_TYPE = "Generic Findings Import"

HTTP_TIMEOUT = 60

SEVERITY_MAP = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info",
}


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------


def api_token() -> str:
    """The API token, from the environment or from ~/.dd_token."""
    config.load_dotenv()
    token = os.environ.get(TOKEN_ENV, "").strip()
    if token:
        return token
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text().strip()
    return ""


def fetch_token(base_url: str, username: str, password: str) -> dict[str, Any]:
    """Trade a username and password for an API token.

    Handy for first-time setup: DefectDojo prints a generated admin password
    in the initializer container's logs.
    """
    result = _request(
        f"{base_url.rstrip('/')}/api/v2/api-token-auth/",
        method="POST", body={"username": username, "password": password}, token="")
    if result["ok"] and "token" in result["data"]:
        return {"ok": True, "token": result["data"]["token"]}
    return {"ok": False, "error": result.get("error", "no token in response")}


def configured() -> bool:
    return bool(api_token())


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


def _request(url: str, method: str = "GET", body: Any = None,
             token: str | None = None, raw_body: bytes | None = None,
             content_type: str = "application/json",
             timeout: int = HTTP_TIMEOUT) -> dict[str, Any]:
    """One HTTP call. Never raises -- returns {"ok": bool, ...}."""
    headers = {"Accept": "application/json"}
    auth = api_token() if token is None else token
    if auth:
        headers["Authorization"] = f"Token {auth}"

    data = raw_body
    if data is None and body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = content_type
    elif raw_body is not None:
        headers["Content-Type"] = content_type

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode()
            return {"ok": True, "status": response.status,
                    "data": json.loads(text) if text.strip() else {}}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:500]
        return {"ok": False, "status": exc.code,
                "error": f"HTTP {exc.code}: {detail}"}
    except urllib.error.URLError as exc:
        return {"ok": False, "status": 0,
                "error": f"cannot reach DefectDojo at {url}: {exc.reason}"}
    except Exception as exc:                       # noqa: BLE001
        return {"ok": False, "status": 0, "error": f"{type(exc).__name__}: {exc}"}


def health(base_url: str | None = None, timeout: int = 4) -> dict[str, Any]:
    """Is DefectDojo up and is our token good?"""
    base_url = (base_url or get_base_url()).rstrip("/")
    if not api_token():
        return {"reachable": False, "authenticated": False,
                "error": f"no token. Set {TOKEN_ENV} or write one to {TOKEN_FILE}."}
    result = _request(f"{base_url}/api/v2/users/?limit=1", timeout=timeout)
    if result["ok"]:
        return {"reachable": True, "authenticated": True, "url": base_url}
    if result.get("status") in (401, 403):
        return {"reachable": True, "authenticated": False, "error": result["error"]}
    return {"reachable": False, "authenticated": False, "error": result["error"]}


# --------------------------------------------------------------------------
# Product and engagement (idempotent)
# --------------------------------------------------------------------------


def _find_or_create_product_type(base_url: str, name: str) -> int | None:
    query = urllib.parse.urlencode({"name": name})
    found = _request(f"{base_url}/api/v2/product_types/?{query}")
    if found["ok"] and found["data"].get("results"):
        return found["data"]["results"][0]["id"]
    created = _request(f"{base_url}/api/v2/product_types/", method="POST",
                       body={"name": name, "description": "Created by the SAST engine"})
    return created["data"].get("id") if created["ok"] else None


def find_or_create_product(base_url: str, name: str,
                           description: str = "") -> dict[str, Any]:
    """Look the product up by name; create it only if it is missing."""
    query = urllib.parse.urlencode({"name": name})
    found = _request(f"{base_url}/api/v2/products/?{query}")
    if found["ok"]:
        for product in found["data"].get("results", []):
            if product["name"] == name:
                return {"ok": True, "id": product["id"], "created": False}
    elif found.get("status") in (401, 403):
        return {"ok": False, "error": found["error"]}

    product_type = _find_or_create_product_type(base_url, DEFAULT_PRODUCT_TYPE)
    if product_type is None:
        return {"ok": False, "error": "could not resolve a product type"}

    created = _request(f"{base_url}/api/v2/products/", method="POST", body={
        "name": name,
        "description": description or "Repositories scanned by the multi-stage SAST engine",
        "prod_type": product_type,
    })
    if created["ok"]:
        return {"ok": True, "id": created["data"]["id"], "created": True}
    return {"ok": False, "error": created["error"]}


def find_or_create_engagement(base_url: str, product_id: int,
                              name: str) -> dict[str, Any]:
    """One engagement per repository, reused across scans."""
    query = urllib.parse.urlencode({"product": product_id, "name": name})
    found = _request(f"{base_url}/api/v2/engagements/?{query}")
    if found["ok"]:
        for engagement in found["data"].get("results", []):
            if engagement["name"] == name:
                return {"ok": True, "id": engagement["id"], "created": False}

    today = time.strftime("%Y-%m-%d")
    created = _request(f"{base_url}/api/v2/engagements/", method="POST", body={
        "name": name,
        "product": product_id,
        "target_start": today,
        "target_end": today,
        "status": "In Progress",
        "engagement_type": "CI/CD",
        "deduplication_on_engagement": True,
    })
    if created["ok"]:
        return {"ok": True, "id": created["data"]["id"], "created": True}
    return {"ok": False, "error": created["error"]}


# --------------------------------------------------------------------------
# Building the import document
# --------------------------------------------------------------------------


def to_defectdojo(scan: dict[str, Any], include_suppressed: bool = False) -> dict[str, Any]:
    """Convert a scan result into a Generic Findings Import document."""
    findings = []

    for finding in scan.get("findings", []):
        confirmed = finding.get("status") == "confirmed"
        if not confirmed and not include_suppressed:
            continue

        validation = finding.get("validation", {})
        poc = finding.get("poc", {})
        fix = finding.get("suggested_fix", {})

        description = [
            finding.get("why_dangerous", ""),
            "",
            f"Detected by     : {finding.get('engine', 'builtin')} engine",
            f"Entry point     : {finding.get('entry', 'unknown')}",
            f"Input source    : {finding.get('source_label', 'unknown')}",
            f"Dangerous call  : {finding.get('sink')}({finding.get('sink_code', '')})",
            "",
            "Taint path:",
        ]
        for index, step in enumerate(finding.get("taint_path", []), start=1):
            description.append(f"  {index}. {finding['file']}:{step['line']} - "
                               f"{step['description']}")
            description.append(f"     {step['code']}")

        if validation:
            description += [
                "",
                f"Validated by : {validation.get('validator', 'unknown')} "
                f"({validation.get('model', '')})",
                f"Confidence   : {validation.get('confidence', 0)}",
                f"Reasoning    : {validation.get('reasoning', '')}",
            ]
        if not confirmed:
            description += ["", f"SUPPRESSED: {finding.get('suppression_reason', '')}"]

        steps = poc.get("command", "")
        if poc.get("expected"):
            steps = f"{steps}\n\nExpected result: {poc['expected']}"

        mitigation = fix.get("guidance", "")
        if fix.get("replacement"):
            mitigation = f"{mitigation}\n\nSuggested change:\n    {fix['replacement']}"
            if fix.get("import_needed"):
                mitigation += f"\n    (requires: {fix['import_needed']})"

        findings.append({
            "title": f"{finding.get('title')} in {finding.get('file')}:{finding.get('line')}",
            "description": "\n".join(description).strip(),
            "severity": SEVERITY_MAP.get(str(finding.get("severity", "medium")).lower(), "Medium"),
            "date": (scan.get("started_at") or time.strftime("%Y-%m-%d"))[:10],
            "cwe": _cwe_number(finding.get("cwe", "")),
            "file_path": finding.get("file"),
            "line": finding.get("line"),
            "mitigation": mitigation,
            "steps_to_reproduce": steps,
            "impact": finding.get("why_dangerous", ""),
            "references": finding.get("owasp", ""),
            "active": confirmed,
            "verified": confirmed,
            "false_p": not confirmed,
            # NOTE: no "duplicate" key. The Generic Findings Import schema
            # rejects it outright ("Not allowed fields are present"), because
            # DefectDojo decides duplication itself via engagement dedup.
            # Our own cluster information travels as a tag instead.
            "unique_id_from_tool": finding.get("id"),
            "vuln_id_from_tool": finding.get("fingerprint", finding.get("id")),
            "tags": _tags(finding, scan),
        })

    return {"findings": findings}


def _cwe_number(cwe: str) -> int:
    digits = "".join(c for c in cwe if c.isdigit())
    return int(digits) if digits else 0


def _tags(finding: dict[str, Any], scan: dict[str, Any]) -> list[str]:
    tags = [
        "sast-engine",
        f"repo:{scan.get('repo', 'unknown')}",
        f"category:{finding.get('category')}",
        f"validator:{finding.get('validation', {}).get('validator', 'none')}",
        f"engine:{finding.get('engine', 'builtin')}",
        f"language:{finding.get('language', 'unknown')}",
    ]
    if finding.get("cluster_size", 1) > 1:
        tags.append(f"cluster:{str(finding.get('fingerprint', ''))[:8]}")
    if finding.get("sla", {}).get("breached"):
        tags.append("sla-breached")
    return tags


# --------------------------------------------------------------------------
# The offline path: write the file
# --------------------------------------------------------------------------


def export(scan: dict[str, Any], include_suppressed: bool = False,
           output_path: str | Path | None = None) -> dict[str, Any]:
    """Write the import file to disk. Works with no server."""
    config.ensure_dirs()
    document = to_defectdojo(scan, include_suppressed=include_suppressed)

    path = Path(output_path) if output_path else (
        config.EXPORTS_DIR / f"defectdojo-{scan.get('id', 'scan')}.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2))

    return {
        "path": str(path),
        "findings_exported": len(document["findings"]),
        "scan_type": SCAN_TYPE,
        "how_to_import": ("In DefectDojo: Product -> Engagement -> Import Scan Results, "
                          f"choose scan type '{SCAN_TYPE}', and upload this file."),
    }


# --------------------------------------------------------------------------
# The live path: push to the API
# --------------------------------------------------------------------------


def _multipart(fields: dict[str, str], file_field: str, filename: str,
               file_bytes: bytes) -> tuple[bytes, str]:
    """Build a multipart/form-data body. The import-scan endpoint needs one."""
    boundary = f"----sast-engine-{int(time.time() * 1000)}"
    parts: list[bytes] = []
    for key, value in fields.items():
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n"
            f"{value}\r\n".encode())
    parts.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; "
        f"filename=\"{filename}\"\r\nContent-Type: application/json\r\n\r\n".encode())
    parts.append(file_bytes)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def push(scan: dict[str, Any],
         base_url: str | None = None,
         product_name: str = DEFAULT_PRODUCT,
         engagement_name: str | None = None,
         include_suppressed: bool = False,
         close_old: bool = False) -> dict[str, Any]:
    """Push a scan into a live DefectDojo: product, engagement, import, verify.

    Idempotent on the product and the engagement. Each push adds a new test
    to the same engagement, which is what gives you a history per repository.
    """
    base_url = (base_url or get_base_url()).rstrip("/")

    if not api_token():
        return {"ok": False, "stage": "auth",
                "error": f"no API token. Set {TOKEN_ENV} or write one to {TOKEN_FILE}."}

    status = health(base_url)
    if not status.get("authenticated"):
        return {"ok": False, "stage": "auth", "error": status.get("error", "not authenticated")}

    repo = scan.get("repo", "unknown")
    engagement_name = engagement_name or f"{repo} (SAST engine)"

    product = find_or_create_product(base_url, product_name)
    if not product["ok"]:
        return {"ok": False, "stage": "product", "error": product["error"]}

    engagement = find_or_create_engagement(base_url, product["id"], engagement_name)
    if not engagement["ok"]:
        return {"ok": False, "stage": "engagement", "error": engagement["error"]}

    document = to_defectdojo(scan, include_suppressed=include_suppressed)
    if not document["findings"]:
        return {"ok": True, "stage": "import", "imported": 0,
                "note": "nothing to import -- the scan produced no confirmed findings",
                "product_id": product["id"], "engagement_id": engagement["id"]}

    body, content_type = _multipart(
        fields={
            "scan_type": SCAN_TYPE,
            "engagement": str(engagement["id"]),
            "active": "true",
            "verified": "true",
            "close_old_findings": "true" if close_old else "false",
            "scan_date": (scan.get("started_at") or time.strftime("%Y-%m-%d"))[:10],
            "test_title": f"{repo} - {scan.get('id', '')}",
            "deduplication_on_engagement": "true",
        },
        file_field="file",
        filename=f"sast-engine-{scan.get('id', 'scan')}.json",
        file_bytes=json.dumps(document).encode(),
    )

    imported = _request(f"{base_url}/api/v2/import-scan/", method="POST",
                        raw_body=body, content_type=content_type)
    if not imported["ok"]:
        return {"ok": False, "stage": "import", "error": imported["error"],
                "product_id": product["id"], "engagement_id": engagement["id"]}

    test_id = imported["data"].get("test") or imported["data"].get("test_id")

    # Read the findings back. An import that reports success but stored
    # nothing is a failure we would otherwise never notice.
    verified = _request(f"{base_url}/api/v2/findings/?test={test_id}&limit=1")
    stored = verified["data"].get("count", 0) if verified["ok"] else 0

    return {
        "ok": True,
        "stage": "done",
        "url": base_url,
        "product_id": product["id"],
        "product_created": product["created"],
        "engagement_id": engagement["id"],
        "engagement_created": engagement["created"],
        "test_id": test_id,
        "submitted": len(document["findings"]),
        "stored": stored,
        "product_url": f"{base_url}/product/{product['id']}",
        "engagement_url": f"{base_url}/engagement/{engagement['id']}",
        "test_url": f"{base_url}/test/{test_id}" if test_id else "",
    }


def findings_in_defectdojo(base_url: str = DEFAULT_URL, test_id: int | None = None,
                           limit: int = 50) -> dict[str, Any]:
    """Read findings back out of DefectDojo -- used to verify a push landed."""
    query = {"limit": limit}
    if test_id is not None:
        query["test"] = test_id
    result = _request(f"{base_url.rstrip('/')}/api/v2/findings/?"
                      f"{urllib.parse.urlencode(query)}")
    if not result["ok"]:
        return {"ok": False, "error": result["error"]}
    return {
        "ok": True,
        "count": result["data"].get("count", 0),
        "findings": [
            {"id": f["id"], "title": f["title"], "severity": f["severity"],
             "cwe": f.get("cwe"), "file_path": f.get("file_path"),
             "line": f.get("line"), "active": f.get("active"),
             "false_p": f.get("false_p")}
            for f in result["data"].get("results", [])
        ],
    }
