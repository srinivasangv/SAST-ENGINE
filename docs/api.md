# API Reference

Base URL `http://127.0.0.1:8000`. Everything is JSON in, JSON out. CORS is
open, so the dashboard on `:5173` can call it directly.

Start it with `.venv/bin/python server.py`.

---

## Health

### `GET /api/health`

```json
{
  "status": "ok",
  "llm_configured": true,
  "llm_provider": "anthropic",
  "llm_model": "claude-opus-5",
  "llm_last_used": "offline",
  "scans_stored": 3,
  "engines": {"builtin": true, "joern": true, "joern_version": "installed", "joern_error": ""},
  "semgrep_available": true,
  "defectdojo": {"url": "http://localhost:8083", "configured": true,
                 "reachable": true, "authenticated": true, "error": ""}
}
```

Three separate facts about the LLM, and they are not interchangeable:

| Field | Means | Does **not** mean |
|---|---|---|
| `llm_configured` | some provider key is present in the environment | the key works |
| `llm_provider` | which one would be tried: `anthropic`, `openai` or `offline` | which one answered |
| `llm_last_used` | which validator actually produced the verdicts on the most recent scan | — |

The payload above is the real state of this machine: a key is configured, the
provider would be Anthropic, and the last scan was nevertheless validated
`offline` because that key returns HTTP 401. Read `llm_last_used` when you
want to know what really happened; it is `null` until something has been
scanned. The specific failure is recorded as `fallback_reason` on each verdict.

`defectdojo.url` follows `DEFECTDOJO_URL`, which is `http://localhost:8080` by
default — it is shown here on `:8083` because that is where this instance is
published.

---

## Scans

### `GET /api/scans`

Every stored scan, newest first, plus any scan currently running.

```json
{
  "scans": [
    {
      "id": "20260813-155702-056ac1",
      "repo": "vuln-flask",
      "repo_path": "/abs/path/testdata/vuln-flask",
      "started_at": "2026-08-13T15:57:02",
      "duration_ms": 7495,
      "raw_findings": 17,
      "confirmed": 11,
      "suppressed": 6,
      "validator": "offline"
    }
  ],
  "running": []
}
```

### `POST /api/scans`

Starts a scan in a background thread and returns immediately.

```json
{ "repo_path": "testdata/vuln-flask", "use_llm": null, "with_baseline": true }
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `repo_path` | string | **required** | Path to scan. Relative to where `server.py` runs. |
| `use_llm` | bool or null | `null` | `null` = use Claude if a key is set. `false` = force offline. `true` = require Claude. |
| `engine` | string | `"builtin"` | `builtin`, `joern`, or `both`. Joern adds ~15 seconds. |
| `with_baseline` | bool | `true` | Run the Joern baseline comparison. |
| `with_semgrep` | bool | `false` | Also measure Semgrep as a secondary baseline. |
| `push_to_defectdojo` | bool | `false` | Push confirmed findings to a live DefectDojo when the scan finishes. |

**202 Accepted**

```json
{ "job_id": "20260813-154615-f17f26", "state": "queued",
  "poll": "/api/scans/status/20260813-154615-f17f26" }
```

**400** if `repo_path` is missing.

Only one scan runs at a time; a second request queues rather than competing
for CPU.

### `GET /api/scans/status/<job_id>`

```json
{
  "job_id": "20260813-154615-f17f26",
  "repo_path": "testdata/vuln-flask",
  "state": "running",
  "stage": "validate",
  "message": "judging exploitability"
}
```

`state` is `queued` → `running` → `done` | `error`. When `done`, the response
also carries `scan_id`.

### `GET /api/scans/<scan_id>`

The complete scan document — the same thing stored in
`data/scans/<scan_id>.json`.

```json
{
  "id": "...", "repo": "...", "repo_path": "...", "started_at": "...", "duration_ms": 7495,
  "stages": {
    "prepare": {"files": 1, "nodes": 115, "edges": 169, "functions": 19,
                "routes": 16, "languages": {"python": 1}, "duration_ms": 15},
    "scan":    {"duration_ms": 2, "raw_findings": 17},
    "validate":{"raw_findings": 17, "confirmed": 11, "suppressed": 6,
                "suppression_rate": 0.3529, "validators_used": {"offline": 17}},
    "prove":   {"duration_ms": 1, "proofs": 11}
  },
  "summary": {"raw_findings": 17, "confirmed": 11, "suppressed": 6,
              "suppression_rate": 0.3529, "validator": "offline",
              "by_severity": {...}, "by_category": {...}, "sla_breached": 0},
  "cpg": {"stats": {...}, "nodes": [...], "edges": [...]},
  "findings": [ ... ],
  "dedupe": {"clusters": [...], "summary": {...}},
  "comparison": { ... },
  "parse_errors": []
}
```

**404** if there is no such scan.

### `DELETE /api/scans/<scan_id>`

```json
{ "deleted": true }
```

---

## Findings

### `GET /api/findings`

| Query parameter | Values |
|---|---|
| `status` | `confirmed`, `suppressed`, or omit for everything |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `repo` | a repository name |

```
GET /api/findings?status=confirmed&severity=critical
```

```json
{ "findings": [ ... ], "count": 7 }
```

### `GET /api/findings/<finding_id>`

```json
{
  "finding": {
    "id": "db191244e7b5",
    "repo": "vuln-flask",
    "category": "command_injection",
    "title": "OS Command Injection",
    "cwe": "CWE-78",
    "owasp": "A03:2021 Injection",
    "severity": "critical",
    "why_dangerous": "The value is passed to a shell, so shell metacharacters run as commands.",

    "file": "app.py", "line": 39, "function": "ping",
    "sink": "os.system", "sink_code": "os.system(\"ping -c 1 \" + host)",
    "language": "python",

    "entry": "HTTP route GET /ping -> ping()",
    "http_reachable": true,
    "route_path": "/ping", "route_methods": ["GET"],
    "source_label": "HTTP query string", "source_pattern": "request.args",

    "sanitizers": [], "sanitizer_covers_sink": false,
    "guarded": false, "unreachable": false,

    "taint_path": [
      {"file": "app.py", "line": 38, "code": "host = request.args.get(\"host\")",
       "description": "attacker input enters via HTTP query string (`request.args`)"},
      {"file": "app.py", "line": 38, "code": "host = request.args.get(\"host\")",
       "description": "value flows into `host`"},
      {"file": "app.py", "line": 39, "code": "os.system(\"ping -c 1 \" + host)",
       "description": "reaches the dangerous call `os.system()`"}
    ],

    "validation": {
      "exploitable": true, "confidence": 0.9, "severity": "critical",
      "reasoning": "Attacker-controlled HTTP query string reaches os.system() with no validation or sanitisation on the path.",
      "attack_scenario": "Send a request to /ping with a payload such as `; id`. ...",
      "validator": "offline", "model": "rule-based fallback",
      "fallback_reason": "ANTHROPIC_API_KEY is not set"
    },

    "status": "confirmed",

    "poc": {
      "reachable": true, "kind": "http", "method": "GET",
      "url": "http://localhost:5001/ping", "parameter": "host", "payload": "; id",
      "command": "curl -G http://localhost:5001/ping --data-urlencode 'host=; id'",
      "expected": "The output of `id` appears in the response or the server logs."
    },

    "suggested_fix": {
      "file": "app.py", "line": 39,
      "current": "os.system(\"ping -c 1 \" + host)",
      "import_needed": "import shlex",
      "replacement": "os.system(\"...\" + shlex.quote(host))",
      "explanation": "or better: subprocess.run([\"cmd\", host], shell=False)",
      "auto_applicable": false
    },
    "fix_status": "pending_approval",

    "fingerprint": "a1b2c3d4e5f60718", "cluster_size": 3,
    "cluster_repos": ["vuln-express", "vuln-flask"],

    "opened_at": "2026-08-13T15:57:02",
    "sla": {"state": "on_track", "age_hours": 0.1, "budget_hours": 24,
            "hours_remaining": 23.9, "breached": false, "escalate_to": ""}
  },
  "scan_id": "20260813-155702-056ac1",
  "repo": "vuln-flask"
}
```

A **suppressed** finding has `status: "suppressed"` and `suppression_reason`,
and carries no `poc` or `suggested_fix`.

---

## The approval gate

The three endpoints below enforce this, in this order:

```
pending_approval ──approve──► approved ──apply──► applied
                 ──reject───► rejected
```

### `POST /api/findings/<finding_id>/approve`

```json
{ "actor": "security-lead", "note": "reviewed the taint path by hand" }
```

```json
{ "ok": true, "finding": { ..., "fix_status": "approved" } }
```

### `POST /api/findings/<finding_id>/reject`

```json
{ "actor": "alice", "reason": "this endpoint is internal only" }
```

**400** if `reason` is empty — a rejection without a reason is not a decision.

### `POST /api/findings/<finding_id>/apply`

```json
{ "actor": "security-lead" }
```

**400 before approval** — this is the gate:

```json
{ "ok": false,
  "error": "the fix has not been approved by a human yet (status is 'pending_approval'). Approve it first." }
```

**200 after approval**, returning a patch rather than editing the file:

```json
{
  "ok": true,
  "patch": "+   import shlex\n--- app.py:39 (current)\n-   os.system(\"ping -c 1 \" + host)\n+++ app.py:39 (suggested)\n+   os.system(\"...\" + shlex.quote(host))\n",
  "note": "The engine never edits source files on its own. Apply this patch, run your tests, and re-scan to confirm the finding is gone."
}
```

### `GET /api/approvals`

```json
{
  "pending_approval": [ ... ], "approved": [ ... ],
  "rejected": [ ... ], "applied": [ ... ],
  "counts": {"pending_approval": 10, "approved": 0, "rejected": 0, "applied": 1}
}
```

---

## SLA

### `GET /api/sla`

```json
{
  "policy_hours": {"critical": 24, "high": 72, "medium": 168, "low": 720},
  "escalation_targets": {"critical": "security-lead + engineering-manager", "...": "..."},
  "findings": [
    {"finding_id": "db191244e7b5", "severity": "critical", "state": "on_track",
     "age_hours": 0.1, "budget_hours": 24, "hours_remaining": 23.9,
     "overdue_by_hours": 0.0, "breached": false, "escalate_to": "",
     "repo": "vuln-flask", "title": "OS Command Injection",
     "file": "app.py", "line": 39, "fix_status": "pending_approval"}
  ],
  "counts": {"on_track": 10, "resolved": 1},
  "breached": 0,
  "escalations": [],
  "generated_at": "2026-08-13T15:57:10"
}
```

`state` is `on_track`, `at_risk` (inside the last quarter of the budget),
`breached`, or `resolved` (the fix was applied, which stops the clock).

---

## Deduplication

### `GET /api/dedupe`

Clusters across **every** stored scan — this is the cross-repo view.

```json
{
  "clusters": [
    {
      "fingerprint": "a1b2c3d4e5f60718",
      "category": "command_injection", "cwe": "CWE-78",
      "title": "OS Command Injection", "severity": "critical",
      "count": 3, "repos": ["vuln-express", "vuln-flask"],
      "cross_repo": true, "shape": "1(0+1)",
      "locations": [
        {"repo": "vuln-flask", "file": "app.py", "line": 39, "id": "db19...", "language": "python"},
        {"repo": "vuln-express", "file": "server.js", "line": 32, "id": "7f2a...", "language": "javascript"}
      ]
    }
  ],
  "summary": {
    "findings_before": 17, "clusters_after": 10, "duplicates_removed": 7,
    "reduction_rate": 0.4118, "cross_repo_clusters": 5
  }
}
```

---

## Comparison

### `GET /api/comparison`

Every scan that has a Semgrep comparison attached.

```json
{
  "comparisons": [{
    "scan_id": "...", "repo": "vuln-flask",
    "semgrep": {"available": true, "rules_config": "p/security-audit",
                "total_findings": 12,
                "score": {"true_positives": 10, "false_positives": 2,
                          "false_negatives": 4, "precision": 0.8333, "recall": 0.7143}},
    "stage2_pattern_matching": {"total_findings": 17,
                "score": {"true_positives": 11, "false_positives": 6,
                          "false_negatives": 0, "precision": 0.6471, "recall": 1.0}},
    "stage3_after_validation": {"total_findings": 11,
                "score": {"true_positives": 11, "false_positives": 0,
                          "false_negatives": 0, "precision": 1.0, "recall": 1.0}},
    "suppression": {"raw_findings": 17, "confirmed_findings": 11, "suppressed": 6,
                    "suppression_rate": 0.3529,
                    "false_positives_before": 6, "false_positives_after": 0,
                    "false_positives_removed": 6, "fp_suppression_rate": 1.0,
                    "precision_gain": 0.3529, "recall_change": 0.0},
    "overlap": {"both_tools": 5, "only_ours": 3, "only_semgrep": 0}
  }]
}
```

---

## DefectDojo (live)

### `GET /api/defectdojo`

Is DefectDojo reachable, and what is already in it?

```json
{
  "url": "http://localhost:8080",
  "configured": true, "reachable": true, "authenticated": true,
  "findings_in_defectdojo": 17,
  "recent": [
    {"id": 1, "title": "OS Command Injection in app.py:39", "severity": "Critical",
     "cwe": 78, "file_path": "app.py", "line": 39, "active": true, "false_p": false}
  ]
}
```

### `POST /api/defectdojo/push`

Creates the product and the engagement if they are missing, imports the scan
as a new test, then reads the findings back to confirm what landed.

```json
{ "scan_id": "20260813-164823-cf1a67", "include_suppressed": false }
```

```json
{
  "ok": true, "stage": "done", "url": "http://localhost:8080",
  "product_id": 1, "product_created": false,
  "engagement_id": 1, "engagement_created": false,
  "test_id": 7, "submitted": 11, "stored": 11,
  "product_url": "http://localhost:8080/product/1",
  "engagement_url": "http://localhost:8080/engagement/1",
  "test_url": "http://localhost:8080/test/7"
}
```

`submitted` against `stored` is the check that matters — an import that
returns 200 and stores nothing is a failure you would otherwise never notice.

**400** with `stage: "auth"` when no token is configured, `stage: "product"`
or `"engagement"` when those calls fail, `stage: "import"` when DefectDojo
rejects the document.

---

## Export (offline)

### `POST /api/export/defectdojo`

```json
{ "scan_id": "20260813-155702-056ac1", "include_suppressed": false }
```

```json
{
  "path": "/abs/path/data/exports/defectdojo-20260813-155702-056ac1.json",
  "findings_exported": 11,
  "scan_type": "Generic Findings Import",
  "how_to_import": "In DefectDojo: Product -> Engagement -> Import Scan Results, choose scan type 'Generic Findings Import', and upload this file."
}
```

With `include_suppressed: true`, suppressed findings are exported too, flagged
`false_p: true`, so a reviewer can audit what the engine dismissed.

---

## Errors

| Status | When |
|---|---|
| 400 | Bad input — missing `repo_path`, empty rejection reason, unapproved apply, malformed JSON body. |
| 404 | No such scan, finding, job, or route. A 404 on an unknown route also lists the available routes. |
| 500 | An unhandled exception. The traceback goes to the server's stdout. |

```json
{ "error": "the fix has not been approved by a human yet ..." }
```
