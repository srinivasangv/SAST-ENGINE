# Module Split — 7 Members

Each member owns a set of files nobody else edits. The interfaces between
modules are frozen on Day 1 morning, which is what lets seven people work in
parallel without waiting for each other.

---

## Ownership

| # | Module | Owns these files | Delivers |
|---|---|---|---|
| **M1** | **Prepare / CPG** | `engine/cpg.py`, `engine/py_parser.py`, `engine/stage1_prepare.py`, `engine/joern_engine.py` | A Code Property Graph built from any Python repository with no build step, plus the Joern integration |
| **M2** | **Scan / Taint engine** | `engine/rules.py`, `engine/stage2_scan.py` | Taint paths for 10 vulnerability classes, with sanitizer / guard / reachability metadata |
| **M3** | **Validate / LLM agent** | `engine/llm.py`, `engine/stage3_validate.py` | Exploitability verdicts from Claude, plus the deterministic offline fallback |
| **M4** | **Dedupe + Baseline** | `engine/dedupe.py`, `engine/baseline.py` | Cross-repo clustering and the measured comparison against Joern (primary) and Semgrep (secondary) |
| **M5** | **Prove + Integrations** | `engine/stage4_prove.py`, `engine/defectdojo.py`, `engine/js_parser.py` | A PoC and a fix per finding, the live DefectDojo API client, JavaScript support |
| **M6** | **API + Workflow** | `server.py`, `scan.py`, `engine/pipeline.py`, `engine/store.py`, `engine/approvals.py`, `engine/sla.py`, `engine/config.py` | The CLI, the HTTP API, the approval gate, the SLA engine |
| **M7** | **UI + QA + Docs** | `ui/`, `tests/`, `docs/`, `testdata/`, the deck | The dashboard, 129 tests, the documentation set, the presentation |

### Why the split is shaped this way

- **One stage per member for the four pipeline stages** (M1, M2, M3, M5) —
  each is a self-contained transformation with a written input and output.
- **M4 gets the two "measurement" modules**, because dedupe and the baseline
  comparison are the two things that produce numbers for the deck. One person
  owning both keeps the metrics consistent.
- **M5 takes the JS parser** as well as Prove, because Prove is small and JS
  support is the biggest single risk item — pairing them keeps the load even.
- **M6 owns everything that stores or serves data**, so there is exactly one
  person to ask about the on-disk format.
- **M7 owns the corpus and the ground truth** as well as the tests. The person
  writing the oracle must not be the person writing the engine — otherwise the
  test is written to match the bug.

---

## Frozen interfaces

These four contracts are agreed on Day 1 and do not change without all seven
people in the room. Everyone codes against them, using stubs until the real
implementation lands.

### 1. M1 → M2: the IR (`engine/cpg.py`)

```python
Function(name, file, line, end_line, lang, params, body, route_path, route_methods, node_id)
Stmt(kind, line, code, targets, value, test, body, orelse, always_false)
    kind ∈ "assign" | "expr" | "return" | "if" | "loop" | "try"
Expr(code, vars, sources, calls, only_literal)
Call(name, line, code, args, kwargs)
```

`name` on a `Call` is the dotted name exactly as written in the source
(`os.system`, `cursor.execute`, `child_process.exec`). `rules.py` matches
against that string.

### 2. M2 → M3 → M4 → M5: the finding dictionary

Stage 2 produces every key below. Later stages **add** keys and never remove
any.

```python
{
  "id": "db191244e7b5",           # stable across re-scans of unchanged code
  "repo", "category", "title", "cwe", "owasp", "severity", "why_dangerous",
  "file", "line", "function", "sink", "sink_code", "language",
  "entry", "http_reachable", "route_path", "route_methods",
  "source_label", "source_pattern",
  "sanitizers": [...], "sanitizer_covers_sink": bool,
  "guarded": bool, "unreachable": bool,
  "taint_path": [{"file", "line", "code", "description"}, ...],
  "snippet", "stage", "status": "unvalidated",
}
# Stage 3 adds:  validation{}, status -> confirmed|suppressed, suppression_reason
# Stage 4 adds:  poc{}, suggested_fix{}, fix_status
# M4 adds:       fingerprint, cluster_size, cluster_repos
# M6 adds:       opened_at, sla{}, approval_*
```

**The `id` must be stable.** It is a hash of repo + file + line + sink +
category. If it changed between runs, every approval recorded against a
finding would be lost on the next scan. `test_finding_ids_are_unique_and_stable`
guards this.

### 3. Pipeline → M6: the scan result file

```python
{
  "id", "repo", "repo_path", "started_at", "duration_ms",
  "stages": {"prepare": {...}, "scan": {...}, "validate": {...}, "prove": {...}},
  "summary": {"raw_findings", "confirmed", "suppressed", "suppression_rate",
              "validator", "by_severity", "by_category", "sla_breached"},
  "cpg": {"stats", "nodes", "edges"},
  "findings": [...],
  "dedupe": {"clusters": [...], "summary": {...}},
  "comparison": {...} | None,
  "parse_errors": [...],
}
```

Written to `data/scans/<id>.json`. This is exactly what `GET /api/scans/<id>`
returns — one shape to learn, not two.

### 4. M6 → M7: the HTTP API

Eighteen endpoints, documented in [api.md](api.md). M6 served hard-coded
fixture JSON from Day 1 so M7 could build screens before the pipeline existed.

---

## Working in parallel

```
Day 1 morning: all seven agree the four contracts above, commit docs/modules.md

M1 ─ parser ────────┐
M2 ─ rules.py ──────┼─► these three only need the IR, which is frozen
M3 ─ llm.py ────────┘

M4 ─ needs findings ──► works against a hand-written sample finding until Day 2
M5 ─ needs findings ──► same
M6 ─ needs nothing ───► serves fixtures from Day 1
M7 ─ needs the API ───► builds against M6's fixtures from Day 1
```

Nobody is blocked on anybody after the Day 1 contract meeting.

---

## Rules of engagement

1. **Do not edit another member's files.** If you need a change there, ask the
   owner. Two people editing `stage2_scan.py` on Day 3 is how a hackathon
   loses an afternoon to a merge conflict.
2. **Adding a key to the finding dictionary is free. Renaming or removing one
   is a group decision.** Everything downstream reads those keys.
3. **`rules.py` is data.** Adding a sink is a one-line change and needs no
   engine change. If you find yourself editing `stage2_scan.py` to add a
   vulnerability class, stop — it belongs in the table.
4. **Every module lands with its tests.** M7 owns the suite, but the module
   owner writes the first tests for their own module.
5. **Push at least twice a day.** A branch nobody has seen for eight hours is
   a merge conflict waiting for Day 4.

---

## If a member is blocked

| Blocked on | Do this instead |
|---|---|
| M1's parser is not ready | Hand-write a `Function` object in a test and code against it. |
| M2's findings are not ready | Use the sample finding in `tests/test_units.py::_finding`. |
| M3's LLM is not ready | Call `llm.offline_verdict()` — same shape, no key needed. |
| M6's API is not ready | `curl` the JSON file in `data/scans/` directly. |
| Semgrep will not install | Scan with `--no-baseline`; the comparison degrades gracefully. |
| No API key | Everything works offline. This is a designed-in path, not a workaround. |
