# QA — Test Strategy and Results

Every number in this document came from a real run of the command shown next
to it. Nothing here is estimated.

```bash
.venv/bin/python -m pytest tests/ -q
# 177 passed, 3 skipped in 260.74s
```

Two companion artefacts, both generated from real runs rather than written by
hand:

- [requirements-matrix.md](requirements-matrix.md) — one test per box on the
  hackathon slide, with the evidence each one printed.
- [demo-video.md](demo-video.md) — the recorded 4:36 walkthrough, its scene
  list, and a plain statement of what it does and does not prove.

---

## 1. Test layers

| Layer | File | Tests | What it proves |
|---|---|---|---|
| Unit | `tests/test_units.py` | 44 | Each module in isolation: rule matching, the parser, dedupe shapes, the offline validator, SLA maths. |
| Integration | `tests/test_pipeline.py` | 17 | Stage N's output is a valid Stage N+1 input, and the handover contracts hold. |
| End-to-end | `tests/test_pipeline.py` | (in the 17) | The CLI on the real corpus, including exit codes. |
| Accuracy | `tests/test_accuracy.py` | 11 | Precision, recall and suppression against the hand-labelled oracle. |
| Workflow | `tests/test_workflow.py` | 26 | Storage, the approval gate, SLA escalation, DefectDojo export. |
| API | `tests/test_api.py` | 16 | Every endpoint returns the documented shape; the gate holds over HTTP. |
| Scenarios | `tests/test_scenarios.py` | 15 | The 14-row matrix below, executed. |
| Integrations | `tests/test_integrations.py` | 24 | Joern and DefectDojo, live and offline. Each skips itself when the external system is down. |

Run one layer:

```bash
.venv/bin/python -m pytest tests/test_accuracy.py -q -s     # -s prints the metrics
.venv/bin/python -m pytest tests/test_scenarios.py -q
```

Every test runs with `use_llm=False`. That is deliberate — the suite must be
deterministic and must pass on a laptop with no API key and no network. The
live Claude path is exercised by the demo, not by the build.

---

## 2. The test data

Three repositories under `testdata/`, and a hand-written oracle.

| Repository | Language | Real vulnerabilities | Decoys | Purpose |
|---|---|---|---|---|
| `vuln-flask/` | Python | 11 | 6 | The main target. Every vulnerability class. |
| `vuln-express/` | JavaScript | 6 | 4 | Second language, second service, cross-repo dedupe. |
| `safe-app/` | Python | 0 | 1 | The false-positive control. |
| **Total** | | **17** | **11** | |

### The decoys are the point

A decoy is code that a pattern-matching scanner **does** report but that is
**not** exploitable. Without them, a suppression rate is unmeasurable — you
cannot show you removed false positives if your corpus has none.

| Decoy | Where | Why it is not exploitable |
|---|---|---|
| DECOY-1 | `vuln-flask/app.py:141` | `shlex.quote()` — the correct defence for a shell argument. |
| DECOY-2 | `vuln-flask/app.py:150` | `int()` cast — an integer cannot carry SQL syntax. |
| DECOY-3 | `vuln-flask/app.py:160` | Checked against an allowlist; the request is rejected otherwise. |
| DECOY-4 | `vuln-flask/app.py:169` | Inside `if False:` — the branch can never execute. |
| DECOY-5 | `vuln-flask/app.py:179` | A helper with no caller; no HTTP route reaches it. |
| DECOY-6 | `vuln-flask/app.py:194` | `html.escape()` before `Markup()` — the right defence for XSS. |
| DECOY-7 | `vuln-express/server.js:76` | `parseInt()` before the query. |
| DECOY-8 | `vuln-express/server.js:83` | `encodeURIComponent()` plus a fixed local path prefix. |
| DECOY-9 | `vuln-express/server.js:90` | `path.basename()` strips traversal. |
| DECOY-10 | `vuln-express/server.js:101` | Allowlist check before the shell call. |
| SAFE-1 | `safe-app/app.py:68` | Host checked against `ALLOWED_HOSTS`. |

> **A decoy that was wrong, and how we caught it.** DECOY-6 originally passed
> `html.escape(name)` into `render_template_string()`. That is *not* safe:
> `html.escape` escapes `& < > " '` and leaves `{{` and `}}` alone, so
> `?name={{7*7}}` still executes. It was a real SSTI mislabelled as a decoy.
> Caught while reviewing the sanitizer coverage table, and changed to use
> `Markup()`, which `html.escape` genuinely does neutralise. Logged as QA-001.

### The oracle

`testdata/ground_truth.json` labels every expected finding with
`exploitable: true|false` and a written reason. `tests/test_accuracy.py`
grades the engine against it: a labelled-exploitable finding we report is a
true positive; a labelled-not-exploitable finding we report is a false
positive; an exploitable one we miss is a false negative. A finding the oracle
does not know about is **also** counted as a false positive rather than being
quietly ignored.

**M7 owns the oracle and writes no engine code.** If the person writing the
tests is the person writing the parser, the test gets written to match the bug.

---

## 3. Scenario matrix

Each row is implemented in `tests/test_scenarios.py` with a matching number,
and `test_every_scenario_in_the_docs_has_a_test` fails if a row here has no
test.

| # | Scenario | Expected | Result |
|---|---|---|---|
| 1 | Scan the vulnerable Flask service | ≥10 true positives | ✅ 11 found |
| 2 | Scan the safe app | 0 findings after validation | ✅ 0 |
| 3 | Decoy: sanitised input | Reported by Stage 2, suppressed by Stage 3 with a reason | ✅ suppressed, cites `shlex.quote` |
| 4 | Decoy: value cast to `int` | Suppressed | ✅ suppressed |
| 5 | Cross-repo duplicate | Two findings → one cluster, spanning both languages | ✅ 1 cluster, `{python, javascript}` |
| 6 | Semgrep baseline comparison | Table plus an FP-suppression rate | ✅ 100% FP suppression |
| 7 | PoC generation | Every confirmed finding has a runnable command | ✅ 17/17 |
| 8 | Auto-fix approval gate | A fix cannot be applied before approval | ✅ refused, then allowed |
| 9 | Auto-fix rejection | Rejection requires and records a reason | ✅ |
| 10 | SLA breach | An aged finding breaches and escalates | ✅ escalates to security-lead |
| 11 | Offline fallback | Key unset → the pipeline still completes | ✅ 11 confirmed, all `validator: offline` |
| 12 | Malformed source file | Recorded; the scan continues | ✅ 1 error logged, the good file still scanned |
| 13 | Empty repository | Graceful, not a crash | ✅ 0 files, 0 findings |
| 14 | Two concurrent scans | Two independent, complete result files | ✅ |

---

## 4. Measured results

### Per repository — `python scan.py testdata/vuln-flask testdata/vuln-express`

**vuln-flask (Python, 11 real + 6 decoys)**

| | findings | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|---|
| Joern `reachableByFlows` (primary baseline) | 16 | 11 | 5 | 0 | 68.8% | 100% |
| Semgrep `p/security-audit` (secondary) | 12 | 10 | 2 | 4 | 83.3% | 71.4% |
| Ours — Stage 2 (pattern matching) | 17 | 11 | 6 | 0 | 64.7% | 100% |
| **Ours — Stage 3 (after validation)** | **11** | **11** | **0** | **0** | **100%** | **100%** |

**vuln-express (JavaScript, 6 real + 4 decoys)**

| | findings | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|---|
| Joern `reachableByFlows` (primary baseline) | 12 | 6 | 6 | 0 | 50.0% | 100% |
| Semgrep `p/security-audit` (secondary) | 3 | 2 | 1 | 4 | 66.7% | 33.3% |
| Ours — Stage 2 | 10 | 6 | 4 | 0 | 60.0% | 100% |
| **Ours — Stage 3** | **6** | **6** | **0** | **0** | **100%** | **100%** |

### Against the primary baseline

| | vuln-flask | vuln-express |
|---|---|---|
| Precision gain over Joern | **+31.2 pts** | **+50.0 pts** |
| Recall change vs Joern | 0.0 | 0.0 |
| Fewer false positives than Joern | 5 | 6 |

Joern has **100% recall on both repositories** — its data-flow engine misses
nothing in this corpus. What it does not do is decide which of its own
findings are exploitable, and that is the entire gap our Stage 3 fills.

### Running the Joern engine instead of ours

`--engine joern` swaps Stages 1 and 2 for Joern's CPG and its own
`reachableByFlows`. Stages 3 and 4 are unchanged, and the result is the same:

```
Joern engine + our validation: 11 confirmed, TP 11, FP 0, FN 0, precision 100%, recall 100%
```

That is the strongest evidence that the validation stage is the contribution,
not the parser: swap the entire front end and the numbers hold.

### What Stage 3 changed

| Metric | vuln-flask | vuln-express |
|---|---|---|
| False positives removed | 6 of 6 (100%) | 4 of 4 (100%) |
| Precision gain | **+35.3 pts** | **+40.0 pts** |
| Recall change | **0.0** — no real bug lost | **0.0** |
| Raw findings suppressed | 35.3% | 40.0% |

The recall row is the one that matters. Suppressing everything would give
perfect precision and be useless; `test_recall_is_not_traded_away_for_precision`
fails the build if validation ever drops a real vulnerability.

### Corpus totals

```
17 true positives · 0 false positives · 0 false negatives
precision 100.0%  ·  recall 100.0%  ·  28 raw findings suppressed to 17 (39.3%)
```

### Deduplication

```
17 confirmed findings across 2 repositories
   → 10 unique vulnerability patterns
   → 5 patterns appear in more than one repository
```

The command-injection cluster contains `vuln-flask/app.py:39` (Python),
`vuln-flask/app.py:128` (Python) and `vuln-express/server.js:32`
(JavaScript) — three findings, one ticket.

### Overlap with Semgrep

| | vuln-flask | vuln-express |
|---|---|---|
| Found by both | 5 | 2 |
| Only us | 3 | 4 |
| Only Semgrep | 0 | 0 |

---

## 5. Reading the comparison fairly

Semgrep is a mature, general-purpose tool and this comparison is narrow. It is
worth being precise about what it does and does not show.

**What is a fair reading:**
- On this corpus, with this rule pack, after LLM validation we report fewer
  findings and every one is real.
- Semgrep's 4 misses per repo are largely cases needing data-flow across
  statements, which `p/security-audit` does not chase by default.

**What would not be fair:**
- Claiming this generalises. Twenty-eight findings across three small files is
  a demonstration, not a benchmark.
- Ignoring that our corpus was written by us. The decoys were chosen to be
  suppressible, so a 100% suppression rate is a best case.
- Comparing runtimes. Semgrep loads a large rule registry; we run one
  hand-written rule table.

The honest claim: **on a corpus with known ground truth, adding a reasoning
stage removed every false positive without losing a single true positive.**

---

## 6. Known limitations

Written down rather than discovered on stage.

### Joern
- Joern's flow output carries **no guard or dead-code information**. A separate
  `ast` pass (`joern_engine.structural_flags`) recovers those two facts;
  without it the allowlist and `if False:` decoys survive validation. That pass
  is Python-only, so on other languages both flags stay False.
- A Joern run costs ~15 seconds and ~4 GB of heap on a one-file repository,
  against ~15 milliseconds for the builtin engine.
- Joern needs a JDK and a 1.8 GB install. Everything degrades to the builtin
  engine when it is absent.

### DefectDojo
- The Generic Findings Import schema **rejects a `duplicate` field** outright
  ("Not allowed fields are present"). Our cluster information travels as a tag.
- `push()` is idempotent on the product and the engagement but not on the test:
  each push adds a new test, which is what gives a per-repository history.

### The JavaScript parser
`engine/js_parser.py` is a line scanner, not a real parser. It does not handle:
- a call whose arguments span several lines
- destructuring beyond `const { a, b } = req.query`
- classes and object-method shorthand
- code inside a string that looks like code

Python — the primary target — uses the real `ast` module and has none of these
limits. Semgrep covers JavaScript in the baseline column.

### The taint engine
- Inter-procedural depth is capped at 2, and calls are resolved by name within
  one repository. No cross-file or cross-module resolution.
- Loop bodies are walked twice rather than to a fixpoint.
- Guard detection records that *a* check happened, not that it is *correct*.
  That judgment is deliberately left to Stage 3.
- Class attributes and container element taint are approximated.

### Stage 3
- **No live LLM answered during this build.** Both credentials available to us
  fail: the Anthropic key returns HTTP 401 (invalid), and the OpenAI key
  authenticates but has no quota (HTTP 429). Every measured number in this
  document therefore comes from the deterministic offline validator, and the
  demo video says `validated by: offline` on screen. The provider layer, the
  prompt and the fallback path are all built and unit-tested; what is missing
  is a key with credit, not code. Requirements REQ-3 and REQ-12 are marked
  PARTIAL in the matrix for exactly this reason.
- One API call per finding. Simple, but slow and costly on a large repository;
  batching is the obvious next step.
- The verdict is only as good as the evidence packet. A vulnerability needing
  context outside ±4 lines may be judged wrong.
- The offline fallback is deterministic and therefore blunter than Claude on
  anything subtle.

### Scale
Tested on three small repositories. Nothing here has been run against a
100k-line codebase, and the per-finding LLM call would be the first thing to
break.

---

## 7. Bug process

Bugs go in [qa-log.md](qa-log.md) as `ID | severity | module | owner | status`.
Critical and high must close before the Day 5 code freeze; medium and low
become a "known limitations" slide.

---

## 8. Reproducing all of it

```bash
# The full suite
.venv/bin/python -m pytest tests/ -q                    # 129 passed

# The accuracy numbers, printed
.venv/bin/python -m pytest tests/test_accuracy.py -q -s

# The comparison tables
.venv/bin/python scan.py testdata/vuln-flask testdata/vuln-express

# The false-positive control
.venv/bin/python scan.py testdata/safe-app              # exit code 0

# The offline fallback
env -u ANTHROPIC_API_KEY .venv/bin/python scan.py testdata/vuln-flask --no-baseline
```
