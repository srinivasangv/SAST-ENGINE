# Multi-Stage Agentic SAST Engine

**Prepare → Scan → Validate → Prove**

A source-code scanner that suppresses false positives by *reasoning* about
them instead of pattern-matching harder.

The problem with a normal SAST tool is not that it misses bugs — it is that it
reports 200 findings, most of them already defended, so developers stop reading
at 20 and the real bug at number 40 ships. This engine separates **finding** a
suspicious path from **judging** whether it is exploitable, and lets a language
model do the judging with the evidence in front of it.

🎬 **Watch it instead:** [`demo/output/sast-engine-demo.mp4`](demo/output/sast-engine-demo.mp4)
— a 4:36 narrated walkthrough of all four stages, both engines, the baseline
comparison and a live DefectDojo push. Scene list, timestamps and stated
limitations in [docs/demo-video.md](docs/demo-video.md). Re-record it with
`./demo/run_demo.sh`.

---

## The measured result

On a 28-finding corpus with hand-labelled ground truth, measured against
**Joern** — a mature CPG-based analyser with its own inter-procedural
data-flow engine:

| vuln-flask | findings | true pos. | false pos. | missed | precision | recall |
|---|---|---|---|---|---|---|
| Joern `reachableByFlows` (baseline) | 16 | 11 | 5 | 0 | 68.8% | 100% |
| Semgrep `p/security-audit` (secondary) | 12 | 10 | 2 | 4 | 83.3% | 71.4% |
| Ours — Stage 2 (pattern matching) | 17 | 11 | 6 | 0 | 64.7% | 100% |
| **Ours — Stage 3 (after validation)** | **11** | **11** | **0** | **0** | **100%** | **100%** |

**vs Joern: +31.2 precision points, recall unchanged, 5 fewer false
positives.** On the JavaScript service the gap is wider — Joern scores 50.0%
precision and we reach 100%, again with no recall lost.

Joern is deliberately the primary baseline. Beating a real data-flow engine
is a harder claim than beating regular expressions.

**100% of false positives removed. Recall did not move.** That last part is
the one that matters — suppressing everything would give perfect precision and
be useless, so a test fails the build if validation ever drops a real bug.

Reproduce it: `.venv/bin/python scan.py testdata/vuln-flask`

---

## 60-second quickstart

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

.venv/bin/python scan.py testdata/vuln-flask
```

That is the whole thing. No API key needed — Stage 3 falls back to a
deterministic validator and tells you it did. No database, no Docker, no
build step.

For the dashboard, one command starts everything and tells you what it found:

```bash
./services.sh start     # API :8000, dashboard :5173, DefectDojo :8083
./services.sh status    # what is up, and what the engine says about itself
./services.sh stop
```

Or by hand, in two terminals:

```bash
.venv/bin/python server.py           # terminal 1  -> :8000
cd ui && npm install && npm run dev  # terminal 2  -> :5173
```

With Joern and a live DefectDojo:

```bash
export JAVA_HOME=~/.local/opt/jdk21
.venv/bin/python scan.py testdata/vuln-flask --engine joern --defectdojo
```

Full instructions: [docs/setup-environment.md](docs/setup-environment.md) →
[docs/setup-application.md](docs/setup-application.md).

---

## What the four stages do

| Stage | Does | Key idea |
|---|---|---|
| **1. Prepare** | Source text → Code Property Graph + a language-neutral IR | Two interchangeable engines: our stdlib-`ast` parser, or **Joern**. Neither installs, builds, or executes the target code. |
| **2. Scan** | Walks each function tracing attacker input to dangerous calls | Deliberately noisy. A sanitizer is **recorded**, not obeyed — Stage 3 decides if it fits. |
| **3. Validate** | Claude reads the taint path and judges exploitability | Suppressed ≠ deleted. Every verdict says who made it and why. |
| **4. Prove** | Generates a PoC and a suggested fix per confirmed finding | Generated, **never applied**. A human approves first. |

Plus: cross-repo deduplication, an enforced approval gate, an SLA clock, and a
**live DefectDojo integration** that creates the product and engagement and
imports findings over the API.

---

## What it looks like

```
  PREPARE   1 files, 115 CPG nodes, 19 functions
  SCAN      17 potential findings
  VALIDATE  11 confirmed, 6 suppressed
  PROVE     11 proofs generated

  CONFIRMED VULNERABILITIES
    CRITICAL  CWE-78   app.py:39  OS Command Injection
      path  line 38 attacker input enters via HTTP query string -> line 39 reaches os.system()
      PoC   curl -G http://localhost:5001/ping --data-urlencode 'host=; id'
      fix   os.system("..." + shlex.quote(host))
      dupe  same pattern across vuln-express, vuln-flask

  SUPPRESSED (reported by pattern matching, dismissed by validation)
    CWE-78   app.py:141  OS Command Injection
      why   The value passes through shlex.quote before reaching os.system(),
            which is the correct defence for os command injection.
```

---

## Repository layout

```
engine/           the four stages plus the cross-cutting modules
  cpg.py            graph + IR              (M1)
  py_parser.py      Python -> IR via ast    (M1)
  js_parser.py      JS/TS -> IR             (M5)
  joern_engine.py   Joern CPG + CPGQL taint (M1)
  stage1_prepare.py                         (M1)
  rules.py          sources/sinks/sanitizers, pure data   (M2)
  stage2_scan.py    the taint engine        (M2)
  llm.py            Claude + offline fallback             (M3)
  stage3_validate.py                        (M3)
  stage4_prove.py   PoC + fix generation    (M5)
  dedupe.py         cross-repo clustering   (M4)
  baseline.py       Semgrep comparison + metrics          (M4)
  approvals.py      the human gate          (M6)
  sla.py            ageing + escalation     (M6)
  defectdojo.py     live DefectDojo API client            (M5)
  store.py          JSON-file storage       (M6)
  pipeline.py       the four stages wired together        (M6)
  config.py         every tunable value
scan.py           CLI                                     (M6)
server.py         JSON API on http.server                 (M6)
ui/               React + Vite dashboard                  (M7)
testdata/         3 repositories + the labelled oracle    (M7)
tests/            153 tests                               (M7)
docs/             this documentation set                  (M7)
```

Total Python dependencies: **three** — `anthropic`, `semgrep`, `pytest`.
Everything else is the standard library, including the DefectDojo client
(`urllib`). Optional external systems: **Joern** (needs a JDK) and a
**DefectDojo** instance. The engine degrades cleanly without any of them —
it falls back to the builtin engine, the offline validator, and a file export.

---

## Documentation

| Document | Read it for |
|---|---|
| [setup-environment.md](docs/setup-environment.md) | Clean-machine install, step by step, with a verify command each |
| [setup-application.md](docs/setup-application.md) | Running the CLI, the API, the dashboard; configuration; troubleshooting |
| [architecture.md](docs/architecture.md) | How the four stages work, with a worked example, and why each design choice was made |
| [modules.md](docs/modules.md) | The 7-member split and the frozen interfaces between modules |
| [plan-5-days.md](docs/plan-5-days.md) | Day-by-day plan with per-member tasks, gates, and a risk register |
| [qa.md](docs/qa.md) | Test strategy, the 14-scenario matrix, measured results, known limitations |
| [qa-log.md](docs/qa-log.md) | Every defect found during the build and how it was resolved |
| [api.md](docs/api.md) | All 16 endpoints with request and response examples |
| [demo-script.md](docs/demo-script.md) | The timed 7-minute and 3-minute demos, and the likely questions |
| [demo-video.md](docs/demo-video.md) | The recorded 4:36 walkthrough — scene list, timestamps, how to re-record, what it does and does not prove |
| [requirements-matrix.md](docs/requirements-matrix.md) | All 16 hackathon requirements, each with the test that proves it |

---

## Testing

```bash
.venv/bin/python -m pytest tests/ -q          # 153 passed

.venv/bin/python -m pytest tests/test_accuracy.py -q -s    # prints the metrics
```

| Layer | Tests | Proves |
|---|---|---|
| Unit | 44 | Each module in isolation |
| Integration + E2E | 17 | The stage handover contracts, and the CLI |
| Accuracy | 11 | Precision / recall / suppression vs the oracle |
| Workflow | 26 | Storage, the approval gate, SLA, export |
| API | 16 | Every endpoint, including the gate over HTTP |
| Scenarios | 15 | The 14-row QA matrix, executed |

---

## Honest limitations

Written down rather than discovered on stage. Full list in
[qa.md §6](docs/qa.md#6-known-limitations).

- **The JavaScript parser is a line scanner, not a real parser.** Multi-line
  call arguments are not handled. Python — the primary target — uses the real
  `ast` module and has none of these limits.
- **Stage 3 makes one API call per finding.** Correct but slow and costly on a
  large codebase. Batching is the first thing to do next.
- **Inter-procedural taint is capped at depth 2**, resolved by name within one
  repository.
- **Joern's flow output carries no guard or dead-code information**, so a
  separate `ast` pass recovers those two facts. Without it, the allowlist and
  `if False:` decoys survive validation on the Joern path.
- **The comparison corpus is ours.** 28 findings across three small files is a
  demonstration, not a benchmark, and the decoys were chosen to be
  suppressible. The transferable part is the methodology: label ground truth
  first, then measure.

---

## Safety

`testdata/vuln-flask` and `testdata/vuln-express` are **deliberately
vulnerable**. Do not deploy them, do not expose them to a network, and only
run the generated PoC commands against a local instance you control.
