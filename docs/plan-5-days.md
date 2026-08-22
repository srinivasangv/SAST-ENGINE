# Five-Day Plan

Seven people, five days, one working demo. Each day ends with a **gate**: a
specific, demonstrable thing. If the gate does not pass, the standup next
morning starts by fixing it rather than starting new work.

**Daily rhythm**

| Time | What |
|---|---|
| 09:30 | Standup, 15 min. Yesterday's gate, today's task, any blocker. |
| 13:00 | Merge window. Everyone pushes; whoever broke `main` fixes it. |
| 17:00 | Gate check. Demo it to the team, not just to yourself. |
| 17:30 | Update `docs/qa-log.md` with anything found today. |

---

## Day 1 — Foundations and contracts

The single most valuable hour of the week is the Day 1 contract meeting.
Freeze the four interfaces in [modules.md](modules.md) and nobody is blocked
for the rest of the week.

| Who | Task | Done when |
|---|---|---|
| **All** | Contract meeting (09:30–10:30). Agree the IR, the finding dict, the scan file, the API. Commit `docs/modules.md`. | The file is on `main` and everyone has read it. |
| **All** | Environment: venv, `pip install -r requirements.txt`, `npm install`. | `pytest tests/ -q` passes on a placeholder test for all 7. |
| **M1** | `cpg.py` dataclasses; `py_parser.py` handling functions, params, assignments, calls, f-strings. | Parsing `testdata/vuln-flask/app.py` yields ≥15 `Function` objects. |
| **M2** | `rules.py` complete — sources, sinks, sanitizers, vulnerability classes, for both languages. | `test_units.py::TestRuleMatching` passes. It is data, so it needs no engine. |
| **M3** | `llm.py` skeleton: the Claude call with `claude-opus-5`, the prompt builder, the offline validator. | `offline_verdict()` returns a correct verdict for a hand-written finding. |
| **M4** | Get Semgrep running on a sample file; write the precision/recall/suppression formulas. | `semgrep --config p/security-audit testdata/` returns JSON. |
| **M5** | Write `testdata/vuln-flask/` (11 vulnerabilities, 6 decoys) and `testdata/safe-app/`. | Both files exist, every case tagged `VULN-n` or `DECOY-n`. |
| **M6** | `config.py`, `store.py`, `server.py` returning **hard-coded fixture JSON**. | `curl localhost:8000/api/scans` returns a plausible scan. |
| **M7** | Vite + React scaffold, five tabs, `api.js` pointed at M6's fixtures. | `npm run dev` shows tabs with fixture data. |

> **Why M6 serves fixtures on Day 1:** it unblocks M7 immediately. M7 is the
> only member whose work is entirely downstream, so they must never wait.

**🚦 Gate:** `docs/modules.md` is committed, all seven environments work, and
the dashboard renders fixture data.

---

## Day 2 — Real detections

| Who | Task | Done when |
|---|---|---|
| **M1** | Branches, loops, `with`, `try`, class methods, Flask route decorators. CPG stats. | `repo.stats()` reports nodes, edges, functions, routes. |
| **M2** | The taint walk: environment, assignment propagation, sink checking. | `scan()` finds VULN-1 through VULN-4 in the Flask app. |
| **M3** | Build the evidence packet; test the prompt against 3 findings by hand. | Claude returns parseable JSON for all 3. |
| **M4** | `fingerprint()` and `code_shape()`; `cluster()`. | Two findings with the same shape in different repos form one cluster. |
| **M5** | Write `testdata/vuln-express/` (6 vulnerabilities, 4 decoys). Start `js_parser.py`. | The Express file exists; the parser finds its route handlers. |
| **M6** | `pipeline.py` wiring the stages; `POST /api/scans` runs it for real. | Fixtures deleted — the API serves real scan results. |
| **M7** | Scans and Findings tabs against real data. Start `ground_truth.json`. | Clicking a scan shows real findings. |

**🚦 Gate:** `python scan.py testdata/vuln-flask` prints real findings with
real taint paths.

---

## Day 3 — The differentiator

This is the day the project stops being a linter. Protect it: no new features
on Day 3 that are not on this list.

| Who | Task | Done when |
|---|---|---|
| **M1** | Inter-procedural taint: follow a call into a helper, carrying the caller's route. | VULN-11 (`/report` → `build_report`) is found with `/report` in its PoC. |
| **M2** | Sanitizer recording (**without** clearing taint), guard detection, dead-code detection, non-route parameter sources. | All 6 Flask decoys are *reported* by Stage 2 with the right metadata. |
| **M3** | Validation over a whole scan; suppression reasons stored; fallback verified with the key unset. | 11 confirmed / 6 suppressed on the Flask app, each with a reason. |
| **M4** | `baseline.compare()` producing the three-row table. Label `ground_truth.json` with M7. | The comparison table prints with real precision and recall. |
| **M5** | `stage4_prove.py`: PoC commands and fix suggestions. Finish `js_parser.py`. | Every confirmed finding has a `curl` command; the Express app scans. |
| **M6** | `approvals.py` and `sla.py` with their endpoints. | Applying an unapproved fix is refused over HTTP. |
| **M7** | Finding-detail screen: taint path, verdict, PoC, fix, approve/reject. | You can approve a fix from the browser. |

**🚦 Gate:** at least one finding is visibly suppressed with a written reason
that a non-security person can read and agree with.

---

## Day 4 — Integration and hardening

| Who | Task | Done when |
|---|---|---|
| **All** | Integration morning. Every stub deleted; every module talks to the real thing. | No `TODO` or fixture left in the pipeline path. |
| **M1** | Robustness: broken files, empty repos, huge files, unreadable files. | Scenario 12 and 13 pass. |
| **M2** | Tune the rules against the corpus. Any rule change re-runs the accuracy test. | No false negative on the corpus. |
| **M3** | Error paths: no key, bad key, timeout, unparseable reply — all fall back cleanly. | Scenario 11 passes; `fallback_reason` is populated. |
| **M4** | Final numbers for both repos. Cross-repo clustering across all three. | The comparison table and dedupe summary are final. |
| **M5** | DefectDojo export verified against the Generic Findings Import shape. | The export file imports without an error. |
| **M6** | Concurrency, error handling, scan history, atomic writes. | Scenario 14 (two concurrent scans) passes. |
| **M7** | Comparison, Dedupe and Workflow tabs. Run the full 14-scenario matrix. | `pytest tests/ -q` is green; `docs/qa-log.md` is filled in. |

**🚦 Gate:** the clean-machine test. Someone who has not touched the repo
clones it, follows `docs/setup-environment.md`, and gets a working scan.
Whatever they trip over is a documentation bug — fix the doc, not their machine.

---

## Day 5 — Polish, docs, demo

**Code freeze is 13:00.** After that only documentation, slides, and rehearsal.

| Time | Who | Task |
|---|---|---|
| 09:30–13:00 | **All** | Fix only critical and high bugs from `qa-log.md`. Medium and low become "known limitations" on a slide. |
| 13:00 | **All** | **Freeze.** Tag the commit. |
| 13:00–15:00 | **M7 + M3** | Finish the docs set and the deck. Every number on a slide comes from a real run. |
| 13:00–15:00 | **M1, M2** | Re-read your own module's comments as if you had never seen them. You will be asked to explain them. |
| 15:00–16:00 | **All** | Dry run 1, with the API key set. Time it. |
| 16:00–16:30 | **All** | Dry run 2, **with the key unset**, to prove the fallback. |
| 16:30–17:00 | **All** | Record a backup video of the full demo. |
| 17:00 | **All** | Final gate. |

**🚦 Gate:** the demo has been run twice end to end, a backup recording
exists, and every member can explain their own module without notes.

---

## Risk register

| Risk | Likelihood | Impact | Mitigation | Owner |
|---|---|---|---|---|
| No internet or bad API key at the venue | Medium | **Fatal without a plan** | The offline fallback is built in from Day 1 and rehearsed in dry run 2. | M3 |
| Semgrep will not install or download rules | Medium | High — no comparison slide | Pre-download the rules on Day 1; `--no-baseline` degrades gracefully. | M4 |
| The JS line scanner misses real code | High | Medium | Python is the primary target; limits documented; Semgrep covers JS in the baseline. | M5 |
| Ground truth written to match the bugs | Medium | High — the metrics become meaningless | M7 owns the oracle and does **not** write engine code. | M7 |
| A member is absent | Low | High | Every module has its interface written down, so someone else can stub it. | All |
| Merge conflicts on Day 4 | Medium | Medium | File ownership; merge window at 13:00 daily. | All |
| Demo runs long | Medium | Medium | `docs/demo-script.md` is timed; the 3-minute version is marked. | M7 |

---

## Definition of done

- [ ] `python scan.py testdata/vuln-flask` finds all 11 planted vulnerabilities
- [ ] `python scan.py testdata/safe-app` reports zero
- [ ] Every confirmed finding has a taint path, a PoC, and a suggested fix
- [ ] At least one finding is suppressed with a reason a reviewer agrees with
- [ ] The comparison table shows measured precision and recall vs Semgrep
- [ ] The same pattern in Python and JavaScript forms one cross-repo cluster
- [ ] An unapproved fix cannot be applied — proven over HTTP
- [ ] An aged finding breaches its SLA and escalates
- [ ] The whole pipeline runs with `ANTHROPIC_API_KEY` unset
- [ ] `pytest tests/ -q` is green
- [ ] A clean machine can follow the docs and reach a working scan
- [ ] The deck's numbers all come from a real run
