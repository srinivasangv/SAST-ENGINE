# Demo Script

Two versions: a **7-minute** full walkthrough and a **3-minute** cut for when
the schedule slips. Rehearse both.

> **Have the recording ready as a fallback.**
> [`demo/output/sast-engine-demo.mp4`](../demo/output/sast-engine-demo.mp4) is
> a narrated 4:36 version of this same walkthrough, against the same live
> application. If the wifi dies, the laptop refuses to project, or a service
> will not start on the day, play it instead of improvising. Scene list and
> timestamps: [demo-video.md](demo-video.md).

---

## Before you start

```bash
# 1. Clean slate so the history panel is not confusing
rm -f data/scans/*.json data/exports/*.json

# 2. Warm the Semgrep rule cache (needs internet — do this in the morning)
.venv/bin/semgrep --config p/security-audit --json --quiet testdata/vuln-flask > /dev/null

# 3. Confirm the key works. If this says offline, decide NOW whether you are
#    demoing the Claude path or the offline path, and say so on stage.
.venv/bin/python -c "from engine import config; print('LLM:', config.llm_available())"

# 4. Terminal 1
.venv/bin/python server.py

# 5. Terminal 2
cd ui && npm run dev

# 6. Open http://localhost:5173 and leave it on the Scans tab
```

**Checklist**
- [ ] Two terminals open, both running, both visible
- [ ] Browser on the Scans tab, zoomed to ~125% so the back row can read it
- [ ] A third terminal ready in the repo root for the CLI part
- [ ] `docs/qa.md` open in a tab in case someone asks for the numbers
- [ ] Backup recording accessible offline

---

## The 7-minute demo

### 0:00 — The problem (45 s)

> "A normal SAST tool finds every place a variable reaches `os.system`. Most of
> those are already safe — the value was quoted, or checked, or the code can't
> even run. Developers get 200 findings, stop reading at 20, and the real bug
> at number 40 ships.
>
> We split the job in two. One stage *finds* suspicious paths and is
> deliberately noisy. A second stage *judges* whether each one is actually
> exploitable, and writes down why."

### 0:45 — Stage 1 and 2, on the CLI (90 s)

Terminal 3:

```bash
.venv/bin/python scan.py testdata/vuln-flask --no-baseline
```

While the stages print:

> "Stage 1 built a Code Property Graph from 115 nodes — no build, no
> `pip install`, we never execute the code we're scanning. Stage 2 walked it
> and found 17 suspicious paths."

When it finishes, point at one finding:

> "Every finding carries the path: line 38 the query string comes in, line 38
> it flows into `host`, line 39 it reaches `os.system`. That's the evidence
> the next stage reasons about."

### 2:15 — Stage 3, the actual point (2 min)

```bash
.venv/bin/python scan.py testdata/vuln-flask --no-baseline --show-suppressed
```

> "17 reported, **11 confirmed, 6 suppressed** — and every suppression has a
> reason."

Read two of them aloud:

> "'The value passes through `shlex.quote` before reaching `os.system`, which
> is the correct defence for OS command injection.' And: 'The dangerous call
> sits inside a branch whose condition is a constant false value, so it can
> never execute.'
>
> A regex can't say that. It's also why we keep suppressed findings instead of
> deleting them — you can disagree with us, and we can measure the rate."

**Then the trap** — switch to the browser, Findings tab, and open the XSS one:

> "This one is subtle. `html.escape` before `Markup` — suppressed, correct.
> But we originally wrote this decoy with `html.escape` before
> `render_template_string`, and *that* would have been a real bug: escaping
> HTML doesn't escape `{{ }}`, so template injection still works. Our own QA
> caught it. It's QA-001 in the log."

### 4:15 — Stage 4 and the gate (1 min)

In the finding detail:

> "For every confirmed finding we generate a proof of concept built from the
> real route and the real parameter —"

```
curl -G http://localhost:5001/ping --data-urlencode 'host=; id'
```

> "— and a suggested fix. Watch what happens if I try to apply it."

Click **Apply approved fix**:

> "Refused. The fix has not been approved by a human. That gate is enforced in
> code, not in a process doc."

Click **Approve**, then **Apply**:

> "Now it hands me a patch. It still doesn't edit my source — an auto-applied
> security fix is how you turn one bug into two."

### 5:15 — The comparison (1 min)

**vs Semgrep** tab:

| | findings | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|---|
| Semgrep | 12 | 10 | 2 | 4 | 83.3% | 71.4% |
| Stage 2 | 17 | 11 | 6 | 0 | 64.7% | 100% |
| Stage 3 | 11 | 11 | 0 | 0 | **100%** | **100%** |

> "Left to right: Semgrep, our pattern matching, our pattern matching plus
> reasoning. Note the last column — **recall did not move**. We removed every
> false positive without losing a single real bug. Suppressing everything
> would give perfect precision and be useless, so that's the number we guard
> with a test."

Be ready for the fair-comparison question:

> "Small corpus, our decoys, one rule pack. It's a demonstration, not a
> benchmark — that caveat is written into our QA doc."

### 6:15 — Dedupe and SLA (45 s)

**Deduplication** tab:

> "The same command injection exists in the Python service and the Node
> service. We fingerprint on CWE plus input source plus the *shape* of the
> code, never the file path — so `os.system("ping " + host)` and
> `child_process.exec("ping " + host)` are one cluster. Three findings, one
> ticket. 17 confirmed findings collapse to 10 patterns."

**Approvals & SLA** tab:

> "And each finding is on a clock. Critical gets 24 hours, then it breaches and
> escalates. Applying a fix stops the clock."

### 7:00 — Close (15 s)

> "Four stages, seven modules, 129 tests. The headline: adding a reasoning
> stage removed 100% of false positives at zero cost to recall."

---

## The 3-minute cut

| Time | Do |
|---|---|
| 0:00 | The problem, 30 s. |
| 0:30 | `scan.py testdata/vuln-flask --no-baseline --show-suppressed`. "17 reported, 11 confirmed, 6 suppressed, each with a reason." Read one reason. |
| 1:30 | Findings tab → one finding → taint path, PoC, then the refused apply → approve → patch. |
| 2:15 | vs Semgrep tab. The three-row table. "Recall did not move." |
| 2:45 | Deduplication tab, the cross-language cluster. Close. |

Skip: the CLI stage-by-stage narration, the QA-001 story, the SLA tab.

---

## The offline moment

If there is no internet, or the key fails, **do not hide it** — it is one of
the better parts of the demo.

```bash
env -u ANTHROPIC_API_KEY .venv/bin/python scan.py testdata/vuln-flask --no-baseline
```

> "No API key. The pipeline still runs — 11 confirmed, 6 suppressed, same
> answers — because Stage 3 falls back to a deterministic validator that asks
> the same questions as rules. Every verdict records which validator produced
> it, so you always know what you're looking at. A demo shouldn't die because
> of the venue wifi."

This is genuinely how it behaved during the build: the key in our build
environment returned a 401, the engine caught it, fell back, and recorded the
reason. That is logged as ENV-1 in the QA log.

---

## Likely questions

| Question | Answer |
|---|---|
| "Isn't the LLM just guessing?" | It gets structured evidence — the taint path, which sanitizers were seen and whether they fit *this* sink, whether a guard was seen, whether the code is reachable. And there's a deterministic fallback that reaches the same verdicts on this corpus, so you can check its work. |
| "What if the LLM is wrong?" | Two safety nets. Nothing is deleted — a suppressed finding stays in the report with its reason, so you can overrule it. And no fix is applied without a human approving it. |
| "How does this scale?" | One API call per finding, which is the honest weak point. Batching is the first thing we'd do next. It's LIM-2 in our QA log. |
| "Why not use Joern?" | We wanted the whole thing readable by the team that built it. Python's `ast` gives a real parse with zero dependencies. Joern would be the upgrade path for deeper analysis. |
| "Is the JS support real?" | Partly. It's a line scanner, not a real parser — multi-line calls are a known gap. Python is the primary target and uses a real AST. That limitation is written in our QA doc, not discovered on stage. |
| "You wrote the test corpus — isn't that convenient?" | Yes, and we say so in the QA doc. The decoys were chosen to be suppressible, so 100% is a best case. The methodology is the transferable part: label ground truth first, then measure. |
| "What does it cost per scan?" | One Claude call per raw finding. 17 findings on a small repo. On a large codebase you'd batch, or run Stage 3 only on high-severity classes. |

---

## If something breaks

| Breaks | Do |
|---|---|
| Dashboard says "API unreachable" | `server.py` died. Restart it in terminal 1. Keep talking — switch to the CLI, which needs nothing. |
| A scan hangs | It's Semgrep. Ctrl-C, re-run with `--no-baseline`. |
| The API key fails mid-demo | Perfect — pivot to the offline moment above. It's a feature. |
| Port already in use | `lsof -ti:8000 \| xargs kill`, restart. |
| Everything is on fire | Play the backup recording. Narrate over it. |
