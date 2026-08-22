# Architecture

## The problem, in one paragraph

A pattern-matching scanner finds every place that `os.system()` is called with
a variable. Most of those places are fine — the value was quoted, or validated,
or the code cannot run, or nothing attacker-controlled ever reaches it. Teams
stop reading the report, and the real bug in position 40 never gets fixed.
This engine separates *finding* a suspicious path from *judging* whether it is
exploitable, and lets a language model do the judging with the evidence in
front of it.

---

## The four stages

```
  ┌───────────────────────────────────────────────────────────────────┐
  │  STAGE 1  PREPARE                                    engine/M1    │
  │  source text ──► Code Property Graph + a small IR                 │
  │  engine: builtin (stdlib ast)  OR  Joern (--engine joern)         │
  │  no build, no install, no execution of the target code            │
  └────────────────────────────┬──────────────────────────────────────┘
                               ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │  STAGE 2  SCAN                                       engine/M2    │
  │  walk each function: source ──► sink, recording the path          │
  │  reports EVERYTHING it can reach, including guarded paths         │
  └────────────────────────────┬──────────────────────────────────────┘
                               ▼  raw findings (noisy on purpose)
  ┌───────────────────────────────────────────────────────────────────┐
  │  STAGE 3  VALIDATE                                   engine/M3    │
  │  Claude reads the taint path, the sanitizers, the guards, the     │
  │  reachability, and the source, then says exploitable / not, with  │
  │  a written reason.  Offline rule-based fallback when no API key.  │
  └────────────────────────────┬──────────────────────────────────────┘
                               ▼  confirmed findings + suppressed ones (kept)
  ┌───────────────────────────────────────────────────────────────────┐
  │  STAGE 4  PROVE                                      engine/M5    │
  │  a curl command with a real payload against the real route,       │
  │  plus a suggested fix — generated, never applied                  │
  └────────────────────────────┬──────────────────────────────────────┘
                               ▼
    dedupe (M4) ──► SLA (M6) ──► data/scans/<id>.json ──► DefectDojo (M5)
                                       │                    live API import
                          server.py ───┴──► ui/ (React)
```

---

## Stage 1 — Prepare

**Files:** `engine/cpg.py`, `engine/py_parser.py`, `engine/js_parser.py`,
`engine/stage1_prepare.py`, `engine/joern_engine.py`

### Two interchangeable engines

| | builtin | Joern |
|---|---|---|
| Parser | stdlib `ast` (Python), line scanner (JS) | Joern's own frontends |
| Data flow | our forward taint walk | `reachableByFlows`, Joern's engine |
| Speed on the corpus | ~15 ms | ~15 s |
| Needs | nothing | a JDK and a 1.8 GB install |
| Knows about guards and dead code | yes | no — recovered by an `ast` pass |

Both emit the **same finding dictionary**, so Stages 3 and 4 are identical for
either. `--engine both` runs the pair and tags each finding with its origin.
That interchangeability is the strongest evidence the validation stage is the
contribution rather than the parser: swap the entire front end and the final
numbers are unchanged (100% precision, 100% recall either way).

### Talking to Joern

`joern` is a Scala REPL. We generate a script, it writes JSON to a file, we
read it back — no server, no JVM bindings. Two details in that script silently
return zero results if you get them wrong, and both cost us real time:

1. **A traversal is a single-use iterator.** `val src = cpg.call...` followed
   by reading `src.size` for a log line consumes it, and the
   `reachableByFlows` that runs next gets an exhausted iterator and finds
   nothing. Every traversal is a `def`.
2. **`get` must not be a sink name.** `requests.get` is an SSRF sink but
   `request.args.get` is a source; listing `get` in both sets makes the whole
   query return nothing. SSRF is matched by `methodFullName` separately.

### What Joern does not give us

Joern's flow output proves the value *can* reach the sink. It says nothing
about whether an allowlist rejects the request two lines earlier, or whether
the branch is `if False:`. `structural_flags()` does one `ast` pass over the
file and recovers both. Joern supplies the data flow; the AST supplies the
structure. Without it, two decoys survive validation on the Joern path.

### The builtin engine

Two outputs from one pass:

**The Code Property Graph** — nodes (`MODULE`, `FUNCTION`, `PARAM`, `ASSIGN`,
`CALL`, `RETURN`, `IF`, `LOOP`, `ROUTE`) and edges (`AST` for containment,
`FLOW` for statement order, `CALL` for route → handler). This is what the
dashboard shows and what lets a finding be traced back to a line of source.

**The IR** — a flattened, language-neutral description of each function:

```python
Function(name, params, body=[Stmt, ...], route_path, route_methods, lang)
Stmt(kind="assign"|"expr"|"return"|"if"|"loop", targets, value: Expr, ...)
Expr(vars=[names read], sources=[patterns hit], calls=[Call], only_literal)
Call(name="os.system", args=[Expr], kwargs={name: Expr})
```

The IR is deliberately **flat**. We do not keep a full expression tree, because
taint analysis only needs three facts about a value: which variables it reads,
which attacker-controlled sources it touches, and which calls it passes
through. Flattening makes Stage 2 readable, and it is why one taint engine
serves both languages.

**Python** is parsed with the standard library `ast` module — a real parse, no
regex, no dependency. **JavaScript/TypeScript** is parsed with a line scanner
(`js_parser.py`): brace-depth tracking to know which function we are in, plus
regular expressions for assignments and calls. That is a real limitation and
it is written down in [qa.md](qa.md#known-limitations) rather than hidden.

Nothing is installed, built, or executed. `prepare()` on the test corpus takes
about 15 ms.

---

## Stage 2 — Scan

**Files:** `engine/rules.py` (data), `engine/stage2_scan.py` (logic)

The whole algorithm:

```python
tainted = {}                    # variable name -> how it got dirty
for each statement, in order:
    if it assigns:
        evaluate the right-hand side
        dirty -> tainted[target] = path      clean -> forget target
    for every call in the statement:
        if the call is a SINK and a dangerous argument is dirty:
            report a finding with the whole path
```

`rules.py` is pure data: 25 sources, 47 sinks, 21 sanitizers, 10 vulnerability
classes. Adding a class means adding rows, not changing the engine — which is
why Member 2 could write it on Day 1 before the engine existed.

### Three decisions that make it useful

**1. A sanitizer does not clear the taint.** It gets recorded on the path and
the finding is *still reported*. Stage 3 decides whether that sanitizer
actually covers that sink. If we suppressed here, we would have destroyed the
evidence that makes the false-positive comparison possible — and we would be
doing exactly the pattern matching we are arguing against.

**2. Parameters of non-route functions are treated as possibly tainted**, with
`http_reachable: false` on the finding. Real SAST tools do this and it is a
large source of their noise. We keep it, and let Stage 3 clean it up.

**3. Calls into functions in the same repository are followed**, two levels
deep, carrying the caller's route with them. That is how `/report` →
`build_report()` → `os.system()` produces one finding that still knows the URL
an attacker would call.

### Worked example

```python
@app.route("/ping")           # ROUTE node, handler is attacker-reachable
def ping():
    host = request.args.get("host")     # `request.args` is a SOURCE
                                        #   tainted = {host: [step 1]}
    os.system("ping -c 1 " + host)      # `os.system` is a SINK
                                        #   arg reads `host`, which is dirty
                                        #   -> FINDING, CWE-78
```

Recorded path:

```
1. line 38  attacker input enters via HTTP query string (`request.args`)
            host = request.args.get("host")
2. line 38  value flows into `host`
3. line 39  reaches the dangerous call `os.system()`
            os.system("ping -c 1 " + host)
```

---

## Stage 3 — Validate

**Files:** `engine/llm.py`, `engine/stage3_validate.py`

Claude gets an evidence packet, not a code dump: the vulnerability class, the
entry point and whether it is HTTP-reachable, the dangerous call, any
sanitizers with a note on whether they fit *this* sink, whether a validation
check was seen, whether the code is reachable, the ordered taint path, and ±4
lines of source. It replies with JSON:

```json
{"exploitable": true, "confidence": 0.0-1.0, "severity": "...",
 "reasoning": "...", "attack_scenario": "..."}
```

The system prompt names the traps explicitly — that `shlex.quote` stops shell
injection but not SQL, and that `html.escape` does **not** stop template
injection because it leaves `{{` and `}}` alone.

### Suppressed is not deleted

A suppressed finding keeps `status: "suppressed"` and carries
`suppression_reason`. Deleting them would make the suppression rate
unmeasurable and leave a reviewer no way to disagree with us.

### The offline fallback

If `ANTHROPIC_API_KEY` is unset, or the call fails, or the reply will not
parse, `offline_verdict()` runs the same four questions as deterministic
rules, in order:

1. Is the code unreachable? → not exploitable
2. Is there a sanitizer that fits this sink? → not exploitable
3. Is there a sanitizer that does *not* fit? → **still exploitable**, and say so
4. Was there a validation check? → not exploitable
5. Is anything attacker-controlled able to reach it? → if not, not exploitable
6. Otherwise → exploitable

Same output shape, so nothing downstream cares. Every verdict records
`validator: "claude" | "offline"` and, on a fallback, `fallback_reason`. A
number on a slide is worthless if you cannot say which validator produced it.

---

## Stage 4 — Prove

**File:** `engine/stage4_prove.py`

The PoC is built from the taint path, not from a template: the route comes
from the handler, the parameter name is recovered from the line that read the
input, and the payload comes from the vulnerability class. The whole argument
is `shlex.quote`d, because several payloads contain quotes of their own and a
broken shell command proves nothing.

```
curl -G http://localhost:5001/ping --data-urlencode 'host=; id'
Expected: the output of `id` appears in the response or the server logs.
```

The suggested fix names the actual tainted variable. It is **generated, never
applied** — see the approval gate below.

---

## Cross-cutting: deduplication

**File:** `engine/dedupe.py`

The fingerprint is deliberately **not** the file path or the function name:

```
sha256( CWE + normalised input source + code shape )
```

`code_shape()` reduces a line to its skeleton — string literals become `0`,
identifiers become `1`, whitespace goes, dotted chains collapse. An f-string
and a template literal both reduce to `0+1`, the same as `"..." + x`, because
they are the same thing written three ways.

```
os.system("ping -c 1 " + host)            ->  1(0+1)
child_process.exec("ping -c 1 " + host)   ->  1(0+1)   same cluster
```

That is how the Python and JavaScript copies of the same bug become one
ticket. On the corpus, 17 confirmed findings collapse to 10 unique patterns,
5 of which span both services.

> The placeholders are digits on purpose. An earlier version used the words
> `STR` and `NAME`; the identifier pass then matched `STR` and rewrote it to
> `NAME`, so `os.system(x)` and `os.system("literal")` collapsed together and
> unrelated findings clustered. Digits cannot match an identifier pattern.

---

## Cross-cutting: the approval gate

**File:** `engine/approvals.py`

```
pending_approval ──approve──► approved ──apply──► applied
                 ──reject───► rejected ──reopen─► pending_approval
```

`apply_fix()` refuses to run unless the fix is already approved, and even then
it returns a patch rather than editing the file. The ordering is enforced in
code, not in a process document someone forgets. Every transition records who,
when, and why, in `approval_history`.

---

## Cross-cutting: SLA

**File:** `engine/sla.py`

Each severity gets a clock (critical 24 h, high 72 h, medium 7 d, low 30 d).
A confirmed finding older than its clock is `breached` and escalates to the
owner in `config.SLA_ESCALATION`. Applying a fix stops the clock. `age_hours`
is injectable so a test can age a finding by three days without waiting.

---

## Storage and the API

**Files:** `engine/store.py`, `server.py`

One JSON file per scan under `data/scans/`. No database, no ORM, no
migrations. Writes are atomic (temp file + rename). The file on disk is the
same structure the API returns.

`server.py` is `http.server.ThreadingHTTPServer` plus a list of
`(method, regex, handler)` tuples. `_dispatch` walks the list and the first
match wins — that is all a router is. The whole web layer is one readable file
with no framework to explain.

---

## Why these choices

| Decision | Alternative | Why we chose this |
|---|---|---|
| Stdlib `ast` as the default engine | Joern only | Zero dependencies and ~1000× faster. Joern is wired in as an option and as the baseline, so you get both. |
| Joern as the primary baseline | Semgrep only | Beating a real inter-procedural data-flow engine is a harder, more honest claim than beating regular expressions. |
| Line scanner for JS | tree-sitter, a Node subprocess | Keeps "simple scripts" true. Limits are documented; Semgrep covers JS in the baseline. |
| JSON files | SQLite, Postgres | Inspectable with `cat`, diffable, nothing to explain. |
| `http.server` | FastAPI, Flask | One file, no framework concepts on top of the security work. |
| Sanitizers do not clear taint | Clear it in Stage 2 | Preserves the evidence the whole comparison depends on. |
| Fix generated, never applied | Auto-apply | An auto-applied security "fix" turns one bug into two. |
| Offline fallback | Fail when no key | A demo must not depend on venue wifi. |

---

## What we would do next

- **Joern or tree-sitter for JavaScript**, replacing the line scanner and its
  multi-line limitation.
- **Deeper inter-procedural analysis** — the depth cap is 2, and there is no
  cross-file call resolution.
- **Batch the Stage 3 calls.** One request per finding is simple but slow on a
  large repository; the Message Batches API would cut both cost and wall time.
- **Incremental scanning** — only re-analyse functions touched by a diff.
- **Feed approvals back into the rules.** A finding a human rejects three times
  is a rule that needs tuning.
