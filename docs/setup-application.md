# Application Setup and Operation

How to run the three pieces: the CLI, the API, and the dashboard.
Finish [setup-environment.md](setup-environment.md) first.

---

## The three ways to run it

| You want to… | Run | Needs |
|---|---|---|
| Scan a repository and read the result in a terminal | `scan.py` | Python only |
| Drive it from a browser, or from another program | `server.py` | Python only |
| Show it to someone | `server.py` + `ui` dev server | Python + Node |

The CLI and the API share the same pipeline code (`engine/pipeline.py`) and
write the same JSON files, so a scan started in one is visible in the other.

---

## 1. The CLI

```bash
# Scan one repository
.venv/bin/python scan.py testdata/vuln-flask

# Scan two, and dedupe the findings across both
.venv/bin/python scan.py testdata/vuln-flask testdata/vuln-express

# Show why each suppressed finding was suppressed
.venv/bin/python scan.py testdata/vuln-flask --show-suppressed

# Force the offline validator even when a key is set
.venv/bin/python scan.py testdata/vuln-flask --no-llm

# Skip the Semgrep comparison (much faster)
.venv/bin/python scan.py testdata/vuln-flask --no-baseline

# Machine-readable output for a CI pipeline
.venv/bin/python scan.py testdata/vuln-flask --json > result.json

# Scan with Joern's CPG and data-flow engine instead of ours
JAVA_HOME=~/.local/opt/jdk21 .venv/bin/python scan.py testdata/vuln-flask --engine joern

# Run both engines and merge what they find
.venv/bin/python scan.py testdata/vuln-flask --engine both

# Also measure Semgrep as a secondary baseline
.venv/bin/python scan.py testdata/vuln-flask --with-semgrep

# Push confirmed findings into a live DefectDojo
.venv/bin/python scan.py testdata/vuln-flask --defectdojo
```

| Flag | Default | What it does |
|---|---|---|
| `--engine builtin\|joern\|both` | `builtin` | Which CPG and taint engine runs Stages 1 and 2. |
| `--no-baseline` | off | Skip the Joern baseline comparison. Much faster. |
| `--with-semgrep` | off | Also measure Semgrep as a secondary baseline. |
| `--defectdojo` | off | Push confirmed findings to a live DefectDojo. |
| `--no-llm` | off | Force the offline validator. |

**Exit codes** — designed for a CI gate:

| Code | Meaning |
|---|---|
| 0 | No confirmed vulnerabilities. |
| 1 | At least one confirmed vulnerability. Fail the build. |
| 2 | The scan could not run (bad path, unreadable repository). |

```bash
# In CI
.venv/bin/python scan.py . --no-baseline || exit 1
```

---

## 2. All three services at once

```bash
./services.sh start      # starts only what is not already running
./services.sh status     # what is up, and what the engine reports about itself
./services.sh stop       # stops the API and the dashboard
./services.sh clean      # archive all but the newest scan per repo
```

`status` prints the part that is easy to get wrong:

```
== services ==
  api        up   http://localhost:8000
  dashboard  up   http://localhost:5173
  defectdojo up   http://localhost:8083

== what the engine reports about itself ==
  validator   offline - anthropic is configured but did not answer
  engines     builtin + joern + semgrep
  defectdojo  authenticated
  scans       3 stored
```

That validator line is the one to read before a demo. "A key is configured"
and "the LLM answered" are different facts, and the script reports the second.

The DefectDojo URL comes from `.env.local`, not a hardcoded 8080, so it stays
right when the port moves. The sections below cover starting each service by
hand.

---

## 2a. The API

```bash
.venv/bin/python server.py
```

Serves on `http://127.0.0.1:8000`. Full endpoint reference: [api.md](api.md).

```bash
curl localhost:8000/api/health

curl -X POST localhost:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"repo_path": "testdata/vuln-flask"}'
```

Scans run in a background thread, so `POST /api/scans` returns a `job_id`
immediately. Poll `GET /api/scans/status/<job_id>` until `state` is `done`.
One scan runs at a time — a second request queues behind the first rather than
fighting it for CPU.

---

## 2b. The dashboard

In a **second terminal**, with the API already running:

```bash
cd ui
npm run dev
```

Open <http://localhost:5173>.

Vite proxies `/api` to `http://127.0.0.1:8000` (see `ui/vite.config.js`), so
the frontend uses relative URLs and there is no hostname to edit between
machines. The header shows which validator is active — if it says
"API unreachable", `server.py` is not running.

For a production-style build:

```bash
cd ui && npm run build && npm run preview
```

---

## Configuration

Everything tunable lives in `engine/config.py`. Nothing is hidden elsewhere.

| Setting | Default | What it controls |
|---|---|---|
| `LLM_MODEL` | `claude-opus-5` | The model Stage 3 asks. |
| `LLM_MAX_TOKENS` | `2000` | Ceiling on one verdict. |
| `SLA_HOURS` | critical 24, high 72, medium 168, low 720 | How long a finding may stay open. |
| `SLA_ESCALATION` | per severity | Who a breached finding escalates to. |
| `SKIP_DIRS` | `node_modules`, `.venv`, `.git`, … | Directories never walked. |
| `MAX_FILE_BYTES` | 512 KB | Files larger than this are skipped as generated. |
| `SERVER_HOST` / `SERVER_PORT` | `127.0.0.1:8000` | Where the API listens. |

Change the port in **two** places if you change it at all: `config.py`, and
the proxy target in `ui/vite.config.js`.

---

## Where the data goes

```
data/
├── scans/<scan-id>.json       one file per scan — the complete result
└── exports/defectdojo-*.json  DefectDojo import files
```

There is no database. A scan is a JSON file, so you can read it with `cat`,
diff two runs, and delete a bad one with `rm`.

```bash
ls -la data/scans/
.venv/bin/python -m json.tool data/scans/<scan-id>.json | head -60

# Start a demo from a clean slate
rm -f data/scans/*.json
```

Writes are atomic (write to a temp file, then rename), so a crash mid-write
cannot leave a half-written file that breaks the dashboard.

---

## Scanning your own code

```bash
.venv/bin/python scan.py /path/to/your/project
```

Nothing is installed, built, or executed — the engine only reads text. It
handles Python (`.py`) and JavaScript/TypeScript (`.js .jsx .ts .tsx .mjs
.cjs`), skips `node_modules`, `.venv`, `.git` and friends, and skips test
files unless you ask for them.

Expect more findings on a real codebase than on the test corpus, especially
`http_reachable: false` ones from internal helper functions — Stage 3 is what
sorts those out.

---

## DefectDojo

Two paths, same document, so they cannot drift.

**Live push** — creates the product and engagement if missing, then imports:

```bash
.venv/bin/python scan.py testdata/vuln-flask --defectdojo

curl -X POST localhost:8000/api/defectdojo/push \
  -H 'Content-Type: application/json' -d '{"scan_id": "<scan-id>"}'
```

The push is idempotent on the product and the engagement; each push adds a new
*test*, which is what gives a per-repository history. It reads the findings
back afterwards and reports `submitted` against `stored`, because an import
that returns 200 and stores nothing is a failure you would otherwise miss.

**Offline file** — no server needed:

## The DefectDojo export file

```bash
curl -X POST localhost:8000/api/export/defectdojo \
  -H 'Content-Type: application/json' \
  -d '{"scan_id": "<scan-id>", "include_suppressed": false}'
```

Writes `data/exports/defectdojo-<scan-id>.json`. In DefectDojo: **Product →
Engagement → Import Scan Results**, scan type **Generic Findings Import**,
upload the file.

Setting `include_suppressed: true` also exports the suppressed findings,
flagged `false_p: true`, so a reviewer can audit what the engine dismissed.

The file and the live push are built from the **same document**, so the two
cannot drift. Use the file when there is no server to talk to.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Dashboard says "API unreachable" | `server.py` is not running. | Start it in another terminal. |
| Dashboard loads but every tab is empty | No scans stored yet. | Run one from the Scans tab. |
| `Address already in use` | Port 8000 or 5173 is taken. | `lsof -i :8000`, kill it, or change the port in both places. |
| Scan seems to hang for ~15 seconds | Joern is building a CPG. | Normal. Use `--no-baseline` and `--engine builtin` to skip it. |
| `--engine joern` silently uses the builtin engine | Joern or the JDK is missing. | The stage log says why. Check `JAVA_HOME` and section 8 of the environment setup. |
| DefectDojo push fails at `auth` | No token. | Put one in `~/.dd_token` or `DEFECTDOJO_TOKEN`. |
| Push reports `stored` lower than `submitted` | DefectDojo deduplicated some. | Check the engagement's deduplication setting. |
| "validated by: offline" with a key set | The key was rejected. | Check `fallback_reason` in the scan JSON. |
| Zero findings on your own repo | No supported files, or everything is behind a guard. | Check `stages.prepare.files` in the JSON; if it is 0, nothing was parsed. |
| `comparison unavailable` | Semgrep missing or offline. | Pre-download the rules (environment setup step 6). |
