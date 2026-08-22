# Localhost Runbook — Setup, Start, Run

A single-page runbook: get the environment up, start the three services, and
run the application on localhost. Verified on this machine on 2026-08-18.

For the long form with a verify command per step, see
[setup-environment.md](setup-environment.md) and
[setup-application.md](setup-application.md). This file is the short path.

---

## 0. What runs where

| Service | Port | Started by | Needed for |
|---|---|---|---|
| API (`server.py`) | 8000 | `./services.sh start` | Dashboard, and any programmatic use |
| Dashboard (Vite + React) | 5173 | `./services.sh start` | The browser UI |
| DefectDojo | 8083 | `docker compose` in `~/defectdojo` | Optional — live ticket import |

The CLI (`scan.py`) needs none of them. It shares `engine/pipeline.py` and
writes the same JSON files under `data/scans/`, so a scan started on the CLI
shows up in the dashboard and vice versa.

---

## 1. Fresh-machine setup

```bash
# 1.1 prerequisites (Ubuntu / WSL)
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git curl
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash - && sudo apt install -y nodejs

# 1.2 python environment + dependencies  (~3 min; semgrep is the large one)
cd ~/projects/sast-engine
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 1.3 dashboard dependencies
cd ui && npm install && cd ..

# 1.4 pre-cache the Semgrep rule pack (needs internet, once)
.venv/bin/semgrep --config p/security-audit --json --quiet testdata/vuln-flask > /dev/null

# 1.5 prove the environment
.venv/bin/python -m pytest tests/ -q          # expect: 153 passed
```

**Verify each layer:**

```bash
python3 --version                 # 3.10+
node --version                    # v18+
.venv/bin/python -c "import anthropic; print('anthropic ok')"
.venv/bin/semgrep --version
.venv/bin/pytest --version
```

### Optional extras

None of these are required — the engine degrades cleanly and tells you which
path it took.

| Extra | Enable with | Without it |
|---|---|---|
| Claude validation (Stage 3) | `export ANTHROPIC_API_KEY="sk-ant-..."` | Deterministic offline validator runs; every verdict is tagged with who made it |
| Joern engine + baseline | `export JAVA_HOME=~/.local/opt/jdk21` | Falls back to the builtin `ast` parser and says so |
| DefectDojo live push | `docker compose up -d` in `~/defectdojo` | Findings are written as a Generic Findings Import file to `data/exports/` |

Install instructions for Joern and DefectDojo: [setup-environment.md](setup-environment.md) §8 and §9.

---

## 2. Start the services

```bash
cd ~/projects/sast-engine
export JAVA_HOME=~/.local/opt/jdk21     # only needed for --engine joern

./services.sh start      # starts only what is not already up
./services.sh status     # what is up, and what the engine reports about itself
./services.sh stop       # stops API + dashboard (leaves DefectDojo running)
./services.sh restart
./services.sh clean      # archive all but the newest scan per repo (never deletes)
```

`status` output to expect:

```
== services ==
  api        up   http://localhost:8000
  dashboard  up   http://localhost:5173
  defectdojo up   http://localhost:8083

== what the engine reports about itself ==
  validator   offline - anthropic is configured but did not answer
  engines     builtin + joern + semgrep
  defectdojo  authenticated
  scans       4 stored
```

Read the **validator** line before any demo. "A key is configured" and "the LLM
answered" are different facts, and this line reports the second.

### By hand instead, in two terminals

```bash
.venv/bin/python server.py            # terminal 1  ->  http://127.0.0.1:8000
cd ui && npm run dev                  # terminal 2  ->  http://localhost:5173
```

Vite proxies `/api` to `127.0.0.1:8000` (see `ui/vite.config.js`), so the
frontend uses relative URLs and there is no hostname to edit between machines.

---

## 3. Run the application on localhost

### 3.1 Dashboard

Open <http://localhost:5173> → **Scans** tab → scan `testdata/vuln-flask`.

If the header says "API unreachable", `server.py` is not running.

### 3.2 CLI

```bash
.venv/bin/python scan.py testdata/vuln-flask --no-baseline    # ~8 s
.venv/bin/python scan.py testdata/vuln-flask                  # + Joern baseline, ~25 s
.venv/bin/python scan.py testdata/vuln-flask --show-suppressed
.venv/bin/python scan.py testdata/vuln-flask testdata/vuln-express   # dedupe across both
.venv/bin/python scan.py testdata/vuln-flask --json > result.json
JAVA_HOME=~/.local/opt/jdk21 .venv/bin/python scan.py testdata/vuln-flask --engine joern
```

Measured on this machine (`--no-baseline`): 17 potential findings → **11
confirmed, 6 suppressed**, collapsed to 9 unique patterns, 8512 ms.

**Exit codes**, designed as a CI gate:

| Code | Meaning |
|---|---|
| 0 | No confirmed vulnerabilities |
| 1 | At least one confirmed vulnerability — fail the build |
| 2 | The scan could not run (bad path, unreadable repository) |

### 3.3 API

```bash
curl localhost:8000/api/health

curl -X POST localhost:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"repo_path": "testdata/vuln-flask"}'
# -> {"job_id": "..."}   then poll:
curl localhost:8000/api/scans/status/<job_id>     # until state == done
```

Scans run in a background thread, one at a time; a second request queues rather
than fighting the first for CPU. All 16 endpoints: [api.md](api.md).

### 3.4 Scan your own code

```bash
.venv/bin/python scan.py /path/to/your/project
```

Nothing is installed, built, or executed — the engine only reads text. Python
and JavaScript/TypeScript are supported; `node_modules`, `.venv`, `.git` and
test files are skipped.

---

## 4. Where the data goes

```
data/
├── scans/<scan-id>.json        one file per scan — the complete result
└── exports/defectdojo-*.json   DefectDojo import files
```

No database. Writes are atomic (temp file + rename), so a crash mid-write
cannot leave a half-written file that breaks the dashboard.

```bash
ls -la data/scans/
.venv/bin/python -m json.tool data/scans/<scan-id>.json | head -60
rm -f data/scans/*.json          # start a demo from a clean slate
```

---

## 5. Machine-specific notes (this box)

1. **`ANTHROPIC_API_KEY` is set but rejected.** The last scan recorded
   `fallback_reason: AuthenticationError: 401 API key is invalid`, so Stage 3
   used the offline rule-based validator. Export a valid `sk-ant-...` key
   before demoing the LLM path, or accept the fallback — it is honest about
   which validator ran. Check `fallback_reason` in `data/scans/<id>.json`
   whenever you see `validated by: offline`.
2. **Port 8080 is occupied by `aziron-server`**, which is why DefectDojo runs
   on **8083**. That is already recorded in `.env.local`, and `services.sh`
   reads the URL from there rather than assuming 8080 — do not move it back.
3. **`JAVA_HOME` is unset in a fresh shell.** Joern and the JDK are installed
   at `~/.local/opt/joern-cli` and `~/.local/opt/jdk21`; export `JAVA_HOME`
   before using `--engine joern`, or `services.sh` will default it for you.

---

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'engine'` | Run from the repository root. Every command assumes it. |
| `Address already in use` on 8000 / 5173 | `ss -lptn 'sport = :8000'`, kill it, or change `SERVER_PORT` in `engine/config.py` **and** the proxy target in `ui/vite.config.js`. |
| Dashboard says "API unreachable" | `server.py` is not running. |
| Dashboard loads but every tab is empty | No scans stored yet — run one from the Scans tab. |
| Scan hangs for ~15 s | Joern is building a CPG. Normal. Use `--no-baseline --engine builtin` to skip. |
| `--engine joern` silently uses the builtin engine | Joern or the JDK is missing; the stage log says why. Check `JAVA_HOME`. |
| `comparison unavailable` | Semgrep missing or offline — pre-cache the rules (step 1.4) or use `--no-baseline`. |
| `validated by: offline` with a key set | The key was rejected. See `fallback_reason` in the scan JSON. |
| Tests fail with `FileNotFoundError: testdata/...` | Run pytest from the root, not from inside `tests/`. |

---

## 7. Safety

`testdata/vuln-flask` and `testdata/vuln-express` are **deliberately
vulnerable**. Do not deploy them, do not expose them to a network, and only run
generated PoC commands against a local instance you control.
