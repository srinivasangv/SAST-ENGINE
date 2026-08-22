# Environment Setup

Everything you need on a clean machine, in order. Each step has a **verify**
command — run it before moving on. If the verify command fails, fix that step
rather than continuing; every later step assumes it worked.

Time to complete on a fresh machine: about 10 minutes, most of it waiting for
`pip install`.

---

## 1. Prerequisites

| Software | Version used | Why |
|---|---|---|
| Python | 3.12.3 (3.10+ works) | The whole engine. `ast`, `http.server`, `json` are all standard library. |
| Node.js | 24.15.0 (18+ works) | Only to build and serve the React dashboard. The engine never needs it. |
| npm | 11.12.1 | Ships with Node. |
| git | any | To clone the repository. |

### Install on Ubuntu / WSL

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git curl

# Node.js 24 from NodeSource
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install -y nodejs
```

### Install on macOS

```bash
brew install python@3.12 node git
```

### Install on Windows

Use WSL2 with Ubuntu and follow the Ubuntu instructions. Native Windows works
too, but the commands in these docs assume a POSIX shell.

**Verify:**

```bash
python3 --version     # expect Python 3.10 or newer
node --version        # expect v18 or newer
npm --version
git --version
```

---

## 2. Get the code

```bash
git clone <your-repository-url> sast-engine
cd sast-engine
```

**Verify:** `ls` shows `engine/`, `ui/`, `testdata/`, `tests/`, `docs/`,
`scan.py`, `server.py`, `requirements.txt`.

---

## 3. Python virtual environment

A virtual environment keeps these three packages out of your system Python.

```bash
python3 -m venv .venv
```

Activating is optional — every command in these docs calls `.venv/bin/python`
directly, which works without activation and is harder to get wrong. If you
prefer to activate:

```bash
source .venv/bin/activate          # Linux / macOS
.venv\Scripts\activate             # Windows
```

**Verify:**

```bash
.venv/bin/python --version
```

---

## 4. Python dependencies

There are only three, and the engine runs without two of them.

```bash
.venv/bin/pip install -r requirements.txt
```

| Package | Needed for | What happens without it |
|---|---|---|
| `anthropic` | Stage 3 LLM validation | The offline rule-based validator runs instead. |
| `semgrep` | The baseline comparison | The comparison section is skipped and says so. |
| `pytest` | The test suite | The engine runs; you just cannot run the tests. |

This takes a few minutes — Semgrep is a large install.

**Verify:**

```bash
.venv/bin/python -c "import anthropic; print('anthropic ok')"
.venv/bin/semgrep --version        # expect 1.100 or newer
.venv/bin/pytest --version         # expect 8.0 or newer
```

---

## 5. Claude API key (optional but recommended)

Stage 3 uses Claude to reason about whether a finding is really exploitable.

```bash
export ANTHROPIC_API_KEY="sk-ant-..."

# To make it permanent:
echo 'export ANTHROPIC_API_KEY="sk-ant-..."' >> ~/.bashrc
```

**Everything works without a key.** The engine detects the missing key and
uses the offline rule-based validator instead, tagging each verdict so you can
see which one ran. The demo script deliberately includes a run with the key
unset, because that is the honest way to show the fallback works.

**Verify:**

```bash
.venv/bin/python -c "from engine import config; print('LLM configured:', config.llm_available())"
```

> ⚠️ **A key that is present but invalid is a different case.** The engine
> catches the 401, falls back, and records `fallback_reason` on the verdict.
> If you see `validated by: offline` when you expected Claude, look for
> `fallback_reason` in `data/scans/<id>.json` — it will tell you exactly why.

---

## 6. Semgrep rule pack

Semgrep downloads `p/security-audit` from its registry on first use and caches
it. Do this once, on a machine with internet, before the demo.

```bash
.venv/bin/semgrep --config p/security-audit --json --quiet testdata/vuln-flask > /dev/null
echo "exit code: $?"
```

**Verify:** exit code 0 or 1 (1 just means it found something). A network
error here means the comparison will be skipped later — run the scan with
`--no-baseline` if you are offline.

---

## 7. Dashboard dependencies

```bash
cd ui
npm install
cd ..
```

**Verify:**

```bash
cd ui && npm run build && cd ..
```

Expect `✓ built in ...` and a `ui/dist/` directory.

---

## 8. Joern (optional — the primary baseline)

Joern is a CPG-based analyser with its own inter-procedural data-flow engine.
It is what `--engine joern` and the baseline comparison use. **Everything
works without it** — the engine falls back to the builtin parser and says so.

It needs a JDK and about 2 GB of disk.

```bash
mkdir -p ~/.local/opt && cd ~/.local/opt

# A private JDK 21, so we do not fight the system Java
URL=$(curl -s "https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=x64&image_type=jdk&os=linux&vendor=eclipse" \
      | python3 -c "import sys,json;print(json.load(sys.stdin)[0]['binary']['package']['link'])")
curl -sL -o jdk21.tar.gz "$URL" && tar xzf jdk21.tar.gz && rm jdk21.tar.gz && mv jdk-21* jdk21

# Joern itself (~1.8 GB)
curl -sLO https://github.com/joernio/joern/releases/latest/download/joern-cli-linux-x86_64.zip
python3 -c "import zipfile; zipfile.ZipFile('joern-cli-linux-x86_64.zip').extractall('.')"

# REQUIRED: Python's zipfile does not preserve the executable bit, and the
# release ships as a zip. Without this, joern fails with 'Permission denied'
# on bin/repl-bridge and again on each language frontend.
cd joern-cli && find . -type d -name bin -exec chmod -R +x {} \; \
  && find . -maxdepth 1 -type f ! -name "*.jar" ! -name "*.bat" -exec chmod +x {} \;

export JAVA_HOME=~/.local/opt/jdk21
echo 'export JAVA_HOME=~/.local/opt/jdk21' >> ~/.bashrc
```

**Verify:**

```bash
cd ~/projects/sast-engine
JAVA_HOME=~/.local/opt/jdk21 .venv/bin/python -c \
  "from engine import joern_engine as j; print('joern available:', j.joern_available())"
```

The engine looks in `$JOERN_HOME`, then `~/.local/opt/joern-cli`, then `PATH`.

> A Joern scan takes about 15 seconds and up to 4 GB of heap on a small
> repository, against about 15 milliseconds for the builtin engine. Cap the
> heap with `JOERN_HEAP=2g` on a constrained machine.

---

## 9. DefectDojo (optional — live ticket import)

Without it, findings are written as a Generic Findings Import file you can
upload by hand. With it, the engine creates the product and engagement and
imports over the API.

```bash
mkdir -p ~/defectdojo && cd ~/defectdojo
curl -sL -o docker-compose.yml \
  https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/docker-compose.yml

docker compose pull                 # ~2 GB of images
docker compose up -d --no-build     # --no-build: use the published images

# The initializer generates the admin password and prints it exactly once
docker compose logs initializer | grep -i "Admin password"
```

Then trade that password for an API token:

```bash
cd ~/projects/sast-engine
.venv/bin/python -c "
from engine import defectdojo as dd
r = dd.fetch_token('http://localhost:8080', 'admin', 'PASTE_THE_PASSWORD')
print(r)
open('$HOME/.dd_token','w').write(r['token']) if r['ok'] else None
"
```

The token is read from `DEFECTDOJO_TOKEN` or `~/.dd_token`; the URL from
`DEFECTDOJO_URL` (default `http://localhost:8080`).

> **If port 8080 is already taken.** DefectDojo's nginx container exits
> silently when it cannot bind, and the rest of its stack keeps running — so
> `docker ps` looks healthy while nothing serves the UI, and something
> unrelated may already have claimed the port. This happened on the build
> machine. The fix is two lines that must agree with each other:
>
> ```bash
> # 1. pick a free port for DefectDojo
> sed -i 's/^DD_PORT=8080$/DD_PORT=8083/' ~/defectdojo/.env
> cd ~/defectdojo && docker compose up -d nginx
>
> # 2. tell the engine where it moved to
> echo 'DEFECTDOJO_URL=http://localhost:8083' >> .env.local
> ```
>
> Check with `./services.sh status`, which reads the URL from `.env.local`
> rather than assuming 8080.

**Verify:**

```bash
.venv/bin/python -c "from engine import defectdojo; print(defectdojo.health())"
# {'reachable': True, 'authenticated': True, 'url': 'http://localhost:8080'}
```

> The stack is six containers and wants roughly 2–3 GB of RAM. `docker compose
> down` stops it; `docker compose down -v` also deletes its database.

---

## 10. Prove the whole environment works

```bash
.venv/bin/python -m pytest tests/ -q
```

**Expected: `153 passed`.** If every test passes, the environment is correct
and you can move on to [setup-application.md](setup-application.md).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'engine'` | Running from the wrong directory. | `cd` to the repository root. Every command runs from there. |
| `.venv/bin/python: No such file or directory` | Step 3 was skipped, or you are not in the repository root. | Re-run `python3 -m venv .venv` from the root. |
| `semgrep: command not found` | Looking on `PATH` instead of in the venv. | Use `.venv/bin/semgrep`. The engine finds it automatically. |
| Semgrep step hangs | No internet for the registry download. | Scan with `--no-baseline`. |
| `npm install` fails with a permissions error | npm's global cache is root-owned. | `sudo chown -R $(whoami) ~/.npm` |
| Port 8000 already in use | Something else is on it. | Change `SERVER_PORT` in `engine/config.py`, and the proxy target in `ui/vite.config.js`. |
| `validated by: offline` when a key is set | The key is invalid, expired, or rate-limited. | Check `fallback_reason` in the scan JSON. |
| Tests fail with `FileNotFoundError: testdata/...` | Running pytest from inside `tests/`. | Run `.venv/bin/python -m pytest tests/` from the root. |
| `joern: Permission denied` on `repl-bridge` or a frontend | Python's `zipfile` dropped the executable bit. | Re-run the `chmod -R +x` step in section 8. |
| Joern finds 0 flows | Usually a query bug, not an install problem. | The traversals must be `def` not `val`, and `get` must not be a sink name. See QA-014 and QA-015. |
| Joern is killed part-way | Not enough heap. | `JOERN_HEAP=2g`, or close other containers. |
| DefectDojo `import-scan` returns 400 | A field the Generic schema rejects. | The error names the field. We hit this with `duplicate` (QA-019). |
| `docker compose up` tries to build images | The compose file has `build:` sections. | Use `docker compose up -d --no-build` after `docker compose pull`. |
