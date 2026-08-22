"""Joern-backed Code Property Graph and inter-procedural taint analysis.

Owner: Member 1 (Prepare / CPG) with Member 4 (comparison).

Joern is the real article: a proper CPG with a query language (CPGQL) and its
own inter-procedural data-flow engine. Our `py_parser.py` was written so the
four stages stay explainable in a demo; Joern is what you reach for when you
want depth instead of a readable afternoon.

Both are wired in and every finding records which produced it:

    python scan.py <repo>                  builtin engine (stdlib ast)
    python scan.py <repo> --engine joern   Joern
    python scan.py <repo> --engine both    run both, compare them

How this talks to Joern
-----------------------
`joern` is a Scala REPL. We generate a script, it writes JSON to a file, we
read the file back. No server, no JVM bindings, no protocol.

The script runs three things: every method, every call, and
`reachableByFlows` -- Joern's own taint engine, which computes the data-flow
path across functions and files for us. We translate those flows into the same
finding dictionary Stage 2 produces, so Stage 3 validates a Joern finding with
exactly the same code that validates ours.

Two hard-won details, both of which silently return zero results:

1.  A Joern traversal is a SINGLE-USE iterator. `val src = cpg.call...` then
    reading `src.size` for a log line consumes it, and the `reachableByFlows`
    that follows gets an exhausted iterator and finds nothing -- with no error.
    Every traversal below is therefore a `def`, so each use rebuilds it.

2.  `get` must not appear in the SINK name list. `requests.get` is an SSRF
    sink, but `request.args.get` is a source; putting `get` in both sets makes
    the whole query return nothing. SSRF is matched by `methodFullName` in a
    separate query instead.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from . import config, rules
from .cpg import CPG, ParsedRepo

JOERN_TIMEOUT_SECONDS = int(os.environ.get("JOERN_TIMEOUT", "900"))
JOERN_HEAP = os.environ.get("JOERN_HEAP", "4g")

JOERN_SEARCH_PATHS = [
    os.environ.get("JOERN_HOME", ""),
    str(Path.home() / "joern-cli"),
    str(Path.home() / ".local" / "opt" / "joern-cli"),
    str(Path.home() / "bin" / "joern-cli"),
    "/opt/joern/joern-cli",
]

JAVA_SEARCH_PATHS = [
    os.environ.get("JAVA_HOME", ""),
    str(Path.home() / ".local" / "opt" / "jdk21"),
]

# Joern's Python frontend names a call by its last segment: `os.system` is
# `system`, `pickle.loads` is `loads`. These are the sink names we ask for.
# `get`/`post` are deliberately ABSENT -- see the module docstring.
SINK_NAMES = (
    # Python
    "system|eval|exec|execute|executemany|executescript|loads|load|open|"
    "render_template_string|Template|redirect|Popen|check_output|Markup|"
    "mark_safe|send_file|unserialize|"
    # JavaScript / TypeScript
    "execSync|query|raw|readFile|readFileSync|writeFile|writeFileSync|"
    "send|write|sendFile|runInNewContext|find"
)

# Anything whose resolved module is one of these is an outbound-request sink.
SSRF_FULLNAME = r".*(requests|httpx|aiohttp)\\.py.*|.*urlopen.*|.*axios.*"

# subprocess.* is matched by module rather than by name, because `run` and
# `call` are far too common as bare names.
SUBPROCESS_FULLNAME = r".*subprocess\\.py.*"

# The attacker-controlled entry points, matched on the call's source text.
SOURCE_CODE_REGEX = (
    r"(?s).*(request|req)\\.(args|form|values|json|data|files|cookies|headers|"
    r"GET|POST|query|body|params).*"
)


# --------------------------------------------------------------------------
# Locating the toolchain
# --------------------------------------------------------------------------


def detect_language(repo_path: str | Path) -> str:
    """Python or JavaScript, decided by which extension is more common.

    Joern picks its own frontend automatically; we need the language only to
    look the sink up in the right half of the rule table. `exec` is Python's
    code-injection builtin AND JavaScript's `child_process.exec`, which is a
    command injection -- getting this wrong mislabels the CWE.
    """
    root = Path(repo_path)
    counts = {"python": 0, "javascript": 0}
    for path in root.rglob("*"):
        if not path.is_file() or any(part in {".git", "node_modules", ".venv"}
                                     for part in path.parts):
            continue
        suffix = path.suffix.lower()
        if suffix == ".py":
            counts["python"] += 1
        elif suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            counts["javascript"] += 1
    return "javascript" if counts["javascript"] > counts["python"] else "python"


def joern_binary() -> str | None:
    config.load_dotenv()
    search_paths = [os.environ.get("JOERN_HOME", "")] + JOERN_SEARCH_PATHS
    for base in search_paths:
        if base:
            for name in ("joern", "joern.bat", "joern.cmd"):
                for candidate in (
                    Path(base) / name,
                    Path(base) / "joern-cli" / name,
                    Path(base) / "bin" / name,
                ):
                    if candidate.exists():
                        return str(candidate)
    for name in ("joern", "joern.bat", "joern.cmd"):
        which = shutil.which(name)
        if which:
            return which
    return None


def java_home() -> str | None:
    config.load_dotenv()
    search_paths = [os.environ.get("JAVA_HOME", "")] + JAVA_SEARCH_PATHS
    for base in search_paths:
        if base:
            for ext in ("", ".exe"):
                if (Path(base) / "bin" / f"java{ext}").exists():
                    return base
    java = shutil.which("java")
    if java:
        try:
            return str(Path(java).resolve().parent.parent)
        except Exception:
            return None
    return None


def joern_available() -> bool:
    return joern_binary() is not None and java_home() is not None


def joern_version() -> str:
    binary = joern_binary()
    if binary is None:
        return "not installed"
    for name in ("version", "VERSION"):
        candidate = Path(binary).parent / name
        if candidate.exists():
            return candidate.read_text().strip()[:40]
    return "installed"


def unavailable_reason() -> str:
    if joern_binary() is None:
        return ("joern is not installed. Download joern-cli from "
                "github.com/joernio/joern/releases and unpack it to "
                "~/.local/opt/joern-cli, or set JOERN_HOME.")
    if java_home() is None:
        return "no JDK found. Joern needs Java 11+; set JAVA_HOME."
    return ""


def _environment() -> dict[str, str]:
    env = dict(os.environ)
    home = java_home()
    if home:
        env["JAVA_HOME"] = home
        bin_dir = str(Path(home) / "bin")
        env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["JAVA_OPTS"] = f"-Xmx{JOERN_HEAP}"
    return env


# --------------------------------------------------------------------------
# The CPGQL script
# --------------------------------------------------------------------------


def build_script(repo_path: str, output_path: str, project: str) -> str:
    """Generate the Scala script fed to the Joern REPL.

    Note every traversal is a `def`. See the module docstring -- a `val` here
    is consumed by its first use and every later query silently returns zero.
    """
    clean_repo = str(Path(repo_path).resolve()).replace("\\", "/")
    clean_out = str(Path(output_path).resolve()).replace("\\", "/")
    return f'''
import java.io.PrintWriter

importCode(inputPath = "{clean_repo}", projectName = "{project}")

def esc(s: String): String =
  if (s == null) ""
  else s.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"")
        .replace("\\n", " ").replace("\\r", " ").replace("\\t", " ").take(300)

// -- def, never val: a traversal is a single-use iterator ------------------
def srcT  = cpg.call.code("{SOURCE_CODE_REGEX}")
def snkT  = cpg.call.name("{SINK_NAMES}")
def ssrfT = cpg.call.methodFullName("{SSRF_FULLNAME}")
def subT  = cpg.call.methodFullName("{SUBPROCESS_FULLNAME}")

val methods = cpg.method.isExternal(false).l.map {{ m =>
  s"""{{"name":"${{esc(m.name)}}","fullName":"${{esc(m.fullName)}}","file":"${{esc(m.filename)}}","line":${{m.lineNumber.getOrElse(0)}},"lineEnd":${{m.lineNumberEnd.getOrElse(0)}},"params":${{m.parameter.size}}}}"""
}}

val calls = cpg.call.l.map {{ c =>
  s"""{{"name":"${{esc(c.name)}}","methodFullName":"${{esc(c.methodFullName)}}","code":"${{esc(c.code)}}","file":"${{esc(c.file.name.headOption.getOrElse(""))}}","line":${{c.lineNumber.getOrElse(0)}}}}"""
}}

// Three separate flow queries, unioned. Each rebuilds srcT because of the
// single-use rule above.
val rawFlows = snkT.reachableByFlows(srcT).l ++
               ssrfT.reachableByFlows(srcT).l ++
               subT.reachableByFlows(srcT).l

val flows = rawFlows.map {{ fl =>
  val first = fl.elements.head
  val last  = fl.elements.last
  val steps = fl.elements.map {{ e =>
    s"""{{"line":${{e.lineNumber.getOrElse(0)}},"code":"${{esc(e.code)}}","label":"${{esc(e.label)}}"}}"""
  }}.mkString(",")
  s"""{{"line":${{last.lineNumber.getOrElse(0)}},"code":"${{esc(last.code)}}","sourceCode":"${{esc(first.code)}}","sourceLine":${{first.lineNumber.getOrElse(0)}},"steps":[${{steps}}]}}"""
}}

val out = new PrintWriter("{clean_out}")
out.println("{{")
out.println("  \\"methods\\": [" + methods.mkString(",") + "],")
out.println("  \\"calls\\": [" + calls.mkString(",") + "],")
out.println("  \\"flows\\": [" + flows.mkString(",") + "]")
out.println("}}")
out.close()

println("SAST_JOERN_DONE methods=" + methods.size + " calls=" + calls.size + " flows=" + flows.size)
'''


# --------------------------------------------------------------------------
# Running Joern
# --------------------------------------------------------------------------


def run_joern(repo_path: str | Path) -> dict[str, Any]:
    """Build a CPG with Joern and run the queries. Never raises."""
    if not joern_available():
        return {"available": False, "error": unavailable_reason(),
                "methods": [], "calls": [], "flows": []}

    repo = Path(repo_path).resolve()
    started = time.time()
    project = f"sast{int(time.time() * 1000) % 100000}"

    with tempfile.TemporaryDirectory(prefix="joern-") as workdir:
        output_path = str(Path(workdir) / "result.json")
        script_path = Path(workdir) / "query.sc"
        script_path.write_text(build_script(str(repo), output_path, project), encoding="utf-8")

        try:
            completed = subprocess.run(
                [joern_binary(), "--script", str(script_path)],
                capture_output=True, text=True, env=_environment(),
                timeout=JOERN_TIMEOUT_SECONDS,
                # Run inside the temp dir so Joern's `workspace/` folder is
                # created there and cleaned up with it, not in the repository.
                cwd=workdir, check=False,
                shell=(os.name == "nt"))
        except subprocess.TimeoutExpired:
            return {"available": False,
                    "error": f"joern timed out after {JOERN_TIMEOUT_SECONDS}s "
                             f"(raise JOERN_TIMEOUT for a bigger repository)",
                    "methods": [], "calls": [], "flows": []}
        except OSError as exc:
            return {"available": False, "error": f"{type(exc).__name__}: {exc}",
                    "methods": [], "calls": [], "flows": []}

        if not Path(output_path).exists():
            tail = ((completed.stderr or "") + (completed.stdout or ""))[-500:]
            return {"available": False,
                    "error": f"joern wrote no output. {tail.strip()}",
                    "methods": [], "calls": [], "flows": []}

        try:
            payload = json.loads(Path(output_path).read_text())
        except json.JSONDecodeError as exc:
            return {"available": False, "error": f"unparseable joern output: {exc}",
                    "methods": [], "calls": [], "flows": []}

    payload["available"] = True
    payload["duration_ms"] = int((time.time() - started) * 1000)
    payload["version"] = joern_version()
    return payload


# --------------------------------------------------------------------------
# Translating Joern's output into our shapes
# --------------------------------------------------------------------------


def to_parsed_repo(payload: dict[str, Any], repo_path: str | Path,
                   repo_name: str, language: str = "python") -> ParsedRepo:
    """Build a ParsedRepo (for the CPG stats panel) from Joern's output."""
    root = Path(repo_path).resolve()
    cpg = CPG()
    repo = ParsedRepo(name=repo_name, path=str(root), cpg=cpg)

    files: set[str] = set()
    modules: dict[str, int] = {}

    def module_for(file_name: str) -> int:
        if file_name not in modules:
            node = cpg.add_node("MODULE", file_name or "<unknown>", file_name, 1)
            modules[file_name] = node.id
        return modules[file_name]

    for method in payload.get("methods", []):
        file_name = _relative(method.get("file", ""), root)
        if file_name:
            files.add(file_name)
        node = cpg.add_node("FUNCTION", method.get("name", "?"), file_name,
                            int(method.get("line") or 0),
                            code=method.get("fullName", "")[:120])
        cpg.add_edge(module_for(file_name), node.id, "AST")
        for index in range(min(int(method.get("params") or 0), 12)):
            param = cpg.add_node("PARAM", f"param{index}", file_name,
                                 int(method.get("line") or 0))
            cpg.add_edge(node.id, param.id, "AST")

    for call in payload.get("calls", []):
        # Joern models operators (assignment, field access) as calls too.
        # Those are graph plumbing, not something to show in a stats panel.
        if call.get("name", "").startswith("<operator>"):
            continue
        file_name = _relative(call.get("file", ""), root)
        if file_name:
            files.add(file_name)
        node = cpg.add_node("CALL", call.get("name", "?"), file_name,
                            int(call.get("line") or 0), code=call.get("code", ""))
        cpg.add_edge(module_for(file_name), node.id, "AST")

    repo.files = sorted(f for f in files if f)
    repo.languages = {language: len(repo.files)}
    repo.duration_ms = int(payload.get("duration_ms") or 0)

    for file_name in repo.files:
        try:
            repo.file_lines[file_name] = (root / file_name).read_text(
                encoding="utf-8", errors="replace").splitlines()
        except OSError:
            repo.file_lines[file_name] = []

    return repo


def to_findings(payload: dict[str, Any], repo_path: str | Path,
                repo_name: str, language: str = "python") -> list[dict[str, Any]]:
    """Turn Joern's data-flow results into our finding dictionary."""
    root = Path(repo_path).resolve()

    # Joern's flow elements carry a line and the code, but not the file. Join
    # them back to the call list, which does, on (line, code).
    call_index: dict[tuple[int, str], dict[str, Any]] = {}
    for call in payload.get("calls", []):
        key = (int(call.get("line") or 0), (call.get("code") or "").strip())
        call_index.setdefault(key, call)

    method_spans = [
        (_relative(m.get("file", ""), root), int(m.get("line") or 0),
         int(m.get("lineEnd") or 0), m.get("name", ""))
        for m in payload.get("methods", [])
    ]

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for flow in payload.get("flows", []):
        line = int(flow.get("line") or 0)
        code = (flow.get("code") or "").strip()
        call = call_index.get((line, code), {})

        sink_name, category = _classify(call, code, language)
        if category is None:
            continue

        file_name = _relative(call.get("file", ""), root)
        if not file_name:
            file_name = _file_for_line(method_spans, line)

        key = f"{file_name}:{line}:{sink_name}:{category}"
        if key in seen:
            continue
        seen.add(key)

        meta = rules.vuln_class(category)
        steps = _steps(flow, file_name, sink_name)
        source_label, source_pattern = _source_of(flow, language)
        sanitizers = _sanitizers_on(flow, language)
        function = _method_for_line(method_spans, file_name, line)
        flags = structural_flags(root, file_name, line, language)

        findings.append({
            "id": hashlib.sha256(f"{repo_name}:{key}".encode()).hexdigest()[:12],
            "repo": repo_name,
            "category": category,
            "title": meta["title"],
            "cwe": meta["cwe"],
            "owasp": meta["owasp"],
            "severity": meta["severity"],
            "why_dangerous": meta["why"],

            "file": file_name,
            "line": line,
            "function": function,
            "sink": sink_name,
            "sink_code": code,
            "language": language,

            "entry": f"data flow traced by Joern from {source_label} "
                     f"into {function}() across {len(steps)} steps",
            "http_reachable": bool(source_pattern),
            "route_path": "",
            "route_methods": [],
            "source_label": source_label,
            "source_pattern": source_pattern,

            "sanitizers": sanitizers,
            "sanitizer_covers_sink": any(
                rules.sanitizer_covers(name, category, language) for name in sanitizers),
            "guarded": flags["guarded"],
            "unreachable": flags["unreachable"],

            "taint_path": steps,
            "snippet": _snippet(root, file_name, line),

            "stage": "scan",
            "status": "unvalidated",
            "engine": "joern",
        })

    return findings


# --------------------------------------------------------------------------
# Structural context Joern's flow output does not carry
# --------------------------------------------------------------------------


def structural_flags(root: Path, file_name: str, line: int,
                     language: str) -> dict[str, bool]:
    """Is this sink inside dead code, and was the value checked first?

    Joern gives us an excellent data-flow path and nothing else. Its
    `reachableByFlows` result says the value CAN reach the sink; it does not
    say the branch is `if False:` or that an allowlist test rejects the
    request two lines earlier. Our own engine knows both, because it walks
    the AST.

    Without this, DECOY-3 (allowlist) and DECOY-4 (dead code) survive
    validation on the Joern path -- the deterministic validator cannot
    suppress what it was never told. So we do one cheap `ast` pass over the
    single file and recover the two facts. Joern supplies the data flow; the
    AST supplies the structure.

    Python only. For other languages both flags stay False and the finding is
    simply judged on the rest of its evidence.
    """
    flags = {"guarded": False, "unreachable": False}
    if language != "python" or line <= 0:
        return flags

    try:
        source = (root / file_name).read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return flags

    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue

        body_lines = [n.lineno for n in ast.walk(node) if hasattr(n, "lineno")]
        if not body_lines:
            continue
        covers_sink = min(body_lines) <= line <= max(body_lines)

        # (a) dead code: `if False:` / `if 0:` with the sink inside the body
        if isinstance(node.test, ast.Constant) and not node.test.value:
            in_body = any(
                inner.lineno <= line <= getattr(inner, "end_lineno", inner.lineno)
                for stmt in node.body for inner in ast.walk(stmt)
                if hasattr(inner, "lineno"))
            if in_body:
                flags["unreachable"] = True

        # (b) a guard: a test BEFORE the sink whose body bails out. That is
        # the shape of `if value not in ALLOWED: return 400`.
        if node.test.lineno < line and not covers_sink:
            bails = any(isinstance(stmt, (ast.Return, ast.Raise, ast.Continue))
                        for stmt in node.body)
            if bails:
                flags["guarded"] = True

    return flags


# --------------------------------------------------------------------------
# Classification and small helpers
# --------------------------------------------------------------------------


def _classify(call: dict[str, Any], code: str,
              language: str = "python") -> tuple[str, str | None]:
    """Work out our sink name and vulnerability class for a Joern call.

    Joern reports a bare name (`system`, `get`, `load`), which is ambiguous:
    `get` is `requests.get` (SSRF) in one place and `request.args.get` (a
    source) in another. `methodFullName` disambiguates -- it carries the
    resolved module, e.g. `os.py:<module>.system`.
    """
    full_name = call.get("methodFullName", "") or ""
    bare = call.get("name", "") or ""

    # Rebuild a dotted name our rule table understands.
    module = ""
    for marker in (".py:", ".js:", ".ts:"):
        if marker in full_name:
            module = full_name.split(marker)[0].split("/")[-1]
            break
    dotted = f"{module}.{bare}" if module and bare else (bare or code.split("(")[0])

    # The call TEXT first, because Joern reports a bare `exec` for both
    # Python's builtin and JavaScript's child_process.exec and only the source
    # line tells them apart -- but matched with rules.matches(), which is
    # dotted-segment aware.
    #
    # A naive `pattern in receiver` here is WRONG and was a real bug: "exec"
    # is a substring of "cursor.execute", so every SQL injection came back
    # labelled CWE-94 code injection instead of CWE-89. rules.matches()
    # requires a whole dotted segment, so "execute" wins and "exec" does not
    # match at all.
    receiver = code.split("(")[0].strip()
    for candidate in (receiver, dotted, bare):
        rule = rules.find_sink(candidate, language)
        if rule is not None:
            return candidate, rule["category"]

    # Last resort only: a substring scan of the whole call text.
    for rule in rules.SINKS:
        if rule["lang"] == language and rule["pattern"] in code:
            return rule["pattern"], rule["category"]

    return dotted or bare, None


def _relative(path: str, root: Path) -> str:
    if not path:
        return ""
    candidate = Path(path)
    try:
        return str(candidate.resolve().relative_to(root))
    except (ValueError, OSError):
        text = str(candidate)
        return text[len(str(root)):].lstrip("/") if text.startswith(str(root)) else text


def _file_for_line(spans: list[tuple[str, int, int, str]], line: int) -> str:
    for file_name, start, end, _ in spans:
        if start <= line <= (end or start):
            return file_name
    return spans[0][0] if spans else ""


def _method_for_line(spans: list[tuple[str, int, int, str]], file_name: str, line: int) -> str:
    best, best_span = "<module>", None
    for span_file, start, end, name in spans:
        if span_file != file_name or not (start <= line <= (end or start)):
            continue
        size = (end or start) - start
        if best_span is None or size < best_span:
            best, best_span = name, size
    return best


def _steps(flow: dict[str, Any], file_name: str, sink_name: str) -> list[dict[str, Any]]:
    raw = flow.get("steps", []) or []
    steps = []
    for index, element in enumerate(raw):
        code = (element.get("code", "") or "").strip()
        if index == 0:
            description = "attacker-controlled value enters here (Joern data-flow source)"
        elif index == len(raw) - 1:
            description = f"reaches the dangerous call `{sink_name}()`"
        else:
            label = (element.get("label", "") or "expression").lower()
            description = f"flows through {label}"
        steps.append({"file": file_name, "line": int(element.get("line") or 0),
                      "code": code, "description": description})
    if not steps:
        steps = [{"file": file_name, "line": int(flow.get("line") or 0),
                  "code": (flow.get("code") or "").strip(),
                  "description": f"reaches the dangerous call `{sink_name}()`"}]
    return steps


def _flow_text(flow: dict[str, Any]) -> str:
    parts = [flow.get("sourceCode", "") or ""]
    parts += [(element.get("code", "") or "") for element in (flow.get("steps", []) or [])]
    return " ".join(parts)


def _source_of(flow: dict[str, Any], language: str = "python") -> tuple[str, str]:
    text = _flow_text(flow)
    for rule in rules.SOURCES:
        if rule["lang"] == language and rule["pattern"] in text:
            return rule["label"], rule["pattern"]
    return "value traced by Joern", ""


def _sanitizers_on(flow: dict[str, Any], language: str = "python") -> list[str]:
    text = _flow_text(flow)
    found = []
    for rule in rules.SANITIZERS:
        if rule["lang"] == language and rule["pattern"] in text:
            found.append(rule["pattern"])
    return list(dict.fromkeys(found))


def _snippet(root: Path, file_name: str, line: int, context: int = 4) -> str:
    try:
        lines = (root / file_name).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not lines or line <= 0:
        return ""
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    return "\n".join(
        f"{'>>' if i == line - 1 else '  '} {i + 1:4d} | {lines[i]}"
        for i in range(start, end))


# --------------------------------------------------------------------------
# The one function the pipeline calls
# --------------------------------------------------------------------------


def prepare_and_scan(repo_path: str | Path, repo_name: str) -> dict[str, Any]:
    """Run Joern end to end. Returns available=False rather than raising."""
    payload = run_joern(repo_path)
    if not payload.get("available"):
        return {"available": False, "error": payload.get("error", "joern unavailable")}

    language = detect_language(repo_path)
    return {
        "available": True,
        "language": language,
        "repo": to_parsed_repo(payload, repo_path, repo_name, language),
        "findings": to_findings(payload, repo_path, repo_name, language),
        "raw": {"methods": len(payload.get("methods", [])),
                "calls": len(payload.get("calls", [])),
                "flows": len(payload.get("flows", []))},
        "duration_ms": payload.get("duration_ms", 0),
        "version": payload.get("version", ""),
    }
