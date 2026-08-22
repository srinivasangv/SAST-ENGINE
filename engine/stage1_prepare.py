"""STAGE 1 of 4 -- PREPARE.

Owner: Member 1 (Prepare / CPG).

Find the source files, parse them, build the Code Property Graph.

Nothing here installs a package, runs a build, or executes the code being
scanned. We only read text. That is what lets the scanner point at an
arbitrary checkout and produce a graph in a couple of seconds.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import config
from .cpg import CPG, ParsedRepo
from .js_parser import JavaScriptParser
from .py_parser import PythonParser


def prepare(repo_path: str | Path, repo_name: str | None = None,
            include_tests: bool = False) -> ParsedRepo:
    """Parse a repository and return everything Stage 2 needs."""
    started = time.time()
    root = Path(repo_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"repository path does not exist: {root}")

    cpg = CPG()
    python_parser = PythonParser(cpg)
    js_parser = JavaScriptParser(cpg)

    repo = ParsedRepo(name=repo_name or root.name, path=str(root), cpg=cpg)

    for path in discover_files(root, include_tests=include_tests):
        rel_path = str(path.relative_to(root))
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            repo.parse_errors.append({"file": rel_path, "error": str(exc)})
            continue

        suffix = path.suffix.lower()
        if suffix in config.PYTHON_EXTENSIONS:
            functions, error = python_parser.parse_file(rel_path, source)
            language = "python"
        else:
            functions, error = js_parser.parse_file(rel_path, source)
            language = "javascript"

        if error:
            # A broken file must not stop the scan -- record it and keep going.
            repo.parse_errors.append({"file": rel_path, "error": error})
            continue

        repo.files.append(rel_path)
        repo.file_lines[rel_path] = source.splitlines()
        repo.functions.extend(functions)
        repo.languages[language] = repo.languages.get(language, 0) + 1

    repo.duration_ms = int((time.time() - started) * 1000)
    return repo


def discover_files(root: Path, include_tests: bool = False) -> list[Path]:
    """Every source file we are willing to parse, in a stable order."""
    wanted = config.PYTHON_EXTENSIONS | config.JS_EXTENSIONS
    found: list[Path] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in config.SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in wanted:
            continue
        if path.name.endswith((".min.js", ".bundle.js", ".d.ts")):
            continue
        if not include_tests and _looks_like_a_test(path):
            continue
        try:
            if path.stat().st_size > config.MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        found.append(path)

    return found


def _looks_like_a_test(path: Path) -> bool:
    lowered = path.as_posix().lower()
    return (
        "/tests/" in lowered or "/test/" in lowered or "/__tests__/" in lowered
        or path.name.startswith("test_")
        or path.name.endswith(("_test.py", ".test.js", ".spec.js", ".test.ts"))
    )
