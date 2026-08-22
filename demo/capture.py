#!/usr/bin/env python3
"""Run the real commands and save their real output for the video to replay.

Owner: Member 7 (UI + QA + Docs).

Playwright can film a browser, but it cannot film a terminal. Rather than
type fake output into a fake terminal -- which would make every number in the
video unverifiable -- we run the actual commands here, save their actual
stdout, and the video replays that text with a typing animation.

So: the text on screen is real output from a real run on this machine. Only
the typing effect is synthetic, and `docs/demo-video.md` says so plainly.

Each capture records the command, its exit code, its real wall-clock time and
its full stdout+stderr, so nothing can be quietly edited afterwards without
the timing and exit code disagreeing.

    python demo/capture.py             # capture everything
    python demo/capture.py 02_scan     # re-capture one
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPTURE_DIR = Path(__file__).resolve().parent / "captures"

PYTHON = str(ROOT / ".venv" / "bin" / "python")
if not Path(PYTHON).exists():
    PYTHON = sys.executable

# Joern needs a JDK. The engine finds it the same way, so if this is wrong the
# joern capture fails loudly here rather than producing an empty scene.
JAVA_HOME = str(Path.home() / ".local" / "opt" / "jdk21")

# The command each terminal scene shows. `display` is what appears at the
# prompt in the video -- the same command, minus the venv path noise.
CAPTURES: dict[str, dict] = {
    "02_scan": {
        "display": "python scan.py testdata/vuln-flask --no-baseline",
        "argv": [PYTHON, "scan.py", "testdata/vuln-flask", "--no-baseline"],
        "note": "Stages 1-4 on the vulnerable Flask service",
    },
    "03_suppressed": {
        "display": "python scan.py testdata/vuln-flask --no-baseline --show-suppressed",
        "argv": [PYTHON, "scan.py", "testdata/vuln-flask", "--no-baseline",
                 "--show-suppressed"],
        "note": "Every suppression, with the reason the validator gave",
    },
    "04_joern": {
        "display": "python scan.py testdata/vuln-flask --engine joern --no-baseline",
        "argv": [PYTHON, "scan.py", "testdata/vuln-flask", "--engine", "joern",
                 "--no-baseline"],
        "note": "Stages 1-2 replaced by Joern; stages 3-4 untouched",
        "timeout": 900,
    },
    "05_comparison": {
        "display": "python scan.py testdata/vuln-flask --with-semgrep",
        "argv": [PYTHON, "scan.py", "testdata/vuln-flask", "--with-semgrep"],
        "note": "Our result against Joern and Semgrep on the same corpus",
        "timeout": 900,
    },
    # `-q` on the whole suite prints three rows of dots, which proves the
    # suite is green but shows nothing about WHAT is covered. The requirement
    # tests are named for the slide boxes they prove, so list those by name
    # and then print the one-line total underneath.
    "14_tests": {
        "display": "python -m pytest tests/test_requirements.py -v  &&  pytest tests/ -q",
        "argv": ["bash", "-c",
                 f'{PYTHON} -m pytest tests/test_requirements.py -v --no-header '
                 f'-p no:cacheprovider 2>&1 | grep -E "test_req_|passed" '
                 f'| sed "s/tests\\/test_requirements.py:://"; '
                 f'echo; echo "  whole suite:"; '
                 f'{PYTHON} -m pytest tests/ -q 2>&1 | tail -1'],
        "note": "One test per box on the hackathon slide, then the whole suite",
        "timeout": 2400,
    },
}


def run_capture(name: str, spec: dict) -> dict:
    """Run one command and write its output to demo/captures/<name>.txt."""
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["JAVA_HOME"] = JAVA_HOME
    env["PATH"] = f"{JAVA_HOME}/bin:" + env.get("PATH", "")
    # Colour codes would show up as escape gibberish in the HTML player.
    env["NO_COLOR"] = "1"
    env["PY_COLORS"] = "0"

    print(f"  $ {spec['display']}")
    started = time.time()
    proc = subprocess.run(
        spec["argv"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=spec.get("timeout", 600),
    )
    elapsed = time.time() - started
    output = proc.stdout + (proc.stderr if proc.returncode else "")

    (CAPTURE_DIR / f"{name}.txt").write_text(output)
    meta = {
        "name": name,
        "command": spec["display"],
        "note": spec["note"],
        "exit_code": proc.returncode,
        "seconds": round(elapsed, 1),
        "lines": len(output.splitlines()),
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    (CAPTURE_DIR / f"{name}.json").write_text(json.dumps(meta, indent=2))

    status = "ok" if proc.returncode in (0, 1) else f"EXIT {proc.returncode}"
    print(f"    -> {meta['lines']} lines in {elapsed:.1f}s  [{status}]")
    if not output.strip():
        print(f"    ! {name} produced NO output -- that scene would be blank")
    return meta


def main() -> int:
    wanted = sys.argv[1:] or list(CAPTURES)
    unknown = [name for name in wanted if name not in CAPTURES]
    if unknown:
        print(f"unknown capture(s): {', '.join(unknown)}")
        print(f"available: {', '.join(CAPTURES)}")
        return 2

    print(f"Capturing {len(wanted)} command(s) for the demo video\n")
    results = []
    for name in wanted:
        try:
            results.append(run_capture(name, CAPTURES[name]))
        except subprocess.TimeoutExpired:
            print(f"    ! {name} timed out -- scene will be missing")
        except FileNotFoundError as error:
            print(f"    ! {name} could not run: {error}")

    print(f"\nCaptured {len(results)}/{len(wanted)} into {CAPTURE_DIR}")
    return 0 if len(results) == len(wanted) else 1


if __name__ == "__main__":
    raise SystemExit(main())
