"""Shared test fixtures.

Owner: Member 7 (UI + QA + Docs).

Every test runs the pipeline with `use_llm=False`. That is deliberate: the
test suite must be deterministic and must pass on a laptop with no API key
and no network. The live Claude path has its own test, and it skips itself
when no key is configured.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine import stage1_prepare, stage2_scan, stage3_validate, stage4_prove  # noqa: E402


@pytest.fixture(scope="session")
def ground_truth() -> dict:
    return json.loads((ROOT / "testdata" / "ground_truth.json").read_text())


@pytest.fixture(scope="session")
def repos() -> dict[str, Path]:
    return {
        "vuln-flask": ROOT / "testdata" / "vuln-flask",
        "vuln-express": ROOT / "testdata" / "vuln-express",
        "safe-app": ROOT / "testdata" / "safe-app",
    }


def _run(path: Path, name: str) -> dict:
    """Stages 1-4 with the deterministic validator."""
    repo = stage1_prepare.prepare(path, repo_name=name)
    raw = stage2_scan.scan(repo)
    raw_snapshot = [dict(finding) for finding in raw]
    stage3_validate.validate(raw, use_llm=False)
    stage4_prove.prove(raw)
    return {
        "repo": repo,
        "raw": raw_snapshot,
        "findings": raw,
        "confirmed": stage3_validate.confirmed_only(raw),
        "suppressed": stage3_validate.suppressed_only(raw),
    }


@pytest.fixture(scope="session")
def flask_scan(repos) -> dict:
    return _run(repos["vuln-flask"], "vuln-flask")


@pytest.fixture(scope="session")
def express_scan(repos) -> dict:
    return _run(repos["vuln-express"], "vuln-express")


@pytest.fixture(scope="session")
def safe_scan(repos) -> dict:
    return _run(repos["safe-app"], "safe-app")


@pytest.fixture(scope="session")
def all_scans(flask_scan, express_scan, safe_scan) -> dict[str, dict]:
    return {
        "vuln-flask": flask_scan,
        "vuln-express": express_scan,
        "safe-app": safe_scan,
    }
