"""The demo script: what is shown, what is said, and which requirement it proves.

Owner: Member 7 (UI + QA + Docs).

One list of scenes drives everything -- the narration audio, the video timing
and the companion document -- so the three can never disagree. Each scene:

    id          used for the capture file and the audio file
    requirement which box on the hackathon slide this scene proves
    narration   spoken by the TTS voice; its length sets the scene's duration
    action      what the recorder does on screen

Scene duration is NOT hardcoded. It comes from the length of the synthesised
narration plus a small pad, so the picture always fits the words.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine import config  # noqa: E402

config.load_dotenv()


@dataclass
class Scene:
    id: str
    title: str
    requirement: str
    narration: str
    kind: str = "terminal"          # terminal | browser | title
    # terminal scenes replay a captured command; browser scenes drive the app
    capture: str = ""               # which demo/captures/<name>.txt to replay
    url: str = ""
    steps: list[dict[str, Any]] = field(default_factory=list)
    pad_seconds: float = 1.2        # breathing room after the narration ends


DASHBOARD = os.environ.get("DEMO_DASHBOARD_URL", "http://localhost:5173")
API = os.environ.get("DEMO_API_URL", "http://localhost:8000")

# Not hardcoded: DefectDojo's published port moves whenever something else
# claims 8080, and a wrong port here films a 404 rather than the tickets.
DEFECTDOJO = os.environ.get("DEFECTDOJO_URL", "http://localhost:8080")

SCENES: list[Scene] = [

    Scene(
        id="00_title",
        title="Multi-Stage Agentic SAST Engine",
        requirement="—",
        kind="title",
        narration=(
            "This is a multi-stage agentic static analysis engine. "
            "Prepare, Scan, Validate, Prove. "
            "It finds vulnerabilities in source code, and then it reasons about "
            "which of them are actually exploitable."),
    ),

    Scene(
        id="01_problem",
        title="The problem",
        requirement="—",
        kind="title",
        narration=(
            "The problem with a normal scanner is not that it misses bugs. "
            "It is that it reports two hundred findings, most of them already "
            "defended. Developers stop reading at twenty, and the real bug at "
            "number forty ships to production. "
            "So we split the job in two: finding a suspicious path, and judging "
            "whether it is exploitable."),
    ),

    Scene(
        id="02_scan",
        title="Stages one and two",
        requirement="REQ-1, 2, 11, 14",
        kind="terminal",
        capture="02_scan",
        narration=(
            "Here is a real scan of a deliberately vulnerable Flask service. "
            "Stage one builds a Code Property Graph from the source. No build, "
            "no pip install, and the code being scanned is never executed. "
            "Stage two walks that graph tracing attacker input to dangerous "
            "calls, and reports seventeen suspicious paths."),
    ),

    Scene(
        id="03_suppressed",
        title="Stage three: the reasoning",
        requirement="REQ-3, 12",
        kind="terminal",
        capture="03_suppressed",
        narration=(
            "Now the part that matters. Of those seventeen, eleven are confirmed "
            "and six are suppressed, and every suppression carries a written "
            "reason. The value passes through shell quote, which is the correct "
            "defence. The call sits in a branch that can never execute. "
            "A regular expression cannot say that."),
    ),

    Scene(
        id="04_joern",
        title="Swap the whole front end",
        requirement="REQ-10",
        kind="terminal",
        capture="04_joern",
        narration=(
            "This same scan, run through Joern instead. Joern is a mature code "
            "property graph tool with its own inter-procedural data flow engine. "
            "Stages one and two are completely replaced, stages three and four "
            "are untouched, and the result is identical. That is the evidence "
            "the validation stage is the contribution, not the parser."),
    ),

    Scene(
        id="05_comparison",
        title="Against the baseline",
        requirement="REQ-6, 15",
        kind="terminal",
        capture="05_comparison",
        narration=(
            "And here is the comparison against both baselines. Joern finds "
            "everything but reports five false positives. Semgrep is cleaner but "
            "misses four real bugs. After our validation stage: eleven true "
            "positives, zero false positives, nothing missed. "
            "Precision up thirty-one points on Joern, and recall did not move."),
    ),

    Scene(
        id="06_dashboard_scans",
        title="The dashboard",
        requirement="REQ-1, 11",
        kind="browser",
        url=f"{DASHBOARD}/",
        narration=(
            "The same engine drives a dashboard. Here is the scan history, and "
            "the Code Property Graph statistics for a run: the nodes, the edges, "
            "the functions and the HTTP routes it discovered."),
        steps=[
            {"do": "goto", "url": f"{DASHBOARD}/"},
            {"do": "wait", "ms": 1500},
            {"do": "click_text", "text": "vuln-flask", "optional": True},
            {"do": "wait", "ms": 2000},
            {"do": "scroll", "y": 400},
        ],
    ),

    Scene(
        id="07_finding",
        title="One finding, end to end",
        requirement="REQ-2, 3, 5",
        kind="browser",
        url=f"{DASHBOARD}/",
        narration=(
            "Opening a single finding shows the whole chain. The taint path, step "
            "by step, from the query string into the variable and on into the "
            "dangerous call. The verdict, with its reasoning. A proof of concept "
            "built from the real route and the real parameter. And a suggested "
            "fix that names the actual variable."),
        steps=[
            {"do": "click_tab", "text": "Findings"},
            {"do": "wait", "ms": 1200},
            {"do": "click_row", "index": 0},
            {"do": "wait", "ms": 1500},
            {"do": "scroll", "y": 500},
            {"do": "wait", "ms": 1500},
            {"do": "scroll", "y": 1100},
        ],
    ),

    Scene(
        id="08_comparison_tab",
        title="Comparison, on screen",
        requirement="REQ-6, 15",
        kind="browser",
        url=f"{DASHBOARD}/",
        narration=(
            "The comparison is in the dashboard too. Joern, Semgrep, our pattern "
            "matching, and our output after validation. Look at the last column: "
            "recall never moves. Suppressing everything would give perfect "
            "precision and be completely useless, so that is the number we guard "
            "with a test."),
        steps=[
            {"do": "click_tab", "text": "vs Baseline SAST"},
            {"do": "wait", "ms": 2000},
            {"do": "scroll", "y": 350},
        ],
    ),

    Scene(
        id="09_dedupe",
        title="Cross-repo deduplication",
        requirement="REQ-4, 7",
        kind="browser",
        url=f"{DASHBOARD}/",
        narration=(
            "The same command injection exists in the Python service and in the "
            "Node service. We fingerprint on the vulnerability class, the input "
            "source and the shape of the code, never on file paths. So the Python "
            "and JavaScript copies of one bug collapse into a single cluster. "
            "One remediation ticket, not three."),
        steps=[
            {"do": "click_tab", "text": "Deduplication"},
            {"do": "wait", "ms": 1800},
            {"do": "scroll", "y": 450},
        ],
    ),

    Scene(
        id="10_gate",
        title="The human-approval gate",
        requirement="REQ-8",
        kind="browser",
        url=f"{DASHBOARD}/",
        narration=(
            "Every confirmed finding gets a suggested fix, and nothing applies it "
            "automatically. Watch: applying the fix before approval is refused "
            "outright. A human approves, and only then does the engine hand over "
            "a patch. It still does not edit your source. That gate is enforced "
            "in code, not in a process document."),
        # Approving triggers a list refresh that closes the detail panel, so
        # the row has to be re-opened before the fix can be applied. That is
        # the app's real behaviour, not a workaround -- the video shows it.
        steps=[
            {"do": "click_tab", "text": "Findings"},
            {"do": "wait", "ms": 1000},
            {"do": "click_row", "index": 0},
            {"do": "wait", "ms": 1200},
            {"do": "scroll_to_text", "text": "Human approval gate"},
            {"do": "wait", "ms": 900},
            {"do": "click_button", "text": "Apply approved fix", "exact": True},
            {"do": "wait", "ms": 2600},
            {"do": "click_button", "text": "Approve", "exact": True},
            {"do": "wait", "ms": 2600},
            {"do": "click_row", "index": 0},
            {"do": "wait", "ms": 1200},
            {"do": "scroll_to_text", "text": "Human approval gate"},
            {"do": "wait", "ms": 700},
            {"do": "click_button", "text": "Apply approved fix", "exact": True},
            {"do": "wait", "ms": 3000},
        ],
    ),

    Scene(
        id="11_sla",
        title="SLA and escalation",
        requirement="REQ-9",
        kind="browser",
        url=f"{DASHBOARD}/",
        narration=(
            "Each finding is also on a clock. Critical gets twenty-four hours, "
            "high gets seventy-two. A finding that outlives its budget breaches "
            "and escalates to a named owner. Applying a fix stops the clock."),
        steps=[
            {"do": "click_tab", "text": "Approvals & SLA"},
            {"do": "wait", "ms": 1800},
            {"do": "scroll", "y": 600},
        ],
    ),

    Scene(
        id="12_defectdojo",
        title="Live DefectDojo",
        requirement="REQ-13",
        kind="browser",
        url=f"{DASHBOARD}/",
        narration=(
            "Confirmed findings are pushed into DefectDojo over its API, live, "
            "right now. The engine creates the product and the engagement, "
            "imports the findings, and then reads them back from the server to "
            "confirm what actually landed. Submitted and stored are counted "
            "separately, because DefectDojo can accept a finding and still "
            "merge it into an existing one."),
        # This scene really presses the button. Filming a push that happened
        # yesterday would prove nothing that a screenshot could not fake.
        steps=[
            {"do": "click_tab", "text": "DefectDojo"},
            {"do": "wait", "ms": 1800},
            {"do": "click_button", "text": "Push to DefectDojo"},
            {"do": "wait", "ms": 6000},
            {"do": "scroll", "y": 400},
        ],
    ),

    Scene(
        id="13_defectdojo_ui",
        title="The tickets, in DefectDojo itself",
        requirement="REQ-13",
        kind="browser",
        url=f"{DEFECTDOJO}/",
        narration=(
            "And this is DefectDojo itself, not our copy of it. The findings are "
            "really there, with their severities, their CWE identifiers and the "
            "file and line they came from."),
        steps=[
            {"do": "goto", "url": f"{DEFECTDOJO}/login?next=/"},
            {"do": "wait", "ms": 2500},
            {"do": "login_defectdojo"},
            {"do": "wait", "ms": 3500},
            {"do": "goto", "url": f"{DEFECTDOJO}/finding/open"},
            {"do": "wait", "ms": 3500},
            {"do": "scroll", "y": 300},
        ],
    ),

    Scene(
        id="14_tests",
        title="Every requirement, tested",
        requirement="REQ-16",
        kind="terminal",
        capture="14_tests",
        narration=(
            "Finally, the evidence. Every box on the hackathon slide has a test "
            "that proves it, and the traceability matrix is generated from a real "
            "run rather than written by hand. Fourteen requirements fully met, "
            "two partial, none failing."),
    ),

    Scene(
        id="15_close",
        title="Summary",
        requirement="—",
        kind="title",
        narration=(
            "Four stages. Two interchangeable analysis engines. A real baseline "
            "comparison, cross-repository deduplication, an enforced approval "
            "gate, an SLA clock, and live ticket import. "
            "One hundred percent of false positives removed, at zero cost to "
            "recall."),
    ),
]


def scene_by_id(scene_id: str) -> Scene:
    for scene in SCENES:
        if scene.id == scene_id:
            return scene
    raise KeyError(scene_id)
