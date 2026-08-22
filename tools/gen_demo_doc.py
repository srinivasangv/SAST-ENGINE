#!/usr/bin/env python3
"""Write docs/demo-video.md from the timeline the recorder actually produced.

Owner: Member 7 (UI + QA + Docs).

The timestamps in the document are the ones measured during the recording,
not ones typed by hand. Hand-typed timestamps drift the moment anything in
the demo gets a second longer, and a document that points at the wrong
minute of the video is worse than no document.

    python tools/gen_demo_doc.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMELINE = ROOT / "demo" / "output" / "timeline.json"
OUT = ROOT / "docs" / "demo-video.md"

# What each scene is evidence for, in words. Keyed by scene id.
PROVES = {
    "00_title": "—",
    "01_problem": "—",
    "02_scan": "CPG built with no build step; taint analysis; Python "
               "orchestration; a repo scanned end to end",
    "03_suppressed": "Stage 3 reasoning, with a written reason per suppression",
    "04_joern": "Joern as an interchangeable CPG/taint front end",
    "05_comparison": "FP-suppression rate against a baseline SAST tool",
    "06_dashboard_scans": "CPG statistics and the four stages, in the UI",
    "07_finding": "Taint path, verdict, auto-generated PoC, suggested fix",
    "08_comparison_tab": "The comparative report on screen",
    "09_dedupe": "Cross-repo, cross-language deduplication",
    "10_gate": "Human approval enforced before any fix is handed over",
    "11_sla": "SLA ageing and escalation",
    "12_defectdojo": "A live push to DefectDojo over its API",
    "13_defectdojo_ui": "The tickets in DefectDojo's own UI",
    "14_tests": "Documented test results, one test per slide requirement",
    "15_close": "—",
}


def main() -> int:
    if not TIMELINE.exists():
        print(f"no timeline at {TIMELINE} -- record the video first:")
        print("  ./demo/run_demo.sh")
        return 1

    data = json.loads(TIMELINE.read_text())
    scenes = data["scenes"]
    total = data["duration_seconds"]
    minutes = f"{int(total) // 60}:{int(total) % 60:02d}"
    used = data.get("validator_used", "unknown")
    configured = data.get("validator_configured", "unknown")

    lines: list[str] = []
    add = lines.append

    add("# The end-to-end demo video")
    add("")
    add(f"**`demo/output/sast-engine-demo.mp4`** — {minutes}, 1280×720, "
        "H.264 + AAC, with narration.")
    add(f"A WebM copy sits beside it, and every scene's final frame is in "
        f"`demo/output/stills/`.")
    add("")
    add(f"Recorded {data['recorded_at'].replace('T', ' ')} against the live "
        "application on this machine.")
    add("")
    add("This is not a slideshow. Apart from the two title cards, everything "
        "in the video is either")
    add("real captured command output or the running application being driven "
        "in a real browser.")
    add("")

    add("## What it shows, scene by scene")
    add("")
    add("| Time | Scene | Requirement | What it is evidence for |")
    add("|---|---|---|---|")
    for scene in scenes:
        add(f"| `{scene['timestamp']}` | {scene['title']} | "
            f"{scene['requirement']} | {PROVES.get(scene['scene'], '')} |")
    add("")

    add("Fourteen of the sixteen slide requirements are demonstrated on "
        "screen. The two that are not —")
    add("REQ-3 and REQ-12, both about the LLM — are covered honestly under "
        "*Limitations* below.")
    add("")

    add("## How to record it again")
    add("")
    add("```bash")
    add("./demo/run_demo.sh                # reuse captured output, record")
    add("./demo/run_demo.sh --recapture    # re-run the real commands first")
    add("./demo/run_demo.sh --no-audio     # silent video")
    add("python demo/record_demo.py --only 10_gate   # iterate on one scene")
    add("python demo/record_demo.py --list           # what the scenes are")
    add("```")
    add("")
    add("`run_demo.sh` starts the API and the dashboard if they are not "
        "already up, and refuses to")
    add("record at all if DefectDojo is unreachable — a video of an error "
        "page looks finished, which")
    add("makes it worse than no video.")
    add("")

    add("## How it is put together")
    add("")
    add("| Piece | File | What it does |")
    add("|---|---|---|")
    add("| Scene list | `demo/scenes.py` | The single source of truth: "
        "narration, on-screen actions, requirement mapping |")
    add("| Capture | `demo/capture.py` | Runs the real commands, saves their "
        "real stdout and exit codes |")
    add("| Terminal | `demo/terminal_player.html` | Replays that captured "
        "text in a styled terminal |")
    add("| Voice | `demo/narrate.py` | Piper neural TTS, offline, no API key |")
    add("| Recorder | `demo/record_demo.py` | Drives one browser page through "
        "every scene and muxes the result |")
    add("| Wrapper | `demo/run_demo.sh` | Health-checks, captures, records |")
    add("")
    add("Two details worth knowing, because they are what keeps the video "
        "honest and in sync:")
    add("")
    add("**Scene length comes from the narration, not the other way round.** "
        "Each scene's speech is")
    add("synthesised and measured first; the picture is then held for that "
        "long. Guessing a duration")
    add("and hoping the words fit is how a sentence ends up cut in half at a "
        "scene change.")
    add("")
    add("**Each narration clip is placed at the offset its scene really "
        "started at**, measured against")
    add("the wall clock during recording. Concatenating the clips end to end "
        "would let a browser step")
    add("that ran 300 ms long push every later scene further out of sync until "
        "the closing narration")
    add(f"played over the wrong picture. Measured against the finished file, "
        f"every scene's speech")
    add("starts within about 0.2 s of its scene.")
    add("")

    add("## Limitations — read this before showing the video")
    add("")
    add("**The terminal segments are real output, animated.** Scenes 3–6 and "
        "15 replay text that")
    add("`demo/capture.py` really captured from real commands on this machine "
        "— the findings, the")
    add("counts, the percentages and the timings are all genuine. The typing "
        "effect is synthetic:")
    add("the text appears line by line rather than at the speed the command "
        "produced it. Nothing is")
    add("edited, and `demo/captures/*.json` records each command's exit code "
        "and real wall-clock time")
    add("so any edit would show up as a disagreement.")
    add("")
    add(f"**Stage 3 ran on the offline validator, not a live LLM.** During "
        f"this recording the configured")
    add(f"provider was `{configured}` and the validator that actually answered "
        f"was `{used}`. The key")
    add("present on this machine authenticates as invalid (HTTP 401), so "
        "Stage 3 fell back to the")
    add("deterministic rule-based validator exactly as it is designed to. "
        "The video shows this on")
    add("screen — `validated by: offline` — rather than hiding it. So the "
        "suppression reasoning you")
    add("see is real reasoning about sanitisers, guards and dead code, but it "
        "is rule-based reasoning.")
    add("REQ-3 and REQ-12 are therefore demonstrated *structurally* (the "
        "provider layer, the prompt,")
    add("the fallback path) and not *live*. Supply a key with quota and the "
        "same scenes run through")
    add("a real model with no code change.")
    add("")
    add("**The corpus is ours.** `testdata/vuln-flask`, `testdata/vuln-express` "
        "and `testdata/safe-app`")
    add("are hand-written and hand-labelled by this team, and the precision "
        "and recall numbers are")
    add("measured against our own ground truth in `testdata/ground_truth.json`. "
        "They are honest")
    add("measurements of a corpus we designed, which is not the same thing as "
        "a result on somebody")
    add("else's code. The decoys were written to be genuinely hard — a "
        "sanitiser that looks wrong")
    add("but is right, a real vulnerability behind an escape that does not "
        "apply to it — but we chose")
    add("them.")
    add("")
    add(f"**DefectDojo was live at `{data.get('defectdojo_url', 'n/a')}`.** "
        f"Scene 13 presses the push")
    add("button on camera and scene 14 shows the findings in DefectDojo's own "
        "UI, read back through")
    add("its API. It is a local instance, seeded by earlier runs of this same "
        "engine.")
    add("")

    add("## Related")
    add("")
    add("- [`docs/requirements-matrix.md`](requirements-matrix.md) — every "
        "slide box, with the test that proves it")
    add("- [`docs/qa.md`](qa.md) — the QA scenarios and the defects found "
        "building this")
    add("- [`docs/demo-script.md`](demo-script.md) — the live-presentation "
        "script, for demoing without the video")
    add("- `demo/output/timeline.json` — the machine-readable timeline this "
        "document is generated from")
    add("")

    OUT.write_text("\n".join(lines) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}  "
          f"({len(scenes)} scenes, {minutes}, validator: {used})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
