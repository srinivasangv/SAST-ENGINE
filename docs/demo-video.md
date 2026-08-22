# The end-to-end demo video

**`demo/output/sast-engine-demo.mp4`** — 4:38, 1280×720, H.264 + AAC, with narration.
A WebM copy sits beside it, and every scene's final frame is in `demo/output/stills/`.

Recorded 2026-08-17 07:10:54 against the live application on this machine.

This is not a slideshow. Apart from the two title cards, everything in the video is either
real captured command output or the running application being driven in a real browser.

## What it shows, scene by scene

| Time | Scene | Requirement | What it is evidence for |
|---|---|---|---|
| `0:01` | Multi-Stage Agentic SAST Engine | — | — |
| `0:14` | The problem | — | — |
| `0:33` | Stages one and two | REQ-1, 2, 11, 14 | CPG built with no build step; taint analysis; Python orchestration; a repo scanned end to end |
| `0:51` | Stage three: the reasoning | REQ-3, 12 | Stage 3 reasoning, with a written reason per suppression |
| `1:08` | Swap the whole front end | REQ-10 | Joern as an interchangeable CPG/taint front end |
| `1:27` | Against the baseline | REQ-6, 15 | FP-suppression rate against a baseline SAST tool |
| `1:48` | The dashboard | REQ-1, 11 | CPG statistics and the four stages, in the UI |
| `2:01` | One finding, end to end | REQ-2, 3, 5 | Taint path, verdict, auto-generated PoC, suggested fix |
| `2:21` | Comparison, on screen | REQ-6, 15 | The comparative report on screen |
| `2:39` | Cross-repo deduplication | REQ-4, 7 | Cross-repo, cross-language deduplication |
| `2:58` | The human-approval gate | REQ-8 | Human approval enforced before any fix is handed over |
| `3:19` | SLA and escalation | REQ-9 | SLA ageing and escalation |
| `3:32` | Live DefectDojo | REQ-13 | A live push to DefectDojo over its API |
| `3:55` | The tickets, in DefectDojo itself | REQ-13 | The tickets in DefectDojo's own UI |
| `4:06` | Every requirement, tested | REQ-16 | Documented test results, one test per slide requirement |
| `4:21` | Summary | — | — |

Fourteen of the sixteen slide requirements are demonstrated on screen. The two that are not —
REQ-3 and REQ-12, both about the LLM — are covered honestly under *Limitations* below.

## How to record it again

```bash
./demo/run_demo.sh                # reuse captured output, record
./demo/run_demo.sh --recapture    # re-run the real commands first
./demo/run_demo.sh --no-audio     # silent video
python demo/record_demo.py --only 10_gate   # iterate on one scene
python demo/record_demo.py --list           # what the scenes are
```

`run_demo.sh` starts the API and the dashboard if they are not already up, and refuses to
record at all if DefectDojo is unreachable — a video of an error page looks finished, which
makes it worse than no video.

## How it is put together

| Piece | File | What it does |
|---|---|---|
| Scene list | `demo/scenes.py` | The single source of truth: narration, on-screen actions, requirement mapping |
| Capture | `demo/capture.py` | Runs the real commands, saves their real stdout and exit codes |
| Terminal | `demo/terminal_player.html` | Replays that captured text in a styled terminal |
| Voice | `demo/narrate.py` | Piper neural TTS, offline, no API key |
| Recorder | `demo/record_demo.py` | Drives one browser page through every scene and muxes the result |
| Wrapper | `demo/run_demo.sh` | Health-checks, captures, records |

Two details worth knowing, because they are what keeps the video honest and in sync:

**Scene length comes from the narration, not the other way round.** Each scene's speech is
synthesised and measured first; the picture is then held for that long. Guessing a duration
and hoping the words fit is how a sentence ends up cut in half at a scene change.

**Each narration clip is placed at the offset its scene really started at**, measured against
the wall clock during recording. Concatenating the clips end to end would let a browser step
that ran 300 ms long push every later scene further out of sync until the closing narration
played over the wrong picture. Measured against the finished file, every scene's speech
starts within about 0.2 s of its scene.

## Limitations — read this before showing the video

**The terminal segments are real output, animated.** Scenes 3–6 and 15 replay text that
`demo/capture.py` really captured from real commands on this machine — the findings, the
counts, the percentages and the timings are all genuine. The typing effect is synthetic:
the text appears line by line rather than at the speed the command produced it. Nothing is
edited, and `demo/captures/*.json` records each command's exit code and real wall-clock time
so any edit would show up as a disagreement.

**Stage 3 ran on the offline validator, not a live LLM.** During this recording the configured
provider was `anthropic` and the validator that actually answered was `offline`. The key
present on this machine authenticates as invalid (HTTP 401), so Stage 3 fell back to the
deterministic rule-based validator exactly as it is designed to. The video shows this on
screen — `validated by: offline` — rather than hiding it. So the suppression reasoning you
see is real reasoning about sanitisers, guards and dead code, but it is rule-based reasoning.
REQ-3 and REQ-12 are therefore demonstrated *structurally* (the provider layer, the prompt,
the fallback path) and not *live*. Supply a key with quota and the same scenes run through
a real model with no code change.

**The corpus is ours.** `testdata/vuln-flask`, `testdata/vuln-express` and `testdata/safe-app`
are hand-written and hand-labelled by this team, and the precision and recall numbers are
measured against our own ground truth in `testdata/ground_truth.json`. They are honest
measurements of a corpus we designed, which is not the same thing as a result on somebody
else's code. The decoys were written to be genuinely hard — a sanitiser that looks wrong
but is right, a real vulnerability behind an escape that does not apply to it — but we chose
them.

**DefectDojo was live at `http://localhost:8083`.** Scene 13 presses the push
button on camera and scene 14 shows the findings in DefectDojo's own UI, read back through
its API. It is a local instance, seeded by earlier runs of this same engine.

## Related

- [`docs/requirements-matrix.md`](requirements-matrix.md) — every slide box, with the test that proves it
- [`docs/qa.md`](qa.md) — the QA scenarios and the defects found building this
- [`docs/demo-script.md`](demo-script.md) — the live-presentation script, for demoing without the video
- `demo/output/timeline.json` — the machine-readable timeline this document is generated from

